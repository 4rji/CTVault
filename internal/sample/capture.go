package sample

import (
	"context"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"time"

	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/loglist"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
)

// CaptureOptions describes one capture.
type CaptureOptions struct {
	Kind           Kind
	Start          uint64 // representative only
	StartAtHead    bool   // representative only: "--start head", resolved from the pinned head
	Count          uint64
	Suffix         string
	Limits         Limits        // zero means DefaultLimits
	Fetch          fetch.Options // workers, rate and stall timeout
	Key            string        // base64 SPKI pinned from the log list
	LogListVersion string
	Version        string // CTVault version for the manifest
	Now            func() time.Time
	// Check, if set, is the disk guard: called before the capture with the
	// estimated size, then every CheckEvery bytes written.
	Check    func(need int64) error
	Progress func(done, total uint64) // called after every frame
}

// SeedBytesPerEntry is the disk-guard preflight estimate of a sample's size:
// the uncompressed JSON size of an entry as served (spec §3.2: 7,409 B). It is
// deliberately conservative: 32,768 real argon2027h1 entries took 900 B each
// in entries.ndjson.zst (measured 2026-10-04).
const SeedBytesPerEntry = 7409

// Capture pins the log's current signed head, fetches the range through the
// real fetcher, collects the proofs and publishes the verified sample under
// samplesDir/<log>/<folder>. On any failure or cancellation nothing becomes
// visible.
func Capture(ctx context.Context, samplesDir string, src *rfc6962.Source, o CaptureOptions) (*Sample, error) {
	if o.Limits == (Limits{}) {
		o.Limits = DefaultLimits
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.StartAtHead && o.Kind != Representative {
		return nil, fmt.Errorf("sample: --start head is for representative samples")
	}
	// Check everything that does not depend on the log before contacting it.
	if o.StartAtHead {
		o.Start = 0
	}
	if err := o.Limits.Check(o.Kind, o.Start, o.Count); err != nil {
		return nil, err
	}
	if _, err := DirName(o.Start, o.Count, o.Suffix); err != nil {
		return nil, err
	}
	info := src.Info()
	var head logsource.SignedHead
	if err := fetch.Retry(ctx, o.Fetch, func(ctx context.Context) (err error) {
		head, err = src.Head(ctx)
		return err
	}); err != nil {
		return nil, err
	}
	if o.StartAtHead {
		var err error
		if o.Start, err = o.Limits.StartForHead(head.TreeSize, o.Count); err != nil {
			return nil, err
		}
	}
	name, err := DirName(o.Start, o.Count, o.Suffix)
	if err != nil {
		return nil, err
	}
	if o.Start+o.Count > head.TreeSize {
		return nil, fmt.Errorf("sample: the log currently has only %d entries; [%d, %d) does not fit", head.TreeSize, o.Start, o.Start+o.Count)
	}
	if o.Check != nil {
		if err := o.Check(int64(o.Count) * SeedBytesPerEntry); err != nil {
			return nil, err
		}
	}
	m := Manifest{
		Format: Format, Kind: o.Kind, Start: o.Start, Count: o.Count, Boundary: o.Limits.Boundary,
		Log: LogRef{Name: info.Name, LogID: base64.StdEncoding.EncodeToString(info.LogID[:]), Key: o.Key,
			URL: info.URL, LogListVersion: o.LogListVersion},
		HeadRaw: head.Raw,
		Head: HeadSummary{TreeSize: head.TreeSize, Timestamp: head.Timestamp,
			RootHash: base64.StdEncoding.EncodeToString(head.RootHash[:])},
		CapturedAt: o.Now().UTC(), CTVaultVersion: o.Version,
	}
	if _, err := loglist.ParseKey(o.Key, m.Log.LogID); err != nil {
		return nil, fmt.Errorf("sample: log %s: %w", info.Name, err)
	}
	dest := filepath.Join(samplesDir, info.Name, name)
	var check func(int64) error
	if o.Check != nil {
		check = func(int64) error { return o.Check(CheckEvery) }
	}
	w, err := Create(dest, m, check)
	if err != nil {
		return nil, err
	}
	defer w.Abort()

	var first [32]byte
	end := o.Start + o.Count
	st, err := fetch.Run(ctx, src, o.Start, end, o.Fetch, func(e logsource.RawEntry) error {
		if e.Index == o.Start {
			first = e.Leaf.LeafHash
		}
		if err := w.Add(e); err != nil {
			return err
		}
		if o.Progress != nil && (e.Index+1-o.Start)%o.Limits.Boundary == 0 {
			o.Progress(e.Index+1-o.Start, o.Count)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	w.m.PageSize = st.LargestResponse

	var p Proofs
	proof := func(first, second uint64) error {
		if first == second {
			return nil
		}
		var ns [][32]byte
		if err := fetch.Retry(ctx, o.Fetch, func(ctx context.Context) (err error) {
			ns, err = src.ConsistencyProof(ctx, first, second)
			return err
		}); err != nil {
			return fmt.Errorf("consistency proof %d → %d: %w", first, second, err)
		}
		p.Consistency = append(p.Consistency, Consistency{First: first, Second: second, Nodes: nodes(ns)})
		return nil
	}
	switch o.Kind {
	case Canonical:
		for b := o.Start + o.Limits.Boundary; b <= end; b += o.Limits.Boundary {
			if err := proof(b, head.TreeSize); err != nil {
				return nil, err
			}
		}
	case Representative:
		var idx uint64
		var path [][32]byte
		if err := fetch.Retry(ctx, o.Fetch, func(ctx context.Context) (err error) {
			idx, path, err = src.Client().GetProofByHash(ctx, first, head.TreeSize)
			return err
		}); err != nil {
			return nil, fmt.Errorf("inclusion proof of leaf %d: %w", o.Start, err)
		}
		if idx != o.Start {
			return nil, fmt.Errorf("sample: leaf %d also appears at index %d, so the log proves that one; choose another --start", o.Start, idx)
		}
		p.Inclusion = &Inclusion{LeafIndex: idx, TreeSize: head.TreeSize, LeafHash: first, AuditPath: nodes(path)}
		if err := proof(end, head.TreeSize); err != nil {
			return nil, err
		}
	}
	return w.Commit(p)
}
