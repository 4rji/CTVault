//go:build ctvault_dev || realdata

// Package measure runs a real-data sample through the production per-entry
// pipeline in a throwaway workspace and reports what it observed (amendment
// A1 §2.6 and §8): decoding, the issuance key, dedup, the vault writer with
// dictionaries and leaf-delta, and Parquet staging, committed batch by batch
// exactly as update commits them. It never creates or changes a vault, and
// a report never changes a setting: disk-guard seeds and defaults change
// only by a reviewed edit.
package measure

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/extract"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/ingest"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/sample"
	"github.com/4rji/ctvault/internal/vault"
)

// DefaultBatchSize is the dev build's batch size (amendment A1 §2.5).
const DefaultBatchSize = 10000

// replayRPS lifts the live rate limit: the replay is on loopback.
const replayRPS = 1000

// Options configure a measurement run.
type Options struct {
	Base    string // the dev base: the workspace goes under Base/tmp, the report under Base/reports
	Version string // CTVault version, for the provenance
	Now     func() time.Time
	Stat    diskguard.StatFunc // the disk guard's statfs
	Out     io.Writer          // progress: the writer's line per batch; nil discards

	BatchSize uint64 // entries per committed batch; default DefaultBatchSize
	// Dependencies are module versions for the provenance when the binary's
	// build info lists none (a go test binary): the caller reads go.mod.
	Dependencies map[string]string
	// Tests shrink these; zero means the production values.
	DictSamples   int
	CanarySamples int
}

// Paths are a written report's files.
type Paths struct{ JSON, Markdown string }

// Run measures s, writes the report under o.Base/reports/<sample-id>/ and
// returns it. The workspace is removed whatever happens; a run that fails
// or is interrupted writes no report.
func Run(ctx context.Context, s *sample.Sample, o Options) (Report, Paths, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Out == nil {
		o.Out = io.Discard
	}
	if o.BatchSize == 0 {
		o.BatchSize = DefaultBatchSize
	}
	if err := ctx.Err(); err != nil {
		return Report{}, Paths{}, err
	}
	sv, err := surveySample(ctx, s, o.BatchSize)
	if err != nil {
		return Report{}, Paths{}, err
	}
	ws, err := workspace(o.Base)
	if err != nil {
		return Report{}, Paths{}, err
	}
	defer os.RemoveAll(ws)
	res, err := ingestAll(ctx, s, o, ws, sv)
	if err != nil {
		return Report{}, Paths{}, err
	}
	r := build(s, o, sv, res)
	p, err := write(o.Base, r)
	return r, p, err
}

// survey is what one pass over the sample's own entries finds: the facts
// the writer does not record (links, delays, duplicates, error codes) and
// the Merkle root at every batch end.
type survey struct {
	heads []logsource.SignedHead // one per batch: its end and the root there

	types      map[string]int    // entry types
	codes      map[leaf.Code]int // leaf error codes
	leafType   map[[32]byte]string
	chainCerts map[[32]byte]bool
	leafCerts  int
	chainRefs  int

	finals, linked, eligible int
	precertLater             int     // finals whose precert comes later in the window
	delays                   []int64 // ms from a precert to its final certificate
}

// surveySample decodes every entry in index order. The roots it records at
// batch ends come from leaves that sample.Open verified against the signed
// head; the writer recomputes them from the replayed entries, so each batch
// is still Merkle-verified (a representative sample has a consistency proof
// only at the end of its window).
func surveySample(ctx context.Context, s *sample.Sample, batch uint64) (*survey, error) {
	st, err := s.StartState()
	if err != nil {
		return nil, err
	}
	m := s.Manifest
	end := m.Start + m.Count
	sv := &survey{types: map[string]int{}, codes: map[leaf.Code]int{}, leafType: map[[32]byte]string{}, chainCerts: map[[32]byte]bool{}}
	precertAt := map[[32]byte]uint64{} // issuance digest → the first precert's timestamp
	var unlinked [][32]byte            // finals met before any precert of theirs
	err = s.Each(func(e sample.Entry) error {
		if err := st.Append(merkle.LeafHash(e.LeafInput)); err != nil {
			return err
		}
		l := leaf.Decode(e.LeafInput, e.ExtraData)
		sv.types[l.Type.String()]++
		if l.Code != leaf.OK {
			sv.codes[l.Code]++
		}
		newCert := false
		if l.CertDER != nil {
			sv.leafCerts++
			sha := sha256.Sum256(l.CertDER)
			if _, seen := sv.leafType[sha]; !seen {
				sv.leafType[sha], newCert = l.Type.String(), true
			}
		}
		for _, c := range l.Chain {
			sv.chainRefs++
			sv.chainCerts[sha256.Sum256(c)] = true
		}
		if l.HasIssuanceDigest {
			switch l.Type {
			case leaf.TypePrecert:
				if _, ok := precertAt[l.IssuanceDigest]; !ok {
					precertAt[l.IssuanceDigest] = l.Timestamp
				}
			case leaf.TypeX509:
				sv.finals++
				if ts, ok := precertAt[l.IssuanceDigest]; ok {
					sv.linked++
					sv.delays = append(sv.delays, int64(l.Timestamp)-int64(ts))
					if newCert {
						sv.eligible++
					}
				} else {
					unlinked = append(unlinked, l.IssuanceDigest)
				}
			}
		}
		if n := e.Index + 1; (n-m.Start)%batch == 0 || n == end {
			root, err := st.Root()
			if err != nil {
				return err
			}
			h := logsource.SignedHead{}
			h.TreeSize, h.RootHash, h.Timestamp = n, root, m.Head.Timestamp
			sv.heads = append(sv.heads, h)
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		return nil
	})
	for _, d := range unlinked {
		if _, ok := precertAt[d]; ok {
			sv.precertLater++
		}
	}
	return sv, err
}

// workspace creates <base>/tmp/measure-<pid> with a vault's folder layout
// (no VAULT_ID: it is never a vault), after removing the workspaces of
// processes that no longer run (a killed measurement).
func workspace(base string) (string, error) {
	tmp := filepath.Join(base, "tmp")
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return "", err
	}
	names, err := filepath.Glob(filepath.Join(tmp, "measure-*"))
	if err != nil {
		return "", err
	}
	for _, n := range names {
		pid, err := strconv.Atoi(strings.TrimPrefix(filepath.Base(n), "measure-"))
		if err == nil && pid > 0 && errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
			if err := os.RemoveAll(n); err != nil {
				return "", err
			}
		}
	}
	ws := filepath.Join(tmp, fmt.Sprintf("measure-%d", os.Getpid()))
	if err := os.RemoveAll(ws); err != nil {
		return "", err
	}
	for _, d := range []string{"state/intent", "state/incidents", "state/logs", "vault/segments", "vault/dict", "dataset", "tmp/stage", "tmp/rebuild"} {
		if err := os.MkdirAll(filepath.Join(ws, d), 0o755); err != nil {
			return "", err
		}
	}
	return ws, nil
}

// result is what the ingest left in the workspace.
type result struct {
	manifests []commit.Manifest
	seconds   []float64 // per batch
	pebble    int64     // state/pebble after the writer closed
	segments  int64     // segment files, headers included
	groups    map[groupKey]*Group
	deltas    map[uint64]*DeltaSaving // by the dictionary of the delta's batch
	chainRecs int
	extractNS int64 // time spent re-parsing every vaulted certificate
	extracted int
}

type groupKey struct {
	kind      string
	dict      uint64
	entryType string
}

// ingestAll commits the sample batch by batch through the production writer,
// fed by the sample's replay over loopback, then scans what it wrote.
func ingestAll(ctx context.Context, s *sample.Sample, o Options, ws string, sv *survey) (*result, error) {
	url, stop, err := sample.Serve(ctx, s)
	if err != nil {
		return nil, err
	}
	defer stop()
	chains := logsource.NewChainCache(logsource.DefaultChainCacheBytes)
	src := rfc6962.NewSource(s.LogInfo(url), &http.Client{Timeout: 60 * time.Second}, chains, nil)

	cfg := config.Default()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	dirs := []string{filepath.Join(ws, "vault")}
	w, err := ingest.Open(ingest.Options{Root: ws, VaultDirs: dirs, VaultUUID: id, Config: cfg,
		Guard: diskguard.Guard{Cap: cfg.Disk.MaxUsedFraction, Stat: o.Stat}, Version: o.Version, Now: o.Now, Out: o.Out,
		Fetch: fetch.Options{Workers: cfg.Ingest.Workers, MaxRPS: replayRPS, PageSize: s.Manifest.PageSize,
			StallTimeout: cfg.Ingest.StallTimeout.Duration, MaxBufferedEntries: cfg.Fetch.MaxBufferedEntries,
			MaxBufferedBytes: int(cfg.Fetch.MaxBufferedBytes)},
		DictSamples: o.DictSamples, CanarySamples: o.CanarySamples})
	if err != nil {
		return nil, err
	}
	defer w.Close()
	m := s.Manifest
	if m.Kind == sample.Representative {
		st, err := s.StartState()
		if err != nil {
			return nil, err
		}
		if err := w.Seed(m.Log.Name, st); err != nil {
			return nil, err
		}
	}
	res := &result{groups: map[groupKey]*Group{}, deltas: map[uint64]*DeltaSaving{}}
	first := m.Start
	for _, h := range sv.heads {
		t0 := time.Now()
		if _, err := w.Batch(ctx, src, h, first, h.TreeSize); err != nil {
			return nil, err
		}
		chains.Reset()
		res.seconds = append(res.seconds, time.Since(t0).Seconds())
		first = h.TreeSize
	}
	res.manifests = w.Committed()
	if err := w.Close(); err != nil {
		return nil, err
	}
	res.pebble = dirSize(filepath.Join(ws, "state", "pebble"))
	res.segments = dirSize(filepath.Join(ws, "vault", "segments"))
	return res, scanVault(dirs, sv, res)
}

// scanVault reads back every record the run wrote, grouped by record kind,
// dictionary and entry type, and prices each leaf-delta record against the
// same certificate stored in full with the batch's dictionary.
func scanVault(dirs []string, sv *survey, res *result) error {
	codec, err := vault.NewCodec()
	if err != nil {
		return err
	}
	defer codec.Close()
	dicts, err := vault.LoadDicts(dirs)
	if err != nil {
		return err
	}
	for _, d := range dicts {
		if err := codec.AddDict(d.Manifest.ID, d.Content); err != nil {
			return err
		}
	}
	r, err := vault.OpenReader(dirs, codec)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, m := range res.manifests {
		err := vault.Scan(dirs, m.Vault.Start, m.Vault.End, func(loc vault.Loc, rec vault.Record) error {
			der, _, err := r.Read(loc)
			if err != nil {
				return err
			}
			t0 := time.Now()
			extract.Parse(der)
			res.extractNS += time.Since(t0).Nanoseconds()
			res.extracted++
			sha := sha256.Sum256(der)
			k := groupKey{dict: rec.DictID}
			switch rec.Kind {
			case vault.KindChain:
				if !sv.chainCerts[sha] {
					return fmt.Errorf("vault record %d:%d is a chain certificate the sample does not hold", loc.Segment, loc.Offset)
				}
				k.kind, k.entryType = "chain", "chain"
				res.chainRecs++
			case vault.KindLeaf, vault.KindDelta:
				t, ok := sv.leafType[sha]
				if !ok {
					return fmt.Errorf("vault record %d:%d is a certificate the sample does not hold", loc.Segment, loc.Offset)
				}
				k.kind, k.entryType = "leaf", t
				if rec.Kind == vault.KindDelta {
					k.kind, k.dict = "delta", m.Dictionary.ID
					full, err := codec.Compress(der, m.Dictionary.ID)
					if err != nil {
						return err
					}
					ds := res.deltas[m.Dictionary.ID]
					if ds == nil {
						ds = &DeltaSaving{Dictionary: m.Dictionary.ID}
						res.deltas[m.Dictionary.ID] = ds
					}
					ds.Records++
					ds.StoredBytes += uint64(len(rec.Frame))
					ds.FullBytes += uint64(len(full))
				}
			}
			g := res.groups[k]
			if g == nil {
				g = &Group{Kind: k.kind, Dictionary: k.dict, EntryType: k.entryType}
				res.groups[k] = g
			}
			g.Records++
			g.RawBytes += uint64(len(der))
			g.StoredBytes += uint64(rec.TotalLen)
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func dirSize(dir string) int64 {
	var n int64
	filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}
