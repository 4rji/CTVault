//go:build realdata

package integration

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/sample"
	"github.com/4rji/ctvault/internal/sampletest"
)

const realLog = "argon2027h1"

// decodeStats summarises decoded entries.
type decodeStats struct {
	types    map[leaf.Type]int
	codes    map[leaf.Code]int
	precerts map[[16]byte]bool
	finals   [][16]byte
}

func newDecodeStats() *decodeStats {
	return &decodeStats{types: map[leaf.Type]int{}, codes: map[leaf.Code]int{}, precerts: map[[16]byte]bool{}}
}

func (d *decodeStats) add(t *testing.T, idx uint64, e leaf.Entry) {
	if e.Code.LeafStructure() {
		t.Errorf("entry %d: the log served a leaf that cannot be interpreted: %s", idx, e.Code)
	}
	d.types[e.Type]++
	d.codes[e.Code]++
	if k, ok := e.IssuanceKey(); ok {
		if e.Type == leaf.TypePrecert {
			d.precerts[k] = true
		} else {
			d.finals = append(d.finals, k)
		}
	}
}

func (d *decodeStats) log(t *testing.T, what string) {
	linked := 0
	for _, k := range d.finals {
		if d.precerts[k] {
			linked++
		}
	}
	t.Logf("%s: x509 %d, precert %d; leaf codes %v; %d of %d final certs link to a precert in the window",
		what, d.types[leaf.TypeX509], d.types[leaf.TypePrecert], d.codes, linked, len(d.finals))
}

// TestCanonicalSampleThroughTheFetcher replays the canonical sample through
// the production client, fetcher and leaf decoder, rebuilds the Merkle range
// from the fetched leaves and checks it against the signed head.
func TestCanonicalSampleThroughTheFetcher(t *testing.T) {
	s := sampletest.Canonical(t, realLog)
	src := sampletest.Serve(t, s)
	m := s.Manifest
	head, err := src.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	st := merkle.NewState()
	stats := newDecodeStats()
	fs, err := fetch.Run(context.Background(), src, m.Start, m.Start+m.Count, fetch.Options{MaxRPS: 1000},
		func(e logsource.RawEntry) error {
			stats.add(t, e.Index, e.Leaf)
			return st.Append(e.Leaf.LeafHash)
		})
	if err != nil {
		t.Fatal(err)
	}
	root, _ := st.Root()
	end := m.Start + m.Count
	if end == head.TreeSize {
		if root != head.RootHash {
			t.Fatal("the fetched leaves do not reach the signed root")
		}
	} else {
		proof, err := src.ConsistencyProof(context.Background(), end, head.TreeSize)
		if err != nil {
			t.Fatal(err)
		}
		if err := merkle.VerifyConsistency(end, head.TreeSize, root, head.RootHash, proof); err != nil {
			t.Fatalf("the fetched leaves are not a prefix of the signed tree: %v", err)
		}
	}
	stats.log(t, m.ID(filepath.Base(s.Dir)))
	t.Logf("fetch: %d requests, page size %d, peak buffer %d entries / %d bytes", fs.Requests, fs.LargestResponse, fs.PeakBufEntries, fs.PeakBufBytes)
}

// TestRepresentativeSamplesDecode opens (and so verifies) every cached
// representative sample and decodes every entry.
func TestRepresentativeSamplesDecode(t *testing.T) {
	samples := sampletest.Representatives(t, realLog)
	if len(samples) == 0 {
		t.Skipf("no representative sample of %s cached; capture one with:\n  ctvault-dev sample capture --log %s --start head --entries 100000", realLog, realLog)
	}
	for _, s := range samples {
		stats := newDecodeStats()
		err := s.Each(func(e sample.Entry) error {
			stats.add(t, e.Index, leaf.Decode(e.LeafInput, e.ExtraData))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		stats.log(t, s.Manifest.ID(filepath.Base(s.Dir)))
	}
}
