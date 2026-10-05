//go:build ctvault_dev || realdata

package measure

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/sample"
)

var now = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

// fakeSample captures a sample of a fake log holding es (frames of 8).
func fakeSample(t *testing.T, es []ctlogtest.Entry, kind sample.Kind, start, count uint64) *sample.Sample {
	t.Helper()
	l := ctlogtest.NewWithEntries(t, es, ctlogtest.Options{PageSize: 8})
	pub, err := x509.ParsePKIXPublicKey(l.PublicKeyDER)
	if err != nil {
		t.Fatal(err)
	}
	src := rfc6962.NewSource(logsource.LogInfo{Name: "fakelog", LogID: l.LogID, PublicKey: pub, URL: l.URL}, nil,
		logsource.NewChainCache(logsource.DefaultChainCacheBytes), nil)
	dir := t.TempDir()
	t.Cleanup(func() { // published samples are read-only; let TempDir remove them
		filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				os.Chmod(p, 0o755)
			}
			return nil
		})
	})
	s, err := sample.Capture(context.Background(), dir, src, sample.CaptureOptions{Kind: kind, Start: start, Count: count,
		Limits: sample.Limits{Boundary: 8, Min: 16, Max: 96}, Key: base64.StdEncoding.EncodeToString(l.PublicKeyDER),
		LogListVersion: "test", Version: "test", Now: func() time.Time { return now },
		Fetch: fetch.Options{MaxRPS: 1000, MinBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func generated(t *testing.T, n int) []ctlogtest.Entry {
	t.Helper()
	g, err := ctlogtest.NewGenerator()
	if err != nil {
		t.Fatal(err)
	}
	es, err := g.Entries(n)
	if err != nil {
		t.Fatal(err)
	}
	return es
}

func options(t *testing.T, base string) Options {
	free := func(string) (diskguard.Usage, error) {
		return diskguard.Usage{Total: 1 << 40, Avail: 1 << 39, Dev: 1}, nil
	}
	return Options{Base: base, Version: "test", Now: func() time.Time { return now }, Stat: free,
		BatchSize: 32, DictSamples: 16, CanarySamples: 8,
		Dependencies: map[string]string{"github.com/klauspost/compress": "v1.20.1"}}
}

// TestMeasureCanonical runs a canonical sample with known contents: 46
// precert/final pairs, a duplicate final, a duplicate precert, a malformed
// leaf and one more duplicate final.
func TestMeasureCanonical(t *testing.T) {
	es := generated(t, 92)
	es = append(es, es[1], es[2], ctlogtest.MalformedEntry(1790000999000), es[3])
	s := fakeSample(t, es, sample.Canonical, 0, 96)
	base := t.TempDir()
	r, paths, err := Run(context.Background(), s, options(t, base))
	if err != nil {
		t.Fatal(err)
	}
	if r.Sample.Count != 96 || r.Run.Batches != 3 || len(r.Batches) != 3 {
		t.Fatalf("sample %+v, run %+v", r.Sample, r.Run)
	}
	if r.Batches[0].Dictionary != 0 || r.Batches[1].Dictionary != 1 || r.Batches[2].Dictionary != 1 {
		t.Fatalf("dictionary 1 is trained after the first batch's 16 precerts: %+v", r.Batches)
	}
	// 46 finals plus 2 duplicates, all after their precert in index order.
	l := r.Links
	if l.Finals != 48 || l.Linked != 48 || l.LinkRate != 1 || l.DeltaEligible != 46 || l.DeltaRecords != 46 || l.DeltaHitRate != 1 {
		t.Fatalf("links %+v", l)
	}
	if l.DelayMS.P50 != 1000 || l.DelayMS.P99 != 1000 {
		t.Fatalf("every generated final is logged 1 s after its precert: %+v", l.DelayMS)
	}
	d := r.Dedup
	if d.LeafCerts != 95 || d.UniqueLeafCerts != 92 || d.LeafHits != 3 || d.ChainRefs == 0 || d.ChainRecords == 0 || d.ChainRecords >= d.ChainRefs {
		t.Fatalf("dedup %+v", d)
	}
	if r.Errors.Total != 1 || r.Errors.ByCode["leaf_bad_version"] != 1 || r.Errors.Structural != 1 {
		t.Fatalf("errors %+v", r.Errors)
	}
	var leafRecords, deltaRecords int
	for _, g := range r.Compression.Groups {
		switch g.Kind {
		case "leaf":
			leafRecords += g.Records
		case "delta":
			deltaRecords += g.Records
		}
		if g.Ratio <= 0 || g.StoredBytes == 0 {
			t.Fatalf("group %+v", g)
		}
	}
	if leafRecords+deltaRecords != 92 || deltaRecords != 46 {
		t.Fatalf("records: %d full leaf + %d delta, want 46 + 46", leafRecords, deltaRecords)
	}
	z := r.Sizes
	if z.Vault <= 0 || z.VaultFiles < z.Vault || z.Parquet <= 0 || z.Pebble <= 0 || z.ParquetByFile["entries.parquet"] <= 0 {
		t.Fatalf("sizes %+v", z)
	}
	deltas := 0
	for _, ds := range r.Compression.Deltas {
		deltas += ds.Records
		if ds.FullBytes == 0 || ds.StoredBytes == 0 {
			t.Fatalf("delta saving %+v", ds)
		}
	}
	if len(r.Compression.Deltas) != 2 || r.Compression.Deltas[0].Dictionary != 0 || r.Compression.Deltas[1].Dictionary != 1 || deltas != 46 {
		t.Fatalf("delta savings by dictionary: %+v", r.Compression.Deltas)
	}
	if !strings.Contains(strings.Join(r.Notes, "\n"), "batch 32-63 trained dictionary 1") {
		t.Fatalf("notes lack the training batch: %q", r.Notes)
	}
	if r.Provenance.GoVersion == "" || r.Provenance.CTVaultVersion != "test" || r.Sample.ID != "fakelog/000000000000-000000000095" {
		t.Fatalf("provenance %+v, sample %+v", r.Provenance, r.Sample)
	}
	// A test binary's build info lists no dependencies; the caller's
	// versions are used and labelled.
	p := r.Provenance
	if p.Dependencies["github.com/klauspost/compress"] != "v1.20.1" || p.DependenciesFrom != "go.mod" || p.ZstdLibrary != "github.com/klauspost/compress v1.20.1" {
		t.Fatalf("dependencies %v from %q, zstd %q", p.Dependencies, p.DependenciesFrom, p.ZstdLibrary)
	}
	// The report is written, the workspace is gone.
	wantDir := filepath.Join(base, "reports", "fakelog", "000000000000-000000000095")
	if filepath.Dir(paths.JSON) != wantDir || filepath.Dir(paths.Markdown) != wantDir {
		t.Fatalf("report paths %+v, want under %s", paths, wantDir)
	}
	b, err := os.ReadFile(paths.JSON)
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(b, &back); err != nil || back.Links != r.Links {
		t.Fatalf("report JSON does not round-trip: %v", err)
	}
	md, err := os.ReadFile(paths.Markdown)
	if err != nil || !strings.Contains(string(md), "fakelog/000000000000-000000000095") {
		t.Fatalf("markdown summary: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(base, "tmp", "measure-*")); len(left) != 0 {
		t.Fatalf("workspace left behind: %v", left)
	}
}

// TestMeasureFinalBeforePrecert: a final certificate logged before its
// precert cannot link or delta-encode; it is counted apart.
func TestMeasureFinalBeforePrecert(t *testing.T) {
	es := generated(t, 16)
	es[2], es[3] = es[3], es[2]
	o := options(t, t.TempDir())
	o.BatchSize = 8
	r, _, err := Run(context.Background(), fakeSample(t, es, sample.Canonical, 0, 16), o)
	if err != nil {
		t.Fatal(err)
	}
	if l := r.Links; l.Finals != 8 || l.Linked != 7 || l.PrecertLater != 1 || l.DeltaEligible != 7 || l.DeltaRecords != 7 {
		t.Fatalf("links %+v", l)
	}
}

// TestMeasureRepresentative: a window that starts mid-log is seeded from the
// sample's inclusion proof and measured; a final whose precert is before the
// window does not link.
func TestMeasureRepresentative(t *testing.T) {
	es := generated(t, 80)
	s := fakeSample(t, es, sample.Representative, 24, 48)
	o := options(t, t.TempDir())
	o.BatchSize = 16
	r, _, err := Run(context.Background(), s, o)
	if err != nil {
		t.Fatal(err)
	}
	if r.Sample.Kind != "representative" || r.Sample.Start != 24 || len(r.Batches) != 3 || r.Batches[0].First != 24 || r.Batches[2].Last != 71 {
		t.Fatalf("sample %+v, batches %+v", r.Sample, r.Batches)
	}
	if r.Links.Finals != 24 || r.Links.Linked != 24 {
		t.Fatalf("the window starts on a precert, so all 24 finals link: %+v", r.Links)
	}
	if !strings.Contains(strings.Join(r.Notes, "\n"), "starts mid-log") {
		t.Fatalf("notes lack the representative caveat: %q", r.Notes)
	}

	small := fakeSample(t, es, sample.Representative, 8, 16) // [8, 24), two batches of 8
	o.BatchSize = 8
	r, _, err = Run(context.Background(), small, o)
	if err != nil || r.Links.Finals != 8 || r.Links.Linked != 8 {
		t.Fatalf("%v %+v", err, r.Links)
	}
}

// TestMeasureLeavesNothingOnFailure: a run interrupted after a committed
// batch leaves no workspace and no report, and a stale workspace of a dead
// process is removed.
func TestMeasureLeavesNothingOnFailure(t *testing.T) {
	s := fakeSample(t, generated(t, 32), sample.Canonical, 0, 32)
	base := t.TempDir()
	stale := filepath.Join(base, "tmp", "measure-999999999")
	if err := os.MkdirAll(filepath.Join(stale, "vault"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	o := options(t, base)
	o.BatchSize = 16
	o.Out = cancelOnWrite(cancel) // the writer's line for the first committed batch
	if _, _, err := Run(ctx, s, o); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run interrupted after its first batch: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(base, "tmp", "measure-*")); len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}
	if reports, _ := filepath.Glob(filepath.Join(base, "reports", "*", "*", "*")); len(reports) != 0 {
		t.Fatalf("a failed run wrote a report: %v", reports)
	}
}

type cancelOnWrite func()

func (c cancelOnWrite) Write(p []byte) (int, error) { c(); return len(p), nil }

func TestPercentiles(t *testing.T) {
	var v []int64
	for i := int64(1); i <= 100; i++ {
		v = append(v, 101-i)
	}
	if p := percentiles(v); p.P50 != 50 || p.P95 != 95 || p.P99 != 99 {
		t.Fatalf("nearest-rank percentiles of 1..100: %+v", p)
	}
	if p := percentiles(nil); p != (Delays{}) {
		t.Fatalf("no values: %+v", p)
	}
}

// TestGapRule is amendment A1 §5's rule: more than 10% worse than the
// spec's figure is flagged.
func TestGapRule(t *testing.T) {
	for _, c := range []struct {
		higherIsBetter bool
		spec, measured float64
		exceeds        bool
	}{
		{true, 1.96, 1.80, false}, // 8.9% lower ratio
		{true, 1.96, 1.70, true},  // 15% lower
		{false, 765, 840, false},  // 9.8% more bytes
		{false, 765, 850, true},   // 11% more
		{true, 1.96, 2.40, false},
	} {
		g := gap("x", c.spec, c.measured, c.higherIsBetter)
		if g.Exceeds != c.exceeds {
			t.Errorf("%+v: exceeds = %v", c, g.Exceeds)
		}
	}
}

// TestReportWriteFailsOnAnUnreadableFolder: a reports folder that cannot be
// searched is an error, never an endless search for a free name.
func TestReportWriteFailsOnAnUnreadableFolder(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "reports", "fakelog", "x")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o600); err != nil { // no search permission
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
	done := make(chan error, 1)
	go func() {
		_, err := write(base, Report{Sample: SampleInfo{ID: "fakelog/x"}, Provenance: Provenance{ReportedAt: now}})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("writing into an unsearchable folder succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("write is still looking for a free report name")
	}
}
