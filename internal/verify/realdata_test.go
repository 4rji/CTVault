//go:build realdata

package verify_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/derivetest"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/ingest"
	"github.com/4rji/ctvault/internal/query"
	"github.com/4rji/ctvault/internal/querytest"
	"github.com/4rji/ctvault/internal/sampletest"
	"github.com/4rji/ctvault/internal/vault"
	. "github.com/4rji/ctvault/internal/verify"
)

// TestVerifyOnRealData: verify --quick and --full pass on the canonical
// sample, with timings at one decoder and at one per core; repair --derived
// rebuilds a damaged real certs file byte for byte (amendment A5 §4.4).
func TestVerifyOnRealData(t *testing.T) {
	s := sampletest.Canonical(t, "argon2027h1")
	start := time.Now()
	v := querytest.FromSample(t, s, s.Manifest.Count, 10000)
	t.Logf("ingested %d entries in %v", s.Manifest.Count, time.Since(start).Round(time.Second))

	start = time.Now()
	r := run(t, options(v.Root))
	t.Logf("--quick: %v\n%s", time.Since(start).Round(time.Millisecond), text(r))
	if r.Damaged() {
		t.Fatal("damage in a sound vault")
	}
	for _, workers := range []int{1, runtime.NumCPU()} {
		o := fullOptions(t, v.Root)
		o.Workers = workers
		start = time.Now()
		r := run(t, o)
		t.Logf("--full, %d decoders: %v", workers, time.Since(start).Round(time.Millisecond))
		if r.Damaged() || r.Check("index").Status != StatusOK {
			t.Fatalf("--full:\n%s", text(r))
		}
		if workers == 1 {
			t.Logf("\n%s", text(r))
		}
	}

	// repair --derived on a real batch.
	dirs := batchDirs(t, v.Root)
	p := filepath.Join(dirs[4], "certs.p1.parquet")
	good, _ := os.ReadFile(p)
	bad := bytes.Clone(good)
	bad[len(bad)/2] ^= 0xff
	os.WriteFile(p, bad, 0o644)
	codec, _ := vault.NewCodec()
	defer codec.Close()
	dicts, _ := vault.ReadDicts(v.Dirs)
	for _, d := range dicts {
		codec.AddDict(d.Manifest.ID, d.Content)
	}
	stager, err := dataset.NewStager(dataset.Options{TempDir: t.TempDir(), MaxTempBytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	defer stager.Close()
	x, err := index.OpenReadOnly(filepath.Join(v.Root, "state", "pebble"))
	if err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	rep, err := ingest.RepairDerived(ctx, ingest.RepairOptions{Root: v.Root, VaultDirs: v.Dirs, Codec: codec, Stager: stager, Index: x, CanarySamples: 64})
	x.Close()
	if err != nil || len(rep.Replaced) != 1 || len(rep.Damaged) != 0 {
		t.Fatalf("repair --derived: %+v %v", rep, err)
	}
	if got, _ := os.ReadFile(p); !bytes.Equal(got, good) {
		t.Fatal("the rebuilt certs file differs from the one ingest wrote")
	}
	t.Logf("repair --derived: %d files checked in %d batches, 1 replaced byte for byte, in %v", rep.Checked, rep.Batches, time.Since(start).Round(time.Millisecond))
	if r := run(t, fullOptions(t, v.Root)); r.Damaged() {
		t.Fatalf("after the repair:\n%s", text(r))
	}
}

// derivedBytes sums the derived files a vault's batches list for a table.
func derivedBytes(t *testing.T, root, file string) int64 {
	t.Helper()
	ms, err := commit.ListCommitted(root)
	if err != nil {
		t.Fatal(err)
	}
	var n int64
	for _, m := range ms {
		if fi, ok := m.Listed(file); ok {
			n += fi.Bytes
		}
	}
	return n
}

// TestUpgradeOnRealData: the canonical sample carried from certs v1 to the
// test v2, side by side in turns and then in place on a second copy, with
// timings and disk use; search gives the same rows and verify passes
// (amendment A5 §11).
func TestUpgradeOnRealData(t *testing.T) {
	s := sampletest.Canonical(t, "argon2027h1")
	v := querytest.FromSample(t, s, s.Manifest.Count, 10000)
	q := query.Query{Mode: query.ModeDomain, Text: "on.aws", Group: "certs", Sort: "cert_id asc"}
	search := func() *query.Result {
		snap, err := query.Open(v.Root, 0)
		if err != nil {
			t.Fatal(err)
		}
		sess, err := query.NewSession(v.Root, querytest.Guard)
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()
		r, err := query.Search(ctx, snap, sess, v.Dirs, q)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	before := search()
	p1 := derivedBytes(t, v.Root, "certs.p1.parquet")

	derivetest.Use(t, "v2")
	w := querytest.Open(t, v, 1000)
	start, turns, slowest := time.Now(), 0, time.Duration(0)
	for pending := true; pending; {
		t0 := time.Now()
		st, p, err := w.RebuildTurn(ctx, 1)
		if err != nil {
			t.Fatal(err)
		}
		pending, turns = p, turns+st.Batches
		slowest = max(slowest, time.Since(t0))
	}
	side := time.Since(start)
	p2 := derivedBytes(t, v.Root, "certs.p2.parquet")
	t.Logf("side by side: %d batches in %v (slowest turn %v); certs v1 %d MiB, v2 %d MiB: peak %d MiB of certs beside each other",
		turns, side.Round(time.Millisecond), slowest.Round(time.Millisecond), p1>>20, p2>>20, (p1+p2)>>20)
	w.Close()
	if after := search(); fmt.Sprint(after.Rows) != fmt.Sprint(before.Rows) || len(before.Rows) == 0 {
		t.Fatalf("search after the upgrade: %d rows, %d before", len(after.Rows), len(before.Rows))
	}
	if r := run(t, fullOptions(t, v.Root)); r.Damaged() || r.Check("index").Status != StatusOK {
		t.Fatalf("verify after the upgrade:\n%s", text(r))
	}
	w = querytest.Open(t, v, 1000)
	st, err := w.RetireOld(true)
	if err != nil || st.Files != 10 {
		t.Fatalf("gc: %+v %v", st, err)
	}
	w.Close()
	t.Logf("gc: retired %d files, %d MiB freed", st.Files, st.Bytes>>20)
	if r := run(t, fullOptions(t, v.Root)); r.Damaged() {
		t.Fatalf("verify after gc:\n%s", text(r))
	}

	// In place, on a second copy of the sample (registry back to v1 first).
	restore := derive.SetRegistry([]derive.Versions{{Current: derive.Certs{}}, {Current: derive.Names{}}})
	v2 := querytest.FromSample(t, s, s.Manifest.Count, 10000)
	restore()
	w = querytest.Open(t, v2, 1000)
	if err := w.StartInPlace(); err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	if _, err := w.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	w.Close()
	t.Logf("in place: 10 batches in %v; certs v2 %d MiB, no v1 left", time.Since(start).Round(time.Millisecond), derivedBytes(t, v2.Root, "certs.p2.parquet")>>20)
	if ps, _ := filepath.Glob(filepath.Join(v2.Root, "dataset", "log=*", "batch=*", "certs.p1.parquet")); len(ps) != 0 {
		t.Fatalf("v1 files remain: %d", len(ps))
	}
	if r := run(t, fullOptions(t, v2.Root)); r.Damaged() {
		t.Fatalf("verify after the in-place conversion:\n%s", text(r))
	}
}
