package ingest

import (
	"testing"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/derivetest"
	"github.com/4rji/ctvault/internal/diskguard"
)

// TestInPlace: rebuild --in-place converts each batch from v1 to v2 with
// one _DERIVED.json write that lists v2 and retires v1, so no batch is
// ever without one of them; the table is mixed meanwhile, new batches build
// only v2, and the last turn makes v2 complete with nothing to retire
// (amendment A5 §10).
func TestInPlace(t *testing.T) {
	h := newHarness(t, entries(t, 200), ctlogtest.Options{})
	w := h.open()
	sth := h.head()
	h.ingest(w, sth, 0, 150, 50)
	w.Close()

	derivetest.Use(t, "v2")
	h.opts.Guard = diskguard.Guard{Cap: 0.85, Stat: func(string) (diskguard.Usage, error) {
		return diskguard.Usage{Total: 100 << 20, Avail: 15 << 20, Dev: 1}, nil // no room side by side
	}}
	w = h.open()
	if len(w.Warnings()) != 1 {
		t.Fatalf("warnings %v", w.Warnings())
	}
	if err := w.StartInPlace(); err != nil {
		t.Fatal(err)
	}
	if s := w.Active().Tables["certs"]; s.Status != derive.StatusMixed || *s.Active != 1 || *s.Building != 2 {
		t.Fatalf("after StartInPlace: %+v", s)
	}
	if _, pending, err := w.RebuildTurn(ctx, 1); err != nil || !pending {
		t.Fatalf("the first turn: %v %v", pending, err)
	}
	ms, _ := commit.ListCommitted(h.root)
	has := func(m commit.Manifest, f string) bool { _, ok := m.Listed(f); return ok }
	if !has(ms[0], "certs.p2.parquet") || has(ms[0], "certs.p1.parquet") || !ms[0].Retired("certs.p1.parquet") {
		t.Fatalf("the oldest batch after one turn: %+v", ms[0].Derived)
	}
	if !has(ms[1], "certs.p1.parquet") || has(ms[1], "certs.p2.parquet") {
		t.Fatal("a turn converted more than one batch")
	}
	// Room again: a later writer keeps the conversion in place, and new
	// batches build only v2.
	w.Close()
	h.opts.Guard = diskguard.Guard{Cap: 0.85, Stat: func(string) (diskguard.Usage, error) {
		return diskguard.Usage{Total: 1 << 40, Avail: 1 << 39, Dev: 1}, nil
	}}
	w = h.open()
	if s := w.Active().Tables["certs"]; s.Status != derive.StatusMixed {
		t.Fatalf("a later writer changed the conversion: %+v", s)
	}
	nb := h.ingest(w, sth, 150, 200, 50)
	if has(nb[0], "certs.p1.parquet") || !has(nb[0], "certs.p2.parquet") {
		t.Fatal("a batch ingested while mixed should build only v2")
	}
	st, pending, err := w.RebuildTurn(ctx, 10)
	if err != nil || pending || !st.Switched {
		t.Fatalf("the last turns: %+v %v %v", st, pending, err)
	}
	if s := w.Active().Tables["certs"]; s.Status != derive.StatusComplete || *s.Active != 2 || s.Retiring != nil || s.Building != nil {
		t.Fatalf("after the conversion: %+v", s)
	}
	ms, err = commit.ListCommitted(h.root)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if !has(m, "certs.p2.parquet") || has(m, "certs.p1.parquet") {
			t.Fatalf("batch %s after the conversion", m.BatchID)
		}
	}
	if p1Files(t, h.root) != 0 {
		t.Fatal("v1 files remain")
	}
}

// TestInPlaceAfterSideBySide: an upgrade started side by side can finish in
// place: batches that already hold both versions only retire v1.
func TestInPlaceAfterSideBySide(t *testing.T) {
	h := newHarness(t, entries(t, 100), ctlogtest.Options{})
	w := h.open()
	h.ingest(w, h.head(), 0, 100, 50)
	w.Close()
	derivetest.Use(t, "v2")
	w = h.open()
	if _, _, err := w.RebuildTurn(ctx, 1); err != nil { // batch 1 now has both
		t.Fatal(err)
	}
	if err := w.StartInPlace(); err != nil {
		t.Fatal(err)
	}
	st, pending, err := w.RebuildTurn(ctx, 10)
	if err != nil || pending || st.Batches != 2 || *w.Active().Tables["certs"].Active != 2 || p1Files(t, h.root) != 0 {
		t.Fatalf("finishing in place: %+v %v %v; %+v", st, pending, err, w.Active().Tables["certs"])
	}
}
