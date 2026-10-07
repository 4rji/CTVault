package ingest

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/derivetest"
)

// upgraded is a vault of 3 batches carried from certs v1 to v2 at now.
func upgraded(t *testing.T, now *time.Time) *harness {
	t.Helper()
	h := newHarness(t, entries(t, 150), ctlogtest.Options{})
	h.opts.Now = func() time.Time { return *now }
	w := h.open()
	h.ingest(w, h.head(), 0, 150, 50)
	w.Close()
	derivetest.Use(t, "v2")
	w = h.open()
	if _, err := w.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return h
}

func p1Files(t *testing.T, root string) int {
	t.Helper()
	ps, _ := filepath.Glob(filepath.Join(root, "dataset", "log=*", "batch=*", "certs.p1.parquet"))
	return len(ps)
}

// TestRetireOld: the replaced version's files stay for 24 hours after the
// switch, then a writer retires them, clears retiring, and the vault reads
// as before; gc does it at once (amendment A5 §9).
func TestRetireOld(t *testing.T) {
	t.Run("24 hours", retireAfterGrace)
	t.Run("gc", retireNow)
}

func retireAfterGrace(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	h := upgraded(t, &now)
	if p1Files(t, h.root) != 3 {
		t.Fatal("the switch deleted the old files")
	}
	now = now.Add(23 * time.Hour)
	w := h.open() // a writer start checks the 24 hours
	if p1Files(t, h.root) != 3 || w.Active().Tables["certs"].Retiring == nil {
		t.Fatal("retired before 24 hours")
	}
	st, err := w.RetireOld(false)
	if err != nil || st.Files != 0 {
		t.Fatalf("before 24 hours: %+v %v", st, err)
	}
	w.Close()
	now = now.Add(2 * time.Hour)
	w = h.open()
	if p1Files(t, h.root) != 0 {
		t.Fatal("a writer started 25 hours after the switch kept the old files")
	}
	if s := w.Active().Tables["certs"]; s.Retiring != nil || s.SwitchedAt != nil || *s.Active != 2 {
		t.Fatalf("after the retirement: %+v", s)
	}
	for _, m := range w.committed {
		if _, ok := m.Listed("certs.p1.parquet"); ok || !m.Retired("certs.p1.parquet") {
			t.Fatalf("batch %s still lists certs v1", m.BatchID)
		}
	}
	w.Close()
	if ms, err := commit.ListCommitted(h.root); err != nil || len(ms) != 3 {
		t.Fatalf("listing after the retirement: %v", err)
	}

}

// retireNow: gc retires at once, whatever the time.
func retireNow(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	h2 := upgraded(t, &now)
	w := h2.open()
	st, err := w.RetireOld(true)
	if err != nil || st.Files != 3 || st.Bytes == 0 || len(st.Tables) != 1 || st.Tables[0] != "certs v1" {
		t.Fatalf("gc: %+v %v", st, err)
	}
	if p1Files(t, h2.root) != 0 || w.Active().Tables["certs"].Retiring != nil {
		t.Fatal("gc left the old files")
	}
	if st, err := w.RetireOld(true); err != nil || st.Files != 0 {
		t.Fatalf("gc twice: %+v %v", st, err)
	}
	if _, err := os.Stat(filepath.Join(h2.root, "dataset", "ACTIVE.json")); err != nil {
		t.Fatal(err)
	}
}
