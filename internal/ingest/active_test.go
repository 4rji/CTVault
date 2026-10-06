package ingest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/derive"
)

// TestActiveOnOpen: the writer settles ACTIVE.json at Open (amendment A2
// §4.6). A vault without batches has nothing to backfill and is complete; a
// vault written before Plan 3, with batches but no ACTIVE.json, starts
// building; an ACTIVE.json this binary cannot honour is refused.
func TestActiveOnOpen(t *testing.T) {
	h := newHarness(t, entries(t, 20), ctlogtest.Options{})
	w := h.open()
	if a, ok, err := derive.ReadActive(h.root); !ok || err != nil || !a.AllComplete() {
		t.Fatalf("a new vault: %+v %v %v", a, ok, err)
	}
	h.ingest(w, h.head(), 0, 20, 20)
	w.Close()

	os.Remove(filepath.Join(h.root, "dataset", derive.ActiveFile)) // a vault written before Plan 3
	w = h.open()
	a, _, _ := derive.ReadActive(h.root)
	if a.AllComplete() || a.Tables["certs"].Building == nil || *a.Tables["certs"].Building != 1 {
		t.Fatalf("a Plan 2 vault with batches: %+v", a)
	}
	views, _ := os.ReadFile(filepath.Join(h.root, "views.sql"))
	if !strings.Contains(string(views), "VIEW certs_building ") || strings.Contains(string(views), "VIEW certs ") {
		t.Fatalf("views.sql of a building vault:\n%s", views)
	}
	w.Close()

	two := 2
	a.Tables["certs"] = derive.TableState{Active: &two, Status: derive.StatusComplete}
	if err := derive.WriteActive(h.root, a); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(h.opts); err == nil || !strings.Contains(err.Error(), derive.ActiveFile) {
		t.Fatalf("an ACTIVE.json naming certs v2: %v", err)
	}
}
