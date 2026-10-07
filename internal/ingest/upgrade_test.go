package ingest

import (
	"strings"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/derivetest"
	"github.com/4rji/ctvault/internal/diskguard"
)

// TestUpgradeInTurns: a writer of a newer binary starts the upgrade; new
// batches build both versions; RebuildTurn rebuilds old batches, oldest
// first, as many as asked; the last turn switches the table, recording
// the old version as retiring (amendment A5 §8).
func TestUpgradeInTurns(t *testing.T) {
	h := newHarness(t, entries(t, 300), ctlogtest.Options{})
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	h.opts.Now = func() time.Time { return now }
	w := h.open()
	sth := h.head()
	h.ingest(w, sth, 0, 150, 50)
	w.Close()

	derivetest.Use(t, "v2")
	w = h.open()
	if st := w.Active().Tables["certs"]; st.Active == nil || *st.Active != 1 || st.Building == nil || *st.Building != 2 || st.Status != derive.StatusBuilding {
		t.Fatalf("the upgrade did not start: %+v", st)
	}
	if len(w.Warnings()) != 0 {
		t.Fatalf("warnings %v", w.Warnings())
	}
	ms := h.ingest(w, sth, 150, 200, 50)
	for _, f := range []string{"certs.p1.parquet", "certs.p2.parquet", "names.p1.parquet"} {
		if _, ok := ms[0].Listed(f); !ok {
			t.Fatalf("a batch ingested during the upgrade lacks %s", f)
		}
	}
	st, pending, err := w.RebuildTurn(ctx, 1)
	if err != nil || st.Batches != 1 || !pending {
		t.Fatalf("the first turn: %+v %v %v", st, pending, err)
	}
	var have []bool
	for _, m := range w.committed {
		_, ok := m.Listed("certs.p2.parquet")
		have = append(have, ok)
	}
	if !have[0] || have[1] || have[2] || !have[3] {
		t.Fatalf("after one turn, batches holding v2: %v (want the oldest and the new one)", have)
	}
	if prog := w.Upgrades(); len(prog) != 1 || prog[0].Table != "certs" || prog[0].Done != 2 || prog[0].Total != 4 {
		t.Fatalf("progress %+v", prog)
	}
	st, pending, err = w.RebuildTurn(ctx, 5)
	if err != nil || st.Batches != 2 || pending || !st.Switched {
		t.Fatalf("the last turn: %+v %v %v", st, pending, err)
	}
	c := w.Active().Tables["certs"]
	if c.Active == nil || *c.Active != 2 || c.Building != nil || c.Status != derive.StatusComplete ||
		c.Retiring == nil || *c.Retiring != 1 || c.SwitchedAt == nil || !c.SwitchedAt.Equal(now) {
		t.Fatalf("after the switch: %+v", c)
	}
	if st, pending, err := w.RebuildTurn(ctx, 1); err != nil || st.Batches != 0 || pending {
		t.Fatalf("a turn with nothing to do: %+v %v %v", st, pending, err)
	}
	w.Close()
	if w = h.open(); w.Active().Tables["certs"].Building != nil {
		t.Fatal("a later writer restarted the upgrade")
	}
}

// TestUpgradeNeedsRoom: when a side-by-side copy does not fit under the
// disk cap, the vault stays at the old version and the writer warns
// (amendment A5 §8).
func TestUpgradeNeedsRoom(t *testing.T) {
	h := newHarness(t, entries(t, 100), ctlogtest.Options{})
	w := h.open()
	h.ingest(w, h.head(), 0, 100, 50)
	w.Close()

	derivetest.Use(t, "v2")
	h.opts.Guard = diskguard.Guard{Cap: 0.85, Stat: func(string) (diskguard.Usage, error) {
		return diskguard.Usage{Total: 100 << 20, Avail: 15 << 20, Dev: 1}, nil // at the cap already
	}}
	w = h.open()
	if st := w.Active().Tables["certs"]; st.Building != nil || *st.Active != 1 {
		t.Fatalf("an upgrade started without room: %+v", st)
	}
	if ws := w.Warnings(); len(ws) != 1 || !strings.Contains(ws[0], "certs v2 needs") || !strings.Contains(ws[0], "rebuild --in-place") {
		t.Fatalf("warnings %v", ws)
	}
}

// TestRebuildFinishesAnUpgrade: rebuild alone does every old batch at once
// and switches.
func TestRebuildFinishesAnUpgrade(t *testing.T) {
	h := newHarness(t, entries(t, 100), ctlogtest.Options{})
	w := h.open()
	h.ingest(w, h.head(), 0, 100, 50)
	w.Close()
	derivetest.Use(t, "v2")
	w = h.open()
	st, err := w.Rebuild(ctx)
	if err != nil || st.Batches != 2 || !st.Switched || *w.Active().Tables["certs"].Active != 2 {
		t.Fatalf("rebuild: %+v %v; %+v", st, err, w.Active().Tables["certs"])
	}
}

// TestNewTableBackfilled: a binary that carries a new table adds it to
// ACTIVE.json as being built when it first opens a vault with batches; it
// is exposed only as <table>_building until the turns have filled every
// batch, then under its name (spec §7.8, A5 §7).
func TestNewTableBackfilled(t *testing.T) {
	h := newHarness(t, entries(t, 150), ctlogtest.Options{})
	w := h.open()
	h.ingest(w, h.head(), 0, 150, 50)
	w.Close()
	derivetest.Use(t, "new-table")
	w = h.open()
	if s := w.Active().Tables["flags"]; s.Active != nil || s.Building == nil || *s.Building != 1 || s.Status != derive.StatusBuilding {
		t.Fatalf("the new table: %+v", s)
	}
	if _, ok := w.Active().Readable("flags"); ok {
		t.Fatal("a table being built for the first time is readable")
	}
	st, pending, err := w.RebuildTurn(ctx, 10)
	if err != nil || pending || st.Batches != 3 || !st.Switched {
		t.Fatalf("backfilling: %+v %v %v", st, pending, err)
	}
	if s := w.Active().Tables["flags"]; *s.Active != 1 || s.Status != derive.StatusComplete || s.Retiring != nil {
		t.Fatalf("after the backfill: %+v", s)
	}
	w.Close()
	// A vault without batches gets it complete at once.
	h2 := newHarness(t, entries(t, 10), ctlogtest.Options{})
	w = h2.open()
	if s := w.Active().Tables["flags"]; s.Active == nil || s.Status != derive.StatusComplete {
		t.Fatalf("a new vault: %+v", s)
	}
}
