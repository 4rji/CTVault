package commit_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/derivetest"
	"github.com/4rji/ctvault/internal/ingest"
	"github.com/4rji/ctvault/internal/vaulttest"
)

// TestTransitionCrashes kills transitions at their crash points (amendment
// A5 §11): an upgrade during a rebuild turn (staged, placed) and before and
// after its switch; an in-place conversion while staging, after placing and
// between its _DERIVED.json and its delete; gc between a retirement's
// record and its delete. Each kill recovers, and the rerun ends with the
// same vault as an uninterrupted run.
func TestTransitionCrashes(t *testing.T) {
	if testing.Short() {
		t.Skip("starts subprocesses")
	}
	l := ctlogtest.New(t, crashEntries, ctlogtest.Options{})
	base := newCrashRun(t, l, crashEntries, crashBatch)
	if base.child("", 0, 0) {
		t.Fatal("the ingest child was killed")
	}
	base.restart()
	derivetest.Use(t, "v2") // this process opens the vault as the v2 binary does

	type result struct {
		run  *crashRun
		dump vaulttest.Content
		sums []string
	}
	reference := func(from *crashRun, mode string) result {
		r := copyRun(t, from, l)
		r.cfg.Mode, r.cfg.Registry = mode, "v2"
		if r.child("", 0, 0) {
			t.Fatalf("the uninterrupted %s was killed", mode)
		}
		r.restart()
		return result{r, r.v.Dump(t), derivedSums(t, r.v.Root)}
	}
	upgraded := reference(base, "rebuild")
	inPlace := reference(base, "inplace")
	gced := reference(upgraded.run, "gc")
	for _, want := range []result{inPlace, gced} {
		if ps, _ := filepath.Glob(filepath.Join(want.run.v.Root, "dataset", "log=*", "batch=*", "certs.p1.parquet")); len(ps) != 0 {
			t.Fatalf("certs v1 files remain after a conversion or gc: %v", ps)
		}
	}

	for _, c := range []struct {
		name  string
		from  *crashRun
		mode  string
		point string
		nth   int
		want  result
	}{
		{"upgrade staged", base, "rebuild", ingest.HookRebuildStaged, 2, upgraded},
		{"upgrade placed", base, "rebuild", ingest.HookRebuildPlaced, 3, upgraded},
		{"upgrade before switch", base, "rebuild", ingest.HookRebuildBeforeSwitch, 1, upgraded},
		{"upgrade after switch", base, "rebuild", ingest.HookRebuildAfterSwitch, 1, upgraded},
		{"in place staged", base, "inplace", ingest.HookRebuildStaged, 2, inPlace},
		{"in place placed", base, "inplace", ingest.HookRebuildPlaced, 2, inPlace},
		{"in place recorded", base, "inplace", commit.HookRetireRecorded, 2, inPlace},
		{"gc recorded", upgraded.run, "gc", commit.HookRetireRecorded, 2, gced},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := copyRun(t, c.from, l)
			r.t = t
			r.cfg.Mode, r.cfg.Registry = c.mode, "v2"
			if !r.child(c.point, c.nth, 0) {
				t.Fatalf("the %s finished without reaching %s #%d", c.mode, c.point, c.nth)
			}
			if c.point == commit.HookRetireRecorded && retiredButPresent(t, r.v.Root) == 0 {
				t.Fatal("killed after the retirement's record, yet no retired file is left: the file was deleted before it was recorded")
			}
			r.restart() // recovery, then spec §13.5's invariants
			if r.child("", 0, 0) {
				t.Fatal("the rerun was killed")
			}
			r.restart()
			if d := vaulttest.Diff(r.v.Dump(t), c.want.dump); d != "" {
				t.Fatal(d)
			}
			if got := derivedSums(t, r.v.Root); !slices.Equal(got, c.want.sums) {
				t.Fatalf("derived files %v, want %v", got, c.want.sums)
			}
		})
	}
}

// retiredButPresent counts the files a batch's _DERIVED.json retires that
// are still on disk: what a kill between record and delete leaves.
func retiredButPresent(t *testing.T, root string) int {
	t.Helper()
	ms, err := commit.ListCommitted(root)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, m := range ms {
		if m.Derived == nil {
			continue
		}
		for _, f := range m.Derived.Retired {
			if _, err := os.Stat(filepath.Join(commit.Paths{Root: root}.BatchDir(m.ID()), f)); err == nil {
				n++
			}
		}
	}
	return n
}
