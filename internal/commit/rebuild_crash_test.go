package commit_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/ingest"
	"github.com/4rji/ctvault/internal/vault"
	"github.com/4rji/ctvault/internal/vaulttest"
)

// reindexChild runs repair --reindex's work in a crash child.
func reindexChild(t *testing.T, root string, hook func(string)) {
	dirs := []string{filepath.Join(root, "vault")}
	codec, err := vault.NewCodec()
	if err != nil {
		t.Fatal(err)
	}
	defer codec.Close()
	dicts, err := vault.LoadDicts(dirs)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range dicts {
		codec.AddDict(d.Manifest.ID, d.Content)
	}
	stager, err := dataset.NewStager(dataset.Options{TempDir: t.TempDir(), MaxTempBytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	defer stager.Close()
	if _, err := commit.Reindex(commit.ReindexOptions{Paths: commit.Paths{Root: root}, VaultDirs: dirs, Codec: codec,
		ChainIDs: stager.ChainIDs, Hook: hook}); err != nil {
		t.Fatal(err)
	}
}

// copyRun copies a crash run's vault into a new run, for one crash point.
func copyRun(t *testing.T, from *crashRun, l *ctlogtest.Log) *crashRun {
	t.Helper()
	r := newCrashRun(t, l, from.cfg.End, from.cfg.BatchSize)
	err := filepath.WalkDir(from.v.Root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from.v.Root, p)
		dst := filepath.Join(r.v.Root, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	r.seen = r.v.Committed(t)
	return r
}

// derivedSums lists every batch's listed derived files and their checksums.
func derivedSums(t *testing.T, root string) []string {
	t.Helper()
	ms, err := commit.ListCommitted(root)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range ms {
		for _, b := range derive.Builders {
			fi, _ := m.Listed(b.Table().File())
			out = append(out, m.BatchID+" "+b.Table().File()+" "+fi.SHA256)
		}
	}
	return out
}

// noPartialView checks what a reader sees right after a kill: views.sql
// exposes certs only once ACTIVE.json says it is complete and every batch
// lists its file (amendment A2 §5.7: no view exposes a partial table).
func noPartialView(t *testing.T, root string) {
	t.Helper()
	views, _ := os.ReadFile(filepath.Join(root, dataset.ViewsFile))
	if !strings.Contains(string(views), "VIEW certs AS") {
		return
	}
	a, _, err := derive.ReadActive(root)
	if err != nil || !a.AllComplete() {
		t.Fatalf("views.sql exposes certs while ACTIVE.json is %+v (%v)", a, err)
	}
	ms, _ := commit.ListCommitted(root)
	for _, m := range ms {
		if _, ok := m.Listed(derive.CertsV1.File()); !ok {
			t.Fatalf("views.sql exposes certs, but batch %s lists no certs file", m.BatchID)
		}
	}
}

// TestRebuildCrashes kills a rebuild of a Plan 2 vault at each of its crash
// points (amendment A2 §5.7): during staging, after the files are placed and
// before _DERIVED.json, and before and after the ACTIVE.json switch. No view
// exposes a partial table, recovery removes the unlisted files, and the
// resumed rebuild ends with the same files as an uninterrupted rebuild of
// the same vault, whose rows equal an ingest with the builders on except
// for internal IDs and locations. (These vaults train a dictionary, and
// Plan 2's trainer is not deterministic, so two separately ingested vaults
// hold different record bytes; ingest-against-rebuild byte equivalence is
// tested without training in internal/ingest and on real data.)
func TestRebuildCrashes(t *testing.T) {
	if testing.Short() {
		t.Skip("starts subprocesses")
	}
	l := ctlogtest.New(t, crashEntries, ctlogtest.Options{})
	ref := newCrashRun(t, l, crashEntries, crashBatch)
	if ref.child("", 0, 0) {
		t.Fatal("the reference child was killed")
	}
	ref.restart()
	want := ref.v.Dump(t)

	base := newCrashRun(t, l, crashEntries, crashBatch)
	base.cfg.NoDerived = true
	if base.child("", 0, 0) {
		t.Fatal("the Plan 2 child was killed")
	}
	os.Remove(filepath.Join(base.v.Root, "dataset", derive.ActiveFile)) // as Plan 2 left it
	base.restart()
	base.cfg.NoDerived = false
	whole := copyRun(t, base, l)
	whole.cfg.Mode = "rebuild"
	if whole.child("", 0, 0) {
		t.Fatal("the uninterrupted rebuild was killed")
	}
	whole.restart()
	wantSums := derivedSums(t, whole.v.Root)
	if d := vaulttest.Diff(whole.v.Dump(t), want); d != "" {
		t.Fatalf("an uninterrupted rebuild differs from an ingest with the builders on: %s", d)
	}

	for _, p := range []struct {
		point string
		nth   int
	}{
		{ingest.HookRebuildStaged, 2},
		{ingest.HookRebuildPlaced, 3},
		{ingest.HookRebuildBeforeSwitch, 1},
		{ingest.HookRebuildAfterSwitch, 1},
	} {
		t.Run(p.point, func(t *testing.T) {
			r := copyRun(t, base, l)
			r.t = t
			r.cfg.Mode = "rebuild"
			if !r.child(p.point, p.nth, 0) {
				t.Fatalf("the rebuild finished without reaching %s #%d", p.point, p.nth)
			}
			noPartialView(t, r.v.Root)
			r.restart()
			noPartialView(t, r.v.Root)
			if r.child("", 0, 0) {
				t.Fatal("the resumed rebuild was killed")
			}
			r.restart()
			if a, _, _ := derive.ReadActive(r.v.Root); !a.AllComplete() {
				t.Fatalf("after the resumed rebuild: %+v", a)
			}
			if got := derivedSums(t, r.v.Root); !slices.Equal(got, wantSums) {
				t.Fatalf("the resumed rebuild's files differ from an uninterrupted rebuild's:\n%s\nwant\n%s",
					strings.Join(got, "\n"), strings.Join(wantSums, "\n"))
			}
			if d := vaulttest.Diff(r.v.Dump(t), want); d != "" {
				t.Fatal(d)
			}
		})
	}
}

// TestReindexCrashes kills repair --reindex during the build, after the
// sync and after the exchange (amendment A2 §5.7). Each kill leaves a
// usable index; the next start removes state/pebble.reindex, and a rerun
// completes.
func TestReindexCrashes(t *testing.T) {
	if testing.Short() {
		t.Skip("starts subprocesses")
	}
	l := ctlogtest.New(t, crashEntries, ctlogtest.Options{})
	base := newCrashRun(t, l, crashEntries, crashBatch)
	if base.child("", 0, 0) {
		t.Fatal("the ingest child was killed")
	}
	base.restart()
	want := base.v.Dump(t)
	for _, point := range []string{commit.HookReindexBuilding, commit.HookReindexSynced, commit.HookReindexExchanged} {
		t.Run(point, func(t *testing.T) {
			r := copyRun(t, base, l)
			r.t = t
			r.cfg.Mode = "reindex"
			if !r.child(point, 1, 0) {
				t.Fatalf("repair --reindex finished without reaching %s", point)
			}
			if _, err := os.Stat(filepath.Join(r.v.Root, "state", commit.ReindexDir)); err != nil {
				t.Fatalf("the kill left no state/%s: %v", commit.ReindexDir, err)
			}
			r.restart() // CheckRecovered: state/pebble matches the vault, no state/pebble.reindex
			if r.child("", 0, 0) {
				t.Fatal("the rerun was killed")
			}
			r.restart()
			if d := vaulttest.Diff(r.v.Dump(t), want); d != "" {
				t.Fatal(d)
			}
		})
	}
}
