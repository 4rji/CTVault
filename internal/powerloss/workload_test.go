package powerloss

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/4rji/ctvault/internal/derive"
)

// copyTree copies a vault folder, as a crash point's image holds it.
func copyTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		dst := filepath.Join(to, rel)
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
}

// TestWorkload: the four phases run on a fresh vault without root, and
// each leaves what it should: a trained dictionary and rolled segments,
// certs v2 active, no v1 file, a replaced index. A copy taken at every
// mark passes Inspect and the checks across points, in order (amendment
// A5 §14, §15).
func TestWorkload(t *testing.T) {
	root := filepath.Join(t.TempDir(), "vault")
	snaps := t.TempDir()
	var marks []string
	res, err := Workload(t, root, func(phase string) error {
		marks = append(marks, phase)
		if phase != "setup" { // no vault yet
			copyTree(t, root, filepath.Join(snaps, phase))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(marks, []string{"setup", "ingest", "upgrade", "gc", "reindex", "end"}) {
		t.Fatalf("marks %v", marks)
	}
	if res.Batches != 14 || len(res.Committed) != 14 {
		t.Fatalf("result %+v", res)
	}
	dicts, _ := filepath.Glob(filepath.Join(root, "vault", "dict", "*"))
	segs, _ := filepath.Glob(filepath.Join(root, "vault", "segments", "*.seg"))
	p1, _ := filepath.Glob(filepath.Join(root, "dataset", "log=*", "batch=*", "certs.p1.parquet"))
	if len(dicts) == 0 || len(segs) < 2 || len(p1) != 0 {
		t.Fatalf("%d dictionary files, %d segments, %d certs v1 files", len(dicts), len(segs), len(p1))
	}
	a, _, _ := derive.ReadActive(root)
	if s := a.Tables["certs"]; s.Active == nil || *s.Active != 2 || s.Retiring != nil {
		t.Fatalf("certs after the workload: %+v", s)
	}
	if _, err := os.Stat(filepath.Join(root, "state", "pebble.reindex")); !os.IsNotExist(err) {
		t.Fatal("the reindex left its folder")
	}

	var tr Tracker
	for _, phase := range append(marks[1:], "") { // at "setup" there is no vault yet
		dir := root
		if phase != "" {
			dir = filepath.Join(snaps, phase)
		}
		p, err := Inspect(context.Background(), WriterOptions(dir))
		if err != nil {
			t.Fatalf("at %q: %v", phase, err)
		}
		if err := tr.Compare(p); err != nil {
			t.Fatalf("at %q: %v", phase, err)
		}
	}
	if !slices.Equal(tr.Committed(), res.Committed) {
		t.Fatalf("committed %v, the workload says %v", tr.Committed(), res.Committed)
	}
}
