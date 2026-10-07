package index

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/vault"
)

// snapshotDir maps each file in dir to its size and modification time.
func snapshotDir(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			out[p] = fmt.Sprint(fi.ModTime().Format(time.RFC3339Nano), " ", fi.Size())
		}
		return nil
	})
	return out
}

// TestOpenReadOnly: verify reads the writer's index without changing a
// file of it (amendment A5 §2.2), even with an unflushed write-ahead log;
// only Pebble's empty LOCK file is re-created.
func TestOpenReadOnly(t *testing.T) {
	dir := t.TempDir()
	x, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	sha, ref := [32]byte{1}, Ref{CertID: 5, Loc: vault.Loc{Segment: 1, Offset: 64, Len: 99}}
	b := x.NewBatch()
	b.AddCert(sha, ref)
	b.AddChain([32]byte{2})
	b.SetApplied("fakelog", 3)
	if err := b.Commit(); err != nil {
		t.Fatal(err)
	}
	b.Close()
	x.Close()

	before := snapshotDir(t, dir)
	ro, err := OpenReadOnly(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := ro.Lookup(sha)
	applied, _ := ro.Applied("fakelog")
	chains := 0
	ro.EachChain(func([32]byte) error { chains++; return nil })
	if err != nil || !ok || got != ref || applied != 3 || chains != 1 {
		t.Fatalf("read-only lookups: %+v %v %v, applied %d, %d chains", got, ok, err, applied, chains)
	}
	if err := ro.Close(); err != nil {
		t.Fatal(err)
	}
	after := snapshotDir(t, dir)
	for p, v := range after {
		// Pebble re-creates its empty LOCK file to lock it: the time
		// changes, never the content.
		if filepath.Base(p) == "LOCK" && strings.HasSuffix(v, " 0") && strings.HasSuffix(before[p], " 0") {
			continue
		}
		if before[p] != v {
			t.Errorf("%s was written or created (before %q, after %q)", filepath.Base(p), before[p], v)
		}
	}
	if len(after) != len(before) {
		t.Errorf("%d files before, %d after", len(before), len(after))
	}
	if _, err := OpenReadOnly(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a missing index opens")
	}
}
