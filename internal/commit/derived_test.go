package commit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

func sampleDerived(id BatchID) Derived {
	return Derived{Format: DerivedFormat, BatchID: id.String(), CTVaultVersion: "test",
		Tables: map[string]DerivedTable{
			"names": {Version: 1, File: "names.p1.parquet", Bytes: 3, Rows: 2, SHA256: "bb", Extractor: "x/1", SchemaSHA256: "s2", PSL: "psl"},
			"certs": {Version: 1, File: "certs.p1.parquet", Bytes: 4, Rows: 1, SHA256: "aa", Extractor: "x/1", SchemaSHA256: "s1"},
		},
		ParseStatus: map[string]int{"ok": 1}}
}

// TestDerivedManifest: _DERIVED.json round-trips, is byte-identical when
// written again (fixed key order, no timestamps), and is refused when its
// checksum fails or it names another batch (amendment A2 §5.3).
func TestDerivedManifest(t *testing.T) {
	dir := t.TempDir()
	id := BatchID{Log: "fakelog", First: 0, Last: 9}
	if _, ok, err := ReadDerived(dir, id); ok || err != nil {
		t.Fatalf("no _DERIVED.json: ok %v, %v", ok, err)
	}
	if err := WriteDerived(dir, sampleDerived(id)); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(filepath.Join(dir, DerivedFile))
	d, ok, err := ReadDerived(dir, id)
	if err != nil || !ok || d.Checksum == "" || d.Tables["certs"].SHA256 != "aa" || d.ParseStatus["ok"] != 1 {
		t.Fatalf("read back %+v, ok %v, %v", d, ok, err)
	}
	if err := WriteDerived(dir, sampleDerived(id)); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(filepath.Join(dir, DerivedFile)); !bytes.Equal(first, again) {
		t.Fatalf("written twice, the bytes differ:\n%s\n%s", first, again)
	}
	if _, _, err := ReadDerived(dir, BatchID{Log: "fakelog", First: 10, Last: 19}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("another batch's _DERIVED.json: %v", err)
	}
	os.WriteFile(filepath.Join(dir, DerivedFile), bytes.Replace(first, []byte(`"aa"`), []byte(`"ab"`), 1), 0o644)
	if _, _, err := ReadDerived(dir, id); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a changed _DERIVED.json: %v", err)
	}
}

// commitWithDerived commits one batch and gives it a _DERIVED.json listing
// a derived file it writes.
func commitWithDerived(t *testing.T, e *env) Manifest {
	t.Helper()
	m, _, _ := e.batch(0, 10, e.ids(1), 1, merkle.NewState(), vault.Tail{}, "done")
	dir := e.p.BatchDir(m.ID())
	os.WriteFile(filepath.Join(dir, "certs.p1.parquet"), []byte("cert"), 0o644)
	d := sampleDerived(m.ID())
	delete(d.Tables, "names")
	if err := WriteDerived(dir, d); err != nil {
		t.Fatal(err)
	}
	return m
}

// TestListCommittedReadsDerived: committed batches carry their
// _DERIVED.json, whose files must exist with their recorded sizes.
func TestListCommittedReadsDerived(t *testing.T) {
	e := newEnv(t)
	m := commitWithDerived(t, e)
	ms, err := ListCommitted(e.p.Root)
	if err != nil || len(ms) != 1 || ms[0].Derived == nil || ms[0].Derived.Tables["certs"].File != "certs.p1.parquet" {
		t.Fatalf("%+v %v", ms, err)
	}
	if fi, ok := ms[0].Listed("certs.p1.parquet"); !ok || fi.Bytes != 4 {
		t.Fatalf("certs.p1.parquet listed: %+v %v", fi, ok)
	}
	if _, ok := ms[0].Listed("names.p1.parquet"); ok {
		t.Fatal("names.p1.parquet is listed by nothing")
	}
	os.WriteFile(filepath.Join(e.p.BatchDir(m.ID()), "certs.p1.parquet"), []byte("ce"), 0o644)
	if _, err := ListCommitted(e.p.Root); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a derived file with the wrong size: %v", err)
	}
}

// TestRecoverRemovesUnlistedDerivedFiles: recovery deletes derived files
// that neither _COMMIT.json nor _DERIVED.json lists, and the leftovers of an
// interrupted _DERIVED.json write and of repair --reindex; listed files and
// files that are not derived stay (amendment A2 §5.5).
func TestRecoverRemovesUnlistedDerivedFiles(t *testing.T) {
	e := newEnv(t)
	m := commitWithDerived(t, e)
	dir := e.p.BatchDir(m.ID())
	for _, name := range []string{"names.p1.parquet", "certs.p2.parquet", "._DERIVED.json.tmp-123", "notes.txt"} {
		os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644)
	}
	os.MkdirAll(filepath.Join(e.p.StateDir(), ReindexDir), 0o755)
	os.WriteFile(filepath.Join(e.p.StateDir(), ReindexDir, "000001.log"), []byte("x"), 0o644)
	e.recover()
	for name, want := range map[string]bool{"certs.p1.parquet": true, "names.p1.parquet": false, "certs.p2.parquet": false,
		"._DERIVED.json.tmp-123": false, "notes.txt": true, DerivedFile: true, ManifestFile: true} {
		if _, err := os.Stat(filepath.Join(dir, name)); (err == nil) != want {
			t.Errorf("%s: present=%v, want %v", name, err == nil, want)
		}
	}
	if _, err := os.Stat(filepath.Join(e.p.StateDir(), ReindexDir)); err == nil {
		t.Error("state/pebble.reindex survived recovery")
	}
}
