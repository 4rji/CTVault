package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomicCreatesAndReplaces(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "VAULT_ID")
	if err := WriteFileAtomic(p, []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(p, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "second" {
		t.Fatalf("content = %q, want %q", got, "second")
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("perm = %v, want 0600", fi.Mode().Perm())
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("temp files left behind: %v", ents)
	}
}

func TestWriteFileAtomicMissingDirFailsCleanly(t *testing.T) {
	err := WriteFileAtomic(filepath.Join(t.TempDir(), "nope", "f"), []byte("x"), 0o644)
	if err == nil {
		t.Fatal("expected error for missing parent directory")
	}
}

func TestMkdirAllSync(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, "state", "intent")
	if err := MkdirAllSync(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
		t.Fatalf("directory not created: %v", err)
	}
	if err := MkdirAllSync(d, 0o755); err != nil {
		t.Fatalf("second call must be a no-op: %v", err)
	}
	f := filepath.Join(root, "file")
	os.WriteFile(f, nil, 0o644)
	if err := MkdirAllSync(f, 0o755); err == nil {
		t.Fatal("expected error when a file occupies the path")
	}
}

// TestIsAtomicTemp: only the names WriteFileAtomic creates match.
func TestIsAtomicTemp(t *testing.T) {
	dir := t.TempDir()
	f, err := os.CreateTemp(dir, "."+"ID_FLOOR"+".tmp-*") // the pattern WriteFileAtomic uses
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	for name, want := range map[string]bool{
		filepath.Base(f.Name()): true, ".views.sql.tmp-12": true, ".a.json.tmp-0": true,
		"views.sql": false, ".tmp-12": false, ".x.tmp-": false, ".x.tmp-12a": false, "x.tmp-12": false, ".hidden": false,
	} {
		if IsAtomicTemp(name) != want {
			t.Errorf("IsAtomicTemp(%q) = %v", name, !want)
		}
	}
}
