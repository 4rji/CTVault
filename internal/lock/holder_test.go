package lock

import (
	"os"
	"path/filepath"
	"testing"
)

// TestHolder: Holder names the process holding the writer lock, reading
// /proc/locks, and never writes the lock file (amendment A5 §1).
func TestHolder(t *testing.T) {
	p := filepath.Join(t.TempDir(), "LOCK")
	if pid, held, err := Holder(p); err != nil || held || pid != 0 {
		t.Fatalf("no lock file: %d %v %v", pid, held, err)
	}
	a, err := Acquire(p)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(p)
	pid, held, err := Holder(p)
	if err != nil || !held || pid != os.Getpid() {
		t.Fatalf("held by this process: %d %v %v", pid, held, err)
	}
	if after, _ := os.Stat(p); !after.ModTime().Equal(before.ModTime()) || after.Size() != before.Size() {
		t.Fatal("Holder wrote the lock file")
	}
	a.Release()
	if _, held, err := Holder(p); err != nil || held {
		t.Fatalf("released: %v %v", held, err)
	}
}
