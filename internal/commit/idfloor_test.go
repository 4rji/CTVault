package commit

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestIDsStayBelowTheDurableFloor checks the spec §8.6 invariant for every
// ID handed out: a crash at any moment leaves every assigned ID below the
// floor on disk.
func TestIDsStayBelowTheDurableFloor(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadIDs(dir, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := uint64(1); i <= 100_000; i++ { // three reservations
		id, err := a.Next()
		if err != nil {
			t.Fatal(err)
		}
		if id != i {
			t.Fatalf("IDs are sequential: got %d, want %d", id, i)
		}
		onDisk, err := ReadFloor(dir)
		if err != nil || id >= onDisk {
			t.Fatalf("id %d handed out with ID_FLOOR %d on disk", id, onDisk)
		}
		if onDisk-id < IDLowWater-1 {
			t.Fatalf("the next block must be reserved before fewer than %d IDs remain (id %d, floor %d)", IDLowWater, id, onDisk)
		}
	}
}

func TestReservationIsInBlocks(t *testing.T) {
	dir := t.TempDir()
	var advances int
	a, _ := LoadIDs(dir, 1, func(p string) {
		if p == HookIDFloorAfterAdvance {
			advances++
		}
	})
	for range 100_000 {
		a.Next()
	}
	// floor starts at 0: 1+65536, then +65536 each time fewer than 32768 remain.
	if advances != 3 || a.Floor() != 1+3*IDBlock {
		t.Fatalf("100,000 IDs take 3 reservations: %d, floor %d", advances, a.Floor())
	}
}

// TestRestartAfterCrashSkipsToFloor: IDs a lost attempt touched are never
// reused, while a clean restart continues from the committed next_cert_id.
func TestRestartAfterCrashSkipsToFloor(t *testing.T) {
	dir := t.TempDir()
	a, _ := LoadIDs(dir, 1, nil)
	for range 10 {
		a.Next()
	}
	floor := a.Floor()
	clean, _ := LoadIDs(dir, 11, nil) // committed next_cert_id after a clean commit
	if id, _ := clean.Next(); id != 11 {
		t.Fatalf("a clean restart continues at the committed next_cert_id: %d", id)
	}
	crashed, _ := LoadIDs(dir, 11, nil)
	crashed.SkipToFloor()
	if id, _ := crashed.Next(); id != floor {
		t.Fatalf("after a crash the next ID is the floor %d, got %d", floor, id)
	}
	if crashed.Floor() <= floor {
		t.Fatal("handing out the floor itself must reserve a new block first")
	}
}

func TestRaiseAndCorruptFloor(t *testing.T) {
	dir := t.TempDir()
	a, _ := LoadIDs(dir, 1, nil)
	if err := a.Raise(500_000); err != nil {
		t.Fatal(err)
	}
	if v, _ := ReadFloor(dir); v != 500_000 {
		t.Fatalf("Raise is durable: %d", v)
	}
	a.Raise(10) // never lowers
	if v, _ := ReadFloor(dir); v != 500_000 {
		t.Fatalf("ID_FLOOR only increases: %d", v)
	}
	os.WriteFile(filepath.Join(dir, idFile), []byte("garbage\n"), 0o644)
	if _, err := LoadIDs(dir, 1, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("an unreadable ID_FLOOR is corruption: %v", err)
	}
}
