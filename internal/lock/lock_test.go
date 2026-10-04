package lock

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestAcquireIsExclusiveAndNamesHolder(t *testing.T) {
	p := filepath.Join(t.TempDir(), "LOCK")
	a, err := Acquire(p)
	if err != nil {
		t.Fatal(err)
	}
	// flock locks belong to open file descriptions, so a second open in the
	// same process conflicts exactly like a second process would.
	_, err = Acquire(p)
	if !errors.Is(err, ErrHeld) {
		t.Fatalf("second Acquire: want ErrHeld, got %v", err)
	}
	if !strings.Contains(err.Error(), "PID "+strconv.Itoa(os.Getpid())) {
		t.Fatalf("error should name the holder PID: %v", err)
	}
	if err := a.Release(); err != nil {
		t.Fatal(err)
	}
	b, err := Acquire(p)
	if err != nil {
		t.Fatalf("Acquire after Release: %v", err)
	}
	b.Release()
}

func TestAcquireMissingDirectory(t *testing.T) {
	if _, err := Acquire(filepath.Join(t.TempDir(), "state", "LOCK")); err == nil {
		t.Fatal("expected error when state/ does not exist")
	}
}
