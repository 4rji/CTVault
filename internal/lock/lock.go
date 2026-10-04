// Package lock implements the single-writer lock on <root>/state/LOCK
// (spec §8.1). Readers never take it.
package lock

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// ErrHeld means another process holds the writer lock.
var ErrHeld = errors.New("writer lock is held")

// Lock is a held writer lock.
type Lock struct {
	f *os.File
}

// Acquire takes the exclusive writer lock without blocking and records this
// process's PID in the lock file so a second writer can name the holder.
func Acquire(path string) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		holder := readPID(f)
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w by PID %s (%s)", ErrHeld, holder, path)
		}
		return nil, fmt.Errorf("locking %s: %w", path, err)
	}
	if err := writePID(f); err != nil {
		unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
		return nil, err
	}
	return &Lock{f: f}, nil
}

func writePID(f *os.File) error {
	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0); err != nil {
		return err
	}
	return f.Sync()
}

func readPID(f *os.File) string {
	b := make([]byte, 32)
	n, _ := f.ReadAt(b, 0)
	if s := strings.TrimSpace(string(b[:n])); s != "" {
		return s
	}
	return "unknown"
}

// Release drops the lock. The file stays behind with a stale PID, which is
// harmless: holding the flock, not the file content, is what counts.
func (l *Lock) Release() error {
	err := unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	return errors.Join(err, l.f.Close())
}
