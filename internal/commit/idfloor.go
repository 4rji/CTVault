// Package commit implements the batch commit protocol and recovery (spec §8)
// and the cert_id allocator with its durable high-water mark, ID_FLOOR
// (spec §8.6, amendment A1 §7).
package commit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/4rji/ctvault/internal/fsutil"
)

// ID_FLOOR reservation (amendment A1 §7): blocks of 65,536 IDs, and the next
// block is reserved durably once fewer than 32,768 reserved IDs remain.
const (
	IDBlock    = 65536
	IDLowWater = 32768
	idFile     = "ID_FLOOR"
)

// ErrCorrupt means committed state cannot be read safely (spec §12: exit 5).
var ErrCorrupt = errors.New("corrupt vault state")

// Hook points the allocator passes to its hook (tests only).
const (
	HookIDFloorBeforeAdvance = "idfloor.before_advance"
	HookIDFloorAfterAdvance  = "idfloor.after_advance"
)

// IDs hands out cert_ids. Every ID it returns is below the durable
// ID_FLOOR, so after a crash every ID that may have been assigned is below
// it, and IDs are never reused (spec §8.6). Not safe for concurrent use.
type IDs struct {
	path  string
	next  uint64
	floor uint64
	hook  func(string)
}

// ReadFloor reads state/ID_FLOOR; a missing file is 0 (a fresh vault).
func ReadFloor(stateDir string) (uint64, error) {
	b, err := os.ReadFile(filepath.Join(stateDir, idFile))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %s is not a number", ErrCorrupt, idFile)
	}
	return v, nil
}

// LoadIDs starts the allocator at next. Callers pass the committed
// next_cert_id after a clean shutdown, or the floor after a crash.
func LoadIDs(stateDir string, next uint64, hook func(string)) (*IDs, error) {
	floor, err := ReadFloor(stateDir)
	if err != nil {
		return nil, err
	}
	return &IDs{path: filepath.Join(stateDir, idFile), next: max(next, 1), floor: floor, hook: hook}, nil
}

// Floor returns the durable high-water mark.
func (a *IDs) Floor() uint64 { return a.floor }

// Peek returns the next ID Next would return.
func (a *IDs) Peek() uint64 { return a.next }

// SkipToFloor makes the next ID the floor: IDs an abandoned attempt may have
// touched are never handed out again.
func (a *IDs) SkipToFloor() { a.next = max(a.next, a.floor) }

// Raise lifts the floor durably to at least v, for example above the
// highest cert_id found beyond the committed tail during recovery.
func (a *IDs) Raise(v uint64) error {
	if v <= a.floor {
		return nil
	}
	return a.write(v)
}

func (a *IDs) write(v uint64) error {
	if a.hook != nil {
		a.hook(HookIDFloorBeforeAdvance)
	}
	if err := fsutil.WriteFileAtomic(a.path, []byte(strconv.FormatUint(v, 10)+"\n"), 0o644); err != nil {
		return err
	}
	a.floor = v
	if a.hook != nil {
		a.hook(HookIDFloorAfterAdvance)
	}
	return nil
}

// Next returns a fresh cert_id, first reserving the next block durably when
// fewer than IDLowWater reserved IDs remain.
func (a *IDs) Next() (uint64, error) {
	if a.floor < a.next+IDLowWater {
		if err := a.write(max(a.floor, a.next) + IDBlock); err != nil {
			return 0, fmt.Errorf("advancing ID_FLOOR: %w", err)
		}
	}
	id := a.next
	a.next++
	return id, nil
}
