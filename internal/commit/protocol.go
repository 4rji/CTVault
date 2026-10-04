package commit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"golang.org/x/sys/unix"

	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

// Named commit boundaries for crash tests (spec §13.5); production passes a
// nil hook.
const (
	HookAfterIntent        = "commit.P1.after_intent"
	HookAfterManifest      = "commit.P7.after_manifest"
	HookBeforeRename       = "commit.P8.before_rename"
	HookAfterRename        = "commit.P8.after_rename"
	HookBeforeIntentDelete = "commit.P10.before_intent_delete"
)

func call(hook func(string), p string) {
	if hook != nil {
		hook(p)
	}
}

// Intent is state/intent/<batch>.json, written before a batch touches the
// vault (spec §8.3 P1).
type Intent struct {
	BatchID      string         `json:"batch_id"`
	Log          string         `json:"log"`
	First        uint64         `json:"first"`
	Last         uint64         `json:"last"`
	STH          STH            `json:"sth"`
	VaultTail    vault.Tail     `json:"vault_tail"`
	NextCertID   uint64         `json:"next_cert_id"`
	MerkleBefore *merkle.State  `json:"merkle_before"`
	Builders     map[string]int `json:"builders"`
	StartedAt    time.Time      `json:"started_at"`
	// Abandoned marks an attempt that was given up in process. The intent is
	// kept so the next start knows cert_ids were touched and resumes at
	// ID_FLOOR (spec §8.6); a later successful commit clears it.
	Abandoned bool `json:"abandoned,omitempty"`
}

// ID returns the intent's batch ID.
func (in Intent) ID() BatchID { return BatchID{Log: in.Log, First: in.First, Last: in.Last} }

// WriteIntent is P1: the intent file and its directory are fsynced.
func WriteIntent(p Paths, in Intent, hook func(string)) error {
	b, err := json.MarshalIndent(in, "", " ")
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(p.IntentPath(in.ID()), b, 0o644); err != nil {
		return err
	}
	call(hook, HookAfterIntent)
	return nil
}

// ReadIntents lists the intents left in state/intent/.
func ReadIntents(p Paths) ([]Intent, error) {
	dir := filepath.Join(p.StateDir(), "intent")
	names, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Intent
	for _, n := range names {
		if filepath.Ext(n.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, n.Name()))
		if err != nil {
			return nil, err
		}
		var in Intent
		if err := json.Unmarshal(b, &in); err != nil || in.ID().file()+".json" != n.Name() {
			return nil, corrupt("intent %s is unreadable", n.Name())
		}
		out = append(out, in)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BatchID < out[j].BatchID })
	return out, nil
}

// RemoveIntent is P10.
func RemoveIntent(p Paths, id BatchID, hook func(string)) error {
	call(hook, HookBeforeIntentDelete)
	if err := os.Remove(p.IntentPath(id)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return fsutil.SyncDir(filepath.Dir(p.IntentPath(id)))
}

// ErrPostCommit marks an error that happened after the commit point: the
// batch directory was renamed into dataset/, so the batch is committed and
// must never be abandoned; recovery finishes it at the next start.
var ErrPostCommit = errors.New("error after the commit point")

// Publish is P7 and P8: _COMMIT.json is written into the staged batch
// directory and fsynced, then the directory is renamed into dataset/ (the
// commit point) without replacing anything, and the parents are fsynced.
// Errors after the rename wrap ErrPostCommit.
func Publish(p Paths, m Manifest, hook func(string)) error {
	id := m.ID()
	stage := p.StageDir(id)
	b, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(stage, ManifestFile), b, 0o644); err != nil {
		return err
	}
	call(hook, HookAfterManifest)
	dest := p.BatchDir(id)
	if err := fsutil.MkdirAllSync(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	call(hook, HookBeforeRename)
	if err := unix.Renameat2(unix.AT_FDCWD, stage, unix.AT_FDCWD, dest, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("committing %s: %w", id, err)
	}
	call(hook, HookAfterRename)
	for _, d := range []string{filepath.Dir(dest), filepath.Dir(filepath.Dir(dest)), filepath.Dir(stage)} {
		if err := fsutil.SyncDir(d); err != nil {
			return fmt.Errorf("%w: %s: %v", ErrPostCommit, id, err)
		}
	}
	return nil
}

// Abandon discards an uncommitted batch in process (a failed verification or
// canary, a stall, a second signal): the vault is cut back to the batch's
// start and staging is deleted. The intent stays, marked abandoned, so that
// a restart skips the cert_ids the attempt touched. The caller must also
// discard the batch's Pebble writes and skip cert_ids to the floor.
func Abandon(p Paths, vaultDirs []string, in Intent) error {
	if err := vault.Truncate(vaultDirs, in.VaultTail); err != nil {
		return err
	}
	if err := os.RemoveAll(p.StageDir(in.ID())); err != nil {
		return err
	}
	in.Abandoned = true
	return WriteIntent(p, in, nil)
}

// ClearAbandoned removes abandoned intents once a later batch has committed:
// its cert_ids already start beyond theirs.
func ClearAbandoned(p Paths) error {
	ins, err := ReadIntents(p)
	if err != nil {
		return err
	}
	for _, in := range ins {
		if in.Abandoned {
			if err := RemoveIntent(p, in.ID(), nil); err != nil {
				return err
			}
		}
	}
	return nil
}
