package commit

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/vault"
)

// repair --reindex crash points (amendment A2 §5.7).
const (
	HookReindexBuilding  = "reindex_building"  // the first batch is in the new index
	HookReindexSynced    = "reindex_synced"    // the new index is verified, closed and synced; not yet exchanged
	HookReindexExchanged = "reindex_exchanged" // state/pebble is the new index; the old one is not yet deleted
)

// ErrNoExchange means the filesystem cannot exchange two directories
// atomically, so repair --reindex refuses before building anything.
var ErrNoExchange = errors.New("the filesystem does not support renameat2(RENAME_EXCHANGE); repair --reindex needs it to replace the index atomically")

// Probe directories: repair --reindex first exchanges two empty directories.
const (
	probeA = ".exchange-probe-a"
	probeB = ".exchange-probe-b"
)

// renameExchange atomically swaps two paths (tests replace it).
var renameExchange = func(a, b string) error {
	return unix.Renameat2(unix.AT_FDCWD, a, unix.AT_FDCWD, b, unix.RENAME_EXCHANGE)
}

// ReindexOptions are what repair --reindex needs, under the writer lock.
// The old index is never opened.
type ReindexOptions struct {
	Paths     Paths
	VaultDirs []string
	Codec     *vault.Codec // with every dictionary loaded
	ChainIDs  func(path string) ([][32]byte, error)
	Hook      func(string)
}

// ReindexReport is what the new index holds.
type ReindexReport struct {
	Batches, Certs, Chains int
}

// Reindex rebuilds the Pebble index from the authority, the vault and the
// committed source files, beside the current one, which is never touched
// until a complete, verified new index replaces it (amendment A2 §5.6):
//
//  1. Build state/pebble.reindex by re-applying every committed batch, as
//     recovery's catch-up does.
//  2. Verify it: every committed vault record maps to its cert_id and
//     location, there is no other certificate key, every chain of
//     chains.parquet has its key, and each log's applied position is its
//     last commit_seq.
//  3. Close it and fsync it and state/.
//  4. Exchange it with state/pebble atomically (renameat2 RENAME_EXCHANGE),
//     fsync state/, and delete the old index.
//
// state/pebble is therefore always a complete index. A crash leaves at most
// a state/pebble.reindex, which recovery deletes, whichever index it holds.
func Reindex(o ReindexOptions) (ReindexReport, error) {
	var rep ReindexReport
	state := o.Paths.StateDir()
	live, tmp := filepath.Join(state, "pebble"), filepath.Join(state, ReindexDir)
	if err := probeExchange(state); err != nil {
		return rep, err
	}
	committed, err := ListCommitted(o.Paths.Root)
	if err != nil {
		return rep, err
	}
	if err := os.RemoveAll(tmp); err != nil {
		return rep, err
	}
	x, err := index.Open(tmp)
	if err != nil {
		return rep, err
	}
	open := true
	defer func() {
		if open {
			x.Close()
		}
	}()
	reader, err := vault.OpenReader(o.VaultDirs, o.Codec)
	if err != nil {
		return rep, err
	}
	defer reader.Close()
	ro := RecoverOptions{Paths: o.Paths, VaultDirs: o.VaultDirs, ChainIDs: o.ChainIDs}
	certs := map[[32]byte]index.Ref{}
	var chains [][32]byte
	last := map[string]uint64{}
	for i, m := range committed {
		as, cs, err := applyBatch(x, reader, ro, m)
		if err != nil {
			return rep, err
		}
		for _, a := range as {
			if _, dup := certs[a.sha]; dup {
				return rep, corrupt("certificate %x is vaulted twice (batch %s)", a.sha[:8], m.BatchID)
			}
			certs[a.sha] = a.ref
		}
		chains = append(chains, cs...)
		last[m.Log] = m.CommitSeq
		if i == 0 {
			call(o.Hook, HookReindexBuilding)
		}
	}
	if err := verifyIndex(x, certs, chains, last); err != nil {
		return rep, err
	}
	rep = ReindexReport{Batches: len(committed), Certs: len(certs), Chains: len(uniq(chains))}

	open = false
	if err := x.Close(); err != nil {
		return rep, err
	}
	if err := syncTree(tmp); err != nil {
		return rep, err
	}
	if err := fsutil.SyncDir(state); err != nil {
		return rep, err
	}
	call(o.Hook, HookReindexSynced)
	if _, err := os.Stat(live); errors.Is(err, fs.ErrNotExist) {
		err = os.Rename(tmp, live) // no index at all: nothing to exchange with
		if err != nil {
			return rep, err
		}
	} else if err := renameExchange(tmp, live); err != nil {
		return rep, fmt.Errorf("exchanging the indexes: %w", err)
	}
	if err := fsutil.SyncDir(state); err != nil {
		return rep, err
	}
	call(o.Hook, HookReindexExchanged)
	if err := os.RemoveAll(tmp); err != nil {
		return rep, err
	}
	return rep, fsutil.SyncDir(state)
}

func uniq(ids [][32]byte) map[[32]byte]bool {
	out := map[[32]byte]bool{}
	for _, id := range ids {
		out[id] = true
	}
	return out
}

// verifyIndex checks a rebuilt index against what was applied to it.
func verifyIndex(x *index.Index, certs map[[32]byte]index.Ref, chains [][32]byte, last map[string]uint64) error {
	for sha, want := range certs {
		got, ok, err := x.Lookup(sha)
		if err != nil {
			return err
		}
		if !ok || got != want {
			return fmt.Errorf("the new index maps %x to %+v (present: %v), the vault to %+v", sha[:8], got, ok, want)
		}
	}
	n := 0
	err := x.EachCert(func(sha [32]byte, _ index.Ref) error {
		n++
		if _, ok := certs[sha]; !ok {
			return fmt.Errorf("the new index holds %x, which no committed vault record has", sha[:8])
		}
		return nil
	})
	if err != nil {
		return err
	}
	if n != len(certs) {
		return fmt.Errorf("the new index holds %d certificates, the vault %d", n, len(certs))
	}
	for _, id := range chains {
		if ok, err := x.HasChain(id); err != nil || !ok {
			return fmt.Errorf("the new index lacks chain %x (%v)", id[:8], err)
		}
	}
	applied, err := x.AppliedLogs()
	if err != nil {
		return err
	}
	if !maps.Equal(applied, last) {
		return fmt.Errorf("the new index has applied %v, the committed batches end at %v", applied, last)
	}
	return nil
}

// syncTree fsyncs every file and directory under dir.
func syncTree(dir string) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return fsutil.SyncDir(p)
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		return f.Sync()
	})
}

// probeExchange exchanges two empty directories in state/, so a filesystem
// without RENAME_EXCHANGE is refused before anything is built.
func probeExchange(state string) error {
	a, b := filepath.Join(state, probeA), filepath.Join(state, probeB)
	for _, p := range []string{a, b} {
		if err := os.RemoveAll(p); err != nil {
			return err
		}
		if err := os.Mkdir(p, 0o755); err != nil {
			return err
		}
	}
	err := renameExchange(a, b)
	if rerr := errors.Join(os.RemoveAll(a), os.RemoveAll(b)); rerr != nil && err == nil {
		err = rerr
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNoExchange, err)
	}
	return nil
}
