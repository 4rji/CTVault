package ingest

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/vault"
)

// repair --derived crash points (amendment A5 §4.3).
const (
	HookRepairStaged   = "repair_staged"   // a batch's files are rebuilt in tmp/rebuild; nothing is replaced
	HookRepairReplaced = "repair_replaced" // they replaced the damaged files; tmp/rebuild is not yet removed
)

// ErrUnknownBatch means --batch names no committed batch.
var ErrUnknownBatch = errors.New("no committed batch has that ID")

// RepairOptions are what repair --derived needs, under the writer lock. It
// runs no recovery and opens no writer, as repair --reindex does not: a
// missing derived file would stop the writer's start.
type RepairOptions struct {
	Root          string
	VaultDirs     []string
	Codec         *vault.Codec // with every dictionary loaded
	Stager        *dataset.Stager
	Index         *index.Index // read for the cross-check that rebuild makes
	CanarySamples int
	Batch         string // one batch ID; "" checks every batch
	Hook          func(string)
	Progress      func(done, total int) // may be nil
}

// RepairReport is what repair --derived did.
type RepairReport struct {
	Batches  int      // batches checked
	Checked  int      // derived files hashed
	Replaced []string // "<batch>/<file>" rebuilt and replaced
	Damaged  []string // what it could not repair (exit 5)
}

// RepairDerived rebuilds the derived files that are missing or fail the
// checksum their manifest records (amendment A5 §3.2). Each is rebuilt from
// the vault through rebuild's path and replaces the bad file by an atomic
// rename only when it reproduces the recorded checksum; manifests are never
// rewritten. Damaged source data (entries, chains, vault records), a file of
// a version this binary does not build, and a rebuild that does not match
// are reported, and nothing in that batch is replaced. Pebble disagreeing
// with the vault stops the repair: repair --reindex comes first.
func RepairDerived(ctx context.Context, o RepairOptions) (RepairReport, error) {
	var rep RepairReport
	ms, err := commit.ListCommittedForRepair(o.Root)
	if err != nil {
		return rep, err
	}
	builders := map[string]derive.Builder{}
	var names []string
	for _, bl := range derive.Builders {
		builders[bl.Table().File()] = bl
		names = append(names, bl.Table().File())
	}
	paths := commit.Paths{Root: o.Root}
	build := derivedBuild{paths: paths, dirs: o.VaultDirs, codec: o.Codec, stager: o.Stager, idx: o.Index, samples: o.CanarySamples}
	hook := func(h string) {
		if o.Hook != nil {
			o.Hook(h)
		}
	}
	found := false
	for i, m := range ms {
		if o.Batch != "" && m.BatchID != o.Batch {
			continue
		}
		found = true
		rep.Batches++
		dir := paths.BatchDir(m.ID())
		type recorded struct{ sum, by string }
		listed := map[string]recorded{}
		for name, fi := range m.Files {
			if commit.IsDerivedFile(name) && !m.Retired(name) {
				listed[name] = recorded{fi.SHA256, commit.ManifestFile}
			}
		}
		if m.Derived != nil {
			for _, t := range m.Derived.Tables {
				listed[t.File] = recorded{t.SHA256, commit.DerivedFile}
			}
		}
		var need []derive.Builder
		bad := map[string]recorded{}
		for _, name := range slices.Sorted(maps.Keys(listed)) {
			got, err := dataset.Sum(filepath.Join(dir, name))
			switch {
			case errors.Is(err, fs.ErrNotExist):
			case err != nil:
				return rep, err
			case got.SHA256 == listed[name].sum:
				rep.Checked++
				continue
			default:
				rep.Checked++
			}
			bl, ok := builders[name]
			if !ok {
				rep.Damaged = append(rep.Damaged, fmt.Sprintf("batch %s: %s is missing or damaged, and this binary builds only %s",
					m.BatchID, name, strings.Join(names, " and ")))
				continue
			}
			need, bad[name] = append(need, bl), listed[name]
		}
		if len(need) > 0 {
			tmp, files, _, err := build.stage(ctx, m, need)
			switch {
			case errors.Is(err, ErrIndexInconsistent):
				os.RemoveAll(tmp)
				return rep, err
			case errors.Is(err, commit.ErrCorrupt), errors.Is(err, vault.ErrCorrupt), errors.Is(err, ErrDatasetInconsistent):
				os.RemoveAll(tmp)
				rep.Damaged = append(rep.Damaged, fmt.Sprintf("batch %s: %v: its source data is damaged; restore the batch from a backup copy", m.BatchID, err))
			case err != nil:
				os.RemoveAll(tmp)
				return rep, err
			default:
				hook(HookRepairStaged)
				replaced := 0
				for _, name := range slices.Sorted(maps.Keys(bad)) {
					if got := files[name].SHA256; got != bad[name].sum {
						rep.Damaged = append(rep.Damaged, fmt.Sprintf("batch %s: %s rebuilt with SHA-256 %s, but %s records %s: the vault or the builder is not what wrote it; the file is left as it is",
							m.BatchID, name, got, bad[name].by, bad[name].sum))
						continue
					}
					if err := os.Rename(filepath.Join(tmp, name), filepath.Join(dir, name)); err != nil {
						return rep, err
					}
					rep.Replaced = append(rep.Replaced, m.BatchID+"/"+name)
					replaced++
				}
				if replaced > 0 {
					if err := fsutil.SyncDir(dir); err != nil {
						return rep, err
					}
					hook(HookRepairReplaced)
				}
				if err := os.RemoveAll(tmp); err != nil {
					return rep, err
				}
			}
		}
		if o.Progress != nil {
			o.Progress(i+1, len(ms))
		}
	}
	if o.Batch != "" && !found {
		return rep, fmt.Errorf("--batch %s: %w", o.Batch, ErrUnknownBatch)
	}
	return rep, nil
}
