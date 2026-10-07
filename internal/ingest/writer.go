// Package ingest runs batches: it fetches a range of a log, verifies it
// against a pinned signed tree head, vaults new certificates, stages the
// source-layer Parquet files and commits through the protocol of spec §8.3.
package ingest

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

// Options configure a Writer. The caller holds the writer lock and has run
// the volume checks.
type Options struct {
	Root      string
	VaultDirs []string // absolute, in VAULT_ID order
	VaultUUID [16]byte
	Config    config.Config
	Guard     diskguard.Guard
	Fetch     fetch.Options // workers, rate and stall timeout from Config, plus test overrides
	Version   string
	Now       func() time.Time
	Out       io.Writer    // one line per batch and recovery action
	Hook      func(string) // crash points, tests only
	// CheckVolumes repeats the volume checks (spec §9.2) at every batch
	// preflight; a failure stops the batch before anything is written.
	CheckVolumes func() error

	// DictSamples is how many leaf certificates train dictionary 1 (20,000;
	// tests use fewer). Train defaults to vault.Train.
	DictSamples int
	Train       func(samples [][]byte, id uint64) ([]byte, error)
	// CanarySamples is how many rows and vault records the canary checks
	// per batch (default 64).
	CanarySamples int
	// NoDerived writes batches without derived files, as Plan 2 did: tests
	// only, for the rebuild's byte-equivalence test (amendment A2 §5.7).
	NoDerived bool
}

// Writer is the single writer of a vault.
type Writer struct {
	o      Options
	paths  commit.Paths
	idx    *index.Index
	codec  *vault.Codec
	stager *dataset.Stager
	ids    *commit.IDs
	vw     *vault.Writer
	delta  *vault.DeltaCache
	dictID uint64

	trainTried bool
	cold       bool  // the delta cache was emptied by a stopped attempt
	broken     error // an abandon failed: no more batches (ErrAbandonFailed)
	spill      string

	committed []commit.Manifest
	tips      map[string]commit.LogTip
	active    derive.Active // dataset/ACTIVE.json
	warnings  []string      // what the writer's start could not do, for the user
}

func (w *Writer) logf(format string, args ...any) {
	if w.o.Out != nil {
		fmt.Fprintf(w.o.Out, format+"\n", args...)
	}
}

// WriterSpillDir is the writer's DuckDB spill folder under tmp/ (spec §10.1
// gives readers tmp/duckdb-<pid>; there is only ever one writer).
const WriterSpillDir = "duckdb-writer"

// Open recovers the vault (spec §8.5) and prepares the writer: index,
// dictionaries, cert_id allocator, vault tail, delta cache warm-up and
// views.sql.
func Open(o Options) (*Writer, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.DictSamples == 0 {
		o.DictSamples = vault.TrainingSamples
	}
	if o.Train == nil {
		o.Train = vault.Train
	}
	if o.CanarySamples == 0 {
		o.CanarySamples = 64
	}
	w := &Writer{o: o, paths: commit.Paths{Root: o.Root}}
	ok := false
	defer func() {
		if !ok {
			w.Close()
		}
	}()
	var err error
	if w.idx, err = index.Open(filepath.Join(o.Root, "state", "pebble")); err != nil {
		return nil, err
	}
	if w.codec, err = vault.NewCodec(); err != nil {
		return nil, err
	}
	dicts, err := vault.LoadDicts(o.VaultDirs)
	if err != nil {
		return nil, err
	}
	for _, d := range dicts {
		if err := w.codec.AddDict(d.Manifest.ID, d.Content); err != nil {
			return nil, err
		}
		w.dictID = d.Manifest.ID
	}
	// The writer's DuckDB spill folder has a fixed name: the writer lock
	// makes it ours, so a killed writer's leftover is emptied here.
	// Readers' tmp/duckdb-<pid> folders are never touched (amendment A1 §7).
	w.spill = filepath.Join(o.Root, "tmp", WriterSpillDir)
	if left, _ := os.ReadDir(w.spill); len(left) > 0 {
		w.logf("recovery: emptied the writer's leftover DuckDB spill folder tmp/%s", WriterSpillDir)
	}
	if err := os.RemoveAll(w.spill); err != nil {
		return nil, err
	}
	if w.stager, err = dataset.NewStager(dataset.Options{TempDir: w.spill, MaxTempBytes: w.spillLimit()}); err != nil {
		return nil, err
	}
	rec, err := commit.Recover(commit.RecoverOptions{Paths: w.paths, VaultDirs: o.VaultDirs, VaultUUID: o.VaultUUID, Index: w.idx,
		Codec: w.codec, ChainIDs: w.stager.ChainIDs})
	if err != nil {
		return nil, err
	}
	for _, a := range rec.Actions {
		w.logf("recovery: %s", a)
	}
	w.committed, w.tips = rec.Committed, commit.Tips(rec.Committed)
	if w.ids, err = commit.LoadIDs(w.paths.StateDir(), rec.NextCertID, o.Hook); err != nil {
		return nil, err
	}
	if w.vw, err = vault.OpenWriter(w.vaultOptions(), w.codec, rec.Tail); err != nil {
		return nil, err
	}
	if err := w.warm(); err != nil {
		return nil, err
	}
	if w.active, err = settleActive(o.Root, len(rec.Committed) > 0); err != nil {
		return nil, err
	}
	if err := w.startUpgrades(); err != nil {
		return nil, err
	}
	if _, err := w.RetireOld(false); err != nil {
		return nil, err
	}
	if _, err := dataset.WriteViews(o.Root, w.active); err != nil {
		return nil, err
	}
	ok = true
	return w, nil
}

func (w *Writer) vaultOptions() vault.Options {
	return vault.Options{Dirs: w.o.VaultDirs, VaultUUID: w.o.VaultUUID, SegmentSize: uint64(w.o.Config.Vault.SegmentSize),
		Check: w.o.Guard.Check, Hook: w.o.Hook, Now: w.o.Now}
}

// SpillBudget caps the writer's DuckDB spill. Spec §10.1 sets every DuckDB
// session's spill limit to the headroom below the cap minus 1 GiB, and
// amendment A1 §7 adds the limit to every batch's peak; together no batch
// could ever start. The writer therefore spills at most this budget, and
// the preflight counts it (Plan 2B decision). Plan 2's tables fit in memory.
const SpillBudget = 4 << 30

// spillLimit is the writer's max_temp_directory_size: the budget, or less
// when the headroom below the cap minus a 1 GiB margin is smaller, but at
// least 64 MiB.
func (w *Writer) spillLimit() uint64 {
	const margin, floor = 1 << 30, 64 << 20
	u, err := w.o.Guard.Stat(w.o.Root)
	if err != nil || u.Total == 0 {
		return floor
	}
	lim := uint64(w.o.Guard.Cap * float64(u.Total))
	if used := u.Used(); lim > used+margin+floor {
		return min(SpillBudget, lim-used-margin)
	}
	return floor
}

// warm refills the delta cache from the last delta.warm_batches committed
// batches (amendment A1 §5).
func (w *Writer) warm() error {
	if w.delta == nil {
		w.delta = vault.NewDeltaCache(w.o.Config.Ingest.DeltaLRUEntries)
	} else {
		w.delta.Reset() // reuse the cache's memory (207 MiB at the default size)
	}
	n := w.o.Config.Delta.WarmBatches
	var ranges []vault.Range
	for i := max(0, len(w.committed)-n); i < len(w.committed); i++ {
		ranges = append(ranges, vault.Range{Start: w.committed[i].Vault.Start, End: w.committed[i].Vault.End})
	}
	return vault.Warm(w.o.VaultDirs, w.codec, w.delta, ranges, leaf.PrecertIssuanceDigest)
}

// settleActive reads dataset/ACTIVE.json, or creates it (amendment A2 §4.6):
// complete for a vault without batches, which has nothing to backfill, and
// building for a vault written before Plan 3. A state this binary cannot
// honour is refused.
func settleActive(root string, committed bool) (derive.Active, error) {
	a, ok, err := derive.ReadActive(root)
	if err != nil {
		return a, err
	}
	if !ok {
		a = derive.Complete()
		if committed {
			a = derive.Upgrading()
		}
		if err := derive.WriteActive(root, a); err != nil {
			return a, err
		}
	}
	// A table this binary carries and ACTIVE.json lacks is new (spec §7.8):
	// built from the vault in turns when batches exist, complete at once
	// otherwise.
	added := false
	for _, b := range derive.Builders {
		t := b.Table()
		if _, ok := a.Tables[t.Name]; ok {
			continue
		}
		if a.Tables == nil {
			a.Tables = map[string]derive.TableState{}
		}
		v := t.Version
		a.Tables[t.Name] = derive.TableState{Active: &v, Status: derive.StatusComplete}
		if committed {
			a.Tables[t.Name] = derive.TableState{Building: &v, Status: derive.StatusBuilding}
		}
		added = true
	}
	if added {
		a.Seq++
		if err := derive.WriteActive(root, a); err != nil {
			return a, err
		}
	}
	return a, a.Check()
}

// Active returns the vault's ACTIVE.json state.
func (w *Writer) Active() derive.Active { return w.active }

// Warnings are what the writer's start could not do, such as an upgrade
// without room.
func (w *Writer) Warnings() []string { return w.warnings }

// Next returns the first index of log not yet committed.
func (w *Writer) Next(log string) uint64 { return w.tips[log].Next }

// Tip returns log's committed position and Merkle state (State is nil when
// nothing of log is committed).
func (w *Writer) Tip(log string) commit.LogTip { return w.tips[log] }

// LastCommitSeq returns the highest commit_seq.
func (w *Writer) LastCommitSeq() uint64 {
	if len(w.committed) == 0 {
		return 0
	}
	return w.committed[len(w.committed)-1].CommitSeq
}

// Close releases every resource; it never commits anything. Closing twice
// is harmless.
func (w *Writer) Close() error {
	var errs []error
	if w.vw != nil {
		errs = append(errs, w.vw.Close())
		w.vw = nil
	}
	if w.stager != nil {
		errs = append(errs, w.stager.Close(), os.RemoveAll(w.spill))
		w.stager = nil
	}
	if w.codec != nil {
		w.codec.Close()
		w.codec = nil
	}
	if w.idx != nil {
		errs = append(errs, w.idx.Close())
		w.idx = nil
	}
	return errors.Join(errs...)
}

// ErrVerification wraps a batch that failed Merkle verification or the
// canary twice: an incident (spec §12, exit 5).
var ErrVerification = errors.New("batch failed verification twice")

// errRetry marks a verification or canary failure; the batch is refetched
// once. A Merkle failure carries the evidence an incident records (spec
// §12): our compact range before the batch, the root we computed at end,
// and the proof the log served.
type errRetry struct {
	err    error
	before *merkle.State
	root   [32]byte
	end    uint64
	proof  [][32]byte
}

func (e errRetry) Error() string { return e.err.Error() }
func (e errRetry) Unwrap() error { return e.err }
