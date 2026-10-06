package ingest

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/extract"
	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/vault"
)

// Rebuild crash points (amendment A2 §5.7).
const (
	HookRebuildStaged       = "rebuild_staged"        // a batch's files are staged in tmp/rebuild
	HookRebuildPlaced       = "rebuild_placed"        // they are in the batch directory, not yet listed
	HookRebuildBeforeSwitch = "rebuild_before_switch" // every batch is verified; ACTIVE.json unchanged
	HookRebuildAfterSwitch  = "rebuild_after_switch"  // ACTIVE.json is complete; views.sql not yet rewritten
)

var (
	// ErrIndexInconsistent means Pebble disagrees with the vault, which is
	// intact (amendment A2 §5.2): the index is rebuilt from the vault.
	ErrIndexInconsistent = errors.New("index inconsistency (the vault is intact; run `ctvault repair --reindex`)")
	// ErrDatasetInconsistent means a batch's Parquet files disagree with its
	// vault records.
	ErrDatasetInconsistent = errors.New("dataset inconsistency")
)

// RebuildStats summarizes a rebuild.
type RebuildStats struct {
	Batches  int            // batches that received files
	Rows     map[string]int // rows written, by table
	Switched bool           // ACTIVE.json moved the tables to complete
}

// Rebuild fills in the derived tables ACTIVE.json lists as building, from the
// local vault and the committed source files (amendment A2 §5.2-5.4). In
// commit order, each batch that lacks a table's file gets it built from its
// vault records, placed in its directory and committed by its
// _DERIVED.json. Then the committed batches are listed again, every one
// must hold every file with its recorded checksum, and only then does
// ACTIVE.json switch the tables to complete and views.sql expose them. An
// interrupted rebuild resumes where it stopped and produces the same files;
// it never needs the network. With nothing to build it does nothing.
func (w *Writer) Rebuild(ctx context.Context) (RebuildStats, error) {
	st := RebuildStats{Rows: map[string]int{}}
	var builds []derive.Builder
	for _, bl := range derive.Builders {
		s := w.active.Tables[bl.Table().Name]
		if s.Status == derive.StatusBuilding && s.Building != nil && *s.Building == bl.Table().Version {
			builds = append(builds, bl)
		}
	}
	if len(builds) == 0 {
		return st, nil
	}
	for i, m := range w.committed {
		var need []derive.Builder
		for _, bl := range builds {
			if _, ok := m.Listed(bl.Table().File()); !ok {
				need = append(need, bl)
			}
		}
		if len(need) == 0 {
			continue
		}
		if err := ctx.Err(); err != nil {
			return st, err
		}
		d, err := w.rebuildBatch(ctx, m, need)
		if err != nil {
			return st, fmt.Errorf("rebuilding batch %s: %w", m.BatchID, err)
		}
		w.committed[i].Derived = d
		st.Batches++
		var parts []string
		for _, bl := range need {
			t := d.Tables[bl.Table().Name]
			st.Rows[bl.Table().Name] += t.Rows
			parts = append(parts, fmt.Sprintf("%s %d rows", bl.Table().Name, t.Rows))
		}
		w.logf("rebuilt batch %s: %s", m.BatchID, strings.Join(parts, ", "))
	}

	// Switch (§5.4): every committed batch, listed again under the lock,
	// must hold every table's file with the checksum its manifests record.
	ms, err := commit.ListCommitted(w.o.Root)
	if err != nil {
		return st, err
	}
	for _, m := range ms {
		dir := w.paths.BatchDir(m.ID())
		for _, bl := range builds {
			name := bl.Table().File()
			fi, ok := m.Listed(name)
			if !ok {
				return st, fmt.Errorf("%w: batch %s has no %s", ErrDatasetInconsistent, m.BatchID, name)
			}
			got, err := dataset.Sum(filepath.Join(dir, name))
			if err != nil {
				return st, err
			}
			if got.SHA256 != fi.SHA256 {
				return st, fmt.Errorf("%w: %s/%s does not match its recorded checksum", commit.ErrCorrupt, m.BatchID, name)
			}
		}
	}
	w.hook(HookRebuildBeforeSwitch)
	next := derive.Active{Seq: w.active.Seq + 1, Tables: maps.Clone(w.active.Tables)}
	for _, bl := range builds {
		v := bl.Table().Version
		next.Tables[bl.Table().Name] = derive.TableState{Active: &v, Status: derive.StatusComplete}
	}
	if err := derive.WriteActive(w.o.Root, next); err != nil {
		return st, err
	}
	w.active, w.committed = next, ms
	w.hook(HookRebuildAfterSwitch)
	if _, err := dataset.WriteViews(w.o.Root, w.active); err != nil {
		return st, err
	}
	st.Switched = true
	return st, nil
}

// rebuildBatch builds a committed batch's missing derived files from its
// vault records, with the same builders and context as ingest, so the files
// are byte-identical to the ones ingest would have written (amendment A2
// §5.2, §5.7). It returns the batch's new _DERIVED.json.
func (w *Writer) rebuildBatch(ctx context.Context, m commit.Manifest, builds []derive.Builder) (*commit.Derived, error) {
	dir := w.paths.BatchDir(m.ID())
	// The batch's entries and chains decide kinds: check them first.
	for _, name := range []string{dataset.EntriesFile, dataset.ChainsFile} {
		got, err := dataset.Sum(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		if got.SHA256 != m.Files[name].SHA256 {
			return nil, fmt.Errorf("%w: %s does not match _COMMIT.json", commit.ErrCorrupt, name)
		}
	}
	types, err := w.stager.EntryTypes(filepath.Join(dir, dataset.EntriesFile))
	if err != nil {
		return nil, err
	}
	inChains, err := w.stager.ChainCertIDs(filepath.Join(dir, dataset.ChainsFile))
	if err != nil {
		return nil, err
	}
	r, err := vault.OpenReader(w.o.VaultDirs, w.codec)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	var tables []derive.Table
	for _, bl := range builds {
		tables = append(tables, bl.Table())
	}
	stage, err := w.stager.BeginDerived(ctx, tables, w.o.CanarySamples, rand.New(rand.NewPCG(m.First, m.Last)))
	if err != nil {
		return nil, err
	}
	defer stage.Close()
	status := map[string]int{}
	err = vault.Scan(w.o.VaultDirs, m.Vault.Start, m.Vault.End, func(loc vault.Loc, rec vault.Record) error {
		der, _, err := r.Read(loc) // checks the record and resolves a leaf-delta
		if err != nil {
			return err
		}
		sha := sha256.Sum256(der)
		ref, ok, err := w.idx.Lookup(sha)
		if err != nil {
			return err
		}
		if !ok || ref.CertID != rec.CertID || ref.Loc != loc {
			return fmt.Errorf("%w: certificate %x, cert_id %d at %d:%d, is indexed as %+v (present: %v)",
				ErrIndexInconsistent, sha[:8], rec.CertID, loc.Segment, loc.Offset, ref, ok)
		}
		cx := derive.Context{CertID: rec.CertID, SHA256: sha, Loc: loc}
		if cx.Kind, err = recordKind(rec, types[rec.CertID], inChains[rec.CertID]); err != nil {
			return err
		}
		if rec.Kind == vault.KindDelta {
			base, _, err := r.RecordAt(rec.BaseSeg, rec.BaseOff)
			if err != nil {
				return err
			}
			cx.DeltaBaseCertID = base.CertID
		}
		c := extract.Parse(der)
		status[string(c.Status)]++
		for i, bl := range builds {
			if err := stage.Add(i, bl.Build(c, cx)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	tmp := w.paths.RebuildDir(m.ID())
	if err := os.RemoveAll(tmp); err != nil {
		return nil, err
	}
	files, err := stage.Write(ctx, tmp)
	if err != nil {
		return nil, err
	}
	if err := stage.Canary(ctx, tmp); err != nil {
		return nil, err
	}
	w.hook(HookRebuildStaged)
	for _, name := range slices.Sorted(maps.Keys(files)) {
		if err := os.Rename(filepath.Join(tmp, name), filepath.Join(dir, name)); err != nil {
			return nil, err
		}
	}
	if err := fsutil.SyncDir(dir); err != nil {
		return nil, err
	}
	w.hook(HookRebuildPlaced)
	d := commit.Derived{Format: commit.DerivedFormat, BatchID: m.BatchID, Tables: map[string]commit.DerivedTable{},
		ParseStatus: status, CTVaultVersion: w.o.Version}
	if m.Derived != nil {
		maps.Copy(d.Tables, m.Derived.Tables)
	}
	for _, t := range tables {
		fi := files[t.File()]
		d.Tables[t.Name] = commit.DerivedTable{Version: t.Version, File: t.File(), Bytes: fi.Bytes, Rows: fi.Rows, SHA256: fi.SHA256,
			Extractor: derive.ExtractorVersion, SchemaSHA256: t.SchemaSHA256(), PSL: t.PSL}
	}
	if err := commit.WriteDerived(dir, d); err != nil {
		return nil, err
	}
	return &d, os.RemoveAll(tmp)
}

// recordKind decides a rebuilt certificate's kind with the vault record's
// kind first, and cross-checks it against the entries and chains of its
// batch (amendment A2 §5.2). A disagreement is a dataset inconsistency,
// never settled by whichever row comes first.
func recordKind(rec vault.Record, types []string, inChains bool) (string, error) {
	x509, precert := leaf.TypeX509.String(), leaf.TypePrecert.String()
	switch rec.Kind {
	case vault.KindChain:
		if !inChains {
			return "", fmt.Errorf("%w: chain record cert_id %d is in none of its batch's chains", ErrDatasetInconsistent, rec.CertID)
		}
		return derive.KindChain, nil
	case vault.KindDelta:
		if !slices.Equal(types, []string{x509}) {
			return "", fmt.Errorf("%w: leaf-delta record cert_id %d is referenced by entries of types %v, not only %s",
				ErrDatasetInconsistent, rec.CertID, types, x509)
		}
		return derive.KindFinal, nil
	case vault.KindLeaf:
		switch {
		case slices.Equal(types, []string{x509}):
			return derive.KindFinal, nil
		case slices.Equal(types, []string{precert}):
			return derive.KindPrecert, nil
		}
		return "", fmt.Errorf("%w: leaf record cert_id %d is referenced by entries of types %v, not exactly one type",
			ErrDatasetInconsistent, rec.CertID, types)
	}
	return "", fmt.Errorf("%w: record cert_id %d has kind %d", vault.ErrCorrupt, rec.CertID, rec.Kind)
}
