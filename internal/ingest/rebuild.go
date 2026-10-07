package ingest

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/extract"
	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/index"
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
// local vault and the committed source files (amendment A2 §5.2-5.4, A5 §8),
// all at once: RebuildTurn without a limit. It never needs the network, and
// an interrupted rebuild resumes where it stopped with the same files. With
// nothing to build it does nothing.
func (w *Writer) Rebuild(ctx context.Context) (RebuildStats, error) {
	st, _, err := w.RebuildTurn(ctx, math.MaxInt)
	return st, err
}

// building are the builders of the versions being built with the given
// status: side by side (building) or in place (mixed, amendment A5 §10).
func (w *Writer) building(status string) []derive.Builder {
	var out []derive.Builder
	for _, bl := range derive.Builders {
		s := w.active.Tables[bl.Table().Name]
		if s.Status == status && s.Building != nil {
			if b := derive.BuilderOf(bl.Table().Name, *s.Building); b != nil {
				out = append(out, b)
			}
		}
	}
	return out
}

// oldFile is the file of the version a mixed table is converting from.
func (w *Writer) oldFile(bl derive.Builder) string {
	s := w.active.Tables[bl.Table().Name]
	if s.Active == nil {
		return ""
	}
	return derive.Table{Name: bl.Table().Name, Version: *s.Active}.File()
}

// StartInPlace turns every table whose active version is older than this
// binary's, or whose upgrade runs side by side, into an in-place conversion
// (rebuild --in-place, amendment A5 §10): ACTIVE.json marks it mixed, and
// each turn then converts a batch.
func (w *Writer) StartInPlace() error {
	next := derive.Active{Seq: w.active.Seq + 1, Tables: maps.Clone(w.active.Tables)}
	started := false
	for _, bl := range derive.Builders {
		name, cur := bl.Table().Name, bl.Table().Version
		s := w.active.Tables[name]
		if s.Active == nil || *s.Active >= cur || s.Status == derive.StatusMixed {
			continue
		}
		v := cur
		s.Building, s.Status, s.Retiring, s.SwitchedAt = &v, derive.StatusMixed, nil, nil
		next.Tables[name] = s
		started = true
		w.logf("converting %s from v%d to v%d in place: it is mixed until every batch is converted", name, *w.active.Tables[name].Active, cur)
	}
	if !started {
		return nil
	}
	if err := derive.WriteActive(w.o.Root, next); err != nil {
		return err
	}
	w.active = next
	_, err := dataset.WriteViews(w.o.Root, w.active)
	return err
}

// RebuildTurn is one turn of a side-by-side transition (amendment A5 §8): in
// commit order, up to n committed batches that lack a version being built
// get it from their vault records, placed in their directory and committed
// by their _DERIVED.json. When no batch lacks one, the turn switches the
// tables (A2 §5.4): every committed batch, listed again under the lock, must
// hold every building file with its recorded checksum; then ACTIVE.json makes
// the built versions active, recording the replaced ones as retiring, and
// views.sql exposes them. pending reports whether batches remain.
func (w *Writer) RebuildTurn(ctx context.Context, n int) (st RebuildStats, pending bool, err error) {
	st = RebuildStats{Rows: map[string]int{}}
	builds, conv := w.building(derive.StatusBuilding), w.building(derive.StatusMixed)
	if len(builds) == 0 && len(conv) == 0 {
		return st, false, nil
	}
	for i, m := range w.committed {
		var need, convert []derive.Builder
		for _, bl := range builds {
			if _, ok := m.Listed(bl.Table().File()); !ok {
				need = append(need, bl)
			}
		}
		for _, bl := range conv {
			_, has := m.Listed(bl.Table().File())
			_, old := m.Listed(w.oldFile(bl))
			if !has || old {
				convert = append(convert, bl)
			}
		}
		if len(need) == 0 && len(convert) == 0 {
			continue
		}
		if st.Batches == n {
			return st, true, nil
		}
		if err := ctx.Err(); err != nil {
			return st, true, err
		}
		var parts []string
		if len(need) > 0 {
			d, err := w.rebuildBatch(ctx, m, need)
			if err != nil {
				return st, true, fmt.Errorf("rebuilding batch %s: %w", m.BatchID, err)
			}
			m.Derived, w.committed[i].Derived = d, d
			for _, bl := range need {
				t := d.Tables[bl.Table().Name]
				st.Rows[bl.Table().Name] += t.Rows
				parts = append(parts, fmt.Sprintf("%s v%d %d rows", bl.Table().Name, bl.Table().Version, t.Rows))
			}
		}
		if len(convert) > 0 {
			d, err := w.convertBatch(ctx, m, convert)
			if err != nil {
				return st, true, fmt.Errorf("converting batch %s: %w", m.BatchID, err)
			}
			w.committed[i].Derived = d
			for _, bl := range convert {
				parts = append(parts, fmt.Sprintf("%s v%d in place of %s", bl.Table().Name, bl.Table().Version, w.oldFile(bl)))
			}
		}
		st.Batches++
		w.logf("rebuilt batch %s: %s", m.BatchID, strings.Join(parts, ", "))
		// The first file of a version turns its view from empty to real.
		if _, err := dataset.WriteViews(w.o.Root, w.active); err != nil {
			return st, true, err
		}
	}
	if err := w.switchTables(builds, conv); err != nil {
		return st, false, err
	}
	st.Switched = true
	return st, false, nil
}

// convertBatch converts a batch in place (amendment A5 §10): the versions
// it lacks are built and placed, unlisted; one _DERIVED.json write then
// lists them and retires the old versions, the batch's commit point; the old
// files are deleted last. No batch is ever without one of the two.
func (w *Writer) convertBatch(ctx context.Context, m commit.Manifest, conv []derive.Builder) (*commit.Derived, error) {
	dir := w.paths.BatchDir(m.ID())
	var need []derive.Builder
	for _, bl := range conv {
		if _, ok := m.Listed(bl.Table().File()); !ok {
			need = append(need, bl)
		}
	}
	d := commit.Derived{Format: commit.DerivedFormat, BatchID: m.BatchID, Tables: map[string]commit.DerivedTable{}, CTVaultVersion: w.o.Version}
	if m.Derived != nil {
		d = *m.Derived
		d.Tables = maps.Clone(d.Tables)
		d.Retired = slices.Clone(d.Retired)
	}
	var tmp string
	if len(need) > 0 {
		var files map[string]dataset.FileInfo
		var status map[string]int
		var err error
		if tmp, files, status, err = w.derivedBuild().stage(ctx, m, need); err != nil {
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
		d.ParseStatus = status
		for _, bl := range need {
			t, fi := bl.Table(), files[bl.Table().File()]
			d.Tables[t.Name] = commit.DerivedTable{Version: t.Version, File: t.File(), Bytes: fi.Bytes, Rows: fi.Rows, SHA256: fi.SHA256,
				Extractor: derive.ExtractorVersion, SchemaSHA256: t.SchemaSHA256(), PSL: t.PSL}
		}
	}
	var old []string
	for _, bl := range conv {
		if f := w.oldFile(bl); f != "" {
			if _, ok := m.Listed(f); ok {
				old = append(old, f)
				for t, dt := range d.Tables {
					if dt.File == f {
						delete(d.Tables, t)
					}
				}
				if !slices.Contains(d.Retired, f) {
					d.Retired = append(d.Retired, f)
				}
			}
		}
	}
	slices.Sort(d.Retired)
	if err := commit.WriteDerived(dir, d); err != nil {
		return nil, err
	}
	w.hook(commit.HookRetireRecorded)
	for _, f := range old {
		if err := os.Remove(filepath.Join(dir, f)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	if err := fsutil.SyncDir(dir); err != nil {
		return nil, err
	}
	if tmp != "" {
		if err := os.RemoveAll(tmp); err != nil {
			return nil, err
		}
	}
	return &d, nil
}

// switchTables makes the built versions active (A2 §5.4, A5 §8, §10): side
// by side the replaced versions become retiring; in place they are already
// gone from every batch.
func (w *Writer) switchTables(builds, conv []derive.Builder) error {
	ms, err := commit.ListCommitted(w.o.Root)
	if err != nil {
		return err
	}
	for _, m := range ms {
		dir := w.paths.BatchDir(m.ID())
		for _, bl := range conv {
			if _, ok := m.Listed(w.oldFile(bl)); ok {
				return fmt.Errorf("%w: batch %s still lists %s after its in-place conversion", ErrDatasetInconsistent, m.BatchID, w.oldFile(bl))
			}
		}
		for _, bl := range append(slices.Clone(builds), conv...) {
			name := bl.Table().File()
			fi, ok := m.Listed(name)
			if !ok {
				return fmt.Errorf("%w: batch %s has no %s", ErrDatasetInconsistent, m.BatchID, name)
			}
			got, err := dataset.Sum(filepath.Join(dir, name))
			if err != nil {
				return err
			}
			if got.SHA256 != fi.SHA256 {
				return fmt.Errorf("%w: %s/%s does not match its recorded checksum", commit.ErrCorrupt, m.BatchID, name)
			}
		}
	}
	w.hook(HookRebuildBeforeSwitch)
	next := derive.Active{Seq: w.active.Seq + 1, Tables: maps.Clone(w.active.Tables)}
	now := w.o.Now().UTC()
	for _, bl := range builds {
		v := bl.Table().Version
		old := w.active.Tables[bl.Table().Name].Active
		s := derive.TableState{Active: &v, Status: derive.StatusComplete}
		if old != nil {
			s.Retiring, s.SwitchedAt = old, &now
		}
		next.Tables[bl.Table().Name] = s
	}
	for _, bl := range conv {
		v := bl.Table().Version
		next.Tables[bl.Table().Name] = derive.TableState{Active: &v, Status: derive.StatusComplete}
	}
	if err := derive.WriteActive(w.o.Root, next); err != nil {
		return err
	}
	w.active, w.committed = next, ms
	for _, bl := range append(slices.Clone(builds), conv...) {
		msg := fmt.Sprintf("switched %s to v%d", bl.Table().Name, bl.Table().Version)
		if s := next.Tables[bl.Table().Name]; s.Retiring != nil {
			msg += fmt.Sprintf("; v%d is retiring: `ctvault gc` deletes its files now, update and rebuild after 24 hours", *s.Retiring)
		}
		w.logf("%s", msg)
	}
	w.hook(HookRebuildAfterSwitch)
	_, err = dataset.WriteViews(w.o.Root, w.active)
	return err
}

// Upgrade is a transition's progress, for stats and the CLI.
type Upgrade struct {
	Table       string
	From, To    int // From is 0 for a new table
	Done, Total int // committed batches that hold To, of all
	Mixed       bool
}

// Upgrades lists the transitions in progress.
func (w *Writer) Upgrades() []Upgrade {
	return Progress(w.active, w.committed)
}

// Progress lists a vault's transitions in progress from its ACTIVE.json and
// committed batches.
func Progress(a derive.Active, committed []commit.Manifest) []Upgrade {
	var out []Upgrade
	for _, bl := range derive.Builders {
		name := bl.Table().Name
		s := a.Tables[name]
		if s.Building == nil {
			continue
		}
		u := Upgrade{Table: name, To: *s.Building, Total: len(committed), Mixed: s.Status == derive.StatusMixed}
		if s.Active != nil {
			u.From = *s.Active
		}
		file := derive.Table{Name: name, Version: *s.Building}.File()
		for _, m := range committed {
			if _, ok := m.Listed(file); ok {
				u.Done++
			}
		}
		out = append(out, u)
	}
	return out
}

// startUpgrades begins a side-by-side upgrade of every table whose active
// version is older than this binary's (amendment A5 §8), under the lock and
// after recovery, when a copy of the table fits under the disk cap: about
// the size of the active version's files. Otherwise the vault stays at the
// old version, and a warning says so.
func (w *Writer) startUpgrades() error {
	next := derive.Active{Seq: w.active.Seq + 1, Tables: maps.Clone(w.active.Tables)}
	started := false
	for _, bl := range derive.Builders {
		name, cur := bl.Table().Name, bl.Table().Version
		s := w.active.Tables[name]
		if s.Status != derive.StatusComplete || s.Active == nil || *s.Active >= cur {
			continue
		}
		old := derive.Table{Name: name, Version: *s.Active}.File()
		var need uint64
		for _, m := range w.committed {
			if fi, ok := m.Listed(old); ok {
				need += uint64(fi.Bytes)
			}
		}
		if err := w.o.Guard.Check(w.o.Root, need); err != nil {
			if !errors.Is(err, diskguard.ErrCap) {
				return err
			}
			w.warnings = append(w.warnings, fmt.Sprintf("%s v%d needs %s more beside v%d, which does not fit under the disk cap (%v); free space or run `ctvault rebuild --in-place`",
				name, cur, human(need), *s.Active, err))
			continue
		}
		v := cur
		s.Building, s.Status = &v, derive.StatusBuilding
		next.Tables[name] = s
		started = true
		w.logf("starting the upgrade of %s from v%d to v%d: old batches are rebuilt in turns", name, *s.Active, cur)
	}
	if !started {
		return nil
	}
	if err := derive.WriteActive(w.o.Root, next); err != nil {
		return err
	}
	w.active = next
	return nil
}

func human(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(b)/(1<<20))
	}
	return fmt.Sprintf("%d bytes", b)
}

// rebuildBatch builds a committed batch's missing derived files from its
// vault records, with the same builders and context as ingest, so the files
// are byte-identical to the ones ingest would have written (amendment A2
// §5.2, §5.7). It returns the batch's new _DERIVED.json.
func (w *Writer) rebuildBatch(ctx context.Context, m commit.Manifest, builds []derive.Builder) (*commit.Derived, error) {
	dir := w.paths.BatchDir(m.ID())
	tmp, files, status, err := w.derivedBuild().stage(ctx, m, builds)
	if err != nil {
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
	for _, bl := range builds {
		t := bl.Table()
		fi := files[t.File()]
		d.Tables[t.Name] = commit.DerivedTable{Version: t.Version, File: t.File(), Bytes: fi.Bytes, Rows: fi.Rows, SHA256: fi.SHA256,
			Extractor: derive.ExtractorVersion, SchemaSHA256: t.SchemaSHA256(), PSL: t.PSL}
	}
	if err := commit.WriteDerived(dir, d); err != nil {
		return nil, err
	}
	return &d, os.RemoveAll(tmp)
}

func (w *Writer) derivedBuild() derivedBuild {
	return derivedBuild{paths: w.paths, dirs: w.o.VaultDirs, codec: w.codec, stager: w.stager, idx: w.idx, samples: w.o.CanarySamples}
}

// derivedBuild builds a committed batch's derived files from the vault, for
// rebuild and repair --derived.
type derivedBuild struct {
	paths   commit.Paths
	dirs    []string
	codec   *vault.Codec
	stager  *dataset.Stager
	idx     *index.Index
	samples int // canary samples
}

// stage builds batch m's files of the given builders into
// tmp/rebuild/<batch>, checked by the canary, and returns that directory,
// the files and the batch's parse-status mix. The batch's entries and
// chains must match their checksums: they decide the kinds. Pebble must
// agree with the vault (ErrIndexInconsistent otherwise).
func (d derivedBuild) stage(ctx context.Context, m commit.Manifest, builds []derive.Builder) (string, map[string]dataset.FileInfo, map[string]int, error) {
	dir := d.paths.BatchDir(m.ID())
	for _, name := range []string{dataset.EntriesFile, dataset.ChainsFile} {
		got, err := dataset.Sum(filepath.Join(dir, name))
		if err != nil {
			return "", nil, nil, err
		}
		if got.SHA256 != m.Files[name].SHA256 {
			return "", nil, nil, fmt.Errorf("%w: %s does not match _COMMIT.json", commit.ErrCorrupt, name)
		}
	}
	types, err := d.stager.EntryTypes(filepath.Join(dir, dataset.EntriesFile))
	if err != nil {
		return "", nil, nil, err
	}
	inChains, err := d.stager.ChainCertIDs(filepath.Join(dir, dataset.ChainsFile))
	if err != nil {
		return "", nil, nil, err
	}
	r, err := vault.OpenReader(d.dirs, d.codec)
	if err != nil {
		return "", nil, nil, err
	}
	defer r.Close()
	var tables []derive.Table
	for _, bl := range builds {
		tables = append(tables, bl.Table())
	}
	stage, err := d.stager.BeginDerived(ctx, tables, d.samples, rand.New(rand.NewPCG(m.First, m.Last)))
	if err != nil {
		return "", nil, nil, err
	}
	defer stage.Close()
	status := map[string]int{}
	err = vault.Scan(d.dirs, m.Vault.Start, m.Vault.End, func(loc vault.Loc, rec vault.Record) error {
		der, _, err := r.Read(loc) // checks the record and resolves a leaf-delta
		if err != nil {
			return err
		}
		sha := sha256.Sum256(der)
		ref, ok, err := d.idx.Lookup(sha)
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
		return "", nil, nil, err
	}
	tmp := d.paths.RebuildDir(m.ID())
	if err := os.RemoveAll(tmp); err != nil {
		return "", nil, nil, err
	}
	files, err := stage.Write(ctx, tmp)
	if err != nil {
		return tmp, nil, nil, err
	}
	if err := stage.Canary(ctx, tmp); err != nil {
		return tmp, nil, nil, err
	}
	return tmp, files, status, nil
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
