package ingest

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/vault"
	"github.com/4rji/ctvault/internal/vaulttest"
)

// plan2Vault ingests es [0, n) in batches of size with the builders off and
// removes ACTIVE.json: a vault as Plan 2 wrote it (amendment A2 §5.7).
func plan2Vault(t *testing.T, es []ctlogtest.Entry, n, size uint64) *harness {
	t.Helper()
	h := newHarness(t, es, ctlogtest.Options{})
	h.opts.NoDerived = true
	w := h.open()
	for _, m := range h.ingest(w, h.head(), 0, n, size) {
		if len(m.Builders) != 0 {
			t.Fatalf("batch %s built %v with the builders off", m.BatchID, m.Builders)
		}
	}
	w.Close()
	h.opts.NoDerived = false
	if err := os.Remove(filepath.Join(h.root, "dataset", derive.ActiveFile)); err != nil {
		t.Fatal(err)
	}
	return h
}

// derivedSums lists, batch by batch, the SHA-256 of every derived file the
// batch's manifests list.
func derivedSums(t *testing.T, root string) []string {
	t.Helper()
	ms, err := commit.ListCommitted(root)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range ms {
		for _, b := range derive.Builders {
			fi, ok := m.Listed(b.Table().File())
			if !ok {
				t.Fatalf("batch %s lists no %s", m.BatchID, b.Table().File())
			}
			out = append(out, m.BatchID+" "+b.Table().File()+" "+fi.SHA256)
		}
	}
	return out
}

func rebuild(t *testing.T, h *harness) RebuildStats {
	t.Helper()
	w := h.open()
	defer w.Close()
	st, err := w.Rebuild(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// TestRebuildIsByteIdentical is amendment A2 §5.7's essential test: a vault
// ingested with the builders off and then rebuilt has certs and names files
// byte-identical to an ingest with the builders on. The rebuild leaves
// _COMMIT.json alone, commits the files through _DERIVED.json (the same
// bytes on two vaults), switches ACTIVE.json to complete and exposes the
// tables; a second rebuild has nothing to do.
func TestRebuildIsByteIdentical(t *testing.T) {
	es := entries(t, 60)
	ref := newHarness(t, es, ctlogtest.Options{})
	w := ref.open()
	ref.ingest(w, ref.head(), 0, 60, 20)
	w.Close()
	want := derivedSums(t, ref.root)

	var manifests [][]byte
	for range 2 {
		h := plan2Vault(t, es, 60, 20)
		before := vaulttest.Vault{Root: h.root}.Committed(t)
		w := h.open()
		if a := w.Active(); a.AllComplete() {
			t.Fatalf("a Plan 2 vault opens complete: %+v", a)
		}
		w.Close()
		if st := rebuild(t, h); st.Batches != 3 || !st.Switched || st.Rows["certs"] == 0 {
			t.Fatalf("rebuild: %+v", st)
		}
		if got := derivedSums(t, h.root); strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("rebuilt files differ from an ingest with the builders on:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
		v := vaulttest.Vault{Root: h.root, Dirs: h.opts.VaultDirs, UUID: h.opts.VaultUUID}
		after := v.Committed(t)
		for dir, b := range before {
			if !bytes.Equal(after[dir], b) {
				t.Fatalf("%s changed: _COMMIT.json is never rewritten", dir)
			}
		}
		v.CheckRecovered(t)
		a, _, _ := derive.ReadActive(h.root)
		views, _ := os.ReadFile(filepath.Join(h.root, dataset.ViewsFile))
		if !a.AllComplete() || a.Seq != 2 || !strings.Contains(string(views), "VIEW certs AS") || strings.Contains(string(views), "_building") {
			t.Fatalf("after the rebuild: ACTIVE %+v\n%s", a, views)
		}
		ms, _ := commit.ListCommitted(h.root)
		b, err := os.ReadFile(filepath.Join(commit.Paths{Root: h.root}.BatchDir(ms[0].ID()), commit.DerivedFile))
		if err != nil {
			t.Fatal(err)
		}
		manifests = append(manifests, b)
		if st := rebuild(t, h); st.Batches != 0 || st.Switched {
			t.Fatalf("a second rebuild: %+v", st)
		}
	}
	if !bytes.Equal(manifests[0], manifests[1]) {
		t.Fatalf("_DERIVED.json differs between two vaults:\n%s\n%s", manifests[0], manifests[1])
	}
}

// TestRebuildFillsOnlyMissingFiles: batches committed while the tables were
// building already carry their files from ingest; the rebuild fills the
// others and then switches.
func TestRebuildFillsOnlyMissingFiles(t *testing.T) {
	h := plan2Vault(t, entries(t, 60), 40, 20)
	w := h.open()
	h.ingest(w, h.head(), 40, 60, 20)
	w.Close()
	if st := rebuild(t, h); st.Batches != 2 || !st.Switched {
		t.Fatalf("rebuild: %+v", st)
	}
	derivedSums(t, h.root)
	vaulttest.Vault{Root: h.root, Dirs: h.opts.VaultDirs, UUID: h.opts.VaultUUID}.CheckRecovered(t)
}

// TestRebuildReportsIndexInconsistency: a Pebble key that disagrees with the
// vault stops the rebuild as an index inconsistency, never as vault
// corruption; files already placed stay valid. repair --reindex fixes the
// index, and the rebuild then completes (amendment A2 §5.7).
func TestRebuildReportsIndexInconsistency(t *testing.T) {
	h := plan2Vault(t, entries(t, 60), 60, 20)
	ms, _ := commit.ListCommitted(h.root)
	var target vault.Loc
	vault.Scan(h.opts.VaultDirs, ms[2].Vault.Start, ms[2].Vault.End, func(l vault.Loc, _ vault.Record) error {
		if target.Len == 0 {
			target = l
		}
		return nil
	})
	v := vaulttest.Vault{Root: h.root, Dirs: h.opts.VaultDirs, UUID: h.opts.VaultUUID}
	w := h.open()
	var sha [32]byte
	found := false
	for sh, ref := range eachCert(t, w.idx) {
		if ref.Loc == target {
			sha, found = sh, true
		}
	}
	if !found {
		t.Fatal("the third batch's first record is not indexed")
	}
	b := w.idx.NewBatch()
	b.AddCert(sha, index.Ref{CertID: 999999, Loc: target})
	if err := b.Commit(); err != nil {
		t.Fatal(err)
	}
	b.Close()
	_, err := w.Rebuild(ctx)
	w.Close()
	if !errors.Is(err, ErrIndexInconsistent) || errors.Is(err, vault.ErrCorrupt) || !strings.Contains(err.Error(), "repair --reindex") {
		t.Fatalf("rebuild over an inconsistent index: %v", err)
	}
	after, _ := commit.ListCommitted(h.root)
	if after[0].Derived == nil || after[1].Derived == nil || after[2].Derived != nil {
		t.Fatalf("the first two batches keep their files, the third has none: %v %v %v", after[0].Derived, after[1].Derived, after[2].Derived)
	}
	v.CheckDerived(t)

	codec, err := vault.NewCodec()
	if err != nil {
		t.Fatal(err)
	}
	defer codec.Close()
	stager, err := dataset.NewStager(dataset.Options{TempDir: t.TempDir(), MaxTempBytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	defer stager.Close()
	if _, err := commit.Reindex(commit.ReindexOptions{Paths: commit.Paths{Root: h.root}, VaultDirs: h.opts.VaultDirs, Codec: codec,
		ChainIDs: stager.ChainIDs}); err != nil {
		t.Fatal(err)
	}
	if st := rebuild(t, h); st.Batches != 1 || !st.Switched {
		t.Fatalf("rebuild after repair --reindex: %+v", st)
	}
	v.CheckRecovered(t)
}

func eachCert(t *testing.T, x *index.Index) map[[32]byte]index.Ref {
	t.Helper()
	out := map[[32]byte]index.Ref{}
	if err := x.EachCert(func(sha [32]byte, r index.Ref) error { out[sha] = r; return nil }); err != nil {
		t.Fatal(err)
	}
	return out
}

// rewriteEntries replaces a committed batch's entries.parquet with the
// result of a query over it and updates _COMMIT.json to match, as if the
// file had been written that way.
func rewriteEntries(t *testing.T, root string, m commit.Manifest, query string) {
	t.Helper()
	dir := commit.Paths{Root: root}.BatchDir(m.ID())
	p := filepath.Join(dir, dataset.EntriesFile)
	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	q := strings.ReplaceAll(query, "ENTRIES", "read_parquet('"+p+"')")
	if _, err := db.Exec(`COPY (` + q + `) TO '` + p + `.new' (FORMAT parquet)`); err != nil {
		t.Fatal(err)
	}
	os.Rename(p+".new", p)
	fi, err := dataset.Sum(p)
	if err != nil {
		t.Fatal(err)
	}
	fi.Rows = m.Files[dataset.EntriesFile].Rows
	m.Files[dataset.EntriesFile] = fi
	b, _ := json.MarshalIndent(m, "", " ")
	if err := os.WriteFile(filepath.Join(dir, commit.ManifestFile), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestRebuildReportsKindDisagreement: the record kind decides a certificate's
// kind, and the batch's entries must agree with it; a leaf-delta record
// referenced by a precert entry is a dataset inconsistency, never resolved
// by whichever row comes first (amendment A2 §5.2).
func TestRebuildReportsKindDisagreement(t *testing.T) {
	h := plan2Vault(t, entries(t, 60), 60, 60)
	ms, _ := commit.ListCommitted(h.root)
	var delta uint64
	vault.Scan(h.opts.VaultDirs, ms[0].Vault.Start, ms[0].Vault.End, func(_ vault.Loc, rec vault.Record) error {
		if rec.Kind == vault.KindDelta && delta == 0 {
			delta = rec.CertID
		}
		return nil
	})
	if delta == 0 {
		t.Fatal("the batch has no leaf-delta record")
	}
	rewriteEntries(t, h.root, ms[0], `SELECT * REPLACE (CASE WHEN cert_id = `+strconv.FormatUint(delta, 10)+` THEN 'precert' ELSE entry_type END AS entry_type) FROM ENTRIES ORDER BY idx`)
	w := h.open()
	_, err := w.Rebuild(ctx)
	w.Close()
	if !errors.Is(err, ErrDatasetInconsistent) || !strings.Contains(err.Error(), "leaf-delta") {
		t.Fatalf("a leaf-delta record referenced by a precert entry: %v", err)
	}
}

// TestRebuildReportsCorruptRecord: a vault record that fails its own checks
// is vault corruption.
func TestRebuildReportsCorruptRecord(t *testing.T) {
	h := plan2Vault(t, entries(t, 60), 60, 60)
	ms, _ := commit.ListCommitted(h.root)
	var loc vault.Loc
	vault.Scan(h.opts.VaultDirs, ms[0].Vault.Start, ms[0].Vault.End, func(l vault.Loc, rec vault.Record) error {
		if rec.Kind == vault.KindLeaf && loc.Len == 0 {
			loc = l
		}
		return nil
	})
	segs, err := vault.FindSegments(h.opts.VaultDirs)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(segs[loc.Segment], os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1)
	at := int64(loc.Offset) + int64(loc.Len) - 6
	f.ReadAt(b, at)
	b[0] ^= 0xff
	f.WriteAt(b, at)
	f.Close()
	h.opts.Config.Delta.WarmBatches = 0 // the delta cache's warm-up would read the record first
	w := h.open()
	_, err = w.Rebuild(ctx)
	w.Close()
	if !errors.Is(err, vault.ErrCorrupt) {
		t.Fatalf("a corrupted record: %v", err)
	}
}
