package ingest

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/vaulttest"
)

// TestBatchesBuildDerivedFiles: each batch commits certs and names with the
// rest (amendment A2 §4.3), listed in _COMMIT.json, and their rows agree
// with the vault. A vault upgraded to building does the same for its new
// batches.
func TestBatchesBuildDerivedFiles(t *testing.T) {
	h := newHarness(t, entries(t, 60), ctlogtest.Options{})
	w := h.open()
	ms := h.ingest(w, h.head(), 0, 30, 30)
	w.Close()
	os.Remove(filepath.Join(h.root, "dataset", derive.ActiveFile)) // as if written before Plan 3
	w = h.open()
	ms = append(ms, h.ingest(w, h.head(), 30, 60, 30)...)
	w.Close()
	for _, m := range ms {
		certs, names := m.Files[derive.CertsV1.File()], m.Files[derive.NamesV1.File()]
		if m.Builders["certs"] != 1 || m.Builders["names"] != 1 || certs.Rows != m.Counts.NewCerts || certs.SHA256 == "" || names.SHA256 == "" {
			t.Fatalf("batch %s: builders %v, certs %+v, names %+v, %d new certificates", m.BatchID, m.Builders, certs, names, m.Counts.NewCerts)
		}
	}
	vaulttest.Vault{Root: h.root, Dirs: h.opts.VaultDirs, UUID: h.opts.VaultUUID}.CheckDerived(t)
}

// TestDerivedFilesAreByteIdentical: the same entries in the same batches
// give the same derived files in two vaults (spec §7.2).
func TestDerivedFilesAreByteIdentical(t *testing.T) {
	es := entries(t, 40)
	var sums [2][]string
	for i := range sums {
		h := newHarness(t, es, ctlogtest.Options{})
		w := h.open()
		for _, m := range h.ingest(w, h.head(), 0, 40, 20) {
			sums[i] = append(sums[i], m.Files[derive.CertsV1.File()].SHA256, m.Files[derive.NamesV1.File()].SHA256)
		}
		w.Close()
	}
	if len(sums[0]) != 4 || slices.Contains(sums[0], "") || !slices.Equal(sums[0], sums[1]) {
		t.Fatalf("checksums missing or different: %v\n%v", sums[0], sums[1])
	}
}
