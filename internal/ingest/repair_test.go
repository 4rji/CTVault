package ingest

import (
	"bytes"
	"errors"
	"github.com/4rji/ctvault/internal/derive"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/vault"
)

// repairEnv is a committed vault of 4 batches and what repair --derived
// needs, opened as the CLI opens it: no writer, no recovery.
type repairEnv struct {
	h     *harness
	ms    []commit.Manifest
	dirs  []string // batch directories, in commit_seq order
	saved map[string][]byte
}

func newRepairEnv(t *testing.T) *repairEnv {
	t.Helper()
	h := newHarness(t, entries(t, 200), ctlogtest.Options{})
	w := h.open()
	ms := h.ingest(w, h.head(), 0, 200, 50)
	w.Close()
	e := &repairEnv{h: h, ms: ms, saved: map[string][]byte{}}
	for _, m := range ms {
		dir := commit.Paths{Root: h.root}.BatchDir(m.ID())
		e.dirs = append(e.dirs, dir)
		for _, f := range []string{"certs.p1.parquet", "names.p1.parquet"} {
			b, err := os.ReadFile(filepath.Join(dir, f))
			if err != nil {
				t.Fatal(err)
			}
			e.saved[filepath.Join(dir, f)] = b
		}
	}
	return e
}

func (e *repairEnv) repair(batch string, hook func(string)) (RepairReport, error) {
	t := e.h.t
	t.Helper()
	codec, err := vault.NewCodec()
	if err != nil {
		t.Fatal(err)
	}
	defer codec.Close()
	dicts, err := vault.LoadDicts(e.h.opts.VaultDirs)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range dicts {
		codec.AddDict(d.Manifest.ID, d.Content)
	}
	stager, err := dataset.NewStager(dataset.Options{TempDir: t.TempDir(), MaxTempBytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	defer stager.Close()
	x, err := index.OpenReadOnly(filepath.Join(e.h.root, "state", "pebble"))
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	return RepairDerived(ctx, RepairOptions{Root: e.h.root, VaultDirs: e.h.opts.VaultDirs, Codec: codec, Stager: stager, Index: x,
		CanarySamples: 16, Batch: batch, Hook: hook})
}

// intact reports whether every derived file is the one ingest wrote.
func (e *repairEnv) intact() bool {
	for p, b := range e.saved {
		got, err := os.ReadFile(p)
		if err != nil || !bytes.Equal(got, b) {
			return false
		}
	}
	return true
}

// TestRepairDerived: repair --derived rebuilds a damaged or missing derived
// file from the vault, byte for byte as ingest wrote it, and replaces it
// only then; a second run finds nothing to do (amendment A5 §3.2).
func TestRepairDerived(t *testing.T) {
	e := newRepairEnv(t)
	certs := filepath.Join(e.dirs[1], "certs.p1.parquet")
	b := bytes.Clone(e.saved[certs])
	b[len(b)/2] ^= 0xff
	os.WriteFile(certs, b, 0o644)
	os.Remove(filepath.Join(e.dirs[2], "names.p1.parquet"))

	var hooks []string
	rep, err := e.repair("", func(h string) { hooks = append(hooks, h) })
	if err != nil {
		t.Fatal(err)
	}
	// Every table's file in 4 batches, but the one removed.
	if len(rep.Replaced) != 2 || len(rep.Damaged) != 0 || rep.Batches != 4 || rep.Checked != 4*len(derive.Builders)-1 {
		t.Fatalf("report %+v", rep)
	}
	if !e.intact() {
		t.Fatal("the rebuilt files are not the ones ingest wrote")
	}
	if strings.Join(hooks, " ") != "repair_staged repair_replaced repair_staged repair_replaced" {
		t.Fatalf("hooks %v", hooks)
	}
	if left, _ := os.ReadDir(filepath.Join(e.h.root, "tmp", "rebuild")); len(left) != 0 {
		t.Fatalf("tmp/rebuild keeps %d entries", len(left))
	}
	rep, err = e.repair("", nil)
	if err != nil || len(rep.Replaced) != 0 || len(rep.Damaged) != 0 || rep.Checked != 4*len(derive.Builders) {
		t.Fatalf("a second run: %+v %v", rep, err)
	}
	// --batch: one batch only.
	if rep, err := e.repair(e.ms[3].BatchID, nil); err != nil || rep.Batches != 1 || rep.Checked != len(derive.Builders) {
		t.Fatalf("--batch: %+v %v", rep, err)
	}
	if _, err := e.repair("fakelog/999999999999-999999999999", nil); !errors.Is(err, ErrUnknownBatch) {
		t.Fatalf("an unknown batch: %v", err)
	}
}

// TestRepairDerivedRefuses: a file whose recorded checksum the rebuild does
// not reproduce is left as it is, and so is a batch whose source data is
// damaged; both are reported (amendment A5 §3.2-3.3).
func TestRepairDerivedRefuses(t *testing.T) {
	e := newRepairEnv(t)
	// A recorded checksum that no rebuild can reproduce.
	p := filepath.Join(e.dirs[0], commit.ManifestFile)
	m, _ := os.ReadFile(p)
	sum := e.ms[0].Files["names.p1.parquet"].SHA256
	os.WriteFile(p, bytes.Replace(m, []byte(sum), []byte(strings.Repeat("0", 64)), 1), 0o644)
	// A damaged source file in another batch, and its damaged certs file.
	entries := filepath.Join(e.dirs[1], dataset.EntriesFile)
	b, _ := os.ReadFile(entries)
	b[len(b)/2] ^= 0xff
	os.WriteFile(entries, b, 0o644)
	certs := filepath.Join(e.dirs[1], "certs.p1.parquet")
	bad := bytes.Clone(e.saved[certs])
	bad[10] ^= 0xff
	os.WriteFile(certs, bad, 0o644)

	rep, err := e.repair("", nil)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(rep.Damaged, "\n")
	if len(rep.Replaced) != 0 || len(rep.Damaged) != 2 || !strings.Contains(all, "names.p1.parquet rebuilt with SHA-256") ||
		!strings.Contains(all, dataset.EntriesFile) || !strings.Contains(all, "backup") {
		t.Fatalf("report %+v", rep)
	}
	if got, _ := os.ReadFile(certs); !bytes.Equal(got, bad) {
		t.Fatal("a batch with damaged source data had a derived file replaced")
	}
	if got, _ := os.ReadFile(filepath.Join(e.dirs[0], "names.p1.parquet")); !bytes.Equal(got, e.saved[filepath.Join(e.dirs[0], "names.p1.parquet")]) {
		t.Fatal("a file was replaced though its rebuild does not match the recorded checksum")
	}
}
