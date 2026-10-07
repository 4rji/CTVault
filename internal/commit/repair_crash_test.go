package commit_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/ingest"
	"github.com/4rji/ctvault/internal/vault"
	"github.com/4rji/ctvault/internal/vaulttest"
)

// repairDerivedChild runs repair --derived as the CLI does: no writer, no
// recovery.
func repairDerivedChild(t *testing.T, root string, hook func(string)) {
	dirs := []string{filepath.Join(root, "vault")}
	codec, err := vault.NewCodec()
	if err != nil {
		t.Fatal(err)
	}
	defer codec.Close()
	dicts, err := vault.LoadDicts(dirs)
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
	x, err := index.OpenReadOnly(filepath.Join(root, "state", "pebble"))
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	rep, err := ingest.RepairDerived(t.Context(), ingest.RepairOptions{Root: root, VaultDirs: dirs, Codec: codec, Stager: stager, Index: x,
		CanarySamples: 16, Hook: hook})
	if err != nil || len(rep.Damaged) != 0 {
		t.Fatalf("repair --derived: %+v %v", rep, err)
	}
}

// TestRepairDerivedCrashes kills repair --derived after a batch's files are
// staged, and after the first damaged file is replaced (amendment A5 §4.3).
// Each damaged file is then either still the damaged copy or the rebuilt
// one, never partial or missing; a rerun completes, and the vault equals
// the undamaged one.
func TestRepairDerivedCrashes(t *testing.T) {
	if testing.Short() {
		t.Skip("starts subprocesses")
	}
	l := ctlogtest.New(t, crashEntries, ctlogtest.Options{})
	base := newCrashRun(t, l, crashEntries, crashBatch)
	if base.child("", 0, 0) {
		t.Fatal("the ingest child was killed")
	}
	base.restart()
	want := base.v.Dump(t)
	ms, err := commit.ListCommitted(base.v.Root)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []struct {
		point     string
		nth       int
		repairedN int // damaged files already replaced at the kill
	}{{ingest.HookRepairStaged, 1, 0}, {ingest.HookRepairReplaced, 1, 1}} {
		t.Run(p.point, func(t *testing.T) {
			r := copyRun(t, base, l)
			r.t = t
			type file struct {
				path string
				good string // the recorded SHA-256
				bad  []byte
			}
			var files []file
			for _, m := range ms[:2] {
				fp := filepath.Join(commit.Paths{Root: r.v.Root}.BatchDir(m.ID()), "certs.p1.parquet")
				b, _ := os.ReadFile(fp)
				b[len(b)/2] ^= 0xff
				os.WriteFile(fp, b, 0o644)
				fi, _ := m.Listed("certs.p1.parquet")
				files = append(files, file{fp, fi.SHA256, b})
			}
			r.cfg.Mode = "repair-derived"
			if !r.child(p.point, p.nth, 0) {
				t.Fatalf("repair --derived finished without reaching %s", p.point)
			}
			repaired := 0
			for _, f := range files {
				b, err := os.ReadFile(f.path)
				sum := sha256.Sum256(b)
				switch {
				case err != nil:
					t.Fatalf("%s is gone after the kill: %v", f.path, err)
				case hex.EncodeToString(sum[:]) == f.good:
					repaired++
				case !bytes.Equal(b, f.bad):
					t.Fatalf("%s is neither the damaged copy nor the rebuilt file after the kill", f.path)
				}
			}
			if repaired != p.repairedN {
				t.Fatalf("%d files replaced at the kill, want %d", repaired, p.repairedN)
			}
			if r.child("", 0, 0) {
				t.Fatal("the rerun was killed")
			}
			r.restart()
			if d := vaulttest.Diff(r.v.Dump(t), want); d != "" {
				t.Fatal(d)
			}
		})
	}
}
