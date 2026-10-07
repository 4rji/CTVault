package cli

import (
	"crypto/sha256"
	"fmt"
	"github.com/4rji/ctvault/internal/derive"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/index"
)

// TestRepairReindex: repair --reindex replaces an index holding a key the
// vault does not have with one rebuilt from the vault, and the vault keeps
// working; repair without --reindex is a usage error (amendment A2 §5.6).
func TestRepairReindex(t *testing.T) {
	e, _ := updateEnv(t, 80, ctlogtest.Options{})
	e.mustRun("--root", e.root, "update")
	x, err := index.Open(filepath.Join(e.root, "state", "pebble"))
	if err != nil {
		t.Fatal(err)
	}
	bogus := sha256.Sum256([]byte("not vaulted"))
	b := x.NewBatch()
	b.AddCert(bogus, index.Ref{CertID: 1 << 40})
	b.Commit()
	b.Close()
	x.Close()

	out := e.mustRun("--root", e.root, "repair", "--reindex")
	if !strings.Contains(out, "rebuilt the index from 2 batches") {
		t.Fatalf("repair --reindex: %s", out)
	}
	x, err = index.Open(filepath.Join(e.root, "state", "pebble"))
	if err != nil {
		t.Fatal(err)
	}
	_, ok, _ := x.Lookup(bogus)
	x.Close()
	if ok {
		t.Fatal("the key the vault does not have survived repair --reindex")
	}
	if out := e.mustRun("--root", e.root, "update"); !strings.Contains(out, "up to date") {
		t.Fatalf("update after the repair: %s", out)
	}
}

// TestRepairDerivedCommand: repair --derived rebuilds a damaged certs file,
// after which verify --full passes; damaged source data is refused with
// exit 5; repair needs exactly one of --reindex and --derived (amendment A5
// §3.2-3.4).
func TestRepairDerivedCommand(t *testing.T) {
	e, _ := updateEnv(t, 80, ctlogtest.Options{})
	e.mustRun("--root", e.root, "update")
	ms := committed(t, e.root)
	flip := func(m commit.Manifest, name string) {
		p := filepath.Join(commit.Paths{Root: e.root}.BatchDir(m.ID()), name)
		b, _ := os.ReadFile(p)
		b[len(b)/2] ^= 0xff
		os.WriteFile(p, b, 0o644)
	}
	flip(ms[1], "certs.p1.parquet")

	for _, args := range [][]string{{"repair"}, {"repair", "--reindex", "--derived"}, {"repair", "--batch", ms[1].BatchID},
		{"repair", "--derived", "--batch", "fakelog/000000000999-000000000999"}} {
		if code := e.run(append([]string{"--root", e.root}, args...)...); code != exitcode.Usage {
			t.Errorf("%v: exit %d, want %d", args, code, exitcode.Usage)
		}
	}
	if e.run("--root", e.root, "repair"); !strings.Contains(e.stderr.String(), "--derived") || !strings.Contains(e.stderr.String(), "verify") {
		t.Fatalf("repair with no flag: %s", e.stderr)
	}
	out := e.mustRun("--root", e.root, "repair", "--derived")
	if !strings.Contains(out, "replaced "+ms[1].BatchID+"/certs.p1.parquet") || !strings.Contains(out, fmt.Sprintf("checked %d derived files in 2 batches; replaced 1", 2*len(derive.Builders))) {
		t.Fatalf("repair --derived:\n%s", out)
	}
	e.mustRun("--root", e.root, "verify", "--full")

	flip(ms[0], dataset.EntriesFile)
	flip(ms[0], "names.p1.parquet")
	if code := e.run("--root", e.root, "repair", "--derived"); code != exitcode.Verification || !strings.Contains(e.stdout.String(), "backup") {
		t.Fatalf("damaged source data: exit %d\n%s\n%s", code, e.stdout, e.stderr)
	}
}
