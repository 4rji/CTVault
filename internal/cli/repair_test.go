package cli

import (
	"crypto/sha256"
	"path/filepath"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
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

	if code := e.run("--root", e.root, "repair"); code != exitcode.Usage {
		t.Fatalf("repair without --reindex: exit %d", code)
	}
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
