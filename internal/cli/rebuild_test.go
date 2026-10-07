package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/ingest"
)

// TestRebuildCommand: rebuild has nothing to do on a complete vault; on a
// vault whose tables are building, update warns and rebuild switches them
// to complete (amendment A2 §5.2, §5.5).
func TestRebuildCommand(t *testing.T) {
	e, _ := updateEnv(t, 80, ctlogtest.Options{})
	e.mustRun("--root", e.root, "update")
	if out := e.mustRun("--root", e.root, "rebuild"); !strings.Contains(out, "nothing to rebuild") {
		t.Fatalf("rebuild on a complete vault: %s", out)
	}
	if err := os.Remove(filepath.Join(e.root, "dataset", derive.ActiveFile)); err != nil {
		t.Fatal(err)
	}
	e.mustRun("--root", e.root, "update")
	if msg := e.stderr.String(); !strings.Contains(msg, "certs v1 is being built (2 of 2 batches have it)") || !strings.Contains(msg, "names v1 is being built") || !strings.Contains(msg, "`ctvault rebuild` finishes it now") {
		t.Fatalf("update on a building vault warns: %q", msg)
	}
	out := e.mustRun("--root", e.root, "rebuild")
	if a, _, _ := derive.ReadActive(e.root); !a.AllComplete() || !strings.Contains(out, "certs, names, cert_extensions, cert_policies, cert_ekus, cert_key_usage, cert_aia, cert_crl_dps and cert_scts are complete") {
		t.Fatalf("rebuild: %+v\n%s", a, out)
	}
	e.mustRun("--root", e.root, "update")
	if msg := e.stderr.String(); strings.Contains(msg, "being built") {
		t.Fatalf("update after the rebuild still warns: %q", msg)
	}
}

// TestRebuildErrorsAreVerificationFailures: an index or dataset
// inconsistency exits 5, like corruption (amendment A2 §5.2).
func TestRebuildErrorsAreVerificationFailures(t *testing.T) {
	for _, err := range []error{ingest.ErrIndexInconsistent, ingest.ErrDatasetInconsistent} {
		if got := exitcode.Of(ingestErr(fmt.Errorf("rebuilding batch x: %w", err))); got != exitcode.Verification {
			t.Errorf("%v: exit %d", err, got)
		}
	}
}
