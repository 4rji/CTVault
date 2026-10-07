package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/exitcode"
)

// TestVerifyCommand: ctvault verify reports each check, exits 0 on a sound
// vault and 5 on damage, writes JSON with --json, and reports --full's
// progress on stderr (amendment A5 §1).
func TestVerifyCommand(t *testing.T) {
	e, _ := updateEnv(t, 80, ctlogtest.Options{})
	e.mustRun("--root", e.root, "update")

	out := e.mustRun("--root", e.root, "verify")
	if !strings.Contains(out, "verify --quick: 2 batches") || !strings.Contains(out, "result: no damage found") {
		t.Fatalf("verify:\n%s", out)
	}
	out = e.mustRun("--root", e.root, "verify", "--full")
	if !strings.Contains(out, "ok      index") || !strings.Contains(out, "ok      records") || !strings.Contains(e.stderr.String(), "verify: records: 2 of 2 batches") {
		t.Fatalf("verify --full:\n%s\nstderr:\n%s", out, e.stderr)
	}
	var rep struct {
		Mode    string `json:"mode"`
		Batches int    `json:"batches"`
	}
	if err := json.Unmarshal([]byte(e.mustRun("--root", e.root, "verify", "--json")), &rep); err != nil || rep.Mode != "quick" || rep.Batches != 2 {
		t.Fatalf("verify --json: %+v %v", rep, err)
	}
	for _, args := range [][]string{{"verify", "--as-of", "9"}, {"verify", "--quick", "--full"}, {"verify", "extra"}} {
		if code := e.run(append([]string{"--root", e.root}, args...)...); code != exitcode.Usage {
			t.Errorf("%v: exit %d, want %d", args, code, exitcode.Usage)
		}
	}

	ms := committed(t, e.root)
	p := filepath.Join(commit.Paths{Root: e.root}.BatchDir(ms[0].ID()), dataset.EntriesFile)
	b, _ := os.ReadFile(p)
	b[100] ^= 0xff
	os.WriteFile(p, b, 0o644)
	e.mustRun("--root", e.root, "verify") // --quick reads no content
	if code := e.run("--root", e.root, "verify", "--full"); code != exitcode.Verification || !strings.Contains(e.stdout.String(), "FAIL    checksums") {
		t.Fatalf("a damaged file: exit %d\n%s", code, e.stdout)
	}
}
