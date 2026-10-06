package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/exitcode"
)

// TestSearchCommand: search's modes, groups and formats from the CLI, its
// usage errors, and export to a file (amendment A3 §3, §5).
func TestSearchCommand(t *testing.T) {
	e, _ := updateEnv(t, 80, ctlogtest.Options{})
	e.mustRun("--root", e.root, "update")

	out := e.mustRun("--root", e.root, "search", "example.test", "--sort", "name asc", "--limit", "3")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[0], "NAME") || !strings.HasPrefix(lines[1], "host0.example.test") {
		t.Fatalf("table:\n%s", out)
	}
	var doc struct {
		Meta struct {
			RowCount int `json:"row_count"`
		} `json:"meta"`
		Rows []map[string]any `json:"rows"`
	}
	raw := e.mustRun("--root", e.root, "search", "example.test", "--format", "json")
	if err := json.Unmarshal([]byte(raw), &doc); err != nil || len(doc.Rows) != 80 || doc.Meta.RowCount != 80 {
		t.Fatalf("json: %d rows, %v\n%s", len(doc.Rows), err, raw)
	}
	if out := e.mustRun("--root", e.root, "search", "--exact", "host1.example.test", "--group", "certs", "--format", "csv"); strings.Count(out, "\n") != 3 {
		t.Fatalf("csv of host1's two certificates:\n%s", out)
	}
	if out := e.mustRun("--root", e.root, "search", "--contains", "host3", "--format", "csv", "--fields", "name"); !strings.Contains(e.stderr.String(), "full scan") || strings.Count(out, "\n") != 23 {
		t.Fatalf("--contains: %q, stderr %q", out, e.stderr)
	}

	dst := filepath.Join(t.TempDir(), "r.json")
	e.mustRun("--root", e.root, "search", "example.test", "--group", "issuances", "--format", "json", "--output", dst)
	if b, err := os.ReadFile(dst); err != nil || !strings.Contains(string(b), `"row_count": 40`) {
		t.Fatalf("export: %v\n%s", err, b)
	}
	for _, c := range []struct {
		args []string
		code int
	}{
		{[]string{"search", "host1.example.test"}, exitcode.Usage},
		{[]string{"search"}, exitcode.Usage},
		{[]string{"search", "example.test", "--exact", "a.example.test"}, exitcode.Usage},
		{[]string{"search", "example.test", "--since", "yesterday"}, exitcode.Usage},
		{[]string{"search", "example.test", "--format", "table", "--output", dst + ".txt"}, exitcode.Usage},
		{[]string{"search", "example.test", "--format", "json", "--output", dst}, exitcode.Error},
	} {
		if code := e.run(append([]string{"--root", e.root}, c.args...)...); code != c.code {
			t.Errorf("%v: exit %d, want %d (%s)", c.args, code, c.code, e.stderr)
		}
	}
	if code := e.run("--root", e.root, "search", "host1.example.test"); code != exitcode.Usage || !strings.Contains(e.stderr.String(), "--suffix") {
		t.Fatalf("a non-registrable domain suggests --suffix: %s", e.stderr)
	}
}
