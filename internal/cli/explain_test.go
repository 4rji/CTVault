package cli

import (
	"bufio"
	"os"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/extract"
	"github.com/4rji/ctvault/internal/leaf"
)

func TestExplainError(t *testing.T) {
	e := newEnv(t, nil)
	if out := e.mustRun("explain-error", "serial_negative"); !strings.Contains(out, "serial_negative (certificate parse error): ") {
		t.Fatalf("output: %q", out)
	}
	if out := e.mustRun("explain-error", "leaf_bad_version"); !strings.Contains(out, "leaf_bad_version (log entry error): ") {
		t.Fatalf("output: %q", out)
	}
	if code := e.run("explain-error", "no_such_code"); code != exitcode.Usage || !strings.Contains(e.stderr.String(), "unknown error code") {
		t.Fatalf("unknown code: exit %d, %s", code, e.stderr)
	}
	if code := e.run("explain-error"); code != exitcode.Usage {
		t.Fatalf("no code: exit %d", code)
	}
}

// TestErrorCodesAreFrozen: error codes are stored in datasets
// (certs.parse_errors, entries.leaf_error), so a published code is never
// renamed or removed (amendment A2 §3.3). testdata/error_codes.txt lists
// every published code; a new code is appended to it.
func TestErrorCodesAreFrozen(t *testing.T) {
	f, err := os.Open("testdata/error_codes.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	listed := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		catalog, code, ok := strings.Cut(line, " ")
		var explained bool
		switch catalog {
		case "extract":
			explained = extract.Code(code).Explain() != ""
		case "leaf":
			explained = leaf.Code(code).Explain() != ""
		}
		if !ok || !explained {
			t.Errorf("published code %q no longer exists", line)
		}
		listed[line] = true
	}
	for _, c := range extract.Codes {
		if !listed["extract "+string(c)] {
			t.Errorf("new code %s: append \"extract %s\" to testdata/error_codes.txt", c, c)
		}
	}
	for _, c := range leaf.Codes {
		if !listed["leaf "+string(c)] {
			t.Errorf("new code %s: append \"leaf %s\" to testdata/error_codes.txt", c, c)
		}
	}
}
