package cli

import (
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/query"
)

// TestExploreNeedsATerminal: without a terminal, explore exits 2 and
// points to search (amendment A4 §4).
func TestExploreNeedsATerminal(t *testing.T) {
	e, _ := updateEnv(t, 20, ctlogtest.Options{})
	e.mustRun("--root", e.root, "update")
	if code := e.run("--root", e.root, "explore", "example.test"); code != exitcode.Usage || !strings.Contains(e.stderr.String(), "ctvault search") {
		t.Fatalf("exit %d, stderr %q", code, e.stderr)
	}
}

// TestBarArgs: explore's arguments become the bar's text: one argument is
// the whole bar; a key:value argument with spaces, which the shell
// unquoted, is quoted again.
func TestBarArgs(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		{nil, ""},
		{[]string{"example.com"}, "example.com"},
		{[]string{"example.com since:2026-10 kind:final"}, "example.com since:2026-10 kind:final"},
		{[]string{"example.com", "issuer:Let's Encrypt", "since:2026-10"}, `example.com issuer:"Let's Encrypt" since:2026-10`},
		{[]string{"example.com", `org:A "B" C`}, `example.com org:A "B" C`},
		{[]string{"example.com", `issuer:"Let's Encrypt"`}, `example.com issuer:"Let's Encrypt"`},
	} {
		if got := barArgs(c.args); got != c.want {
			t.Errorf("%q: %q, want %q", c.args, got, c.want)
		}
	}
	q, err := query.ParseBar(barArgs([]string{"example.com", "issuer:Let's Encrypt"}))
	if err != nil || q.Issuer != "Let's Encrypt" || q.Text != "example.com" {
		t.Fatalf("%+v %v", q, err)
	}
}
