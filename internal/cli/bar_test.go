package cli

import (
	"reflect"
	"testing"

	"github.com/4rji/ctvault/internal/query"
)

// TestBarMatchesSearchFlags: explore's query bar and search's flags build
// the same query (amendment A4 §2.1), so both give the same results.
func TestBarMatchesSearchFlags(t *testing.T) {
	for _, c := range []struct {
		bar  string
		args []string
	}{
		{"example.com", []string{"example.com"}},
		{`suffix:api.example.com issuer:"Let's Encrypt" since:2026-10 kind:final`,
			[]string{"--suffix", "api.example.com", "--issuer", "Let's Encrypt", "--since", "2026-10", "--kind", "final"}},
		{`exact:a.example.com org:"CTVault Tests" key:ecdsa status:ok valid-at:2026-10-15 wildcard log:argon2027h1 until:2027 by:not-before issued-by:42`,
			[]string{"--exact", "a.example.com", "--issuer-org", "CTVault Tests", "--key-alg", "ecdsa", "--parse-status", "ok", "--valid-at", "2026-10-15",
				"--wildcard", "--log", "argon2027h1", "--until", "2027", "--by", "not-before", "--issued-by", "42"}},
		{"contains:host2 kind:precert,final", []string{"--contains", "host2", "--kind", "precert,final"}},
	} {
		fromBar, err := query.ParseBar(c.bar)
		if err != nil {
			t.Fatal(err)
		}
		cmd, sf := newSearchCommand(&app{})
		if err := cmd.ParseFlags(c.args); err != nil {
			t.Fatal(err)
		}
		fromFlags, err := sf.query(cmd.Flags().Args())
		if err != nil {
			t.Fatal(err)
		}
		fromFlags.Group, fromFlags.Limit = "", 0 // set by the CLI and by Tab, not by the bar
		if !reflect.DeepEqual(fromBar, fromFlags) {
			t.Errorf("%q:\n bar   %+v\n flags %+v", c.bar, fromBar, fromFlags)
		}
	}
}
