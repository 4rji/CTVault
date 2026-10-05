package extract

import (
	"regexp"
	"testing"
)

var codeFormat = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// TestEveryCodeIsExplained: each parse error code is listed once, is a
// compact lowercase identifier, and has an explanation for explain-error.
func TestEveryCodeIsExplained(t *testing.T) {
	seen := map[Code]bool{}
	for _, c := range Codes {
		if seen[c] {
			t.Errorf("%s is listed twice", c)
		}
		seen[c] = true
		if !codeFormat.MatchString(string(c)) {
			t.Errorf("%q is not a compact lowercase code", c)
		}
		if c.Explain() == "" {
			t.Errorf("%s has no explanation", c)
		}
	}
	if Code("no_such_code").Explain() != "" {
		t.Error("an unknown code has an explanation")
	}
}
