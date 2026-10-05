package extract

import (
	"reflect"
	"slices"
	"testing"
)

// FuzzParse: the extractor never panics, gives the same result twice, and
// its status always agrees with its codes (amendment A2 §3.4).
func FuzzParse(f *testing.F) {
	for _, m := range malformedCorpus() {
		f.Add(m.der)
	}
	for _, der := range corpus(f)[:50] {
		f.Add(der)
	}
	f.Fuzz(func(t *testing.T, der []byte) {
		c := Parse(der)
		if again := Parse(der); !reflect.DeepEqual(c, again) {
			t.Fatal("two parses of the same bytes differ")
		}
		failed := slices.Contains(c.Errors, CertUnreadable) || slices.Contains(c.Errors, TBSUnreadable)
		switch {
		case failed && c.Status != StatusFailed,
			!failed && len(c.Errors) > 0 && c.Status != StatusPartial,
			len(c.Errors) == 0 && c.Status != StatusOK:
			t.Fatalf("status %s with codes %v", c.Status, c.Errors)
		}
		seen := map[Code]bool{}
		for _, code := range c.Errors {
			if seen[code] || code.Explain() == "" {
				t.Fatalf("code %q repeated or unknown in %v", code, c.Errors)
			}
			seen[code] = true
		}
		_ = c.Issuer.String()
		_ = c.Subject.String()
	})
}
