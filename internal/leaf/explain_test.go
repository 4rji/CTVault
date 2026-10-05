package leaf

import "testing"

// TestEveryLeafCodeIsExplained: explain-error covers the leaf codes too
// (spec §11.2: "Explain a parse or leaf error code").
func TestEveryLeafCodeIsExplained(t *testing.T) {
	for _, c := range Codes {
		if c.Explain() == "" {
			t.Errorf("%s has no explanation", c)
		}
	}
	if Code("no_such_code").Explain() != "" || OK.Explain() != "" {
		t.Error("an unknown or empty code has an explanation")
	}
}
