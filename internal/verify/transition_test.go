package verify_test

import (
	"testing"

	"github.com/4rji/ctvault/internal/derivetest"
	"github.com/4rji/ctvault/internal/querytest"
	. "github.com/4rji/ctvault/internal/verify"
)

// TestVerifyTransitionStates: verify finds no damage in a vault caught in
// the middle of a transition: an upgrade side by side, an in-place
// conversion, a new table being built (amendment A5 §11).
func TestVerifyTransitionStates(t *testing.T) {
	for _, c := range []struct {
		name, registry string
		inPlace        bool
	}{
		{"side by side", "v2", false},
		{"in place", "v2", true},
		{"a new table", "new-table", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			g, es := querytest.Pairs(t, 60)
			v := querytest.New(t, g, es, 20, 1000)
			derivetest.Use(t, c.registry)
			w := querytest.Open(t, v, 1000)
			if c.inPlace {
				if err := w.StartInPlace(); err != nil {
					t.Fatal(err)
				}
			}
			if _, pending, err := w.RebuildTurn(ctx, 1); err != nil || !pending {
				t.Fatalf("one turn: %v %v", pending, err)
			}
			w.Close()
			r := run(t, fullOptions(t, v.Root))
			if r.Damaged() || r.Check("index").Status != StatusOK {
				t.Fatalf("mid-transition:\n%s", text(r))
			}
		})
	}
}
