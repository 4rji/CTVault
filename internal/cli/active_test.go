package cli

import (
	"testing"

	"github.com/4rji/ctvault/internal/derive"
)

// TestInitWritesActive: a new vault's derived tables are complete from the
// start (amendment A2 §4.6).
func TestInitWritesActive(t *testing.T) {
	e := newEnv(t, nil)
	e.mustRun("init", e.root)
	if a, ok, err := derive.ReadActive(e.root); !ok || err != nil || !a.AllComplete() {
		t.Fatalf("ACTIVE.json after init: %+v %v %v", a, ok, err)
	}
}
