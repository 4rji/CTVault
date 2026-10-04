//go:build !ctvault_dev

package volume

import "testing"

func TestDevBuildIsOffInProductionBuilds(t *testing.T) {
	if DevBuild() {
		t.Fatal("DevBuild() must be false without -tags ctvault_dev")
	}
}
