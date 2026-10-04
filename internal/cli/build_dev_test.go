//go:build ctvault_dev

package cli

import (
	"strings"
	"testing"
)

func TestDevBuildIsMarkedEverywhere(t *testing.T) {
	e := newEnv(t, realSTH(t))
	e.mustRun("version")
	if !strings.Contains(e.stdout.String(), "DEV BUILD — not for production") {
		t.Fatalf("version output: %q", e.stdout)
	}
	if !strings.Contains(e.stderr.String(), "WARNING: DEV BUILD") {
		t.Fatalf("every command must print the dev banner, stderr: %q", e.stderr)
	}
}
