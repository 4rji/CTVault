//go:build !ctvault_dev

package cli

import (
	"strings"
	"testing"
)

func TestProductionBuildHasNoDevBanner(t *testing.T) {
	e := newEnv(t, realSTH(t))
	e.mustRun("version")
	if strings.Contains(e.stdout.String()+e.stderr.String(), "DEV BUILD") {
		t.Fatalf("production output mentions a dev build: %q %q", e.stdout, e.stderr)
	}
}

func TestProductionBuildHasNoSampleCommand(t *testing.T) {
	e := newEnv(t, realSTH(t))
	if code := e.run("sample", "verify", "x"); code == 0 || !strings.Contains(e.stderr.String(), `unknown command "sample"`) {
		t.Fatalf("production must not know sample: exit %d, %s", code, e.stderr)
	}
}
