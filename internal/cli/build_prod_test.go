//go:build !ctvault_dev

package cli

import (
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/exitcode"
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

func TestProductionUpdateHasNoReplay(t *testing.T) {
	e := newEnv(t, realSTH(t))
	if code := e.run("update", "--replay", "x"); code != exitcode.Usage || !strings.Contains(e.stderr.String(), "unknown flag") {
		t.Fatalf("production must not know --replay: exit %d, %s", code, e.stderr)
	}
}
