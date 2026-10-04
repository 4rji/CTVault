package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/volume"
)

func TestDevVaultRefusedWithExit4(t *testing.T) {
	e := newEnv(t, realSTH(t))
	e.mustRun("init", e.root)
	id, err := volume.ReadVaultID(e.root)
	if err != nil {
		t.Fatal(err)
	}
	id.Mode = volume.ModeDev
	b, _ := json.Marshal(id)
	os.WriteFile(filepath.Join(e.root, volume.VaultIDFile), b, 0o644)
	if got := e.run("--root", e.root, "logs", "list"); got != exitcode.Volume {
		t.Fatalf("dev vault in a production build: exit %d, want %d", got, exitcode.Volume)
	}
	if !strings.Contains(e.stderr.String(), "dev vault created by a ctvault_dev build") {
		t.Fatalf("stderr: %s", e.stderr)
	}
}
