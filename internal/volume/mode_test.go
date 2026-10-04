package volume_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/4rji/ctvault/internal/volume"
)

// rewriteVaultID lets a test edit VAULT_ID in place.
func rewriteVaultID(t *testing.T, root string, edit func(*volume.VaultID)) {
	t.Helper()
	id, err := volume.ReadVaultID(root)
	if err != nil {
		t.Fatal(err)
	}
	edit(&id)
	b, _ := json.Marshal(id)
	if err := os.WriteFile(filepath.Join(root, volume.VaultIDFile), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestInitRecordsProductionMode(t *testing.T) {
	c, _, root := newSSD(t)
	id, err := c.Init(root, volume.InitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if id.Mode != volume.ModeProduction {
		t.Fatalf("mode = %q, want %q", id.Mode, volume.ModeProduction)
	}
}

func TestProductionRefusesDevVault(t *testing.T) {
	c, _, root := newSSD(t)
	if _, err := c.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	rewriteVaultID(t, root, func(id *volume.VaultID) { id.Mode = volume.ModeDev })
	_, err := c.Check(root)
	wantVolumeErr(t, err, "dev vault created by a ctvault_dev build")
}

func TestUnknownModeRefusedAndMissingModeIsProduction(t *testing.T) {
	c, _, root := newSSD(t)
	if _, err := c.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	rewriteVaultID(t, root, func(id *volume.VaultID) { id.Mode = "" }) // a Plan 1 vault
	if _, err := c.Check(root); err != nil {
		t.Fatalf("a VAULT_ID without mode is a production vault: %v", err)
	}
	rewriteVaultID(t, root, func(id *volume.VaultID) { id.Mode = "staging" })
	_, err := c.Check(root)
	wantVolumeErr(t, err, "unknown vault mode")
}

// Plan 1 review, minor 6: the root checks run whatever VAULT_ID lists.
func TestCheckRequiresExactlyOneRoot(t *testing.T) {
	c, _, root := newSSD(t)
	if _, err := c.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	rewriteVaultID(t, root, func(id *volume.VaultID) { id.Volumes = nil })
	_, err := c.Check(root)
	wantVolumeErr(t, err, "exactly one root volume")

	rewriteVaultID(t, root, func(id *volume.VaultID) {
		id.Volumes = []volume.Volume{{Role: volume.RoleRoot}, {Role: volume.RoleRoot}}
	})
	_, err = c.Check(root)
	wantVolumeErr(t, err, "exactly one root volume")
}

func TestCheckEmptyVolumesInPlainDirStillRefused(t *testing.T) {
	c, p, root := newSSD(t)
	if _, err := c.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	rewriteVaultID(t, root, func(id *volume.VaultID) { id.Volumes = nil })
	p.Mounts = p.Mounts[:1] // now a plain directory on the system disk
	_, err := c.Check(root)
	wantVolumeErr(t, err, "not a mount point")
}

// Plan 1 review, minor 7: layout folders must stay on the vault's filesystem.
func TestCheckRefusesSymlinkedLayoutFolder(t *testing.T) {
	c, _, root := newSSD(t)
	if _, err := c.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir() // on the system disk in the fake mount table
	state := filepath.Join(root, "state")
	if err := os.RemoveAll(state); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, state); err != nil {
		t.Fatal(err)
	}
	_, err := c.Check(root)
	wantVolumeErr(t, err, "is a symlink")
}

func TestCheckRefusesLayoutFolderOnAnotherFilesystem(t *testing.T) {
	c, p, root := newSSD(t)
	if _, err := c.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	p.Mount(t, filepath.Join(root, "state"), "ext4", "8:65", "other-disk")
	_, err := c.Check(root)
	wantVolumeErr(t, err, "different filesystem")
}

func TestCheckRefusesMissingLayoutFolder(t *testing.T) {
	c, _, root := newSSD(t)
	if _, err := c.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(filepath.Join(root, "dataset"))
	_, err := c.Check(root)
	wantVolumeErr(t, err, "is missing")
}
