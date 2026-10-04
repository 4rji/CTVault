//go:build ctvault_dev

package volume_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/4rji/ctvault/internal/volume"
	"github.com/4rji/ctvault/internal/volume/volumetest"
)

// newDev returns a dev probe whose base is a temp folder; the fake mount
// table places it on "/" (ext4, UUID "system-root"), like a laptop's disk.
func newDev(t *testing.T) (volume.DevProbe, *volumetest.Probe, string) {
	t.Helper()
	p := volumetest.New()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return volume.DevProbe{Base: base, Probe: p, Now: fixedNow}, p, base
}

func TestDevBuildIsOn(t *testing.T) {
	if !volume.DevBuild() {
		t.Fatal("DevBuild() must be true with -tags ctvault_dev")
	}
}

func TestDevInitAndCheck(t *testing.T) {
	d, _, base := newDev(t)
	root := filepath.Join(base, "vaults", "try1") // created by Init
	id, err := d.Init(root, volume.InitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if id.Mode != volume.ModeDev || id.Durability != volume.DurabilityDevUnsafe {
		t.Fatalf("dev VAULT_ID = %+v", id)
	}
	if id.Volumes[0].FSUUID != "system-root" {
		t.Fatalf("dev vault must record the normal disk's real UUID: %+v", id.Volumes[0])
	}
	if _, err := d.Check(root); err != nil {
		t.Fatalf("Check of a fresh dev vault: %v", err)
	}
}

func TestDevRefusesPathsOutsideTheBase(t *testing.T) {
	d, _, base := newDev(t)
	_, err := d.Init(t.TempDir(), volume.InitOptions{})
	wantVolumeErr(t, err, "outside the dev base")
	_, err = d.Init(base, volume.InitOptions{})
	wantVolumeErr(t, err, "outside the dev base")
	_, err = d.Init(filepath.Join(base, "..", "sneaky"), volume.InitOptions{})
	wantVolumeErr(t, err, "outside the dev base")
}

func TestDevRefusesSymlinkEscape(t *testing.T) {
	d, _, base := newDev(t)
	if err := os.MkdirAll(filepath.Join(base, "vaults"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "vaults", "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	_, err := d.Init(link, volume.InitOptions{})
	wantVolumeErr(t, err, "escapes the dev base")
}

func TestDevRefusesProductionVault(t *testing.T) {
	d, p, base := newDev(t)
	root := filepath.Join(base, "vaults", "prod")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	p.Mount(t, root, "ext4", "8:17", "ssd-uuid") // present it as a real SSD to create a production vault
	if _, err := (volume.Checker{Probe: p, Now: fixedNow}).Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	_, err := d.Check(root)
	wantVolumeErr(t, err, "production vault; the ctvault_dev build refuses it")
}

func TestDevRefusesNetworkFuseAndTmpfs(t *testing.T) {
	for _, fstype := range []string{"tmpfs", "nfs4", "fuse.sshfs", "fuseblk"} {
		d, p, base := newDev(t)
		p.Mounts[0].FSType = fstype // the base now sits on this filesystem
		_, err := d.Init(filepath.Join(base, "vaults", "v"), volume.InitOptions{})
		wantVolumeErr(t, err, "dev vaults need a local filesystem")
	}
}

func TestDevCheckDetectsDifferentFilesystem(t *testing.T) {
	d, p, base := newDev(t)
	root := filepath.Join(base, "vaults", "try1")
	if _, err := d.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	p.UUIDs["8:1"] = "another-disk"
	_, err := d.Check(root)
	wantVolumeErr(t, err, "VAULT_ID records")
}

// TestDevProbeOnThisMachine uses the real mount table and /dev/disk/by-uuid,
// with a temp folder as the dev base (never the user's ~/.cache).
func TestDevProbeOnThisMachine(t *testing.T) {
	if _, err := os.Stat("/dev/disk/by-uuid"); err != nil {
		t.Skip("no /dev/disk/by-uuid on this host")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d := volume.DevProbe{Base: base, Probe: volume.HostProbe{}, Now: fixedNow}
	root := filepath.Join(base, "vaults", "machine")
	id, err := d.Init(root, volume.InitOptions{})
	if err != nil {
		t.Skipf("temp folder is not usable for a dev vault on this host: %v", err)
	}
	if id.Volumes[0].FSUUID == "" {
		t.Fatal("dev vault recorded no filesystem UUID")
	}
	if _, err := d.Check(root); err != nil {
		t.Fatalf("Check on the real host: %v", err)
	}
}

func TestDevAddDirUnsupported(t *testing.T) {
	d, _, base := newDev(t)
	root := filepath.Join(base, "vaults", "try1")
	if _, err := d.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	_, err := d.AddDir(root, filepath.Join(base, "x"), volume.InitOptions{})
	wantVolumeErr(t, err, "production-only")
}
