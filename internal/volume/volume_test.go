package volume_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/volume"
	"github.com/4rji/ctvault/internal/volume/volumetest"
)

var fixedNow = func() time.Time { return time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC) }

// newSSD returns a checker and a temp dir presented as an ext4 mount point
// on device 8:17 with UUID "ssd-uuid".
func newSSD(t *testing.T) (volume.Checker, *volumetest.Probe, string) {
	t.Helper()
	p := volumetest.New()
	root := p.Mount(t, t.TempDir(), "ext4", "8:17", "ssd-uuid")
	return volume.Checker{Probe: p, Now: fixedNow}, p, root
}

func wantVolumeErr(t *testing.T, err error, substr string) {
	t.Helper()
	if !errors.Is(err, volume.ErrVolume) {
		t.Fatalf("want ErrVolume, got %v", err)
	}
	if !strings.Contains(err.Error(), substr) {
		t.Fatalf("error %q does not mention %q", err, substr)
	}
}

func TestInitCreatesLayoutAndMarkers(t *testing.T) {
	c, _, root := newSSD(t)
	id, err := c.Init(root, volume.InitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if id.Durability != volume.DurabilityTested || len(id.Volumes) != 2 {
		t.Fatalf("unexpected VAULT_ID: %+v", id)
	}
	for _, d := range volume.LayoutDirs {
		if fi, err := os.Stat(filepath.Join(root, d)); err != nil || !fi.IsDir() {
			t.Errorf("layout dir %s missing", d)
		}
	}
	dir, err := volume.ReadDirID(filepath.Join(root, "vault"))
	if err != nil || dir.VaultUUID != id.VaultUUID || dir.FSUUID != "ssd-uuid" {
		t.Fatalf("DIR_ID = %+v, %v", dir, err)
	}
	got, err := c.Check(root)
	if err != nil {
		t.Fatalf("Check after Init: %v", err)
	}
	if got.VaultUUID != id.VaultUUID || !got.CreatedAt.Equal(fixedNow()) {
		t.Fatalf("Check returned %+v", got)
	}
}

func TestInitRefusals(t *testing.T) {
	t.Run("not a mount point", func(t *testing.T) {
		c, _, root := newSSD(t)
		sub := filepath.Join(root, "sub")
		os.Mkdir(sub, 0o755)
		_, err := c.Init(sub, volume.InitOptions{})
		wantVolumeErr(t, err, "not a mount point")
	})
	t.Run("system disk bind mount", func(t *testing.T) {
		p := volumetest.New()
		root := p.Mount(t, t.TempDir(), "ext4", "8:1", "system-root")
		_, err := volume.Checker{Probe: p}.Init(root, volume.InitOptions{})
		wantVolumeErr(t, err, "same device as /")
	})
	t.Run("untested filesystem", func(t *testing.T) {
		p := volumetest.New()
		root := p.Mount(t, t.TempDir(), "xfs", "8:17", "x")
		_, err := volume.Checker{Probe: p}.Init(root, volume.InitOptions{})
		wantVolumeErr(t, err, "--allow-untested-fs")
		id, err := volume.Checker{Probe: p}.Init(root, volume.InitOptions{AllowUntestedFS: true})
		if err != nil || id.Durability != volume.DurabilityUntested {
			t.Fatalf("with override: %+v, %v", id, err)
		}
	})
	t.Run("unsupported filesystem", func(t *testing.T) {
		p := volumetest.New()
		root := p.Mount(t, t.TempDir(), "exfat", "8:17", "x")
		_, err := volume.Checker{Probe: p}.Init(root, volume.InitOptions{AllowUntestedFS: true})
		wantVolumeErr(t, err, "exfat")
	})
	t.Run("nobarrier", func(t *testing.T) {
		p := volumetest.New()
		root := p.Mount(t, t.TempDir(), "ext4", "8:17", "x", "rw", "nobarrier")
		_, err := volume.Checker{Probe: p}.Init(root, volume.InitOptions{})
		wantVolumeErr(t, err, "nobarrier")
	})
	t.Run("no filesystem UUID", func(t *testing.T) {
		p := volumetest.New()
		root := p.Mount(t, t.TempDir(), "ext4", "8:17", "")
		_, err := volume.Checker{Probe: p}.Init(root, volume.InitOptions{})
		wantVolumeErr(t, err, "cannot determine filesystem UUID")
	})
	t.Run("not empty", func(t *testing.T) {
		c, _, root := newSSD(t)
		os.WriteFile(filepath.Join(root, "photos.zip"), nil, 0o644)
		_, err := c.Init(root, volume.InitOptions{})
		wantVolumeErr(t, err, "not empty")
	})
	t.Run("already initialized", func(t *testing.T) {
		c, _, root := newSSD(t)
		if _, err := c.Init(root, volume.InitOptions{}); err != nil {
			t.Fatal(err)
		}
		_, err := c.Init(root, volume.InitOptions{})
		wantVolumeErr(t, err, "already an initialized")
	})
}

func TestInitAllowsLostFoundAndRetry(t *testing.T) {
	c, _, root := newSSD(t)
	os.Mkdir(filepath.Join(root, "lost+found"), 0o700)
	os.MkdirAll(filepath.Join(root, "state", "intent"), 0o755) // interrupted earlier init
	if _, err := c.Init(root, volume.InitOptions{}); err != nil {
		t.Fatalf("Init should accept lost+found and partial layout: %v", err)
	}
}

func TestCheckDetectsDifferentFilesystem(t *testing.T) {
	c, p, root := newSSD(t)
	if _, err := c.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	p.UUIDs["8:17"] = "some-other-disk"
	_, err := c.Check(root)
	wantVolumeErr(t, err, "VAULT_ID records")
}

func TestCheckDetectsUnmountedDrive(t *testing.T) {
	c, p, root := newSSD(t)
	if _, err := c.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	p.Mounts = p.Mounts[:1] // only "/" remains: the path is now a plain directory on the system disk
	_, err := c.Check(root)
	wantVolumeErr(t, err, "not a mount point")
}

func TestCheckUninitialized(t *testing.T) {
	c, _, root := newSSD(t)
	_, err := c.Check(root)
	wantVolumeErr(t, err, "not an initialized CTVault root")
}

func TestCheckAcceptsTrailingSlashAndSymlink(t *testing.T) {
	c, _, root := newSSD(t)
	if _, err := c.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Check(root + "/"); err != nil {
		t.Fatalf("trailing slash: %v", err)
	}
	link := filepath.Join(t.TempDir(), "ctvault-link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Check(link); err != nil {
		t.Fatalf("symlink to root: %v", err)
	}
}

func TestCheckAfterRemountAtNewPath(t *testing.T) {
	c, _, oldRoot := newSSD(t)
	id, err := c.Init(oldRoot, volume.InitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// The same filesystem (same UUID) is mounted somewhere else next time.
	p2 := volumetest.New()
	newRoot := p2.Mount(t, t.TempDir(), "ext4", "8:65", "ssd-uuid")
	ents, _ := os.ReadDir(oldRoot)
	for _, e := range ents {
		if err := os.Rename(filepath.Join(oldRoot, e.Name()), filepath.Join(newRoot, e.Name())); err != nil {
			t.Fatal(err)
		}
	}
	got, err := volume.Checker{Probe: p2}.Check(newRoot)
	if err != nil {
		t.Fatalf("remounted vault should pass: %v", err)
	}
	if got.VaultUUID != id.VaultUUID {
		t.Fatal("vault identity changed")
	}
}

func TestAddDir(t *testing.T) {
	c, p, root := newSSD(t)
	if _, err := c.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	disk2 := p.Mount(t, t.TempDir(), "ext4", "8:33", "disk2-uuid")
	extra := filepath.Join(disk2, "ctvault-vault")
	id, err := c.AddDir(root, extra, volume.InitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(id.Volumes) != 3 || id.Volumes[2].FSUUID != "disk2-uuid" {
		t.Fatalf("volumes = %+v", id.Volumes)
	}
	if _, err := c.Check(root); err != nil {
		t.Fatalf("Check with added dir: %v", err)
	}
	p.UUIDs["8:33"] = "swapped-disk"
	_, err = c.Check(root)
	wantVolumeErr(t, err, "vault dir")
}

func TestAddDirRefusesSystemDiskAndNonEmpty(t *testing.T) {
	c, p, root := newSSD(t)
	if _, err := c.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	onSystem := filepath.Join(t.TempDir(), "v") // not mounted in the fake: lives on "/"
	_, err := c.AddDir(root, onSystem, volume.InitOptions{})
	wantVolumeErr(t, err, "same device as /")

	disk2 := p.Mount(t, t.TempDir(), "ext4", "8:33", "disk2-uuid")
	os.WriteFile(filepath.Join(disk2, "junk"), nil, 0o644)
	_, err = c.AddDir(root, disk2, volume.InitOptions{})
	wantVolumeErr(t, err, "not empty")
}
