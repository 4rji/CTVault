package volume

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestHostProbeOnThisMachine reads the real mount table and resolves the UUID
// of the filesystem holding "/". It skips where /dev/disk/by-uuid is absent
// (some containers).
func TestHostProbeOnThisMachine(t *testing.T) {
	if _, err := os.Stat("/dev/disk/by-uuid"); err != nil {
		t.Skip("no /dev/disk/by-uuid on this host")
	}
	p := HostProbe{}
	ms, err := p.MountInfo()
	if err != nil {
		t.Fatal(err)
	}
	root, ok := MountFor(ms, "/")
	if !ok {
		t.Fatal("no mount for /")
	}
	uuid, err := p.FSUUID(root)
	if err != nil {
		t.Skipf("root filesystem has no by-uuid entry here: %v", err)
	}
	if len(uuid) < 8 {
		t.Fatalf("implausible UUID %q", uuid)
	}
	if devs, err := p.BackingDevices(root); err != nil || len(devs) == 0 {
		t.Fatalf("backing devices of /: %v, %v", devs, err)
	}
}

// TestHostProbeBackingDevices follows loop backing files and dm slaves on a
// fake /sys/dev/block tree down to the devices that really hold the data.
func TestHostProbeBackingDevices(t *testing.T) {
	sys := t.TempDir()
	img := filepath.Join(t.TempDir(), "vault.img")
	if err := os.WriteFile(img, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	realImg, _ := filepath.EvalSymlinks(img)
	mi := filepath.Join(t.TempDir(), "mountinfo")
	// "/" holds the image file; its source does not exist here, so 8:1 is used.
	os.WriteFile(mi, []byte("30 1 8:1 / / rw - ext4 /dev/nonexistent-sda1 rw\n"), 0o644)
	mk := func(rel, content string) {
		p := filepath.Join(sys, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(content), 0o644)
	}
	mk("7:0/loop/backing_file", realImg+"\n") // loop0 backed by a file on "/"
	mk("253:0/slaves/loop0/dev", "7:0\n")     // dm-crypt on loop0
	mk("253:1/slaves/sdb1/dev", "8:17\n")     // dm-crypt on an external partition
	mk("7:1/loop/backing_file", "/nonexistent/old.img (deleted)\n")

	p := HostProbe{MountInfoPath: mi, SysDevBlockDir: sys}
	for dev, want := range map[string][]string{"7:0": {"8:1"}, "253:0": {"8:1"}, "253:1": {"8:17"}, "8:17": {"8:17"}} {
		got, err := p.BackingDevices(MountEntry{MountPoint: "/mnt/x", MajorMinor: dev, Source: "/dev/nonexistent"})
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("BackingDevices(%s) = %v, %v; want %v", dev, got, err, want)
		}
	}
	if _, err := p.BackingDevices(MountEntry{MountPoint: "/mnt/y", MajorMinor: "7:1", Source: "/dev/nonexistent"}); err == nil {
		t.Error("an unresolvable loop backing file must be an error (fail safe)")
	}
}

func TestHostProbeMissingByUUID(t *testing.T) {
	p := HostProbe{ByUUIDDir: t.TempDir() + "/absent"}
	_, err := p.FSUUID(MountEntry{MountPoint: "/mnt/x", MajorMinor: "8:17", Source: "/dev/nonexistent"})
	if !errors.Is(err, ErrNoUUID) {
		t.Fatalf("want ErrNoUUID, got %v", err)
	}
}
