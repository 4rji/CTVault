package volume

import (
	"errors"
	"os"
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
}

func TestHostProbeMissingByUUID(t *testing.T) {
	p := HostProbe{ByUUIDDir: t.TempDir() + "/absent"}
	_, err := p.FSUUID(MountEntry{MountPoint: "/mnt/x", MajorMinor: "8:17", Source: "/dev/nonexistent"})
	if !errors.Is(err, ErrNoUUID) {
		t.Fatalf("want ErrNoUUID, got %v", err)
	}
}
