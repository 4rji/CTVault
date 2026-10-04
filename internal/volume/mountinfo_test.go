package volume

import (
	"strings"
	"testing"
)

const sampleMountInfo = `24 30 0:22 / /sys rw,nosuid,nodev,noexec,relatime shared:6 - sysfs sysfs rw
30 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro
88 30 8:17 / /mnt/ctvault rw,relatime shared:40 - ext4 /dev/sdb1 rw
89 30 8:33 / /mnt/my\040disk rw,relatime - ext4 /dev/sdc1 rw,nobarrier
90 88 8:49 / /mnt/ctvault/extra rw - xfs /dev/sdd1 rw
91 30 8:17 / /mnt/ctvault rw,relatime shared:41 - ext4 /dev/sdb1 rw
`

func TestParseMountInfo(t *testing.T) {
	ms, err := ParseMountInfo(strings.NewReader(sampleMountInfo))
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 6 {
		t.Fatalf("got %d entries, want 6", len(ms))
	}
	root := ms[1]
	if root.MountPoint != "/" || root.MajorMinor != "8:1" || root.FSType != "ext4" || root.Source != "/dev/sda1" {
		t.Fatalf("root entry parsed wrong: %+v", root)
	}
	if got := ms[3].MountPoint; got != "/mnt/my disk" {
		t.Fatalf("octal escape not decoded: %q", got)
	}
	if got := ms[3].SuperOptions; len(got) != 2 || got[1] != "nobarrier" {
		t.Fatalf("super options = %v", got)
	}
	if ms[0].MountOptions[0] != "rw" || ms[0].FSType != "sysfs" {
		t.Fatalf("optional fields handled wrong: %+v", ms[0])
	}
}

func TestParseMountInfoRejectsMalformed(t *testing.T) {
	if _, err := ParseMountInfo(strings.NewReader("24 30 0:22 / /sys rw\n")); err == nil {
		t.Fatal("expected error for a line without the '-' separator")
	}
}

func TestMountFor(t *testing.T) {
	ms, _ := ParseMountInfo(strings.NewReader(sampleMountInfo))
	cases := map[string]string{
		"/":                    "/",
		"/home/metro":          "/",
		"/mnt/ctvault":         "/mnt/ctvault",
		"/mnt/ctvault/vault":   "/mnt/ctvault",
		"/mnt/ctvault/extra/x": "/mnt/ctvault/extra",
		"/mnt/ctvaultX":        "/",
		"/mnt/my disk/ctvault": "/mnt/my disk",
	}
	for path, want := range cases {
		m, ok := MountFor(ms, path)
		if !ok || m.MountPoint != want {
			t.Errorf("MountFor(%q) = %q, want %q", path, m.MountPoint, want)
		}
	}
	m, _ := MountFor(ms, "/mnt/ctvault")
	if m.MountID != 91 {
		t.Errorf("stacked mount: got id %d, want the topmost (91)", m.MountID)
	}
}
