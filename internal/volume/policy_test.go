package volume

import (
	"errors"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		fstype string
		super  []string
		want   Durability
		reject bool
	}{
		{"ext4", []string{"rw"}, DurabilityTested, false},
		{"xfs", []string{"rw"}, DurabilityUntested, false},
		{"btrfs", []string{"rw"}, DurabilityUntested, false},
		{"f2fs", []string{"rw"}, DurabilityUntested, false},
		{"exfat", []string{"rw"}, "", true},
		{"vfat", []string{"rw"}, "", true},
		{"ntfs3", []string{"rw"}, "", true},
		{"fuseblk", []string{"rw"}, "", true},
		{"fuse.sshfs", []string{"rw"}, "", true},
		{"nfs4", []string{"rw"}, "", true},
		{"cifs", []string{"rw"}, "", true},
		{"tmpfs", []string{"rw"}, "", true},
		{"overlay", []string{"rw"}, "", true},
		{"ext4", []string{"rw", "nobarrier"}, "", true},
		{"ext4", []string{"rw", "barrier=0"}, "", true},
	}
	for _, c := range cases {
		got, err := Classify(MountEntry{MountPoint: "/mnt/x", FSType: c.fstype, MountOptions: []string{"rw"}, SuperOptions: c.super})
		if c.reject {
			if !errors.Is(err, ErrUnsupportedFS) {
				t.Errorf("%s %v: want ErrUnsupportedFS, got %v", c.fstype, c.super, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s: got (%q, %v), want %q", c.fstype, got, err, c.want)
		}
	}
}
