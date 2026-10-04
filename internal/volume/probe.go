package volume

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Probe reads the host's mount table and filesystem identities. Tests use
// volumetest.Probe; production uses HostProbe.
type Probe interface {
	MountInfo() ([]MountEntry, error)
	// FSUUID returns the filesystem UUID of the device backing the mount.
	FSUUID(m MountEntry) (string, error)
}

// ErrNoUUID means the filesystem UUID could not be determined.
var ErrNoUUID = errors.New("cannot determine filesystem UUID")

// HostProbe reads /proc/self/mountinfo and /dev/disk/by-uuid.
type HostProbe struct {
	MountInfoPath string // default /proc/self/mountinfo
	ByUUIDDir     string // default /dev/disk/by-uuid
}

// MountInfo parses the host mount table.
func (p HostProbe) MountInfo() ([]MountEntry, error) {
	path := p.MountInfoPath
	if path == "" {
		path = "/proc/self/mountinfo"
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseMountInfo(f)
}

// FSUUID finds the /dev/disk/by-uuid entry whose block device matches the
// mount's major:minor, or failing that, the device named as the mount source.
func (p HostProbe) FSUUID(m MountEntry) (string, error) {
	dir := p.ByUUIDDir
	if dir == "" {
		dir = "/dev/disk/by-uuid"
	}
	want := []string{m.MajorMinor}
	var st unix.Stat_t
	if unix.Stat(m.Source, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFBLK {
		want = append(want, devString(st.Rdev))
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("%w for %s: %v", ErrNoUUID, m.MountPoint, err)
	}
	for _, e := range ents {
		if unix.Stat(filepath.Join(dir, e.Name()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFBLK {
			continue
		}
		for _, w := range want {
			if devString(st.Rdev) == w {
				return e.Name(), nil
			}
		}
	}
	return "", fmt.Errorf("%w for %s (device %s): no match in %s", ErrNoUUID, m.MountPoint, m.MajorMinor, dir)
}

func devString(rdev uint64) string {
	return fmt.Sprintf("%d:%d", unix.Major(rdev), unix.Minor(rdev))
}
