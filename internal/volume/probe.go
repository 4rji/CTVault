package volume

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// Probe reads the host's mount table and filesystem identities. Tests use
// volumetest.Probe; production uses HostProbe.
type Probe interface {
	MountInfo() ([]MountEntry, error)
	// FSUUID returns the filesystem UUID of the device backing the mount.
	FSUUID(m MountEntry) (string, error)
	// BackingDevices returns the block devices ("major:minor", sorted) that
	// ultimately hold the mount's data, following loop backing files and
	// dm/md slaves.
	BackingDevices(m MountEntry) ([]string, error)
}

// ErrNoUUID means the filesystem UUID could not be determined.
var ErrNoUUID = errors.New("cannot determine filesystem UUID")

// HostProbe reads /proc/self/mountinfo, /dev/disk/by-uuid and /sys/dev/block.
type HostProbe struct {
	MountInfoPath  string // default /proc/self/mountinfo
	ByUUIDDir      string // default /dev/disk/by-uuid
	SysDevBlockDir string // default /sys/dev/block
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

// maxDeviceDepth bounds loop/dm/md chains; real stacks are a few levels deep.
const maxDeviceDepth = 16

// BackingDevices resolves the mount's device through /sys/dev/block: a loop
// device is replaced by the devices of the filesystem holding its backing
// file, a dm or md device by its slaves. Anything it cannot resolve is an
// error, so callers fail safe instead of assuming a separate disk.
func (p HostProbe) BackingDevices(m MountEntry) ([]string, error) {
	mounts, err := p.MountInfo()
	if err != nil {
		return nil, err
	}
	leaves := map[string]bool{}
	if err := p.walkMount(m, mounts, leaves, map[string]bool{}, 0); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(leaves))
	for d := range leaves {
		out = append(out, d)
	}
	slices.Sort(out)
	return out, nil
}

func (p HostProbe) walkMount(m MountEntry, mounts []MountEntry, leaves, seen map[string]bool, depth int) error {
	dev := m.MajorMinor
	var st unix.Stat_t
	if unix.Stat(m.Source, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFBLK {
		dev = devString(st.Rdev) // btrfs and friends report an anonymous device in mountinfo
	}
	return p.walkDevice(dev, m.MountPoint, mounts, leaves, seen, depth)
}

func (p HostProbe) walkDevice(dev, mountPoint string, mounts []MountEntry, leaves, seen map[string]bool, depth int) error {
	if depth > maxDeviceDepth {
		return fmt.Errorf("device chain behind %s is deeper than %d levels", mountPoint, maxDeviceDepth)
	}
	if seen[dev] {
		return nil
	}
	seen[dev] = true
	sys := p.SysDevBlockDir
	if sys == "" {
		sys = "/sys/dev/block"
	}
	base := filepath.Join(sys, dev)
	if b, err := os.ReadFile(filepath.Join(base, "loop", "backing_file")); err == nil {
		file := strings.TrimSpace(string(b))
		real, err := filepath.EvalSymlinks(file)
		if err != nil {
			return fmt.Errorf("loop device %s behind %s: cannot resolve backing file %q: %v", dev, mountPoint, file, err)
		}
		holder, ok := MountFor(mounts, real)
		if !ok {
			return fmt.Errorf("loop device %s behind %s: backing file %s is on no mounted filesystem", dev, mountPoint, real)
		}
		return p.walkMount(holder, mounts, leaves, seen, depth+1)
	}
	slaves, _ := os.ReadDir(filepath.Join(base, "slaves"))
	if len(slaves) == 0 {
		leaves[dev] = true
		return nil
	}
	for _, s := range slaves {
		b, err := os.ReadFile(filepath.Join(base, "slaves", s.Name(), "dev"))
		if err != nil {
			return fmt.Errorf("device %s behind %s: reading slave %s: %v", dev, mountPoint, s.Name(), err)
		}
		if err := p.walkDevice(strings.TrimSpace(string(b)), mountPoint, mounts, leaves, seen, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func devString(rdev uint64) string {
	return fmt.Sprintf("%d:%d", unix.Major(rdev), unix.Minor(rdev))
}
