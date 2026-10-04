// Package volumetest provides a fake volume.Probe so tests can present
// temporary directories as mounted filesystems without root privileges.
package volumetest

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/4rji/ctvault/internal/volume"
)

// Probe is an in-memory mount table plus device → UUID and device → backing
// device maps.
type Probe struct {
	Mounts  []volume.MountEntry
	UUIDs   map[string]string   // major:minor → filesystem UUID
	Backing map[string][]string // major:minor → devices holding its data; default: itself
}

// MountInfo returns the configured mount table.
func (p *Probe) MountInfo() ([]volume.MountEntry, error) { return p.Mounts, nil }

// BackingDevices looks the mount's device up in Backing.
func (p *Probe) BackingDevices(m volume.MountEntry) ([]string, error) {
	if b, ok := p.Backing[m.MajorMinor]; ok {
		return b, nil
	}
	return []string{m.MajorMinor}, nil
}

// FSUUID looks the mount's device up in UUIDs.
func (p *Probe) FSUUID(m volume.MountEntry) (string, error) {
	if u, ok := p.UUIDs[m.MajorMinor]; ok {
		return u, nil
	}
	return "", fmt.Errorf("%w: device %s", volume.ErrNoUUID, m.MajorMinor)
}

// New returns a probe whose "/" is ext4 on device 8:1 (UUID "system-root").
func New() *Probe {
	return &Probe{
		Mounts: []volume.MountEntry{{MountID: 1, MajorMinor: "8:1", Root: "/", MountPoint: "/", FSType: "ext4",
			Source: "/dev/sda1", MountOptions: []string{"rw"}, SuperOptions: []string{"rw"}}},
		UUIDs:   map[string]string{"8:1": "system-root"},
		Backing: map[string][]string{},
	}
}

// Mount presents dir (resolved through symlinks) as a mount point of fstype on
// device majorMinor with filesystem UUID uuid. It returns the resolved path.
func (p *Probe) Mount(t testing.TB, dir, fstype, majorMinor, uuid string, superOpts ...string) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(superOpts) == 0 {
		superOpts = []string{"rw"}
	}
	p.Mounts = append(p.Mounts, volume.MountEntry{MountID: len(p.Mounts) + 1, MajorMinor: majorMinor, Root: "/",
		MountPoint: real, FSType: fstype, Source: "/dev/fake" + majorMinor, MountOptions: []string{"rw"}, SuperOptions: superOpts})
	if uuid != "" {
		p.UUIDs[majorMinor] = uuid
	}
	return real
}
