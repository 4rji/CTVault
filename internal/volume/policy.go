package volume

import (
	"errors"
	"fmt"
)

// Durability records whether a vault's filesystems are tested (spec §9.3).
type Durability string

const (
	DurabilityTested   Durability = "tested"
	DurabilityUntested Durability = "untested"
	// DurabilityDevUnsafe marks dev vaults on the normal disk (amendment A1 §1).
	DurabilityDevUnsafe Durability = "dev-unsafe"
)

// ErrUnsupportedFS means the filesystem can never hold a vault.
var ErrUnsupportedFS = errors.New("unsupported filesystem")

var (
	testedFS   = map[string]bool{"ext4": true}
	untestedFS = map[string]bool{"xfs": true, "btrfs": true, "f2fs": true}
)

// Classify applies the spec §9.3 policy: ext4 is tested; xfs, btrfs and f2fs
// are untested; everything else is rejected, as are mounts that disable
// cache flushes.
func Classify(m MountEntry) (Durability, error) {
	for _, opts := range [][]string{m.MountOptions, m.SuperOptions} {
		for _, o := range opts {
			if o == "nobarrier" || o == "barrier=0" {
				return "", fmt.Errorf("%w: %s is mounted with %q, which disables cache flushes", ErrUnsupportedFS, m.MountPoint, o)
			}
		}
	}
	switch {
	case testedFS[m.FSType]:
		return DurabilityTested, nil
	case untestedFS[m.FSType]:
		return DurabilityUntested, nil
	default:
		return "", fmt.Errorf("%w: %s is %s; CTVault requires ext4 (xfs, btrfs and f2fs only with --allow-untested-fs)", ErrUnsupportedFS, m.MountPoint, m.FSType)
	}
}
