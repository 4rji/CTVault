// Package diskguard enforces the per-volume disk cap (spec §10.1): a batch may
// start only if its estimated peak fits under the cap, and nothing may ever
// push a volume past it.
package diskguard

import (
	"errors"
	"fmt"
	"math"
	"slices"

	"golang.org/x/sys/unix"
)

// Usage is a filesystem's size and the space available to unprivileged writers.
type Usage struct {
	Total uint64
	Avail uint64
}

// Used counts everything not available to us, including ext4's reserved blocks.
func (u Usage) Used() uint64 {
	if u.Avail > u.Total {
		return 0
	}
	return u.Total - u.Avail
}

// UsedFraction is Used/Total; a zero-sized filesystem counts as full.
func (u Usage) UsedFraction() float64 {
	if u.Total == 0 {
		return 1
	}
	return float64(u.Used()) / float64(u.Total)
}

// StatFunc reports usage for the filesystem holding path.
type StatFunc func(path string) (Usage, error)

// Statfs is the real StatFunc: (f_blocks − f_bavail) × fragment size.
func Statfs(path string) (Usage, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return Usage{}, err
	}
	bs := uint64(st.Frsize)
	if bs == 0 {
		bs = uint64(st.Bsize)
	}
	return Usage{Total: st.Blocks * bs, Avail: st.Bavail * bs}, nil
}

// ErrCap is matched by every *CapError.
var ErrCap = errors.New("disk cap would be exceeded")

// CapError reports the numbers behind a refusal.
type CapError struct {
	Path  string
	Usage Usage
	Need  uint64
	Cap   float64
}

func (e *CapError) Error() string {
	return fmt.Sprintf("%s: %v; %s used of %s (%.1f%%), need %s more, cap %.0f%% allows %s",
		e.Path, ErrCap, human(e.Usage.Used()), human(e.Usage.Total), 100*e.Usage.UsedFraction(),
		human(e.Need), 100*e.Cap, human(limit(e.Usage, e.Cap)))
}

func (e *CapError) Is(target error) bool { return target == ErrCap }

func limit(u Usage, capFrac float64) uint64 { return uint64(capFrac * float64(u.Total)) }

func human(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// Guard checks requests against a cap such as 0.85.
type Guard struct {
	Cap  float64
	Stat StatFunc
}

// Check returns a *CapError if adding need bytes to path's volume would take
// usage above Cap × Total.
func (g Guard) Check(path string, need uint64) error {
	u, err := g.Stat(path)
	if err != nil {
		return fmt.Errorf("statfs %s: %w", path, err)
	}
	lim, used := limit(u, g.Cap), u.Used()
	if u.Total == 0 || used > lim || need > lim-used {
		return &CapError{Path: path, Usage: u, Need: need, Cap: g.Cap}
	}
	return nil
}

// Seed bytes-per-entry figures used until MinHistory batches exist (spec §10.1).
const (
	SeedVaultBytesPerEntry   = 840
	SeedParquetBytesPerEntry = 175
	SeedPebbleBytesPerEntry  = 60
	MinHistory               = 20

	SegmentReserve             = 1 << 30
	MetadataOverhead           = 64 << 20
	MinPebbleCompactionReserve = 2 << 30
)

// P95 returns the 95th percentile of samples, or seed when there are fewer
// than MinHistory samples.
func P95(samples []float64, seed float64) float64 {
	if len(samples) < MinHistory {
		return seed
	}
	s := slices.Clone(samples)
	slices.Sort(s)
	return s[int(math.Ceil(0.95*float64(len(s))))-1]
}

// PeakInput holds the values the spec §10.1 formula needs.
type PeakInput struct {
	Entries              uint64
	VaultP95             float64 // bytes per entry
	ParquetP95           float64
	PebbleP95            float64
	Safety               float64
	PebbleSize           uint64
	CanarySpill          uint64
	RebuildExtraPerEntry float64 // derived bytes per entry for a dual-built version, 0 if none
}

// Peak is the space a batch may need on the vault volume and the root volume.
type Peak struct {
	Vault uint64
	Root  uint64
}

// EstimatePeak applies the spec §10.1 formula.
func EstimatePeak(in PeakInput) Peak {
	n := float64(in.Entries)
	compaction := max(uint64(MinPebbleCompactionReserve), in.PebbleSize/10)
	return Peak{
		Vault: uint64(math.Ceil(n*in.VaultP95*in.Safety)) + SegmentReserve,
		Root: uint64(math.Ceil(n*(in.ParquetP95+in.PebbleP95+in.RebuildExtraPerEntry)*in.Safety)) +
			compaction + MetadataOverhead + in.CanarySpill,
	}
}
