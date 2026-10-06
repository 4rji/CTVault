// Package diskguard enforces the per-volume disk cap (spec §10.1): a batch may
// start only if its estimated peak fits under the cap, and nothing may ever
// push a volume past it.
package diskguard

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// Usage is a filesystem's size and the space available to unprivileged
// writers. Dev identifies the filesystem (st_dev of the path), so targets that
// share one are checked together.
type Usage struct {
	Total uint64
	Avail uint64
	Dev   uint64
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

// Statfs is the real StatFunc: (f_blocks − f_bavail) × fragment size, with
// the filesystem identified by the path's st_dev.
func Statfs(path string) (Usage, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return Usage{}, err
	}
	var fi unix.Stat_t
	if err := unix.Stat(path, &fi); err != nil {
		return Usage{}, err
	}
	bs := uint64(st.Frsize)
	if bs == 0 {
		bs = uint64(st.Bsize)
	}
	return Usage{Total: st.Blocks * bs, Avail: st.Bavail * bs, Dev: uint64(fi.Dev)}, nil
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

// ErrBadCap means the guard was given a cap outside (0, MaxCap]; it refuses
// every request rather than guess (Plan 1 review, minor 9).
var ErrBadCap = errors.New("disk guard: cap must be a finite fraction in (0, 0.95]")

// MaxCap is the highest cap the guard accepts (config allows the same).
const MaxCap = 0.95

func (g Guard) validCap() error {
	if math.IsNaN(g.Cap) || math.IsInf(g.Cap, 0) || g.Cap <= 0 || g.Cap > MaxCap {
		return fmt.Errorf("%w (got %v)", ErrBadCap, g.Cap)
	}
	return nil
}

// Check returns a *CapError if adding need bytes to path's volume would take
// usage above Cap × Total.
func (g Guard) Check(path string, need uint64) error {
	if err := g.validCap(); err != nil {
		return err
	}
	u, err := g.Stat(path)
	if err != nil {
		return fmt.Errorf("statfs %s: %w", path, err)
	}
	return g.fits(path, u, need)
}

func (g Guard) fits(path string, u Usage, need uint64) error {
	lim, used := limit(u, g.Cap), u.Used()
	if u.Total == 0 || used > lim || need > lim-used {
		return &CapError{Path: path, Usage: u, Need: need, Cap: g.Cap}
	}
	return nil
}

// Seed bytes-per-entry figures used until MinHistory batches exist (spec
// §10.1). Reviewed with Plan 4's live smoke test (amendment A3 §7.4):
// Parquet now includes certs and names (measured 172-200), Pebble measured
// 77 over a million live entries; the vault seed covers 561-733 with a
// dictionary.
const (
	SeedVaultBytesPerEntry   = 840
	SeedParquetBytesPerEntry = 210
	SeedPebbleBytesPerEntry  = 80
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
	DuckDBSpill          uint64  // DuckDB temp/spill limit (max_temp_directory_size), amendment A1 §7
	RebuildExtraPerEntry float64 // derived bytes per entry for a dual-built version, 0 if none
}

// Peak is the space a batch may need on the vault volume and the root volume.
type Peak struct {
	Vault uint64
	Root  uint64
}

// EstimatePeak applies the spec §10.1 formula. It computes in float64 and
// saturates at the largest uint64, so absurd inputs give a peak that can never
// fit instead of a wrapped small number (Plan 1 review, minor 10).
func EstimatePeak(in PeakInput) Peak {
	n := float64(in.Entries)
	compaction := max(uint64(MinPebbleCompactionReserve), in.PebbleSize/10)
	vault := toBytes(n*in.VaultP95*in.Safety) + SegmentReserve
	root := toBytes(n*(in.ParquetP95+in.PebbleP95+in.RebuildExtraPerEntry)*in.Safety) +
		float64(compaction) + MetadataOverhead + float64(in.DuckDBSpill)
	return Peak{Vault: saturate(vault), Root: saturate(root)}
}

// toBytes rounds a non-negative byte estimate up; NaN counts as unbounded.
func toBytes(f float64) float64 {
	if math.IsNaN(f) {
		return math.Inf(1)
	}
	return math.Ceil(max(f, 0))
}

// saturate converts to uint64, clamping anything at or beyond 2^64.
func saturate(f float64) uint64 {
	if f >= math.MaxUint64 {
		return math.MaxUint64
	}
	return uint64(f)
}

// Target is one place a batch writes and the bytes it may need there.
type Target struct {
	Path string
	Need uint64
}

// Preflight checks every target before a batch starts. Targets on the same
// filesystem (the default vault/ folder lives on the root volume, and a dev
// vault shares the normal disk) are summed and checked once, so two separate
// "fits" answers can never add up to a crossed cap.
func (g Guard) Preflight(targets []Target) error {
	if err := g.validCap(); err != nil {
		return err
	}
	type group struct {
		paths []string
		usage Usage
		need  uint64
	}
	var order []uint64
	groups := map[uint64]*group{}
	for _, t := range targets {
		u, err := g.Stat(t.Path)
		if err != nil {
			return fmt.Errorf("statfs %s: %w", t.Path, err)
		}
		gr, ok := groups[u.Dev]
		if !ok {
			gr = &group{usage: u}
			groups[u.Dev] = gr
			order = append(order, u.Dev)
		}
		gr.paths = append(gr.paths, t.Path)
		gr.need = addSat(gr.need, t.Need)
	}
	for _, dev := range order {
		gr := groups[dev]
		if err := g.fits(strings.Join(gr.paths, " + "), gr.usage, gr.need); err != nil {
			return err
		}
	}
	return nil
}

func addSat(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}
