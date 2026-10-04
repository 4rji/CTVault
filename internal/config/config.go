// Package config loads <root>/ctvault.toml (spec §11.1). A missing file means
// defaults, so an interrupted init never leaves a vault unusable.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/4rji/ctvault/internal/fsutil"
)

// FileName is the config file inside the vault root.
const FileName = "ctvault.toml"

// Config mirrors the sections of ctvault.toml.
type Config struct {
	Ingest  Ingest  `toml:"ingest"`
	Fetch   Fetch   `toml:"fetch"`
	Delta   Delta   `toml:"delta"`
	Vault   Vault   `toml:"vault"`
	Disk    Disk    `toml:"disk"`
	Rebuild Rebuild `toml:"rebuild"`
}

type Ingest struct {
	BatchSize       int      `toml:"batch_size"`
	Workers         int      `toml:"workers"`
	MaxRPS          float64  `toml:"max_rps"`
	FollowInterval  Duration `toml:"follow_interval"`
	StallTimeout    Duration `toml:"stall_timeout"`
	DeltaLRUEntries int      `toml:"delta_lru_entries"`
}

// Fetch bounds the fetcher's reorder buffer (amendment A1 §4): workers pause
// when either limit is reached.
type Fetch struct {
	MaxBufferedEntries int  `toml:"max_buffered_entries"`
	MaxBufferedBytes   Size `toml:"max_buffered_bytes"`
}

// Delta tunes the leaf-delta cache (amendment A1 §5).
type Delta struct {
	WarmBatches int `toml:"warm_batches"`
}

type Vault struct {
	SegmentSize Size `toml:"segment_size"`
}

type Disk struct {
	MaxUsedFraction float64 `toml:"max_used_fraction"`
	SafetyFactor    float64 `toml:"safety_factor"`
}

type Rebuild struct {
	Workers int `toml:"workers"`
}

// Duration is a time.Duration written as a Go duration string ("10m").
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	d.Duration = v
	return err
}

func (d Duration) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

// Size is a byte count written as "1GiB", "512MiB", "64KiB" or plain bytes.
type Size uint64

var sizeUnits = []struct {
	suffix string
	mult   uint64
}{{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"B", 1}}

func (s *Size) UnmarshalText(b []byte) error {
	str := strings.TrimSpace(string(b))
	for _, u := range sizeUnits {
		if num, ok := strings.CutSuffix(str, u.suffix); ok {
			n, err := strconv.ParseUint(strings.TrimSpace(num), 10, 64)
			if err != nil {
				return fmt.Errorf("invalid size %q", str)
			}
			if n > math.MaxUint64/u.mult {
				return fmt.Errorf("size %q overflows 64 bits", str)
			}
			*s = Size(n * u.mult)
			return nil
		}
	}
	n, err := strconv.ParseUint(str, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid size %q (use e.g. 1GiB)", str)
	}
	*s = Size(n)
	return nil
}

// Default returns the spec §11.1 defaults.
func Default() Config {
	return Config{
		Ingest: Ingest{BatchSize: 500000, Workers: 4, MaxRPS: 20,
			FollowInterval: Duration{10 * time.Minute}, StallTimeout: Duration{15 * time.Minute}, DeltaLRUEntries: 2000000},
		Fetch:   Fetch{MaxBufferedEntries: 65536, MaxBufferedBytes: 256 << 20},
		Delta:   Delta{WarmBatches: 4},
		Vault:   Vault{SegmentSize: 1 << 30},
		Disk:    Disk{MaxUsedFraction: 0.85, SafetyFactor: 1.5},
		Rebuild: Rebuild{Workers: 2},
	}
}

// DefaultTOML is written by `ctvault init`.
const DefaultTOML = `# CTVault configuration (spec §11.1). Logs and volumes are managed with
# "ctvault logs add" and "ctvault vault add-dir", not in this file.

[ingest]
batch_size = 500000
workers = 4
max_rps = 20.0
follow_interval = "10m"
stall_timeout = "15m"
delta_lru_entries = 2000000

[fetch]
max_buffered_entries = 65536
max_buffered_bytes = "256MiB"

[delta]
warm_batches = 4

[vault]
segment_size = "1GiB"

[disk]
max_used_fraction = 0.85
safety_factor = 1.5

[rebuild]
workers = 2
`

// Load reads <root>/ctvault.toml over the defaults and validates the result.
// Unknown keys are errors so that typos do not silently fall back to defaults.
func Load(root string) (Config, error) {
	cfg := Default()
	b, err := os.ReadFile(filepath.Join(root, FileName))
	if errors.Is(err, fs.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	md, err := toml.Decode(string(b), &cfg)
	if err != nil {
		return cfg, fmt.Errorf("%s: %w", FileName, err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		return cfg, fmt.Errorf("%s: unknown keys: %s", FileName, strings.Join(keys, ", "))
	}
	return cfg, cfg.Validate()
}

// Validate rejects values that would make ingestion unsafe or meaningless:
// non-finite numbers, values out of range, and sizes beyond what any real
// deployment uses (Plan 1 review, minor 11).
func (c Config) Validate() error {
	var errs []error
	check := func(ok bool, format string, args ...any) {
		if !ok {
			errs = append(errs, fmt.Errorf(format, args...))
		}
	}
	finite := func(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) }
	check(c.Ingest.BatchSize >= 1 && c.Ingest.BatchSize <= 10_000_000, "ingest.batch_size must be 1-10000000")
	check(c.Ingest.Workers >= 1 && c.Ingest.Workers <= 64, "ingest.workers must be 1-64")
	check(finite(c.Ingest.MaxRPS) && c.Ingest.MaxRPS > 0 && c.Ingest.MaxRPS <= 1000, "ingest.max_rps must be in (0, 1000]")
	check(c.Ingest.FollowInterval.Duration >= time.Second && c.Ingest.FollowInterval.Duration <= 24*time.Hour, "ingest.follow_interval must be 1s-24h")
	check(c.Ingest.StallTimeout.Duration >= time.Second && c.Ingest.StallTimeout.Duration <= 24*time.Hour, "ingest.stall_timeout must be 1s-24h")
	check(c.Ingest.DeltaLRUEntries >= 0 && c.Ingest.DeltaLRUEntries <= 100_000_000, "ingest.delta_lru_entries must be 0-100000000")
	check(c.Fetch.MaxBufferedEntries >= 1024 && c.Fetch.MaxBufferedEntries <= 16<<20, "fetch.max_buffered_entries must be 1024-16777216")
	check(c.Fetch.MaxBufferedBytes >= 16<<20 && c.Fetch.MaxBufferedBytes <= 64<<30, "fetch.max_buffered_bytes must be 16MiB-64GiB")
	check(c.Delta.WarmBatches >= 0 && c.Delta.WarmBatches <= 64, "delta.warm_batches must be 0-64")
	check(c.Vault.SegmentSize >= 1<<20 && c.Vault.SegmentSize <= 64<<30, "vault.segment_size must be 1MiB-64GiB")
	check(finite(c.Disk.MaxUsedFraction) && c.Disk.MaxUsedFraction > 0 && c.Disk.MaxUsedFraction <= 0.95, "disk.max_used_fraction must be in (0, 0.95]")
	check(finite(c.Disk.SafetyFactor) && c.Disk.SafetyFactor >= 1 && c.Disk.SafetyFactor <= 10, "disk.safety_factor must be 1-10")
	check(c.Rebuild.Workers >= 1 && c.Rebuild.Workers <= 64, "rebuild.workers must be 1-64")
	if len(errs) > 0 {
		return fmt.Errorf("%s: %w", FileName, errors.Join(errs...))
	}
	return nil
}

// WriteDefault writes DefaultTOML unless the file already exists.
func WriteDefault(root string) error { return WriteDefaultBatch(root, Default().Ingest.BatchSize) }

// WriteDefaultBatch is WriteDefault with another ingest.batch_size.
func WriteDefaultBatch(root string, batchSize int) error {
	p := filepath.Join(root, FileName)
	if _, err := os.Stat(p); err == nil {
		return nil
	}
	body := strings.Replace(DefaultTOML, "batch_size = 500000", fmt.Sprintf("batch_size = %d", batchSize), 1)
	return fsutil.WriteFileAtomic(p, []byte(body), 0o644)
}
