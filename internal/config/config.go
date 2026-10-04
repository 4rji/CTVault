// Package config loads <root>/ctvault.toml (spec §11.1). A missing file means
// defaults, so an interrupted init never leaves a vault unusable.
package config

import (
	"errors"
	"fmt"
	"io/fs"
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

// Validate rejects values that would make ingestion unsafe or meaningless.
func (c Config) Validate() error {
	var errs []error
	check := func(ok bool, format string, args ...any) {
		if !ok {
			errs = append(errs, fmt.Errorf(format, args...))
		}
	}
	check(c.Ingest.BatchSize >= 1, "ingest.batch_size must be >= 1")
	check(c.Ingest.Workers >= 1 && c.Ingest.Workers <= 64, "ingest.workers must be 1-64")
	check(c.Ingest.MaxRPS > 0, "ingest.max_rps must be > 0")
	check(c.Ingest.FollowInterval.Duration >= time.Second, "ingest.follow_interval must be >= 1s")
	check(c.Ingest.StallTimeout.Duration >= time.Second, "ingest.stall_timeout must be >= 1s")
	check(c.Ingest.DeltaLRUEntries >= 0, "ingest.delta_lru_entries must be >= 0")
	check(c.Vault.SegmentSize >= 1<<20, "vault.segment_size must be >= 1MiB")
	check(c.Disk.MaxUsedFraction > 0 && c.Disk.MaxUsedFraction <= 0.95, "disk.max_used_fraction must be in (0, 0.95]")
	check(c.Disk.SafetyFactor >= 1, "disk.safety_factor must be >= 1")
	check(c.Rebuild.Workers >= 1, "rebuild.workers must be >= 1")
	if len(errs) > 0 {
		return fmt.Errorf("%s: %w", FileName, errors.Join(errs...))
	}
	return nil
}

// WriteDefault writes DefaultTOML unless the file already exists.
func WriteDefault(root string) error {
	p := filepath.Join(root, FileName)
	if _, err := os.Stat(p); err == nil {
		return nil
	}
	return fsutil.WriteFileAtomic(p, []byte(DefaultTOML), 0o644)
}
