package diskguard

import (
	"errors"
	"math"
	"strings"
	"testing"
)

// TestBadCapRefusesEverything covers Plan 1 review minor 9: a NaN, infinite,
// zero, negative or above-0.95 cap must refuse, never compare as "fits".
func TestBadCapRefusesEverything(t *testing.T) {
	u := fixed(Usage{Total: 100 * tb, Avail: 99 * tb})
	for _, c := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), 0, -0.5, 0.96, 1, 2} {
		g := Guard{Cap: c, Stat: u}
		if err := g.Check("/x", 0); !errors.Is(err, ErrBadCap) {
			t.Errorf("cap %v: Check = %v, want ErrBadCap", c, err)
		}
		if err := g.Preflight([]Target{{Path: "/x", Need: 0}}); !errors.Is(err, ErrBadCap) {
			t.Errorf("cap %v: Preflight = %v, want ErrBadCap", c, err)
		}
	}
	if err := (Guard{Cap: 0.95, Stat: u}).Check("/x", 1); err != nil {
		t.Fatalf("0.95 is the highest allowed cap: %v", err)
	}
}

// TestEstimatePeakSaturates covers Plan 1 review minor 10: the result never
// wraps around to a small number.
func TestEstimatePeakSaturates(t *testing.T) {
	for name, in := range map[string]PeakInput{
		"huge entries": {Entries: math.MaxUint64, VaultP95: 840, ParquetP95: 175, PebbleP95: 60, Safety: 1.5},
		"huge p95":     {Entries: 500000, VaultP95: 1e300, ParquetP95: 1e300, Safety: 1.5},
		"inf p95":      {Entries: 1, VaultP95: math.Inf(1), ParquetP95: math.Inf(1), Safety: 1},
		"nan p95":      {Entries: 1, VaultP95: math.NaN(), ParquetP95: math.NaN(), Safety: 1},
		"huge spill":   {Entries: 1, Safety: 1, VaultP95: math.MaxFloat64, DuckDBSpill: math.MaxUint64},
	} {
		p := EstimatePeak(in)
		if p.Vault != math.MaxUint64 || p.Root != math.MaxUint64 {
			t.Errorf("%s: peak %+v, want both saturated at MaxUint64", name, p)
		}
	}
}

// statByPath gives each path its own fake filesystem.
func statByPath(m map[string]Usage) StatFunc {
	return func(p string) (Usage, error) {
		u, ok := m[p]
		if !ok {
			return Usage{}, errors.New("no such path")
		}
		return u, nil
	}
}

// TestPreflightSumsTargetsOnOneFilesystem: the default vault/ folder lives on
// the root volume, so the vault peak and the root peak must fit together.
func TestPreflightSumsTargetsOnOneFilesystem(t *testing.T) {
	shared := Usage{Total: 100 * tb, Avail: 50 * tb, Dev: 7} // 50% used; 35 TB below the cap
	g := Guard{Cap: 0.85, Stat: statByPath(map[string]Usage{"/r": shared, "/r/vault": shared})}
	if err := g.Preflight([]Target{{"/r", 20 * tb}, {"/r/vault", 10 * tb}}); err != nil {
		t.Fatalf("30 TB in total fits under 35 TB: %v", err)
	}
	err := g.Preflight([]Target{{"/r", 20 * tb}, {"/r/vault", 20 * tb}})
	var ce *CapError
	if !errors.As(err, &ce) || ce.Need != 40*tb {
		t.Fatalf("each target fits alone but 40 TB together does not: %v", err)
	}
	if !strings.Contains(ce.Path, "/r + /r/vault") {
		t.Fatalf("the refusal must name every path on the filesystem: %q", ce.Path)
	}
}

func TestPreflightChecksSeparateFilesystemsSeparately(t *testing.T) {
	g := Guard{Cap: 0.85, Stat: statByPath(map[string]Usage{
		"/r":     {Total: 100 * tb, Avail: 50 * tb, Dev: 1},
		"/disk2": {Total: 100 * tb, Avail: 50 * tb, Dev: 2},
	})}
	if err := g.Preflight([]Target{{"/r", 30 * tb}, {"/disk2", 30 * tb}}); err != nil {
		t.Fatalf("30 TB on each of two volumes fits: %v", err)
	}
	if err := g.Preflight([]Target{{"/r", 30 * tb}, {"/disk2", 40 * tb}}); !errors.Is(err, ErrCap) {
		t.Fatalf("the second volume must refuse: %v", err)
	}
	if err := g.Preflight([]Target{{"/missing", 1}}); err == nil || errors.Is(err, ErrCap) {
		t.Fatalf("a statfs failure is an error, not a cap answer: %v", err)
	}
}

func TestPreflightSaturatesSummedNeed(t *testing.T) {
	u := Usage{Total: 100 * tb, Avail: 100 * tb, Dev: 1}
	g := Guard{Cap: 0.85, Stat: statByPath(map[string]Usage{"/a": u, "/b": u})}
	if err := g.Preflight([]Target{{"/a", math.MaxUint64}, {"/b", math.MaxUint64}}); !errors.Is(err, ErrCap) {
		t.Fatalf("an overflowing sum must refuse: %v", err)
	}
}

func TestStatfsReportsDevice(t *testing.T) {
	d := t.TempDir()
	a, err := Statfs(d)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Statfs(d + "/.")
	if err != nil {
		t.Fatal(err)
	}
	if a.Dev == 0 || a.Dev != b.Dev {
		t.Fatalf("Dev must identify the filesystem: %d vs %d", a.Dev, b.Dev)
	}
}
