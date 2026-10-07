package diskguard

import (
	"errors"
	"strings"
	"testing"
)

const tb = 1_000_000_000_000

func fixed(u Usage) StatFunc { return func(string) (Usage, error) { return u, nil } }

func TestCheckUnderAndOverCap(t *testing.T) {
	g := Guard{Cap: 0.85, Stat: fixed(Usage{Total: 4 * tb, Avail: 2 * tb})} // 50% used
	if err := g.Check("/mnt/ctvault", tb); err != nil {
		t.Fatalf("75%% after write is under the cap: %v", err)
	}
	// The limit is rounded down (conservative), so ask for just under 85%.
	if err := g.Check("/mnt/ctvault", 1.399*tb); err != nil {
		t.Fatalf("84.98%% is allowed: %v", err)
	}
	err := g.Check("/mnt/ctvault", 1.5*tb)
	if !errors.Is(err, ErrCap) {
		t.Fatalf("87.5%% must be refused, got %v", err)
	}
	var ce *CapError
	if !errors.As(err, &ce) || ce.Need != 1.5*tb {
		t.Fatalf("CapError fields: %+v", ce)
	}
	if !strings.Contains(err.Error(), "cap 85%") {
		t.Fatalf("message should show the cap: %v", err)
	}
}

func TestCheckAlreadyOverCapAndHugeNeed(t *testing.T) {
	over := Guard{Cap: 0.85, Stat: fixed(Usage{Total: 100, Avail: 10})}
	if err := over.Check("/x", 0); !errors.Is(err, ErrCap) {
		t.Fatalf("volume already at 90%% must refuse even zero bytes: %v", err)
	}
	g := Guard{Cap: 0.85, Stat: fixed(Usage{Total: 100, Avail: 100})}
	if err := g.Check("/x", ^uint64(0)); !errors.Is(err, ErrCap) {
		t.Fatalf("overflowing need must refuse: %v", err)
	}
}

func TestCheckZeroSizedFilesystem(t *testing.T) {
	g := Guard{Cap: 0.85, Stat: fixed(Usage{})}
	if err := g.Check("/x", 0); !errors.Is(err, ErrCap) {
		t.Fatalf("zero-sized filesystem must refuse: %v", err)
	}
	if f := (Usage{}).UsedFraction(); f != 1 {
		t.Fatalf("UsedFraction of empty fs = %v, want 1", f)
	}
}

func TestStatfsOnTempDir(t *testing.T) {
	u, err := Statfs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if u.Total == 0 || u.Avail > u.Total {
		t.Fatalf("implausible usage %+v", u)
	}
}

func TestP95(t *testing.T) {
	if got := P95([]float64{1, 2, 3}, 840); got != 840 {
		t.Fatalf("short history must use the seed, got %v", got)
	}
	s := make([]float64, 20)
	for i := range s {
		s[i] = float64(20 - i) // 20..1, unsorted
	}
	if got := P95(s, 840); got != 19 {
		t.Fatalf("p95 of 1..20 = %v, want 19", got)
	}
}

func TestEstimatePeak(t *testing.T) {
	p := EstimatePeak(PeakInput{
		Entries: 500000, VaultP95: 840, ParquetP95: 175, PebbleP95: 60, Safety: 1.5,
		PebbleSize: 100 << 30, DuckDBSpill: 1 << 30,
	})
	wantVault := uint64(500000*840*1.5) + SegmentReserve
	wantRoot := uint64(500000*(175+60)*1.5) + 10<<30 + MetadataOverhead + 1<<30
	if p.Vault != wantVault || p.Root != wantRoot {
		t.Fatalf("peak = %+v, want vault %d root %d", p, wantVault, wantRoot)
	}
	small := EstimatePeak(PeakInput{Entries: 1, Safety: 1})
	if small.Root < MinPebbleCompactionReserve {
		t.Fatal("compaction reserve has a 2 GiB floor")
	}
}

// TestSeedsAreReviewed pins the seeds: they change only by an explicit,
// reviewed edit (A1 §8), the last one with Plan 4's live smoke test
// (amendment A3 §7.4: measured Parquet 172-200 and Pebble 77 B/entry).
func TestSeedsAreReviewed(t *testing.T) {
	if SeedVaultBytesPerEntry != 840 || SeedParquetBytesPerEntry != 265 || SeedPebbleBytesPerEntry != 80 { // Parquet: + the D tables, amendment A7 §3
		t.Fatalf("seeds vault %d, Parquet %d, Pebble %d", SeedVaultBytesPerEntry, SeedParquetBytesPerEntry, SeedPebbleBytesPerEntry)
	}
}
