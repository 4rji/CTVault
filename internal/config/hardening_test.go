package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultsForFetchAndDelta(t *testing.T) {
	d := Default()
	if d.Fetch.MaxBufferedEntries != 65536 || d.Fetch.MaxBufferedBytes != 256<<20 || d.Delta.WarmBatches != 4 {
		t.Fatalf("amendment A1 defaults: fetch %+v delta %+v", d.Fetch, d.Delta)
	}
}

// TestLoadRejectsNonFiniteAndAbsurdValues covers Plan 1 review minor 11: TOML
// accepts nan and inf, and a size suffix can overflow 64 bits.
func TestLoadRejectsNonFiniteAndAbsurdValues(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"nan rps":           {"[ingest]\nmax_rps = nan\n", "ingest.max_rps"},
		"inf rps":           {"[ingest]\nmax_rps = inf\n", "ingest.max_rps"},
		"nan cap":           {"[disk]\nmax_used_fraction = nan\n", "disk.max_used_fraction"},
		"inf safety":        {"[disk]\nsafety_factor = inf\n", "disk.safety_factor"},
		"huge safety":       {"[disk]\nsafety_factor = 1e9\n", "disk.safety_factor"},
		"huge batch":        {"[ingest]\nbatch_size = 1000000000\n", "ingest.batch_size"},
		"size overflow":     {"[vault]\nsegment_size = \"17179869184GiB\"\n", "overflows"},
		"huge segment":      {"[vault]\nsegment_size = \"1TiB\"\n", "vault.segment_size"},
		"tiny buffer":       {"[fetch]\nmax_buffered_entries = 10\n", "fetch.max_buffered_entries"},
		"tiny buffer bytes": {"[fetch]\nmax_buffered_bytes = \"1MiB\"\n", "fetch.max_buffered_bytes"},
		"negative warm":     {"[delta]\nwarm_batches = -1\n", "delta.warm_batches"},
		"day-long stall":    {"[ingest]\nstall_timeout = \"48h\"\n", "ingest.stall_timeout"},
	} {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, FileName), []byte(tc.body), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := Load(root)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to mention %q", name, err, tc.want)
		}
	}
}

func TestLoadFetchAndDeltaOverrides(t *testing.T) {
	root := t.TempDir()
	body := "[fetch]\nmax_buffered_entries = 4096\nmax_buffered_bytes = \"64MiB\"\n[delta]\nwarm_batches = 0\n"
	if err := os.WriteFile(filepath.Join(root, FileName), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Fetch.MaxBufferedEntries != 4096 || got.Fetch.MaxBufferedBytes != 64<<20 || got.Delta.WarmBatches != 0 {
		t.Fatalf("overrides not applied: fetch %+v delta %+v", got.Fetch, got.Delta)
	}
}
