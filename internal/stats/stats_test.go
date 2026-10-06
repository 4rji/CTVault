package stats

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/diskguard"
)

var now = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

// batches makes n consecutive 1,000-entry batches of log "a", committed
// every step up to now, whose STHs grow by growth entries per hour.
func batches(n int, step time.Duration) []commit.Manifest {
	var out []commit.Manifest
	for i := range n {
		at := now.Add(-time.Duration(n-1-i) * step)
		m := commit.Manifest{CommitSeq: uint64(i + 1), Log: "a", First: uint64(i) * 1000, Last: uint64(i)*1000 + 999,
			BatchID: "a/x", CommittedAt: at,
			STH:         commit.STH{TreeSize: 1_000_000 + uint64(at.Sub(now.Add(-48*time.Hour)).Hours()*3600), Timestamp: uint64(at.UnixMilli())},
			Counts:      commit.Counts{Entries: 1000, NewCerts: 900, DeltaRecords: 300, VaultBytes: 600_000},
			Files:       map[string]dataset.FileInfo{"entries.parquet": {Bytes: 100_000}, "certs.p1.parquet": {Bytes: 50_000}},
			Fetch:       &commit.FetchCounts{Requests: 40, RateLimited: 2, Retries: 3},
			ParseStatus: map[string]int{"ok": 899, "partial": 1},
			DeltaSaved:  &commit.DeltaSaved{Approximate: true, Bytes: 120_000, DeltaRecords: 300, SampledRecords: 19, SampledSavedBytes: 7_600}}
		out = append(out, m)
	}
	return out
}

func input(ms []commit.Manifest) Input {
	return Input{Now: now, Committed: ms, Active: derive.Complete(), Incidents: 1, Cap: 0.85, PebbleBytes: 70 * uint64(len(ms)) * 1000,
		Logs:    []LogInput{{Name: "a", State: "usable", Head: &Head{TreeSize: 1_000_000, Timestamp: now.Add(-time.Minute)}}},
		Volumes: []Volume{{Path: "/v", Role: "root", Usage: diskguard.Usage{Total: 1 << 40, Avail: 1 << 39, Dev: 7}}}}
}

// TestEstimatesNeedEnoughHistory: every estimate is unknown until its window
// holds enough history (amendment A2 §6.3), and is computed after.
func TestEstimatesNeedEnoughHistory(t *testing.T) {
	r := Compute(input(batches(2, 10*time.Minute)))
	l := r.Logs[0]
	if l.IngestRate != nil || l.ETA != nil || r.BytesPerEntry != nil || r.ProjectedCapDate != nil || l.GrowthRate != nil {
		t.Fatalf("two batches: rate %v, ETA %v, bytes/entry %v, cap %v, growth %v", l.IngestRate, l.ETA, r.BytesPerEntry, r.ProjectedCapDate, l.GrowthRate)
	}
	if !strings.Contains(r.ProjectedCapNote, "unknown") {
		t.Fatalf("cap note: %q", r.ProjectedCapNote)
	}
	r = Compute(input(batches(3, 3*time.Minute))) // three batches spanning 6 minutes
	if r.Logs[0].IngestRate != nil {
		t.Fatal("batches spanning less than 10 minutes give no ingest rate")
	}

	r = Compute(input(batches(30, 20*time.Minute)))
	l = r.Logs[0]
	// The last 24 hours hold the last 30 batches; 29 batches after the first
	// took 29 × 20 minutes.
	if l.IngestRate == nil || *l.IngestRate < 0.83 || *l.IngestRate > 0.84 {
		t.Fatalf("ingest rate %v, want 29,000 entries / 34,800 s", l.IngestRate)
	}
	if l.Remaining == nil || *l.Remaining != 1_000_000-30_000 || l.ETA == nil {
		t.Fatalf("remaining %v, ETA %v", l.Remaining, l.ETA)
	}
	if l.GrowthRate == nil || *l.GrowthRate < 0.99 || *l.GrowthRate > 1.01 {
		t.Fatalf("growth %v entries/s, want 1", l.GrowthRate)
	}
	if l.RateLimitedRatio == nil || *l.RateLimitedRatio != 0.05 {
		t.Fatalf("429 ratio %v", l.RateLimitedRatio)
	}
	pe := r.BytesPerEntry
	if pe == nil || pe.Batches != 20 || pe.Vault != 600 || pe.Parquet != 150 || pe.Pebble != 70 || pe.Total != 820 {
		t.Fatalf("bytes per entry %+v", pe)
	}
	if r.ProjectedCapDate == nil || !r.ProjectedCapDate.After(now) {
		t.Fatalf("projected cap %v: %s", r.ProjectedCapDate, r.ProjectedCapNote)
	}
}

// TestProjectedCapDate: while catching up the projection adds the remaining
// entries at the ingest rate, then the log's growth rate.
func TestProjectedCapDate(t *testing.T) {
	ms := batches(30, 20*time.Minute)
	in := input(ms)
	// 820 B/entry; headroom 0.85 × 1 TiB − used.
	in.Volumes[0].Usage = diskguard.Usage{Total: 1_000_000_000, Avail: 1_000_000_000 - 100_000_000, Dev: 7}
	r := Compute(in)
	headroom := 0.85*1e9 - 100e6
	entries := headroom / 820
	rate := 29000.0 / (29 * 1200)
	// 970,000 entries remain, more than the headroom allows: the cap comes during the catch-up.
	want := now.Add(time.Duration(entries / rate * float64(time.Second)))
	if r.ProjectedCapDate == nil || r.ProjectedCapDate.Sub(want).Abs() > time.Minute {
		t.Fatalf("cap %v, want about %v (%s)", r.ProjectedCapDate, want, r.ProjectedCapNote)
	}
	in.Volumes = append(in.Volumes, Volume{Path: "/other", Role: "vault", Usage: diskguard.Usage{Total: 1 << 40, Dev: 8}})
	if r := Compute(in); r.ProjectedCapDate != nil {
		t.Fatal("vault directories on another filesystem: the projection is unknown")
	}
}

// TestVaultSummary: totals, the approximate delta savings, the parse_status
// mix (with backfilled batches' _DERIVED.json), tables and incidents.
func TestVaultSummary(t *testing.T) {
	ms := batches(3, time.Hour)
	ms[0].ParseStatus = nil
	ms[0].Derived = &commit.Derived{ParseStatus: map[string]int{"ok": 800, "failed": 2}}
	ms[1].DeltaSaved = nil
	r := Compute(input(ms))
	v := r.Vault
	if v.Batches != 3 || v.Entries != 3000 || v.NewCerts != 2700 || v.DeltaRecords != 900 || v.DeltaShare == nil || *v.DeltaShare != 900.0/2700 {
		t.Fatalf("vault %+v", v)
	}
	if v.DeltaSavedApprox == nil || *v.DeltaSavedApprox != 240_000 || v.DeltaSavedBatches != 2 {
		t.Fatalf("delta saved ≈ %v over %d batches", v.DeltaSavedApprox, v.DeltaSavedBatches)
	}
	if v.ParseStatus["ok"] != 800+899*2 || v.ParseStatus["failed"] != 2 || v.ParseStatus["partial"] != 2 {
		t.Fatalf("parse_status %v", v.ParseStatus)
	}
	if v.Incidents != 1 || v.Tables["certs"].Status != derive.StatusComplete {
		t.Fatalf("incidents %d, tables %+v", v.Incidents, v.Tables)
	}
	b, err := json.Marshal(r)
	if err != nil || !strings.Contains(string(b), `"delta_saved_bytes_approx":240000`) {
		t.Fatalf("JSON: %s %v", b, err)
	}
	text := Text(r)
	for _, s := range []string{"≈", "unknown", "no post-commit audit recorded yet", "certs v1 complete"} {
		if !strings.Contains(text, s) {
			t.Errorf("the text lacks %q:\n%s", s, text)
		}
	}
}
