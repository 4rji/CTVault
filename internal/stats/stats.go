// Package stats computes what ctvault stats shows (spec §11.2, amendment A2
// §6): per log, the heads, the remaining entries, the ingest rate and the
// catch-up ETA; for the vault, deltas, parse results, tables, incidents and
// disk use, with a projected date for the disk cap. Every estimate has a
// defined window and is shown as unknown when the window holds too little
// history; nothing is projected from too little data.
package stats

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/health"
)

// Estimation windows (amendment A2 §6.3).
const (
	// The ingest rate and catch-up ETA: batches committed in the last 24
	// hours, at least 3 of them spanning at least 10 minutes.
	RateWindow     = 24 * time.Hour
	RateMinBatches = 3
	RateMinSpan    = 10 * time.Minute
	// The log growth rate: the signed heads of committed batches over the
	// last 7 days, spanning at least an hour.
	GrowthWindow  = 7 * 24 * time.Hour
	GrowthMinSpan = time.Hour
	// Bytes per entry: the last 20 committed batches, as the disk guard,
	// once there are at least 5.
	BytesWindow     = diskguard.MinHistory
	BytesMinBatches = 5

	HealthNotYet     = "no post-commit audit recorded yet (state/health.json)"
	unknownTooLittle = "unknown"
)

// Head is a log's last verified signed head.
type Head struct {
	TreeSize  uint64    `json:"tree_size"`
	Timestamp time.Time `json:"timestamp"`
}

// LogInput is a pinned log.
type LogInput struct {
	Name     string
	State    string
	PinnedAt time.Time
	Head     *Head // nil before the first verified head
}

// Volume is one filesystem the vault uses.
type Volume struct {
	Path  string
	Role  string // root or vault
	Usage diskguard.Usage
}

// Input is everything stats reads.
type Input struct {
	Now         time.Time
	Logs        []LogInput
	Committed   []commit.Manifest // by commit_seq
	Active      derive.Active
	Incidents   int
	Volumes     []Volume
	Cap         float64        // disk.max_used_fraction
	PebbleBytes uint64         // the size of state/pebble
	Health      *health.Health // state/health.json; nil before the first audit
}

// LogReport is one log. A nil estimate is unknown.
type LogReport struct {
	Name             string    `json:"name"`
	State            string    `json:"state"`
	PinnedAt         time.Time `json:"pinned_at"`
	VerifiedHead     *Head     `json:"verified_head"`
	CommittedEntries uint64    `json:"committed_entries"`
	CommittedSTH     uint64    `json:"committed_sth_tree_size"` // the head the last batch was verified against
	Remaining        *uint64   `json:"remaining"`
	IngestRate       *float64  `json:"ingest_entries_per_second"`
	ETA              *float64  `json:"catch_up_eta_seconds"`
	RateLimitedRatio *float64  `json:"rate_limited_ratio"`
	GrowthRate       *float64  `json:"growth_entries_per_second"`
}

// VaultReport summarises the committed batches.
type VaultReport struct {
	Batches           int                          `json:"batches"`
	Entries           uint64                       `json:"entries"`
	NewCerts          int                          `json:"new_certs"`
	DeltaRecords      int                          `json:"delta_records"`
	DeltaShare        *float64                     `json:"delta_share"`              // delta records per new certificate
	DeltaSavedApprox  *int64                       `json:"delta_saved_bytes_approx"` // ≈, over the batches that estimate it
	DeltaSavedBatches int                          `json:"delta_saved_batches"`
	ParseStatus       map[string]int               `json:"parse_status"`
	Tables            map[string]derive.TableState `json:"tables"`
	Incidents         int                          `json:"incidents"`
}

// VolumeReport is one filesystem's use.
type VolumeReport struct {
	Path         string  `json:"path"`
	Role         string  `json:"role"`
	TotalBytes   uint64  `json:"total_bytes"`
	UsedBytes    uint64  `json:"used_bytes"`
	UsedFraction float64 `json:"used_fraction"`
	Cap          float64 `json:"cap"`
}

// PerEntry is the rolling bytes per entry of each component.
type PerEntry struct {
	Batches int     `json:"batches"`
	Vault   float64 `json:"vault"`
	Parquet float64 `json:"parquet"`
	Pebble  float64 `json:"pebble"` // state/pebble over every committed entry
	Total   float64 `json:"total"`
}

// Report is what stats shows.
type Report struct {
	GeneratedAt      time.Time      `json:"generated_at"`
	Logs             []LogReport    `json:"logs"`
	Vault            VaultReport    `json:"vault"`
	Volumes          []VolumeReport `json:"volumes"`
	BytesPerEntry    *PerEntry      `json:"bytes_per_entry"`
	ProjectedCapDate *time.Time     `json:"projected_cap_date"`
	ProjectedCapNote string         `json:"projected_cap_note"`
	Health           string         `json:"health"`
	HealthRecord     *health.Health `json:"health_record,omitempty"`
}

// rate is entries per second over the batches committed in the window:
// the entries after the first batch over the time since it committed.
func rate(ms []commit.Manifest, now time.Time) *float64 {
	var in []commit.Manifest
	for _, m := range ms {
		if now.Sub(m.CommittedAt) <= RateWindow {
			in = append(in, m)
		}
	}
	if len(in) < RateMinBatches {
		return nil
	}
	span := in[len(in)-1].CommittedAt.Sub(in[0].CommittedAt)
	if span < RateMinSpan {
		return nil
	}
	var n uint64
	for _, m := range in[1:] {
		n += m.Last - m.First + 1
	}
	r := float64(n) / span.Seconds()
	return &r
}

// rateLimited is the 429 share of requests over the rate window.
func rateLimited(ms []commit.Manifest, now time.Time) *float64 {
	var req, lim int64
	for _, m := range ms {
		if now.Sub(m.CommittedAt) <= RateWindow && m.Fetch != nil {
			req, lim = req+m.Fetch.Requests, lim+m.Fetch.RateLimited
		}
	}
	if req == 0 {
		return nil
	}
	r := float64(lim) / float64(req)
	return &r
}

// growth is the log's growth in entries per second, from the signed heads
// its committed batches were verified against over the growth window.
func growth(ms []commit.Manifest, now time.Time) *float64 {
	var lo, hi *commit.STH
	for i := range ms {
		s := &ms[i].STH
		ts := time.UnixMilli(int64(s.Timestamp))
		if now.Sub(ts) > GrowthWindow {
			continue
		}
		if lo == nil || s.Timestamp < lo.Timestamp {
			lo = s
		}
		if hi == nil || s.Timestamp > hi.Timestamp {
			hi = s
		}
	}
	if lo == nil {
		return nil
	}
	span := time.Duration(hi.Timestamp-lo.Timestamp) * time.Millisecond
	if span < GrowthMinSpan || hi.TreeSize <= lo.TreeSize {
		return nil
	}
	g := float64(hi.TreeSize-lo.TreeSize) / span.Seconds()
	return &g
}

func perEntry(ms []commit.Manifest, pebble uint64) *PerEntry {
	var total uint64
	for _, m := range ms {
		total += uint64(m.Counts.Entries)
	}
	var in []commit.Manifest
	for _, m := range ms[max(0, len(ms)-BytesWindow):] {
		if m.Counts.Entries > 0 {
			in = append(in, m)
		}
	}
	if len(in) < BytesMinBatches || total == 0 {
		return nil
	}
	p := &PerEntry{Batches: len(in), Pebble: float64(pebble) / float64(total)}
	for _, m := range in {
		var pq int64
		for name := range m.Files {
			pq += m.Files[name].Bytes
		}
		if m.Derived != nil {
			for _, t := range m.Derived.Tables {
				pq += t.Bytes
			}
		}
		p.Vault += float64(m.Counts.VaultBytes) / float64(m.Counts.Entries)
		p.Parquet += float64(pq) / float64(m.Counts.Entries)
	}
	p.Vault /= float64(len(in))
	p.Parquet /= float64(len(in))
	p.Total = p.Vault + p.Parquet + p.Pebble
	return p
}

// Compute builds the report.
func Compute(in Input) Report {
	r := Report{GeneratedAt: in.Now.UTC(), Health: healthLine(in.Health), HealthRecord: in.Health}
	byLog := map[string][]commit.Manifest{}
	for _, m := range in.Committed {
		byLog[m.Log] = append(byLog[m.Log], m)
	}
	var remaining uint64
	remainingKnown, growthKnown := true, true
	var growthSum float64
	for _, l := range in.Logs {
		ms := byLog[l.Name]
		lr := LogReport{Name: l.Name, State: l.State, PinnedAt: l.PinnedAt, VerifiedHead: l.Head,
			IngestRate: rate(ms, in.Now), RateLimitedRatio: rateLimited(ms, in.Now), GrowthRate: growth(ms, in.Now)}
		if len(ms) > 0 {
			last := ms[len(ms)-1]
			lr.CommittedEntries, lr.CommittedSTH = last.Last+1, last.STH.TreeSize
		}
		if l.Head != nil {
			rem := uint64(0)
			if l.Head.TreeSize > lr.CommittedEntries {
				rem = l.Head.TreeSize - lr.CommittedEntries
			}
			lr.Remaining = &rem
			remaining += rem
			if lr.IngestRate != nil {
				eta := float64(rem) / *lr.IngestRate
				lr.ETA = &eta
			}
		} else {
			remainingKnown = false
		}
		if lr.GrowthRate != nil {
			growthSum += *lr.GrowthRate
		} else {
			growthKnown = false
		}
		r.Logs = append(r.Logs, lr)
	}

	v := VaultReport{Batches: len(in.Committed), ParseStatus: map[string]int{}, Tables: maps.Clone(in.Active.Tables), Incidents: in.Incidents}
	var saved int64
	for _, m := range in.Committed {
		v.Entries += uint64(m.Counts.Entries)
		v.NewCerts += m.Counts.NewCerts
		v.DeltaRecords += m.Counts.DeltaRecords
		if m.DeltaSaved != nil {
			saved += m.DeltaSaved.Bytes
			v.DeltaSavedBatches++
		}
		ps := m.ParseStatus
		if ps == nil && m.Derived != nil {
			ps = m.Derived.ParseStatus
		}
		for k, n := range ps {
			v.ParseStatus[k] += n
		}
	}
	if v.NewCerts > 0 {
		share := float64(v.DeltaRecords) / float64(v.NewCerts)
		v.DeltaShare = &share
	}
	if v.DeltaSavedBatches > 0 {
		v.DeltaSavedApprox = &saved
	}
	r.Vault = v

	for _, vol := range in.Volumes {
		r.Volumes = append(r.Volumes, VolumeReport{Path: vol.Path, Role: vol.Role, TotalBytes: vol.Usage.Total,
			UsedBytes: vol.Usage.Used(), UsedFraction: vol.Usage.UsedFraction(), Cap: in.Cap})
	}
	r.BytesPerEntry = perEntry(in.Committed, in.PebbleBytes)
	r.ProjectedCapDate, r.ProjectedCapNote = project(in, r.BytesPerEntry, remaining, remainingKnown, rate(in.Committed, in.Now), growthSum, growthKnown)
	return r
}

// project dates the disk cap (amendment A2 §6.3): while catching up, the
// remaining entries arrive at the current ingest rate; after that, at the
// logs' growth rate. It is unknown when any input it needs is unknown.
func project(in Input, pe *PerEntry, remaining uint64, remainingKnown bool, ingest *float64, growthRate float64, growthKnown bool) (*time.Time, string) {
	if len(in.Volumes) == 0 {
		return nil, unknownTooLittle + ": no volume"
	}
	dev := in.Volumes[0].Usage.Dev
	for _, vol := range in.Volumes[1:] {
		if vol.Usage.Dev != dev {
			return nil, unknownTooLittle + ": the vault spans more than one filesystem"
		}
	}
	if pe == nil {
		return nil, fmt.Sprintf("%s: fewer than %d committed batches to measure bytes per entry", unknownTooLittle, BytesMinBatches)
	}
	if !remainingKnown {
		return nil, unknownTooLittle + ": a log has no verified head yet"
	}
	u := in.Volumes[0].Usage
	headroom := in.Cap*float64(u.Total) - float64(u.Used())
	if headroom <= 0 {
		t := in.Now.UTC()
		return &t, "the disk cap is reached"
	}
	fits := headroom / pe.Total // entries until the cap
	if remaining > 0 {
		if ingest == nil {
			return nil, unknownTooLittle + ": the ingest rate needs at least 3 batches over 10 minutes in the last 24 hours"
		}
		if fits <= float64(remaining) {
			t := in.Now.Add(time.Duration(fits / *ingest * float64(time.Second))).UTC()
			return &t, "during the catch-up, at the current ingest rate"
		}
	}
	if !growthKnown || growthRate <= 0 {
		return nil, unknownTooLittle + ": the log growth rate needs signed heads spanning an hour in the last 7 days"
	}
	catchUp := 0.0
	if remaining > 0 {
		catchUp = float64(remaining) / *ingest
	}
	after := (fits - float64(remaining)) / growthRate
	t := in.Now.Add(time.Duration((catchUp + after) * float64(time.Second))).UTC()
	return &t, "after the catch-up, at the logs' growth rate"
}

// Text renders the report for a terminal.
func Text(r Report) string {
	var b strings.Builder
	f := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	num := func(p *float64, format string) string {
		if p == nil {
			return "unknown"
		}
		return fmt.Sprintf(format, *p)
	}
	for _, l := range r.Logs {
		f("log %s (%s, pinned %s)", l.Name, l.State, l.PinnedAt.Format(time.DateOnly))
		if l.VerifiedHead != nil {
			f("  last verified head: tree size %d at %s", l.VerifiedHead.TreeSize, l.VerifiedHead.Timestamp.UTC().Format(time.RFC3339))
		} else {
			f("  last verified head: none yet")
		}
		f("  committed: %d entries (last batch verified against tree size %d)", l.CommittedEntries, l.CommittedSTH)
		rem := "unknown"
		if l.Remaining != nil {
			rem = fmt.Sprint(*l.Remaining)
		}
		eta := "unknown"
		if l.ETA != nil {
			eta = (time.Duration(*l.ETA) * time.Second).Round(time.Minute).String()
		}
		f("  remaining: %s entries; catch-up ETA %s", rem, eta)
		f("  ingest rate: %s entries/s; 429 ratio %s; log growth %s entries/s", num(l.IngestRate, "%.1f"),
			num(l.RateLimitedRatio, "%.3f"), num(l.GrowthRate, "%.2f"))
	}
	v := r.Vault
	f("vault: %d batches, %d entries, %d new certificates", v.Batches, v.Entries, v.NewCerts)
	saved := "unknown"
	if v.DeltaSavedApprox != nil {
		saved = fmt.Sprintf("≈ %d bytes (estimated in %d of %d batches)", *v.DeltaSavedApprox, v.DeltaSavedBatches, v.Batches)
	}
	f("  leaf-delta: %d records, %s of new certificates; saved %s", v.DeltaRecords, num(pct(v.DeltaShare), "%.1f%%"), saved)
	var mix []string
	for _, k := range slices.Sorted(maps.Keys(v.ParseStatus)) {
		mix = append(mix, fmt.Sprintf("%s %d", k, v.ParseStatus[k]))
	}
	f("  parse_status: %s", orNone(strings.Join(mix, ", ")))
	var tables []string
	for _, name := range slices.Sorted(maps.Keys(v.Tables)) {
		s := v.Tables[name]
		ver := s.Active
		if s.Status != derive.StatusComplete {
			ver = s.Building
		}
		if ver != nil {
			tables = append(tables, fmt.Sprintf("%s v%d %s", name, *ver, s.Status))
		}
	}
	f("  derived tables: %s", orNone(strings.Join(tables, ", ")))
	f("  incidents: %d", v.Incidents)
	for _, vol := range r.Volumes {
		f("disk %s (%s): %.1f%% used of %d bytes; cap %.0f%%", vol.Path, vol.Role, 100*vol.UsedFraction, vol.TotalBytes, 100*vol.Cap)
	}
	if pe := r.BytesPerEntry; pe != nil {
		f("bytes per entry (last %d batches): vault %.0f, Parquet %.0f, Pebble %.0f, total %.0f", pe.Batches, pe.Vault, pe.Parquet, pe.Pebble, pe.Total)
	} else {
		f("bytes per entry: unknown (fewer than %d committed batches)", BytesMinBatches)
	}
	if r.ProjectedCapDate != nil {
		f("projected disk cap: %s (%s)", r.ProjectedCapDate.Format(time.DateOnly), r.ProjectedCapNote)
	} else {
		f("projected disk cap: %s", r.ProjectedCapNote)
	}
	f("health: %s", r.Health)
	return b.String()
}

func pct(p *float64) *float64 {
	if p == nil {
		return nil
	}
	v := 100 * *p
	return &v
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// healthLine summarises state/health.json (amendment A3 §6).
func healthLine(h *health.Health) string {
	if h == nil {
		return HealthNotYet
	}
	s := fmt.Sprintf("%d post-commit audits passed, %d failed", h.Passes, h.FailedAudits)
	if n := len(h.Failures); n > 0 {
		f := h.Failures[n-1]
		s += fmt.Sprintf("; last failure: batch %s, %s: %s, at %s", f.BatchID, f.Check, f.Detail, f.At.Format(time.RFC3339))
	}
	return s
}
