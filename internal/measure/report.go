//go:build ctvault_dev || realdata

package measure

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/sample"
	"github.com/4rji/ctvault/internal/vault"
)

// ReportFormat is the report's JSON format version.
const ReportFormat = 1

// Report is one measurement (amendment A1 §8). Bytes per entry divide by
// the sample's entries.
type Report struct {
	Format      int         `json:"format"`
	Provenance  Provenance  `json:"provenance"`
	Sample      SampleInfo  `json:"sample"`
	Run         RunInfo     `json:"run"`
	Sizes       Sizes       `json:"bytes_per_entry"`
	Compression Compression `json:"compression"`
	Links       Links       `json:"links"`
	Dedup       Dedup       `json:"dedup"`
	Errors      Errors      `json:"errors"`
	Batches     []Batch     `json:"batches"`
	Notes       []string    `json:"notes"`
}

// Provenance says what produced the numbers.
type Provenance struct {
	CTVaultVersion   string            `json:"ctvault_version"`
	Module           string            `json:"module"` // path and version from the Go build info
	VCSRevision      string            `json:"vcs_revision,omitempty"`
	VCSModified      bool              `json:"vcs_modified,omitempty"`
	GoVersion        string            `json:"go_version"`
	Dependencies     map[string]string `json:"dependencies"`
	DependenciesFrom string            `json:"dependencies_from"` // "build info", or "go.mod" for a test binary
	ZstdLibrary      string            `json:"zstd_library"`
	ReportedAt       time.Time         `json:"reported_at"`
}

// SampleInfo identifies the measured sample.
type SampleInfo struct {
	ID           string    `json:"id"`
	Kind         string    `json:"kind"`
	Log          string    `json:"log"`
	Start        uint64    `json:"start"`
	Count        uint64    `json:"count"`
	CapturedAt   time.Time `json:"captured_at"`
	HeadTreeSize uint64    `json:"head_tree_size"`
}

// RunInfo describes the run.
type RunInfo struct {
	BatchSize        uint64         `json:"batch_size"`
	Batches          int            `json:"batches"`
	IngestSeconds    float64        `json:"ingest_seconds"`
	EntriesPerSecond float64        `json:"entries_per_second"`
	DictSamples      int            `json:"dict_samples"`
	DeltaWarmBatches int            `json:"delta_warm_batches"`
	DeltaLRUEntries  int            `json:"delta_lru_entries"`
	EntryTypes       map[string]int `json:"entry_types"`
}

// Sizes are bytes per entry.
type Sizes struct {
	Vault               float64            `json:"vault"`       // record bytes
	VaultFiles          float64            `json:"vault_files"` // segment files, headers included
	VaultWithDictionary float64            `json:"vault_with_dictionary"`
	Parquet             float64            `json:"parquet"`
	ParquetByFile       map[string]float64 `json:"parquet_by_file"`
	Pebble              float64            `json:"pebble"` // state/pebble after close, WAL included
	Total               float64            `json:"total"`  // vault files + Parquet + Pebble
	SeedVault           int                `json:"seed_vault"`
	SeedParquet         int                `json:"seed_parquet"`
	SeedPebble          int                `json:"seed_pebble"`
}

// Group is one kind of vault record: full leaf, leaf-delta or chain, by
// dictionary (for deltas, the dictionary its batch used) and entry type.
type Group struct {
	Kind        string  `json:"kind"`
	Dictionary  uint64  `json:"dictionary"`
	EntryType   string  `json:"entry_type"`
	Records     int     `json:"records"`
	RawBytes    uint64  `json:"raw_bytes"`    // DER
	StoredBytes uint64  `json:"stored_bytes"` // whole records
	Ratio       float64 `json:"ratio"`
	MeanStored  float64 `json:"mean_stored"`
}

// DeltaSaving prices leaf-delta frames against the same certificates
// compressed in full with their batch's dictionary.
type DeltaSaving struct {
	Dictionary  uint64  `json:"dictionary"`
	Records     int     `json:"records"`
	StoredBytes uint64  `json:"stored_frame_bytes"`
	FullBytes   uint64  `json:"full_frame_bytes"`
	Saving      float64 `json:"saving"`
}

// Gap compares a measured value with the spec's figure. Gap is negative
// when the measurement is worse; Exceeds flags more than 10% worse
// (amendment A1 §5).
type Gap struct {
	What     string  `json:"what"`
	Spec     float64 `json:"spec"`
	Measured float64 `json:"measured"`
	Gap      float64 `json:"gap"`
	Exceeds  bool    `json:"exceeds_10_percent"`
}

// Compression is the vault's compression, overall and per group.
type Compression struct {
	RawBytes    uint64        `json:"raw_bytes"`
	StoredBytes uint64        `json:"stored_bytes"`
	Ratio       float64       `json:"ratio"`
	Groups      []Group       `json:"groups"`
	Deltas      []DeltaSaving `json:"leaf_delta"` // by dictionary
	Spec        []Gap         `json:"spec_gaps"`
}

// Delays are nearest-rank percentiles in milliseconds.
type Delays struct {
	P50 int64 `json:"p50"`
	P95 int64 `json:"p95"`
	P99 int64 `json:"p99"`
}

// Links are the precert→final relationships seen in the window.
type Links struct {
	Finals        int     `json:"finals"`         // x509 entries with an issuance key
	Linked        int     `json:"linked"`         // ... whose precert is earlier in the window
	PrecertLater  int     `json:"precert_later"`  // ... whose precert comes later in the window
	LinkRate      float64 `json:"link_rate"`      // linked / finals
	DeltaEligible int     `json:"delta_eligible"` // linked finals vaulted for the first time
	DeltaRecords  int     `json:"delta_records"`
	DeltaHitRate  float64 `json:"delta_hit_rate"` // delta records / eligible
	DelayMS       Delays  `json:"delay_ms"`       // linked final's timestamp minus its precert's
}

// Dedup counts certificates already vaulted when they were met again.
type Dedup struct {
	LeafCerts       int     `json:"leaf_certs"`
	UniqueLeafCerts int     `json:"unique_leaf_certs"`
	LeafHits        int     `json:"leaf_hits"`
	LeafHitRate     float64 `json:"leaf_hit_rate"`
	ChainRefs       int     `json:"chain_refs"`
	ChainRecords    int     `json:"chain_records"`
	ChainHitRate    float64 `json:"chain_hit_rate"`
}

// Errors are the leaf error codes (spec §5.4, amendment A1 §4): leaf
// structure codes, and semantic ones (extra_data, chain and precert checks).
type Errors struct {
	Total      int            `json:"total"`
	Structural int            `json:"structural"`
	Semantic   int            `json:"semantic"`
	ByCode     map[string]int `json:"by_code"`
	Committed  int            `json:"committed"` // the manifests' leaf_errors, which must equal Total
}

// Batch is one committed batch.
type Batch struct {
	First         uint64  `json:"first"`
	Last          uint64  `json:"last"`
	Entries       int     `json:"entries"`
	NewCerts      int     `json:"new_certs"`
	DeltaRecords  int     `json:"delta_records"`
	LeafErrors    int     `json:"leaf_errors"`
	VaultBytes    uint64  `json:"vault_bytes"`
	ParquetBytes  int64   `json:"parquet_bytes"`
	Dictionary    uint64  `json:"dictionary"`
	TrainingError string  `json:"training_error,omitempty"`
	Seconds       float64 `json:"seconds"`
}

// The spec's figures (§3.4 with C zstd level 19, §10.2).
const (
	specDictRatio   = 1.96  // per certificate, 110 KB dictionary, contiguous sample
	specNoDictRatio = 1.21  // per certificate, no dictionary
	specDeltaSaving = 0.171 // final certificate against its own precert
	specVaultBudget = 765   // §10.2 vault B/entry, upper end
)

func ratio(a, b uint64) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func perEntry(n int64, entries uint64) float64 {
	if entries == 0 {
		return 0
	}
	return float64(n) / float64(entries)
}

// gap compares measured with spec; for a size (higherIsBetter false) more
// bytes is worse.
func gap(what string, spec, measured float64, higherIsBetter bool) Gap {
	g := Gap{What: what, Spec: spec, Measured: measured}
	if spec > 0 && measured > 0 {
		if higherIsBetter {
			g.Gap = measured/spec - 1
		} else {
			g.Gap = spec/measured - 1
		}
		g.Exceeds = g.Gap < 1/1.1-1
	}
	return g
}

// percentiles returns nearest-rank percentiles of v (which it sorts).
func percentiles(v []int64) Delays {
	if len(v) == 0 {
		return Delays{}
	}
	slices.Sort(v)
	at := func(p int) int64 { return v[max(0, (p*len(v)+99)/100-1)] }
	return Delays{P50: at(50), P95: at(95), P99: at(99)}
}

// reportedDeps are the dependencies amendment A1 §8 names.
var reportedDeps = []string{"github.com/duckdb/duckdb-go/v2", "github.com/cockroachdb/pebble/v2", "github.com/klauspost/compress", "github.com/transparency-dev/merkle"}

// provenance reads the Go build info. A go test binary's build info lists
// no dependencies; fallback (read from go.mod by the caller) fills them in,
// and the report says where they came from.
func provenance(version string, now time.Time, fallback map[string]string) Provenance {
	p := Provenance{CTVaultVersion: version, Dependencies: map[string]string{}, ZstdLibrary: vault.LibraryVersion(), ReportedAt: now.UTC()}
	if bi, ok := debug.ReadBuildInfo(); ok {
		p.Module, p.GoVersion = bi.Main.Path+"@"+bi.Main.Version, bi.GoVersion
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				p.VCSRevision = s.Value
			case "vcs.modified":
				p.VCSModified = s.Value == "true"
			}
		}
		for _, d := range bi.Deps {
			if slices.Contains(reportedDeps, d.Path) {
				p.Dependencies[d.Path] = d.Version
			}
		}
	}
	if len(p.Dependencies) > 0 {
		p.DependenciesFrom = "build info"
		return p
	}
	for _, path := range reportedDeps {
		if v, ok := fallback[path]; ok {
			p.Dependencies[path], p.DependenciesFrom = v, "go.mod"
		}
	}
	if v, ok := p.Dependencies["github.com/klauspost/compress"]; ok {
		p.ZstdLibrary = "github.com/klauspost/compress " + v
	}
	return p
}

func build(s *sample.Sample, o Options, sv *survey, res *result) Report {
	m := s.Manifest
	n := m.Count
	cfg := res.manifests // shorthand below
	r := Report{Format: ReportFormat, Provenance: provenance(o.Version, o.Now(), o.Dependencies),
		Sample: SampleInfo{ID: m.ID(filepath.Base(s.Dir)), Kind: string(m.Kind), Log: m.Log.Name, Start: m.Start, Count: n,
			CapturedAt: m.CapturedAt, HeadTreeSize: s.Head.TreeSize}}
	dictSamples := o.DictSamples
	if dictSamples == 0 {
		dictSamples = vault.TrainingSamples
	}
	def := defaultsForReport()
	r.Run = RunInfo{BatchSize: o.BatchSize, Batches: len(cfg), DictSamples: dictSamples, DeltaWarmBatches: def.warm,
		DeltaLRUEntries: def.lru, EntryTypes: sv.types}

	var vaultBytes, dictVault, dictEntries uint64
	var parquet int64
	byFile := map[string]int64{}
	committedErrors := 0
	for i, mf := range cfg {
		var pq int64
		for name, f := range mf.Files {
			pq += f.Bytes
			byFile[name] += f.Bytes
		}
		r.Batches = append(r.Batches, Batch{First: mf.First, Last: mf.Last, Entries: mf.Counts.Entries, NewCerts: mf.Counts.NewCerts,
			DeltaRecords: mf.Counts.DeltaRecords, LeafErrors: mf.Counts.LeafErrors, VaultBytes: mf.Counts.VaultBytes,
			ParquetBytes: pq, Dictionary: mf.Dictionary.ID, TrainingError: mf.Dictionary.TrainingError, Seconds: res.seconds[i]})
		r.Run.IngestSeconds += res.seconds[i]
		vaultBytes += mf.Counts.VaultBytes
		parquet += pq
		committedErrors += mf.Counts.LeafErrors
		if mf.Dictionary.ID > 0 {
			dictVault += mf.Counts.VaultBytes
			dictEntries += uint64(mf.Counts.Entries)
		}
	}
	if r.Run.IngestSeconds > 0 {
		r.Run.EntriesPerSecond = float64(n) / r.Run.IngestSeconds
	}
	z := Sizes{Vault: perEntry(int64(vaultBytes), n), VaultFiles: perEntry(res.segments, n), Parquet: perEntry(parquet, n),
		ParquetByFile: map[string]float64{}, Pebble: perEntry(res.pebble, n), SeedVault: diskguard.SeedVaultBytesPerEntry,
		SeedParquet: diskguard.SeedParquetBytesPerEntry, SeedPebble: diskguard.SeedPebbleBytesPerEntry}
	if dictEntries > 0 {
		z.VaultWithDictionary = float64(dictVault) / float64(dictEntries)
	}
	for name, b := range byFile {
		z.ParquetByFile[name] = perEntry(b, n)
	}
	z.Total = z.VaultFiles + z.Parquet + z.Pebble
	r.Sizes = z

	var c Compression
	var dictRaw, dictStored, plainRaw, plainStored uint64
	for _, g := range res.groups {
		g.Ratio, g.MeanStored = ratio(g.RawBytes, g.StoredBytes), float64(g.StoredBytes)/float64(g.Records)
		c.Groups = append(c.Groups, *g)
		c.RawBytes += g.RawBytes
		c.StoredBytes += g.StoredBytes
		if g.Kind == "leaf" && g.Dictionary > 0 {
			dictRaw, dictStored = dictRaw+g.RawBytes, dictStored+g.StoredBytes
		}
		if g.Kind == "leaf" && g.Dictionary == 0 {
			plainRaw, plainStored = plainRaw+g.RawBytes, plainStored+g.StoredBytes
		}
	}
	slices.SortFunc(c.Groups, func(a, b Group) int {
		return strings.Compare(fmt.Sprintf("%s/%d/%s", a.Kind, a.Dictionary, a.EntryType), fmt.Sprintf("%s/%d/%s", b.Kind, b.Dictionary, b.EntryType))
	})
	c.Ratio = ratio(c.RawBytes, c.StoredBytes)
	var withDict DeltaSaving
	for _, ds := range res.deltas {
		ds.Saving = 1 - ratio(ds.StoredBytes, ds.FullBytes)
		c.Deltas = append(c.Deltas, *ds)
		if ds.Dictionary > 0 {
			withDict.Records += ds.Records
			withDict.StoredBytes += ds.StoredBytes
			withDict.FullBytes += ds.FullBytes
		}
	}
	slices.SortFunc(c.Deltas, func(a, b DeltaSaving) int { return int(a.Dictionary) - int(b.Dictionary) })
	steady := z.VaultWithDictionary
	if steady == 0 {
		steady = z.Vault
	}
	c.Spec = append(c.Spec, gap("vault bytes per entry (spec §10.2 budget, upper end)", specVaultBudget, steady, false))
	if dictStored > 0 {
		c.Spec = append(c.Spec, gap("full leaf records with a dictionary, ratio (spec §3.4, contiguous sample)", specDictRatio, ratio(dictRaw, dictStored), true))
	}
	if plainStored > 0 {
		c.Spec = append(c.Spec, gap("full leaf records without a dictionary, ratio (spec §3.4)", specNoDictRatio, ratio(plainRaw, plainStored), true))
	}
	if withDict.Records > 0 { // the spec's figure is against a dictionary-compressed final certificate
		c.Spec = append(c.Spec, gap("leaf-delta saving over a full record with a dictionary (spec §3.4)", specDeltaSaving,
			1-ratio(withDict.StoredBytes, withDict.FullBytes), true))
	}
	r.Compression = c

	deltaRecords := 0
	for _, mf := range cfg {
		deltaRecords += mf.Counts.DeltaRecords
	}
	r.Links = Links{Finals: sv.finals, Linked: sv.linked, PrecertLater: sv.precertLater, LinkRate: ratio(uint64(sv.linked), uint64(sv.finals)),
		DeltaEligible: sv.eligible, DeltaRecords: deltaRecords, DeltaHitRate: ratio(uint64(deltaRecords), uint64(sv.eligible)),
		DelayMS: percentiles(sv.delays)}
	unique := len(sv.leafType)
	r.Dedup = Dedup{LeafCerts: sv.leafCerts, UniqueLeafCerts: unique, LeafHits: sv.leafCerts - unique,
		LeafHitRate: ratio(uint64(sv.leafCerts-unique), uint64(sv.leafCerts)), ChainRefs: sv.chainRefs, ChainRecords: res.chainRecs,
		ChainHitRate: ratio(uint64(sv.chainRefs-res.chainRecs), uint64(sv.chainRefs))}
	e := Errors{ByCode: map[string]int{}, Committed: committedErrors}
	for code, k := range sv.codes {
		e.ByCode[string(code)] = k
		e.Total += k
		if code.LeafStructure() {
			e.Structural += k
		} else {
			e.Semantic += k
		}
	}
	r.Errors = e
	r.Notes = notes(r, m)
	return r
}

// defaults are the delta settings every run uses: config.Default's.
type defaults struct{ warm, lru int }

func defaultsForReport() defaults {
	c := config.Default()
	return defaults{warm: c.Delta.WarmBatches, lru: c.Ingest.DeltaLRUEntries}
}

func notes(r Report, m sample.Manifest) []string {
	var out []string
	switch m.Kind {
	case sample.Canonical:
		out = append(out, "Canonical sample: the start of a shard is not representative (amendment A1 §2.1); tune seeds and defaults from a representative sample.")
	case sample.Representative:
		out = append(out, fmt.Sprintf("Representative sample: the window starts mid-log at index %d, so precerts logged before it are unknown. Early finals cannot link or delta-encode, and dedup sees only the window.", m.Start))
	}
	dict := false
	for i, b := range r.Batches {
		dict = dict || b.Dictionary > 0
		if i > 0 && b.Dictionary != r.Batches[i-1].Dictionary {
			out = append(out, fmt.Sprintf("batch %d-%d trained dictionary %d before it started; its %.1f s include the training.", b.First, b.Last, b.Dictionary, b.Seconds))
		}
		if b.TrainingError != "" {
			out = append(out, fmt.Sprintf("Dictionary training failed in batch %d-%d: %s", b.First, b.Last, b.TrainingError))
		}
	}
	if !dict {
		out = append(out, fmt.Sprintf("No batch used a trained dictionary: dictionary 1 trains once %d full leaf records are committed, before a later batch starts.", r.Run.DictSamples))
	}
	for _, g := range r.Compression.Spec {
		if g.Exceeds {
			out = append(out, fmt.Sprintf("%s: measured %.3g against the spec's %.3g, more than 10%% worse; Plan 3 decides on any change (amendment A1 §5).", g.What, g.Measured, g.Spec))
		}
	}
	if r.Errors.Total != r.Errors.Committed {
		out = append(out, fmt.Sprintf("The survey found %d leaf errors but the batches committed %d.", r.Errors.Total, r.Errors.Committed))
	}
	out = append(out, "The spec's compression figures are C zstd level 19. The vault uses pure-Go klauspost/compress: full records at SpeedBetterCompression, deltas at SpeedDefault.",
		"This report changes nothing. Disk-guard seeds and the delta warm-up default change only by a reviewed edit (amendment A1 §8).")
	return out
}

// write stores r as <base>/reports/<sample-id>/<UTC time>.json, plus a
// Markdown summary next to it. An existing report is never overwritten.
func write(base string, r Report) (Paths, error) {
	dir := filepath.Join(base, "reports", filepath.FromSlash(r.Sample.ID))
	if err := fsutil.MkdirAllSync(dir, 0o755); err != nil {
		return Paths{}, err
	}
	stem := r.Provenance.ReportedAt.Format("20060102T150405Z")
	for i := 2; ; i++ {
		_, err := os.Stat(filepath.Join(dir, stem+".json"))
		if errors.Is(err, fs.ErrNotExist) {
			break
		}
		if err != nil {
			return Paths{}, err
		}
		stem = fmt.Sprintf("%s-%d", r.Provenance.ReportedAt.Format("20060102T150405Z"), i)
	}
	b, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		return Paths{}, err
	}
	p := Paths{JSON: filepath.Join(dir, stem+".json"), Markdown: filepath.Join(dir, stem+".md")}
	if err := fsutil.WriteFileAtomic(p.JSON, append(b, '\n'), 0o644); err != nil {
		return Paths{}, err
	}
	return p, fsutil.WriteFileAtomic(p.Markdown, []byte(Markdown(r)), 0o644)
}

// Markdown is a short human summary of r.
func Markdown(r Report) string {
	var b strings.Builder
	f := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	z, c, l, d := r.Sizes, r.Compression, r.Links, r.Dedup
	f("# Measurement: %s\n\n", r.Sample.ID)
	f("- Sample: %s, entries [%d, %d) of %s, captured %s\n", r.Sample.Kind, r.Sample.Start, r.Sample.Start+r.Sample.Count, r.Sample.Log, r.Sample.CapturedAt.UTC().Format(time.RFC3339))
	rev := "revision " + r.Provenance.VCSRevision
	if r.Provenance.VCSRevision == "" {
		rev = "no VCS revision"
	} else if r.Provenance.VCSModified {
		rev += ", modified"
	}
	f("- CTVault %s (%s, %s), %s, %s\n", r.Provenance.CTVaultVersion, r.Provenance.Module, rev, r.Provenance.GoVersion, r.Provenance.ZstdLibrary)
	deps := []string{}
	for _, d := range reportedDeps {
		if v, ok := r.Provenance.Dependencies[d]; ok {
			deps = append(deps, d+" "+v)
		}
	}
	f("- Dependencies (from %s): %s\n", r.Provenance.DependenciesFrom, strings.Join(deps, ", "))
	f("- Run: %d batches of %d, %.1f s of ingest (%.0f entries/s), reported %s\n\n", r.Run.Batches, r.Run.BatchSize, r.Run.IngestSeconds, r.Run.EntriesPerSecond, r.Provenance.ReportedAt.Format(time.RFC3339))
	f("## Bytes per entry\n\n| Component | Measured | Disk-guard seed |\n|---|---|---|\n")
	f("| Vault (records) | %.1f | %d |\n| Vault (segment files) | %.1f | |\n| Vault, batches with a dictionary | %.1f | |\n", z.Vault, z.SeedVault, z.VaultFiles, z.VaultWithDictionary)
	f("| Parquet | %.1f | %d |\n| Pebble | %.1f | %d |\n| **Total** | **%.1f** | %d |\n\n", z.Parquet, z.SeedParquet, z.Pebble, z.SeedPebble, z.Total, z.SeedVault+z.SeedParquet+z.SeedPebble)
	f("## Compression\n\nOverall %.2f× (%d raw DER bytes in %d record bytes).\n\n| Records | Dictionary | Entry type | Count | Ratio | Mean bytes |\n|---|---|---|---|---|---|\n", c.Ratio, c.RawBytes, c.StoredBytes)
	for _, g := range c.Groups {
		f("| %s | %d | %s | %d | %.2f× | %.0f |\n", g.Kind, g.Dictionary, g.EntryType, g.Records, g.Ratio, g.MeanStored)
	}
	f("\n")
	for _, ds := range c.Deltas {
		f("leaf-delta in batches with dictionary %d: %d records, %.1f%% smaller than the same certificates stored in full.\n", ds.Dictionary, ds.Records, 100*ds.Saving)
	}
	f("\n| Against the spec | Spec | Measured | Gap | More than 10%% worse |\n|---|---|---|---|---|\n")
	for _, g := range c.Spec {
		f("| %s | %.3g | %.3g | %+.1f%% | %v |\n", g.What, g.Spec, g.Measured, 100*g.Gap, g.Exceeds)
	}
	f("\n## Links, dedup and errors\n\n")
	f("- precert→final: %d of %d finals link (%.1f%%), %d more have their precert later in the window; delay p50 %s, p95 %s, p99 %s\n", l.Linked, l.Finals, 100*l.LinkRate, l.PrecertLater,
		time.Duration(l.DelayMS.P50)*time.Millisecond, time.Duration(l.DelayMS.P95)*time.Millisecond, time.Duration(l.DelayMS.P99)*time.Millisecond)
	f("- leaf-delta hit rate: %d of %d eligible finals (%.1f%%)\n", l.DeltaRecords, l.DeltaEligible, 100*l.DeltaHitRate)
	f("- dedup: leaf %d of %d (%.2f%%), chain %d of %d references (%.2f%%)\n", d.LeafHits, d.LeafCerts, 100*d.LeafHitRate, d.ChainRefs-d.ChainRecords, d.ChainRefs, 100*d.ChainHitRate)
	f("- leaf errors: %d (%d structural, %d semantic) %v\n\n", r.Errors.Total, r.Errors.Structural, r.Errors.Semantic, r.Errors.ByCode)
	f("## Batches\n\n| Range | Entries | New certs | Deltas | Vault B/entry | Parquet B/entry | Dictionary | Seconds |\n|---|---|---|---|---|---|---|---|\n")
	for _, x := range r.Batches {
		f("| %d-%d | %d | %d | %d | %.1f | %.1f | %d | %.1f |\n", x.First, x.Last, x.Entries, x.NewCerts, x.DeltaRecords,
			perEntry(int64(x.VaultBytes), uint64(x.Entries)), perEntry(x.ParquetBytes, uint64(x.Entries)), x.Dictionary, x.Seconds)
	}
	f("\n## Notes\n\n")
	for _, n := range r.Notes {
		f("- %s\n", n)
	}
	return b.String()
}
