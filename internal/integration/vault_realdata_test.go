//go:build realdata

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	_ "github.com/duckdb/duckdb-go/v2" // the "duckdb" database/sql driver

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/extract"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/ingest"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/sources"
	"github.com/4rji/ctvault/internal/measure"
	"github.com/4rji/ctvault/internal/sample"
	"github.com/4rji/ctvault/internal/sampletest"
	"github.com/4rji/ctvault/internal/vault"
	"github.com/4rji/ctvault/internal/vaulttest"
)

// realVault is a fresh vault in a temp folder, ingesting a canonical sample
// replayed over loopback through the production client, fetcher and writer.
type realVault struct {
	t      *testing.T
	s      *sample.Sample
	v      vaulttest.Vault
	opts   ingest.Options
	src    logsource.LogSource
	chains *logsource.ChainCache
	head   logsource.SignedHead
	out    bytes.Buffer
}

func newRealVault(t *testing.T, s *sample.Sample, dictSamples int) *realVault {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"state/intent", "state/incidents", "state/logs", "vault/segments", "vault/dict", "dataset", "tmp/stage", "tmp/rebuild"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var id [16]byte
	rand.Read(id[:])
	r := &realVault{t: t, s: s, v: vaulttest.Vault{Root: root, Dirs: []string{filepath.Join(root, "vault")}, UUID: id}}
	url, stop, err := sample.Serve(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	r.chains = logsource.NewChainCache(logsource.DefaultChainCacheBytes)
	// The RFC 6962 or the tiled source, by the sample's protocol (A6 §5).
	if r.src, err = sources.Open(s.LogInfo(url), nil, r.chains, nil); err != nil {
		t.Fatal(err)
	}
	if r.head, err = r.src.Head(context.Background()); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	r.opts = ingest.Options{Root: root, VaultDirs: r.v.Dirs, VaultUUID: id, Config: cfg,
		Guard: diskguard.Guard{Cap: cfg.Disk.MaxUsedFraction, Stat: diskguard.Statfs}, Version: "realdata-test", Out: &r.out,
		Fetch:       fetch.Options{MaxRPS: 1000, PageSize: s.Manifest.PageSize, MinBackoff: time.Millisecond, MaxBackoff: 10 * time.Millisecond},
		DictSamples: dictSamples}
	return r
}

func (r *realVault) open() *ingest.Writer {
	r.t.Helper()
	w, err := ingest.Open(r.opts)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { w.Close() })
	return w
}

// ingest commits [w's next index, to) in batches of size, verified against
// the sample's signed head with its stored consistency proofs.
func (r *realVault) ingest(w *ingest.Writer, to, size uint64) {
	r.t.Helper()
	log := r.s.Manifest.Log.Name
	for first := w.Next(log); first < to; first = w.Next(log) {
		if _, err := w.Batch(context.Background(), r.src, r.head, first, min(first+size, to)); err != nil {
			r.t.Fatalf("batch at %d: %v\n%s", first, err, r.out.String())
		}
		r.chains.Reset()
	}
}

// expected decodes the sample's entries [0, n) directly, for comparison.
type expected struct {
	types map[string]int
	certs map[uint64][]byte // idx → leaf certificate DER
}

func decodeSample(t *testing.T, s *sample.Sample, n uint64) expected {
	t.Helper()
	e := expected{types: map[string]int{}, certs: map[uint64][]byte{}}
	err := s.Each(func(x sample.Entry) error {
		if x.Index >= n {
			return nil
		}
		l := leaf.Decode(x.LeafInput, x.ExtraData)
		e.types[l.Type.String()]++
		if l.CertDER != nil {
			e.certs[x.Index] = l.CertDER
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func queryInt(t *testing.T, db *sql.DB, q string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// TestCanonicalIngestEndToEnd ingests the whole canonical sample into a
// vault with the production settings (dictionary 1 trains on 20,000 real
// certificates), then checks the vault's invariants, queries it through
// views.sql and reads certificates back.
func TestCanonicalIngestEndToEnd(t *testing.T) {
	s := sampletest.Canonical(t, realLog)
	n := s.Manifest.Count
	r := newRealVault(t, s, 0)
	w := r.open()
	start := time.Now()
	r.ingest(w, n, 10000)
	t.Logf("ingested %d entries in %v", n, time.Since(start).Round(time.Second))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r.v.CheckRecovered(t)

	ms, err := commit.ListCommitted(r.v.Root)
	if err != nil || uint64(len(ms)) != n/10000 {
		t.Fatalf("%d batches, %v", len(ms), err)
	}
	trained := false
	for _, m := range ms {
		if m.Verified.Method != "consistency_proof" {
			t.Fatalf("batch %s verified by %q", m.BatchID, m.Verified.Method)
		}
		trained = trained || m.Dictionary.ID == 1
	}
	ds, err := vault.LoadDicts(r.v.Dirs)
	if err != nil || !trained || len(ds) != 1 || ds[0].Manifest.Training.Records != vault.TrainingSamples {
		t.Fatalf("dictionary 1 trained on %d real certificates: %v %v", vault.TrainingSamples, ds, err)
	}

	want := decodeSample(t, s, n)
	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	views, err := os.ReadFile(filepath.Join(r.v.Root, dataset.ViewsFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(views)); err != nil {
		t.Fatalf("loading views.sql: %v", err)
	}
	if got := queryInt(t, db, `SELECT count(*) FROM entries`); got != int64(n) {
		t.Fatalf("entries: %d rows", got)
	}
	if got := queryInt(t, db, `SELECT count(DISTINCT idx) FROM entries WHERE idx BETWEEN 0 AND ?`, n-1); got != int64(n) {
		t.Fatalf("entries: %d distinct indexes in [0, %d)", got, n)
	}
	for typ, k := range want.types {
		if got := queryInt(t, db, `SELECT count(*) FROM entries WHERE entry_type = ?`, typ); got != int64(k) {
			t.Fatalf("entry_type %s: %d rows, the sample has %d", typ, got, k)
		}
	}
	if got := queryInt(t, db, `SELECT count(*) FROM batches`); got != int64(len(ms)) {
		t.Fatalf("batches view: %d rows", got)
	}
	// Every chain starts at position 0, and each entry's chain resolves.
	if a, b := queryInt(t, db, `SELECT count(*) FROM entries WHERE chain_id IS NOT NULL`),
		queryInt(t, db, `SELECT count(*) FROM entries e JOIN (SELECT DISTINCT chain_id FROM chains WHERE position = 0) c USING (chain_id)`); a != b || a == 0 {
		t.Fatalf("%d entries have a chain, %d resolve to one", a, b)
	}
	// Amendment A1 §6 on real data: a literal lookup on a BLOB column finds
	// every row (a bloom filter would have returned none).
	var ikh string
	var rows int64
	if err := db.QueryRow(`SELECT hex(issuer_key_hash), count(*) FROM entries WHERE issuer_key_hash IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 1`).Scan(&ikh, &rows); err != nil {
		t.Fatal(err)
	}
	if got := queryInt(t, db, fmt.Sprintf(`SELECT count(*) FROM entries WHERE issuer_key_hash = from_hex('%s')`, ikh)); got != rows || rows == 0 {
		t.Fatalf("literal issuer_key_hash lookup: %d rows, want %d", got, rows)
	}

	// Derived tables (amendment A2 §4): every batch built them, ACTIVE.json
	// is complete, every vaulted certificate has one certs row, every entry
	// joins its certificate, and kinds agree with the entry types.
	if a, ok, err := derive.ReadActive(r.v.Root); err != nil || !ok || !a.AllComplete() {
		t.Fatalf("ACTIVE.json: %+v %v %v", a, ok, err)
	}
	var newCerts int64
	for _, m := range ms {
		if m.Builders[derive.CertsV1.Name] != derive.CertsV1.Version || m.Builders[derive.NamesV1.Name] != derive.NamesV1.Version {
			t.Fatalf("batch %s built %v", m.BatchID, m.Builders)
		}
		newCerts += int64(m.Counts.NewCerts)
	}
	if got := queryInt(t, db, `SELECT count(*) FROM certs`); got != newCerts {
		t.Fatalf("certs: %d rows for %d vaulted certificates", got, newCerts)
	}
	if a, b := queryInt(t, db, `SELECT count(*) FROM entries WHERE cert_id IS NOT NULL`), queryInt(t, db, `SELECT count(*) FROM entry_certs`); a != b || a == 0 {
		t.Fatalf("%d entries have a certificate, %d join certs", a, b)
	}
	if got := queryInt(t, db, `SELECT count(*) FROM entry_certs
		WHERE NOT (entry_type = 'precert' AND kind = 'precert' OR entry_type = 'x509' AND kind IN ('final', 'chain'))`); got != 0 {
		t.Fatalf("%d entries disagree with their certificate's kind", got)
	}
	if got := queryInt(t, db, `SELECT count(*) FROM logging_delay WHERE logging_delay IS NOT NULL`); got == 0 {
		t.Fatal("logging_delay has no values")
	}
	// Literal lookups on the bloom-filtered columns find every row.
	var top string
	if err := db.QueryRow(`SELECT name, count(*) FROM names WHERE dns_valid GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 1`).Scan(&top, &rows); err != nil {
		t.Fatal(err)
	}
	if got := queryInt(t, db, `SELECT count(*) FROM names WHERE name = '`+top+`'`); got != rows || rows == 0 {
		t.Fatalf("literal names lookup of %s: %d rows, want %d", top, got, rows)
	}
	t.Logf("derived: %d certs rows, %d names rows (%d dns_valid), %d entries joined to certs", newCerts,
		queryInt(t, db, `SELECT count(*) FROM names`), queryInt(t, db, `SELECT count(*) FROM names WHERE dns_valid`),
		queryInt(t, db, `SELECT count(*) FROM entry_certs`))

	// Certificates read back through Pebble and the vault, verified.
	idx, err := index.Open(filepath.Join(r.v.Root, "state", "pebble"))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	codec, err := vault.NewCodec()
	if err != nil {
		t.Fatal(err)
	}
	defer codec.Close()
	for _, d := range ds {
		codec.AddDict(d.Manifest.ID, d.Content)
	}
	vr, err := vault.OpenReader(r.v.Dirs, codec)
	if err != nil {
		t.Fatal(err)
	}
	defer vr.Close()
	rnd := mrand.New(mrand.NewPCG(1, 2))
	for range 1000 {
		i := rnd.Uint64N(n)
		der, ok := want.certs[i]
		if !ok {
			continue
		}
		sha := sha256.Sum256(der)
		ref, ok, err := idx.Lookup(sha)
		if err != nil || !ok {
			t.Fatalf("entry %d: certificate %x not in the index (%v)", i, sha[:8], err)
		}
		got, err := vr.ReadVerified(ref.Loc, sha)
		if err != nil || !bytes.Equal(got, der) {
			t.Fatalf("entry %d: reading certificate %x back: %v", i, sha[:8], err)
		}
		if c := queryInt(t, db, `SELECT count(*) FROM entries WHERE idx = ? AND cert_id = ?`, i, ref.CertID); c != 1 {
			t.Fatalf("entry %d: entries.parquet does not point at cert_id %d", i, ref.CertID)
		}
		// Its derived rows, found by a literal sha256, match the extractor.
		c := extract.Parse(der)
		var status, issuer string
		var dns int64
		if err := db.QueryRow(fmt.Sprintf(`SELECT parse_status, coalesce(issuer_der, ''), n_dns_names FROM certs WHERE sha256 = '%x' AND cert_id = %d`, sha, ref.CertID)).
			Scan(&status, &issuer, &dns); err != nil || status != string(c.Status) || issuer != hex.EncodeToString(c.Issuer.Raw) || dns != int64(len(c.DNSNames)) {
			t.Fatalf("entry %d: certs row (%s, %s, %d) differs from the extractor's %+v: %v", i, status, issuer, dns, c, err)
		}
		if got, want := queryInt(t, db, `SELECT count(*) FROM names WHERE cert_id = ?`, ref.CertID), len(derive.Names{}.Build(c, derive.Context{CertID: ref.CertID})); got != int64(want) {
			t.Fatalf("entry %d: %d names rows, the builder gives %d", i, got, want)
		}
	}
}

// TestRecoveryEquivalenceOnRealData crashes an ingest of real entries at
// commit boundaries, across dictionary training and leaf-delta batches,
// recovers each time, and requires the result to equal a clean ingest on
// everything but internal IDs (amendment A1 §7).
func TestRecoveryEquivalenceOnRealData(t *testing.T) {
	s := sampletest.Canonical(t, realLog)
	const n, size, dict = 30000, 5000, 2000 // dictionary 1 trains before the second batch
	clean := newRealVault(t, s, dict)
	cw := clean.open()
	clean.ingest(cw, n, size)
	cw.Close()
	want := clean.v.Dump(t)
	if len(want.Certs) == 0 {
		t.Fatal("the clean ingest has no derived rows")
	}

	r := newRealVault(t, s, dict)
	crashes := []struct {
		at    uint64 // the batch that crashes
		point string
	}{
		{5000, commit.HookAfterIntent}, // the batch that trains dictionary 1
		{10000, vault.HookAppendMidRecord},
		{15000, ingest.HookDuringCanary},
		{20000, commit.HookBeforeRename},
		{25000, ingest.HookBeforePebble},
	}
	for _, c := range crashes {
		w := r.open()
		r.ingest(w, c.at, size)
		w.Close()
		r.opts.Hook = func(p string) {
			if p == c.point {
				panic("crash at " + p)
			}
		}
		w = r.open()
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("batch at %d: %s did not fire", c.at, c.point)
				}
			}()
			w.Batch(context.Background(), r.src, r.head, c.at, c.at+size)
		}()
		w.Close()
		r.chains.Reset()
		r.opts.Hook = nil
		w = r.open() // recovers
		w.Close()
		r.v.CheckRecovered(t)
		if !strings.Contains(r.out.String(), "recovery:") {
			t.Fatalf("crash at %s (batch %d): recovery reported nothing", c.point, c.at)
		}
	}
	w := r.open()
	r.ingest(w, n, size)
	w.Close()
	r.v.CheckRecovered(t)
	if d := vaulttest.Diff(r.v.Dump(t), want); d != "" {
		t.Fatalf("the recovered ingest differs from a clean one: %s", d)
	}
	ms, _ := commit.ListCommitted(r.v.Root)
	got, want2 := ms[len(ms)-1].NextCertID, lastNext(t, clean.v.Root)
	if got <= want2 {
		t.Fatalf("after crashes cert_ids resume at ID_FLOOR, leaving gaps: next %d, clean %d", got, want2)
	}
	t.Logf("%d crashes recovered; %d batches equal a clean ingest of %d real entries (next cert_id %d, clean %d)",
		len(crashes), len(ms), n, got, want2)
}

// TestRebuildEquivalenceOnRealData is amendment A2 §5.7's essential test on
// the canonical sample: ingested with the builders off and then rebuilt,
// every batch's certs and names files are byte-identical to an ingest with
// the builders on. No dictionary is trained, so both vaults hold the same
// records at the same locations.
func TestRebuildEquivalenceOnRealData(t *testing.T) {
	s := sampletest.Canonical(t, realLog)
	n := s.Manifest.Count
	sums := func(root string) []string {
		ms, err := commit.ListCommitted(root)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, m := range ms {
			for _, b := range derive.Builders {
				fi, ok := m.Listed(b.Table().File())
				if !ok {
					t.Fatalf("batch %s lists no %s", m.BatchID, b.Table().File())
				}
				out = append(out, m.BatchID+" "+b.Table().File()+" "+fi.SHA256)
			}
		}
		return out
	}
	on := newRealVault(t, s, 1<<30)
	w := on.open()
	on.ingest(w, n, 10000)
	w.Close()

	off := newRealVault(t, s, 1<<30)
	off.opts.NoDerived = true
	w = off.open()
	off.ingest(w, n, 10000)
	w.Close()
	off.opts.NoDerived = false
	if err := os.Remove(filepath.Join(off.v.Root, "dataset", derive.ActiveFile)); err != nil {
		t.Fatal(err)
	}
	w = off.open()
	start := time.Now()
	st, err := w.Rebuild(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	w.Close()
	if got, want := sums(off.v.Root), sums(on.v.Root); !slices.Equal(got, want) || !st.Switched {
		t.Fatalf("rebuilt files differ from an ingest with the builders on (switched %v):\n%s\nwant\n%s",
			st.Switched, strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	off.v.CheckRecovered(t)
	t.Logf("rebuilt %d batches of %d real entries in %v (%d certs rows, %d names rows): byte-identical to ingest",
		st.Batches, n, took.Round(time.Millisecond), st.Rows["certs"], st.Rows["names"])
}

func lastNext(t *testing.T, root string) uint64 {
	ms, err := commit.ListCommitted(root)
	if err != nil || len(ms) == 0 {
		t.Fatal(err)
	}
	return ms[len(ms)-1].NextCertID
}

// TestMeasurementReports measures every cached sample of the log and writes
// the reports under the dev base (amendment A1 §8).
func TestMeasurementReports(t *testing.T) {
	samples := []*sample.Sample{sampletest.Canonical(t, realLog)}
	samples = append(samples, sampletest.Representatives(t, realLog)...)
	base := filepath.Dir(sampletest.Base(t))
	for _, s := range samples {
		id := s.Manifest.ID(filepath.Base(s.Dir))
		t.Run(strings.ReplaceAll(id, "/", "_"), func(t *testing.T) {
			r, p, err := measure.Run(context.Background(), s, measure.Options{Base: base, Version: "realdata-test", Stat: diskguard.Statfs,
				Dependencies: goModVersions(t)})
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Provenance.Dependencies) != 5 {
				t.Fatalf("provenance lacks dependency versions: %v", r.Provenance.Dependencies)
			}
			if r.Errors.Total != r.Errors.Committed || r.Sizes.Vault <= 0 || r.Sizes.Parquet <= 0 || r.Sizes.Pebble <= 0 {
				t.Fatalf("inconsistent report: errors %+v, sizes %+v", r.Errors, r.Sizes)
			}
			full := 0
			for _, g := range r.Compression.Groups {
				if g.Kind == "leaf" || g.Kind == "delta" {
					full += g.Records
				}
			}
			if full != r.Dedup.UniqueLeafCerts {
				t.Fatalf("%d leaf and delta records for %d unique leaf certificates", full, r.Dedup.UniqueLeafCerts)
			}
			t.Logf("report %s\n%s", p.JSON, measure.Markdown(r))
		})
	}
}

// goModVersions reads the required module versions from go.mod: a go test
// binary's build info lists no dependencies.
func goModVersions(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "require "))
		if len(f) >= 2 && strings.Contains(f[0], ".") && strings.HasPrefix(f[1], "v") {
			out[f[0]] = f[1]
		}
	}
	return out
}
