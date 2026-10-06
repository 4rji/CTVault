package dataset

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/4rji/ctvault/internal/derive"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var ctx = context.Background()

func stager(t *testing.T) *Stager {
	t.Helper()
	s, err := NewStager(Options{TempDir: filepath.Join(t.TempDir(), "duckdb-1"), MaxTempBytes: 1 << 30, Threads: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// rows makes n entries covering every column state: precerts with an issuer
// key hash, x509 entries, and leaf errors with NULL certificate fields.
func rows(n int) ([]EntryRow, []ChainRow) {
	var es []EntryRow
	var cs []ChainRow
	for i := range n {
		r := EntryRow{Idx: uint64(1000 + i), CTTimestamp: 1790000000000 + uint64(i), EntryType: "x509", CertID: uint64(i + 1),
			LeafHash: sha256.Sum256([]byte{byte(i), byte(i >> 8)}), HasIssuanceKey: true, HasChainID: true}
		r.IssuanceKey[0], r.ChainID = byte(i), sha256.Sum256([]byte{byte(i % 3)})
		switch i % 4 {
		case 1:
			r.EntryType, r.HasIssuerKeyHash = "precert", true
			r.IssuerKeyHash[5] = 7
		case 3:
			r = EntryRow{Idx: r.Idx, LeafHash: r.LeafHash, EntryType: "unknown", LeafError: "leaf_bad_version"}
		}
		es = append(es, r)
	}
	for c := range 3 {
		for p := range 2 {
			cs = append(cs, ChainRow{ChainID: sha256.Sum256([]byte{byte(c)}), Position: uint16(p), CertID: uint64(500 + 10*c + p)})
		}
	}
	return es, cs
}

func TestStageAndCanary(t *testing.T) {
	s := stager(t)
	dir := filepath.Join(t.TempDir(), "stage", "b1")
	es, cs := rows(200)
	files, err := s.Stage(ctx, dir, es, cs)
	if err != nil {
		t.Fatal(err)
	}
	for name, rowsWant := range map[string]int{EntriesFile: 200, ChainsFile: 6} {
		fi := files[name]
		sum, err := Sum(filepath.Join(dir, name))
		if err != nil || fi.Rows != rowsWant || fi.Bytes == 0 || sum.SHA256 != fi.SHA256 {
			t.Fatalf("%s: %+v (recomputed %+v, %v)", name, fi, sum, err)
		}
	}
	if err := s.Canary(ctx, dir, es, cs, 1000, rand.New(rand.NewPCG(1, 2))); err != nil {
		t.Fatalf("every row must read back: %v", err)
	}
}

func TestCanaryCatchesMismatches(t *testing.T) {
	s := stager(t)
	dir := filepath.Join(t.TempDir(), "b")
	es, cs := rows(40)
	if _, err := s.Stage(ctx, dir, es, cs); err != nil {
		t.Fatal(err)
	}
	rnd := func() *rand.Rand { return rand.New(rand.NewPCG(3, 4)) }
	if err := s.Canary(ctx, dir, es[:39], cs, 5, rnd()); !errors.Is(err, ErrCanary) {
		t.Fatalf("a row count mismatch: %v", err)
	}
	bad := append([]EntryRow(nil), es...)
	for i := range bad {
		bad[i].CertID++
	}
	if err := s.Canary(ctx, dir, bad, cs, 5, rnd()); !errors.Is(err, ErrCanary) {
		t.Fatalf("a field that reads back differently: %v", err)
	}
	badChains := append([]ChainRow(nil), cs...)
	for i := range badChains {
		badChains[i].CertID++
	}
	if err := s.Canary(ctx, dir, es, badChains, 5, rnd()); !errors.Is(err, ErrCanary) {
		t.Fatalf("a chain that reads back differently: %v", err)
	}
}

func TestCanaryRefusesBloomFilters(t *testing.T) {
	s := stager(t)
	dir := filepath.Join(t.TempDir(), "b")
	es, cs := rows(40)
	if _, err := s.Stage(ctx, dir, es, cs); err != nil {
		t.Fatal(err)
	}
	// Rewrite entries.parquet the default way, which adds bloom filters.
	p := filepath.Join(dir, EntriesFile)
	if _, err := s.db.Exec(`COPY (SELECT * FROM read_parquet(` + quote(p) + `)) TO ` + quote(p+".bloom") + ` (FORMAT parquet)`); err != nil {
		t.Fatal(err)
	}
	os.Rename(p+".bloom", p)
	if err := s.Canary(ctx, dir, es, cs, 5, rand.New(rand.NewPCG(5, 6))); !errors.Is(err, ErrCanary) || !strings.Contains(err.Error(), "bloom") {
		t.Fatalf("a bloom-filtered file must fail the canary: %v", err)
	}
}

// TestDuckDBBloomFilterBugRegression reproduces spec §3.6 on the pinned
// DuckDB: a literal lookup on a bloom-filtered, low-cardinality BLOB column
// finds nothing. When DuckDB fixes it this test fails, so decision D19 (no
// bloom filters on BLOB columns) can be revisited; the writer keeps them off
// either way.
func TestDuckDBBloomFilterBugRegression(t *testing.T) {
	s := stager(t)
	dir := t.TempDir()
	const data = `SELECT unhex(sha256((i % 3)::VARCHAR)) AS ikh FROM range(2000) t(i)`
	lookup := `SELECT count(*) FROM read_parquet(?) WHERE ikh = unhex(sha256('1'))`
	bloom, plain := filepath.Join(dir, "bloom.parquet"), filepath.Join(dir, "plain.parquet")
	if _, err := s.db.Exec(`COPY (` + data + `) TO ` + quote(bloom) + ` (FORMAT parquet)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`COPY (` + data + `) TO ` + quote(plain) + ` ` + copyOptions); err != nil {
		t.Fatal(err)
	}
	var withBloom, without int
	s.db.QueryRow(lookup, bloom).Scan(&withBloom)
	s.db.QueryRow(lookup, plain).Scan(&without)
	if without != 667 {
		t.Fatalf("control: CTVault's writer settings must find all 667 rows, got %d", without)
	}
	if withBloom == 667 {
		t.Error("DuckDB no longer shows the BLOB bloom-filter bug (spec §3.6); D19 can be revisited")
	} else if withBloom != 0 {
		t.Fatalf("unexpected count %d with bloom filters", withBloom)
	}
}

func TestStagerConfinesSpill(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "duckdb-42")
	s, err := NewStager(Options{TempDir: dir, MaxTempBytes: 3 << 30})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var temp, max string
	s.db.QueryRow(`SELECT current_setting('temp_directory'), current_setting('max_temp_directory_size')`).Scan(&temp, &max)
	if temp != dir || !strings.HasPrefix(max, "3.0 GiB") {
		t.Fatalf("temp_directory %q, max_temp_directory_size %q", temp, max)
	}
}

// TestViewsSeeCommittedBatchesOnly loads views.sql into a fresh DuckDB
// session over two committed batches and a staged one.
func TestViewsSeeCommittedBatchesOnly(t *testing.T) {
	s := stager(t)
	root := t.TempDir()
	for i, b := range []string{"batch=000000000000-000000000039", "batch=000000000040-000000000079"} {
		dir := filepath.Join(root, "dataset", "log=argon2027h1", b)
		es, cs := rows(40)
		for j := range es {
			es[j].Idx = uint64(40*i + j)
		}
		if _, err := s.Stage(ctx, dir, es, cs); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, "_COMMIT.json"), []byte(fmt.Sprintf(`{"format":1,"commit_seq":%d}`, i+1)), 0o644)
	}
	es, cs := rows(40)
	if _, err := s.Stage(ctx, filepath.Join(root, "tmp", "stage", "x"), es, cs); err != nil {
		t.Fatal(err)
	}
	if changed, err := WriteViews(root, derive.Complete()); err != nil || !changed {
		t.Fatalf("first write: %v %v", changed, err)
	}
	if changed, _ := WriteViews(root, derive.Complete()); changed {
		t.Fatal("views.sql is rewritten only when it changes")
	}
	v, _ := os.ReadFile(filepath.Join(root, ViewsFile))
	if _, err := s.db.Exec(string(v)); err != nil {
		t.Fatal(err)
	}
	var n, logs, batches int
	s.db.QueryRow(`SELECT count(*), count(DISTINCT log) FROM entries`).Scan(&n, &logs)
	s.db.QueryRow(`SELECT count(*) FROM batches`).Scan(&batches)
	var chains int
	s.db.QueryRow(`SELECT count(*) FROM chains`).Scan(&chains)
	if n != 80 || logs != 1 || batches != 2 || chains != 12 {
		t.Fatalf("views: %d entries in %d logs, %d batches, %d chain rows; want 80, 1, 2, 12 (staging excluded)", n, logs, batches, chains)
	}
}
