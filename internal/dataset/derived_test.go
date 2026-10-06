package dataset

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/klauspost/compress/zstd"

	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/extract"
	"github.com/4rji/ctvault/internal/vault"
)

// corpus returns the first n real certificates of the extractor's corpus.
func corpus(t *testing.T, n int) [][]byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "extract", "testdata", "corpus.bin.zst"))
	if err != nil {
		t.Fatal(err)
	}
	dec, _ := zstd.NewReader(nil)
	defer dec.Close()
	raw, _ := dec.DecodeAll(b, nil)
	var out [][]byte
	for len(out) < n && len(raw) > 0 {
		l, k := binary.Uvarint(raw)
		out = append(out, raw[k:k+int(l)])
		raw = raw[k+int(l):]
	}
	return out
}

func tables() []derive.Table {
	var out []derive.Table
	for _, bl := range derive.Builders {
		out = append(out, bl.Table())
	}
	return out
}

// stageDerived adds every builder's rows for ders, with cert_ids 1..n, to
// a new DerivedStage that samples keep rows per table, and writes the files
// into dir.
func stageDerived(t *testing.T, s *Stager, dir string, ders [][]byte, keep int) (*DerivedStage, map[string]FileInfo) {
	t.Helper()
	d, err := s.BeginDerived(ctx, tables(), keep, rand.New(rand.NewPCG(3, 4)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	for i, der := range ders {
		c := extract.Parse(der)
		cx := derive.Context{CertID: uint64(i + 1), SHA256: sha256.Sum256(der), Kind: derive.KindFinal,
			Loc: vault.Loc{Segment: 1, Offset: uint64(64 + 1000*i), Len: 900}}
		for j, bl := range derive.Builders {
			if err := d.Add(j, bl.Build(c, cx)); err != nil {
				t.Fatal(err)
			}
		}
	}
	files, err := d.Write(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	return d, files
}

func singleThreaded(t *testing.T) *Stager {
	t.Helper()
	s, err := NewStager(Options{TempDir: filepath.Join(t.TempDir(), "duckdb-1"), MaxTempBytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestStageDerived: the derived files carry their schema, KV metadata and
// bloom filters, pass the canary, and are byte-identical when staged again
// by another session (spec §7.2).
func TestStageDerived(t *testing.T) {
	ders := corpus(t, 400)
	s := singleThreaded(t)
	dir := filepath.Join(t.TempDir(), "b")
	d, files := stageDerived(t, s, dir, ders, 16)
	if fi := files[derive.CertsV1.File()]; fi.Rows != 400 || fi.Bytes == 0 {
		t.Fatalf("certs: %+v for 400 certificates", fi)
	}
	if fi := files[derive.NamesV1.File()]; fi.Rows < 400 || fi.Bytes == 0 {
		t.Fatalf("names: %+v for 400 certificates", fi)
	}
	if err := d.Canary(ctx, dir); err != nil {
		t.Fatal(err)
	}
	// The files keep the order the rows were added in (amendment A2 §4.3).
	var want []string
	for i, der := range ders {
		for _, r := range (derive.Names{}).Build(extract.Parse(der), derive.Context{CertID: uint64(i + 1)}) {
			want = append(want, fmt.Sprint(r[0], " ", r[2]))
		}
	}
	rs, err := s.db.Query(`SELECT cert_id, name FROM read_parquet(` + quote(filepath.Join(dir, derive.NamesV1.File())) + `, file_row_number = true) ORDER BY file_row_number`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rs.Next() {
		var id uint64
		var name string
		rs.Scan(&id, &name)
		got = append(got, fmt.Sprint(id, " ", name))
	}
	rs.Close()
	if !slices.Equal(got, want) {
		t.Fatalf("names rows are not in the order they were added: %d rows, first %v, want %d rows, first %v", len(got), got[:min(3, len(got))], len(want), want[:3])
	}
	var kv string
	s.db.QueryRow(`SELECT string_agg(decode(key) || '=' || decode(value), ',' ORDER BY key) FROM parquet_kv_metadata(` +
		quote(filepath.Join(dir, derive.CertsV1.File())) + `)`).Scan(&kv)
	if kv != "ctvault.extractor="+derive.ExtractorVersion+",ctvault.psl=,ctvault.schema_sha256="+derive.CertsV1.SchemaSHA256()+",ctvault.table=certs,ctvault.version=1" {
		t.Errorf("certs KV metadata: %s", kv)
	}

	again := filepath.Join(t.TempDir(), "b")
	stageDerived(t, singleThreaded(t), again, ders, 16)
	for _, tb := range tables() {
		a, _ := os.ReadFile(filepath.Join(dir, tb.File()))
		b, _ := os.ReadFile(filepath.Join(again, tb.File()))
		if !bytes.Equal(a, b) {
			t.Errorf("%s is not byte-identical when staged again", tb.File())
		}
	}
}

// TestDerivedSample: each table keeps a uniform sample of its rows for the
// canary: all of them when there are fewer, otherwise keep distinct rows
// drawn from the whole batch, not just its first rows.
func TestDerivedSample(t *testing.T) {
	ders := corpus(t, 200)
	s := singleThreaded(t)
	d, _ := stageDerived(t, s, filepath.Join(t.TempDir(), "all"), ders, 500)
	if got := len(d.tables[0].sample); got != 200 {
		t.Fatalf("keeping 500 of 200 rows kept %d", got)
	}
	d, _ = stageDerived(t, s, filepath.Join(t.TempDir(), "some"), ders, 20)
	seen, late := map[uint64]bool{}, 0
	for _, r := range d.tables[0].sample {
		id := r[0].(uint64)
		if seen[id] {
			t.Fatalf("cert_id %d sampled twice", id)
		}
		seen[id] = true
		if id > 20 {
			late++
		}
	}
	if len(seen) != 20 || late == 0 {
		t.Fatalf("kept %d rows, %d beyond the first 20", len(seen), late)
	}
}

// TestDerivedCanaryCatchesBadFiles: a row that reads back differently, or a
// file without its bloom filters, fails the canary.
func TestDerivedCanaryCatchesBadFiles(t *testing.T) {
	s := singleThreaded(t)
	dir := filepath.Join(t.TempDir(), "b")
	d, _ := stageDerived(t, s, dir, corpus(t, 50), 50)
	certs := d.tables[0]
	good := certs.sample[7]
	row := append(derive.Row(nil), good...)
	row[1] = "00" + row[1].(string)[2:] // another sha256 for this cert_id
	certs.sample[7] = row
	if err := d.Canary(ctx, dir); !errors.Is(err, ErrCanary) {
		t.Fatalf("a certs row that reads back differently: %v", err)
	}
	certs.sample[7] = good
	p := filepath.Join(dir, derive.CertsV1.File())
	if _, err := s.db.Exec(`COPY (SELECT * FROM read_parquet(` + quote(p) + `)) TO ` + quote(p+".nobloom") +
		` (FORMAT parquet, WRITE_BLOOM_FILTER false)`); err != nil {
		t.Fatal(err)
	}
	os.Rename(p+".nobloom", p)
	if err := d.Canary(ctx, dir); !errors.Is(err, ErrCanary) {
		t.Fatalf("certs without bloom filters: %v", err)
	}
}

// TestDerivedStageClose: closing a stage that never wrote (a failed batch
// attempt) drops its staging tables, and the next stage starts empty.
func TestDerivedStageClose(t *testing.T) {
	s := singleThreaded(t)
	d, err := s.BeginDerived(ctx, tables(), 4, rand.New(rand.NewPCG(1, 2)))
	if err != nil {
		t.Fatal(err)
	}
	der := corpus(t, 1)[0]
	if err := d.Add(0, derive.Certs{}.Build(extract.Parse(der), derive.Context{CertID: 1, SHA256: sha256.Sum256(der), Kind: derive.KindFinal})); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM duckdb_tables() WHERE table_name LIKE '%_stage'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d staging tables left after Close (%v)", n, err)
	}
	dir := filepath.Join(t.TempDir(), "b")
	_, files := stageDerived(t, s, dir, nil, 4)
	if fi := files[derive.CertsV1.File()]; fi.Rows != 0 {
		t.Fatalf("the next stage starts with %d rows", fi.Rows)
	}
}

// TestDerivedViewsOverStagedFiles: once a batch holds derived files, the
// views read them with the same columns as the empty views, and the joins
// on certs work.
func TestDerivedViewsOverStagedFiles(t *testing.T) {
	root := t.TempDir()
	if _, err := WriteViews(root, derive.Complete()); err != nil {
		t.Fatal(err)
	}
	empty := stager(t)
	loadViews(t, empty, root)

	s := singleThreaded(t)
	dir := filepath.Join(root, "dataset", "log=argon2027h1", "batch=000000001000-000000001039")
	es, cs := rows(40)
	if _, err := s.Stage(ctx, dir, es, cs); err != nil {
		t.Fatal(err)
	}
	stageDerived(t, s, dir, corpus(t, 40), 8)
	os.WriteFile(filepath.Join(dir, "_COMMIT.json"), []byte(`{"format":1,"commit_seq":1}`), 0o644)
	if _, err := WriteViews(root, derive.Complete()); err != nil {
		t.Fatal(err)
	}
	full := stager(t)
	loadViews(t, full, root)
	for _, v := range []string{"certs", "names", "entry_certs", "logging_delay"} {
		if got, want := describe(t, full, v), describe(t, empty, v); got != want {
			t.Errorf("%s over files: %s\nempty: %s", v, got, want)
		}
	}
	var certs, joined int
	full.db.QueryRow(`SELECT (SELECT count(*) FROM certs), (SELECT count(*) FROM entry_certs)`).Scan(&certs, &joined)
	if certs != 40 || joined != 30 {
		t.Errorf("certs %d rows, entry_certs %d rows (want 40, 30)", certs, joined)
	}
}

// TestStageDerivedEmpty: a batch that vaults no new certificate still writes
// both files, with their schema and no rows, and they pass the canary.
func TestStageDerivedEmpty(t *testing.T) {
	s := singleThreaded(t)
	dir := filepath.Join(t.TempDir(), "b")
	d, files := stageDerived(t, s, dir, nil, 16)
	for _, tb := range tables() {
		if fi := files[tb.File()]; fi.Rows != 0 || fi.Bytes == 0 {
			t.Fatalf("%s: %+v for no rows", tb.File(), fi)
		}
	}
	if err := d.Canary(ctx, dir); err != nil {
		t.Fatal(err)
	}
}

// TestStageDerivedOddNames: a name holding invalid UTF-8, a NUL, a quote and
// a backslash reaches the files as the extractor renders it (valid UTF-8,
// with \XX escapes) and reads back unchanged, so no certificate can make a
// batch fail to stage.
func TestStageDerivedOddNames(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cn := asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte("a\xff\x00b'\\c")}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), NotBefore: time.Unix(1.7e9, 0), NotAfter: time.Unix(1.8e9, 0),
		Subject: pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: cn}}}}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	s := singleThreaded(t)
	dir := filepath.Join(t.TempDir(), "b")
	d, _ := stageDerived(t, s, dir, [][]byte{der}, 16)
	if err := d.Canary(ctx, dir); err != nil {
		t.Fatal(err)
	}
	certRow, nameRow := d.tables[0].sample[0], d.tables[1].sample[0]
	subject, ok := certRow[23].(string) // subject_cn
	if !ok || !utf8.ValidString(subject) || strings.ContainsRune(subject, 0) {
		t.Fatalf("subject_cn %q is not valid UTF-8 without NUL", subject)
	}
	var gotCN, gotDN, gotName string
	if err := s.db.QueryRow(`SELECT subject_cn, issuer_dn FROM read_parquet(`+quote(filepath.Join(dir, derive.CertsV1.File()))+`)`).Scan(&gotCN, &gotDN); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT name FROM read_parquet(` + quote(filepath.Join(dir, derive.NamesV1.File())) + `)`).Scan(&gotName); err != nil {
		t.Fatal(err)
	}
	if gotCN != subject || gotDN != certRow[11] || gotName != nameRow[2] {
		t.Fatalf("read back subject_cn %q, issuer_dn %q, name %q; staged %q, %q, %q", gotCN, gotDN, gotName, subject, certRow[11], nameRow[2])
	}
	t.Logf("subject_cn %q, issuer_dn %q, parse_errors %v", subject, gotDN, certRow[9])
}

// TestDerivedStageHoldsNoRows: adding a batch's rows does not keep them in
// Go memory, only the canary's sample: at the default batch size (500,000
// entries) collected rows would take gigabytes. Collecting them measured
// about 1,700 bytes of live heap per certificate; streaming keeps well
// under 200.
func TestDerivedStageHoldsNoRows(t *testing.T) {
	ders := corpus(t, 3000)
	s := singleThreaded(t)
	d, err := s.BeginDerived(ctx, tables(), 64, rand.New(rand.NewPCG(1, 2)))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	const n = 20000
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := range n {
		der := ders[i%len(ders)]
		cx := derive.Context{CertID: uint64(i + 1), SHA256: sha256.Sum256(der), Kind: derive.KindFinal}
		c := extract.Parse(der)
		for j, bl := range derive.Builders {
			if err := d.Add(j, bl.Build(c, cx)); err != nil {
				t.Fatal(err)
			}
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if per := (int64(after.HeapAlloc) - int64(before.HeapAlloc)) / n; per > 200 {
		t.Fatalf("adding rows keeps %d bytes of Go heap per certificate", per)
	}
}
