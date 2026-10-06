package query_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	. "github.com/4rji/ctvault/internal/query"
	"strings"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/diskguard"
)

// searchVault is 30 issuances (60 entries) in three batches; every third
// precert is issued by the Precertificate Signing Certificate.
func searchVault(t *testing.T) *testVault {
	t.Helper()
	g, es := entriesWithSigner(t, 60)
	return newTestVault(t, g, es, 20)
}

func search(t *testing.T, v *testVault, q Query) *Result {
	t.Helper()
	s, err := Open(v.root, q.AsOf)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := NewSession(v.root, diskguard.Guard{Cap: 0.85, Stat: freeDisk})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	r, err := Search(ctx, s, sess, v.dirs, q)
	if err != nil {
		t.Fatalf("%+v: %v", q, err)
	}
	return r
}

func column(r *Result, name string) []any {
	i := r.Index(name)
	var out []any
	for _, row := range r.Rows {
		out = append(out, row[i])
	}
	return out
}

// TestSearchModes: each mode's predicate, with its boundaries (amendment A3
// §3.1).
func TestSearchModes(t *testing.T) {
	v := searchVault(t)
	for _, c := range []struct {
		q     Query
		names int
	}{
		{Query{Mode: ModeDomain, Text: "example.test"}, 60},
		{Query{Mode: ModeDomain, Text: "EXAMPLE.test."}, 60},
		{Query{Mode: ModeExact, Text: "host1.example.test"}, 1},
		{Query{Mode: ModeSuffix, Text: "host1.example.test"}, 2}, // host1 and www.host1, never host11
		{Query{Mode: ModeContains, Text: "HOST2"}, 22},           // host2, host20-29 and their www.
		{Query{Mode: ModeRegex, Text: `^host1[0-9]\.`}, 10},
		{Query{Mode: ModeDomain, Text: "other.test"}, 0},
	} {
		r := search(t, v, c.q)
		if len(r.Rows) != c.names {
			t.Errorf("%s %q: %d names, want %d: %v", c.q.Mode, c.q.Text, len(r.Rows), c.names, column(r, "name"))
		}
	}
	r := search(t, v, Query{Mode: ModeExact, Text: "host1.example.test"})
	if certs := column(r, "certs")[0]; certs != int64(2) {
		t.Fatalf("host1: %v certificates (a precert and its final)", certs)
	}
	if fs, ls := column(r, "first_seen")[0], column(r, "last_seen")[0]; fs == nil || ls == nil || !fs.(time.Time).Before(ls.(time.Time)) {
		t.Fatalf("first seen %v, last seen %v", fs, ls)
	}
}

// TestSearchUsage: a default-mode argument must be a registrable domain;
// invalid regular expressions and addresses are usage errors (amendment A3
// §3.1).
func TestSearchUsage(t *testing.T) {
	v := searchVault(t)
	s, _ := Open(v.root, 0)
	sess, _ := NewSession(v.root, diskguard.Guard{Cap: 0.85, Stat: freeDisk})
	defer sess.Close()
	for _, q := range []Query{
		{Mode: ModeDomain, Text: "host1.example.test"},
		{Mode: ModeDomain, Text: "test"},
		{Mode: ModeRegex, Text: "("},
		{Mode: ModeIP, Text: "300.1.1.1"},
		{Mode: ModeSuffix, Text: "bad name"},
		{Mode: ModeDomain, Text: "example.test", Group: "nope"},
		{Mode: ModeDomain, Text: "example.test", Sort: "nope desc"},
		{Mode: ModeDomain, Text: "example.test", Fields: []string{"nope"}},
	} {
		if _, err := Search(ctx, s, sess, v.dirs, q); !errors.Is(err, ErrUsage) {
			t.Errorf("%+v: %v, want a usage error", q, err)
		}
	}
	_, err := Search(ctx, s, sess, v.dirs, Query{Mode: ModeDomain, Text: "host1.example.test"})
	if err == nil || !strings.Contains(err.Error(), "--suffix") {
		t.Fatalf("the error suggests --suffix or --exact: %v", err)
	}
}

// TestSearchFilters: certificate, name and entry filters; chain
// certificates only with --kind chain (amendment A3 §3.2).
func TestSearchFilters(t *testing.T) {
	v := searchVault(t)
	certs := func(q Query) int {
		q.Mode, q.Text, q.Group = ModeDomain, "example.test", "certs"
		return len(search(t, v, q).Rows)
	}
	t0 := time.UnixMilli(1790000000000).UTC()
	for _, c := range []struct {
		name string
		q    Query
		want int
	}{
		{"all", Query{}, 60},
		{"finals", Query{Kinds: []string{"final"}}, 30},
		{"issuer CN, any case", Query{Issuer: "ctvault test ca"}, 50},
		{"issuer O", Query{IssuerOrg: "CTVault Tests"}, 60},
		{"key algorithm", Query{KeyAlg: "ecdsa"}, 60},
		{"parse status", Query{ParseStatus: "ok"}, 60},
		{"log", Query{Log: "fakelog"}, 60},
		{"another log", Query{Log: "other"}, 0},
		{"since: issuances 15-29", Query{Since: &[]time.Time{t0.Add(30 * time.Second)}[0]}, 30},
		{"until: issuances 0-14", Query{Until: &[]time.Time{t0.Add(30 * time.Second)}[0]}, 30},
		{"valid at", Query{ValidAt: &[]time.Time{time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)}[0]}, 60},
		{"not valid yet", Query{ValidAt: &[]time.Time{time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)}[0]}, 0},
	} {
		if got := certs(c.q); got != c.want {
			t.Errorf("%s: %d certificates, want %d", c.name, got, c.want)
		}
	}
	if got := certs(Query{Kinds: []string{"chain"}}); got != 0 {
		t.Errorf("chain certificates hold no example.test name: %d", got)
	}
}

// TestSearchIssuedBy: --issued-by matches by relationship, with the DER as
// a cross-check (amendment A3 §3.2).
func TestSearchIssuedBy(t *testing.T) {
	v := searchVault(t)
	shaOf := func(der []byte) string {
		s := sha256.Sum256(der)
		return hex.EncodeToString(s[:])
	}
	for _, c := range []struct {
		name string
		by   string
		want int
	}{
		{"the CA: every final and the direct precerts", shaOf(v.gen.CADER()), 50},
		{"the precert signer: every third precert", shaOf(v.gen.SignerDER()), 10},
	} {
		r := search(t, v, Query{Mode: ModeDomain, Text: "example.test", Group: "certs", IssuedBy: c.by})
		if len(r.Rows) != c.want {
			t.Errorf("%s: %d certificates, want %d", c.name, len(r.Rows), c.want)
		}
	}
	s, _ := Open(v.root, 0)
	sess, _ := NewSession(v.root, diskguard.Guard{Cap: 0.85, Stat: freeDisk})
	defer sess.Close()
	leaf := shaOf(v.es[1].CertDER)
	if _, err := Search(ctx, s, sess, v.dirs, Query{Mode: ModeDomain, Text: "example.test", IssuedBy: leaf}); !errors.Is(err, ErrUsage) {
		t.Fatalf("--issued-by a leaf: %v, want a usage error (not a CA seen in a chain)", err)
	}
}

// TestSearchGroups: certs and issuances groupings, --as-of, sort, limit and
// fields (amendment A3 §3.3).
func TestSearchGroups(t *testing.T) {
	v := searchVault(t)
	r := search(t, v, Query{Mode: ModeDomain, Text: "example.test", Group: "issuances"})
	if len(r.Rows) != 30 {
		t.Fatalf("%d issuances, want 30", len(r.Rows))
	}
	for _, row := range r.Rows {
		if row[r.Index("certs")] != int64(2) || row[r.Index("precert")] != true || row[r.Index("final")] != true {
			t.Fatalf("an issuance merges its precert and final: %v", row)
		}
	}
	if r := search(t, v, Query{Mode: ModeDomain, Text: "example.test", AsOf: 1}); len(r.Rows) != 20 || r.AsOf != 1 {
		t.Fatalf("--as-of 1: %d names, as-of %d", len(r.Rows), r.AsOf)
	}
	r = search(t, v, Query{Mode: ModeDomain, Text: "example.test", Sort: "name asc", Limit: 3, Fields: []string{"name", "certs"}})
	if got := column(r, "name"); len(r.Columns) != 2 || len(got) != 3 || got[0] != "host0.example.test" || got[1] != "host1.example.test" || got[2] != "host10.example.test" {
		t.Fatalf("sorted by name, 3 rows, 2 fields: %v %v", r.Columns, got)
	}
	a := search(t, v, Query{Mode: ModeDomain, Text: "example.test", Group: "certs"})
	b := search(t, v, Query{Mode: ModeDomain, Text: "example.test", Group: "certs"})
	for i := range a.Rows {
		if a.Rows[i][a.Index("sha256")] != b.Rows[i][b.Index("sha256")] {
			t.Fatal("the same query gives rows in a different order")
		}
	}
}

// TestSearchSeesLaterEntries: a certificate logged again in a later batch
// shows that entry as last seen, though its certs row lives in the batch
// that first vaulted it.
func TestSearchSeesLaterEntries(t *testing.T) {
	g, es := entriesWithSigner(t, 60)
	final := es[1].CertDER
	again := ctlogtest.Entry{Type: ctlogtest.X509Entry, Timestamp: 1790000999000, CertDER: final}
	again.LeafInput = ctlogtest.MerkleTreeLeaf(again.Timestamp, ctlogtest.X509Entry, final, [32]byte{})
	again.ExtraData = ctlogtest.Chain(g.CADER())
	v := newTestVault(t, g, append(es, again), 20)
	r := search(t, v, Query{Mode: ModeExact, Text: "host0.example.test", Group: "certs", Kinds: []string{"final"}})
	if len(r.Rows) != 1 || !r.Rows[0][r.Index("last_seen")].(time.Time).Equal(time.UnixMilli(1790000999000)) {
		t.Fatalf("last seen: %v", r.Rows)
	}
}
