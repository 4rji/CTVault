//go:build realdata

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/health"
	"github.com/4rji/ctvault/internal/query"
	"github.com/4rji/ctvault/internal/sampletest"
)

// TestReadPathOnRealData ingests the canonical sample and checks the read
// path against it (amendment A3 §8): the post-commit audit passed every
// batch; 1,000 sampled certificates fetch byte-exact by SHA-256 and by
// cert_id; search results equal independent DuckDB queries over views.sql.
// It logs fetch and search latencies on 10 batches (M2 and M3 at small
// scale; §7.1 extrapolates them).
func TestReadPathOnRealData(t *testing.T) {
	ctx := context.Background()
	s := sampletest.Canonical(t, realLog)
	n := s.Manifest.Count
	r := newRealVault(t, s, 0)
	w := r.open()
	r.ingest(w, n, 10000)
	w.Close()
	root := r.v.Root
	if h, ok, err := health.Read(filepath.Join(root, "state")); err != nil || !ok || h.Passes != int(n/10000) || h.FailedAudits != 0 {
		t.Fatalf("post-commit audits: %+v %v %v", h, ok, err)
	}

	snap, err := query.Open(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := query.NewSession(root, diskguard.Guard{Cap: 0.85, Stat: diskguard.Statfs})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	f, err := query.NewFetcher(snap, sess, r.v.Dirs)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	want := decodeSample(t, s, n)
	rnd := mrand.New(mrand.NewPCG(3, 4))
	var bySHA, byID []time.Duration
	for checked := 0; checked < 1000; {
		der, ok := want.certs[rnd.Uint64N(n)]
		if !ok {
			continue
		}
		checked++
		t0 := time.Now()
		c, err := f.BySHA256(ctx, sha256.Sum256(der))
		bySHA = append(bySHA, time.Since(t0))
		if err != nil || !bytes.Equal(c.DER, der) {
			t.Fatalf("fetch by SHA-256: %v", err)
		}
		t0 = time.Now()
		c2, err := f.ByCertID(ctx, c.CertID)
		byID = append(byID, time.Since(t0))
		if err != nil || !bytes.Equal(c2.DER, der) {
			t.Fatalf("fetch by cert_id %d: %v", c.CertID, err)
		}
	}

	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	views, _ := os.ReadFile(filepath.Join(root, dataset.ViewsFile))
	if _, err := db.Exec(string(views)); err != nil {
		t.Fatal(err)
	}
	pick := func(order string) (string, int) {
		var e string
		var k int
		q := `SELECT etld1, count(DISTINCT name) FROM names JOIN certs USING (cert_id) WHERE etld1 IS NOT NULL AND kind IN ('precert', 'final')
		      GROUP BY 1 ORDER BY 2 ` + order + `, 1 LIMIT 1`
		if err := db.QueryRow(q).Scan(&e, &k); err != nil {
			t.Fatal(err)
		}
		return e, k
	}
	common, commonNames := pick("DESC")
	rare, rareNames := pick("ASC")
	timed := func(q query.Query) (*query.Result, time.Duration) {
		t0 := time.Now()
		res, err := query.Search(ctx, snap, sess, r.v.Dirs, q)
		if err != nil {
			t.Fatalf("%+v: %v", q, err)
		}
		return res, time.Since(t0)
	}
	res, tCommon := timed(query.Query{Mode: query.ModeDomain, Text: common})
	if len(res.Rows) != commonNames {
		t.Fatalf("search %s: %d names, DuckDB over views.sql says %d", common, len(res.Rows), commonNames)
	}
	var certs int
	db.QueryRow(`SELECT count(DISTINCT cert_id) FROM names JOIN certs USING (cert_id) WHERE etld1 = ? AND kind IN ('precert', 'final')`, common).Scan(&certs)
	if res, _ := timed(query.Query{Mode: query.ModeDomain, Text: common, Group: "certs"}); len(res.Rows) != certs {
		t.Fatalf("search %s --group certs: %d, DuckDB says %d", common, len(res.Rows), certs)
	}
	res, tRare := timed(query.Query{Mode: query.ModeDomain, Text: rare})
	if len(res.Rows) != rareNames {
		t.Fatalf("search %s: %d names, want %d", rare, len(res.Rows), rareNames)
	}
	name := res.Rows[0][res.Index("name")].(string)
	if res, _ := timed(query.Query{Mode: query.ModeExact, Text: name}); len(res.Rows) != 1 {
		t.Fatalf("--exact %s: %d rows", name, len(res.Rows))
	}
	_, tSuffix := timed(query.Query{Mode: query.ModeSuffix, Text: common})
	p := func(d []time.Duration, q float64) time.Duration {
		s := slices.Clone(d)
		slices.Sort(s)
		return s[int(q*float64(len(s)-1))]
	}
	t.Logf("10 batches: fetch by SHA-256 p50 %v p95 %v; by cert_id p50 %v p95 %v; search %s (%d names) %v, rare %s %v, --suffix %v",
		p(bySHA, 0.5), p(bySHA, 0.95), p(byID, 0.5), p(byID, 0.95), common, commonNames, tCommon.Round(time.Millisecond), rare,
		tRare.Round(time.Millisecond), tSuffix.Round(time.Millisecond))
}
