//go:build realdata

package tui

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	_ "github.com/duckdb/duckdb-go/v2" // the "duckdb" database/sql driver

	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/query"
	"github.com/4rji/ctvault/internal/querytest"
	"github.com/4rji/ctvault/internal/sampletest"
)

// TestExploreOnRealData is A4 §4's scripted session on the canonical
// sample: for the most common domain and a rare one, every group's pages
// in explore are search's rows; a certificate's detail opens; the / filter
// and a sort agree with search.
func TestExploreOnRealData(t *testing.T) {
	s := sampletest.Canonical(t, "argon2027h1")
	start0 := time.Now()
	v := querytest.FromSample(t, s, s.Manifest.Count, 10000)
	t.Logf("ingested %d entries in %v", s.Manifest.Count, time.Since(start0).Round(time.Second))

	common, rare := domains(t, v)
	t.Logf("common domain %s, rare domain %s", common, rare)
	h := start(t, v, setup{})
	for _, c := range []struct {
		domain, group string
	}{{common, "names"}, {rare, "names"}, {rare, "certs"}, {rare, "issuances"}} {
		h.toBar()
		h.group(c.group)
		began := time.Now()
		h.query(c.domain)
		first := time.Since(began)
		h.all()
		got := h.rows()
		want := h.search(query.Query{Mode: query.ModeDomain, Text: c.domain, Group: c.group})
		sameRows(t, c.domain+" "+c.group, got, want)
		t.Logf("%s %s: %d rows; first page %v; every page %v", c.domain, c.group, len(got), first.Round(time.Millisecond), time.Since(began).Round(time.Millisecond))
	}

	// The rare domain's certificates: the first one's detail.
	h.toBar()
	h.group("certs")
	h.query(rare)
	h.key("enter")
	st := h.loaded()
	sha := fmt.Sprint(st.data[0][0])
	if !st.cert || !strings.Contains(st.screen, sha) || !strings.Contains(st.screen, "entries (") {
		t.Fatalf("the detail of %s:\n%s", sha, st.screen)
	}

	// The filter and a sort, on the common domain's names.
	h.toBar()
	h.group("names")
	h.query(common)
	began := time.Now()
	h.key("s")
	h.loaded()
	sorted := time.Since(began)
	h.key("/")
	h.typ("api")
	began = time.Now()
	h.key("enter")
	h.loaded()
	filtered := time.Since(began)
	h.all()
	sameRows(t, "filtered and sorted", h.rows(), h.search(query.Query{Mode: query.ModeDomain, Text: common, Sort: "name desc", Filter: "api"}))
	t.Logf("%s names: a sort %v, the filter %v (both from the held rows)", common, sorted.Round(time.Millisecond), filtered.Round(time.Millisecond))

	// The query package alone, without the UI: the held rows' pages, and
	// keyset pages that re-run the query.
	snap, err := query.Open(v.Root, 0)
	if err != nil {
		t.Fatal(err)
	}
	q := query.Query{Mode: query.ModeDomain, Text: common}
	began = time.Now()
	res, err := query.Hold(ctx, snap, h.sess, v.Dirs, q)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()
	held := time.Since(began)
	began, pages := time.Now(), 0
	for from := 0; from < res.Len(); from += pageSize {
		if _, err := res.Page(ctx, from, pageSize); err != nil {
			t.Fatal(err)
		}
		pages++
	}
	heldPages := time.Since(began)
	began = time.Now()
	var after *query.Cursor
	for i := 0; i < 5; i++ {
		p, err := query.SearchPage(ctx, snap, h.sess, v.Dirs, q, after, pageSize)
		if err != nil {
			t.Fatal(err)
		}
		after = p.Next
	}
	t.Logf("query alone: hold %v; %d held pages %v (%v each); a keyset page %v", held.Round(time.Millisecond), pages, heldPages.Round(time.Millisecond),
		(heldPages / time.Duration(pages)).Round(10*time.Microsecond), (time.Since(began) / 5).Round(time.Millisecond))
}

// domains picks the eTLD+1 with the most names and one with 5 to 20.
func domains(t *testing.T, v *querytest.Vault) (common, rare string) {
	t.Helper()
	snap, err := query.Open(v.Root, 0)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	files := "['" + strings.Join(snap.Files(derive.NamesV1.File()), "', '") + "']"
	if err := db.QueryRow(`SELECT etld1 FROM read_parquet(` + files + `) WHERE etld1 IS NOT NULL GROUP BY etld1 ORDER BY count(*) DESC, etld1 LIMIT 1`).Scan(&common); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT etld1 FROM read_parquet(` + files + `) WHERE etld1 IS NOT NULL GROUP BY etld1 HAVING count(*) BETWEEN 5 AND 20 ORDER BY etld1 LIMIT 1`).Scan(&rare); err != nil {
		t.Fatal(err)
	}
	return common, rare
}
