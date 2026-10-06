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
	h.key("s")
	h.key("/")
	h.typ("api")
	h.key("enter")
	h.all()
	sameRows(t, "filtered and sorted", h.rows(), h.search(query.Query{Mode: query.ModeDomain, Text: common, Sort: "name desc", Filter: "api"}))
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
