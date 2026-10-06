package query_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/diskguard"
	. "github.com/4rji/ctvault/internal/query"
)

// TestPagesEqualTheFullResult: concatenated keyset pages equal the full
// result, for every group, for both directions and for a sort with NULLs
// (amendment A4 §2.2).
func TestPagesEqualTheFullResult(t *testing.T) {
	g, es := entriesWithSigner(t, 60)
	v := newTestVault(t, g, es, 20)
	s, _ := Open(v.root, 0)
	sess, err := NewSession(v.root, diskguard.Guard{Cap: 0.85, Stat: freeDisk})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	for _, q := range []Query{
		{Mode: ModeDomain, Text: "example.test"},
		{Mode: ModeDomain, Text: "example.test", Sort: "name asc"},
		{Mode: ModeDomain, Text: "example.test", Sort: "certs desc"},
		{Mode: ModeDomain, Text: "example.test", Group: "certs"},
		{Mode: ModeDomain, Text: "example.test", Group: "certs", Sort: "first_seen asc"},
		{Mode: ModeDomain, Text: "example.test", Group: "certs", Kinds: []string{"precert", "final", "chain"}, Sort: "kind desc"},
		{Mode: ModeDomain, Text: "example.test", Group: "issuances", Sort: "last_seen desc"},
		{Mode: ModeDomain, Text: "example.test", Group: "names", Filter: "HOST1"},
	} {
		full, err := Search(ctx, s, sess, v.dirs, q)
		if err != nil {
			t.Fatal(err)
		}
		var paged [][]any
		var after *Cursor
		for pages := 0; ; pages++ {
			p, err := SearchPage(ctx, s, sess, v.dirs, q, after, 7)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(p.Columns, full.Columns) {
				t.Fatalf("page columns %v, full %v", p.Columns, full.Columns)
			}
			if !reflect.DeepEqual(p.Query, full.Query) {
				t.Fatalf("a page's query %+v, the full search's %+v", p.Query, full.Query)
			}
			paged = append(paged, p.Rows...)
			if p.Next == nil {
				break
			}
			if pages > 100 {
				t.Fatal("pagination does not end")
			}
			after = p.Next
		}
		if fmt.Sprint(paged) != fmt.Sprint(full.Rows) {
			t.Fatalf("%+v: pages give %d rows, the full search %d", q, len(paged), len(full.Rows))
		}
	}
}

// TestResultFilter: / keeps the rows whose displayed columns contain the
// text, any case, across every page (amendment A4 §3).
func TestResultFilter(t *testing.T) {
	g, es := entriesWithSigner(t, 60)
	v := newTestVault(t, g, es, 20)
	r := search(t, v, Query{Mode: ModeDomain, Text: "example.test", Filter: "WWW.HOST2"})
	for _, row := range r.Rows {
		if !strings.HasPrefix(row[r.Index("name")].(string), "www.host2") {
			t.Fatalf("filtered rows: %v", column(r, "name"))
		}
	}
	if len(r.Rows) != 11 { // www.host2 and www.host20-29
		t.Fatalf("%d rows: %v", len(r.Rows), column(r, "name"))
	}
}
