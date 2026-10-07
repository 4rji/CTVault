package query_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/diskguard"
	. "github.com/4rji/ctvault/internal/query"
)

// pagedQueries are TestPagesEqualTheFullResult's queries: every group, both
// directions, a sort with NULLs (chain certificates have no entries) and
// the / filter.
var pagedQueries = []Query{
	{Mode: ModeDomain, Text: "example.test"},
	{Mode: ModeDomain, Text: "example.test", Sort: "name asc"},
	{Mode: ModeDomain, Text: "example.test", Sort: "certs desc"},
	{Mode: ModeDomain, Text: "example.test", Group: "certs"},
	{Mode: ModeDomain, Text: "example.test", Group: "certs", Sort: "first_seen asc"},
	{Mode: ModeDomain, Text: "example.test", Group: "certs", Kinds: []string{"precert", "final", "chain"}, Sort: "kind desc"},
	{Mode: ModeDomain, Text: "example.test", Group: "issuances", Sort: "last_seen desc"},
	{Mode: ModeDomain, Text: "example.test", Group: "names", Filter: "HOST1"},
}

// heldVault is the paging tests' vault and a session over it.
func heldVault(t *testing.T) (*testVault, *Snapshot, *Session) {
	t.Helper()
	g, es := entriesWithSigner(t, 60)
	v := newTestVault(t, g, es, 20)
	s, err := Open(v.root, 0)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := NewSession(v.root, diskguard.Guard{Cap: 0.85, Stat: freeDisk})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close() })
	return v, s, sess
}

// allPages reads r in pages of n and checks each page's shape.
func allPages(t *testing.T, r *Results, n int) [][]any {
	t.Helper()
	var rows [][]any
	for from := 0; ; from += n {
		p, err := r.Page(ctx, from, n)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(p.Query, r.Query()) || !reflect.DeepEqual(p.Columns, columnsOf(r.Query())) {
			t.Fatalf("page %d: query %+v columns %v", from/n, p.Query, p.Columns)
		}
		rows = append(rows, p.Rows...)
		if p.Next == nil {
			if len(rows) != r.Len() {
				t.Fatalf("pages end after %d rows, Len is %d", len(rows), r.Len())
			}
			return rows
		}
		if len(p.Rows) != n || len(rows) >= r.Len() {
			t.Fatalf("page %d: %d rows, %d of %d read, and a next page", from/n, len(p.Rows), len(rows), r.Len())
		}
		if last := p.Rows[n-1]; Render(p.Next.Tie) != Render(last[colIndex(p.Columns, KeyColumn(r.Query().Group))]) {
			t.Fatalf("page %d ends at %v, its cursor says %v", from/n, last, p.Next.Tie)
		}
		if from > 1000 {
			t.Fatal("pages do not end")
		}
	}
}

func colIndex(cols []string, c string) int {
	for i, x := range cols {
		if x == c {
			return i
		}
	}
	return -1
}

// TestHeldPagesEqualTheFullResult: a query held once gives search's rows,
// page by page, for every group, direction and filter; reordering the held
// rows gives what searching with the new sort and filter gives (amendment
// A4 §2.2, as revised by Plan 5's summary).
func TestHeldPagesEqualTheFullResult(t *testing.T) {
	v, s, sess := heldVault(t)
	for _, q := range pagedQueries {
		full, err := Search(ctx, s, sess, v.dirs, q)
		if err != nil {
			t.Fatal(err)
		}
		r, err := Hold(ctx, s, sess, v.dirs, q)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(r.Query(), full.Query) || r.AsOf() != s.AsOf {
			t.Fatalf("held query %+v as of %d, search's %+v as of %d", r.Query(), r.AsOf(), full.Query, s.AsOf)
		}
		if got := allPages(t, r, 7); fmt.Sprint(got) != fmt.Sprint(full.Rows) {
			t.Fatalf("%+v: held pages give %d rows, search %d\n%v\n%v", q, len(got), len(full.Rows), got, full.Rows)
		}
		// Every other sort and filter of the same query, from the held rows.
		for _, o := range pagedQueries {
			if o.Group != q.Group || !reflect.DeepEqual(o.Kinds, q.Kinds) {
				continue
			}
			want, err := Search(ctx, s, sess, v.dirs, o)
			if err != nil {
				t.Fatal(err)
			}
			re, err := r.Reorder(ctx, want.Query.Sort, o.Filter)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(re.Query(), want.Query) {
				t.Fatalf("reordered query %+v, search's %+v", re.Query(), want.Query)
			}
			if got := allPages(t, re, 5); fmt.Sprint(got) != fmt.Sprint(want.Rows) {
				t.Fatalf("%+v reordered as %+v: %d rows, search %d", q, o, len(got), len(want.Rows))
			}
			re.Close()
		}
		r.Close()
	}
	if n, err := sess.Held(ctx); err != nil || n != 0 {
		t.Fatalf("%d held tables after every result closed (%v)", n, err)
	}
}

// TestHeldRowsReadNoVaultFile: once held, pages, reorders and exports read
// the held rows only: they work with the vault's data files gone.
func TestHeldRowsReadNoVaultFile(t *testing.T) {
	v, s, sess := heldVault(t)
	q := Query{Mode: ModeDomain, Text: "example.test", Group: "certs"}
	full, err := Search(ctx, s, sess, v.dirs, q)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	want := filepath.Join(dir, "want.json")
	now := func() time.Time { return time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC) }
	o := ExportOptions{Format: "json", Version: "test", Now: now, Path: want}
	if err := Export(ctx, s, sess, v.dirs, q, o); err != nil {
		t.Fatal(err)
	}
	r, err := Hold(ctx, s, sess, v.dirs, q)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	removed := 0
	filepath.WalkDir(v.root, func(p string, e fs.DirEntry, err error) error {
		if err == nil && strings.HasSuffix(p, ".parquet") && os.Remove(p) == nil {
			removed++
		}
		return nil
	})
	if removed == 0 {
		t.Fatal("no data file to remove")
	}
	if _, err := Search(ctx, s, sess, v.dirs, q); err == nil {
		t.Fatal("search still runs without the data files: the test proves nothing")
	}

	if got := allPages(t, r, 4); fmt.Sprint(got) != fmt.Sprint(full.Rows) {
		t.Fatalf("held pages: %d rows, search gave %d", len(got), len(full.Rows))
	}
	re, err := r.Reorder(ctx, "cert_id desc", "precert")
	if err != nil {
		t.Fatal(err)
	}
	defer re.Close()
	if re.Len() == 0 || re.Len() >= r.Len() {
		t.Fatalf("the filter keeps %d of %d rows", re.Len(), r.Len())
	}
	o.Path = filepath.Join(dir, "held.json")
	if err := r.Export(ctx, o); err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(want)
	b, _ := os.ReadFile(o.Path)
	if string(a) != string(b) || len(a) == 0 {
		t.Fatalf("the held export differs from search's:\n%s\n%s", a, b)
	}
}

// TestHeldExportSelection: an export of held rows keeps only the selection,
// as Export does, and records it.
func TestHeldExportSelection(t *testing.T) {
	v, s, sess := heldVault(t)
	q := Query{Mode: ModeDomain, Text: "example.test", Sort: "name asc"}
	r, err := Hold(ctx, s, sess, v.dirs, q)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	dir := t.TempDir()
	now := func() time.Time { return time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC) }
	sel := []string{hostName(3), hostName(1), "gone.example.test"}
	a := ExportOptions{Format: "csv", Version: "test", Now: now, Path: filepath.Join(dir, "a.csv"), Selection: sel}
	b := a
	b.Path = filepath.Join(dir, "b.csv")
	if err := Export(ctx, s, sess, v.dirs, q, a); err != nil {
		t.Fatal(err)
	}
	if err := r.Export(ctx, b); err != nil {
		t.Fatal(err)
	}
	for _, ext := range []string{"", ".meta.json"} {
		x, _ := os.ReadFile(a.Path + ext)
		y, _ := os.ReadFile(b.Path + ext)
		if string(x) != string(y) || len(x) == 0 {
			t.Fatalf("%s: search's export and the held one differ:\n%s\n%s", ext, x, y)
		}
	}
	if x, _ := os.ReadFile(b.Path); strings.Count(string(x), "\n") != 3 {
		t.Fatalf("a selection of 2 present rows:\n%s", x)
	}
}

// TestHeldResultsShareTheirRows: a reordered result keeps the held rows
// alive after the one it came from closes; the last Close drops them, and
// a closed result refuses pages.
func TestHeldResultsShareTheirRows(t *testing.T) {
	v, s, sess := heldVault(t)
	r, err := Hold(ctx, s, sess, v.dirs, Query{Mode: ModeDomain, Text: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	same, err := r.Reorder(ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := sess.Held(ctx); n != 1 {
		t.Fatalf("the default order shares the held table: %d tables", n)
	}
	re, err := r.Reorder(ctx, "name asc", "host2")
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := sess.Held(ctx); n != 2 {
		t.Fatalf("a new order is a second table: %d tables", n)
	}
	r.Close()
	r.Close() // twice is harmless
	if _, err := r.Page(ctx, 0, 5); err == nil {
		t.Fatal("a closed result gives pages")
	}
	if got := allPages(t, re, 3); len(got) != re.Len() || re.Len() == 0 {
		t.Fatalf("after the first result closed: %d rows", len(got))
	}
	again, err := same.Reorder(ctx, "certs asc", "")
	if err != nil {
		t.Fatal(err)
	}
	same.Close()
	re.Close()
	if n, _ := sess.Held(ctx); n != 2 {
		t.Fatalf("one open result over the held rows: %d tables, want the rows and its order", n)
	}
	again.Close()
	if n, _ := sess.Held(ctx); n != 0 {
		t.Fatalf("%d tables after every result closed", n)
	}
	if _, err := again.Reorder(ctx, "", ""); err == nil {
		t.Fatal("a closed result reorders")
	}
}

// TestHeldEdges: no matching row, a bad sort, a cancelled hold.
func TestHeldEdges(t *testing.T) {
	v, s, sess := heldVault(t)
	r, err := Hold(ctx, s, sess, v.dirs, Query{Mode: ModeDomain, Text: "nothing.test", Group: "certs"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := r.Page(ctx, 0, 10)
	if err != nil || r.Len() != 0 || len(p.Rows) != 0 || p.Next != nil || !reflect.DeepEqual(p.Columns, columnsOf(r.Query())) {
		t.Fatalf("no match: len %d, page %+v, %v", r.Len(), p, err)
	}
	if re, err := r.Reorder(ctx, "kind asc", "x"); err != nil || re.Len() != 0 {
		t.Fatalf("reordering nothing: %v", err)
	}
	r.Close()

	r, err = Hold(ctx, s, sess, v.dirs, Query{Mode: ModeDomain, Text: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := r.Reorder(ctx, "cert_id asc", ""); !errors.Is(err, ErrUsage) {
		t.Fatalf("a certs column on names: %v", err)
	}
	if _, err := Hold(ctx, s, sess, v.dirs, Query{Mode: ModeDomain, Text: "example.test", Sort: "bogus"}); !errors.Is(err, ErrUsage) {
		t.Fatalf("a bad sort: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := Hold(cancelled, s, sess, v.dirs, Query{Mode: ModeDomain, Text: "example.test", Group: "certs"}); err == nil {
		t.Fatal("a cancelled hold succeeds")
	}
	if n, _ := sess.Held(ctx); n != 1 {
		t.Fatalf("%d held tables: a failed hold leaves one behind", n)
	}
}

func columnsOf(q Query) []string { return q.Columns() }
