package dataset

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"

	"github.com/4rji/ctvault/internal/derive"
)

func describe(t *testing.T, s *Stager, view string) string {
	t.Helper()
	rows, err := s.db.Query(`SELECT column_name, column_type FROM (DESCRIBE ` + view + `)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n, ty string
		rows.Scan(&n, &ty)
		out = append(out, n+" "+ty)
	}
	return fmt.Sprint(out)
}

func loadViews(t *testing.T, s *Stager, root string) {
	t.Helper()
	v, err := os.ReadFile(filepath.Join(root, ViewsFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(string(v)); err != nil {
		t.Fatalf("views.sql does not load: %v", err)
	}
}

// TestViewsWorkBeforeTheFirstBatch: a new vault's views.sql loads and
// shows empty tables with the committed columns; after the first batch
// commits it changes and shows the batch.
func TestViewsWorkBeforeTheFirstBatch(t *testing.T) {
	root := t.TempDir()
	if changed, err := WriteViews(root, derive.Complete()); err != nil || !changed {
		t.Fatalf("first write: %v %v", changed, err)
	}
	empty := stager(t)
	loadViews(t, empty, root)
	for _, v := range []string{"entries", "chains", "batches", "certs", "names", "entry_certs", "logging_delay"} {
		var n int
		if err := empty.db.QueryRow(`SELECT count(*) FROM ` + v).Scan(&n); err != nil || n != 0 {
			t.Fatalf("an empty vault: %s has %d rows (%v)", v, n, err)
		}
	}

	s := stager(t)
	dir := filepath.Join(root, "dataset", "log=argon2027h1", "batch=000000000000-000000000039")
	es, cs := rows(40)
	if _, err := s.Stage(ctx, dir, es, cs); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "_COMMIT.json"), []byte(`{"format":1,"commit_seq":1}`), 0o644)
	if changed, err := WriteViews(root, derive.Complete()); err != nil || !changed {
		t.Fatalf("the first commit changes views.sql: %v %v", changed, err)
	}
	full := stager(t)
	loadViews(t, full, root)
	var n int
	full.db.QueryRow(`SELECT count(*) FROM entries`).Scan(&n)
	if n != 40 {
		t.Fatalf("after the first commit: %d entries", n)
	}
	for _, v := range []string{"entries", "chains"} {
		if got, want := describe(t, empty, v), describe(t, full, v); got != want {
			t.Fatalf("%s before the first batch has columns %s\nafter: %s", v, got, want)
		}
	}
}

// TestEmptyDerivedViewsHaveTheSchema: before any batch holds a derived file,
// its view is empty but already has the table's exact columns, plus the
// hive partition columns.
func TestEmptyDerivedViewsHaveTheSchema(t *testing.T) {
	root := t.TempDir()
	if _, err := WriteViews(root, derive.Complete()); err != nil {
		t.Fatal(err)
	}
	s := stager(t)
	loadViews(t, s, root)
	for _, b := range derive.Builders {
		tb := b.Table()
		var want []string
		for _, c := range tb.Columns {
			want = append(want, c.Name+" "+c.Type)
		}
		want = append(want, "batch VARCHAR", "log VARCHAR")
		if got := describe(t, s, tb.Name); got != fmt.Sprint(want) {
			t.Errorf("%s: %s\nwant %v", tb.Name, got, want)
		}
	}
}

// TestDerivedViewsFollowActive: a table that is still being built is only
// exposed as <table>_building, never as the complete table (amendment A2
// §4.7), and the joins on it do not exist yet.
func TestDerivedViewsFollowActive(t *testing.T) {
	root := t.TempDir()
	exists := func(view string) bool {
		s := stager(t)
		loadViews(t, s, root)
		var n int
		return s.db.QueryRow(`SELECT count(*) FROM `+view).Scan(&n) == nil
	}
	if _, err := WriteViews(root, derive.Upgrading()); err != nil {
		t.Fatal(err)
	}
	for view, want := range map[string]bool{"certs_building": true, "names_building": true, "certs": false, "names": false, "entry_certs": false, "logging_delay": false} {
		if exists(view) != want {
			t.Errorf("building: view %s exists = %v", view, !want)
		}
	}
	if changed, err := WriteViews(root, derive.Complete()); err != nil || !changed {
		t.Fatalf("switching to complete must rewrite views.sql: %v %v", changed, err)
	}
	for view, want := range map[string]bool{"certs_building": false, "certs": true, "names": true, "entry_certs": true, "logging_delay": true} {
		if exists(view) != want {
			t.Errorf("complete: view %s exists = %v", view, !want)
		}
	}
}

// TestCanaryChecksCertIDRanges: spec §8.3 P6(e), cert_id range lookups
// through the reader's predicate.
func TestCanaryChecksCertIDRanges(t *testing.T) {
	s := stager(t)
	dir := filepath.Join(t.TempDir(), "b")
	es, cs := rows(40)
	if _, err := s.Stage(ctx, dir, es, cs); err != nil {
		t.Fatal(err)
	}
	if err := s.Canary(ctx, dir, es, cs, 8, rand.New(rand.NewPCG(5, 6))); err != nil {
		t.Fatal(err)
	}
	bad := append([]EntryRow(nil), es...)
	bad[4].CertID = 0 // the file holds a cert_id the batch does not
	if err := s.Canary(ctx, dir, bad, cs, 0, rand.New(rand.NewPCG(5, 6))); !errors.Is(err, ErrCanary) {
		t.Fatalf("a cert_id range that reads back a different count: %v", err)
	}
}
