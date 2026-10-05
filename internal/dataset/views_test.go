package dataset

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
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
	if changed, err := WriteViews(root); err != nil || !changed {
		t.Fatalf("first write: %v %v", changed, err)
	}
	empty := stager(t)
	loadViews(t, empty, root)
	var n, c, b int
	empty.db.QueryRow(`SELECT (SELECT count(*) FROM entries), (SELECT count(*) FROM chains), (SELECT count(*) FROM batches)`).Scan(&n, &c, &b)
	if n != 0 || c != 0 || b != 0 {
		t.Fatalf("an empty vault: %d entries, %d chain rows, %d batches", n, c, b)
	}

	s := stager(t)
	dir := filepath.Join(root, "dataset", "log=argon2027h1", "batch=000000000000-000000000039")
	es, cs := rows(40)
	if _, err := s.Stage(ctx, dir, es, cs); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "_COMMIT.json"), []byte(`{"format":1,"commit_seq":1}`), 0o644)
	if changed, err := WriteViews(root); err != nil || !changed {
		t.Fatalf("the first commit changes views.sql: %v %v", changed, err)
	}
	full := stager(t)
	loadViews(t, full, root)
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
