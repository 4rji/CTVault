package query_test

import (
	"errors"
	. "github.com/4rji/ctvault/internal/query"
	"os"
	"path/filepath"
	"testing"

	"github.com/4rji/ctvault/internal/derive"
)

// TestSnapshot: a snapshot lists, per table, the files the committed
// batches' manifests list; --as-of keeps the batches up to a commit_seq;
// files nothing lists are never read (amendment A3 §2.1).
func TestSnapshot(t *testing.T) {
	g, es := entriesWithSigner(t, 60)
	v := newTestVault(t, g, es, 20)
	s, err := Open(v.root, 0)
	if err != nil {
		t.Fatal(err)
	}
	if s.AsOf != 3 || len(s.Batches) != 3 || len(s.Files("certs.p1.parquet")) != 3 || len(s.Files("entries.parquet")) != 3 {
		t.Fatalf("snapshot: as-of %d, %d batches, %v", s.AsOf, len(s.Batches), s.Files("certs.p1.parquet"))
	}
	old, err := Open(v.root, 2)
	if err != nil || old.AsOf != 2 || len(old.Batches) != 2 || len(old.Files("names.p1.parquet")) != 2 {
		t.Fatalf("--as-of 2: %+v %v", old, err)
	}
	// A file placed in a batch directory but listed by no manifest is not
	// in the snapshot.
	stray := filepath.Join(filepath.Dir(s.Files("certs.p1.parquet")[0]), "certs.p2.parquet")
	os.WriteFile(stray, []byte("x"), 0o644)
	if s2, _ := Open(v.root, 0); len(s2.Files("certs.p2.parquet")) != 0 {
		t.Fatal("an unlisted file entered the snapshot")
	}
	if err := s.Ready(derive.CertsV1); err != nil {
		t.Fatal(err)
	}
	if err := derive.WriteActive(v.root, derive.Upgrading()); err != nil {
		t.Fatal(err)
	}
	s3, _ := Open(v.root, 0)
	if err := s3.Ready(derive.CertsV1); !errors.Is(err, ErrBuilding) {
		t.Fatalf("certs being built: %v", err)
	}
}
