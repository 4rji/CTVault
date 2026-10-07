//go:build realdata

package integration

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/sampletest"
)

// realTiledLog is the tiled log whose canonical sample the real-data layer
// replays (amendment A6 §7.6). Capture it with:
//
//	ctvault-dev sample capture --log parcelyard2027h1
const realTiledLog = "parcelyard2027h1"

// TestTiledCanonicalOnRealData ingests the canonical tiled sample through
// the tiled source, from the mirrored files alone, in batches that end inside
// tiles: every batch is verified with a proof built from the sample's hash
// tiles, the vault holds what the entries decode to, and every precert
// cross-check passes with the issuers the log served.
func TestTiledCanonicalOnRealData(t *testing.T) {
	s := sampletest.Canonical(t, realTiledLog)
	if !s.Tiled() {
		t.Fatalf("%s is not a tiled sample", s.Dir)
	}
	n := s.Manifest.Count
	r := newRealVault(t, s, 0)
	w := r.open()
	start := time.Now()
	r.ingest(w, n, 10000)
	t.Logf("ingested %d tiled entries in %v", n, time.Since(start).Round(time.Second))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r.v.CheckRecovered(t)
	ms, err := commit.ListCommitted(r.v.Root)
	if err != nil || len(ms) != int((n+9999)/10000) {
		t.Fatalf("%d batches, %v", len(ms), err)
	}
	var leafErrors int
	for _, m := range ms {
		if m.Verified.Method != "consistency_proof" || len(m.Verified.Proof) == 0 {
			t.Fatalf("batch %s verified by %q", m.BatchID, m.Verified.Method)
		}
		leafErrors += m.Counts.LeafErrors
	}
	if leafErrors != 0 {
		t.Fatalf("%d leaf errors on real tiled data (PROBE.md and the sample's measurement found none)", leafErrors)
	}

	want := decodeSample(t, s, n)
	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	views, err := os.ReadFile(filepath.Join(r.v.Root, dataset.ViewsFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(views)); err != nil {
		t.Fatalf("loading views.sql: %v", err)
	}
	if got := queryInt(t, db, `SELECT count(DISTINCT idx) FROM entries`); got != int64(n) {
		t.Fatalf("entries: %d distinct indexes, want %d", got, n)
	}
	for typ, k := range want.types {
		if got := queryInt(t, db, `SELECT count(*) FROM entries WHERE entry_type = ?`, typ); got != int64(k) {
			t.Fatalf("entry_type %s: %d rows, the sample has %d", typ, got, k)
		}
	}
	if a, b := queryInt(t, db, `SELECT count(*) FROM entries WHERE chain_id IS NOT NULL`),
		queryInt(t, db, `SELECT count(*) FROM entries e JOIN (SELECT DISTINCT chain_id FROM chains WHERE position = 0) c USING (chain_id)`); a != int64(n) || b != a {
		t.Fatalf("%d entries have a chain, %d resolve to one; want all %d", a, b, n)
	}
	if got := queryInt(t, db, `SELECT count(*) FROM entries WHERE cert_id IS NULL`); got != 0 {
		t.Fatalf("%d entries without a certificate", got)
	}
	if got := queryInt(t, db, `SELECT count(*) FROM entries WHERE leaf_error = ?`, string(leaf.LeafIndexMismatch)); got != 0 {
		t.Fatalf("%d entries with leaf_index_mismatch", got)
	}
}
