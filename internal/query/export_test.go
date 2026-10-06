package query_test

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	. "github.com/4rji/ctvault/internal/query"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/diskguard"
)

func runExport(t *testing.T, v *testVault, q Query, format, path string, force bool) error {
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
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	return Export(ctx, s, sess, v.dirs, q, ExportOptions{Path: path, Format: format, Force: force, Version: "test", Now: func() time.Time { return now }})
}

// TestExport: every format carries the metadata that reproduces it; the
// same query and snapshot give the same bytes; an existing file is never
// overwritten without --force (amendment A3 §5).
func TestExport(t *testing.T) {
	v := searchVault(t)
	dir := t.TempDir()
	q := Query{Mode: ModeDomain, Text: "example.test", Group: "certs", Issuer: "CTVault Test CA", AsOf: 2}

	j := filepath.Join(dir, "r.json")
	if err := runExport(t, v, q, "json", j, false); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Meta Meta             `json:"meta"`
		Rows []map[string]any `json:"rows"`
	}
	b, _ := os.ReadFile(j)
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	m := doc.Meta
	if m.AsOfCommitSeq != 2 || m.RowCount != len(doc.Rows) || m.RowCount == 0 || m.Query.Issuer != "CTVault Test CA" || m.Query.Group != "certs" ||
		len(m.Logs) != 1 || m.Logs[0].Log != "fakelog" || m.Logs[0].VerifiedTreeSize == 0 || m.Builders["certs"] != float64(1) || m.Approximate {
		t.Fatalf("meta %+v", m)
	}
	// The recorded query, re-run as of its commit, gives the same bytes.
	again := filepath.Join(dir, "again.json")
	q2 := m.Query
	q2.AsOf = m.AsOfCommitSeq
	if err := runExport(t, v, q2, "json", again, false); err != nil {
		t.Fatal(err)
	}
	if b2, _ := os.ReadFile(again); !bytes.Equal(b, b2) {
		t.Fatalf("re-running the recorded query changes the export:\n%s\n%s", b, b2)
	}

	c := filepath.Join(dir, "r.csv")
	if err := runExport(t, v, q, "csv", c, false); err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(c)
	recs, err := csv.NewReader(f).ReadAll()
	f.Close()
	if err != nil || len(recs) != m.RowCount+1 || recs[0][0] != "sha256" {
		t.Fatalf("csv: %d records, %v", len(recs), err)
	}
	var side Meta
	sb, err := os.ReadFile(c + ".meta.json")
	if err != nil || json.Unmarshal(sb, &side) != nil || side.RowCount != m.RowCount {
		t.Fatalf("csv sidecar: %s %v", sb, err)
	}

	md := filepath.Join(dir, "r.md")
	if err := runExport(t, v, q, "md", md, false); err != nil {
		t.Fatal(err)
	}
	mb, _ := os.ReadFile(md)
	if !strings.Contains(string(mb), `"as_of_commit_seq": 2`) || strings.Count(string(mb), "\n| ") != m.RowCount+1 {
		t.Fatalf("markdown:\n%s", mb)
	}

	if err := runExport(t, v, q, "json", j, false); !errors.Is(err, os.ErrExist) {
		t.Fatalf("an existing file without --force: %v", err)
	}
	if err := runExport(t, v, q, "json", j, true); err != nil {
		t.Fatalf("--force: %v", err)
	}
	left, _ := filepath.Glob(filepath.Join(dir, ".*"))
	if len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
}

// TestRender: values render the same way in every text format.
func TestRender(t *testing.T) {
	ts := time.Date(2026, 10, 1, 0, 0, 1, 500_000_000, time.UTC)
	for v, want := range map[any]string{nil: "", "x": "x", int64(3): "3", true: "true", ts: "2026-10-01T00:00:01.5Z"} {
		if got := Render(v); got != want {
			t.Errorf("Render(%v) = %q, want %q", v, got, want)
		}
	}
	if got := Render([]any{"a", "b"}); got != "a, b" {
		t.Errorf("a list renders as %q", got)
	}
}

// TestExportSelection: an export of marked rows holds only those rows, in
// the result's order, and records the selection by the group's key
// (amendment A4 §3); the / filter applies on top.
func TestExportSelection(t *testing.T) {
	v := searchVault(t)
	s, _ := Open(v.root, 0)
	sess, err := NewSession(v.root, diskguard.Guard{Cap: 0.85, Stat: freeDisk})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	q := Query{Mode: ModeDomain, Text: "example.test", Group: "certs"}
	all, err := Search(ctx, s, sess, v.dirs, q)
	if err != nil || len(all.Rows) < 6 {
		t.Fatalf("%d rows, %v", len(all.Rows), err)
	}
	if KeyColumn("certs") != "cert_id" || KeyColumn("names") != "name" || KeyColumn("issuances") != "issuance_key" || KeyColumn("x") != "" ||
		DefaultSort("names") != "last_seen desc" || DefaultSort("certs") != "first_seen desc" || DefaultSort("x") != "" {
		t.Fatal("KeyColumn or DefaultSort")
	}
	key := all.Index("cert_id")
	pick := []string{Render(all.Rows[4][key]), Render(all.Rows[1][key]), "999999"} // 999999 is not in the result
	dir := t.TempDir()
	p := filepath.Join(dir, "marked.json")
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	o := ExportOptions{Path: p, Format: "json", Version: "test", Now: func() time.Time { return now }, Selection: pick}
	if err := Export(ctx, s, sess, v.dirs, q, o); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Meta Meta             `json:"meta"`
		Rows []map[string]any `json:"rows"`
	}
	b, _ := os.ReadFile(p)
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Rows) != 2 || doc.Meta.RowCount != 2 || Render(doc.Rows[0]["cert_id"]) != pick[1] || Render(doc.Rows[1]["cert_id"]) != pick[0] {
		t.Fatalf("rows %v, meta %+v", doc.Rows, doc.Meta)
	}
	if sel := doc.Meta.Selection; sel == nil || sel.Key != "cert_id" || !slices.Equal(sel.Values, slices.Sorted(slices.Values(pick))) {
		t.Fatalf("selection %+v", doc.Meta.Selection)
	}

	// The filter narrows the marked rows further; without marks, no
	// selection is recorded.
	q.Filter = Render(all.Rows[1][all.Index("sha256")])
	o.Path = filepath.Join(dir, "filtered.json")
	if err := Export(ctx, s, sess, v.dirs, q, o); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(o.Path)
	doc.Rows = nil
	json.Unmarshal(b, &doc)
	if len(doc.Rows) != 1 || doc.Meta.Query.Filter != q.Filter {
		t.Fatalf("filtered: %v %+v", doc.Rows, doc.Meta)
	}
	o.Path, o.Selection = filepath.Join(dir, "all.json"), nil
	if err := Export(ctx, s, sess, v.dirs, q, o); err != nil {
		t.Fatal(err)
	}
	if b, _ = os.ReadFile(o.Path); strings.Contains(string(b), `"selection"`) {
		t.Fatalf("an export without marks records a selection:\n%s", b)
	}
}
