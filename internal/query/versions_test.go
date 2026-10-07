package query_test

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/derivetest"
	. "github.com/4rji/ctvault/internal/query"
	"github.com/4rji/ctvault/internal/querytest"
)

func setActive(t *testing.T, root string, edit func(a *derive.Active)) {
	t.Helper()
	a, _, err := derive.ReadActive(root)
	if err != nil {
		t.Fatal(err)
	}
	edit(&a)
	a.Seq++
	if err := derive.WriteActive(root, a); err != nil {
		t.Fatal(err)
	}
	if _, err := dataset.WriteViews(root, a); err != nil {
		t.Fatal(err)
	}
}

func intp(v int) *int { return &v }

// TestReadersFollowTheActiveVersion: readers use each table's active
// version (amendment A5 §7): v1 while v2 is being built, so search keeps
// working through an upgrade; v2 once it is active, with the same rows;
// fetch, the views and the snapshot follow.
func TestReadersFollowTheActiveVersion(t *testing.T) {
	v := searchVault(t)
	q := Query{Mode: ModeDomain, Text: "example.test", Group: "certs"}
	before := search(t, v, q)

	derivetest.Use(t, "v2")
	setActive(t, v.root, func(a *derive.Active) {
		a.Tables["certs"] = derive.TableState{Active: intp(1), Building: intp(2), Status: derive.StatusBuilding}
	})
	if during := search(t, v, q); fmt.Sprint(during.Rows) != fmt.Sprint(before.Rows) {
		t.Fatalf("search during the upgrade: %d rows, %d before", len(during.Rows), len(before.Rows))
	}
	views, _ := os.ReadFile(filepath.Join(v.root, dataset.ViewsFile))
	if !strings.Contains(string(views), "VIEW certs AS") || !strings.Contains(string(views), "certs.p1.parquet") || !strings.Contains(string(views), "VIEW certs_building AS") {
		t.Fatalf("views during the upgrade:\n%s", views)
	}

	w := querytest.Open(t, &querytest.Vault{Root: v.root, Dirs: v.dirs}, 1000)
	if _, err := w.Rebuild(ctx); err != nil {
		t.Fatal(err)
	}
	w.Close()
	s, err := Open(v.root, 0)
	if err != nil {
		t.Fatal(err)
	}
	if tb, err := s.Table("certs"); err != nil || tb.File() != "certs.p2.parquet" {
		t.Fatalf("certs after the switch: %+v %v", tb, err)
	}
	after := search(t, v, q)
	if fmt.Sprint(after.Rows) != fmt.Sprint(before.Rows) {
		t.Fatalf("search on v2: %d rows, %d on v1", len(after.Rows), len(before.Rows))
	}
	sha := fmt.Sprint(after.Rows[0][after.Index("sha256")])
	sess, err := NewSession(v.root, querytest.Guard)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	f, err := NewFetcher(s, sess, v.dirs)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if c, err := f.ByCertID(ctx, after.Rows[0][after.Index("cert_id")].(uint64)); err != nil || hex.EncodeToString(c.SHA256[:]) != sha {
		t.Fatalf("fetch from v2: %+v %v", c, err)
	}
	views, _ = os.ReadFile(filepath.Join(v.root, dataset.ViewsFile))
	if !strings.Contains(string(views), "certs.p2.parquet") || strings.Contains(string(views), "certs_building") {
		t.Fatalf("views after the switch:\n%s", views)
	}
}

// TestNotReadable: a table being built for the first time, or mixed, is
// refused with a message that says why (amendment A5 §7, §10).
func TestNotReadable(t *testing.T) {
	v := searchVault(t)
	derivetest.Use(t, "v2")
	q := Query{Mode: ModeDomain, Text: "example.test"}
	for state, want := range map[string]string{
		"new":   "being built",
		"mixed": "mixed",
	} {
		setActive(t, v.root, func(a *derive.Active) {
			if state == "new" {
				a.Tables["names"] = derive.TableState{Building: intp(1), Status: derive.StatusBuilding}
				a.Tables["certs"] = derive.TableState{Active: intp(1), Status: derive.StatusComplete}
			} else {
				a.Tables["names"] = derive.TableState{Active: intp(1), Status: derive.StatusComplete}
				a.Tables["certs"] = derive.TableState{Active: intp(1), Building: intp(2), Status: derive.StatusMixed}
			}
		})
		s, _ := Open(v.root, 0)
		sess, _ := NewSession(v.root, querytest.Guard)
		_, err := Search(ctx, s, sess, v.dirs, q)
		sess.Close()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want an error mentioning %q", state, err, want)
		}
	}
}

// toMixed converts searchVault's first batch in place only: certs is then
// mixed, v2 in batch 1 and v1 in batches 2 and 3.
func toMixed(t *testing.T, v *testVault) {
	t.Helper()
	derivetest.Use(t, "v2")
	w := querytest.Open(t, &querytest.Vault{Root: v.root, Dirs: v.dirs}, 1000)
	defer w.Close()
	if err := w.StartInPlace(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.RebuildTurn(ctx, 1); err != nil {
		t.Fatal(err)
	}
}

func searchMixed(t *testing.T, v *testVault, q Query, m MixedRead) (*Result, error) {
	t.Helper()
	s, err := Open(v.root, 0)
	if err != nil {
		t.Fatal(err)
	}
	s.Mixed = m
	sess, err := NewSession(v.root, querytest.Guard)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	return Search(ctx, s, sess, v.dirs, q)
}

// TestMixedReads: a mixed table is refused unless the reader chooses:
// --parser-version reads the batches at that version only, --allow-mixed
// reads each batch's own version (amendment A5 §10).
func TestMixedReads(t *testing.T) {
	q := Query{Mode: ModeDomain, Text: "example.test", Group: "certs", Sort: "cert_id asc"}
	v := searchVault(t)
	before := search(t, v, q)
	toMixed(t, v)
	if _, err := searchMixed(t, v, q, MixedRead{}); !errors.Is(err, ErrMixed) || !strings.Contains(err.Error(), "v1 in 2 batches, v2 in 1") {
		t.Fatalf("a mixed table without a choice: %v", err)
	}
	views, _ := os.ReadFile(filepath.Join(v.root, dataset.ViewsFile))
	if strings.Contains(string(views), "VIEW certs AS") || strings.Contains(string(views), "VIEW entry_certs") ||
		!strings.Contains(string(views), "VIEW certs_building AS") || !strings.Contains(string(views), "VIEW certs_previous AS") {
		t.Fatalf("views of a mixed table:\n%s", views)
	}
	v2, err := searchMixed(t, v, q, MixedRead{ParserVersion: 2})
	if err != nil {
		t.Fatal(err)
	}
	v1, err := searchMixed(t, v, q, MixedRead{ParserVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(v2.Rows) == 0 || len(v1.Rows) == 0 || fmt.Sprint(append(v2.Rows, v1.Rows...)) != fmt.Sprint(before.Rows) {
		t.Fatalf("v2 gives %d rows and v1 %d; together they should be the %d rows", len(v2.Rows), len(v1.Rows), len(before.Rows))
	}
	all, err := searchMixed(t, v, q, MixedRead{Allow: true})
	if err != nil || fmt.Sprint(all.Rows) != fmt.Sprint(before.Rows) {
		t.Fatalf("--allow-mixed: %d rows, %v; want %d", len(all.Rows), err, len(before.Rows))
	}
	if _, err := searchMixed(t, v, q, MixedRead{ParserVersion: 3}); err == nil {
		t.Fatal("a version the table does not have")
	}

	// fetch reads each batch's own version.
	s, _ := Open(v.root, 0)
	s.Mixed = MixedRead{Allow: true}
	sess, _ := NewSession(v.root, querytest.Guard)
	defer sess.Close()
	f, err := NewFetcher(s, sess, v.dirs)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, row := range [][]any{all.Rows[0], all.Rows[len(all.Rows)-1]} {
		if c, err := f.ByCertID(ctx, row[all.Index("cert_id")].(uint64)); err != nil || hex.EncodeToString(c.SHA256[:]) != row[all.Index("sha256")] {
			t.Fatalf("fetch of %v: %v", row[all.Index("cert_id")], err)
		}
		// By SHA-256: every batch's file at once, of both versions.
		var sha [32]byte
		b, _ := hex.DecodeString(row[all.Index("sha256")].(string))
		copy(sha[:], b)
		if c, err := f.BySHA256(ctx, sha); err != nil || c.CertID != row[all.Index("cert_id")].(uint64) {
			t.Fatalf("fetch of %x: %v", sha[:4], err)
		}
	}

	// Exports record what was read.
	m := NewMeta(s, all.Query, "test", time.Unix(0, 0), len(all.Rows))
	if len(m.Mixed) != 1 || m.Mixed[0].Table != "certs" || m.Mixed[0].Partial || m.Mixed[0].Batches["1"] != 2 || m.Mixed[0].Batches["2"] != 1 {
		t.Fatalf("export metadata %+v", m.Mixed)
	}
	s.Mixed = MixedRead{ParserVersion: 2}
	if m := NewMeta(s, all.Query, "test", time.Unix(0, 0), 0); len(m.Mixed) != 1 || !m.Mixed[0].Partial || m.Mixed[0].Batches["2"] != 1 {
		t.Fatalf("partial export metadata %+v", m.Mixed)
	}
}
