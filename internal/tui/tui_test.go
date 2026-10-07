package tui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/query"
)

// search runs q through the query package, as `ctvault search` does.
func (h *harness) search(q query.Query) *query.Result {
	h.t.Helper()
	s, err := query.Open(h.v.Root, h.m.snap.AsOf)
	if err != nil {
		h.t.Fatal(err)
	}
	r, err := query.Search(ctx, s, h.sess, h.v.Dirs, q)
	if err != nil {
		h.t.Fatal(err)
	}
	return r
}

func sameRows(t *testing.T, what string, got [][]any, want *query.Result) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want.Rows) {
		t.Fatalf("%s: explore shows %d rows, search gives %d\nexplore %v\nsearch  %v", what, len(got), len(want.Rows), got, want.Rows)
	}
}

// TestGoldenScreens: the main screen for each group, help, and the notice
// of a terminal under 80×24, at fixed sizes (amendment A4 §3, §4).
func TestGoldenScreens(t *testing.T) {
	v := testVault(t)
	h := start(t, v, setup{bar: "example.test"})
	st := h.loaded()
	golden(t, "names", st.screen)
	h.key("down", "down", "space")
	golden(t, "names-marked", h.settled().screen)
	h.key("tab")
	golden(t, "certs", h.loaded().screen)
	h.key("tab")
	golden(t, "issuances", h.loaded().screen)
	h.key("?")
	golden(t, "help", h.settled().screen)

	small := start(t, v, setup{w: 79, h: 24})
	golden(t, "too-small", small.settled().screen)

	narrow := start(t, v, setup{bar: "example.test", w: 80, h: 24, tweak: func(m *Model) { m.group = "certs" }})
	golden(t, "certs-80x24", narrow.loaded().screen)

	empty := start(t, v, setup{})
	golden(t, "start", empty.settled().screen)
}

// TestExploreGivesSearchRows: for every group, a sort and the / filter,
// the pages explore loads are search's rows (amendment A4 §2.2, §3).
func TestExploreGivesSearchRows(t *testing.T) {
	v := testVault(t)
	var holds atomic.Int32
	h := start(t, v, setup{tweak: func(m *Model) {
		m.pageSize = 7
		real := m.hold
		m.hold = func(c context.Context, s *query.Snapshot, sess *query.Session, dirs []string, q query.Query) (*query.Results, error) {
			holds.Add(1)
			return real(c, s, sess, dirs, q)
		}
	}})
	q := query.Query{Mode: query.ModeDomain, Text: "example.test"}
	r := h.search(q)
	// The count is the whole result's from the first page on.
	st := h.query("example.test")
	if st.rows != 7 || !st.more || !strings.Contains(st.screen, fmt.Sprintf("%d names ·", len(r.Rows))) {
		t.Fatalf("the first page: %+v\n%s", st, st.screen)
	}
	h.all()
	sameRows(t, "names", h.rows(), r)

	for _, g := range []string{"certs", "issuances"} {
		h.key("tab")
		h.all()
		q.Group = g
		sameRows(t, g, h.rows(), h.search(q))
	}
	if n := holds.Load(); n != 3 {
		t.Fatalf("%d queries ran for 3 groups' pages", n)
	}

	// s: the next column, descending, then ascending.
	h.key("tab") // names
	h.settled()
	h.key("s")
	h.all()
	q.Group, q.Sort = "names", "name desc"
	sameRows(t, "sorted by name desc", h.rows(), h.search(q))
	h.key("s")
	h.all()
	q.Sort = "name asc"
	sameRows(t, "sorted by name asc", h.rows(), h.search(q))
	if st := h.settled(); !strings.Contains(st.screen, "sort name asc") {
		t.Fatalf("the info line does not show the sort:\n%s", st.screen)
	}

	// /: the filter covers every page, not only the loaded rows.
	h.key("/")
	h.typ("WWW.HOST2")
	h.key("enter")
	h.all()
	q.Filter = "WWW.HOST2"
	r = h.search(q)
	if len(r.Rows) != 11 {
		t.Fatalf("search with the filter: %d rows", len(r.Rows))
	}
	sameRows(t, "filtered", h.rows(), r)
	// Sorts and the filter reorder the held rows: no query ran for them.
	if n := holds.Load(); n != 4 {
		t.Fatalf("%d queries ran, want 4: one per group, then names again", n)
	}
}

// TestHeldRowsFollowTheLists: a list's rows are held once; a sort or a
// filter adds an order of them; a list explore leaves drops its rows, and
// so does closing explore (amendment A4 §2.2, as revised).
func TestHeldRowsFollowTheLists(t *testing.T) {
	v := testVault(t)
	h := start(t, v, setup{bar: "example.test"})
	h.loaded()
	h.held(1, "a query")
	h.key("s")
	h.loaded()
	h.held(2, "a sort: the rows and their new order")
	h.key("s")
	h.loaded()
	h.held(2, "another sort replaces the first")
	h.key("enter")
	h.loaded()
	h.held(3, "a name's certificates")
	h.key("esc")
	h.settled()
	h.held(2, "back from them")
	h.key("tab")
	h.loaded()
	h.held(1, "another group")
	h.toBar()
	h.key("ctrl+u")
	h.typ("exact:host1.example.test")
	h.key("enter")
	h.loaded()
	h.held(1, "a new query")
	h.key("R")
	h.loaded()
	h.held(1, "re-pinned")
	h.tm.Quit()
	h.tm.WaitFinished(t, teatest.WithFinalTimeout(20*time.Second))
	h.m.Close()
	h.held(0, "explore closed")
}

// TestOpenAndBack: Enter on a name lists its certificates, Enter on a
// certificate opens its detail; f shows the text dump and the PEM; Esc goes
// back each time (amendment A4 §3).
func TestOpenAndBack(t *testing.T) {
	v := testVault(t)
	h := start(t, v, setup{})
	h.query("example.test")
	h.key("s", "s") // name asc: host0 first
	h.all()
	h.key("down") // host1.example.test
	h.key("enter")
	st := h.loaded()
	if !strings.Contains(st.screen, "query: exact:host1.example.test") || st.group != "certs" || st.rows != 2 {
		t.Fatalf("Enter on host1.example.test: %+v\n%s", st, st.screen)
	}
	sameRows(t, "host1's certificates", st.data, h.search(query.Query{Mode: query.ModeExact, Text: "host1.example.test", Group: "certs"}))

	// The final's detail: its names, its entry, its chain, and its precert.
	r := h.search(query.Query{Mode: query.ModeExact, Text: "host1.example.test", Group: "certs", Kinds: []string{"final"}})
	finalID := r.Rows[0][r.Index("cert_id")]
	for i, row := range st.data {
		if row[r.Index("cert_id")] == finalID {
			for range i {
				h.key("down")
			}
		}
	}
	h.key("enter")
	st = h.loaded()
	pre := h.search(query.Query{Mode: query.ModeExact, Text: "host1.example.test", Group: "certs", Kinds: []string{"precert"}})
	preSHA := fmt.Sprint(pre.Rows[0][pre.Index("sha256")])
	for _, want := range []string{"names (2)", "www.host1.example.test", "entries (1)", "fakelog #3", "chains (1)", "CTVault Test CA", "linked", "precert " + fmt.Sprint(pre.Rows[0][pre.Index("cert_id")])} {
		if !st.cert || !strings.Contains(st.screen, want) {
			t.Fatalf("the detail lacks %q:\n%s", want, st.screen)
		}
	}
	if strings.Contains(st.screen, preSHA[:12]) == false {
		t.Fatalf("the detail does not show the precert's SHA-256:\n%s", st.screen)
	}
	h.key("f")
	if st := h.loaded(); !strings.Contains(st.screen, "sha256:") || !strings.Contains(st.screen, "ct poison:") {
		t.Fatalf("f: the text dump:\n%s", st.screen)
	}
	h.key("f")
	if st := h.loaded(); !strings.Contains(st.screen, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("f again: the PEM:\n%s", st.screen)
	}
	h.key("esc")
	if st := h.settled(); st.cert || st.group != "certs" || st.rows != 2 {
		t.Fatalf("Esc from the certificate: %+v", st)
	}
	h.key("esc")
	st = h.settled()
	if st.group != "names" || st.cursor != 1 || !strings.Contains(st.screen, "query: example.test") {
		t.Fatalf("Esc from the name's certificates: %+v\n%s", st, st.screen)
	}

	// f on a certificate row opens the text dump directly.
	h.key("tab")
	h.loaded()
	h.key("f")
	if st := h.loaded(); !st.cert || !strings.Contains(st.screen, "sha256:") {
		t.Fatalf("f on a certs row:\n%s", st.screen)
	}
	h.key("esc")
	h.settled()
	// Enter on an issuance explains itself and opens nothing.
	h.key("tab")
	h.loaded()
	h.key("enter")
	if st := h.settled(); st.cert || st.group != "issuances" || !strings.Contains(st.msg, "Enter opens") {
		t.Fatalf("Enter on an issuance: %+v", st)
	}
}

// TestMarkAndExport: marks persist across pages; e exports the marked rows
// with the selection, or every row; an existing file is refused (amendment
// A4 §3).
func TestMarkAndExport(t *testing.T) {
	v := testVault(t)
	dir := t.TempDir()
	h := start(t, v, setup{tweak: func(m *Model) { m.pageSize = 7 }})
	h.key("tab")
	h.query("example.test")
	h.key("space") // row 0, then the cursor moves down
	h.key("down", "space")
	h.key("end")
	h.settled()
	h.key("end") // row 13, on the second page
	h.settled()
	h.key("space")
	st := h.settled()
	if !strings.Contains(st.screen, "3 marked") {
		t.Fatalf("three marks:\n%s", st.screen)
	}
	key := func(i int) string { return query.Render(st.data[i][1]) } // cert_id
	want := []string{key(0), key(2), key(13)}
	slices.Sort(want)

	p := filepath.Join(dir, "marked.json")
	h.key("e")
	h.key("ctrl+u")
	h.typ(p)
	h.key("enter")
	st = h.loaded()
	if !strings.Contains(st.msg, "exported") {
		t.Fatalf("export: %q", st.msg)
	}
	var doc struct {
		Meta query.Meta       `json:"meta"`
		Rows []map[string]any `json:"rows"`
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Rows) != 3 || doc.Meta.Selection == nil || doc.Meta.Selection.Key != "cert_id" || !slices.Equal(doc.Meta.Selection.Values, want) ||
		doc.Meta.Query.Group != "certs" || doc.Meta.Query.Text != "example.test" || doc.Meta.AsOfCommitSeq != 3 {
		t.Fatalf("the marked export: %d rows, meta %+v", len(doc.Rows), doc.Meta)
	}

	// The same path again is refused, and the file is untouched.
	h.key("e", "ctrl+u")
	h.typ(p)
	h.key("enter")
	if st := h.settled(); !strings.Contains(st.msg, "exists") {
		t.Fatalf("an existing export path: %q", st.msg)
	}
	if b2, _ := os.ReadFile(p); !bytes.Equal(b, b2) {
		t.Fatal("an existing export was changed")
	}

	// Space again unmarks; with no marks, e exports every row, without a
	// selection.
	h.key("home", "space") // row 0; the cursor moves to row 1
	h.key("down", "space") // row 2
	for range 10 {
		h.key("down")
	}
	h.key("space") // row 13
	if st := h.settled(); strings.Contains(st.screen, "marked") {
		t.Fatalf("marks left:\n%s", st.screen)
	}
	csvPath := filepath.Join(dir, "all.csv")
	h.key("e", "ctrl+u")
	h.typ(csvPath)
	h.key("enter")
	h.loaded()
	all := h.search(query.Query{Mode: query.ModeDomain, Text: "example.test", Group: "certs"})
	if b, err := os.ReadFile(csvPath); err != nil || bytes.Count(b, []byte("\n")) != len(all.Rows)+1 {
		t.Fatalf("export of every row: %v\n%s", err, b)
	}
	if b, err := os.ReadFile(csvPath + ".meta.json"); err != nil || strings.Contains(string(b), "selection") {
		t.Fatalf("the CSV's metadata: %v\n%s", err, b)
	}
	h.key("e", "ctrl+u")
	h.typ(filepath.Join(dir, "r.txt"))
	h.key("enter")
	if st := h.settled(); !strings.Contains(st.msg, ".md, .json or .csv") {
		t.Fatalf("an export path without a known extension: %q", st.msg)
	}
}

// TestWriteNeverOverwrites: w writes the shown certificate, as PEM or as
// the text dump, and refuses an existing file (amendment A4 §3).
func TestWriteNeverOverwrites(t *testing.T) {
	v := testVault(t)
	dir := t.TempDir()
	h := start(t, v, setup{})
	h.key("tab")
	st := h.query("exact:host4.example.test")
	sha := fmt.Sprint(st.data[0][0])
	h.key("enter")
	h.loaded()
	h.key("w")
	if st := h.settled(); !st.prompts || !strings.Contains(st.screen, "write to: "+sha[:16]+".pem") {
		t.Fatalf("w proposes <sha256>.pem:\n%s", st.screen)
	}
	p := filepath.Join(dir, "c.pem")
	h.key("ctrl+u")
	h.typ(p)
	h.key("enter")
	if st := h.settled(); !strings.Contains(st.msg, "wrote") {
		t.Fatalf("write: %q", st.msg)
	}
	b, _ := os.ReadFile(p)
	blk, _ := pem.Decode(b)
	if blk == nil || hex.EncodeToString(sumOf(blk.Bytes)) != sha {
		t.Fatalf("the written PEM is not the certificate:\n%s", b)
	}

	if err := os.WriteFile(filepath.Join(dir, "taken.txt"), []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.key("f") // the text dump
	h.loaded()
	h.key("w", "ctrl+u")
	h.typ(filepath.Join(dir, "taken.txt"))
	h.key("enter")
	if st := h.settled(); !strings.Contains(st.msg, "exists") {
		t.Fatalf("w onto an existing file: %q", st.msg)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "taken.txt")); string(b) != "mine" {
		t.Fatal("w overwrote a file")
	}
	h.key("w", "ctrl+u")
	h.typ(filepath.Join(dir, "dump.txt"))
	h.key("enter")
	h.settled()
	if b, _ := os.ReadFile(filepath.Join(dir, "dump.txt")); !strings.HasPrefix(string(b), "sha256:") {
		t.Fatalf("the text dump written:\n%s", b)
	}
	left, _ := filepath.Glob(filepath.Join(dir, ".*"))
	if len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
}

func sumOf(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

// TestEscCancels: Esc cancels a running query through its context; a late
// answer to a query that was replaced is dropped (amendment A4 §2.2).
func TestEscCancels(t *testing.T) {
	v := testVault(t)
	started := make(chan string, 4)
	cancelled := make(chan error, 1)
	release, answered := make(chan struct{}), make(chan struct{})
	h := start(t, v, setup{tweak: func(m *Model) {
		real := m.hold
		m.hold = func(c context.Context, s *query.Snapshot, sess *query.Session, dirs []string, q query.Query) (*query.Results, error) {
			started <- q.Text
			switch q.Text {
			case "example.test": // slow until cancelled
				<-c.Done()
				cancelled <- c.Err()
				return nil, c.Err()
			case "host1.example.test": // ignores its context and answers late, with rows
				<-release
				defer close(answered)
				return real(context.Background(), s, sess, dirs, q)
			}
			return real(c, s, sess, dirs, q)
		}
	}})
	h.typ("example.test")
	h.key("enter")
	<-started
	st := h.wait("the query to run", func(st state) bool { return st.busy != "" })
	if !strings.Contains(st.screen, "Esc cancels") {
		t.Fatalf("a running query:\n%s", st.screen)
	}
	h.key("esc")
	st = h.settled()
	if err := <-cancelled; st.msg != "cancelled" || st.rows != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("after Esc: %+v, the query saw %v", st, err)
	}

	// A query replaced by another: the first answer comes last and is
	// dropped.
	h.key("esc") // to the bar
	h.key("ctrl+u")
	h.typ("exact:host1.example.test")
	h.key("enter")
	<-started
	h.key("esc", "esc", "ctrl+u") // cancel, then edit the query
	h.typ("exact:host2.example.test")
	h.key("enter")
	<-started
	h.loaded()
	close(release)
	<-answered
	time.Sleep(200 * time.Millisecond) // the late answer reaches the program
	if rows := h.rows(); len(rows) != 1 || rows[0][0] != "host2.example.test" {
		t.Fatalf("a late answer replaced the current one: %v", rows)
	}
	h.held(1, "the late answer's rows are dropped")

	// An answer that completed, but arrives after its operation was
	// replaced, gives back the rows no list took.
	s, err := query.Open(v.Root, 0)
	if err != nil {
		t.Fatal(err)
	}
	res, err := query.Hold(ctx, s, h.sess, v.Dirs, query.Query{Mode: query.ModeExact, Text: "host3.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	h.held(2, "rows held for a stale answer")
	h.tm.Send(pageMsg{seq: -1, l: &list{}, res: res, fresh: true, p: &query.Page{}})
	h.held(1, "a stale answer's rows are dropped")
	if rows := h.rows(); len(rows) != 1 || rows[0][0] != "host2.example.test" {
		t.Fatalf("a stale answer changed the list: %v", rows)
	}
}

// TestRepin: --as-of pins an earlier commit; R re-pins the latest
// (amendment A4 §2.2).
func TestRepin(t *testing.T) {
	v := testVault(t)
	h := start(t, v, setup{asOf: 1, bar: "example.test"})
	st := h.loaded()
	if st.asOf != 1 || st.rows != 20 || !strings.Contains(st.screen, "as-of commit 1") {
		t.Fatalf("as of commit 1: %+v\n%s", st, st.screen)
	}
	h.key("R")
	st = h.loaded()
	if st.asOf != 3 || st.rows != 60 || !strings.Contains(st.screen, "re-pinned to commit 3") {
		t.Fatalf("after R: %+v\n%s", st, st.screen)
	}
}

// TestBarErrors: a malformed bar shows search's message and runs nothing.
func TestBarErrors(t *testing.T) {
	v := testVault(t)
	var runs atomic.Int32
	h := start(t, v, setup{tweak: func(m *Model) {
		real := m.hold
		m.hold = func(c context.Context, s *query.Snapshot, sess *query.Session, dirs []string, q query.Query) (*query.Results, error) {
			runs.Add(1)
			return real(c, s, sess, dirs, q)
		}
	}})
	for bar, want := range map[string]string{
		"bogus:x example.test":     `unknown term "bogus:"`,
		"example.test exact:a.b":   "exactly one search term",
		`issuer:"Let's`:            "unclosed quote",
		"example.test since:never": "since:never",
	} {
		h.key("ctrl+u")
		h.typ(bar)
		h.key("enter")
		if st := h.settled(); !strings.Contains(st.msg, want) || !strings.Contains(st.screen, want) {
			t.Errorf("%q: %q", bar, st.msg)
		}
	}
	// A bar that parses but that search refuses: the same message search
	// gives.
	h.key("ctrl+u")
	h.typ("host1.example.test")
	h.key("enter")
	if st := h.settled(); !strings.Contains(st.msg, "is not a registrable domain") {
		t.Errorf("a name in the domain mode: %q", st.msg)
	}
	if n := runs.Load(); n != 1 {
		t.Fatalf("%d searches ran, want 1 (only the parsed one)", n)
	}
}

// TestReadOnly: a whole session changes nothing in the vault: no file
// outside tmp/duckdb-<pid>/ is written, and that folder is removed when
// the session closes (amendment A4 §3).
func TestReadOnly(t *testing.T) {
	v := testVault(t)
	before := tree(t, v.Root)
	out := t.TempDir()
	func() {
		h := start(t, v, setup{bar: "example.test"})
		h.loaded()
		h.key("enter")
		h.loaded()
		h.key("enter")
		h.loaded()
		h.key("f")
		h.loaded()
		h.key("w", "ctrl+u")
		h.typ(filepath.Join(out, "c.txt"))
		h.key("enter")
		h.settled()
		h.key("esc", "esc", "tab")
		h.loaded()
		h.key("e", "ctrl+u")
		h.typ(filepath.Join(out, "e.md"))
		h.key("enter")
		h.loaded()
		h.key("R", "q")
		h.tm.WaitFinished(t)
		h.m.Close()
		h.sess.Close()
	}()
	after := tree(t, v.Root)
	if d := diffTrees(before, after); d != "" {
		t.Fatalf("explore changed the vault:\n%s", d)
	}
	if ents, _ := os.ReadDir(out); len(ents) != 2 {
		t.Fatalf("the requested files: %v", ents)
	}
}

// tree is every file under root with its size, mode and modification time.
func tree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		out[rel] = fmt.Sprintf("%v %d %v", fi.Mode(), fi.Size(), fi.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func diffTrees(a, b map[string]string) string {
	var d []string
	for k, v := range a {
		if b[k] != v && !strings.HasPrefix(k, "tmp") {
			d = append(d, fmt.Sprintf("%s: %s → %q", k, v, b[k]))
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			d = append(d, "new: "+k)
		}
	}
	slices.Sort(d)
	return strings.Join(d, "\n")
}

// TestReloadBanner: explore checks ACTIVE.json's seq; when a switch
// changes it, the status line asks for a reload, and R clears it
// (amendment A5 §9).
func TestReloadBanner(t *testing.T) {
	v := testVault(t)
	h := start(t, v, setup{bar: "example.test", tweak: func(m *Model) { m.pollEvery = 20 * time.Millisecond }})
	h.loaded()
	a, _, err := derive.ReadActive(v.Root)
	if err != nil {
		t.Fatal(err)
	}
	a.Seq++
	if err := derive.WriteActive(v.Root, a); err != nil {
		t.Fatal(err)
	}
	h.wait("the reload banner", func(st state) bool {
		return strings.Contains(st.screen, "the dataset changed") && strings.Contains(st.screen, "press R to reload")
	})
	h.key("R")
	h.loaded()
	h.wait("the banner gone", func(st state) bool { return !strings.Contains(st.screen, "the dataset changed") })
}
