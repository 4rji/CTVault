package tui

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/4rji/ctvault/internal/query"
	"github.com/4rji/ctvault/internal/querytest"
)

// updating reports -update, which teatest's golden package defines.
func updating() bool {
	f := flag.Lookup("update")
	return f != nil && f.Value.String() == "true"
}

var ctx = context.Background()

// testVault is 30 issuances (60 entries) in 3 batches of 20.
func testVault(t *testing.T) *querytest.Vault {
	t.Helper()
	g, es := querytest.Pairs(t, 60)
	return querytest.New(t, g, es, 20, 1000)
}

// state is what a test waits on, copied after every update.
type state struct {
	screen  string // the view, without styles
	busy    string
	rows    int
	more    bool // a next page exists
	group   string
	cert    bool
	msg     string
	asOf    uint64
	cursor  int
	prompts bool
	bar     bool    // the bar has focus
	data    [][]any // the shown list's rows
}

// harness runs a model in a real Bubble Tea program (teatest) and records
// its state after every update, so tests wait on the model rather than on
// the renderer's output.
type harness struct {
	t     *testing.T
	v     *querytest.Vault
	m     *Model
	sess  *query.Session
	tm    *teatest.TestModel
	mu    sync.Mutex
	st    state
	pings int // ctrl+l keys handled
}

type setup struct {
	asOf  uint64
	bar   string
	w, h  int
	tweak func(*Model)
}

func start(t *testing.T, v *querytest.Vault, su setup) *harness {
	t.Helper()
	s, err := query.Open(v.Root, su.asOf)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := query.NewSession(v.Root, querytest.Guard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close() })
	m := New(Options{Root: v.Root, Dirs: v.Dirs, Snapshot: s, Session: sess, Query: su.bar, Version: "test",
		Now: func() time.Time { return time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC) }})
	m.since = func(time.Time) time.Duration { return 42 * time.Millisecond }
	h := &harness{t: t, v: v, m: m, sess: sess}
	m.afterUpdate = func(m *Model, msg tea.Msg) {
		st := state{screen: plain(m.View().Content), busy: m.busy, group: m.group, cert: m.cert != nil, msg: m.msg, asOf: m.snap.AsOf, prompts: m.focus == onPrompt, bar: m.focus == onBar}
		if l := m.top(); l != nil {
			st.rows, st.more, st.cursor, st.data = len(l.rows), l.next != nil, l.cursor, l.rows
		}
		h.mu.Lock()
		h.st = st
		if k, ok := msg.(tea.KeyPressMsg); ok && k.String() == "ctrl+l" {
			h.pings++
		}
		h.mu.Unlock()
	}
	if su.tweak != nil {
		su.tweak(m)
	}
	if su.w == 0 {
		su.w, su.h = 100, 30
	}
	h.tm = teatest.NewTestModel(t, m, teatest.WithInitialTermSize(su.w, su.h))
	t.Cleanup(func() {
		h.tm.Quit()
		h.tm.WaitFinished(t, teatest.WithFinalTimeout(20*time.Second))
		m.Close()
	})
	h.wait("the first frame", func(st state) bool { return st.screen != "" })
	return h
}

// plain strips styles and trailing spaces.
func plain(s string) string {
	lines := strings.Split(ansi.Strip(s), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " ")
	}
	return strings.Join(lines, "\n")
}

// wait polls the recorded state until cond holds.
func (h *harness) wait(what string, cond func(state) bool) state {
	h.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		h.mu.Lock()
		st := h.st
		h.mu.Unlock()
		if cond(st) {
			return st
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("waiting for %s; screen:\n%s\nstate %+v", what, st.screen, st)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// settled waits until every key sent so far was handled and no operation
// runs.
func (h *harness) settled() state {
	h.t.Helper()
	h.mu.Lock()
	n := h.pings
	h.mu.Unlock()
	h.key("ctrl+l") // redraw, a no-op: once it is handled, every key before it was
	return h.wait("idle", func(st state) bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.pings > n && st.busy == ""
	})
}

// key sends named keys: enter, tab, esc, space, up, down, end, home,
// ctrl+<letter>, or single characters.
func (h *harness) key(names ...string) {
	for _, n := range names {
		h.tm.Send(keyMsg(n))
	}
}

// typ types text into whatever has focus.
func (h *harness) typ(s string) { h.tm.Type(s) }

func keyMsg(n string) tea.KeyPressMsg {
	switch n {
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "tab":
		return tea.KeyPressMsg{Code: tea.KeyTab}
	case "esc":
		return tea.KeyPressMsg{Code: tea.KeyEscape}
	case "space":
		return tea.KeyPressMsg{Code: tea.KeySpace, Text: " "}
	case "up":
		return tea.KeyPressMsg{Code: tea.KeyUp}
	case "down":
		return tea.KeyPressMsg{Code: tea.KeyDown}
	case "end":
		return tea.KeyPressMsg{Code: tea.KeyEnd}
	case "home":
		return tea.KeyPressMsg{Code: tea.KeyHome}
	}
	if c, ok := strings.CutPrefix(n, "ctrl+"); ok {
		return tea.KeyPressMsg{Code: rune(c[0]), Mod: tea.ModCtrl}
	}
	r := []rune(n)
	return tea.KeyPressMsg{Code: r[0], Text: n}
}

// toBar presses Esc until the bar has focus: it closes a certificate and
// pushed lists on the way.
func (h *harness) toBar() {
	h.t.Helper()
	for i := 0; !h.settled().bar; i++ {
		if i > 10 {
			h.t.Fatal("Esc does not reach the bar")
		}
		h.key("esc")
	}
}

// group presses Tab until g is the group.
func (h *harness) group(g string) {
	h.t.Helper()
	for i := 0; h.settled().group != g; i++ {
		if i > 3 {
			h.t.Fatalf("Tab does not reach %s", g)
		}
		h.key("tab")
	}
}

// query types a bar query and runs it, waiting for its first page.
func (h *harness) query(bar string) state {
	h.t.Helper()
	h.key("ctrl+u")
	h.typ(bar)
	h.key("enter")
	return h.loaded()
}

// loaded waits for the running operation to end without error.
func (h *harness) loaded() state {
	h.t.Helper()
	st := h.settled()
	if strings.HasPrefix(st.msg, "error") {
		h.t.Fatalf("%s\n%s", st.msg, st.screen)
	}
	return st
}

// all loads every page of the shown list (End, until the last page).
func (h *harness) all() state {
	h.t.Helper()
	for {
		st := h.settled()
		if !st.more {
			return st
		}
		h.key("end")
		h.settled()
	}
}

// rows is the shown list's rows once idle.
func (h *harness) rows() [][]any {
	h.t.Helper()
	return h.settled().data
}

// hexRun masks SHA-256 values and issuance keys, which the test CA's random
// keys change on every run; the layout stays the same.
var hexRun = regexp.MustCompile(`[0-9a-f]{10,}`)

func masked(s string) string {
	return hexRun.ReplaceAllStringFunc(s, func(x string) string { return strings.Repeat("x", len(x)) })
}

// golden compares a screen with testdata/<name>.golden.
func golden(t *testing.T, name, screen string) {
	t.Helper()
	p := filepath.Join("testdata", name+".golden")
	screen = masked(screen) + "\n"
	if updating() {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(screen), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != screen {
		t.Errorf("%s differs (run with -update to accept):\n--- got\n%s\n--- want\n%s", name, screen, want)
	}
}
