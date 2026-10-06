// Package tui is `ctvault explore` (spec §11.4, amendment A4): a terminal
// UI over the query package. It has no SQL of its own, so search and
// explore give the same rows for the same query. It is read-only: it takes
// no lock and writes nothing but the reader session's spill and the files
// the user names.
package tui

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"charm.land/bubbles/v2/table"
	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"

	"github.com/4rji/ctvault/internal/query"
)

// pageSize is how many rows a page holds (amendment A4 §2.2).
const pageSize = 200

// defaultKinds are search's kinds when the query names none.
var defaultKinds = []string{"precert", "final"}

// groups, in Tab's order.
var groups = []string{"names", "certs", "issuances"}

// Options configure a session.
type Options struct {
	Root     string // the vault root, for R
	Dirs     []string
	Snapshot *query.Snapshot // pinned until R
	Session  *query.Session
	Query    string // the bar's initial text; it runs at start when not empty
	Version  string // recorded in exports
	Now      func() time.Time
}

type focus int

const (
	onBar focus = iota
	onResults
	onPrompt
)

type promptKind int

const (
	promptFilter promptKind = iota + 1
	promptExport
	promptWrite
)

// list is one result: its query and the rows loaded so far.
type list struct {
	text   string      // the bar's text for it
	q      query.Query // with defaults filled in once a page arrives
	cols   []string
	rows   [][]any
	next   *query.Cursor // nil after the last page
	asOf   uint64        // the commit its rows come from
	took   time.Duration // the first page's
	marks  map[string]bool
	cursor int
}

// key is a row's identity: the group's unique key as Render shows it, as
// exports record selections.
func (l *list) key(row []any) string {
	return query.Render(row[slices.Index(l.cols, query.KeyColumn(l.q.Group))])
}

// Model is explore's root model.
type Model struct {
	o     Options
	snap  *query.Snapshot
	certs *certSource

	// Seams for tests.
	search      func(ctx context.Context, s *query.Snapshot, sess *query.Session, dirs []string, q query.Query, after *query.Cursor, n int) (*query.Page, error)
	since       func(time.Time) time.Duration
	pageSize    int
	afterUpdate func(*Model, tea.Msg)

	w, h   int
	keys   keyMap
	bar    textinput.Model
	prompt textinput.Model
	pk     promptKind
	table  table.Model
	vp     viewport.Model

	focus    focus
	group    string  // the shown list's, or the next query's
	lists    []*list // Enter on a name pushes its certificates
	cert     *certView
	showHelp bool

	seq    int // the latest operation's number; older answers are dropped
	cancel context.CancelFunc
	busy   string // what runs, "" when idle
	msg    string // the last notice or error, until the next key
	isErr  bool
}

// New makes a session's model. Close releases it.
func New(o Options) *Model {
	if o.Now == nil {
		o.Now = time.Now
	}
	m := &Model{o: o, snap: o.Snapshot, search: query.SearchPage, since: time.Since, pageSize: pageSize, group: "names", keys: newKeys()}
	m.certs = newCertSource(o.Snapshot, o.Session, o.Dirs)
	m.bar = textinput.New()
	m.bar.Prompt = "query: "
	m.bar.Placeholder = `example.com issuer:"Let's Encrypt" since:2026-10 kind:final`
	m.bar.SetVirtualCursor(false)
	m.bar.SetValue(o.Query)
	m.bar.Focus()
	m.prompt = textinput.New()
	m.prompt.SetVirtualCursor(false)
	m.table = table.New(table.WithKeyMap(tableKeys()), table.WithStyles(tableStyles()), table.WithFocused(true))
	m.vp = viewport.New()
	m.vp.KeyMap = viewportKeys()
	return m
}

// Close cancels what runs and releases the vault reader. The session and
// snapshot belong to the caller.
func (m *Model) Close() {
	m.abort()
	m.certs.close()
}

// Init runs the initial query, if any.
func (m *Model) Init() tea.Cmd {
	if strings.TrimSpace(m.bar.Value()) == "" {
		return nil
	}
	return m.submit()
}

// Update handles a message.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	cmd := m.update(msg)
	if m.afterUpdate != nil {
		m.afterUpdate(m, msg)
	}
	return m, cmd
}

// Messages from commands. seq ties each to the operation that sent it.
type (
	pageMsg struct {
		seq   int
		l     *list
		after *query.Cursor
		p     *query.Page
		asOf  uint64
		took  time.Duration
		err   error
	}
	certMsg struct {
		seq int
		cv  *certView
		err error
	}
	doneMsg struct {
		seq  int
		note string
		err  error
	}
)

func (m *Model) update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		m.layout()
	case tea.KeyPressMsg:
		return m.onKey(msg)
	case pageMsg:
		return m.onPage(msg)
	case certMsg:
		if msg.seq == m.seq {
			m.end()
			if msg.err != nil {
				m.fail(msg.err)
				return nil
			}
			m.cert = msg.cv
			m.showCert()
		}
	case doneMsg:
		if msg.seq == m.seq {
			m.end()
			if msg.err != nil {
				m.fail(msg.err)
			} else {
				m.note(msg.note)
			}
		}
	}
	return nil
}

// begin starts an operation, cancelling the running one; its answer will
// carry the new seq.
func (m *Model) begin(what string) (context.Context, int) {
	m.abort()
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel, m.busy = cancel, what
	return ctx, m.seq
}

// abort cancels the running operation and drops its answer.
func (m *Model) abort() {
	if m.cancel != nil {
		m.cancel()
	}
	m.cancel, m.busy = nil, ""
	m.seq++
}

// end marks the current operation answered.
func (m *Model) end() {
	if m.cancel != nil {
		m.cancel()
	}
	m.cancel, m.busy = nil, ""
}

func (m *Model) note(s string) { m.msg, m.isErr = s, false }

func (m *Model) fail(err error) { m.msg, m.isErr = "error: "+err.Error(), true }

func (m *Model) top() *list {
	if len(m.lists) == 0 {
		return nil
	}
	return m.lists[len(m.lists)-1]
}

func (m *Model) setFocus(f focus) {
	m.focus = f
	if f == onBar {
		m.bar.Focus()
		m.bar.CursorEnd()
	} else {
		m.bar.Blur()
	}
	if f != onPrompt {
		m.prompt.Blur()
	}
}

func (m *Model) onKey(k tea.KeyPressMsg) tea.Cmd {
	s := k.String()
	switch s {
	case "ctrl+c":
		m.abort()
		return tea.Quit
	case "ctrl+l":
		return nil // the renderer redraws every frame anyway
	}
	m.msg, m.isErr = "", false
	if m.showHelp {
		if s == "?" || s == "esc" || s == "q" {
			m.showHelp = false
		}
		return nil
	}
	switch {
	case m.focus == onPrompt:
		return m.promptKey(k)
	case m.focus == onBar:
		return m.barKey(k)
	case m.cert != nil:
		return m.certKey(k)
	}
	return m.listKey(k)
}

func (m *Model) barKey(k tea.KeyPressMsg) tea.Cmd {
	switch k.String() {
	case "enter":
		return m.submit()
	case "tab":
		return m.nextGroup()
	case "esc":
		if m.busy != "" {
			m.cancelRunning()
		} else if m.top() != nil {
			m.setFocus(onResults)
		}
		return nil
	}
	var cmd tea.Cmd
	m.bar, cmd = m.bar.Update(k)
	return cmd
}

// cancelRunning is Esc on a running operation.
func (m *Model) cancelRunning() {
	m.abort()
	m.note("cancelled")
}

// submit parses the bar and runs it as a new result; a malformed bar runs
// nothing and shows search's message.
func (m *Model) submit() tea.Cmd {
	text := m.bar.Value()
	q, err := query.ParseBar(text)
	if err != nil {
		m.fail(err)
		return nil
	}
	q.Group = m.group
	l := &list{text: text, q: q, marks: map[string]bool{}}
	m.lists, m.cert = []*list{l}, nil
	m.setFocus(onResults)
	m.refreshTable()
	return m.load(l, nil)
}

// load fetches a page of l: the first when after is nil.
func (m *Model) load(l *list, after *query.Cursor) tea.Cmd {
	ctx, seq := m.begin("searching")
	snap, sess, dirs, q, n, search, since := m.snap, m.o.Session, m.o.Dirs, l.q, m.pageSize, m.search, m.since
	return func() tea.Msg {
		start := time.Now()
		p, err := search(ctx, snap, sess, dirs, q, after, n)
		return pageMsg{seq: seq, l: l, after: after, p: p, asOf: snap.AsOf, took: since(start), err: err}
	}
}

func (m *Model) onPage(msg pageMsg) tea.Cmd {
	if msg.seq != m.seq {
		return nil // an answer to a query that was cancelled or replaced
	}
	m.end()
	if msg.err != nil {
		m.fail(msg.err)
		return nil
	}
	l := msg.l
	if msg.after == nil {
		l.rows, l.cursor, l.asOf, l.took = nil, 0, msg.asOf, msg.took
	}
	l.q, l.cols, l.next = msg.p.Query, msg.p.Columns, msg.p.Next
	l.rows = append(l.rows, msg.p.Rows...)
	if l != m.top() {
		return nil
	}
	m.group = l.q.Group
	m.refreshTable()
	return m.prefetch()
}

// prefetch requests the next page when the cursor nears the end of the
// loaded rows (amendment A4 §2.2).
func (m *Model) prefetch() tea.Cmd {
	l := m.top()
	if l == nil || l.next == nil || m.busy != "" || len(l.rows)-l.cursor > max(1, m.pageSize/4) {
		return nil
	}
	return m.load(l, l.next)
}

func (m *Model) listKey(k tea.KeyPressMsg) tea.Cmd {
	l := m.top()
	switch k.String() {
	case "q":
		m.abort()
		return tea.Quit
	case "?":
		m.showHelp = true
		return nil
	case "esc":
		switch {
		case m.busy != "":
			m.cancelRunning()
		case len(m.lists) > 1:
			return m.pop()
		default:
			m.setFocus(onBar)
		}
		return nil
	case "tab":
		return m.nextGroup()
	case "R":
		return m.repin()
	}
	if l == nil {
		return nil
	}
	switch k.String() {
	case "enter":
		return m.open()
	case "f":
		if l.q.Group != "certs" {
			m.note("f shows a certificate: use it on the certs group or in a certificate's detail")
			return nil
		}
		if row := m.selected(); row != nil {
			return m.openCert(certID(l, row), formText)
		}
		return nil
	case "space":
		if row := m.selected(); row != nil {
			key := l.key(row)
			if l.marks[key] {
				delete(l.marks, key)
			} else {
				l.marks[key] = true
			}
			m.markRow(l.cursor)
			m.table.MoveDown(1)
			m.moved()
		}
		return m.prefetch()
	case "e":
		m.ask(promptExport, fmt.Sprintf("ctvault-%s-commit%d.json", l.q.Group, m.snap.AsOf))
		return nil
	case "/":
		m.ask(promptFilter, l.q.Filter)
		return nil
	case "s":
		l.q.Sort = nextSort(l.q)
		return m.reload(l)
	}
	m.table, _ = m.table.Update(k)
	m.moved()
	return m.prefetch()
}

// moved follows the table's cursor.
func (m *Model) moved() {
	l := m.top()
	if l == nil || m.table.Cursor() == l.cursor {
		return
	}
	old := l.cursor
	l.cursor = m.table.Cursor()
	m.markRow(old)
	m.markRow(l.cursor)
}

func (m *Model) selected() []any {
	l := m.top()
	if l == nil || l.cursor < 0 || l.cursor >= len(l.rows) {
		return nil
	}
	return l.rows[l.cursor]
}

func certID(l *list, row []any) uint64 {
	id, _ := row[slices.Index(l.cols, "cert_id")].(uint64)
	return id
}

// reload re-runs l from its first page, keeping its marks.
func (m *Model) reload(l *list) tea.Cmd {
	l.rows, l.next, l.cursor = nil, nil, 0
	m.refreshTable()
	return m.load(l, nil)
}

// nextGroup is Tab: the next group, re-running the shown query.
func (m *Model) nextGroup() tea.Cmd {
	m.group = groups[(slices.Index(groups, m.group)+1)%len(groups)]
	l := m.top()
	if l == nil {
		return nil
	}
	l.q.Group, l.q.Sort, l.q.Fields = m.group, "", nil
	l.cols, l.marks = nil, map[string]bool{}
	return m.reload(l)
}

// nextSort is s: from the group's default, every column descending then
// ascending, in the group's order, and back to the default.
func nextSort(q query.Query) string {
	def := query.DefaultSort(q.Group)
	seq := []string{def}
	for _, c := range (&query.Query{Group: q.Group}).Columns() {
		for _, d := range []string{" desc", " asc"} {
			if c+d != def {
				seq = append(seq, c+d)
			}
		}
	}
	cur := q.Sort
	if cur == "" {
		cur = def
	}
	return seq[(slices.Index(seq, cur)+1)%len(seq)]
}

// open is Enter: a name's certificates, or a certificate's detail.
func (m *Model) open() tea.Cmd {
	l, row := m.top(), m.selected()
	if row == nil {
		return nil
	}
	switch l.q.Group {
	case "names":
		q := l.q
		q.Mode, q.Text, q.Group, q.Sort, q.Filter, q.Fields = query.ModeExact, fmt.Sprint(row[slices.Index(l.cols, "name")]), "certs", "", "", nil
		if slices.Equal(q.Kinds, defaultKinds) {
			q.Kinds = nil // the default, left out of the bar
		}
		nl := &list{text: q.Bar(), q: q, marks: map[string]bool{}}
		m.lists = append(m.lists, nl)
		m.group = "certs"
		m.bar.SetValue(nl.text)
		m.refreshTable()
		return m.load(nl, nil)
	case "certs":
		return m.openCert(certID(l, row), formDetail)
	}
	m.note("Enter opens a name's certificates or a certificate's detail; an issuance has none")
	return nil
}

// pop is Esc on a pushed list: back to the one under it, re-run if R
// re-pinned the snapshot since it loaded.
func (m *Model) pop() tea.Cmd {
	m.lists = m.lists[:len(m.lists)-1]
	l := m.top()
	m.group = l.q.Group
	m.bar.SetValue(l.text)
	if l.asOf != m.snap.AsOf {
		return m.reload(l)
	}
	m.refreshTable()
	return nil
}

// repin is R: the latest commit, for the shown list and what follows.
func (m *Model) repin() tea.Cmd {
	s, err := query.Open(m.o.Root, 0)
	if err != nil {
		m.fail(err)
		return nil
	}
	m.abort()
	m.certs.close()
	m.snap, m.cert = s, nil
	m.certs = newCertSource(s, m.o.Session, m.o.Dirs)
	m.note(fmt.Sprintf("re-pinned to commit %d", s.AsOf))
	if l := m.top(); l != nil {
		return m.reload(l)
	}
	return nil
}

// ask opens the prompt line.
func (m *Model) ask(k promptKind, value string) {
	m.pk = k
	m.prompt.Prompt = map[promptKind]string{promptFilter: "/ filter: ", promptExport: "export to: ", promptWrite: "write to: "}[k]
	m.prompt.SetWidth(max(1, m.w-len(m.prompt.Prompt)-1))
	m.prompt.SetValue(value)
	m.prompt.CursorEnd()
	m.prompt.Focus()
	m.setFocus(onPrompt)
}

func (m *Model) promptKey(k tea.KeyPressMsg) tea.Cmd {
	switch k.String() {
	case "esc":
		m.setFocus(onResults)
		return nil
	case "enter":
		v := m.prompt.Value()
		m.setFocus(onResults)
		switch m.pk {
		case promptFilter:
			l := m.top()
			l.q.Filter = strings.TrimSpace(v)
			return m.reload(l)
		case promptExport:
			return m.export(v)
		case promptWrite:
			m.write(v)
		}
		return nil
	}
	var cmd tea.Cmd
	m.prompt, cmd = m.prompt.Update(k)
	return cmd
}

// export is e: the marked rows, or every row, with A3 §5's metadata and the
// selection. An existing file is refused.
func (m *Model) export(path string) tea.Cmd {
	path = expand(strings.TrimSpace(path))
	format := strings.TrimPrefix(filepath.Ext(path), ".")
	if format != "md" && format != "json" && format != "csv" {
		m.fail(errors.New("an export path ends in .md, .json or .csv"))
		return nil
	}
	l := m.top()
	var sel []string
	what := "every row"
	if len(l.marks) > 0 {
		sel = slices.Sorted(maps.Keys(l.marks))
		what = strconv.Itoa(len(sel)) + " marked rows"
	}
	ctx, seq := m.begin("exporting")
	snap, sess, dirs, q := m.snap, m.o.Session, m.o.Dirs, l.q
	o := query.ExportOptions{Path: path, Format: format, Version: m.o.Version, Now: m.o.Now, Selection: sel}
	return func() tea.Msg {
		err := query.Export(ctx, snap, sess, dirs, q, o)
		return doneMsg{seq: seq, note: "exported " + what + " to " + path, err: err}
	}
}

// layout sizes the components to the terminal.
func (m *Model) layout() {
	m.bar.SetWidth(max(1, m.w-len(m.bar.Prompt)-1))
	m.prompt.SetWidth(max(1, m.w-len(m.prompt.Prompt)-1))
	m.table.SetHeight(max(2, m.h-8))
	m.table.SetWidth(m.w)
	m.vp.SetWidth(m.w)
	m.vp.SetHeight(max(1, m.h-4))
	m.refreshTable()
	if m.cert != nil {
		m.showCert()
	}
}

// certSource opens the vault reader on first use and serializes its use:
// commands run off the UI goroutine.
type certSource struct {
	mu     sync.Mutex
	s      *query.Snapshot
	sess   *query.Session
	dirs   []string
	f      *query.Fetcher
	closed bool
}

func newCertSource(s *query.Snapshot, sess *query.Session, dirs []string) *certSource {
	return &certSource{s: s, sess: sess, dirs: dirs}
}

func (c *certSource) with(fn func(*query.Fetcher) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return context.Canceled
	}
	if c.f == nil {
		f, err := query.NewFetcher(c.s, c.sess, c.dirs)
		if err != nil {
			return err
		}
		c.f = f
	}
	return fn(c.f)
}

func (c *certSource) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.f != nil {
		c.f.Close()
		c.f = nil
	}
	c.closed = true
}
