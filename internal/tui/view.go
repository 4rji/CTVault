package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/table"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/query"
)

// The smallest terminal explore draws in (amendment A4 §4).
const minWidth, minHeight = 80, 24

// paneLines is the detail pane's height.
const paneLines = 3

var (
	errStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	ruleStyle = lipgloss.NewStyle().Faint(true)
)

// View draws the screen: the bar, the group line, the results or the
// certificate or help, and the status line.
func (m *Model) View() tea.View {
	v := tea.NewView(m.render())
	v.AltScreen = true
	v.WindowTitle = "ctvault explore"
	v.Cursor = m.cursorPos()
	return v
}

func (m *Model) small() bool { return m.w < minWidth || m.h < minHeight }

func (m *Model) render() string {
	if m.w == 0 {
		return ""
	}
	if m.small() {
		return fmt.Sprintf("explore needs a terminal of at least %d×%d; this one is %d×%d.\nEnlarge it, or press Ctrl-C to quit.", minWidth, minHeight, m.w, m.h)
	}
	var mid string
	switch {
	case m.showHelp:
		mid = fit(m.keys.view(), m.h-4)
	case m.cert != nil:
		mid = fit(m.vp.View(), m.h-4)
	default:
		mid = fit(m.table.View(), m.h-4-paneLines-1) + "\n" + rule("detail", m.w) + "\n" + fit(m.pane(), paneLines)
	}
	lines := strings.Split(strings.Join([]string{m.bar.View(), m.info(), mid, rule("", m.w), m.status()}, "\n"), "\n")
	for i, l := range lines {
		lines[i] = ansi.Truncate(l, m.w, "")
	}
	return strings.Join(lines, "\n")
}

func (m *Model) cursorPos() *tea.Cursor {
	if m.w == 0 || m.small() || m.showHelp {
		return nil
	}
	switch m.focus {
	case onBar:
		return m.bar.Cursor()
	case onPrompt:
		if c := m.prompt.Cursor(); c != nil {
			c.Y += m.h - 1
			return c
		}
	}
	return nil
}

// fit pads or cuts s to n lines.
func fit(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for len(lines) < n {
		lines = append(lines, "")
	}
	return strings.Join(lines[:n], "\n")
}

func rule(title string, w int) string {
	if title == "" {
		return ruleStyle.Render(strings.Repeat("─", w))
	}
	return ruleStyle.Render("─ " + title + " " + strings.Repeat("─", max(0, w-len(title)-3)))
}

// info is the line under the bar: the groups and the sort and filter, or
// the open certificate's forms.
func (m *Model) info() string {
	if cv := m.cert; cv != nil {
		forms := make([]string, len(formNames))
		for i, f := range formNames {
			forms[i] = f
			if form(i) == cv.form {
				forms[i] = "[" + f + "]"
			}
		}
		return fmt.Sprintf("certificate %d · %s · f switches · w writes it · Esc back", cv.id, strings.Join(forms, " "))
	}
	tabs := make([]string, len(groups))
	for i, g := range groups {
		tabs[i] = " " + g + " "
		if g == m.group {
			tabs[i] = "[" + g + "]"
		}
	}
	s := strings.Join(tabs, "")
	if l := m.top(); l != nil {
		sort := l.q.Sort
		if sort == "" {
			sort = query.DefaultSort(l.q.Group)
		}
		s += " · sort " + sort
		if l.q.Filter != "" {
			s += " · filter " + strconv.Quote(l.q.Filter)
		}
	}
	return s
}

// pane is the selected row in full: the table cuts long values.
func (m *Model) pane() string {
	l := m.top()
	if l == nil {
		return "Type a query and press Enter: a domain, or suffix:, exact:, ip:, contains: or regex:, then filters.\n" +
			"Tab switches names, certs and issuances; ? shows every key."
	}
	row := m.selected()
	if row == nil {
		if m.busy == "" && l.cols != nil {
			return "no rows"
		}
		return ""
	}
	parts := make([]string, len(l.cols))
	for i, c := range l.cols {
		parts[i] = c + " " + query.Render(row[i])
	}
	return wrap(parts, " · ", m.w)
}

// wrap joins parts with sep into lines of at most w columns, where it can.
func wrap(parts []string, sep string, w int) string {
	var lines []string
	cur := ""
	for _, p := range parts {
		switch {
		case cur == "":
			cur = p
		case ansi.StringWidth(cur+sep+p) <= w:
			cur += sep + p
		default:
			lines = append(lines, cur)
			cur = p
		}
	}
	return strings.Join(append(lines, cur), "\n")
}

func (m *Model) status() string {
	if m.focus == onPrompt {
		return m.prompt.View()
	}
	const right = "[?]help"
	var left string
	switch {
	case m.msg != "" && m.isErr:
		left = errStyle.Render(m.msg)
	case m.msg != "":
		left = m.msg
	case m.busy != "":
		left = m.busy + "… (Esc cancels)"
	case m.changed != "":
		left = m.changed
	default:
		left = m.counts()
	}
	room := m.w - len(right) - 1
	if ansi.StringWidth(left) > room {
		left = ansi.Truncate(left, room, "…")
	}
	return left + strings.Repeat(" ", m.w-ansi.StringWidth(left)-len(right)) + right
}

// counts is the status line at rest: rows, time, the derived tables, the
// snapshot.
func (m *Model) counts() string {
	var parts []string
	if l := m.top(); l != nil && l.cols != nil {
		n, unit := strconv.Itoa(l.total), l.q.Group
		if l.total == 1 {
			unit = strings.TrimSuffix(unit, "s")
		}
		parts = append(parts, n+" "+unit, fmt.Sprintf("%d ms", l.took.Milliseconds()))
		if len(l.marks) > 0 {
			parts = append(parts, fmt.Sprintf("%d marked", len(l.marks)))
		}
	}
	for _, name := range []string{derive.CertsV1.Name, derive.NamesV1.Name} {
		st := m.snap.Active.Tables[name]
		switch t, ok := m.snap.Active.Readable(name); {
		case ok && st.Building != nil:
			parts = append(parts, fmt.Sprintf("%s v%d ✓ (v%d building)", name, t.Version, *st.Building))
		case ok:
			parts = append(parts, fmt.Sprintf("%s v%d ✓", name, t.Version))
		default:
			parts = append(parts, name+" "+st.Status)
		}
	}
	parts = append(parts, fmt.Sprintf("as-of commit %d", m.snap.AsOf))
	return strings.Join(parts, " · ")
}

// The table: a marker column (the cursor and the mark), then the group's
// columns. Columns that do not fit are left out, the least useful first.

const markWidth = 2

type colSpec struct {
	width int
	flex  bool // grows into the room left
	prio  int  // 0 is never left out; the highest goes first
}

var colSpecs = map[string]colSpec{
	"name": {24, true, 0}, "first_seen": {10, false, 1}, "last_seen": {10, false, 1}, "certs": {5, false, 1}, "issuers": {12, true, 2},
	"sha256": {12, false, 0}, "cert_id": {9, false, 2}, "kind": {7, false, 1}, "issuer_cn": {14, true, 1},
	"not_before": {10, false, 3}, "not_after": {10, false, 2}, "names": {5, false, 3}, "logs": {10, true, 4},
	"issuance_key": {16, false, 0}, "precert": {7, false, 2}, "final": {5, false, 2},
}

const maxFlex = 60

func (m *Model) columns(cols []string) []table.Column {
	widths := make([]int, len(cols))
	for i, c := range cols {
		widths[i] = colSpecs[c].width
	}
	used := func() int {
		t := markWidth + 1
		for _, w := range widths {
			if w > 0 {
				t += w + 1 // the cell's right padding
			}
		}
		return t
	}
	for used() > m.w {
		drop := -1
		for i := len(cols) - 1; i >= 0; i-- {
			if p := colSpecs[cols[i]].prio; widths[i] > 0 && p > 0 && (drop < 0 || p > colSpecs[cols[drop]].prio) {
				drop = i
			}
		}
		if drop < 0 {
			break
		}
		widths[drop] = 0
	}
	for room := m.w - used(); room > 0; {
		grew := false
		for i, c := range cols {
			if room > 0 && widths[i] > 0 && colSpecs[c].flex && widths[i] < maxFlex {
				widths[i]++
				room--
				grew = true
			}
		}
		if !grew {
			break
		}
	}
	out := []table.Column{{Width: markWidth}}
	for i, c := range cols {
		out = append(out, table.Column{Title: strings.ToUpper(strings.ReplaceAll(c, "_", " ")), Width: widths[i]})
	}
	return out
}

// refreshTable rebuilds the table from the shown list.
func (m *Model) refreshTable() {
	l := m.top()
	group := m.group
	if l != nil {
		group = l.q.Group
	}
	cols := (&query.Query{Group: group}).Columns()
	if l != nil && l.cols != nil {
		cols = l.cols
	}
	m.table.SetRows(nil)
	m.table.SetColumns(m.columns(cols))
	if l == nil {
		return
	}
	rows := make([]table.Row, len(l.rows))
	for i := range l.rows {
		rows[i] = l.tableRow(i)
	}
	m.table.SetRows(rows)
	m.table.SetCursor(l.cursor)
}

// appendRows adds l's rows from i on to a table that shows the ones
// before: a page costs its own rows, not every row loaded so far.
func (m *Model) appendRows(l *list, i int) {
	rows := m.table.Rows()
	if len(rows) != i {
		m.refreshTable()
		return
	}
	for ; i < len(l.rows); i++ {
		rows = append(rows, l.tableRow(i))
	}
	m.table.SetRows(rows)
}

// tableRow is row i in the table: its marker, then its cells.
func (l *list) tableRow(i int) table.Row {
	row := make(table.Row, 0, len(l.rows[i])+1)
	row = append(row, l.marker(i))
	for _, v := range l.rows[i] {
		row = append(row, cell(v))
	}
	return row
}

// markRow redraws row i's marker.
func (m *Model) markRow(i int) {
	l, rows := m.top(), m.table.Rows()
	if l == nil || i < 0 || i >= len(rows) {
		return
	}
	rows[i][0] = l.marker(i)
	m.table.SetRows(rows)
}

func (l *list) marker(i int) string {
	s := " "
	if i == l.cursor {
		s = "▸"
	}
	if l.marks[l.key(l.rows[i])] {
		return s + "●"
	}
	return s + " "
}

// cell is a value in the table: dates without the time, booleans as yes
// or no. The pane shows values in full.
func cell(v any) string {
	switch x := v.(type) {
	case time.Time:
		return x.UTC().Format("2006-01-02")
	case bool:
		if x {
			return "yes"
		}
		return "no"
	}
	return query.Render(v)
}

func tableStyles() table.Styles {
	return table.Styles{
		Header:   lipgloss.NewStyle().Bold(true).Padding(0, 1, 0, 0),
		Cell:     lipgloss.NewStyle().Padding(0, 1, 0, 0),
		Selected: lipgloss.NewStyle().Reverse(true),
	}
}

// Keys. Space, f, b, u and d are explore's, not the table's or the
// viewport's.

func tableKeys() table.KeyMap {
	return table.KeyMap{
		LineUp:       key.NewBinding(key.WithKeys("up", "k")),
		LineDown:     key.NewBinding(key.WithKeys("down", "j")),
		PageUp:       key.NewBinding(key.WithKeys("pgup")),
		PageDown:     key.NewBinding(key.WithKeys("pgdown")),
		HalfPageUp:   key.NewBinding(key.WithKeys("ctrl+u")),
		HalfPageDown: key.NewBinding(key.WithKeys("ctrl+d")),
		GotoTop:      key.NewBinding(key.WithKeys("home", "g")),
		GotoBottom:   key.NewBinding(key.WithKeys("end", "G")),
	}
}

func viewportKeys() viewport.KeyMap {
	return viewport.KeyMap{
		PageDown:     key.NewBinding(key.WithKeys("pgdown")),
		PageUp:       key.NewBinding(key.WithKeys("pgup")),
		HalfPageUp:   key.NewBinding(key.WithKeys("ctrl+u")),
		HalfPageDown: key.NewBinding(key.WithKeys("ctrl+d")),
		Up:           key.NewBinding(key.WithKeys("up", "k")),
		Down:         key.NewBinding(key.WithKeys("down", "j")),
		Left:         key.NewBinding(key.WithKeys("left", "h")),
		Right:        key.NewBinding(key.WithKeys("right", "l")),
	}
}

// keyMap is the help screen's content (amendment A4 §3).
type keyMap struct {
	Enter, Tab, Esc, Move, Fetch, Write, Mark, Export, Filter, Sort, Repin, Help, Quit key.Binding
}

func newKeys() keyMap {
	b := func(keys, desc string) key.Binding {
		return key.NewBinding(key.WithKeys(keys), key.WithHelp(keys, desc))
	}
	return keyMap{
		Enter:  b("enter", "run the query; open a name's certs or a cert"),
		Tab:    b("tab", "names, certs, issuances"),
		Esc:    b("esc", "cancel; close; edit the query"),
		Move:   b("↑↓ pgup pgdn g G", "move"),
		Fetch:  b("f", "certificate: detail, text, PEM"),
		Write:  b("w", "write the shown certificate"),
		Mark:   b("space", "mark a row"),
		Export: b("e", "export the marked rows, or all"),
		Filter: b("/", "filter the whole result"),
		Sort:   b("s", "sort: next column and direction"),
		Repin:  b("R", "re-pin to the latest commit"),
		Help:   b("?", "help"),
		Quit:   b("q ctrl+c", "quit"),
	}
}

// view lists every key, one per line.
func (k keyMap) view() string {
	var b strings.Builder
	b.WriteString("Keys (? or Esc closes this)\n\n")
	for _, kb := range []key.Binding{k.Enter, k.Tab, k.Esc, k.Move, k.Fetch, k.Write, k.Mark, k.Export, k.Filter, k.Sort, k.Repin, k.Help, k.Quit} {
		fmt.Fprintf(&b, "  %-18s %s\n", kb.Help().Key, kb.Help().Desc)
	}
	b.WriteString("\nThe bar: a domain, or suffix:, exact:, ip:, contains: or regex:, then filters:\n" +
		"  issuer: org: issued-by: key: kind: status: valid-at: wildcard log: since: until: by:not-before\n" +
		"  Values with spaces go in double quotes: issuer:\"Let's Encrypt\"\n")
	return b.String()
}
