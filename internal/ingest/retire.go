package ingest

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/derive"
)

// RetireGrace is how long a replaced version's files stay after a switch,
// so that running explore sessions can reload (spec §7.8).
const RetireGrace = 24 * time.Hour

// RetireStats is what a retirement removed.
type RetireStats struct {
	Files  int
	Bytes  int64
	Tables []string // "certs v1", the versions retired
}

// RetireOld retires, in every committed batch, the derived files of
// versions that are neither active nor being built (amendment A5 §9),
// through commit.Retire: the batch's _DERIVED.json records them, then they
// are deleted. Without force (update and rebuild) it waits until RetireGrace
// has passed since a table's switch; with force (gc) it retires at once.
// When no batch holds a table's retiring version any more, ACTIVE.json
// drops retiring and switched_at.
func (w *Writer) RetireOld(force bool) (RetireStats, error) {
	var st RetireStats
	now := w.o.Now()
	keep := map[string]map[int]bool{} // table → versions that stay
	for _, bl := range derive.Builders {
		name := bl.Table().Name
		s := w.active.Tables[name]
		if !force && (s.Retiring == nil || now.Sub(*s.SwitchedAt) < RetireGrace) {
			continue
		}
		keep[name] = map[int]bool{}
		for _, v := range []*int{s.Active, s.Building} {
			if v != nil {
				keep[name][*v] = true
			}
		}
	}
	if len(keep) == 0 {
		return st, nil
	}
	retired := map[string]bool{}
	for i, m := range w.committed {
		var names []string
		var bytes int64
		for _, f := range listedDerived(m) {
			table, version, ok := parseDerivedFile(f)
			if vs, judged := keep[table]; !ok || !judged || vs[version] {
				continue
			}
			fi, _ := m.Listed(f)
			names, bytes = append(names, f), bytes+fi.Bytes
			retired[fmt.Sprintf("%s v%d", table, version)] = true
		}
		if len(names) == 0 {
			continue
		}
		nm, err := commit.Retire(w.paths, m, names, w.o.Version, w.o.Hook)
		if err != nil {
			return st, fmt.Errorf("retiring %s of batch %s: %w", strings.Join(names, ", "), m.BatchID, err)
		}
		w.committed[i] = nm
		st.Files += len(names)
		st.Bytes += bytes
	}
	st.Tables = slices.Sorted(maps.Keys(retired))
	next := derive.Active{Seq: w.active.Seq + 1, Tables: maps.Clone(w.active.Tables)}
	changed := false
	for name := range keep {
		if s := next.Tables[name]; s.Retiring != nil {
			s.Retiring, s.SwitchedAt = nil, nil
			next.Tables[name] = s
			changed = true
		}
	}
	if changed {
		if err := derive.WriteActive(w.o.Root, next); err != nil {
			return st, err
		}
		w.active = next
	}
	if st.Files > 0 {
		w.logf("retired %d files (%s), %s freed", st.Files, strings.Join(st.Tables, ", "), human(uint64(st.Bytes)))
		if _, err := dataset.WriteViews(w.o.Root, w.active); err != nil {
			return st, err
		}
	}
	return st, nil
}

// listedDerived are the derived files a batch lists.
func listedDerived(m commit.Manifest) []string {
	var out []string
	for name := range m.Files {
		if commit.IsDerivedFile(name) && !m.Retired(name) {
			out = append(out, name)
		}
	}
	if m.Derived != nil {
		for _, t := range m.Derived.Tables {
			out = append(out, t.File)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// parseDerivedFile splits "certs.p2.parquet" into its table and version.
func parseDerivedFile(name string) (string, int, bool) {
	base, ok := strings.CutSuffix(name, ".parquet")
	i := strings.LastIndex(base, ".p")
	if !ok || i <= 0 {
		return "", 0, false
	}
	v, err := strconv.Atoi(base[i+2:])
	return base[:i], v, err == nil
}
