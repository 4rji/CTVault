// Package query is CTVault's read path (spec §11, amendment A3): snapshots
// of the committed dataset, the reader's DuckDB session, search, fetch and
// export. search and explore share it, so the same query gives the same
// rows in both. Readers take no lock and never write to dataset/, state/
// or vault/.
package query

import (
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/derive"
)

// ErrBuilding means a derived table the query needs is still being built.
var ErrBuilding = errors.New("being built: run `ctvault rebuild`")

// ErrMixed means a derived table is mixed: an in-place rebuild is converting
// it batch by batch (amendment A5 §10).
var ErrMixed = errors.New("mixed")

// Snapshot is a reader's fixed view of the committed dataset (amendment A3
// §2.1): the committed batches up to AsOf, with the files their manifests
// list. Batches committed later, and files no manifest lists, are never
// read.
type Snapshot struct {
	Root    string
	AsOf    uint64            // the highest commit_seq included; 0 when nothing is committed
	Batches []commit.Manifest // by commit_seq
	Active  derive.Active
	Mixed   MixedRead // how a mixed table is read; the zero value refuses it
}

// MixedRead is how a reader reads a mixed table (amendment A5 §10): only
// the batches at ParserVersion (--parser-version, a partial result), or
// with Allow each batch's own version (--allow-mixed).
type MixedRead struct {
	ParserVersion int
	Allow         bool
}

// Open snapshots the vault at root. asOf 0 means the latest commit; any
// other value keeps the batches with commit_seq ≤ asOf.
func Open(root string, asOf uint64) (*Snapshot, error) {
	ms, err := commit.ListCommitted(root)
	if err != nil {
		return nil, err
	}
	a, _, err := derive.ReadActive(root)
	if err != nil {
		return nil, err
	}
	s := &Snapshot{Root: root, Active: a}
	for _, m := range ms {
		if asOf == 0 || m.CommitSeq <= asOf {
			s.Batches = append(s.Batches, m)
			s.AsOf = m.CommitSeq
		}
	}
	return s, nil
}

// Files returns the path of every listed file named name, in commit order.
func (s *Snapshot) Files(name string) []string {
	var out []string
	p := commit.Paths{Root: s.Root}
	for _, m := range s.Batches {
		if _, ok := m.Listed(name); ok {
			out = append(out, filepath.Join(p.BatchDir(m.ID()), name))
		}
	}
	return out
}

// Table returns the version of a derived table readers use: its active
// version, which every batch has (amendment A5 §7). A table with no active
// version yet is being built; a mixed one is refused (A2 §4.7: a partial
// table is never presented as complete).
func (s *Snapshot) Table(name string) (derive.Table, error) {
	if t, ok := s.Active.Readable(name); ok {
		return t, nil
	}
	st := s.Active.Tables[name]
	if st.Status != derive.StatusMixed {
		return derive.Table{}, fmt.Errorf("%s %w", name, ErrBuilding)
	}
	switch pv := s.Mixed.ParserVersion; {
	case pv != 0 && (pv == *st.Active || pv == *st.Building):
		return derive.Table{Name: name, Version: pv}, nil
	case pv != 0:
		return derive.Table{}, fmt.Errorf("%s is mixed between v%d and v%d; --parser-version %d names neither: %w", name, *st.Active, *st.Building, pv, ErrMixed)
	case s.Mixed.Allow:
		return derive.Table{Name: name, Version: *st.Building}, nil
	}
	counts := map[int]int{}
	for _, m := range s.Batches {
		for _, v := range []*int{st.Active, st.Building} {
			if v != nil {
				if _, ok := m.Listed(derive.Table{Name: name, Version: *v}.File()); ok {
					counts[*v]++
				}
			}
		}
	}
	return derive.Table{}, fmt.Errorf("%s is %w (v%d in %d batches, v%d in %d): an in-place rebuild is converting it; pass --parser-version %d or --allow-mixed",
		name, ErrMixed, *st.Active, counts[*st.Active], *st.Building, counts[*st.Building], *st.Building)
}

// batchFile is the file of a table this snapshot reads in batch m: the
// active version's, or for a mixed table the chosen version's (MixedRead).
func (s *Snapshot) batchFile(m commit.Manifest, name string) (string, bool) {
	var versions []int
	if t, ok := s.Active.Readable(name); ok {
		versions = []int{t.Version}
	} else if st := s.Active.Tables[name]; st.Status == derive.StatusMixed {
		switch {
		case s.Mixed.ParserVersion != 0:
			versions = []int{s.Mixed.ParserVersion}
		case s.Mixed.Allow:
			versions = []int{*st.Building, *st.Active}
		}
	}
	for _, v := range versions {
		f := derive.Table{Name: name, Version: v}.File()
		if _, ok := m.Listed(f); ok {
			return f, true
		}
	}
	return "", false
}

// TableFiles are the paths of a table's files this snapshot reads, in
// commit order.
func (s *Snapshot) TableFiles(name string) []string {
	if _, err := s.Table(name); err != nil {
		return nil
	}
	p := commit.Paths{Root: s.Root}
	var out []string
	for _, m := range s.Batches {
		if f, ok := s.batchFile(m, name); ok {
			out = append(out, filepath.Join(p.BatchDir(m.ID()), f))
		}
	}
	return out
}

// unionOpt is read_parquet's option for a table whose files may be of two
// versions: their columns are matched by name.
func (s *Snapshot) unionOpt(name string) string {
	if s.Active.Tables[name].Status == derive.StatusMixed && s.Mixed.Allow {
		return ", union_by_name = true"
	}
	return ""
}

// MixedNotes say how the mixed tables are read, for the user (amendment A5
// §10): "certs is mixed: reading only the 1 of 3 batches at v2".
func (s *Snapshot) MixedNotes() []string {
	var out []string
	for _, mt := range s.mixedReads() {
		if mt.Partial {
			out = append(out, fmt.Sprintf("%s is mixed: reading only the %d of %d batches at v%d (a partial result)", mt.Table, mt.Batches[fmt.Sprint(mt.ParserVersion)], len(s.Batches), mt.ParserVersion))
			continue
		}
		var parts []string
		for _, v := range slices.Sorted(maps.Keys(mt.Batches)) {
			parts = append(parts, fmt.Sprintf("v%s in %d batches", v, mt.Batches[v]))
		}
		out = append(out, fmt.Sprintf("%s is mixed: reading %s", mt.Table, strings.Join(parts, " and ")))
	}
	return out
}

// MixedTable is how a mixed table was read, for export metadata.
type MixedTable struct {
	Table         string         `json:"table"`
	ParserVersion int            `json:"parser_version,omitempty"`
	Partial       bool           `json:"partial"`
	Batches       map[string]int `json:"batches"` // version → batches read at it
}

func (s *Snapshot) mixedReads() []MixedTable {
	var out []MixedTable
	for _, name := range slices.Sorted(maps.Keys(s.Active.Tables)) {
		if s.Active.Tables[name].Status != derive.StatusMixed || (s.Mixed.ParserVersion == 0 && !s.Mixed.Allow) {
			continue
		}
		mt := MixedTable{Table: name, ParserVersion: s.Mixed.ParserVersion, Partial: s.Mixed.ParserVersion != 0, Batches: map[string]int{}}
		for _, m := range s.Batches {
			if f, ok := s.batchFile(m, name); ok {
				mt.Batches[strings.TrimSuffix(strings.TrimPrefix(f, name+".p"), ".parquet")]++
			}
		}
		out = append(out, mt)
	}
	return out
}
