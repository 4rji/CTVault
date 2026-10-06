// Package query is CTVault's read path (spec §11, amendment A3): snapshots
// of the committed dataset, the reader's DuckDB session, search, fetch and
// export. search and explore share it, so the same query gives the same
// rows in both. Readers take no lock and never write to dataset/, state/
// or vault/.
package query

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/derive"
)

// ErrBuilding means a derived table the query needs is still being built.
var ErrBuilding = errors.New("being built: run `ctvault rebuild`")

// Snapshot is a reader's fixed view of the committed dataset (amendment A3
// §2.1): the committed batches up to AsOf, with the files their manifests
// list. Batches committed later, and files no manifest lists, are never
// read.
type Snapshot struct {
	Root    string
	AsOf    uint64            // the highest commit_seq included; 0 when nothing is committed
	Batches []commit.Manifest // by commit_seq
	Active  derive.Active
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

// Ready refuses a derived table ACTIVE.json does not mark complete: a
// partial table is never presented as complete (A2 §4.7).
func (s *Snapshot) Ready(t derive.Table) error {
	st, ok := s.Active.Tables[t.Name]
	if !ok || st.Status != derive.StatusComplete || st.Active == nil || *st.Active != t.Version {
		return fmt.Errorf("%s %w", t.Name, ErrBuilding)
	}
	return nil
}
