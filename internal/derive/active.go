package derive

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/4rji/ctvault/internal/fsutil"
)

// ActiveFile is dataset/ACTIVE.json (spec §4.3, §7.8): which version of each
// derived table is active and which is being built.
const ActiveFile = "ACTIVE.json"

// Table statuses.
const (
	StatusComplete = "complete" // every committed batch has the active version
	StatusBuilding = "building" // a version is being built; only <table>_building is exposed
)

// TableState is one table's entry in ACTIVE.json.
type TableState struct {
	Active   *int   `json:"active"`
	Building *int   `json:"building"`
	Status   string `json:"status"`
}

// Active is ACTIVE.json.
type Active struct {
	Seq    uint64                `json:"seq"`
	Tables map[string]TableState `json:"tables"`
}

func ptr(v int) *int { return &v }

// Complete is a vault whose every derived table is active at this binary's
// version: a new vault (amendment A2 §4.6).
func Complete() Active {
	a := Active{Seq: 1, Tables: map[string]TableState{}}
	for _, b := range Builders {
		a.Tables[b.Table().Name] = TableState{Active: ptr(b.Table().Version), Status: StatusComplete}
	}
	return a
}

// Upgrading is a vault written before its derived tables existed: every
// table is building at this binary's version, with nothing active yet.
func Upgrading() Active {
	a := Active{Seq: 1, Tables: map[string]TableState{}}
	for _, b := range Builders {
		a.Tables[b.Table().Name] = TableState{Building: ptr(b.Table().Version), Status: StatusBuilding}
	}
	return a
}

// AllComplete reports whether every table is complete.
func (a Active) AllComplete() bool {
	for _, s := range a.Tables {
		if s.Status != StatusComplete {
			return false
		}
	}
	return len(a.Tables) > 0
}

// Check refuses an ACTIVE.json this binary cannot honour (spec §7.5): a table
// or a version it does not know, a table it lacks, or an unknown status.
func (a Active) Check() error {
	known := map[string]Table{}
	for _, b := range Builders {
		known[b.Table().Name] = b.Table()
		if _, ok := a.Tables[b.Table().Name]; !ok {
			return fmt.Errorf("%s lacks table %s", ActiveFile, b.Table().Name)
		}
	}
	for name, s := range a.Tables {
		tb, ok := known[name]
		if !ok {
			return fmt.Errorf("%s names table %s, which this binary does not build: upgrade ctvault", ActiveFile, name)
		}
		for _, v := range []*int{s.Active, s.Building} {
			if v != nil && *v != tb.Version {
				return fmt.Errorf("%s names %s version %d; this binary builds version %d", ActiveFile, name, *v, tb.Version)
			}
		}
		switch {
		case s.Status == StatusComplete && s.Active != nil && s.Building == nil:
		case s.Status == StatusBuilding && s.Building != nil:
		default:
			return fmt.Errorf("%s: table %s has an inconsistent state %+v", ActiveFile, name, s)
		}
	}
	return nil
}

// ReadActive reads dataset/ACTIVE.json; ok is false when it does not exist.
func ReadActive(root string) (a Active, ok bool, err error) {
	b, err := os.ReadFile(filepath.Join(root, "dataset", ActiveFile))
	if errors.Is(err, fs.ErrNotExist) {
		return a, false, nil
	}
	if err != nil {
		return a, false, err
	}
	if err := json.Unmarshal(b, &a); err != nil {
		return a, false, fmt.Errorf("%s: %w", ActiveFile, err)
	}
	return a, true, nil
}

// WriteActive replaces dataset/ACTIVE.json atomically. The JSON is
// deterministic: map keys are sorted.
func WriteActive(root string, a Active) error {
	b, err := json.MarshalIndent(a, "", " ")
	if err != nil {
		return err
	}
	dir := filepath.Join(root, "dataset")
	if err := fsutil.MkdirAllSync(dir, 0o755); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(dir, ActiveFile), append(b, '\n'), 0o644)
}
