package derive

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/4rji/ctvault/internal/fsutil"
)

// ActiveFile is dataset/ACTIVE.json (spec §4.3, §7.8): which version of each
// derived table is active and which is being built.
const ActiveFile = "ACTIVE.json"

// Table statuses.
const (
	StatusComplete = "complete" // every committed batch has the active version
	StatusBuilding = "building" // a version is being built: exposed as <table>_building, beside the active one if any
	StatusMixed    = "mixed"    // an in-place rebuild: each batch has one version or the other (amendment A5 §10)
)

// TableState is one table's entry in ACTIVE.json.
type TableState struct {
	Active   *int   `json:"active"`
	Building *int   `json:"building"`
	Status   string `json:"status"`
	// Retiring is the version a switch replaced, whose files remain until
	// they are retired, and SwitchedAt the switch's time (amendment A5 §9).
	Retiring   *int       `json:"retiring,omitempty"`
	SwitchedAt *time.Time `json:"switched_at,omitempty"`
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

// Check refuses an ACTIVE.json this binary cannot honour (spec §7.5,
// amendment A5 §7): a table it does not carry or lacks, a version it does
// not carry, or a state that is not one of these:
//
//	complete   active N or N−1, nothing building (with retiring < active
//	           and its switch time while old files remain)
//	building   active N−1 and building N (an upgrade), or building N alone
//	           (a new table)
//	mixed      active N−1 and building N (an in-place rebuild)
//
// N is the binary's current version and N−1 its previous one, if it
// carries one: a vault older than that needs the release in between.
func (a Active) Check() error {
	for _, b := range Builders {
		if _, ok := a.Tables[b.Table().Name]; !ok {
			return fmt.Errorf("%s lacks table %s", ActiveFile, b.Table().Name)
		}
	}
	for name, s := range a.Tables {
		cur, prev, ok := versions(name)
		if !ok {
			return fmt.Errorf("%s names table %s, which this binary does not build: upgrade ctvault", ActiveFile, name)
		}
		known := func(v *int) bool { return v == nil || *v == cur || (prev != 0 && *v == prev) }
		if !known(s.Active) || !known(s.Building) {
			return fmt.Errorf("%s names %s version %s; this binary carries %s: upgrade ctvault, through the release in between if the vault is older",
				ActiveFile, name, versionList(s.Active, s.Building), versionList(&cur, intOrNil(prev)))
		}
		valid := false
		switch s.Status {
		case StatusComplete:
			valid = s.Active != nil && s.Building == nil &&
				(s.Retiring == nil) == (s.SwitchedAt == nil) && (s.Retiring == nil || *s.Retiring < *s.Active)
		case StatusBuilding:
			valid = s.Building != nil && *s.Building == cur && (s.Active == nil || *s.Active < cur) && s.Retiring == nil
		case StatusMixed:
			valid = s.Active != nil && s.Building != nil && *s.Building == cur && *s.Active < cur && s.Retiring == nil
		}
		if !valid {
			return fmt.Errorf("%s: table %s has an inconsistent state %s", ActiveFile, name, describe(s))
		}
	}
	return nil
}

func intOrNil(v int) *int {
	if v == 0 {
		return nil
	}
	return &v
}

func versionList(vs ...*int) string {
	var out []string
	for _, v := range vs {
		if v != nil {
			out = append(out, fmt.Sprintf("v%d", *v))
		}
	}
	return strings.Join(out, " and ")
}

func describe(s TableState) string {
	f := func(v *int) string {
		if v == nil {
			return "null"
		}
		return fmt.Sprint(*v)
	}
	return fmt.Sprintf("{active %s, building %s, status %q, retiring %s}", f(s.Active), f(s.Building), s.Status, f(s.Retiring))
}

// Readable returns the version of a table readers use: its active version,
// unless it has none or is mixed (amendment A5 §7).
func (a Active) Readable(name string) (Table, bool) {
	s, ok := a.Tables[name]
	if !ok || s.Active == nil || s.Status == StatusMixed {
		return Table{}, false
	}
	return tableAt(name, *s.Active), true
}

// BuildVersions are the versions of a table a new batch builds: the active
// and the building one, or only the building one while mixed (amendment A5
// §8, §10).
func (a Active) BuildVersions(name string) []Table {
	s, ok := a.Tables[name]
	if !ok {
		return nil
	}
	var out []Table
	if s.Active != nil && s.Status != StatusMixed {
		out = append(out, tableAt(name, *s.Active))
	}
	if s.Building != nil {
		out = append(out, tableAt(name, *s.Building))
	}
	return out
}

// tableAt is a version's table definition: the builder's when the binary
// carries it, else the name and version alone (enough for its file name).
func tableAt(name string, version int) Table {
	if b := BuilderOf(name, version); b != nil {
		return b.Table()
	}
	return Table{Name: name, Version: version}
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
