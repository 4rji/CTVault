package derive

import (
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/extract"
)

// certsV2 is a test-only certs v2: v1's columns and one more.
type certsV2 struct{}

func (certsV2) Table() Table {
	t := CertsV1
	t.Version = 2
	t.Columns = append(append([]Column{}, CertsV1.Columns...), Column{"v2_marker", "BOOLEAN"})
	return t
}

func (certsV2) Build(c *extract.Cert, ctx Context) []Row {
	rows := Certs{}.Build(c, ctx)
	for i := range rows {
		rows[i] = append(rows[i], true)
	}
	return rows
}

func withV2(t *testing.T) {
	t.Helper()
	t.Cleanup(SetRegistry([]Versions{{Current: certsV2{}, Previous: Certs{}}, {Current: Names{}}}))
}

func ptr2(v int) *int { return &v }

// TestRegistry: the registry gives each version's builder; Builders are the
// current versions.
func TestRegistry(t *testing.T) {
	withV2(t)
	if b := BuilderOf("certs", 1); b == nil || b.Table().Version != 1 {
		t.Fatalf("certs v1: %v", b)
	}
	if b := BuilderOf("certs", 2); b == nil || b.Table().Version != 2 || b.Table().File() != "certs.p2.parquet" {
		t.Fatalf("certs v2: %v", b)
	}
	if BuilderOf("certs", 3) != nil || BuilderOf("names", 2) != nil || BuilderOf("nope", 1) != nil {
		t.Fatal("a version the binary does not carry")
	}
	if len(Builders) != 2 || Builders[0].Table().Version != 2 {
		t.Fatalf("current builders: %v", Builders)
	}
}

// TestTransitionStates: Check accepts amendment A5 §7's states, Readable
// says which version readers use, and BuildVersions which versions a new
// batch builds.
func TestTransitionStates(t *testing.T) {
	withV2(t)
	at := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	names := TableState{Active: ptr2(1), Status: StatusComplete}
	cases := []struct {
		name     string
		certs    TableState
		ok       bool
		readable int   // 0: not readable
		build    []int // versions a new batch builds
	}{
		{"complete at N", TableState{Active: ptr2(2), Status: StatusComplete}, true, 2, []int{2}},
		{"complete at N-1, upgrade not started", TableState{Active: ptr2(1), Status: StatusComplete}, true, 1, []int{1}},
		{"upgrading", TableState{Active: ptr2(1), Building: ptr2(2), Status: StatusBuilding}, true, 1, []int{1, 2}},
		{"a new table", TableState{Building: ptr2(2), Status: StatusBuilding}, true, 0, []int{2}},
		{"mixed", TableState{Active: ptr2(1), Building: ptr2(2), Status: StatusMixed}, true, 0, []int{2}},
		{"retiring", TableState{Active: ptr2(2), Status: StatusComplete, Retiring: ptr2(1), SwitchedAt: &at}, true, 2, []int{2}},
		{"building the old version", TableState{Active: ptr2(2), Building: ptr2(1), Status: StatusBuilding}, false, 0, nil},
		{"an unknown version", TableState{Active: ptr2(3), Status: StatusComplete}, false, 0, nil},
		{"retiring the active version", TableState{Active: ptr2(2), Status: StatusComplete, Retiring: ptr2(2), SwitchedAt: &at}, false, 0, nil},
		{"retiring without its time", TableState{Active: ptr2(2), Status: StatusComplete, Retiring: ptr2(1)}, false, 0, nil},
		{"mixed with nothing active", TableState{Building: ptr2(2), Status: StatusMixed}, false, 0, nil},
	}
	for _, c := range cases {
		a := Active{Seq: 3, Tables: map[string]TableState{"certs": c.certs, "names": names}}
		err := a.Check()
		if (err == nil) != c.ok {
			t.Errorf("%s: Check %v", c.name, err)
			continue
		}
		if !c.ok {
			continue
		}
		v, ok := a.Readable("certs")
		if (c.readable != 0) != ok || (ok && v.Version != c.readable) {
			t.Errorf("%s: readable %+v %v, want version %d", c.name, v, ok, c.readable)
		}
		var got []int
		for _, tb := range a.BuildVersions("certs") {
			got = append(got, tb.Version)
		}
		if len(got) != len(c.build) || (len(got) > 0 && (got[0] != c.build[0] || got[len(got)-1] != c.build[len(c.build)-1])) {
			t.Errorf("%s: builds %v, want %v", c.name, got, c.build)
		}
	}
	// A binary without v1 refuses a vault still at v1: the release that
	// carries both must come first.
	t.Cleanup(SetRegistry([]Versions{{Current: certsV2{}}, {Current: Names{}}}))
	a := Active{Seq: 1, Tables: map[string]TableState{"certs": {Active: ptr2(1), Status: StatusComplete}, "names": names}}
	if err := a.Check(); err == nil {
		t.Fatal("a vault two versions behind is accepted")
	}
}
