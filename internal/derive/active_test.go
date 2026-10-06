package derive

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestActiveStates(t *testing.T) {
	c, u := Complete(), Upgrading()
	for _, b := range Builders {
		tb := b.Table()
		if s := c.Tables[tb.Name]; s.Active == nil || *s.Active != tb.Version || s.Building != nil || s.Status != StatusComplete {
			t.Errorf("Complete %s: %+v", tb.Name, s)
		}
		if s := u.Tables[tb.Name]; s.Active != nil || s.Building == nil || *s.Building != tb.Version || s.Status != StatusBuilding {
			t.Errorf("Upgrading %s: %+v", tb.Name, s)
		}
	}
	if c.Seq != 1 || u.Seq != 1 || !c.AllComplete() || u.AllComplete() {
		t.Errorf("seq %d %d, complete %v %v", c.Seq, u.Seq, c.AllComplete(), u.AllComplete())
	}
}

func TestActiveRoundTrip(t *testing.T) {
	root := t.TempDir()
	if _, ok, err := ReadActive(root); ok || err != nil {
		t.Fatalf("missing ACTIVE.json: %v %v", ok, err)
	}
	if err := WriteActive(root, Upgrading()); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(filepath.Join(root, "dataset", ActiveFile))
	if err := WriteActive(root, Upgrading()); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(filepath.Join(root, "dataset", ActiveFile))
	if string(first) != string(second) {
		t.Fatal("ACTIVE.json is not deterministic")
	}
	a, ok, err := ReadActive(root)
	if !ok || err != nil || a.AllComplete() || *a.Tables["certs"].Building != 1 {
		t.Fatalf("read back %+v %v %v", a, ok, err)
	}
}

// TestActiveCheck: a binary refuses an ACTIVE.json it cannot honour (spec
// §7.5): a version or a table it does not know, or one it lacks.
func TestActiveCheck(t *testing.T) {
	two := 2
	for name, edit := range map[string]func(*Active){
		"unknown version": func(a *Active) { s := a.Tables["certs"]; s.Active = &two; a.Tables["certs"] = s },
		"unknown table":   func(a *Active) { a.Tables["cert_policies"] = a.Tables["certs"] },
		"missing table":   func(a *Active) { delete(a.Tables, "names") },
		"unknown status":  func(a *Active) { s := a.Tables["names"]; s.Status = "mixed"; a.Tables["names"] = s },
		"nothing active or building": func(a *Active) {
			s := a.Tables["names"]
			s.Active, s.Building = nil, nil
			a.Tables["names"] = s
		},
	} {
		a := Complete()
		edit(&a)
		if err := a.Check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := Complete().Check(); err != nil {
		t.Error(err)
	}
	if err := Upgrading().Check(); err != nil {
		t.Error(err)
	}
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "dataset"), 0o755)
	os.WriteFile(filepath.Join(root, "dataset", ActiveFile), []byte("{"), 0o644)
	if _, _, err := ReadActive(root); err == nil || !strings.Contains(err.Error(), ActiveFile) {
		t.Errorf("unreadable ACTIVE.json: %v", err)
	}
}
