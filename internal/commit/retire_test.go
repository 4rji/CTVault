package commit_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/querytest"
)

// TestRetire: a retired derived file is recorded in _DERIVED.json, then
// deleted; it is no longer part of its batch, so the listing does not
// look for it; a crash between the two steps leaves a file recovery
// deletes (amendment A5 §9).
func TestRetire(t *testing.T) {
	g, es := querytest.Pairs(t, 60)
	v := querytest.New(t, g, es, 20, 1000)
	p := commit.Paths{Root: v.Root}
	ms, err := commit.ListCommitted(v.Root)
	if err != nil {
		t.Fatal(err)
	}
	var hooks []string
	m, err := commit.Retire(p, ms[0], []string{"names.p1.parquet"}, "test", func(h string) { hooks = append(hooks, h) })
	if err != nil {
		t.Fatal(err)
	}
	dir := p.BatchDir(ms[0].ID())
	if _, err := os.Stat(filepath.Join(dir, "names.p1.parquet")); !os.IsNotExist(err) {
		t.Fatalf("the retired file is still there: %v", err)
	}
	if _, ok := m.Listed("names.p1.parquet"); ok || m.Derived == nil || !slices.Equal(m.Derived.Retired, []string{"names.p1.parquet"}) {
		t.Fatalf("the manifest still lists it: %+v", m.Derived)
	}
	if !slices.Equal(hooks, []string{commit.HookRetireRecorded}) {
		t.Fatalf("hooks %v", hooks)
	}
	again, err := commit.ListCommitted(v.Root)
	if err != nil {
		t.Fatalf("listing after a retirement: %v", err)
	}
	if _, ok := again[0].Listed("names.p1.parquet"); ok {
		t.Fatal("the listing still counts the retired file")
	}
	if _, ok := again[0].Listed("certs.p1.parquet"); !ok {
		t.Fatal("a file that was not retired left the batch")
	}
	// Retiring it again, or a file already retired with another, keeps
	// one sorted list.
	if m, err = commit.Retire(p, again[0], []string{"certs.p1.parquet", "names.p1.parquet"}, "test", nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.Derived.Retired, []string{"certs.p1.parquet", "names.p1.parquet"}) {
		t.Fatalf("retired %v", m.Derived.Retired)
	}

	// A crash after the record, before the delete, leaves the file on
	// disk: recovery deletes it.
	f := filepath.Join(p.BatchDir(ms[1].ID()), "names.p1.parquet")
	b, _ := os.ReadFile(f)
	if _, err := commit.Retire(p, ms[1], []string{"names.p1.parquet"}, "test", nil); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(f, b, 0o644)
	querytest.Open(t, v, 1000).Close()
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Fatalf("recovery left the retired file: %v", err)
	}
}
