package verify_test

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/health"
	"github.com/4rji/ctvault/internal/lock"
	"github.com/4rji/ctvault/internal/querytest"
	"github.com/4rji/ctvault/internal/vault"
	. "github.com/4rji/ctvault/internal/verify"
)

var ctx = context.Background()

// template is a writer-built vault: 60 entries in 3 batches of 20.
func template(t *testing.T) string {
	t.Helper()
	g, es := querytest.Pairs(t, 60)
	return querytest.New(t, g, es, 20, 1000).Root
}

// fresh copies the template to a new root, as if the vault had always been
// there: views.sql, which names the root, is regenerated.
func fresh(t *testing.T, tmpl string) string {
	t.Helper()
	root := t.TempDir()
	err := filepath.WalkDir(tmpl, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(tmpl, p)
		dst := filepath.Join(root, rel)
		if d.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	a, _, err := derive.ReadActive(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dataset.WriteViews(root, a); err != nil {
		t.Fatal(err)
	}
	return root
}

func options(root string) Options {
	return Options{Root: root, VaultDirs: []string{filepath.Join(root, "vault")}}
}

func run(t *testing.T, o Options) *Report {
	t.Helper()
	r, err := Run(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// batchDirs are the committed batch directories in commit_seq order.
func batchDirs(t *testing.T, root string) []string {
	t.Helper()
	ms, err := commit.ListCommitted(root)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range ms {
		out = append(out, commit.Paths{Root: root}.BatchDir(m.ID()))
	}
	return out
}

// editManifest rewrites a batch's _COMMIT.json through fn, as raw JSON.
func editManifest(t *testing.T, dir string, fn func(m map[string]any)) {
	t.Helper()
	p := filepath.Join(dir, commit.ManifestFile)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	fn(m)
	if b, err = json.MarshalIndent(m, "", " "); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func flipByte(t *testing.T, p string, off int64) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if off < 0 {
		st, _ := f.Stat()
		off += st.Size()
	}
	b := []byte{0}
	f.ReadAt(b, off)
	b[0] ^= 0xff
	if _, err := f.WriteAt(b, off); err != nil {
		t.Fatal(err)
	}
}

func segments(t *testing.T, root string) []string {
	t.Helper()
	ps, _ := filepath.Glob(filepath.Join(root, "vault", "segments", "*.seg"))
	slices.Sort(ps)
	if len(ps) == 0 {
		t.Fatal("no segment")
	}
	return ps
}

// expectFail checks that the report is damaged and that check name failed
// with a problem mentioning want.
func expectFail(t *testing.T, r *Report, name, want string) {
	t.Helper()
	c := r.Check(name)
	if !r.Damaged() || c == nil || c.Status != StatusFail {
		t.Fatalf("check %q: %+v; damaged %v\n%s", name, c, r.Damaged(), text(r))
	}
	for _, p := range c.Problems {
		if strings.Contains(p, want) {
			return
		}
	}
	t.Fatalf("check %q has no problem mentioning %q: %q", name, want, c.Problems)
}

func text(r *Report) string {
	var b strings.Builder
	r.WriteText(&b)
	return b.String()
}

// TestQuickClean: a sound vault passes every quick check, exit 0, nothing
// pending; the report names each check (amendment A5 §1, §2.1).
func TestQuickClean(t *testing.T) {
	root := fresh(t, template(t))
	r := run(t, options(root))
	if r.Damaged() || r.Batches != 3 || r.AsOf != 3 || len(r.Pending) != 0 || len(r.Warnings) != 0 || r.Writer != "" {
		t.Fatalf("a sound vault:\n%s", text(r))
	}
	for _, name := range []string{"batches", "ids", "vault", "files", "tables", "sth signatures"} {
		if c := r.Check(name); c == nil || c.Status != StatusOK {
			t.Fatalf("check %q: %+v\n%s", name, c, text(r))
		}
	}
	if !strings.Contains(text(r), "ok      batches") {
		t.Fatalf("the text report:\n%s", text(r))
	}
	// --as-of: the first two batches.
	o := options(root)
	o.AsOf = 2
	if r := run(t, o); r.Damaged() || r.Batches != 2 || r.AsOf != 2 {
		t.Fatalf("as of commit 2:\n%s", text(r))
	}
	o.AsOf = 9
	if _, err := Run(ctx, o); err == nil {
		t.Fatal("--as-of past the last commit runs")
	}
}

// TestQuickFaults: one fault at a time, each in a fresh copy, fails its
// check and names what is wrong (amendment A5 §4.1).
func TestQuickFaults(t *testing.T) {
	tmpl := template(t)
	cases := []struct {
		name        string
		damage      func(t *testing.T, root string)
		check, want string
	}{
		{"a deleted _COMMIT.json", func(t *testing.T, root string) {
			os.Remove(filepath.Join(batchDirs(t, root)[1], commit.ManifestFile))
		}, "batches", "_COMMIT.json"},
		{"a malformed _COMMIT.json", func(t *testing.T, root string) {
			os.WriteFile(filepath.Join(batchDirs(t, root)[1], commit.ManifestFile), []byte("{"), 0o644)
		}, "batches", "_COMMIT.json"},
		{"a missing batch", func(t *testing.T, root string) {
			os.RemoveAll(batchDirs(t, root)[1])
		}, "batches", "gap"},
		{"a duplicate commit_seq", func(t *testing.T, root string) {
			editManifest(t, batchDirs(t, root)[2], func(m map[string]any) { m["commit_seq"] = 2 })
		}, "batches", "commit_seq 2"},
		{"a wrong merkle_after.size", func(t *testing.T, root string) {
			// 20 is 10100b; 24 (11000b) has as many nodes, so it parses.
			editManifest(t, batchDirs(t, root)[0], func(m map[string]any) { m["merkle_after"].(map[string]any)["size"] = 24 })
		}, "batches", "merkle_after"},
		{"overlapping cert_id ranges", func(t *testing.T, root string) {
			editManifest(t, batchDirs(t, root)[1], func(m map[string]any) {
				r := m["cert_id_range"].([]any)
				r[0] = r[0].(float64) - 5
			})
		}, "ids", "cert_id"},
		{"ID_FLOOR lowered", func(t *testing.T, root string) {
			os.WriteFile(filepath.Join(root, "state", "ID_FLOOR"), []byte("2\n"), 0o644)
		}, "ids", "ID_FLOOR"},
		{"a segment header byte flipped", func(t *testing.T, root string) {
			flipByte(t, segments(t, root)[0], 0)
		}, "vault", "segment 1"},
		{"a segment cut short", func(t *testing.T, root string) {
			s := segments(t, root)
			st, _ := os.Stat(s[len(s)-1])
			os.Truncate(s[len(s)-1], st.Size()-10)
		}, "vault", "committed tail"},
		{"a damaged dictionary", func(t *testing.T, root string) {
			dirs := []string{filepath.Join(root, "vault")}
			if _, err := vault.InstallDict(dirs, 7, []byte(strings.Repeat("dictionary ", 100)), vault.Training{}, time.Unix(0, 0)); err != nil {
				t.Fatal(err)
			}
			ps, _ := filepath.Glob(filepath.Join(root, "vault", "dict", "*7*"))
			for _, p := range ps {
				if !strings.HasSuffix(p, ".json") {
					os.Chmod(p, 0o644) // installed read-only
					flipByte(t, p, 3)
				}
			}
		}, "vault", "dictionar"},
		{"a batch's dictionary absent", func(t *testing.T, root string) {
			editManifest(t, batchDirs(t, root)[2], func(m map[string]any) { m["dictionary"].(map[string]any)["id"] = 99 })
		}, "vault", "dictionary 99"},
		{"a file resized", func(t *testing.T, root string) {
			f, _ := os.OpenFile(filepath.Join(batchDirs(t, root)[0], dataset.EntriesFile), os.O_APPEND|os.O_WRONLY, 0)
			f.Write([]byte{0})
			f.Close()
		}, "files", dataset.EntriesFile},
		{"a damaged _DERIVED.json", func(t *testing.T, root string) {
			dir := batchDirs(t, root)[0]
			id := filepath.Base(filepath.Dir(dir))[len("log="):] + "/" + filepath.Base(dir)[len("batch="):]
			if err := commit.WriteDerived(dir, commit.Derived{Format: commit.DerivedFormat, BatchID: id, Tables: map[string]commit.DerivedTable{}}); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(dir, commit.DerivedFile)
			b, _ := os.ReadFile(p)
			os.WriteFile(p, []byte(strings.Replace(string(b), `"format": 1`, `"format": 1 `, 1)), 0o644)
		}, "files", commit.DerivedFile},
		{"an invalid ACTIVE.json", func(t *testing.T, root string) {
			os.WriteFile(filepath.Join(root, "dataset", derive.ActiveFile), []byte(`{"seq": 1, "tables": {"certs": {"active": 7, "building": null, "status": "complete"}}}`), 0o644)
		}, "tables", derive.ActiveFile},
		{"an edited views.sql", func(t *testing.T, root string) {
			f, _ := os.OpenFile(filepath.Join(root, dataset.ViewsFile), os.O_APPEND|os.O_WRONLY, 0)
			f.Write([]byte("-- edited\n"))
			f.Close()
		}, "tables", dataset.ViewsFile},
		{"an STH signature flipped", func(t *testing.T, root string) {
			editManifest(t, batchDirs(t, root)[0], func(m map[string]any) {
				sth := m["sth"].(map[string]any)
				sig := []byte(sth["signature"].(string))
				sig[20] ^= 1
				if sig[20] == '+' || sig[20] == '/' || sig[20] == '=' {
					sig[20] = 'A'
				}
				sth["signature"] = string(sig)
			})
		}, "sth signatures", "signature"},
		{"vault bytes past the tail that nothing explains", func(t *testing.T, root string) {
			s := segments(t, root)
			f, _ := os.OpenFile(s[len(s)-1], os.O_APPEND|os.O_WRONLY, 0)
			f.Write(make([]byte, 100))
			f.Close()
		}, "vault", "beyond the committed tail"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := fresh(t, tmpl)
			c.damage(t, root)
			expectFail(t, run(t, options(root)), c.check, c.want)
		})
	}
}

// TestQuickNotDamage: what a stopped writer leaves is recovery pending,
// exit 0; audit failures are warnings; a running writer's work in flight
// is not judged (amendment A5 §1).
func TestQuickNotDamage(t *testing.T) {
	tmpl := template(t)
	root := fresh(t, tmpl)
	ms, err := commit.ListCommitted(root)
	if err != nil {
		t.Fatal(err)
	}
	last := ms[len(ms)-1]
	next := commit.BatchID{Log: "fakelog", First: last.Last + 1, Last: last.Last + 20}
	in := commit.Intent{BatchID: next.String(), Log: next.Log, First: next.First, Last: next.Last, VaultTail: last.Vault.End,
		NextCertID: last.NextCertID, MerkleBefore: last.MerkleAfter, StartedAt: time.Unix(1, 0).UTC()}
	if err := commit.WriteIntent(commit.Paths{Root: root}, in, nil); err != nil {
		t.Fatal(err)
	}
	s := segments(t, root)
	f, _ := os.OpenFile(s[len(s)-1], os.O_APPEND|os.O_WRONLY, 0)
	f.Write(make([]byte, 100))
	f.Close()
	os.MkdirAll(filepath.Join(root, "tmp", "stage", "leftover"), 0o755)
	if err := health.Record(filepath.Join(root, "state"), last.BatchID, last.CommitSeq,
		[]health.Failure{{Check: "sha256", Detail: "lookup missed"}}, time.Unix(2, 0).UTC()); err != nil {
		t.Fatal(err)
	}

	r := run(t, options(root))
	if r.Damaged() || len(r.Pending) != 3 || len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], "lookup missed") {
		t.Fatalf("a stopped writer's leftovers:\n%s", text(r))
	}
	for _, want := range []string{"intent", "past the committed tail", "tmp/stage/leftover"} {
		if !strings.Contains(strings.Join(r.Pending, "\n"), want) {
			t.Fatalf("pending lacks %q: %q", want, r.Pending)
		}
	}
	if !strings.Contains(text(r), "recovery pending") {
		t.Fatalf("the text report:\n%s", text(r))
	}

	// The same files while a writer holds the lock: its batch in flight.
	lk, err := lock.Acquire(filepath.Join(root, "state", "LOCK"))
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Release()
	r = run(t, options(root))
	if r.Damaged() || len(r.Pending) != 0 || !strings.Contains(r.Writer, "running") {
		t.Fatalf("a running writer:\n%s", text(r))
	}
}

// TestReportJSON: --json carries the same report.
func TestReportJSON(t *testing.T) {
	root := fresh(t, template(t))
	r := run(t, options(root))
	var back Report
	b, err := json.Marshal(r)
	if err != nil || json.Unmarshal(b, &back) != nil || back.Batches != 3 || len(back.Checks) != len(r.Checks) {
		t.Fatalf("JSON report %s (%v)", b, err)
	}
	r.WriteText(io.Discard)
}
