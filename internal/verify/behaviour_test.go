package verify_test

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/lock"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/querytest"
	"github.com/4rji/ctvault/internal/vault"
	. "github.com/4rji/ctvault/internal/verify"
)

// TestMoreFaults: the faults that no other case isolates: a vault span
// that does not follow the last, a certs row's SHA-256, a cert_id that does
// not increase, and a batch rewritten consistently that its signed head
// disproves (amendment A5 §2.1-2.3).
func TestMoreFaults(t *testing.T) {
	tmpl := template(t)
	cases := []struct {
		name        string
		full        bool
		damage      func(t *testing.T, root string)
		check, want string
	}{
		{"a vault span that does not follow", false, func(t *testing.T, root string) {
			editManifest(t, batchDirs(t, root)[1], func(m map[string]any) {
				st := m["vault"].(map[string]any)["start"].(map[string]any)
				st["offset"] = st["offset"].(float64) + 10
			})
		}, "vault", "vault span"},
		{"a certs row with another SHA-256", true, func(t *testing.T, root string) {
			rewrite(t, batchDirs(t, root)[1], "certs.p1.parquet",
				`SELECT * REPLACE (CASE WHEN cert_id = (SELECT min(cert_id) FROM {f}) THEN repeat('0', 64) ELSE sha256 END AS sha256) FROM {f}`)
		}, "records", "SHA-256"},
		{"a cert_id that does not increase", true, func(t *testing.T, root string) {
			ms, _ := commit.ListCommitted(root)
			var locs []vault.Loc
			var recs []vault.Record
			vault.Scan([]string{filepath.Join(root, "vault")}, ms[1].Vault.Start, ms[1].Vault.End, func(l vault.Loc, r vault.Record) error {
				locs, recs = append(locs, l), append(recs, r)
				if len(locs) == 2 {
					return errors.New("two")
				}
				return nil
			})
			r := recs[1]
			r.CertID = recs[0].CertID
			b := vault.AppendRecord(nil, r)
			if len(b) != int(locs[1].Len) {
				t.Fatalf("the rewritten record is %d bytes, not %d", len(b), locs[1].Len)
			}
			f, _ := os.OpenFile(segmentPath(root, locs[1].Segment), os.O_WRONLY, 0)
			f.WriteAt(b, int64(locs[1].Offset))
			f.Close()
		}, "records", "increase"},
		{"a consistent rewrite the signed head disproves", true, func(t *testing.T, root string) {
			dirs := batchDirs(t, root)
			rewrite(t, dirs[2], dataset.EntriesFile, `SELECT * REPLACE (CASE WHEN idx = 45 THEN unhex(sha256('forged')) ELSE leaf_hash END AS leaf_hash) FROM {f}`)
			// merkle_after now matches the forged leaves, as a careful forger
			// would write it; only the signed head can tell.
			db, _ := sql.Open("duckdb", "")
			defer db.Close()
			files := make([]string, len(dirs))
			for i, d := range dirs {
				files[i] = "'" + filepath.Join(d, dataset.EntriesFile) + "'"
			}
			rows, err := db.Query(`SELECT leaf_hash FROM read_parquet([` + strings.Join(files, ", ") + `]) ORDER BY idx`)
			if err != nil {
				t.Fatal(err)
			}
			st := merkle.NewState()
			for rows.Next() {
				var h []byte
				rows.Scan(&h)
				st.Append([32]byte(h))
			}
			rows.Close()
			b, _ := st.MarshalJSON()
			var after any
			json.Unmarshal(b, &after)
			editManifest(t, dirs[2], func(m map[string]any) { m["merkle_after"] = after })
		}, "sth roots", "signed head"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := fresh(t, tmpl)
			c.damage(t, root)
			o := options(root)
			if c.full {
				o = fullOptions(t, root)
			}
			expectFail(t, run(t, o), c.check, c.want)
		})
	}
}

// tree maps every file under root, but tmp/, to its SHA-256.
func tree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if rel == "tmp" {
			return filepath.SkipDir
		}
		if !d.IsDir() {
			b, _ := os.ReadFile(p)
			sum := sha256.Sum256(b)
			out[rel] = hex.EncodeToString(sum[:])
		}
		return nil
	})
	return out
}

func diff(before, after map[string]string, allowed ...string) []string {
	var out []string
	for p, s := range after {
		if before[p] != s && !contains(allowed, p) {
			out = append(out, p)
		}
	}
	for p := range before {
		if _, ok := after[p]; !ok {
			out = append(out, p+" (removed)")
		}
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// TestReadOnly: verify changes no file outside tmp/. Only the index phase
// writes, to the lock files: state/LOCK records verify's PID while it
// holds the lock, and Pebble re-creates its empty LOCK (amendment A5 §1).
func TestReadOnly(t *testing.T) {
	root := fresh(t, template(t))
	before := tree(t, root)
	if r := run(t, options(root)); r.Damaged() {
		t.Fatal(text(r))
	}
	if d := diff(before, tree(t, root)); len(d) != 0 {
		t.Fatalf("verify --quick changed %v", d)
	}
	if r := run(t, fullOptions(t, root)); r.Damaged() || r.Check("index").Status != StatusOK {
		t.Fatal(text(r))
	}
	if d := diff(before, tree(t, root), filepath.Join("state", "LOCK")); len(d) != 0 {
		t.Fatalf("verify --full changed %v", d)
	}
	lk, err := lock.Acquire(filepath.Join(root, "state", "LOCK"))
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Release()
	held := tree(t, root)
	if r := run(t, fullOptions(t, root)); r.Damaged() {
		t.Fatal(text(r))
	}
	if d := diff(held, tree(t, root)); len(d) != 0 {
		t.Fatalf("verify --full beside a writer changed %v", d)
	}
}

// TestQuickReadsNoContent: --quick never opens a Parquet file; --full does.
func TestQuickReadsNoContent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads unreadable files")
	}
	root := fresh(t, template(t))
	p := filepath.Join(batchDirs(t, root)[1], dataset.EntriesFile)
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(p, 0o644)
	if r := run(t, options(root)); r.Damaged() {
		t.Fatalf("--quick read an unreadable file:\n%s", text(r))
	}
	expectFail(t, run(t, fullOptions(t, root)), "checksums", "cannot be read")
}

// TestVerifyAlongsideIngest: verify --full runs while a writer holds the
// lock and commits batches. It checks the batches committed when it
// started, passes, and skips the index, naming the writer (amendment A5
// §1).
func TestVerifyAlongsideIngest(t *testing.T) {
	g, es := querytest.Pairs(t, 200)
	v, l := querytest.NewPublished(t, g, es, 60, 20, 1000)
	lk, err := lock.Acquire(filepath.Join(v.Root, "state", "LOCK")) // as update holds it
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Release()
	l.Publish(200)
	type result struct {
		r   *Report
		err error
	}
	done := make(chan result, 1)
	started := false
	o := fullOptions(t, v.Root)
	querytest.Ingest(t, v, l, 20, 1000, func(commit.Manifest) {
		if !started {
			started = true
			go func() {
				r, err := Run(ctx, o)
				done <- result{r, err}
			}()
		}
	})
	res := <-done
	if res.err != nil {
		t.Fatal(res.err)
	}
	r := res.r
	if c := r.Check("index"); r.Damaged() || r.Batches < 4 || r.Batches > 10 || c.Status != StatusSkipped || !strings.Contains(c.Summary, "PID") || r.Writer == "" {
		t.Fatalf("verify beside a writer:\n%s", text(r))
	}
}

// TestViewsRootSpelling: views.sql names the root as the writer was given
// it. The same vault reached through a symlink is not damage; a vault
// moved or copied keeps views over its old path until the next update
// rewrites them, which is pending, not damage.
func TestViewsRootSpelling(t *testing.T) {
	root := fresh(t, template(t))
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	o := options(root)
	o.Root = link
	if r := run(t, o); r.Damaged() || len(r.Pending) != 0 {
		t.Fatalf("the vault through a symlink:\n%s", text(r))
	}

	moved := t.TempDir()
	if err := os.Rename(root, filepath.Join(moved, "vault-root")); err != nil {
		t.Fatal(err)
	}
	r := run(t, options(filepath.Join(moved, "vault-root")))
	if r.Damaged() || len(r.Pending) != 1 || !strings.Contains(r.Pending[0], dataset.ViewsFile) {
		t.Fatalf("a moved vault:\n%s", text(r))
	}
}

// TestEmptyVault: a vault no batch has committed to yet, with no index
// and no views.sql, is sound in both modes.
func TestEmptyVault(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"state/intent", "state/logs", "vault/segments", "vault/dict", "dataset", "tmp/stage", "tmp/rebuild"} {
		os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	for _, o := range []Options{options(root), fullOptions(t, root)} {
		if r := run(t, o); r.Damaged() || r.Batches != 0 || len(r.Pending) != 0 {
			t.Fatalf("an empty vault (full %v):\n%s", o.Full, text(r))
		}
	}
}
