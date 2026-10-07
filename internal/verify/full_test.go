package verify_test

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/duckdb/duckdb-go/v2" // the "duckdb" database/sql driver

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/lock"
	"github.com/4rji/ctvault/internal/query"
	"github.com/4rji/ctvault/internal/querytest"
	"github.com/4rji/ctvault/internal/vault"
	. "github.com/4rji/ctvault/internal/verify"
)

func fullOptions(t *testing.T, root string) Options {
	t.Helper()
	sess, err := query.NewSession(root, querytest.Guard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close() })
	o := options(root)
	o.Full, o.Session, o.Workers = true, sess, 3
	return o
}

// rewrite replaces a batch's Parquet file with the rows sql selects from it
// (as {f}), and records the new file's checksum and size in _COMMIT.json:
// a dataset that is consistent but wrong.
func rewrite(t *testing.T, dir, name, sel string) {
	t.Helper()
	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	p := filepath.Join(dir, name)
	tmp := p + ".new"
	if _, err := db.Exec(`COPY (` + strings.ReplaceAll(sel, "{f}", `read_parquet('`+p+`')`) + `) TO '` + tmp + `' (FORMAT parquet)`); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, p); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	sum := sha256.Sum256(b)
	editManifest(t, dir, func(m map[string]any) {
		fi := m["files"].(map[string]any)[name].(map[string]any)
		fi["sha256"], fi["bytes"] = hex.EncodeToString(sum[:]), len(b)
	})
}

// firstRecord returns the first record of a kind in the vault, and its
// location.
func firstRecord(t *testing.T, root string, kind byte) (vault.Loc, vault.Record) {
	t.Helper()
	ms, _ := commit.ListCommitted(root)
	var loc vault.Loc
	var rec vault.Record
	errFound := errors.New("found")
	err := vault.Scan([]string{filepath.Join(root, "vault")}, ms[0].Vault.Start, ms[len(ms)-1].Vault.End, func(l vault.Loc, r vault.Record) error {
		if r.Kind == kind {
			loc, rec = l, r
			return errFound
		}
		return nil
	})
	if err != errFound {
		t.Fatalf("no record of kind %d (%v)", kind, err)
	}
	return loc, rec
}

func segmentPath(root string, seg uint64) string {
	return filepath.Join(root, "vault", "segments", vault.SegmentName(seg))
}

// editIndex applies fn to the vault's index.
func editIndex(t *testing.T, root string, fn func(x *index.Index, b *index.Batch)) {
	t.Helper()
	x, err := index.Open(filepath.Join(root, "state", "pebble"))
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	b := x.NewBatch()
	defer b.Close()
	fn(x, b)
	if err := b.Commit(); err != nil {
		t.Fatal(err)
	}
}

// TestFullClean: a sound vault passes every check, the index included when
// the writer lock is free (amendment A5 §2.2).
func TestFullClean(t *testing.T) {
	root := fresh(t, template(t))
	r := run(t, fullOptions(t, root))
	if r.Damaged() || len(r.Pending) != 0 {
		t.Fatalf("a sound vault:\n%s", text(r))
	}
	for _, name := range []string{"checksums", "records", "references", "merkle", "sth roots", "index"} {
		if c := r.Check(name); c == nil || c.Status != StatusOK {
			t.Fatalf("check %q: %+v\n%s", name, c, text(r))
		}
	}
	if s := r.Check("records").Summary; !strings.Contains(s, "62 records") {
		t.Fatalf("records: %q", s)
	}
	// --as-of 1: the batch's STH lies past index 19, so its proof is
	// re-checked; without a recorded proof, the check is skipped.
	o := fullOptions(t, root)
	o.AsOf = 1
	if r := run(t, o); r.Damaged() || !strings.Contains(r.Check("sth roots").Summary, "1 proof re-checked") {
		t.Fatalf("as of commit 1:\n%s", text(r))
	}
	editManifest(t, batchDirs(t, root)[0], func(m map[string]any) { delete(m["verified"].(map[string]any), "proof") })
	if r := run(t, o); r.Damaged() || !strings.Contains(r.Check("sth roots").Summary, "1 proved at ingest, proof not recorded") {
		t.Fatalf("an older batch without a proof:\n%s", text(r))
	}
}

// TestFullFaults: one fault at a time; a consistent-but-wrong file, whose
// checksum was updated, still fails its content check (amendment A5 §4.1).
func TestFullFaults(t *testing.T) {
	tmpl := template(t)
	cases := []struct {
		name        string
		damage      func(t *testing.T, root string)
		check, want string
	}{
		{"a byte flipped in a Parquet file", func(t *testing.T, root string) {
			flipByte(t, filepath.Join(batchDirs(t, root)[1], dataset.EntriesFile), 100)
		}, "checksums", dataset.EntriesFile},
		{"a damaged record frame", func(t *testing.T, root string) {
			loc, _ := firstRecord(t, root, vault.KindLeaf)
			flipByte(t, segmentPath(root, loc.Segment), int64(loc.Offset)+int64(loc.Len)-8)
		}, "records", "record"},
		{"a delta pointing forward", func(t *testing.T, root string) {
			loc, rec := firstRecord(t, root, vault.KindDelta)
			fwd := rec
			fwd.BaseSeg = loc.Segment + 1 // a later segment: as long a varint, so the record keeps its length
			b := vault.AppendRecord(nil, fwd)
			if len(b) != int(loc.Len) {
				t.Fatalf("the rewritten record is %d bytes, not %d", len(b), loc.Len)
			}
			f, _ := os.OpenFile(segmentPath(root, loc.Segment), os.O_WRONLY, 0)
			f.WriteAt(b, int64(loc.Offset))
			f.Close()
		}, "records", "forward"},
		{"a certs row pointing at another record", func(t *testing.T, root string) {
			dir := batchDirs(t, root)[1]
			rewrite(t, dir, "certs.p1.parquet", `SELECT * REPLACE (CASE WHEN cert_id = (SELECT min(cert_id) FROM {f}) THEN vault_off + 1 ELSE vault_off END AS vault_off) FROM {f}`)
		}, "records", "location"},
		{"an altered leaf_hash", func(t *testing.T, root string) {
			rewrite(t, batchDirs(t, root)[1], dataset.EntriesFile, `SELECT * REPLACE (CASE WHEN idx = 25 THEN unhex(sha256('x')) ELSE leaf_hash END AS leaf_hash) FROM {f}`)
		}, "merkle", "merkle_after"},
		{"a gap in idx", func(t *testing.T, root string) {
			rewrite(t, batchDirs(t, root)[1], dataset.EntriesFile, `SELECT * REPLACE (CASE WHEN idx = 25 THEN 1025 ELSE idx END AS idx) FROM {f}`)
		}, "merkle", "idx"},
		{"a dangling cert_id", func(t *testing.T, root string) {
			rewrite(t, batchDirs(t, root)[2], dataset.EntriesFile, `SELECT * REPLACE (CASE WHEN idx = 45 THEN 999999 ELSE cert_id END AS cert_id) FROM {f}`)
		}, "references", "999999"},
		{"an altered proof node", func(t *testing.T, root string) {
			editManifest(t, batchDirs(t, root)[0], func(m map[string]any) {
				p := m["verified"].(map[string]any)["proof"].([]any)
				p[0] = strings.Repeat("ab", 32)
			})
		}, "sth roots", "proof"},
		{"an index key missing", func(t *testing.T, root string) {
			editIndex(t, root, func(x *index.Index, b *index.Batch) {
				x.EachCert(func(sha [32]byte, _ index.Ref) error { b.DeleteCert(sha); return errors.New("one") })
			})
		}, "index", "lacks certificate"},
		{"an extra index key", func(t *testing.T, root string) {
			editIndex(t, root, func(_ *index.Index, b *index.Batch) { b.AddCert(sha256.Sum256([]byte("x")), index.Ref{CertID: 1}) })
		}, "index", "have no record"},
		{"an index key pointing elsewhere", func(t *testing.T, root string) {
			editIndex(t, root, func(x *index.Index, b *index.Batch) {
				x.EachCert(func(sha [32]byte, r index.Ref) error {
					r.Loc.Offset++
					b.AddCert(sha, r)
					return errors.New("one")
				})
			})
		}, "index", "maps"},
		{"the index applied ahead", func(t *testing.T, root string) {
			editIndex(t, root, func(_ *index.Index, b *index.Batch) { b.SetApplied("fakelog", 9) })
		}, "index", "ahead"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := fresh(t, tmpl)
			c.damage(t, root)
			expectFail(t, run(t, fullOptions(t, root)), c.check, c.want)
		})
	}
}

// TestFullIndexStates: an index behind the commits is recovery pending; a
// held writer lock skips the index check and names the PID.
func TestFullIndexStates(t *testing.T) {
	tmpl := template(t)
	root := fresh(t, tmpl)
	editIndex(t, root, func(_ *index.Index, b *index.Batch) { b.SetApplied("fakelog", 2) })
	// Batch 3's keys stay: the check must not count them as extra, as a
	// writer that stopped between P8 and P9 never wrote them. Remove them.
	ms, _ := commit.ListCommitted(root)
	editIndex(t, root, func(x *index.Index, b *index.Batch) {
		vault.Scan([]string{filepath.Join(root, "vault")}, ms[2].Vault.Start, ms[2].Vault.End, func(l vault.Loc, rec vault.Record) error {
			x.EachCert(func(sha [32]byte, r index.Ref) error {
				if r.CertID == rec.CertID {
					b.DeleteCert(sha)
				}
				return nil
			})
			return nil
		})
	})
	r := run(t, fullOptions(t, root))
	if r.Damaged() || !strings.Contains(strings.Join(r.Pending, "\n"), "has not applied") {
		t.Fatalf("an index one batch behind:\n%s", text(r))
	}

	root = fresh(t, tmpl)
	lk, err := lock.Acquire(filepath.Join(root, "state", "LOCK"))
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Release()
	r = run(t, fullOptions(t, root))
	if c := r.Check("index"); r.Damaged() || c == nil || c.Status != StatusSkipped || !strings.Contains(c.Summary, "PID") {
		t.Fatalf("a held lock:\n%s", text(r))
	}
}

// TestIndexInUse: an index another holder has open, without the writer
// lock, is skipped, not reported as damage.
func TestIndexInUse(t *testing.T) {
	root := fresh(t, template(t))
	x, err := index.Open(filepath.Join(root, "state", "pebble"))
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	r := run(t, fullOptions(t, root))
	if c := r.Check("index"); r.Damaged() || c.Status != StatusSkipped || !strings.Contains(c.Summary, "in use") {
		t.Fatalf("an index in use:\n%s", text(r))
	}
}
