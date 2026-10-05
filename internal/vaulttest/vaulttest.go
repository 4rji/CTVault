// Package vaulttest checks a vault the way the crash suite needs (spec
// §13.5) and compares a recovered vault with a clean one (amendment A1 §7).
// It is test infrastructure: production binaries never import it.
package vaulttest

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	_ "github.com/duckdb/duckdb-go/v2" // the "duckdb" database/sql driver

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

// Vault is a vault root and its vault directories.
type Vault struct {
	Root string
	Dirs []string
	UUID [16]byte
}

// reader opens the vault's records with every dictionary loaded.
func (v Vault) reader(t testing.TB) *vault.Reader {
	t.Helper()
	c, err := vault.NewCodec()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	ds, err := vault.LoadDicts(v.Dirs)
	if err != nil {
		t.Fatalf("dictionaries: %v", err)
	}
	for _, d := range ds {
		if err := c.AddDict(d.Manifest.ID, d.Content); err != nil {
			t.Fatal(err)
		}
	}
	r, err := vault.OpenReader(v.Dirs, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

// record is a vault record with its certificate's SHA-256.
type record struct {
	loc    vault.Loc
	certID uint64
	sha    [32]byte
}

// scan reads the records in [from, to), resolving each to its SHA-256. A
// torn record ends the scan when torn is allowed.
func (v Vault) scan(t testing.TB, from, to vault.Tail, torn bool) []record {
	t.Helper()
	r := v.reader(t)
	var out []record
	err := vault.Scan(v.Dirs, from, to, func(loc vault.Loc, rec vault.Record) error {
		der, _, err := r.Read(loc)
		if err != nil {
			return err
		}
		out = append(out, record{loc, rec.CertID, sha256.Sum256(der)})
		return nil
	})
	if err != nil && !(torn && errors.Is(err, vault.ErrTorn)) {
		t.Fatalf("reading the vault: %v", err)
	}
	return out
}

// BeyondTail returns the cert_id and SHA-256 of every record past the
// committed tail, up to a torn record: what recovery will truncate.
func (v Vault) BeyondTail(t testing.TB) map[uint64][32]byte {
	t.Helper()
	ms, err := commit.ListCommitted(v.Root)
	if err != nil {
		t.Fatal(err)
	}
	var tail vault.Tail
	if len(ms) > 0 {
		tail = ms[len(ms)-1].Vault.End
	}
	segs, err := vault.FindSegments(v.Dirs)
	if err != nil {
		t.Fatal(err)
	}
	out := map[uint64][32]byte{}
	if len(segs) == 0 {
		return out
	}
	last := slices.Max(slices.Collect(maps.Keys(segs)))
	for _, rec := range v.scan(t, tail, vault.Tail{Segment: last, Offset: math.MaxInt64}, true) {
		out[rec.certID] = rec.sha
	}
	return out
}

// Assignments returns the cert_id and SHA-256 of every record in the
// segments, beyond the committed tail too, up to a torn record. Called after
// a kill and before recovery, it sees what the killed attempt assigned.
func (v Vault) Assignments(t testing.TB) map[uint64][32]byte {
	t.Helper()
	segs, err := vault.FindSegments(v.Dirs)
	if err != nil {
		t.Fatal(err)
	}
	out := map[uint64][32]byte{}
	if len(segs) == 0 {
		return out
	}
	last := slices.Max(slices.Collect(maps.Keys(segs)))
	for _, rec := range v.scan(t, vault.Tail{}, vault.Tail{Segment: last, Offset: math.MaxInt64}, true) {
		if prev, dup := out[rec.certID]; dup && prev != rec.sha {
			t.Fatalf("cert_id %d holds two different certificates in one vault", rec.certID)
		}
		out[rec.certID] = rec.sha
	}
	return out
}

func fileSHA256(t testing.TB, p string) string {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Committed is what a reader snapshot sees: every directory under
// dataset/log=*/ must be a committed batch whose files match _COMMIT.json
// byte for byte, so no partial batch is ever visible. It returns each
// batch directory's _COMMIT.json.
func (v Vault) Committed(t testing.TB) map[string][]byte {
	t.Helper()
	ms, err := commit.ListCommitted(v.Root)
	if err != nil {
		t.Fatalf("committed batches: %v", err)
	}
	paths := commit.Paths{Root: v.Root}
	out := map[string][]byte{}
	for _, m := range ms {
		dir := paths.BatchDir(m.ID())
		for name, fi := range m.Files {
			if got := fileSHA256(t, filepath.Join(dir, name)); got != fi.SHA256 {
				t.Fatalf("%s/%s does not match its checksum", dir, name)
			}
		}
		b, err := os.ReadFile(filepath.Join(dir, commit.ManifestFile))
		if err != nil {
			t.Fatal(err)
		}
		out[dir] = b
	}
	logs, _ := filepath.Glob(filepath.Join(v.Root, "dataset", "*", "*"))
	for _, d := range logs {
		if _, ok := out[d]; !ok {
			t.Fatalf("%s is visible under dataset/ but is not a committed batch", d)
		}
	}
	return out
}

// CheckRecovered asserts spec §13.5's invariants on a vault whose writer
// has opened (recovered) and closed it:
//   - committed batches are contiguous and every file matches its checksum;
//   - the vault holds nothing beyond the committed tail, and its segments
//     are intact;
//   - every committed record has a unique cert_id and a unique certificate;
//   - Pebble agrees with the vault, and applied/<log> is each log's last
//     commit_seq;
//   - each batch's Merkle state equals a recomputation from entries.parquet;
//   - only intents marked abandoned remain, for uncommitted batches, and
//     tmp/ holds only empty stage/ and rebuild/;
//   - no interrupted atomic write left its temp file anywhere.
func (v Vault) CheckRecovered(t testing.TB) {
	t.Helper()
	v.Committed(t)
	ms, _ := commit.ListCommitted(v.Root)
	var tail vault.Tail
	if len(ms) > 0 {
		tail = ms[len(ms)-1].Vault.End
	}
	if u, err := vault.InspectTail(v.Dirs, tail); err != nil || u.Bytes != 0 {
		t.Fatalf("data beyond the committed tail after recovery: %+v, %v", u, err)
	}
	if err := vault.CheckSegments(v.Dirs, v.UUID, tail); err != nil {
		t.Fatal(err)
	}
	refs := map[[32]byte]index.Ref{}
	ids := map[uint64]bool{}
	for _, rec := range v.scan(t, vault.Tail{}, tail, false) {
		if ids[rec.certID] {
			t.Fatalf("cert_id %d is committed twice", rec.certID)
		}
		if _, dup := refs[rec.sha]; dup {
			t.Fatalf("certificate %x is vaulted twice", rec.sha[:8])
		}
		ids[rec.certID], refs[rec.sha] = true, index.Ref{CertID: rec.certID, Loc: rec.loc}
	}

	idx, err := index.Open(filepath.Join(v.Root, "state", "pebble"))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	n := 0
	err = idx.EachCert(func(sha [32]byte, r index.Ref) error {
		if want, ok := refs[sha]; !ok || want != r {
			return fmt.Errorf("pebble has %x → %+v, the vault %+v (%v)", sha[:8], r, want, ok)
		}
		n++
		return nil
	})
	if err != nil || n != len(refs) {
		t.Fatalf("pebble and the vault disagree: %v (%d index entries, %d records)", err, n, len(refs))
	}
	last := map[string]uint64{}
	for _, m := range ms {
		last[m.Log] = m.CommitSeq
	}
	if applied, err := idx.AppliedLogs(); err != nil || !maps.Equal(applied, last) {
		t.Fatalf("applied %v, want %v (%v)", applied, last, err)
	}

	db := duck(t)
	states := map[string]*merkle.State{}
	paths := commit.Paths{Root: v.Root}
	for _, m := range ms {
		st, ok := states[m.Log]
		if !ok {
			st = merkle.NewState()
			states[m.Log] = st
		}
		for i, e := range entries(t, db, filepath.Join(paths.BatchDir(m.ID()), dataset.EntriesFile)) {
			if e.idx != m.First+uint64(i) {
				t.Fatalf("batch %s: row %d has index %d", m.BatchID, i, e.idx)
			}
			st.Append(e.leafHash)
		}
		want, _ := m.MerkleAfter.Root()
		if got, _ := st.Root(); got != want || st.Size() != m.Last+1 {
			t.Fatalf("batch %s: the Merkle state recomputed from entries.parquet differs from merkle_after", m.BatchID)
		}
	}

	ins, err := commit.ReadIntents(commit.Paths{Root: v.Root})
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range ins {
		if _, err := os.Stat(filepath.Join(paths.BatchDir(in.ID()), commit.ManifestFile)); !in.Abandoned || err == nil {
			t.Fatalf("intent of %s left after recovery (abandoned=%v, committed=%v)", in.BatchID, in.Abandoned, err == nil)
		}
	}
	filepath.WalkDir(v.Root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && fsutil.IsAtomicTemp(d.Name()) {
			t.Errorf("an interrupted write's temp file survived recovery: %s", p)
		}
		return nil
	})
	var tmp []string
	filepath.WalkDir(filepath.Join(v.Root, "tmp"), func(p string, d os.DirEntry, err error) error {
		if rel, _ := filepath.Rel(v.Root, p); err == nil && rel != "tmp" {
			tmp = append(tmp, rel)
		}
		return nil
	})
	if !slices.Equal(tmp, []string{"tmp/rebuild", "tmp/stage"}) {
		t.Fatalf("tmp/ after recovery: %v", tmp)
	}
}

func duck(t testing.TB) *sql.DB {
	t.Helper()
	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

type row struct {
	idx                uint64
	ts                 sql.Null[int64]
	typ                string
	certID             sql.Null[uint64]
	leafHash           [32]byte
	ikey, ikh, chainID []byte
	leafErr            sql.Null[string]
}

func entries(t testing.TB, db *sql.DB, path string) []row {
	t.Helper()
	rs, err := db.Query(`SELECT idx, epoch_ms(ct_ts), entry_type, cert_id, leaf_hash, issuance_key, issuer_key_hash, chain_id, leaf_error
		FROM read_parquet(` + quote(path) + `) ORDER BY idx`)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	var out []row
	for rs.Next() {
		var r row
		var lh []byte
		if err := rs.Scan(&r.idx, &r.ts, &r.typ, &r.certID, &lh, &r.ikey, &r.ikh, &r.chainID, &r.leafErr); err != nil {
			t.Fatal(err)
		}
		copy(r.leafHash[:], lh)
		out = append(out, r)
	}
	if err := rs.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// Entry is one log entry's content without internal IDs: certificates and
// chains are given by SHA-256 (hex), and NULL fields are empty.
type Entry struct {
	Idx           uint64
	LeafHash      string
	Timestamp     string // milliseconds, "" when NULL
	Type          string
	IssuanceKey   string
	IssuerKeyHash string
	LeafError     string
	Cert          string
	Chain         []string
}

// Dump returns every committed entry by log, in index order. A recovered
// ingest must equal a clean one on all of it; only cert_id and chain_id may
// differ (amendment A1 §7). Dump also checks that every reference resolves:
// each cert_id to one vault record, each chain_id to positions 0..n-1
// written by exactly one batch, and every committed record is referenced.
func (v Vault) Dump(t testing.TB) map[string][]Entry {
	t.Helper()
	ms, err := commit.ListCommitted(v.Root)
	if err != nil {
		t.Fatal(err)
	}
	var tail vault.Tail
	if len(ms) > 0 {
		tail = ms[len(ms)-1].Vault.End
	}
	certs := map[uint64]string{}
	for _, rec := range v.scan(t, vault.Tail{}, tail, false) {
		certs[rec.certID] = hex.EncodeToString(rec.sha[:])
	}
	used := map[uint64]bool{}
	cert := func(id uint64) string {
		s, ok := certs[id]
		if !ok {
			t.Fatalf("cert_id %d is referenced but not in the committed vault", id)
		}
		used[id] = true
		return s
	}

	db := duck(t)
	paths := commit.Paths{Root: v.Root}
	chains := map[string][]uint64{}
	for _, m := range ms {
		rs, err := db.Query(`SELECT chain_id, position, cert_id FROM read_parquet(` + quote(filepath.Join(paths.BatchDir(m.ID()), dataset.ChainsFile)) + `) ORDER BY chain_id, position`)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for rs.Next() {
			var id []byte
			var pos uint16
			var c uint64
			if err := rs.Scan(&id, &pos, &c); err != nil {
				t.Fatal(err)
			}
			k := string(id)
			if !seen[k] && len(chains[k]) > 0 {
				t.Fatalf("chain %x is written by two batches", id[:4])
			}
			if seen[k] = true; int(pos) != len(chains[k]) {
				t.Fatalf("chain %x: position %d out of order", id[:4], pos)
			}
			chains[k] = append(chains[k], c)
		}
		rs.Close()
	}

	out := map[string][]Entry{}
	for _, m := range ms {
		for _, r := range entries(t, db, filepath.Join(paths.BatchDir(m.ID()), dataset.EntriesFile)) {
			e := Entry{Idx: r.idx, LeafHash: hex.EncodeToString(r.leafHash[:]), Type: r.typ,
				IssuanceKey: hex.EncodeToString(r.ikey), IssuerKeyHash: hex.EncodeToString(r.ikh), LeafError: r.leafErr.V}
			if r.ts.Valid {
				e.Timestamp = fmt.Sprint(r.ts.V)
			}
			if r.certID.Valid {
				e.Cert = cert(r.certID.V)
			}
			if r.chainID != nil {
				ids, ok := chains[string(r.chainID)]
				if !ok {
					t.Fatalf("entry %d: chain %x has no chains.parquet rows", r.idx, r.chainID[:4])
				}
				e.Chain = []string{}
				for _, id := range ids {
					e.Chain = append(e.Chain, cert(id))
				}
			}
			out[m.Log] = append(out[m.Log], e)
		}
	}
	for id := range certs {
		if !used[id] {
			t.Fatalf("committed record cert_id %d is referenced by no entry or chain", id)
		}
	}
	return out
}

// Diff describes the first difference between two dumps, "" if equal.
func Diff(got, want map[string][]Entry) string {
	for _, log := range slices.Sorted(maps.Keys(want)) {
		g, w := got[log], want[log]
		for i := range min(len(g), len(w)) {
			if a, b := fmt.Sprintf("%+v", g[i]), fmt.Sprintf("%+v", w[i]); a != b {
				return fmt.Sprintf("log %s entry %d:\n got  %s\n want %s", log, w[i].Idx, a, b)
			}
		}
		if len(g) != len(w) {
			return fmt.Sprintf("log %s: %d entries, want %d", log, len(g), len(w))
		}
	}
	if len(got) != len(want) {
		return fmt.Sprintf("%d logs, want %d", len(got), len(want))
	}
	return ""
}
