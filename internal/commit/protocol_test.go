package commit

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

// env is a vault root with the writer's resources.
type env struct {
	t      *testing.T
	p      Paths
	dirs   []string
	idx    *index.Index
	codec  *vault.Codec
	stager *dataset.Stager
	certs  [][]byte
	hooks  []string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"state/intent", "state/logs", "vault/segments", "vault/dict", "dataset", "tmp/stage", "tmp/rebuild"} {
		os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	e := &env{t: t, p: Paths{Root: root}, dirs: []string{filepath.Join(root, "vault")}}
	var err error
	if e.idx, err = index.Open(filepath.Join(root, "state", "pebble")); err != nil {
		t.Fatal(err)
	}
	if e.codec, err = vault.NewCodec(); err != nil {
		t.Fatal(err)
	}
	if e.stager, err = dataset.NewStager(dataset.Options{TempDir: filepath.Join(root, "tmp", "duckdb-test"), MaxTempBytes: 1 << 30}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.stager.Close(); e.codec.Close(); e.idx.Close() })
	g, _ := ctlogtest.NewGenerator()
	es, _ := g.Entries(60)
	for _, x := range es {
		e.certs = append(e.certs, x.CertDER)
	}
	return e
}

func (e *env) hook(p string) { e.hooks = append(e.hooks, p) }

func (e *env) recover() Recovered {
	e.t.Helper()
	r, err := Recover(RecoverOptions{Paths: e.p, VaultDirs: e.dirs, Index: e.idx, Codec: e.codec, ChainIDs: e.stager.ChainIDs})
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

// batch runs one batch of n entries through the protocol up to stopAfter:
// "intent", "vault" (records synced), "stage", "publish", "pebble" or "done".
func (e *env) batch(first, n uint64, ids *IDs, seq uint64, before *merkle.State, tail vault.Tail, stopAfter string) (Manifest, *merkle.State, vault.Tail) {
	e.t.Helper()
	t := e.t
	id := BatchID{Log: "fakelog", First: first, Last: first + n - 1}
	in := Intent{BatchID: id.String(), Log: id.Log, First: id.First, Last: id.Last, VaultTail: tail,
		NextCertID: ids.Peek(), MerkleBefore: before, StartedAt: time.Unix(1, 0).UTC()}
	if err := WriteIntent(e.p, in, e.hook); err != nil {
		t.Fatal(err)
	}
	if stopAfter == "intent" {
		return Manifest{}, nil, tail
	}
	w, err := vault.OpenWriter(vault.Options{Dirs: e.dirs, SegmentSize: 8 << 10}, e.codec, tail)
	if err != nil {
		t.Fatal(err)
	}
	state := before.Clone()
	var rows []dataset.EntryRow
	var chains []dataset.ChainRow
	pb := e.idx.NewBatch()
	defer pb.Close()
	firstID := ids.Peek()
	for i := range n {
		der := e.certs[(first+i)%uint64(len(e.certs))]
		cid, _ := ids.Next()
		loc, err := w.AppendCert(vault.KindLeaf, cid, der, 0)
		if err != nil {
			t.Fatal(err)
		}
		pb.AddCert(sha256.Sum256(der), index.Ref{CertID: cid, Loc: loc})
		lh := merkle.LeafHash([]byte{byte(first + i)})
		state.Append(lh)
		rows = append(rows, dataset.EntryRow{Idx: first + i, CTTimestamp: 1, EntryType: "x509", CertID: cid, LeafHash: lh})
	}
	chainID := sha256.Sum256([]byte{byte(first)})
	chains = append(chains, dataset.ChainRow{ChainID: chainID, Position: 0, CertID: firstID})
	pb.AddChain(chainID)
	w.Sync()
	end := w.Tail()
	w.Close()
	if stopAfter == "vault" {
		return Manifest{}, state, end
	}
	files, err := e.stager.Stage(context.Background(), e.p.StageDir(id), rows, chains)
	if err != nil {
		t.Fatal(err)
	}
	if stopAfter == "stage" {
		return Manifest{}, state, end
	}
	m := Manifest{Format: ManifestFormat, CommitSeq: seq, BatchID: id.String(), Log: id.Log, First: id.First, Last: id.Last,
		MerkleAfter: state, Verified: Verified{Method: "root_equals_sth"}, CertIDRange: &[2]uint64{firstID, ids.Peek() - 1},
		NextCertID: ids.Peek(), Vault: Span{Start: tail, End: end}, Builders: map[string]int{}, Files: files,
		Counts: Counts{Entries: int(n), NewCerts: int(n)}, CTVaultVersion: "test", CommittedAt: time.Unix(2, 0).UTC()}
	if err := Publish(e.p, m, e.hook); err != nil {
		t.Fatal(err)
	}
	if stopAfter == "publish" {
		return m, state, end
	}
	pb.SetApplied(id.Log, seq)
	if err := pb.Commit(); err != nil {
		t.Fatal(err)
	}
	if stopAfter == "pebble" {
		return m, state, end
	}
	if err := RemoveIntent(e.p, id, e.hook); err != nil {
		t.Fatal(err)
	}
	return m, state, end
}

func (e *env) ids(next uint64) *IDs {
	ids, err := LoadIDs(e.p.StateDir(), next, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	return ids
}

func TestCleanCommitAndHookOrder(t *testing.T) {
	e := newEnv(t)
	m, _, end := e.batch(0, 10, e.ids(1), 1, merkle.NewState(), vault.Tail{}, "done")
	want := []string{HookAfterIntent, HookAfterManifest, HookBeforeRename, HookAfterRename, HookBeforeIntentDelete}
	if !slices.Equal(e.hooks, want) {
		t.Fatalf("hooks %v, want %v", e.hooks, want)
	}
	r := e.recover()
	if r.Crashed || r.Tail != end || r.NextCertID != m.NextCertID || len(r.Committed) != 1 || len(r.Actions) != 0 {
		t.Fatalf("a clean vault needs nothing: %+v", r)
	}
	if _, err := os.Stat(e.p.StageDir(m.ID())); !os.IsNotExist(err) {
		t.Fatal("the staging directory is gone after the commit point")
	}
	if err := Publish(e.p, m, nil); err == nil {
		t.Fatal("a committed batch directory is never replaced")
	}
}

// TestRecoverAfterCrashBeforeCommit covers spec §8.5 rows 1-2: vault data
// beyond the committed tail, and an intent whose batch never committed.
func TestRecoverAfterCrashBeforeCommit(t *testing.T) {
	e := newEnv(t)
	ids := e.ids(1)
	m1, s1, end1 := e.batch(0, 10, ids, 1, merkle.NewState(), vault.Tail{}, "done")
	e.batch(10, 15, ids, 2, s1, end1, "stage") // crash after staging: vault data, intent and staging remain
	r := e.recover()
	if !r.Crashed || r.Tail != end1 || len(r.Committed) != 1 {
		t.Fatalf("recovery: %+v", r)
	}
	floor, _ := ReadFloor(e.p.StateDir())
	if r.NextCertID != floor || floor <= 25 {
		t.Fatalf("IDs 11-25 were assigned by the lost attempt; allocation must resume at the floor %d, got %d", floor, r.NextCertID)
	}
	if u, _ := vault.InspectTail(e.dirs, end1); u.Bytes != 0 {
		t.Fatal("uncommitted vault data must be truncated")
	}
	if left, _ := ReadIntents(e.p); len(left) != 1 || !left[0].Abandoned {
		t.Fatalf("the intent must stay, marked abandoned, until a later commit: %+v", left)
	}
	if left, _ := os.ReadDir(filepath.Join(e.p.Root, "tmp", "stage")); len(left) != 0 {
		t.Fatal("the staging directory must be removed")
	}
	// The vault keeps working from the committed tail.
	ids2 := e.ids(r.NextCertID)
	m2, _, _ := e.batch(10, 5, ids2, 2, m1.MerkleAfter, r.Tail, "done")
	if m2.CertIDRange[0] != floor {
		t.Fatalf("the retried batch starts at the floor: %v", m2.CertIDRange)
	}
	if err := ClearAbandoned(e.p); err != nil {
		t.Fatal(err)
	}
	if left, _ := ReadIntents(e.p); len(left) != 0 {
		t.Fatalf("a later commit clears the abandoned intent: %+v", left)
	}
}

// TestCrashSkipSurvivesARestartWithoutACommit: the writer that recovers may
// stop before committing anything (update finds nothing to do, a Ctrl-C).
// The next start must still resume at ID_FLOOR, or it would hand out again
// the cert_ids of the records recovery truncated (spec §8.6).
func TestCrashSkipSurvivesARestartWithoutACommit(t *testing.T) {
	e := newEnv(t)
	ids := e.ids(1)
	_, s1, end1 := e.batch(0, 10, ids, 1, merkle.NewState(), vault.Tail{}, "done")
	e.batch(10, 15, ids, 2, s1, end1, "vault") // cert_ids 11-25 written past the tail, then a kill
	e.recover()
	floor, _ := ReadFloor(e.p.StateDir())
	r := e.recover() // the second start, with nothing committed in between
	if !r.Crashed || r.NextCertID != floor {
		t.Fatalf("the second start resumes at %d, want the floor %d (crashed=%v)", r.NextCertID, floor, r.Crashed)
	}
}

// TestRecoverFinishesACommittedBatch covers spec §8.5 rows 3-4: a crash
// between the commit point and the Pebble apply.
func TestRecoverFinishesACommittedBatch(t *testing.T) {
	e := newEnv(t)
	ids := e.ids(1)
	m1, s1, end1 := e.batch(0, 10, ids, 1, merkle.NewState(), vault.Tail{}, "done")
	m2, _, end2 := e.batch(10, 8, ids, 2, s1, end1, "publish")
	if seq, _ := e.idx.Applied("fakelog"); seq != 1 {
		t.Fatalf("Pebble lags: applied %d", seq)
	}
	r := e.recover()
	if r.Crashed || r.Tail != end2 || r.NextCertID != m2.NextCertID || len(r.Committed) != 2 {
		t.Fatalf("a committed batch is kept as is: %+v", r)
	}
	if seq, _ := e.idx.Applied("fakelog"); seq != 2 {
		t.Fatalf("Pebble must catch up to commit_seq 2, got %d", seq)
	}
	for i := range 8 {
		der := e.certs[(10+i)%len(e.certs)]
		ref, ok, err := e.idx.Lookup(sha256.Sum256(der))
		if err != nil || !ok || ref.CertID != m2.CertIDRange[0]+uint64(i) {
			t.Fatalf("certificate %d of the batch must be re-indexed: %+v %v %v", i, ref, ok, err)
		}
	}
	b := e.idx.NewBatch()
	defer b.Close()
	if has, _ := b.HasChain(sha256.Sum256([]byte{10})); !has {
		t.Fatal("the batch's chains must be re-indexed")
	}
	if left, _ := ReadIntents(e.p); len(left) != 0 {
		t.Fatal("the intent of a committed batch is removed")
	}
	_ = m1
	if again := e.recover(); len(again.Actions) != 0 {
		t.Fatalf("recovery is idempotent: %v", again.Actions)
	}
}

func TestRecoverRefusesDamagedCommits(t *testing.T) {
	for name, damage := range map[string]func(e *env, m Manifest){
		"missing manifest": func(e *env, m Manifest) { os.Remove(filepath.Join(e.p.BatchDir(m.ID()), ManifestFile)) },
		"garbage manifest": func(e *env, m Manifest) {
			os.WriteFile(filepath.Join(e.p.BatchDir(m.ID()), ManifestFile), []byte("{"), 0o644)
		},
		"truncated parquet": func(e *env, m Manifest) {
			p := filepath.Join(e.p.BatchDir(m.ID()), dataset.EntriesFile)
			b, _ := os.ReadFile(p)
			os.WriteFile(p, b[:len(b)/2], 0o644)
		},
		"gap between batches": func(e *env, m Manifest) {
			os.Rename(e.p.BatchDir(m.ID()), filepath.Join(filepath.Dir(e.p.BatchDir(m.ID())), "batch=000000000010-000000000019"))
		},
	} {
		e := newEnv(t)
		ids := e.ids(1)
		_, s1, end1 := e.batch(0, 5, ids, 1, merkle.NewState(), vault.Tail{}, "done")
		m2, _, _ := e.batch(5, 5, ids, 2, s1, end1, "done")
		damage(e, m2)
		_, err := Recover(RecoverOptions{Paths: e.p, VaultDirs: e.dirs, Index: e.idx, Codec: e.codec, ChainIDs: e.stager.ChainIDs})
		if !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: want ErrCorrupt, got %v", name, err)
		}
	}
}

func TestRecoverCleansOnlyStageAndRebuild(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"tmp/stage/leftover/x", "tmp/rebuild/old/y", "tmp/duckdb-123/spill", "tmp/notes/keep"} {
		os.MkdirAll(filepath.Dir(filepath.Join(e.p.Root, p)), 0o755)
		os.WriteFile(filepath.Join(e.p.Root, p), []byte("x"), 0o644)
	}
	e.recover()
	for p, want := range map[string]bool{"tmp/stage/leftover": false, "tmp/rebuild/old": false, "tmp/duckdb-123/spill": true, "tmp/notes/keep": true} {
		if _, err := os.Stat(filepath.Join(e.p.Root, p)); (err == nil) != want {
			t.Errorf("%s: present=%v, want %v (amendment A1 §7: only tmp/stage and tmp/rebuild)", p, err == nil, want)
		}
	}
}

func TestAbandonInProcess(t *testing.T) {
	e := newEnv(t)
	ids := e.ids(1)
	_, s1, end1 := e.batch(0, 5, ids, 1, merkle.NewState(), vault.Tail{}, "done")
	e.batch(5, 10, ids, 2, s1, end1, "stage")
	in, _ := ReadIntents(e.p)
	if len(in) != 1 {
		t.Fatal("one intent in flight")
	}
	if err := Abandon(e.p, e.dirs, in[0]); err != nil {
		t.Fatal(err)
	}
	if u, _ := vault.InspectTail(e.dirs, end1); u.Bytes != 0 {
		t.Fatal("the vault is cut back to the batch's start")
	}
	if left, _ := ReadIntents(e.p); len(left) != 1 || !left[0].Abandoned {
		t.Fatal("the intent stays, marked abandoned, so a restart skips the touched cert_ids")
	}
	if _, err := os.Stat(e.p.StageDir(in[0].ID())); !os.IsNotExist(err) {
		t.Fatal("staging is removed")
	}
	floor, _ := ReadFloor(e.p.StateDir())
	for restart := 1; restart <= 2; restart++ {
		if r := e.recover(); !r.Crashed || r.NextCertID != floor {
			t.Fatalf("restart %d after an abandon resumes at the floor %d: %+v", restart, floor, r)
		}
		if left, _ := ReadIntents(e.p); len(left) != 1 || !left[0].Abandoned {
			t.Fatalf("restart %d: the abandoned intent stays until a later commit: %+v", restart, left)
		}
	}
}

func (e *env) recoverErr() error {
	_, err := Recover(RecoverOptions{Paths: e.p, VaultDirs: e.dirs, Index: e.idx, Codec: e.codec, ChainIDs: e.stager.ChainIDs})
	return err
}

// TestRecoverRefusesToTruncateUnexplainedData: vault data beyond the
// committed tail that no in-flight batch explains belongs to committed
// batches whose directories went missing (a mistaken rm, a partial
// restore). Truncating it would destroy the only copy; recovery must stop
// with nothing changed.
func TestRecoverRefusesToTruncateUnexplainedData(t *testing.T) {
	e := newEnv(t)
	ids := e.ids(1)
	_, s1, end1 := e.batch(0, 10, ids, 1, merkle.NewState(), vault.Tail{}, "done")
	m2, _, _ := e.batch(10, 10, ids, 2, s1, end1, "done")
	os.RemoveAll(e.p.BatchDir(m2.ID()))
	before, _ := vault.InspectTail(e.dirs, end1)
	if err := e.recoverErr(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("recovery must refuse: %v", err)
	}
	if after, _ := vault.InspectTail(e.dirs, end1); after.Bytes != before.Bytes || before.Bytes == 0 {
		t.Fatalf("nothing may be truncated: %d bytes before, %d after", before.Bytes, after.Bytes)
	}
	os.RemoveAll(filepath.Join(e.p.Root, "dataset", "log=fakelog"))
	if err := e.recoverErr(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a vault with no committed batches at all must not be wiped: %v", err)
	}
}

// TestRecoverRefusesAnIndexAheadOfTheDataset: Pebble is applied after the
// commit point, so it can lag the dataset but never lead it (spec §8.5).
func TestRecoverRefusesAnIndexAheadOfTheDataset(t *testing.T) {
	e := newEnv(t)
	e.batch(0, 10, e.ids(1), 1, merkle.NewState(), vault.Tail{}, "done")
	b := e.idx.NewBatch()
	b.SetApplied("fakelog", 3)
	b.Commit()
	b.Close()
	if err := e.recoverErr(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("an index ahead of the dataset means committed batches are missing: %v", err)
	}
}

// TestRecoverRefusesAForeignSegment: a committed segment whose header names
// another vault (a restore from the wrong backup) is corruption, found
// before Pebble is rebuilt from it (spec §6.2).
func TestRecoverRefusesAForeignSegment(t *testing.T) {
	e := newEnv(t)
	e.batch(0, 10, e.ids(1), 1, merkle.NewState(), vault.Tail{}, "done")
	segs, _ := vault.FindSegments(e.dirs)
	f, _ := os.OpenFile(segs[1], os.O_RDWR, 0)
	b := make([]byte, vault.HeaderSize)
	f.ReadAt(b, 0)
	h, _ := vault.DecodeHeader(b)
	h.VaultUUID = [16]byte{7}
	f.WriteAt(h.Encode(), 0)
	f.Close()
	if err := e.recoverErr(); !errors.Is(err, vault.ErrCorrupt) {
		t.Fatalf("a segment of another vault: %v", err)
	}
}

// TestRecoverRemovesInterruptedAtomicWrites: a writer killed inside
// fsutil.WriteFileAtomic leaves ".<name>.tmp-<n>" behind (found by the
// random kill loop in state/intent). Recovery removes such leftovers from
// the vault's metadata folders and dataset/ (ACTIVE.json), leaves Pebble's
// folder and every other name alone.
func TestRecoverRemovesInterruptedAtomicWrites(t *testing.T) {
	e := newEnv(t)
	gone := []string{"state/intent/.fakelog__000000000080-000000000119.json.tmp-432468658", "state/.ID_FLOOR.tmp-1",
		"state/heads/.fakelog.json.tmp-7", ".views.sql.tmp-99", "vault/dict/.1.dict.tmp-5",
		"dataset/.ACTIVE.json.tmp-3385969005"} // found by the random kill loop with the D tables (A7)
	kept := []string{"state/notes.tmp", "state/pebble/.keep.tmp-3", "tmp/duckdb-1/.x.tmp-4", "state/.hidden", "dataset/notes.tmp"}
	for _, p := range append(slices.Clone(gone), kept...) {
		os.MkdirAll(filepath.Dir(filepath.Join(e.p.Root, p)), 0o755)
		os.WriteFile(filepath.Join(e.p.Root, p), []byte("x"), 0o644)
	}
	r := e.recover()
	for _, p := range gone {
		if _, err := os.Stat(filepath.Join(e.p.Root, p)); err == nil {
			t.Errorf("%s survived recovery", p)
		}
	}
	for _, p := range kept {
		if _, err := os.Stat(filepath.Join(e.p.Root, p)); err != nil {
			t.Errorf("%s was removed: %v", p, err)
		}
	}
	if !slices.Contains(r.Actions, "removed the leftover of an interrupted write: state/.ID_FLOOR.tmp-1") {
		t.Errorf("actions: %q", r.Actions)
	}
}
