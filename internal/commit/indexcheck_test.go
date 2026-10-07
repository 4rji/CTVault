package commit

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

func (e *env) checkIndex(live bool) (IndexReport, error) {
	e.t.Helper()
	committed, err := ListCommitted(e.p.Root)
	if err != nil {
		e.t.Fatal(err)
	}
	return CheckIndex(e.idx, IndexCheck{Paths: e.p, VaultDirs: e.dirs, Codec: e.codec, ChainIDs: e.stager.ChainIDs, Committed: committed, Live: live})
}

// edit applies fn to the live index in one batch.
func (e *env) edit(fn func(b *index.Batch)) {
	e.t.Helper()
	b := e.idx.NewBatch()
	defer b.Close()
	fn(b)
	if err := b.Commit(); err != nil {
		e.t.Fatal(err)
	}
}

// someCert is one certificate key of the index and its reference.
func (e *env) someCert() ([32]byte, index.Ref) {
	var sha [32]byte
	var ref index.Ref
	e.idx.EachCert(func(s [32]byte, r index.Ref) error {
		sha, ref = s, r
		return errors.New("stop")
	})
	return sha, ref
}

// TestCheckIndex: the index check passes on a sound index and names each
// kind of damage: a missing key, a key pointing elsewhere, a key with no
// record, a missing or extra chain key, applied positions ahead of the
// commits; a live index behind the commits is pending, not damaged
// (amendment A5 §2.2, §3.1).
func TestCheckIndex(t *testing.T) {
	cases := map[string]struct {
		damage func(e *env)
		want   string // "" passes
	}{
		"sound": {func(*env) {}, ""},
		"a missing key": {func(e *env) {
			sha, _ := e.someCert()
			e.edit(func(b *index.Batch) { b.DeleteCert(sha) })
		}, "lacks certificate"},
		"a key pointing elsewhere": {func(e *env) {
			sha, r := e.someCert()
			r.Loc.Offset++
			e.edit(func(b *index.Batch) { b.AddCert(sha, r) })
		}, "maps"},
		"a key with no record": {func(e *env) {
			e.edit(func(b *index.Batch) { b.AddCert(sha256.Sum256([]byte("never vaulted")), index.Ref{CertID: 999}) })
		}, "have no record"},
		"a missing chain": {func(e *env) {
			e.edit(func(b *index.Batch) { b.DeleteChain(sha256.Sum256([]byte{10})) })
		}, "lacks chain"},
		"an extra chain": {func(e *env) {
			e.edit(func(b *index.Batch) { b.AddChain(sha256.Sum256([]byte("no such chain"))) })
		}, "chain keys"},
		"applied ahead": {func(e *env) {
			e.edit(func(b *index.Batch) { b.SetApplied("fakelog", 9) })
		}, "ahead"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			threeBatches(t, e)
			c.damage(e)
			rep, err := e.checkIndex(true)
			switch {
			case c.want == "" && err != nil:
				t.Fatal(err)
			case c.want == "":
				if rep.Batches != 3 || rep.Certs != 30 || rep.Chains != 3 || len(rep.Pending) != 0 {
					t.Fatalf("report %+v", rep)
				}
			case err == nil || !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), c.want):
				t.Fatalf("got %v, want damage mentioning %q", err, c.want)
			}
		})
	}

	// A live index one batch behind: the writer stopped between the commit
	// point and P9 (spec §8.5). Pending for the writer's index; damage for
	// a rebuilt one, which must be complete.
	e := newEnv(t)
	ids := e.ids(1)
	m1, s1, end1 := e.batch(0, 10, ids, 1, merkle.NewState(), vault.Tail{}, "done")
	e.batch(10, 10, ids, 2, s1, end1, "publish")
	rep, err := e.checkIndex(true)
	if err != nil || rep.Batches != 1 || rep.Certs != 10 || len(rep.Pending) != 1 || rep.Pending[0] == m1.BatchID {
		t.Fatalf("a lagging live index: %+v, %v", rep, err)
	}
	if _, err := e.checkIndex(false); err == nil || !strings.Contains(err.Error(), "applied") {
		t.Fatalf("a lagging rebuilt index passes: %v", err)
	}
}

// TestReindexMemoryStaysFlat: repair --reindex keeps no per-certificate
// state, so its Go heap does not grow with the vault (amendment A5 §3.1):
// within one reindex of 8 batches, the heap after the first batch and after
// the last are the same, while building and while checking. A2's check held
// a map of every certificate.
func TestReindexMemoryStaysFlat(t *testing.T) {
	const batches, size = 8, 1000
	e := newEnv(t)
	e.certs = nil
	for i := range batches * size {
		e.certs = append(e.certs, []byte(fmt.Sprintf("certificate %08d %s", i, strings.Repeat("x", 200))))
	}
	ids := e.ids(1)
	state, tail := merkle.NewState(), vault.Tail{}
	for i := range uint64(batches) {
		_, state, tail = e.batch(i*size, size, ids, i+1, state, tail, "done")
	}
	e.certs = nil // the fixture's own data is not the reindex's
	heap := func() int64 {
		var ms runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&ms)
		return int64(ms.HeapAlloc)
	}
	var built, checked [2]int64
	e.idx.Close()
	_, err := Reindex(ReindexOptions{Paths: e.p, VaultDirs: e.dirs, Codec: e.codec, ChainIDs: e.stager.ChainIDs,
		Hook: func(h string) {
			switch h {
			case HookReindexBuilding:
				built[0] = heap()
			case HookReindexBuilt:
				built[1] = heap()
			}
		},
		Progress: func(done, total int) {
			switch done {
			case 1:
				checked[0] = heap()
			case total:
				checked[1] = heap()
			}
		}})
	var oerr error
	e.idx, oerr = index.Open(e.p.StateDir() + "/pebble")
	if err != nil || oerr != nil {
		t.Fatal(err, oerr)
	}
	for _, p := range []struct {
		what string
		at   [2]int64
	}{{"building", built}, {"checking", checked}} {
		if per := (p.at[1] - p.at[0]) / ((batches - 1) * size); p.at[0] == 0 || per > 20 {
			t.Fatalf("%s the index keeps %d bytes of Go heap per certificate (%d → %d)", p.what, per, p.at[0], p.at[1])
		}
	}
}
