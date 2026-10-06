package commit

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

// threeBatches commits three batches and returns them.
func threeBatches(t *testing.T, e *env) []Manifest {
	t.Helper()
	ids := e.ids(1)
	var ms []Manifest
	state, tail := merkle.NewState(), vault.Tail{}
	for i := range uint64(3) {
		var m Manifest
		m, state, tail = e.batch(i*10, 10, ids, i+1, state, tail, "done")
		ms = append(ms, m)
	}
	return ms
}

func (e *env) reindex() (ReindexReport, error) {
	e.t.Helper()
	e.idx.Close()
	rep, err := Reindex(ReindexOptions{Paths: e.p, VaultDirs: e.dirs, Codec: e.codec, ChainIDs: e.stager.ChainIDs})
	var oerr error
	if e.idx, oerr = index.Open(filepath.Join(e.p.StateDir(), "pebble")); oerr != nil {
		e.t.Fatal(oerr)
	}
	return rep, err
}

// TestReindexReplacesTheIndex: repair --reindex builds a new index from the
// vault and chains.parquet beside the old one and exchanges them; wrong,
// extra and missing keys are gone, and nothing is left beside state/pebble
// (amendment A2 §5.6).
func TestReindexReplacesTheIndex(t *testing.T) {
	e := newEnv(t)
	ms := threeBatches(t, e)
	good := map[[32]byte]index.Ref{}
	e.idx.EachCert(func(sha [32]byte, r index.Ref) error { good[sha] = r; return nil })
	var some [32]byte
	for sha := range good {
		some = sha
		break
	}
	b := e.idx.NewBatch()
	b.AddCert(some, index.Ref{CertID: 424242, Loc: vault.Loc{Segment: 9}})
	b.AddCert(sha256.Sum256([]byte("not vaulted")), index.Ref{CertID: 7})
	b.SetApplied("fakelog", 1)
	b.Commit()
	b.Close()

	rep, err := e.reindex()
	if err != nil {
		t.Fatal(err)
	}
	if rep.Batches != 3 || rep.Certs != len(good) || rep.Chains != 3 {
		t.Fatalf("report %+v, want 3 batches, %d certificates, 3 chains", rep, len(good))
	}
	n := 0
	e.idx.EachCert(func(sha [32]byte, r index.Ref) error {
		if n++; good[sha] != r {
			t.Errorf("%x: %+v, want %+v", sha[:4], r, good[sha])
		}
		return nil
	})
	if applied, _ := e.idx.AppliedLogs(); n != len(good) || applied["fakelog"] != ms[2].CommitSeq {
		t.Fatalf("%d certificate keys (want %d), applied %v", n, len(good), applied)
	}
	if ok, _ := e.idx.HasChain(sha256.Sum256([]byte{byte(ms[1].First)})); !ok {
		t.Fatal("a chain of chains.parquet is missing from the new index")
	}
	es, _ := os.ReadDir(e.p.StateDir())
	for _, x := range es {
		if x.Name() != "pebble" && x.IsDir() && x.Name() != "intent" && x.Name() != "logs" {
			t.Errorf("state/%s is left beside the index", x.Name())
		}
	}
}

// TestReindexRefusesWithoutExchange: on a filesystem without
// RENAME_EXCHANGE, repair --reindex refuses before building anything and
// the old index is untouched.
func TestReindexRefusesWithoutExchange(t *testing.T) {
	e := newEnv(t)
	threeBatches(t, e)
	old := renameExchange
	renameExchange = func(a, b string) error { return unix.EINVAL }
	defer func() { renameExchange = old }()
	before := map[[32]byte]index.Ref{}
	e.idx.EachCert(func(sha [32]byte, r index.Ref) error { before[sha] = r; return nil })
	if _, err := e.reindex(); !errors.Is(err, ErrNoExchange) {
		t.Fatalf("without RENAME_EXCHANGE: %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.p.StateDir(), ReindexDir)); err == nil {
		t.Fatal("a new index was started")
	}
	n := 0
	e.idx.EachCert(func(sha [32]byte, r index.Ref) error {
		if n++; before[sha] != r {
			t.Errorf("%x changed", sha[:4])
		}
		return nil
	})
	if n != len(before) {
		t.Fatalf("%d keys, had %d", n, len(before))
	}
}
