package index

import (
	"testing"

	"github.com/4rji/ctvault/internal/vault"
)

func TestBatchSeesItsOwnWritesAndCommitsDurably(t *testing.T) {
	dir := t.TempDir()
	x, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	sha := [32]byte{1}
	ref := Ref{CertID: 1 << 40, Loc: vault.Loc{Segment: 3, Offset: 1 << 33, Len: 1500}}
	b := x.NewBatch()
	if _, ok, _ := b.Lookup(sha); ok {
		t.Fatal("empty index")
	}
	b.AddCert(sha, ref)
	if got, ok, err := b.Lookup(sha); err != nil || !ok || got != ref {
		t.Fatalf("a duplicate within the batch must be found: %+v %v %v", got, ok, err)
	}
	if _, ok, _ := x.Lookup(sha); ok {
		t.Fatal("nothing is visible before the commit point")
	}
	b.AddChain([32]byte{9})
	if has, _ := b.HasChain([32]byte{9}); !has {
		t.Fatal("a chain added in this batch is known")
	}
	b.SetApplied("argon2027h1", 7)
	if err := b.Commit(); err != nil {
		t.Fatal(err)
	}
	b.Close()
	x.Close()

	x, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	if got, ok, err := x.Lookup(sha); err != nil || !ok || got != ref {
		t.Fatalf("committed entry after reopen: %+v %v %v", got, ok, err)
	}
	if seq, err := x.Applied("argon2027h1"); err != nil || seq != 7 {
		t.Fatalf("applied/<log>: %d %v", seq, err)
	}
	if seq, _ := x.Applied("other"); seq != 0 {
		t.Fatal("a log never applied reports 0")
	}
	b2 := x.NewBatch()
	defer b2.Close()
	if has, _ := b2.HasChain([32]byte{9}); !has {
		t.Fatal("committed chains are remembered")
	}
}

func TestDiscardedBatchLeavesNothing(t *testing.T) {
	x, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	b := x.NewBatch()
	b.AddCert([32]byte{2}, Ref{CertID: 5})
	b.Close() // an abandoned batch
	if _, ok, _ := x.Lookup([32]byte{2}); ok {
		t.Fatal("an abandoned batch must not reach the index")
	}
}

func TestRefEncoding(t *testing.T) {
	r := Ref{CertID: 123456789, Loc: vault.Loc{Segment: 70000, Offset: 1<<40 + 5, Len: 1<<32 - 1}}
	got, err := decodeRef(encodeRef(r))
	if err != nil || got != r {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if _, err := decodeRef(append(encodeRef(r), 0)); err == nil {
		t.Fatal("trailing bytes are malformed")
	}
	if _, err := decodeRef([]byte{0x80}); err == nil {
		t.Fatal("a truncated varint is malformed")
	}
}
