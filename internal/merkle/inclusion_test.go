package merkle

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
)

// TestStateFromInclusionEveryLeaf checks the left-sibling rule against a
// reference tree: for every tree size 1-70 and every leaf, the range taken
// from the inclusion proof equals the range built by appending leaves.
func TestStateFromInclusionEveryLeaf(t *testing.T) {
	tree := testonly.New(rfc6962.DefaultHasher)
	var leaves [][32]byte
	for size := uint64(1); size <= 70; size++ {
		data := []byte{byte(size), byte(size >> 8), 7}
		tree.AppendData(data)
		leaves = append(leaves, LeafHash(data))
		var root [32]byte
		copy(root[:], tree.Hash())
		for index := range size {
			raw, err := tree.InclusionProof(index, size)
			if err != nil {
				t.Fatal(err)
			}
			p := make([][32]byte, len(raw))
			for i := range raw {
				copy(p[i][:], raw[i])
			}
			got, err := StateFromInclusion(index, size, leaves[index], root, p)
			if err != nil {
				t.Fatalf("size %d leaf %d: %v", size, index, err)
			}
			want := NewState()
			for _, h := range leaves[:index] {
				want.Append(h)
			}
			gr, _ := got.Root()
			wr, _ := want.Root()
			if got.Size() != index || gr != wr {
				t.Fatalf("size %d leaf %d: range from proof differs from the reference", size, index)
			}
			// The derived range continues correctly: append the rest and
			// reach the signed root.
			for _, h := range leaves[index:size] {
				got.Append(h)
			}
			if r, _ := got.Root(); r != root {
				t.Fatalf("size %d leaf %d: continuing from the derived range must reach the root", size, index)
			}
		}
	}
}

func TestStateFromInclusionRejectsBadProofs(t *testing.T) {
	tree := testonly.New(rfc6962.DefaultHasher)
	var leaves [][32]byte
	for i := range 13 {
		d := []byte{byte(i)}
		tree.AppendData(d)
		leaves = append(leaves, LeafHash(d))
	}
	var root [32]byte
	copy(root[:], tree.Hash())
	raw, _ := tree.InclusionProof(6, 13)
	p := make([][32]byte, len(raw))
	for i := range raw {
		copy(p[i][:], raw[i])
	}
	if _, err := StateFromInclusion(6, 13, leaves[6], root, p); err != nil {
		t.Fatal(err)
	}
	bad := append([][32]byte(nil), p...)
	bad[0][0] ^= 1
	if _, err := StateFromInclusion(6, 13, leaves[6], root, bad); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("an altered node must fail: %v", err)
	}
	if _, err := StateFromInclusion(7, 13, leaves[6], root, p); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("the wrong index must fail: %v", err)
	}
	if err := VerifyInclusion(6, 13, sha256.Sum256(nil), root, p); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("the wrong leaf must fail: %v", err)
	}
}

// TestZeroStateDoesNotPanic covers Plan 1 review minor 16.
func TestZeroStateDoesNotPanic(t *testing.T) {
	var s State
	if _, err := s.Root(); !errors.Is(err, ErrNoState) {
		t.Fatalf("Root: %v", err)
	}
	if err := s.Append([32]byte{}); !errors.Is(err, ErrNoState) {
		t.Fatalf("Append: %v", err)
	}
	if _, err := json.Marshal(&s); !errors.Is(err, ErrNoState) {
		t.Fatalf("Marshal: %v", err)
	}
	if s.Size() != 0 || s.Clone().Size() != 0 {
		t.Fatal("an uninitialized state has size 0")
	}
	for _, in := range []string{`{}`, `{"size": 3}`, `{"compact_range": []}`, `{"size": 0, "compact_range": null}`} {
		var d State
		if err := json.Unmarshal([]byte(in), &d); err == nil {
			t.Errorf("%s: a missing field must be refused, not read as an empty log", in)
		}
	}
	var empty State
	if err := json.Unmarshal([]byte(`{"size": 0, "compact_range": []}`), &empty); err != nil || empty.Size() != 0 {
		t.Fatalf("an explicit empty log is valid: %v", err)
	}
	if r, err := empty.Root(); err != nil || r != [32]byte(rfc6962.DefaultHasher.EmptyRoot()) {
		t.Fatalf("empty root: %v", err)
	}
}
