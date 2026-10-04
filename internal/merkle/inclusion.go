package merkle

import (
	"fmt"
	"slices"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

// VerifyInclusion checks that leafHash is leaf index of the tree of size with
// the given root.
func VerifyInclusion(index, size uint64, leafHash, root [32]byte, p [][32]byte) error {
	nodes := make([][]byte, len(p))
	for i := range p {
		nodes[i] = p[i][:]
	}
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, index, size, leafHash[:], nodes, root[:]); err != nil {
		return fmt.Errorf("%w: inclusion of leaf %d in tree %d: %v", ErrInconsistent, index, size, err)
	}
	return nil
}

// StateFromInclusion returns the authenticated compact range of leaves
// [0, index), taken from a verified inclusion proof for leaf index. In the
// RFC 9162 §2.1.3.2 verification walk, a proof node is a left sibling exactly
// when the low bit of fn is set or fn == sn; those left siblings, read from
// the top down, are the compact range of [0, index) (amendment A1 §2.4).
func StateFromInclusion(index, size uint64, leafHash, root [32]byte, p [][32]byte) (*State, error) {
	if err := VerifyInclusion(index, size, leafHash, root, p); err != nil {
		return nil, err
	}
	var left [][]byte
	fn, sn := index, size-1
	for _, node := range p {
		if sn == 0 {
			return nil, fmt.Errorf("%w: inclusion proof for leaf %d is too long", ErrInconsistent, index)
		}
		if fn&1 == 1 || fn == sn {
			left = append(left, node[:])
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		}
		fn >>= 1
		sn >>= 1
	}
	slices.Reverse(left)
	r, err := factory.NewRange(0, index, left)
	if err != nil {
		return nil, fmt.Errorf("%w: left siblings do not form the range [0, %d): %v", ErrInconsistent, index, err)
	}
	return &State{r: r}, nil
}
