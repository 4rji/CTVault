package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

var factory = &compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}

// ErrInconsistent is returned when a consistency proof or root comparison fails.
var ErrInconsistent = errors.New("merkle: tree is inconsistent with signed head")

// LeafHash returns the RFC 6962 leaf hash SHA-256(0x00 || leafInput).
func LeafHash(leafInput []byte) [32]byte {
	var h [32]byte
	copy(h[:], rfc6962.DefaultHasher.HashLeaf(leafInput))
	return h
}

// ErrNoState means a State was used without being created by NewState,
// Clone, StateFromInclusion or a successful UnmarshalJSON.
var ErrNoState = errors.New("merkle: state is not initialized")

// State is the compact Merkle range for leaves [0, Size) of one log. Its zero
// value is not usable: methods report ErrNoState (or size 0) instead of
// panicking (Plan 1 review, minor 16).
type State struct {
	r *compact.Range
}

// NewState returns the state of an empty log.
func NewState() *State { return &State{r: factory.NewEmptyRange(0)} }

// Size returns the number of leaves accumulated (0 for an uninitialized state).
func (s *State) Size() uint64 {
	if s.r == nil {
		return 0
	}
	return s.r.End()
}

// Append adds the next leaf hash. Callers must append in strict index order.
func (s *State) Append(leafHash [32]byte) error {
	if s.r == nil {
		return ErrNoState
	}
	return s.r.Append(leafHash[:], nil)
}

// Root returns the RFC 6962 root hash of leaves [0, Size).
func (s *State) Root() ([32]byte, error) {
	var out [32]byte
	if s.r == nil {
		return out, ErrNoState
	}
	if s.r.End() == 0 {
		copy(out[:], rfc6962.DefaultHasher.EmptyRoot())
		return out, nil
	}
	h, err := s.r.GetRootHash(nil)
	if err != nil {
		return out, err
	}
	copy(out[:], h)
	return out, nil
}

// Clone returns an independent copy.
func (s *State) Clone() *State {
	if s.r == nil {
		return &State{}
	}
	c, err := factory.NewRange(0, s.r.End(), s.r.Hashes())
	if err != nil {
		panic(fmt.Sprintf("merkle: cloning a valid range failed: %v", err))
	}
	return &State{r: c}
}

type stateJSON struct {
	Size   *uint64  `json:"size"`
	Hashes []string `json:"compact_range"`
}

// MarshalJSON encodes the state as {"size": N, "compact_range": [hex...]}.
func (s *State) MarshalJSON() ([]byte, error) {
	if s.r == nil {
		return nil, ErrNoState
	}
	size := s.r.End()
	hs := s.r.Hashes()
	out := stateJSON{Size: &size, Hashes: make([]string, len(hs))}
	for i, h := range hs {
		out.Hashes[i] = hex.EncodeToString(h)
	}
	return json.Marshal(out)
}

// UnmarshalJSON decodes and validates the state. Both fields are required:
// a missing size or compact_range is an error, never an empty log.
func (s *State) UnmarshalJSON(b []byte) error {
	var in stateJSON
	if err := json.Unmarshal(b, &in); err != nil {
		return err
	}
	if in.Size == nil || in.Hashes == nil {
		return errors.New("merkle: state needs both size and compact_range")
	}
	hs := make([][]byte, len(in.Hashes))
	for i, h := range in.Hashes {
		d, err := hex.DecodeString(h)
		if err != nil || len(d) != sha256.Size {
			return fmt.Errorf("merkle: compact_range[%d] is not a 32-byte hex hash", i)
		}
		hs[i] = d
	}
	r, err := factory.NewRange(0, *in.Size, hs)
	if err != nil {
		return fmt.Errorf("merkle: invalid compact range for size %d: %w", *in.Size, err)
	}
	s.r = r
	return nil
}

// VerifyConsistency checks that the tree of size1 with root1 is a prefix of the
// signed tree of size2 with root2.
func VerifyConsistency(size1, size2 uint64, root1, root2 [32]byte, p [][32]byte) error {
	nodes := make([][]byte, len(p))
	for i := range p {
		nodes[i] = p[i][:]
	}
	if err := proof.VerifyConsistency(rfc6962.DefaultHasher, size1, size2, nodes, root1[:], root2[:]); err != nil {
		return fmt.Errorf("%w: %v", ErrInconsistent, err)
	}
	return nil
}
