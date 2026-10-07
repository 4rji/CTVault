package tiled

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync/atomic"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"

	"github.com/4rji/ctvault/internal/logsource"
)

// fetchTile fetches the file of tile n (hash tile at level, or data tile
// when level < 0) as it exists in a tree of size: the full file when the
// tile is full there, else the partial ".p/W", falling back to the full file
// when the partial answers 404 (amendment A6 §4.2). It returns the body, the
// width the tree needs and the width of the file served: a full file read
// for a partial tile holds more, and the caller uses the first items.
func (c *Client) fetchTile(ctx context.Context, level int, n, size uint64, max int, fallbacks *atomic.Int64) ([]byte, int, int, error) {
	l := level
	if l < 0 {
		l = 0
	}
	w := tileWidth(l, n, size)
	if w == 0 {
		return nil, 0, 0, fmt.Errorf("tile %d at level %d is beyond a tree of %d entries", n, level, size)
	}
	path := func(width int) string {
		if level < 0 {
			return DataPath(n, width)
		}
		return TilePath(level, n, width)
	}
	b, err := c.Get(ctx, path(w), max)
	served := w
	if err != nil && w < Width && notFound(err) {
		if fallbacks != nil {
			fallbacks.Add(1)
		}
		b, err = c.Get(ctx, path(Width), max)
		served = Width
	}
	return b, w, served, err
}

// HashTile returns the first width hashes of hash tile n at level within a
// tree of size. The tile's length must be exactly 32 hashes per item.
func (c *Client) HashTile(ctx context.Context, level int, n, size uint64, fallbacks *atomic.Int64) ([][32]byte, error) {
	b, w, served, err := c.fetchTile(ctx, level, n, size, maxTileBytes, fallbacks)
	if err != nil {
		return nil, err
	}
	if len(b) != served*32 {
		return nil, fmt.Errorf("%w: hash tile %s: %d bytes, want %d", logsource.ErrMalformed, TilePath(level, n, served), len(b), served*32)
	}
	out := make([][32]byte, w)
	for i := range out {
		copy(out[i][:], b[i*32:])
	}
	return out, nil
}

// hashChildren is RFC 6962's interior node hash, SHA-256(0x01 || l || r),
// without allocating: a proof may rebuild a few hundred nodes.
func hashChildren(l, r [32]byte) [32]byte {
	var b [65]byte
	b[0] = 1
	copy(b[1:], l[:])
	copy(b[33:], r[:])
	return sha256.Sum256(b[:])
}

// subtreeRoot is the RFC 6962 hash of a perfect subtree given its leaves at
// one tile level (a power-of-two count).
func subtreeRoot(hs [][32]byte) [32]byte {
	cur := append([][32]byte(nil), hs...)
	for len(cur) > 1 {
		next := cur[:len(cur)/2]
		for i := range next {
			next[i] = hashChildren(cur[2*i], cur[2*i+1])
		}
		cur = next
	}
	return cur[0]
}

// tileReader returns the first width hashes of hash tile n at level within
// a tree of size, as hashTile does over HTTP.
type tileReader func(ctx context.Context, level int, n, size uint64) ([][32]byte, error)

func (c *Client) reader(fallbacks *atomic.Int64) tileReader {
	return func(ctx context.Context, level int, n, size uint64) ([][32]byte, error) {
		return c.HashTile(ctx, level, n, size, fallbacks)
	}
}

// node reads the hash of the perfect subtree at (level L, index i) of a tree
// of size from the tile at level L/8: one hash when L is a multiple of 8,
// else the root of 2^(L mod 8) consecutive hashes of one tile (A6 §4.1).
// tiles caches the tiles one proof reads.
func node(ctx context.Context, read tileReader, L uint, i, size uint64, tiles map[[2]uint64][][32]byte) ([32]byte, error) {
	t, r := int(L/8), L%8
	first := i << r
	k := first / Width
	key := [2]uint64{uint64(t), k}
	hs, ok := tiles[key]
	if !ok {
		var err error
		if hs, err = read(ctx, t, k, size); err != nil {
			return [32]byte{}, err
		}
		tiles[key] = hs
	}
	off, cnt := first%Width, uint64(1)<<r
	if off+cnt > uint64(len(hs)) {
		return [32]byte{}, fmt.Errorf("%w: node (%d, %d) needs hashes [%d, %d) of a tile of %d", logsource.ErrMalformed, L, i, off, off+cnt, len(hs))
	}
	return subtreeRoot(hs[off : off+cnt]), nil
}

// ConsistencyProof computes the proof that the tree of size first is a
// prefix of the tree of size second from hash tiles. second must be the size
// of a verified checkpoint, which is what lets partial tiles be asked for.
// The tiles are not trusted: the caller checks the proof against both roots.
func (c *Client) ConsistencyProof(ctx context.Context, first, second uint64, fallbacks *atomic.Int64) ([][32]byte, error) {
	return consistencyProof(ctx, c.reader(fallbacks), first, second)
}

func consistencyProof(ctx context.Context, read tileReader, first, second uint64) ([][32]byte, error) {
	if first == 0 || first == second {
		return nil, nil
	}
	p, err := proof.Consistency(first, second)
	if err != nil {
		return nil, err
	}
	tiles := map[[2]uint64][][32]byte{}
	hs := make([][]byte, len(p.IDs))
	for k, id := range p.IDs {
		h, err := node(ctx, read, id.Level, id.Index, second, tiles)
		if err != nil {
			return nil, err
		}
		hs[k] = h[:]
	}
	nodes, err := p.Rehash(hs, rfc6962.DefaultHasher.HashChildren)
	if err != nil {
		return nil, err
	}
	out := make([][32]byte, len(nodes))
	for k, n := range nodes {
		copy(out[k][:], n)
	}
	return out, nil
}

// CompactRange reads the compact range of entries [0, size) from the hash
// tiles of a tree of size ref (ref >= size, a verified checkpoint's size):
// the hashes of compact.RangeNodes(0, size), left to right. It is the Merkle
// state at size without an inclusion proof (amendment A6 §5).
func (c *Client) CompactRange(ctx context.Context, size, ref uint64, fallbacks *atomic.Int64) ([][32]byte, error) {
	if size > ref {
		return nil, fmt.Errorf("compact range of %d entries in a tree of %d", size, ref)
	}
	read := c.reader(fallbacks)
	tiles := map[[2]uint64][][32]byte{}
	ids := compact.RangeNodes(0, size, nil)
	out := make([][32]byte, len(ids))
	for k, id := range ids {
		h, err := node(ctx, read, id.Level, id.Index, ref, tiles)
		if err != nil {
			return nil, err
		}
		out[k] = h
	}
	return out, nil
}
