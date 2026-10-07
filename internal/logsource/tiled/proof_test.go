package tiled

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"testing"

	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"

	"github.com/4rji/ctvault/internal/ctlogtest"
)

// memTiles serves the hash tiles of a tree over leaf hashes from memory, at
// every width, so proofs are tested without sockets. levels[k][i] is the
// hash of the i-th complete subtree of 256^k leaves.
type memTiles struct {
	levels [][][32]byte
	gets   int
}

func newMemTiles(leaves [][32]byte) *memTiles {
	m := &memTiles{levels: [][][32]byte{leaves}}
	for prev := leaves; len(prev) >= Width; {
		next := make([][32]byte, len(prev)/Width)
		for i := range next {
			next[i] = subtreeRoot(prev[i*Width : (i+1)*Width])
		}
		m.levels = append(m.levels, next)
		prev = next
	}
	return m
}

func (m *memTiles) RoundTrip(r *http.Request) (*http.Response, error) {
	m.gets++
	level, n, w, ok := ctlogtest.ParseTilePath(strings.TrimPrefix(r.URL.Path, "/tile/"))
	if !ok || level < 0 || level >= len(m.levels) || n*Width+uint64(w) > uint64(len(m.levels[level])) {
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}, Request: r}, nil
	}
	var b []byte
	for _, h := range m.levels[level][n*Width : n*Width+uint64(w)] {
		b = append(b, h[:]...)
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(b)), Header: http.Header{}, Request: r}, nil
}

func newMemClient(leaves [][32]byte) (*Client, *memTiles) {
	m := newMemTiles(leaves)
	return NewClient("http://tiles.test/", &http.Client{Transport: m}), m
}

func randomLeaves(n int, seed uint64) ([][32]byte, *testonly.Tree) {
	r := rand.New(rand.NewPCG(seed, 1))
	tree := testonly.New(rfc6962.DefaultHasher)
	leaves := make([][32]byte, n)
	for i := range leaves {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], r.Uint64())
		leaves[i] = sha256.Sum256(b[:])
		tree.Append(leaves[i][:])
	}
	return leaves, tree
}

// memReader reads tiles straight from memTiles, without HTTP.
func (m *memTiles) reader() tileReader {
	return func(_ context.Context, level int, n, size uint64) ([][32]byte, error) {
		w := tileWidth(level, n, size)
		return m.levels[level][n*Width : n*Width+uint64(w)], nil
	}
}

func checkProof(t *testing.T, read tileReader, tree *testonly.Tree, m, n uint64) {
	t.Helper()
	got, err := consistencyProof(context.Background(), read, m, n)
	if err != nil {
		t.Fatalf("proof %d → %d: %v", m, n, err)
	}
	want, err := tree.ConsistencyProof(m, n)
	if err != nil {
		t.Fatal(err)
	}
	if m == 0 || m == n {
		want = nil
	}
	if len(got) != len(want) {
		t.Fatalf("proof %d → %d: %d nodes, want %d", m, n, len(got), len(want))
	}
	for i := range got {
		if !bytes.Equal(got[i][:], want[i]) {
			t.Fatalf("proof %d → %d: node %d differs", m, n, i)
		}
	}
}

// TestProofsFromTiles: a proof read from hash tiles equals the reference
// tree's, byte for byte, for every pair up to 600 entries and random pairs
// up to 70,000, which needs level-1 and level-2 tiles (amendment A6 §7.2).
func TestProofsFromTiles(t *testing.T) {
	// Every pair up to 600, in four parallel parts of about 45,000 proofs
	// each: some nodes are rebuilt from up to 128 hashes, so this is about
	// 45 million hashes in all.
	t.Run("every pair", func(t *testing.T) {
		for _, part := range [][2]uint64{{1, 300}, {301, 425}, {426, 520}, {521, 600}} {
			t.Run(fmt.Sprintf("n=%d-%d", part[0], part[1]), func(t *testing.T) {
				t.Parallel()
				leaves, tree := randomLeaves(600, 1)
				read := newMemTiles(leaves).reader()
				for n := part[0]; n <= part[1]; n++ {
					for m := uint64(0); m <= n; m++ {
						checkProof(t, read, tree, m, n)
					}
				}
			})
		}
	})
	if testing.Short() {
		return
	}
	leaves, tree := randomLeaves(70000, 2)
	c, _ := newMemClient(leaves) // over HTTP: paths, widths and lengths
	read := c.reader(nil)
	r := rand.New(rand.NewPCG(3, 4))
	for k := 0; k < 300; k++ {
		n := 1 + r.Uint64N(70000)
		checkProof(t, read, tree, r.Uint64N(n+1), n)
	}
	for _, p := range [][2]uint64{{65535, 65536}, {65536, 70000}, {256, 65537}, {69999, 70000}, {1, 70000}} {
		checkProof(t, read, tree, p[0], p[1])
	}
}
