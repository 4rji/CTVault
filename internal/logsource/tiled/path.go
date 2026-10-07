package tiled

import (
	"strconv"
	"strings"
)

// Width is the number of hashes in a full tile, and of entries in a full
// data tile (tlog-tiles).
const Width = 256

// PageSize is the fetcher's page size for tiled logs: one data tile per
// request (amendment A6 §4.4).
const PageSize = Width

// encodeIndex writes a tile index as 3-digit path elements, all but the
// last prefixed with "x": 1234067 is "x001/x234/067" (tlog-tiles).
func encodeIndex(n uint64) string {
	parts := []string{}
	for {
		parts = append(parts, strconv.FormatUint(n%1000, 10))
		n /= 1000
		if n == 0 {
			break
		}
	}
	var b strings.Builder
	for i := len(parts) - 1; i >= 0; i-- {
		if i != len(parts)-1 {
			b.WriteByte('/')
		}
		if i > 0 {
			b.WriteByte('x')
		}
		b.WriteString(strings.Repeat("0", 3-len(parts[i])) + parts[i])
	}
	return b.String()
}

func withWidth(p string, w int) string {
	if w == Width {
		return p
	}
	return p + ".p/" + strconv.Itoa(w)
}

// TilePath is the path of hash tile n at level, of width w (Width for a
// full tile).
func TilePath(level int, n uint64, w int) string {
	return withWidth("tile/"+strconv.Itoa(level)+"/"+encodeIndex(n), w)
}

// DataPath is the path of data tile n, of width w (Width for a full tile).
func DataPath(n uint64, w int) string {
	return withWidth("tile/data/"+encodeIndex(n), w)
}

// IssuerPath is the path of the issuer with SHA-256 fp, lowercase hex.
func IssuerPath(fp [32]byte) string {
	const hexdigits = "0123456789abcdef"
	b := make([]byte, 0, 7+64)
	b = append(b, "issuer/"...)
	for _, c := range fp {
		b = append(b, hexdigits[c>>4], hexdigits[c&15])
	}
	return string(b)
}

// tileWidth is the width of tile n at level within a tree of size: Width
// when the tile is full in it, the partial width when n is the right edge,
// and 0 when the tile is beyond the tree.
func tileWidth(level int, n, size uint64) int {
	span := pow256(level + 1) // entries one tile covers
	switch {
	case span == 0: // beyond 2^64 entries: only tile 0 exists, and it is partial
		if n > 0 {
			return 0
		}
		return int(size / pow256(level) % Width)
	case n < size/span:
		return Width
	case n == size/span:
		return int(size / pow256(level) % Width)
	}
	return 0
}

// pow256 is 256^k, or 0 when it overflows a uint64.
func pow256(k int) uint64 {
	if k >= 8 {
		return 0
	}
	return 1 << (8 * k)
}
