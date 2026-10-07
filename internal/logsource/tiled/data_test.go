package tiled

import (
	"errors"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/logsource"
)

// TestParseDataTileRejects: a tile whose entry boundaries cannot be trusted
// is malformed as a whole (amendment A6 §3.3), each for its stated reason.
func TestParseDataTileRejects(t *testing.T) {
	g, err := ctlogtest.NewGenerator()
	if err != nil {
		t.Fatal(err)
	}
	pre, fin, err := g.Pair("a.example.test", 1790000000000)
	if err != nil {
		t.Fatal(err)
	}
	var fp [32]byte
	x509 := ctlogtest.TileLeaf(fin.LeafInput, ctlogtest.X509Entry, nil, [][32]byte{fp})
	precert := ctlogtest.TileLeaf(pre.LeafInput, ctlogtest.PrecertEntry, pre.CertDER, [][32]byte{fp, fp})
	two := append(append([]byte(nil), x509...), precert...)
	if ls, err := parseDataTile(two, 2, "ok"); err != nil || len(ls) != 2 || !ls[1].precert || len(ls[1].chain) != 2 {
		t.Fatalf("a good tile: %v", err)
	}
	unknown := append([]byte(nil), x509...)
	unknown[9] = 7 // entry_type
	badChain := append([]byte(nil), x509[:len(x509)-34]...)
	badChain = append(badChain, 0, 31)
	badChain = append(badChain, make([]byte, 31)...)
	for name, c := range map[string]struct {
		tile []byte
		want int
		why  string
	}{
		"an entry too many":    {two, 1, "bytes follow the 1 entries"},
		"bytes after the last": {append(append([]byte(nil), two...), 0, 1), 2, "bytes follow the 2 entries"},
		"an entry missing":     {x509, 2, "1 entries, want 2"},
		"cut in the middle":    {two[:len(two)-10], 2, "truncated"},
		"unknown entry type":   {unknown, 1, "unknown entry type 7"},
		"chain of 31 bytes":    {badChain, 1, "not a multiple of 32"},
		"empty":                {nil, 1, "0 entries, want 1"},
	} {
		_, err := parseDataTile(c.tile, c.want, "t")
		if !errors.Is(err, logsource.ErrMalformed) || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: got %v, want %q", name, err, c.why)
		}
	}
}
