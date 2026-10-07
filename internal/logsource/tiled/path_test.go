package tiled

import "testing"

// TestPaths: the specs' own examples (tlog-tiles, static-ct-api).
func TestPaths(t *testing.T) {
	for n, want := range map[uint64]string{0: "000", 7: "007", 999: "999", 1000: "x001/000", 1234067: "x001/x234/067", 6202854: "x006/x202/854"} {
		if got := encodeIndex(n); got != want {
			t.Errorf("encodeIndex(%d) = %q, want %q", n, got, want)
		}
	}
	for got, want := range map[string]string{
		TilePath(0, 1234067, Width):   "tile/0/x001/x234/067",
		TilePath(1, 24229, 230):       "tile/1/x024/229.p/230",
		TilePath(3, 0, 94):            "tile/3/000.p/94",
		DataPath(6202854, Width):      "tile/data/x006/x202/854",
		DataPath(0, 1):                "tile/data/000.p/1",
		IssuerPath([32]byte{0xad, 1}): "issuer/ad01000000000000000000000000000000000000000000000000000000000000",
	} {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

// TestTileWidths: tlog-tiles' example, a tree of 70,000 entries, is 273
// full level-0 tiles and one of width 112, one full level-1 tile and one of
// width 17, and one level-2 tile of width 1; a tree of 256 is one full
// level-0 tile and a level-1 tile of width 1.
func TestTileWidths(t *testing.T) {
	cases := []struct {
		level   int
		n, size uint64
		want    int
	}{
		{0, 0, 70000, Width}, {0, 272, 70000, Width}, {0, 273, 70000, 112}, {0, 274, 70000, 0},
		{1, 0, 70000, Width}, {1, 1, 70000, 17}, {1, 2, 70000, 0},
		{2, 0, 70000, 1}, {2, 1, 70000, 0}, {3, 0, 70000, 0},
		{0, 0, 256, Width}, {1, 0, 256, 1}, {0, 1, 256, 0},
		{0, 6202854, 1587930800, 176}, {1, 24229, 1587930800, 230}, {2, 94, 1587930800, 165}, {3, 0, 1587930800, 94},
	}
	for _, c := range cases {
		if got := tileWidth(c.level, c.n, c.size); got != c.want {
			t.Errorf("tileWidth(%d, %d, %d) = %d, want %d", c.level, c.n, c.size, got, c.want)
		}
	}
}
