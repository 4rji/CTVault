package ctlogtest

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/transparency-dev/merkle/rfc6962"
)

func getTiled(t *testing.T, url string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// TestTiledPartials: partial tiles exist only for published sizes, and go
// once the full tile exists unless KeepPartials (static-ct-api).
func TestTiledPartials(t *testing.T) {
	l := New(t, 300, Options{Tiled: true})
	l.Publish(100)
	l.Publish(300)
	for path, want := range map[string]int{
		"tile/data/000":       200, // full since 256 entries are published
		"tile/data/000.p/100": 404, // a published size, but the full tile exists now
		"tile/data/001.p/44":  200, // 300 = 256 + 44
		"tile/data/001.p/43":  404, // never published
		"tile/0/001.p/44":     200,
		"tile/1/000.p/1":      200,
		"tile/1/000":          404,
		"tile/data/002":       404,
	} {
		if code, _ := getTiled(t, l.URL+path); code != want {
			t.Errorf("%s: %d, want %d", path, code, want)
		}
	}
	k := New(t, 300, Options{Tiled: true, KeepPartials: true})
	k.Publish(100)
	k.Publish(300)
	if code, _ := getTiled(t, k.URL+"tile/data/000.p/100"); code != 200 {
		t.Errorf("KeepPartials: %d", code)
	}
}

// TestTiledTrees: the level-1 tile of a 256-entry tree is the tree's root,
// the level-0 tile its leaf hashes, and the checkpoint carries the same root
// as get-sth.
func TestTiledTrees(t *testing.T) {
	l := New(t, 256, Options{Tiled: true})
	_, l1 := getTiled(t, l.URL+"tile/1/000.p/1")
	if !bytes.Equal(l1, l.rootAt(256)) {
		t.Fatal("tile/1/000.p/1 is not the root of 256 entries")
	}
	_, l0 := getTiled(t, l.URL+"tile/0/000")
	for i, e := range l.Entries {
		if !bytes.Equal(l0[32*i:32*i+32], rfc6962.DefaultHasher.HashLeaf(e.LeafInput)) {
			t.Fatalf("level-0 hash %d", i)
		}
	}
	_, cp := getTiled(t, l.URL+"checkpoint")
	lines := strings.Split(string(cp), "\n")
	if lines[0] != DefaultOrigin || lines[1] != "256" || lines[3] != "" || !strings.HasPrefix(lines[4], "— "+DefaultOrigin+" ") {
		t.Fatalf("checkpoint:\n%s", cp)
	}
	// Every entry carries leaf_index = position in both protocols.
	for i, e := range l.Entries {
		ext := e.LeafInput[len(e.LeafInput)-8:]
		if e.LeafInput[len(e.LeafInput)-10] != 0 || e.LeafInput[len(e.LeafInput)-9] != 8 || ext[0] != 0 || ext[2] != 5 || ext[7] != byte(i) {
			t.Fatalf("entry %d extensions %x", i, e.LeafInput[len(e.LeafInput)-10:])
		}
	}
}

func TestParseTilePath(t *testing.T) {
	for p, want := range map[string][3]int{
		"0/x001/x234/067": {0, 1234067, 256}, "data/005.p/7": {-1, 5, 7}, "3/000.p/94": {3, 0, 94},
	} {
		level, n, w, ok := ParseTilePath(p)
		if !ok || level != want[0] || n != uint64(want[1]) || w != want[2] {
			t.Errorf("%s: %d %d %d %v", p, level, n, w, ok)
		}
	}
	for _, bad := range []string{"0/1", "0/x1/000", "6/000", "0/000.p/256", "0/000.p/0", "data/000.p/01", "01/000"} {
		if _, _, _, ok := ParseTilePath(bad); ok {
			t.Errorf("%s parsed", bad)
		}
	}
}
