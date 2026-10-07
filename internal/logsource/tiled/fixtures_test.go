package tiled

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/loglist"
	"github.com/4rji/ctvault/internal/merkle"
)

// The probe's real files from parcelyard2026h2 (internal/testdata, captured
// 2026-10-07 04:22Z; /mnt/disk/ctvault/tiled/PROBE.md).
const (
	pyOrigin = "parcelyard2026h2.prod.certificate.transparency.goog"
	pySize   = 1587930800
	pyTile   = 6202854 // the live data tile and its level-0 tile
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parcelyard(t *testing.T) loglist.Resolved {
	t.Helper()
	l, err := loglist.Fetch(context.Background(), http.DefaultClient, "../../testdata/log_list_v93.6_full.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := l.Find("parcelyard2026h2")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// fileTiles serves fixture files at their log paths; anything else is 404.
type fileTiles map[string][]byte

func (f fileTiles) RoundTrip(r *http.Request) (*http.Response, error) {
	b, ok := f[strings.TrimPrefix(r.URL.Path, "/")]
	code := 200
	if !ok {
		code = 404
	}
	return &http.Response{StatusCode: code, Body: io.NopCloser(bytes.NewReader(b)), Header: http.Header{}, Request: r}, nil
}

// TestRealCheckpoint: ParcelYard's checkpoint verifies with the log list's
// key; its other three signature lines (the log's Ed25519 one, two
// witnesses) are ignored (amendment A6 §2).
func TestRealCheckpoint(t *testing.T) {
	r := parcelyard(t)
	pub, err := loglist.ParseKey(r.Log.Key, r.Log.LogID)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := base64.StdEncoding.DecodeString(r.Log.LogID)
	origin, err := loglist.Origin(r.SubmissionURL)
	if err != nil || origin != pyOrigin {
		t.Fatalf("origin %q, %v", origin, err)
	}
	if k := KeyID(origin, [32]byte(id)); hex.EncodeToString(k[:]) != "93a78ae0" {
		t.Fatalf("key ID %x, the checkpoint's line says 93a78ae0", k)
	}
	cp := fixture(t, "parcelyard2026h2_checkpoint")
	sth, err := ParseCheckpoint(cp, origin, [32]byte(id))
	if err != nil {
		t.Fatal(err)
	}
	if sth.TreeSize != pySize || sth.Timestamp != 1791346973252 {
		t.Fatalf("parsed %+v", sth)
	}
	if err := merkle.VerifySTH(pub, sth); err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(cp), "\n— ") != 4 {
		t.Fatal("the fixture should carry four signature lines")
	}
}

// TestRealRootFromTiles: the compact range of the whole tree, read from the
// right-edge tiles (the level-0 partial answering 404 and falling back to
// the full tile, as it did live), gives the checkpoint's root.
func TestRealRootFromTiles(t *testing.T) {
	r := parcelyard(t)
	id, _ := base64.StdEncoding.DecodeString(r.Log.LogID)
	sth, err := ParseCheckpoint(fixture(t, "parcelyard2026h2_checkpoint"), pyOrigin, [32]byte(id))
	if err != nil {
		t.Fatal(err)
	}
	files := fileTiles{
		"tile/0/x006/x202/854":  fixture(t, "parcelyard2026h2_tile_0_x006_x202_854"),
		"tile/1/x024/229.p/230": fixture(t, "parcelyard2026h2_tile_1_x024_229.p_230"),
		"tile/2/094.p/165":      fixture(t, "parcelyard2026h2_tile_2_094.p_165"),
		"tile/3/000.p/94":       fixture(t, "parcelyard2026h2_tile_3_000.p_94"),
	}
	c := NewClient("http://py.test/", &http.Client{Transport: files})
	var fallbacks atomic.Int64
	hs, err := c.CompactRange(context.Background(), pySize, pySize, &fallbacks)
	if err != nil {
		t.Fatal(err)
	}
	st, err := merkle.StateFromNodes(pySize, hs)
	if err != nil {
		t.Fatal(err)
	}
	root, err := st.Root()
	if err != nil || root != sth.RootHash {
		t.Fatalf("root from tiles %x, checkpoint %x (%v)", root, sth.RootHash, err)
	}
	if fallbacks.Load() != 1 {
		t.Fatalf("%d fallbacks; the level-0 partial is the one missing", fallbacks.Load())
	}
}

// TestRealDataTile: all 256 live entries hash to the level-0 tile, each
// carries its leaf_index, and the tile's measured mix holds (PROBE.md).
func TestRealDataTile(t *testing.T) {
	data := fixture(t, "parcelyard2026h2_data_x006_x202_854")
	hashes := fixture(t, "parcelyard2026h2_tile_0_x006_x202_854")
	leaves, err := parseDataTile(data, Width, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	issuers := map[[32]byte]bool{}
	precerts := 0
	for i, l := range leaves {
		li := l.leafInput()
		if merkle.LeafHash(li) != [32]byte(hashes[32*i:32*i+32]) {
			t.Fatalf("entry %d does not hash to the level-0 tile", i)
		}
		e := leaf.Entry{}
		leaf.CheckLeafIndex(&e, l.extensions, pyTile*Width+uint64(i))
		if e.Code != leaf.OK {
			t.Fatalf("entry %d: %s", i, e.Code)
		}
		if l.precert {
			precerts++
		}
		if len(l.chain) < 2 || len(l.chain) > 4 {
			t.Fatalf("entry %d: chain of %d", i, len(l.chain))
		}
		for _, fp := range l.chain {
			issuers[fp] = true
		}
		if !bytes.Equal(l.raw[:len(l.entry)], l.entry) {
			t.Fatalf("entry %d: TileLeaf does not start with its TimestampedEntry", i)
		}
	}
	if precerts != 98 || len(issuers) != 52 {
		t.Fatalf("%d precerts, %d issuers; PROBE.md measured 98 and 52", precerts, len(issuers))
	}
	// The wrong position is caught.
	e := leaf.Entry{}
	leaf.CheckLeafIndex(&e, leaves[0].extensions, pyTile*Width+1)
	if e.Code != leaf.LeafIndexMismatch {
		t.Fatalf("a wrong position: %q", e.Code)
	}
}

// TestRealIssuer: the issuer as served hashes to its fingerprint, which the
// issuer cache checks.
func TestRealIssuer(t *testing.T) {
	const fp = "adb4a7e96552b132901fa13917b030bb8e0f9afe391416c4abd6598a63d09925"
	der := fixture(t, "parcelyard2026h2_issuer_"+fp)
	raw, _ := hex.DecodeString(fp)
	c := NewClient("http://py.test/", &http.Client{Transport: fileTiles{IssuerPath([32]byte(raw)): der}})
	is := newIssuers(c, 1<<20)
	got, err := is.get(context.Background(), [32]byte(raw))
	if err != nil || sha256.Sum256(got) != [32]byte(raw) {
		t.Fatalf("issuer: %v", err)
	}
}
