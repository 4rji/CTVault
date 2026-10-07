package sample

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/loglist"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/tiled"
	"github.com/4rji/ctvault/internal/merkle"
)

var smallTiled = Limits{Boundary: tiled.Width, Min: tiled.Width, Max: 1 << 20}

func tiledFake(t *testing.T, n int, publish uint64) (*ctlogtest.Log, logsource.LogInfo, string) {
	t.Helper()
	l := ctlogtest.New(t, n, ctlogtest.Options{Tiled: true})
	l.Publish(publish)
	pub, _ := x509.ParsePKIXPublicKey(l.PublicKeyDER)
	info := logsource.LogInfo{Name: "fakelog", Kind: loglist.KindTiled, LogID: l.LogID, PublicKey: pub, URL: l.URL, Origin: l.Origin}
	return l, info, base64.StdEncoding.EncodeToString(l.PublicKeyDER)
}

// samplesDir is a temporary samples folder that cleanup can remove,
// although published samples are read-only.
func samplesDir(t *testing.T) string {
	d := t.TempDir()
	t.Cleanup(func() { makeWritable(d) })
	return d
}

func tiledOpts(kind Kind, start, count uint64, key string) CaptureOptions {
	return CaptureOptions{Kind: kind, Start: start, Count: count, Limits: smallTiled, Key: key, Version: "test",
		Fetch: fetch.Options{MaxRPS: 1000, MinBackoff: 1, MaxBackoff: 2}}
}

// TestTiledSampleCanonical: a canonical tiled sample mirrors the files as
// served, verifies, and replays through the real tiled source: every entry
// and every consistency proof from a position in the range to the head
// come from the mirror alone (amendment A6 §5).
func TestTiledSampleCanonical(t *testing.T) {
	l, info, key := tiledFake(t, 1100, 1000) // the head's right edge is partial
	dir := samplesDir(t)
	s, err := CaptureTiled(context.Background(), dir, info, nil, tiledOpts(Canonical, 0, 768, key))
	if err != nil {
		t.Fatal(err)
	}
	m := s.Manifest
	if m.Protocol != ProtocolTiled || m.Head.TreeSize != 1000 || m.Log.Origin != l.Origin || s.Dir != filepath.Join(dir, "fakelog", "000000000000-000000000767") {
		t.Fatalf("manifest %+v at %s", m, s.Dir)
	}
	for _, f := range []string{"checkpoint", "tile/data/000", "tile/data/002", "tile/0/000", "tile/0/002"} {
		if _, ok := m.Files[f]; !ok {
			t.Errorf("the sample lacks %s", f)
		}
	}
	if _, ok := m.Files["tile/data/003.p/232"]; ok {
		t.Error("the sample holds data beyond its range")
	}
	issuers := 0
	for f := range m.Files {
		if strings.HasPrefix(f, "issuer/") {
			issuers++
		}
	}
	if issuers != 1 {
		t.Errorf("%d issuers mirrored, want the fake's CA", issuers)
	}

	// Replay: the tiled source reads the mirror, never the fake.
	before := l.Requests("all")
	url, stop, err := Serve(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	ri := info
	ri.URL = url
	src := tiled.NewSource(ri, nil, nil)
	head, err := src.Head(context.Background())
	if err != nil || head.TreeSize != 1000 {
		t.Fatalf("replayed head %d: %v", head.TreeSize, err)
	}
	var leaves [][32]byte
	for next := uint64(0); next < 768; {
		es, err := src.Fetch(context.Background(), next, 768)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range es {
			leaves = append(leaves, e.Leaf.LeafHash)
		}
		next += uint64(len(es))
	}
	// The proof from every position in the range, read from the mirror,
	// verifies against the root rebuilt from the mirrored entries.
	st := merkle.NewState()
	for b := uint64(1); b <= 768; b++ {
		st.Append(leaves[b-1])
		root, _ := st.Root()
		p, err := src.ConsistencyProof(context.Background(), b, 1000)
		if err != nil {
			t.Fatalf("proof from %d: %v", b, err)
		}
		if err := merkle.VerifyConsistency(b, 1000, root, head.RootHash, p); err != nil {
			t.Fatalf("proof from %d: %v", b, err)
		}
	}
	if l.Requests("all") != before {
		t.Fatalf("replay reached the fake log: %d requests", l.Requests("all")-before)
	}
}

// TestTiledSampleRepresentative: a mid-log window takes its start state
// from hash tiles, and that state continues to the head.
func TestTiledSampleRepresentative(t *testing.T) {
	_, info, key := tiledFake(t, 1100, 1100)
	s, err := CaptureTiled(context.Background(), samplesDir(t), info, nil, tiledOpts(Representative, 512, 256, key))
	if err != nil {
		t.Fatal(err)
	}
	st, err := s.StartState()
	if err != nil || st.Size() != 512 {
		t.Fatalf("start state: %v", err)
	}
	if _, err := CaptureTiled(context.Background(), samplesDir(t), info, nil, tiledOpts(Representative, 100, 256, key)); err == nil {
		t.Fatal("a start that is not a tile boundary was accepted")
	}
}

// TestTiledSampleCorrupt: a changed byte, a missing file, or a file whose
// recorded sum was changed with it, is ErrCorrupt.
func TestTiledSampleCorrupt(t *testing.T) {
	_, info, key := tiledFake(t, 600, 600)
	s, err := CaptureTiled(context.Background(), samplesDir(t), info, nil, tiledOpts(Canonical, 0, 512, key))
	if err != nil {
		t.Fatal(err)
	}
	copyDir := func() string {
		d := filepath.Join(t.TempDir(), "copy")
		if err := os.CopyFS(d, os.DirFS(s.Dir)); err != nil {
			t.Fatal(err)
		}
		filepath.WalkDir(d, func(p string, e os.DirEntry, err error) error { os.Chmod(p, 0o755); return nil })
		return d
	}
	flip := func(p string) {
		b, _ := os.ReadFile(p)
		b[len(b)/2] ^= 1
		os.WriteFile(p, b, 0o644)
	}
	d := copyDir()
	flip(filepath.Join(d, "tile", "data", "001"))
	if _, err := Open(d); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a changed data tile: %v", err)
	}
	d = copyDir()
	for f := range s.Manifest.Files {
		if strings.HasPrefix(f, "issuer/") {
			os.Remove(filepath.Join(d, filepath.FromSlash(f)))
		}
	}
	if _, err := Open(d); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a missing issuer: %v", err)
	}
	// A level-0 tile changed together with its recorded sum: the sums pass,
	// the Merkle check does not.
	d = copyDir()
	p := filepath.Join(d, "tile", "0", "001")
	flip(p)
	m := s.Manifest
	sum, _ := fileSum(p)
	m.Files["tile/0/001"] = sum
	b, _ := json.MarshalIndent(m, "", " ")
	os.WriteFile(filepath.Join(d, ManifestFile), b, 0o644)
	if _, err := Open(d); !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "level-0") {
		t.Errorf("a level-0 tile changed with its sum: %v", err)
	}
}

// TestTiledSampleUnderAPathPrefix: a monitoring prefix with a path (as
// storage.googleapis.com/<bucket>/ is) records files under their log paths,
// and the capture writes nothing outside its own folder (found on real data,
// A6 step 5).
func TestTiledSampleUnderAPathPrefix(t *testing.T) {
	l, info, key := tiledFake(t, 600, 600)
	target, _ := url.Parse(l.URL)
	proxy := httptest.NewServer(http.StripPrefix("/bucket.example", httputil.NewSingleHostReverseProxy(target)))
	defer proxy.Close()
	info.URL = proxy.URL + "/bucket.example/"
	cwd := t.TempDir()
	t.Chdir(cwd)
	s, err := CaptureTiled(context.Background(), samplesDir(t), info, nil, tiledOpts(Canonical, 0, 512, key))
	if err != nil {
		t.Fatal(err)
	}
	for f := range s.Manifest.Files {
		if strings.Contains(f, "bucket.example") {
			t.Errorf("file %s is recorded under the prefix", f)
		}
	}
	if _, ok := s.Manifest.Files["tile/data/001"]; !ok {
		t.Error("the data tiles are not at their log paths")
	}
	if left, _ := os.ReadDir(cwd); len(left) != 0 {
		t.Errorf("the capture wrote %d files outside its folder", len(left))
	}
}
