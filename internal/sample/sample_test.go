package sample

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
)

// Small limits keep the fake log small: windows of 16-96 entries in frames of 8.
var testLimits = Limits{Boundary: 8, Min: 16, Max: 96}

type fixture struct {
	log  *ctlogtest.Log
	src  *rfc6962.Source
	dir  string // samples folder
	opts CaptureOptions
}

func newFixture(t *testing.T, n int) *fixture {
	t.Helper()
	l := ctlogtest.New(t, n, ctlogtest.Options{PageSize: 4})
	pub, err := x509.ParsePKIXPublicKey(l.PublicKeyDER)
	if err != nil {
		t.Fatal(err)
	}
	info := logsource.LogInfo{Name: "fakelog", LogID: l.LogID, PublicKey: pub, URL: l.URL}
	dir := t.TempDir()
	t.Cleanup(func() { makeWritable(dir) }) // runs before TempDir's removal
	return &fixture{log: l, dir: dir,
		src: rfc6962.NewSource(info, nil, logsource.NewChainCache(logsource.DefaultChainCacheBytes), nil),
		opts: CaptureOptions{Limits: testLimits, Key: base64.StdEncoding.EncodeToString(l.PublicKeyDER),
			LogListVersion: "test", Version: "test", Now: func() time.Time { return time.Unix(1790000000, 0) },
			Fetch: fetch.Options{MaxRPS: 1000, MinBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond}}}
}

// makeWritable undoes the read-only modes of published samples.
func makeWritable(dir string) {
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			os.Chmod(p, 0o755)
		}
		return nil
	})
}

func (f *fixture) capture(t *testing.T, kind Kind, start, count uint64, suffix string) (*Sample, error) {
	t.Helper()
	o := f.opts
	o.Kind, o.Start, o.Count, o.Suffix = kind, start, count, suffix
	return Capture(context.Background(), f.dir, f.src, o)
}

func checkEntries(t *testing.T, f *fixture, s *Sample) {
	t.Helper()
	next := s.Manifest.Start
	err := s.Each(func(e Entry) error {
		want := f.log.Entries[e.Index]
		if e.Index != next || !bytes.Equal(e.LeafInput, want.LeafInput) || !bytes.Equal(e.ExtraData, want.ExtraData) {
			t.Fatalf("entry %d differs from the log", e.Index)
		}
		next++
		return nil
	})
	if err != nil || next != s.Manifest.Start+s.Manifest.Count {
		t.Fatalf("Each: %v, stopped at %d", err, next)
	}
}

func TestCaptureCanonical(t *testing.T) {
	f := newFixture(t, 120)
	s, err := f.capture(t, Canonical, 0, 48, "")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(s.Dir) != "000000000000-000000000047" || filepath.Base(filepath.Dir(s.Dir)) != "fakelog" {
		t.Fatalf("folder %s", s.Dir)
	}
	m := s.Manifest
	if m.Kind != Canonical || m.Count != 48 || len(m.Frames) != 6 || m.PageSize != 4 || m.Head.TreeSize != 120 {
		t.Fatalf("manifest: %+v", m)
	}
	if len(s.Proofs.Consistency) != 6 || s.Proofs.Inclusion != nil {
		t.Fatalf("a canonical sample has one proof per boundary: %+v", s.Proofs)
	}
	checkEntries(t, f, s)
	for _, name := range []string{ManifestFile, EntriesFile, ProofsFile, "."} {
		fi, err := os.Stat(filepath.Join(s.Dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o222 != 0 {
			t.Fatalf("%s is writable (%v); samples are read-only", name, fi.Mode())
		}
	}
	if _, err := Open(s.Dir); err != nil {
		t.Fatalf("a published sample verifies on every load: %v", err)
	}
}

func TestCaptureRepresentative(t *testing.T) {
	f := newFixture(t, 120)
	s, err := f.capture(t, Representative, 40, 32, "")
	if err != nil {
		t.Fatal(err)
	}
	inc := s.Proofs.Inclusion
	if inc == nil || inc.LeafIndex != 40 || len(s.Proofs.Consistency) != 1 || s.Proofs.Consistency[0].First != 72 {
		t.Fatalf("a representative sample has the inclusion proof of leaf 40 and one consistency proof from 72: %+v", s.Proofs)
	}
	checkEntries(t, f, s)
}

// TestCaptureAtTheHead: "--start head" picks the last whole window, which
// may end exactly at the tree size; then the root itself must match.
func TestCaptureAtTheHead(t *testing.T) {
	f := newFixture(t, 120)
	start, err := testLimits.StartForHead(120, 32)
	if err != nil || start != 88 {
		t.Fatalf("StartForHead(120, 32) = %d, %v; want 88", start, err)
	}
	s, err := f.capture(t, Representative, start, 32, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Proofs.Consistency) != 0 {
		t.Fatal("a window ending at the head needs no consistency proof")
	}
	if _, err := testLimits.StartForHead(10, 32); err == nil {
		t.Fatal("a window larger than the log is refused")
	}
	o := f.opts
	o.Kind, o.StartAtHead, o.Count, o.Suffix = Representative, true, 32, "head"
	if s, err := Capture(context.Background(), f.dir, f.src, o); err != nil || s.Manifest.Start != 88 {
		t.Fatalf("StartAtHead resolves the window from the pinned head: %v", err)
	}
	o.Kind = Canonical
	if _, err := Capture(context.Background(), f.dir, f.src, o); err == nil {
		t.Fatal("--start head is for representative samples only")
	}
}

func TestCaptureRefusals(t *testing.T) {
	f := newFixture(t, 120)
	for name, tc := range map[string]struct {
		kind         Kind
		start, count uint64
		suffix       string
	}{
		"count not a multiple": {Canonical, 0, 20, ""},
		"count too small":      {Canonical, 0, 8, ""},
		"count too large":      {Canonical, 0, 104, ""},
		"canonical not at 0":   {Canonical, 8, 16, ""},
		"start not aligned":    {Representative, 4, 16, ""},
		"beyond the tree":      {Representative, 112, 16, ""},
		"bad suffix":           {Canonical, 0, 16, "../x"},
		"unknown kind":         {"other", 0, 16, ""},
	} {
		if _, err := f.capture(t, tc.kind, tc.start, tc.count, tc.suffix); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
	if entries, _ := os.ReadDir(f.dir); len(entries) != 0 {
		t.Fatalf("refusals must not create anything: %v", entries)
	}
}

func TestCaptureNeverOverwritesAndLeavesNothingOnFailure(t *testing.T) {
	f := newFixture(t, 120)
	if _, err := f.capture(t, Canonical, 0, 16, ""); err != nil {
		t.Fatal(err)
	}
	before := f.log.Requests("get-entries")
	if _, err := f.capture(t, Canonical, 0, 16, ""); !errors.Is(err, ErrExists) {
		t.Fatalf("a second capture of the same range: %v", err)
	}
	if f.log.Requests("get-entries") != before {
		t.Fatal("an existing sample is refused before fetching anything")
	}
	if s, err := f.capture(t, Canonical, 0, 16, "again"); err != nil || !strings.HasSuffix(s.Dir, "_again") {
		t.Fatalf("a new suffix captures the range again: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	o := f.opts
	o.Kind, o.Count, o.Suffix = Canonical, 48, "interrupted"
	o.Progress = func(done, _ uint64) {
		if done == 16 {
			cancel()
		}
	}
	if _, err := Capture(ctx, f.dir, f.src, o); !errors.Is(err, context.Canceled) {
		t.Fatalf("an interrupted capture fails: %v", err)
	}
	names, _ := filepath.Glob(filepath.Join(f.dir, "fakelog", "*"))
	for _, n := range names {
		if strings.Contains(n, "interrupted") || strings.Contains(filepath.Base(n), ".staging") {
			t.Fatalf("an interrupted capture left %s behind", n)
		}
	}
}

func TestDiskCheckAbortsCapture(t *testing.T) {
	f := newFixture(t, 120)
	o := f.opts
	o.Kind, o.Count = Canonical, 16
	var asked int64
	o.Check = func(need int64) error { asked = need; return errors.New("disk cap would be exceeded") }
	if _, err := Capture(context.Background(), f.dir, f.src, o); err == nil || asked != 16*SeedBytesPerEntry {
		t.Fatalf("the preflight asks for count x %d bytes and its refusal stops the capture: %v (asked %d)", SeedBytesPerEntry, err, asked)
	}
	if f.log.Requests("get-entries") != 0 {
		t.Fatal("nothing is fetched after a refused preflight")
	}
}

// copyWritable copies a published sample into a writable temp folder so a
// test can damage it.
func copyWritable(t *testing.T, s *Sample) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "copy")
	os.MkdirAll(dst, 0o755)
	for _, name := range []string{ManifestFile, EntriesFile, ProofsFile} {
		b, err := os.ReadFile(filepath.Join(s.Dir, name))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dst, name), b, 0o644)
	}
	return dst
}

func editJSON(t *testing.T, path string, edit func(map[string]any)) {
	t.Helper()
	b, _ := os.ReadFile(path)
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	edit(v)
	b, _ = json.Marshal(v)
	os.WriteFile(path, b, 0o644)
}

// resum records a file's new checksum in the manifest, as a careless editor
// would: checksums alone must not be the only defence.
func resum(t *testing.T, dir, name string) {
	t.Helper()
	sum, err := fileSum(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	editJSON(t, filepath.Join(dir, ManifestFile), func(m map[string]any) {
		m["files"].(map[string]any)[name] = map[string]any{"sha256": sum.SHA256, "bytes": sum.Bytes}
	})
}

func TestOpenDetectsTampering(t *testing.T) {
	f := newFixture(t, 120)
	s, err := f.capture(t, Canonical, 0, 32, "")
	if err != nil {
		t.Fatal(err)
	}
	for name, damage := range map[string]func(dir string){
		"entries byte flipped": func(dir string) {
			p := filepath.Join(dir, EntriesFile)
			b, _ := os.ReadFile(p)
			b[len(b)/2] ^= 1
			os.WriteFile(p, b, 0o644)
		},
		"proof removed, checksum updated": func(dir string) {
			editJSON(t, filepath.Join(dir, ProofsFile), func(p map[string]any) {
				p["consistency"] = p["consistency"].([]any)[1:]
			})
			resum(t, dir, ProofsFile)
		},
		"proof node altered, checksum updated": func(dir string) {
			editJSON(t, filepath.Join(dir, ProofsFile), func(p map[string]any) {
				c := p["consistency"].([]any)[0].(map[string]any)
				c["nodes"].([]any)[0] = base64.StdEncoding.EncodeToString(make([]byte, 32))
			})
			resum(t, dir, ProofsFile)
		},
		"head signature altered": func(dir string) {
			editJSON(t, filepath.Join(dir, ManifestFile), func(m map[string]any) {
				raw, _ := base64.StdEncoding.DecodeString(m["head_raw"].(string))
				raw = bytes.Replace(raw, []byte(`"timestamp":`), []byte(`"timestamp":1`), 1)
				m["head_raw"] = base64.StdEncoding.EncodeToString(raw)
			})
		},
		"other log's key": func(dir string) {
			other := ctlogtest.New(t, 1, ctlogtest.Options{})
			editJSON(t, filepath.Join(dir, ManifestFile), func(m map[string]any) {
				m["log"].(map[string]any)["key"] = base64.StdEncoding.EncodeToString(other.PublicKeyDER)
			})
		},
	} {
		dir := copyWritable(t, s)
		if _, err := Open(dir); err != nil {
			t.Fatalf("%s: the undamaged copy must verify: %v", name, err)
		}
		damage(dir)
		if _, err := Open(dir); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: want ErrCorrupt, got %v", name, err)
		}
	}
}

// TestCommitRefusesEntriesThatDoNotMatchTheProofs: an entry changed before
// publishing (new checksums and all) fails the Merkle check, and nothing is
// published.
func TestCommitRefusesEntriesThatDoNotMatchTheProofs(t *testing.T) {
	f := newFixture(t, 120)
	s, err := f.capture(t, Canonical, 0, 16, "")
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(f.dir, "fakelog", "forged")
	w, err := Create(dest, s.Manifest, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Abort()
	s.Each(func(e Entry) error {
		if e.Index == 9 {
			e.LeafInput = append([]byte(nil), e.LeafInput...)
			e.LeafInput[20] ^= 1
		}
		return w.Add(logsource.RawEntry{Index: e.Index, LeafInput: e.LeafInput, ExtraData: e.ExtraData})
	})
	if _, err := w.Commit(s.Proofs); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("want ErrCorrupt, got %v", err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("a sample that fails verification must never become visible")
	}
}

func TestEntriesFileIsOneZstdStream(t *testing.T) {
	f := newFixture(t, 120)
	s, err := f.capture(t, Canonical, 0, 24, "")
	if err != nil {
		t.Fatal(err)
	}
	fh, _ := os.Open(filepath.Join(s.Dir, EntriesFile))
	defer fh.Close()
	dec, err := zstd.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()
	sc := bufio.NewScanner(dec)
	sc.Buffer(nil, maxLine)
	n := 0
	for sc.Scan() {
		n++
	}
	if sc.Err() != nil || n != 24 {
		t.Fatalf("plain zstd tools must read every line: %d lines, %v", n, sc.Err())
	}
}

func TestReplayServesTheSample(t *testing.T) {
	f := newFixture(t, 120)
	s, err := f.capture(t, Representative, 16, 32, "")
	if err != nil {
		t.Fatal(err)
	}
	url, stop, err := Serve(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if !strings.HasPrefix(url, "http://127.0.0.1:") {
		t.Fatalf("replay must listen on loopback only: %s", url)
	}
	info := f.src.Info()
	info.URL = url
	src := rfc6962.NewSource(info, nil, logsource.NewChainCache(logsource.DefaultChainCacheBytes), nil)
	head, err := src.Head(context.Background())
	if err != nil || !bytes.Equal(head.Raw, s.Manifest.HeadRaw) {
		t.Fatalf("get-sth must return the captured head byte for byte: %v", err)
	}
	next := uint64(16)
	st, err := fetch.Run(context.Background(), src, 16, 48, f.opts.Fetch, func(e logsource.RawEntry) error {
		if e.Index != next || !bytes.Equal(e.LeafInput, f.log.Entries[e.Index].LeafInput) {
			t.Fatalf("replayed entry %d differs", e.Index)
		}
		next++
		return nil
	})
	if err != nil || next != 48 || st.LargestResponse != 4 {
		t.Fatalf("replay: %v, next %d, page %d (captured page size 4)", err, next, st.LargestResponse)
	}
	if p, err := src.ConsistencyProof(context.Background(), 48, 120); err != nil || len(p) == 0 {
		t.Fatalf("stored consistency proof: %v", err)
	}
	idx, _, err := src.Client().GetProofByHash(context.Background(), s.Proofs.Inclusion.LeafHash, 120)
	if err != nil || idx != 16 {
		t.Fatalf("stored inclusion proof: %d %v", idx, err)
	}
	if _, err := src.Fetch(context.Background(), 48, 50); err == nil {
		t.Fatal("entries outside the sample are refused")
	}
}
