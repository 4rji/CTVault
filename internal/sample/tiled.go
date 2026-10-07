package sample

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"golang.org/x/sys/unix"

	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/loglist"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/tiled"
	"github.com/4rji/ctvault/internal/merkle"
)

// Tiled samples (amendment A6 §5) mirror a tiled log's files exactly as
// served: the checkpoint, the data and level-0 tiles of the range, every
// hash tile a consistency proof from a position in the range to the head
// needs, and every issuer the range references. Replay serves the folder
// as a static site, so the real tiled source reads it unchanged.

// ProtocolTiled marks a tiled sample's manifest; RFC 6962 samples have none.
const ProtocolTiled = "tiled"

// TiledLimits are A1 §2.1's size rules aligned to tiles.
var TiledLimits = Limits{Boundary: tiled.Width, Min: 51_200, Max: 512_000}

// CheckpointFile is the mirrored checkpoint, the pinned head byte for byte.
const CheckpointFile = "checkpoint"

// recorder is the capture's HTTP transport: every file the tiled source
// reads is written into the staging folder under its log path (the URL path
// less the monitoring prefix's own, such as storage.googleapis.com/<bucket>/),
// and read from there if asked for again. Nothing is recorded before the
// staging folder exists; the checkpoint is written explicitly.
type recorder struct {
	base    http.RoundTripper
	prefix  string // the monitoring prefix's URL path, ending in "/"
	staging string
	mu      sync.Mutex
	files   map[string]bool
	written int64
	check   func(written int64) error
	checked int64
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	p, ok := strings.CutPrefix(req.URL.Path, r.prefix)
	r.mu.Lock()
	have := r.files[p]
	r.mu.Unlock()
	if !ok || r.staging == "" {
		return r.base.RoundTrip(req)
	}
	if have && p != CheckpointFile {
		b, err := os.ReadFile(filepath.Join(r.staging, filepath.FromSlash(p)))
		if err != nil {
			return nil, err
		}
		return okResponse(req, b), nil
	}
	resp, err := r.base.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return resp, err
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	dst := filepath.Join(r.staging, filepath.FromSlash(p))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.files[p] = true
	r.written += int64(len(b))
	if r.check != nil && r.written-r.checked >= CheckEvery {
		r.checked = r.written
		if err := r.check(r.written); err != nil {
			return nil, err
		}
	}
	return okResponse(req, b), nil
}

func okResponse(req *http.Request, b []byte) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(b)), ContentLength: int64(len(b)), Request: req}
}

// proofTiles lists the hash tiles (level, index) that the consistency
// proofs from every position in (start, end] to size read, and for a
// representative sample the compact range at start.
func proofTiles(start, end, size uint64, representative bool) ([][2]uint64, error) {
	set := map[[2]uint64]bool{}
	add := func(ids []compact.NodeID) {
		for _, id := range ids {
			set[[2]uint64{uint64(id.Level / 8), (id.Index << (id.Level % 8)) / tiled.Width}] = true
		}
	}
	for b := start + 1; b <= end; b++ {
		if b == size {
			continue
		}
		p, err := proof.Consistency(b, size)
		if err != nil {
			return nil, err
		}
		add(p.IDs)
	}
	if representative {
		add(compact.RangeNodes(0, start, nil))
	}
	out := make([][2]uint64, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] || (out[i][0] == out[j][0] && out[i][1] < out[j][1]) })
	return out, nil
}

// CaptureTiled captures [Start, Start+Count) of the tiled log info as a
// tiled sample (amendment A6 §5). hc is the HTTP client the capture's
// requests go through; nil means the default.
func CaptureTiled(ctx context.Context, samplesDir string, info logsource.LogInfo, hc *http.Client, o CaptureOptions) (*Sample, error) {
	if o.Limits == (Limits{}) {
		o.Limits = TiledLimits
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.StartAtHead && o.Kind != Representative {
		return nil, fmt.Errorf("sample: --start head is for representative samples")
	}
	if o.StartAtHead {
		o.Start = 0
	}
	if err := o.Limits.Check(o.Kind, o.Start, o.Count); err != nil {
		return nil, err
	}
	if _, err := DirName(o.Start, o.Count, o.Suffix); err != nil {
		return nil, err
	}
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	base := hc.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	u, err := url.Parse(info.URL)
	if err != nil {
		return nil, fmt.Errorf("sample: monitoring prefix %q: %w", info.URL, err)
	}
	rec := &recorder{base: base, prefix: strings.TrimSuffix(u.Path, "/") + "/", files: map[string]bool{}}
	rhc := *hc
	rhc.Transport = rec
	src := tiled.NewSource(info, &rhc, nil)

	var head logsource.SignedHead
	if err := fetch.Retry(ctx, o.Fetch, func(ctx context.Context) (err error) {
		head, err = src.Head(ctx)
		return err
	}); err != nil {
		return nil, err
	}
	if o.StartAtHead {
		var err error
		if o.Start, err = o.Limits.StartForHead(head.TreeSize, o.Count); err != nil {
			return nil, err
		}
	}
	name, err := DirName(o.Start, o.Count, o.Suffix)
	if err != nil {
		return nil, err
	}
	end := o.Start + o.Count
	if end > head.TreeSize {
		return nil, fmt.Errorf("sample: the log currently has only %d entries; [%d, %d) does not fit", head.TreeSize, o.Start, end)
	}
	if o.Check != nil {
		if err := o.Check(int64(o.Count) * SeedBytesPerEntry); err != nil {
			return nil, err
		}
	}
	if _, err := loglist.ParseKey(o.Key, base64.StdEncoding.EncodeToString(info.LogID[:])); err != nil {
		return nil, fmt.Errorf("sample: log %s: %w", info.Name, err)
	}
	dest := filepath.Join(samplesDir, info.Name, name)
	staging, err := stage(dest)
	if err != nil {
		return nil, err
	}
	defer func() {
		if staging != "" {
			os.Chmod(staging, 0o755)
			os.RemoveAll(staging)
		}
	}()
	rec.staging = staging
	if o.Check != nil {
		rec.check = func(int64) error { return o.Check(CheckEvery) }
	}

	// The data tiles and issuers, through the real fetcher.
	if _, err := fetch.Run(ctx, src, o.Start, end, o.Fetch, func(e logsource.RawEntry) error {
		if o.Progress != nil && (e.Index+1-o.Start)%(64*tiled.Width) == 0 {
			o.Progress(e.Index+1-o.Start, o.Count)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	// The level-0 tiles of the range, and the proofs' hash tiles.
	tiles, err := proofTiles(o.Start, end, head.TreeSize, o.Kind == Representative)
	if err != nil {
		return nil, err
	}
	for n := o.Start / tiled.Width; n < end/tiled.Width; n++ {
		tiles = append(tiles, [2]uint64{0, n})
	}
	for _, t := range tiles {
		if err := fetch.Retry(ctx, o.Fetch, func(ctx context.Context) error {
			_, err := src.Client().HashTile(ctx, int(t[0]), t[1], head.TreeSize, nil)
			return err
		}); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(staging, CheckpointFile), head.Raw, 0o644); err != nil {
		return nil, err
	}
	m := Manifest{
		Format: Format, Protocol: ProtocolTiled, Kind: o.Kind, Start: o.Start, Count: o.Count, Boundary: tiled.Width, PageSize: tiled.PageSize,
		Log: LogRef{Name: info.Name, LogID: base64.StdEncoding.EncodeToString(info.LogID[:]), Key: o.Key,
			URL: info.URL, Origin: info.Origin, LogListVersion: o.LogListVersion},
		HeadRaw: head.Raw,
		Head: HeadSummary{TreeSize: head.TreeSize, Timestamp: head.Timestamp,
			RootHash: base64.StdEncoding.EncodeToString(head.RootHash[:])},
		CapturedAt: o.Now().UTC(), CTVaultVersion: o.Version, Files: map[string]FileSum{},
	}
	rec.files[CheckpointFile] = true
	for p := range rec.files {
		sum, err := fileSum(filepath.Join(staging, filepath.FromSlash(p)))
		if err != nil {
			return nil, err
		}
		m.Files[p] = sum
	}
	if err := publish(staging, dest, m); err != nil {
		return nil, err
	}
	staging = ""
	return Open(dest)
}

// stage makes the staging folder next to dest, which must not exist.
func stage(dest string) (string, error) {
	if _, err := os.Lstat(dest); err == nil {
		return "", fmt.Errorf("%w: %s", ErrExists, dest)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	parent := filepath.Dir(dest)
	if err := fsutil.MkdirAllSync(parent, 0o755); err != nil {
		return "", err
	}
	return os.MkdirTemp(parent, ".staging-"+filepath.Base(dest)+"-")
}

// publish writes the manifest, verifies the staged sample as every later
// load does, makes it read-only and renames it into place without replacing
// anything.
func publish(staging, dest string, m Manifest) error {
	mb, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return err
	}
	if err := writeSynced(filepath.Join(staging, ManifestFile), mb); err != nil {
		return err
	}
	if _, err := Open(staging); err != nil {
		return fmt.Errorf("sample: verification before publishing failed: %w", err)
	}
	err = filepath.WalkDir(staging, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return fsutil.SyncDir(p)
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := f.Sync(); err != nil {
			return err
		}
		return os.Chmod(p, 0o444)
	})
	if err != nil {
		return err
	}
	// Folders read-only, deepest first.
	var dirs []string
	filepath.WalkDir(staging, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			dirs = append(dirs, p)
		}
		return nil
	})
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := os.Chmod(dirs[i], 0o555); err != nil {
			return err
		}
	}
	if err := unix.Renameat2(unix.AT_FDCWD, staging, unix.AT_FDCWD, dest, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			err = fmt.Errorf("%w: %s", ErrExists, dest)
		}
		return err
	}
	return fsutil.SyncDir(filepath.Dir(dest))
}

// files serves a tiled sample's manifest-listed files; anything else is 404.
type files struct{ s *Sample }

func (f files) path(p string) (string, bool) {
	p = strings.TrimPrefix(path.Clean("/"+p), "/")
	if _, ok := f.s.Manifest.Files[p]; !ok {
		return "", false
	}
	return filepath.Join(f.s.Dir, filepath.FromSlash(p)), true
}

func (f files) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p, ok := f.path(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	b, err := os.ReadFile(p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	switch {
	case strings.HasPrefix(r.URL.Path, "/issuer/"):
		w.Header().Set("Content-Type", "application/pkix-cert")
	case r.URL.Path == "/"+CheckpointFile:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.Write(b)
}

// RoundTrip reads the files directly, for verification without a socket.
func (f files) RoundTrip(req *http.Request) (*http.Response, error) {
	p, ok := f.path(req.URL.Path)
	if !ok {
		return &http.Response{StatusCode: http.StatusNotFound, Status: "404 Not Found", Header: http.Header{},
			Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	return okResponse(req, b), nil
}

// serveTiled serves a tiled sample on loopback until ctx ends or stop is
// called.
func serveTiled(ctx context.Context, s *Sample) (string, func(), error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	srv := &http.Server{Handler: files{s}, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			ln.Close()
		}
	}()
	stop := func() { srv.Close() }
	context.AfterFunc(ctx, stop)
	return "http://" + ln.Addr().String() + "/", stop, nil
}

// loadTiled checks a tiled sample: every file's sum, the checkpoint with
// the pinned key and origin, then its Merkle tree (verifyTiled).
func loadTiled(dir string, s *Sample) error {
	m := s.Manifest
	lim := Limits{Boundary: tiled.Width, Min: 1, Max: ^uint64(0)}
	if m.Boundary != tiled.Width || lim.Check(m.Kind, m.Start, m.Count) != nil {
		return corrupt("inconsistent range: start %d, count %d, boundary %d", m.Start, m.Count, m.Boundary)
	}
	for name, want := range m.Files {
		if strings.Contains(name, "..") || path.IsAbs(name) {
			return corrupt("file path %q", name)
		}
		got, err := fileSum(filepath.Join(dir, filepath.FromSlash(name)))
		if errors.Is(err, fs.ErrNotExist) {
			return corrupt("%s is missing (an incomplete copy?)", name)
		}
		if err != nil {
			return err
		}
		if got != want {
			return corrupt("%s: sha256 %s (%d bytes), manifest records %s (%d bytes)", name, got.SHA256, got.Bytes, want.SHA256, want.Bytes)
		}
	}
	cp, err := os.ReadFile(filepath.Join(dir, CheckpointFile))
	if err != nil || !bytes.Equal(cp, m.HeadRaw) {
		return corrupt("the checkpoint file is not the pinned head")
	}
	var err2 error
	if s.pub, err2 = loglist.ParseKey(m.Log.Key, m.Log.LogID); err2 != nil {
		return corrupt("pinned key: %v", err2)
	}
	sth, err := tiled.ParseCheckpoint(m.HeadRaw, m.Log.Origin, s.LogIDBytes())
	if err != nil {
		return corrupt("checkpoint: %v", err)
	}
	if err := merkle.VerifySTH(s.pub, sth); err != nil {
		return corrupt("checkpoint: %v", err)
	}
	s.Head = sth
	if m.Start+m.Count > sth.TreeSize {
		return corrupt("entries end at %d, beyond the signed tree of %d", m.Start+m.Count, sth.TreeSize)
	}
	return nil
}

// verifyTiled ties every mirrored entry to the signed root: the compact
// range at Start from hash tiles (empty for a canonical sample), every
// entry's leaf hash appended and checked against the level-0 tiles, then
// the root at the end equal to the head's or proven a prefix of it with a
// proof built from the sample's own tiles.
func (s *Sample) verifyTiled(ctx context.Context) error {
	m := s.Manifest
	src := s.mirror()
	c := src.Client()
	st := merkle.NewState()
	if m.Kind == Representative {
		nodes, err := c.CompactRange(ctx, m.Start, s.Head.TreeSize, nil)
		if err != nil {
			return corrupt("compact range at %d: %v", m.Start, err)
		}
		if st, err = merkle.StateFromNodes(m.Start, nodes); err != nil {
			return corrupt("%v", err)
		}
	}
	s.start = st.Clone()
	end := m.Start + m.Count
	for first := m.Start; first < end; first += tiled.Width {
		es, err := src.Fetch(ctx, first, first+tiled.Width)
		if err != nil || len(es) != tiled.Width {
			return corrupt("data tile at %d: %d entries, %v", first, len(es), err)
		}
		level0, err := c.HashTile(ctx, 0, first/tiled.Width, s.Head.TreeSize, nil)
		if err != nil {
			return corrupt("level-0 tile at %d: %v", first, err)
		}
		for i, e := range es {
			if e.Leaf.LeafHash != level0[i] {
				return corrupt("entry %d does not hash to its level-0 tile", e.Index)
			}
			if err := st.Append(e.Leaf.LeafHash); err != nil {
				return err
			}
		}
	}
	root, err := st.Root()
	if err != nil {
		return err
	}
	if end == s.Head.TreeSize {
		if root != s.Head.RootHash {
			return corrupt("root at %d differs from the signed root", end)
		}
		return nil
	}
	p, err := src.ConsistencyProof(ctx, end, s.Head.TreeSize)
	if err != nil {
		return corrupt("consistency proof from %d: %v", end, err)
	}
	if err := merkle.VerifyConsistency(end, s.Head.TreeSize, root, s.Head.RootHash, p); err != nil {
		return corrupt("entries up to %d: %v", end, err)
	}
	return nil
}

// mirror is the tiled source over the sample's own files, with its pinned
// head as the last accepted one.
func (s *Sample) mirror() *tiled.Source {
	head := s.SignedHead()
	return tiled.NewSource(s.LogInfo("http://sample.invalid/"), &http.Client{Transport: files{s}}, &head)
}

// eachTiled yields a tiled sample's entries in their RFC 6962 form, read
// through the tiled source from the mirrored files.
func (s *Sample) eachTiled(fn func(Entry) error) error {
	src := s.mirror()
	end := s.Manifest.Start + s.Manifest.Count
	for next := s.Manifest.Start; next < end; {
		es, err := src.Fetch(context.Background(), next, end)
		if err != nil {
			return corrupt("entries at %d: %v", next, err)
		}
		for _, e := range es {
			if err := fn(Entry{Index: e.Index, LeafInput: e.LeafInput, ExtraData: e.ExtraData}); err != nil {
				return err
			}
		}
		next += uint64(len(es))
	}
	return nil
}
