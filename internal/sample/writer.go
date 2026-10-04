package sample

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/sys/unix"

	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/logsource"
)

// ErrExists means the destination sample already exists. Samples are never
// overwritten; capture the same range again with a new --suffix.
var ErrExists = errors.New("sample already exists")

// CheckEvery is how often, in bytes written, the writer calls its disk check.
const CheckEvery = 64 << 20

// line is one entries.ndjson line; []byte fields encode as standard base64.
type line struct {
	Index     uint64 `json:"i"`
	LeafInput []byte `json:"leaf_input"`
	ExtraData []byte `json:"extra_data"`
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// Writer streams a sample into a staging folder next to its destination.
// Nothing becomes visible until Commit has verified the whole sample.
type Writer struct {
	dest, staging string
	m             Manifest
	f             *os.File
	cw            *countingWriter
	enc           *zstd.Encoder
	next          uint64
	inFrame       uint64
	check         func(written int64) error
	lastCheck     int64
}

// Create starts a sample for dest. check, if set, is called every CheckEvery
// bytes with the bytes written so far, and its error aborts the capture.
func Create(dest string, m Manifest, check func(written int64) error) (*Writer, error) {
	if _, err := os.Lstat(dest); err == nil {
		return nil, fmt.Errorf("%w: %s", ErrExists, dest)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	parent := filepath.Dir(dest)
	if err := fsutil.MkdirAllSync(parent, 0o755); err != nil {
		return nil, err
	}
	staging, err := os.MkdirTemp(parent, ".staging-"+filepath.Base(dest)+"-")
	if err != nil {
		return nil, err
	}
	f, err := os.Create(filepath.Join(staging, EntriesFile))
	if err != nil {
		os.RemoveAll(staging)
		return nil, err
	}
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		f.Close()
		os.RemoveAll(staging)
		return nil, err
	}
	m.Frames = nil
	return &Writer{dest: dest, staging: staging, m: m, f: f, cw: &countingWriter{w: f}, enc: enc,
		next: m.Start, check: check}, nil
}

// Staging returns the staging folder (for tests and error messages).
func (w *Writer) Staging() string { return w.staging }

// Add appends the next entry; indexes must be consecutive from Start.
func (w *Writer) Add(e logsource.RawEntry) error {
	if e.Index != w.next || e.Index >= w.m.Start+w.m.Count {
		return fmt.Errorf("sample: got entry %d, want %d", e.Index, w.next)
	}
	if w.inFrame == 0 {
		w.m.Frames = append(w.m.Frames, w.cw.n)
		w.enc.Reset(w.cw)
	}
	b, err := json.Marshal(line{Index: e.Index, LeafInput: e.LeafInput, ExtraData: e.ExtraData})
	if err != nil {
		return err
	}
	if _, err := w.enc.Write(append(b, '\n')); err != nil {
		return err
	}
	w.next++
	if w.inFrame++; w.inFrame == w.m.Boundary {
		if err := w.enc.Close(); err != nil {
			return err
		}
		w.inFrame = 0
	}
	if w.check != nil && w.cw.n-w.lastCheck >= CheckEvery {
		w.lastCheck = w.cw.n
		return w.check(w.cw.n)
	}
	return nil
}

// Commit writes the proofs and the manifest, verifies the staged sample with
// the same checks as every later load, makes it read-only and renames it into
// place without replacing anything. It returns the opened sample.
func (w *Writer) Commit(p Proofs) (*Sample, error) {
	if w.next != w.m.Start+w.m.Count || w.inFrame != 0 {
		return nil, fmt.Errorf("sample: %d of %d entries written", w.next-w.m.Start, w.m.Count)
	}
	if err := w.f.Sync(); err != nil {
		return nil, err
	}
	if err := w.f.Close(); err != nil {
		return nil, err
	}
	w.f = nil
	pb, err := json.MarshalIndent(p, "", " ")
	if err != nil {
		return nil, err
	}
	if err := writeSynced(filepath.Join(w.staging, ProofsFile), pb); err != nil {
		return nil, err
	}
	w.m.Files = map[string]FileSum{}
	for _, name := range []string{EntriesFile, ProofsFile} {
		sum, err := fileSum(filepath.Join(w.staging, name))
		if err != nil {
			return nil, err
		}
		w.m.Files[name] = sum
	}
	mb, err := json.MarshalIndent(w.m, "", " ")
	if err != nil {
		return nil, err
	}
	if err := writeSynced(filepath.Join(w.staging, ManifestFile), mb); err != nil {
		return nil, err
	}
	if _, err := Open(w.staging); err != nil {
		return nil, fmt.Errorf("sample: verification before publishing failed: %w", err)
	}
	for _, name := range []string{EntriesFile, ProofsFile, ManifestFile} {
		if err := os.Chmod(filepath.Join(w.staging, name), 0o444); err != nil {
			return nil, err
		}
	}
	if err := os.Chmod(w.staging, 0o555); err != nil {
		return nil, err
	}
	if err := fsutil.SyncDir(w.staging); err != nil {
		return nil, err
	}
	parent := filepath.Dir(w.dest)
	if err := unix.Renameat2(unix.AT_FDCWD, w.staging, unix.AT_FDCWD, w.dest, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			err = fmt.Errorf("%w: %s", ErrExists, w.dest)
		}
		return nil, err
	}
	w.staging = ""
	if err := fsutil.SyncDir(parent); err != nil {
		return nil, err
	}
	return Open(w.dest)
}

// Abort removes the staging folder. It is safe after a failed Commit and a
// no-op after a successful one.
func (w *Writer) Abort() {
	if w.f != nil {
		w.f.Close()
		w.f = nil
	}
	w.enc.Close()
	if w.staging == "" {
		return
	}
	os.Chmod(w.staging, 0o755)
	os.RemoveAll(w.staging)
	w.staging = ""
}

func writeSynced(path string, b []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func fileSum(path string) (FileSum, error) {
	f, err := os.Open(path)
	if err != nil {
		return FileSum{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return FileSum{}, err
	}
	return FileSum{SHA256: hex.EncodeToString(h.Sum(nil)), Bytes: n}, nil
}
