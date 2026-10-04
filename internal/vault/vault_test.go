package vault

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/ctlogtest"
)

var testUUID = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

func fixedNow() time.Time { return time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC) }

// vaultDirs makes n vault directories with segments/ and dict/.
func vaultDirs(t *testing.T, n int) []string {
	t.Helper()
	var dirs []string
	for i := range n {
		d := filepath.Join(t.TempDir(), fmt.Sprintf("v%d", i))
		for _, sub := range []string{SegmentsDir, DictDir} {
			if err := os.MkdirAll(filepath.Join(d, sub), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		dirs = append(dirs, d)
	}
	return dirs
}

// certs returns n distinct real certificates from the fake-log generator.
func certs(t *testing.T, n int) [][]byte {
	t.Helper()
	g, err := ctlogtest.NewGenerator()
	if err != nil {
		t.Fatal(err)
	}
	es, err := g.Entries(n)
	if err != nil {
		t.Fatal(err)
	}
	out := make([][]byte, n)
	for i, e := range es {
		out[i] = e.CertDER
	}
	return out
}

func codec(t *testing.T) *Codec {
	t.Helper()
	c, err := NewCodec()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestHeader(t *testing.T) {
	h := Header{Version: FormatVersion, VaultUUID: testUUID, Segment: 7, FirstCertID: 42, Created: fixedNow()}
	b := h.Encode()
	if len(b) != HeaderSize || string(b[:8]) != Magic {
		t.Fatalf("header layout: %d bytes, magic %q", len(b), b[:8])
	}
	got, err := DecodeHeader(b)
	if err != nil || got != h {
		t.Fatalf("round trip: %+v, %v", got, err)
	}
	bad := slices.Clone(b)
	bad[30] ^= 1
	if _, err := DecodeHeader(bad); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a flipped bit must fail the checksum: %v", err)
	}
	if _, err := DecodeHeader(b[:20]); !errors.Is(err, ErrTorn) {
		t.Fatalf("a short header is torn: %v", err)
	}
	if u, err := ParseUUID("01020304-0506-0708-090a-0b0c0d0e0f10"); err != nil || u != testUUID {
		t.Fatalf("ParseUUID: %x %v", u, err)
	}
	if _, err := ParseUUID("not-a-uuid"); err == nil {
		t.Fatal("a bad UUID is refused")
	}
}

func TestRecordCodec(t *testing.T) {
	for _, r := range []Record{
		{Kind: KindLeaf, CertID: 1, DictID: 0, Frame: []byte("frame")},
		{Kind: KindChain, CertID: 1 << 40, DictID: 3, Frame: []byte("x")},
		{Kind: KindDelta, CertID: 9, BaseSeg: 2, BaseOff: 300, Frame: []byte("delta")},
	} {
		b := AppendRecord(nil, r)
		got, err := ParseRecord(append(b, 0xff, 0xff)) // trailing bytes belong to the next record
		if err != nil || got.Kind != r.Kind || got.CertID != r.CertID || got.DictID != r.DictID ||
			got.BaseSeg != r.BaseSeg || got.BaseOff != r.BaseOff || string(got.Frame) != string(r.Frame) || got.TotalLen != len(b) {
			t.Fatalf("round trip of %+v: %+v, %v", r, got, err)
		}
		if _, err := ParseRecord(b[:len(b)-1]); !errors.Is(err, ErrTorn) {
			t.Fatalf("a record cut short is torn: %v", err)
		}
	}
	if _, err := ParseRecord(AppendRecord(nil, Record{Kind: 9, CertID: 1})); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("an unknown kind is corruption: %v", err)
	}
}

func openWriter(t *testing.T, dirs []string, segSize uint64, tail Tail, check func(string, uint64) error) *Writer {
	t.Helper()
	w, err := OpenWriter(Options{Dirs: dirs, VaultUUID: testUUID, SegmentSize: segSize, Check: check, Now: fixedNow}, codec(t), tail)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestWriteReadAcrossSegments(t *testing.T) {
	dirs := vaultDirs(t, 1)
	cs := certs(t, 60)
	w := openWriter(t, dirs, 8<<10, Tail{}, nil)
	locs := make([]Loc, len(cs))
	for i, der := range cs {
		kind := byte(KindLeaf)
		if i%7 == 0 {
			kind = KindChain
		}
		loc, err := w.AppendCert(kind, uint64(i+1), der, 0)
		if err != nil {
			t.Fatal(err)
		}
		locs[i] = loc
	}
	if err := w.Sync(); err != nil {
		t.Fatal(err)
	}
	tail := w.Tail()
	w.Close()
	if tail.Segment < 3 {
		t.Fatalf("60 certificates in 8 KiB segments need several segments, got %d", tail.Segment)
	}
	r, err := OpenReader(dirs, codec(t))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for i, der := range cs {
		got, err := r.ReadVerified(locs[i], sha256.Sum256(der))
		if err != nil || string(got) != string(der) {
			t.Fatalf("cert %d: %v", i+1, err)
		}
	}
	// Each segment's header names its first cert_id and the vault.
	segs, _ := FindSegments(dirs)
	b, _ := os.ReadFile(segs[2])
	h, err := DecodeHeader(b)
	if err != nil || h.VaultUUID != testUUID || h.Segment != 2 || h.FirstCertID != firstIn(locs, 2) {
		t.Fatalf("segment 2 header %+v, %v", h, err)
	}
	// A reopened writer continues after the tail and leaves earlier records
	// intact.
	w2 := openWriter(t, dirs, 8<<10, tail, nil)
	loc, err := w2.AppendCert(KindLeaf, 61, cs[0], 0)
	if err != nil || loc.Segment != tail.Segment || loc.Offset != tail.Offset {
		t.Fatalf("append after reopen at %+v: %+v, %v", tail, loc, err)
	}
	w2.Sync()
	w2.Close()
	r2, _ := OpenReader(dirs, codec(t))
	defer r2.Close()
	for i, der := range append(cs, cs[0]) {
		l := loc
		if i < len(cs) {
			l = locs[i]
		}
		if _, err := r2.ReadVerified(l, sha256.Sum256(der)); err != nil {
			t.Fatalf("after reopening, record %d: %v", i+1, err)
		}
	}
}

func firstIn(locs []Loc, seg uint64) uint64 {
	for i, l := range locs {
		if l.Segment == seg {
			return uint64(i + 1)
		}
	}
	return 0
}

// TestRolloverPicksFirstDirWithRoom: new segments go to the first vault
// directory that passes the disk guard (spec §6.2), and a full vault is an
// error, never a silent skip.
func TestRolloverPicksFirstDirWithRoom(t *testing.T) {
	dirs := vaultDirs(t, 2)
	full := map[string]bool{dirs[0]: true}
	check := func(dir string, need uint64) error {
		if full[dir] {
			return fmt.Errorf("%s: disk cap would be exceeded", dir)
		}
		return nil
	}
	w := openWriter(t, dirs, 8<<10, Tail{}, check)
	if _, err := w.AppendCert(KindLeaf, 1, certs(t, 1)[0], 0); err != nil {
		t.Fatal(err)
	}
	w.Close()
	if _, err := os.Stat(filepath.Join(dirs[1], SegmentsDir, SegmentName(1))); err != nil {
		t.Fatalf("segment 1 must go to the second directory: %v", err)
	}
	full[dirs[1]] = true
	w = openWriter(t, dirs, 8<<10, w.Tail(), check)
	var err error
	for i := 0; err == nil && i < 20; i++ {
		_, err = w.AppendCert(KindLeaf, uint64(i+2), certs(t, 1)[0], 0)
	}
	if err == nil {
		t.Fatal("with every directory full, the next rollover must fail")
	}
	w.Close()
}

func TestAppendsRecheckTheCap(t *testing.T) {
	dirs := vaultDirs(t, 1)
	var calls []uint64
	check := func(dir string, need uint64) error {
		calls = append(calls, need)
		if len(calls) > 3 {
			return errors.New("disk cap would be exceeded")
		}
		return nil
	}
	w, err := OpenWriter(Options{Dirs: dirs, VaultUUID: testUUID, SegmentSize: 1 << 30, Check: check, CheckEvery: 2000, Now: fixedNow}, codec(t), Tail{})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	cs := certs(t, 20)
	for i := 0; i < 20; i++ {
		if _, err = w.AppendCert(KindLeaf, uint64(i+1), cs[i], 0); err != nil {
			break
		}
	}
	if err == nil || len(calls) != 4 || calls[0] != 1<<30 || calls[1] != 2000 {
		t.Fatalf("one check before the segment, then one per 2000 bytes, and a refusal stops appends: %v, calls %v", err, calls)
	}
}

func TestReadDetectsCorruption(t *testing.T) {
	dirs := vaultDirs(t, 1)
	c := certs(t, 2)
	w := openWriter(t, dirs, 1<<20, Tail{}, nil)
	loc, _ := w.AppendCert(KindLeaf, 1, c[0], 0)
	loc2, _ := w.AppendCert(KindLeaf, 2, c[1], 0)
	w.Sync()
	w.Close()
	r, _ := OpenReader(dirs, codec(t))
	defer r.Close()
	if _, err := r.ReadVerified(loc, sha256.Sum256(c[1])); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a SHA-256 mismatch is corruption: %v", err)
	}
	if _, err := r.ReadVerified(Loc{Segment: loc.Segment, Offset: loc.Offset, Len: loc.Len + 1}, sha256.Sum256(c[0])); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a wrong length is corruption: %v", err)
	}
	if _, err := r.ReadVerified(Loc{Segment: 9, Offset: 64, Len: 10}, [32]byte{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a missing segment is corruption: %v", err)
	}
	r.Close()
	segs, _ := FindSegments(dirs)
	b, _ := os.ReadFile(segs[1])
	b[loc2.Offset+uint64(loc2.Len)-6] ^= 0xff // inside the frame
	os.WriteFile(segs[1], b, 0o644)
	r2, _ := OpenReader(dirs, codec(t))
	defer r2.Close()
	if _, err := r2.ReadVerified(loc2, sha256.Sum256(c[1])); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a damaged frame is corruption: %v", err)
	}
	if _, err := r2.ReadVerified(loc, sha256.Sum256(c[0])); err != nil {
		t.Fatalf("the intact record still reads: %v", err)
	}
}

func TestDecompressChecksTheFrameDictionary(t *testing.T) {
	c := codec(t)
	frame, err := c.Compress([]byte("certificate"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Decompress(frame, 1); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a record claiming dictionary 1 for a dictionary-less frame is corrupt: %v", err)
	}
	if _, err := c.Compress([]byte("x"), 5); err == nil {
		t.Fatal("an unknown dictionary is refused")
	}
}

func TestDuplicateSegmentIsCorruption(t *testing.T) {
	dirs := vaultDirs(t, 2)
	for _, d := range dirs {
		os.WriteFile(filepath.Join(d, SegmentsDir, SegmentName(3)), Header{Version: 1, Segment: 3}.Encode(), 0o644)
	}
	if _, err := FindSegments(dirs); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("segment 3 in two directories: %v", err)
	}
	os.WriteFile(filepath.Join(dirs[0], SegmentsDir, "junk.seg"), nil, 0o644)
	if _, err := FindSegments(dirs[:1]); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("an unexpected segment file name: %v", err)
	}
}

// TestInspectAndTruncateUncommittedData walks spec §8.5's first recovery
// row: data beyond the committed tail, ending in a torn record.
func TestInspectAndTruncateUncommittedData(t *testing.T) {
	dirs := vaultDirs(t, 1)
	cs := certs(t, 40)
	w := openWriter(t, dirs, 8<<10, Tail{}, nil)
	for i := range 10 {
		w.AppendCert(KindLeaf, uint64(i+1), cs[i], 0)
	}
	w.Sync()
	committed := w.Tail()
	for i := 10; i < 40; i++ { // an uncommitted batch that rolls into new segments
		w.AppendCert(KindLeaf, uint64(i+1), cs[i], 0)
	}
	last := w.Tail()
	w.Close()
	segs, _ := FindSegments(dirs)
	f, _ := os.OpenFile(segs[last.Segment], os.O_WRONLY|os.O_APPEND, 0)
	f.Write(AppendRecord(nil, Record{Kind: KindLeaf, CertID: 99, Frame: make([]byte, 500)})[:100]) // torn
	f.Close()

	if _, err := OpenWriter(Options{Dirs: dirs, SegmentSize: 8 << 10}, codec(t), committed); err == nil {
		t.Fatal("a writer must refuse to open over uncommitted data")
	}
	u, err := InspectTail(dirs, committed)
	if err != nil || u.MaxCertID != 40 || u.Bytes == 0 {
		t.Fatalf("InspectTail: %+v, %v; want max cert_id 40 (the torn record 99 is not intact)", u, err)
	}
	var seen []uint64
	err = Scan(dirs, Tail{}, last, func(l Loc, r Record) error { seen = append(seen, r.CertID); return nil })
	if err != nil || len(seen) != 40 {
		t.Fatalf("Scan up to the last intact record: %d records, %v", len(seen), err)
	}
	if err := Scan(dirs, committed, Tail{Segment: last.Segment, Offset: last.Offset + 100}, func(Loc, Record) error { return nil }); !errors.Is(err, ErrTorn) {
		t.Fatalf("scanning into the torn record: %v", err)
	}
	if err := Truncate(dirs, committed); err != nil {
		t.Fatal(err)
	}
	after, _ := FindSegments(dirs)
	fi, _ := os.Stat(after[committed.Segment])
	if len(after) != int(committed.Segment) || uint64(fi.Size()) != committed.Offset {
		t.Fatalf("after Truncate: %d segments, tail segment %d bytes; want %d segments ending at %d", len(after), fi.Size(), committed.Segment, committed.Offset)
	}
	if u, err := InspectTail(dirs, committed); err != nil || u.Bytes != 0 || u.MaxCertID != 0 {
		t.Fatalf("nothing remains beyond the tail: %+v, %v", u, err)
	}
	w = openWriter(t, dirs, 8<<10, committed, nil)
	if _, err := w.AppendCert(KindLeaf, 41, cs[0], 0); err != nil {
		t.Fatal(err)
	}
	w.Close()
}

func TestOpenWriterRefusesSegmentsBeyondTail(t *testing.T) {
	dirs := vaultDirs(t, 1)
	w := openWriter(t, dirs, 4<<10, Tail{}, nil)
	for i, der := range certs(t, 12) {
		w.AppendCert(KindLeaf, uint64(i+1), der, 0)
	}
	w.Close()
	if _, err := OpenWriter(Options{Dirs: dirs, SegmentSize: 4 << 10}, codec(t), Tail{Segment: 1, Offset: HeaderSize}); err == nil {
		t.Fatal("later segments beyond the tail must be refused")
	}
}

func TestRolloverHooks(t *testing.T) {
	dirs := vaultDirs(t, 1)
	var points []string
	w, err := OpenWriter(Options{Dirs: dirs, VaultUUID: testUUID, SegmentSize: 1 << 20, Now: fixedNow,
		Hook: func(p string) { points = append(points, p) }}, codec(t), Tail{})
	if err != nil {
		t.Fatal(err)
	}
	w.AppendCert(KindLeaf, 1, []byte("der"), 0)
	w.Close()
	want := []string{HookRolloverBeforeHeader, HookRolloverAfterHeader, HookRolloverBeforeDirSync}
	if !slices.Equal(points, want) {
		t.Fatalf("hook order %v, want %v", points, want)
	}
}

func TestPreferStartsNewSegmentsInTheReservedDirectory(t *testing.T) {
	dirs := vaultDirs(t, 2)
	w := openWriter(t, dirs, 1<<20, Tail{}, nil)
	defer w.Close()
	cs := certs(t, 3)
	a, _ := w.AppendCert(KindLeaf, 1, cs[0], 0)
	w.Prefer(dirs[1])
	b, _ := w.AppendCert(KindLeaf, 2, cs[1], 0)
	c, _ := w.AppendCert(KindLeaf, 3, cs[2], 0)
	segs, _ := FindSegments(dirs)
	if a.Segment != 1 || b.Segment != 2 || c.Segment != 2 || filepath.Dir(filepath.Dir(segs[2])) != dirs[1] {
		t.Fatalf("after Prefer, appends continue in a new segment in the preferred directory: %v %v %v, %s", a, b, c, segs[2])
	}
	w.Prefer(dirs[1])
	d, _ := w.AppendCert(KindLeaf, 4, cs[0], 0)
	if d.Segment != 2 {
		t.Fatal("preferring the current directory again does not roll over")
	}
}

func TestPreferAfterReopenKeepsTheTailSegment(t *testing.T) {
	dirs := vaultDirs(t, 2)
	w := openWriter(t, dirs, 1<<20, Tail{}, nil)
	w.AppendCert(KindLeaf, 1, certs(t, 1)[0], 0)
	w.Sync()
	tail := w.Tail()
	w.Close()
	w = openWriter(t, dirs, 1<<20, tail, nil)
	defer w.Close()
	w.Prefer(dirs[0])
	if loc, _ := w.AppendCert(KindLeaf, 2, certs(t, 1)[0], 0); loc.Segment != 1 {
		t.Fatalf("a reopened writer preferring the tail segment's own directory must not roll over: segment %d", loc.Segment)
	}
}
