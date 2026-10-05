package vault

import (
	"errors"
	"os"
	"slices"
	"testing"
)

// TestTornAppendHook: with a hook set, a record is written in two halves
// around HookAppendMidRecord, so a kill there leaves a torn record (spec
// §13.5); recovery's tools see the intact records before it.
func TestTornAppendHook(t *testing.T) {
	dirs := vaultDirs(t, 1)
	cs := certs(t, 4)
	n := 0
	w, err := OpenWriter(Options{Dirs: dirs, VaultUUID: testUUID, SegmentSize: 1 << 20, Now: fixedNow,
		Hook: func(p string) {
			if p == HookAppendMidRecord {
				if n++; n == 3 {
					panic("killed mid-record")
				}
			}
		}}, codec(t), Tail{})
	if err != nil {
		t.Fatal(err)
	}
	w.AppendCert(KindLeaf, 1, cs[0], 0)
	w.AppendCert(KindLeaf, 2, cs[1], 0)
	intact := w.Tail()
	func() {
		defer func() { recover() }()
		w.AppendCert(KindLeaf, 3, cs[2], 0)
		t.Fatal("the hook did not fire")
	}()
	w.Close()
	segs, _ := FindSegments(dirs)
	fi, _ := os.Stat(segs[1])
	if uint64(fi.Size()) <= intact.Offset {
		t.Fatalf("half of record 3 must be on disk: segment is %d bytes, intact records end at %d", fi.Size(), intact.Offset)
	}
	u, err := InspectTail(dirs, Tail{Segment: 1, Offset: HeaderSize})
	if err != nil || u.MaxCertID != 2 {
		t.Fatalf("InspectTail: %+v, %v; want max cert_id 2", u, err)
	}
	if err := Scan(dirs, Tail{}, Tail{Segment: 1, Offset: uint64(fi.Size())}, func(Loc, Record) error { return nil }); !errors.Is(err, ErrTorn) {
		t.Fatalf("the half-written record is torn: %v", err)
	}
}

// TestTruncateNeverExtends: cutting a segment back to a tail it does not
// reach would fill it with zeros; that, or a missing tail segment, is
// corruption, and the file is left alone.
func TestTruncateNeverExtends(t *testing.T) {
	dirs := vaultDirs(t, 1)
	w := openWriter(t, dirs, 1<<20, Tail{}, nil)
	w.AppendCert(KindLeaf, 1, certs(t, 1)[0], 0)
	end := w.Tail()
	w.Close()
	if err := Truncate(dirs, Tail{Segment: 1, Offset: end.Offset + 100}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a tail beyond the segment's end: %v", err)
	}
	segs, _ := FindSegments(dirs)
	if fi, _ := os.Stat(segs[1]); uint64(fi.Size()) != end.Offset {
		t.Fatalf("the segment changed: %d bytes, want %d", fi.Size(), end.Offset)
	}
	if err := Truncate(dirs, Tail{Segment: 2, Offset: HeaderSize}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a missing tail segment: %v", err)
	}
}

// TestCheckSegments: every committed segment exists, sits at or before the
// tail, and carries an intact header with its own number and this vault's
// UUID (spec §6.2). A segment restored from another vault is corruption.
func TestCheckSegments(t *testing.T) {
	dirs := vaultDirs(t, 1)
	w := openWriter(t, dirs, 4<<10, Tail{}, nil)
	for i, der := range certs(t, 24) {
		w.AppendCert(KindLeaf, uint64(i+1), der, 0)
	}
	tail := w.Tail()
	w.Close()
	if tail.Segment < 3 {
		t.Fatalf("the test needs three segments, got %d", tail.Segment)
	}
	if err := CheckSegments(dirs, testUUID, tail); err != nil {
		t.Fatalf("a clean vault: %v", err)
	}
	if err := CheckSegments(dirs, [16]byte{9}, tail); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("another vault's UUID: %v", err)
	}
	if err := CheckSegments(dirs, testUUID, Tail{Segment: 2, Offset: HeaderSize}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a segment beyond the tail: %v", err)
	}
	segs, _ := FindSegments(dirs)
	rewrite := func(id uint64, edit func(*Header)) {
		f, _ := os.OpenFile(segs[id], os.O_RDWR, 0)
		defer f.Close()
		b := make([]byte, HeaderSize)
		f.ReadAt(b, 0)
		h, _ := DecodeHeader(b)
		edit(&h)
		f.WriteAt(h.Encode(), 0)
	}
	rewrite(2, func(h *Header) { h.Segment = 3 })
	if err := CheckSegments(dirs, testUUID, tail); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("segment file 2 holding segment 3: %v", err)
	}
	rewrite(2, func(h *Header) { h.Segment = 2 })
	b, _ := os.ReadFile(segs[2])
	os.WriteFile(segs[2], slices.Concat([]byte("garbage!"), b[8:]), 0o644)
	if err := CheckSegments(dirs, testUUID, tail); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a damaged header: %v", err)
	}
	os.WriteFile(segs[2], b, 0o644)
	os.Remove(segs[2])
	if err := CheckSegments(dirs, testUUID, tail); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a missing segment: %v", err)
	}
}
