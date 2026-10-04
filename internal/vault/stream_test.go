package vault

import (
	"crypto/rand"
	"runtime"
	"testing"
)

// allocated returns the bytes fn allocates.
func allocated(fn func()) uint64 {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	fn()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

// bigSegment writes 40 records of 1 MiB of random (incompressible) data into
// one segment and returns the tail before the last record and the end.
func bigSegment(t *testing.T) ([]string, Tail, Tail) {
	t.Helper()
	dirs := vaultDirs(t, 1)
	w := openWriter(t, dirs, 1<<30, Tail{}, nil)
	var beforeLast Tail
	for i := range 40 {
		der := make([]byte, 1<<20)
		rand.Read(der)
		if i == 39 {
			beforeLast = w.Tail()
		}
		if _, err := w.AppendCert(KindLeaf, uint64(i+1), der, 0); err != nil {
			t.Fatal(err)
		}
	}
	w.Sync()
	end := w.Tail()
	w.Close()
	return dirs, beforeLast, end
}

// TestScanAndInspectStream: recovery and warm-up must not load whole
// segments (1 GiB by default) into memory.
func TestScanAndInspectStream(t *testing.T) {
	dirs, beforeLast, end := bigSegment(t)
	n := 0
	scan := allocated(func() {
		if err := Scan(dirs, beforeLast, end, func(Loc, Record) error { n++; return nil }); err != nil {
			t.Fatal(err)
		}
	})
	if n != 1 || scan > 8<<20 {
		t.Fatalf("scanning the last record of a 40 MiB segment read %d records and allocated %d MiB", n, scan>>20)
	}
	inspect := allocated(func() {
		if u, err := InspectTail(dirs, end); err != nil || u.Bytes != 0 {
			t.Fatalf("clean tail: %+v %v", u, err)
		}
	})
	if inspect > 1<<20 {
		t.Fatalf("inspecting a clean tail allocated %d MiB; nothing lies beyond it", inspect>>20)
	}
	var ranges []Range
	for range 4 { // the last record, as four contiguous empty-or-not ranges
		ranges = append(ranges, Range{Start: beforeLast, End: beforeLast})
	}
	ranges[3].End = end
	c := NewDeltaCache(10)
	warm := allocated(func() {
		if err := Warm(dirs, codec(t), c, ranges, func([]byte) ([32]byte, bool) { return [32]byte{}, false }); err != nil {
			t.Fatal(err)
		}
	})
	if warm > 16<<20 {
		t.Fatalf("warming over the end of a 40 MiB segment allocated %d MiB", warm>>20)
	}
}
