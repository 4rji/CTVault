package vault

import (
	"crypto/sha256"
	"errors"
	"os"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/leaf"
)

func pairs(t *testing.T, n int) (pres, finals [][]byte) {
	t.Helper()
	g, err := ctlogtest.NewGenerator()
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		p, f, err := g.Pair("delta.example.test", uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		pres, finals = append(pres, p.CertDER), append(finals, f.CertDER)
	}
	return pres, finals
}

func TestDeltaRoundTrip(t *testing.T) {
	dirs := vaultDirs(t, 1)
	pres, finals := pairs(t, 5)
	w := openWriter(t, dirs, 1<<20, Tail{}, nil)
	var bases, deltas, fulls []Loc
	for i := range pres {
		b, _ := w.AppendCert(KindLeaf, uint64(3*i+1), pres[i], 0)
		d, err := w.AppendDelta(uint64(3*i+2), finals[i], b) // base still unsynced: same batch
		if err != nil {
			t.Fatal(err)
		}
		f, _ := w.AppendCert(KindLeaf, uint64(3*i+3), finals[i], 0)
		bases, deltas, fulls = append(bases, b), append(deltas, d), append(fulls, f)
	}
	w.Sync()
	w.Close()
	r, _ := OpenReader(dirs, codec(t))
	defer r.Close()
	saved := 0
	for i := range finals {
		got, err := r.ReadVerified(deltas[i], sha256.Sum256(finals[i]))
		if err != nil || string(got) != string(finals[i]) {
			t.Fatalf("delta %d: %v", i, err)
		}
		saved += int(fulls[i].Len) - int(deltas[i].Len)
	}
	if saved <= 0 {
		t.Fatalf("a final certificate against its own precert must be smaller than in full (saved %d bytes)", saved)
	}
}

func TestDeltaCorruption(t *testing.T) {
	dirs := vaultDirs(t, 1)
	pres, finals := pairs(t, 1)
	w := openWriter(t, dirs, 1<<20, Tail{}, nil)
	chain, _ := w.AppendCert(KindChain, 1, pres[0], 0)
	if _, err := w.AppendDelta(2, finals[0], chain); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a delta base must be a leaf record: %v", err)
	}
	base, _ := w.AppendCert(KindLeaf, 3, pres[0], 0)
	d, _ := w.AppendDelta(4, finals[0], base)
	w.Sync()
	w.Close()

	// A record claiming a base that is not a leaf, or lies ahead, is corrupt.
	segs, _ := FindSegments(dirs)
	b, _ := os.ReadFile(segs[1])
	forged := AppendRecord(nil, Record{Kind: KindDelta, CertID: 5, BaseSeg: 1, BaseOff: chain.Offset, Frame: []byte{0x28, 0xb5}})
	ahead := AppendRecord(nil, Record{Kind: KindDelta, CertID: 6, BaseSeg: 1, BaseOff: 1 << 20, Frame: []byte{0x28, 0xb5}})
	os.WriteFile(segs[1], append(append(b, forged...), ahead...), 0o644)
	r, _ := OpenReader(dirs, codec(t))
	defer r.Close()
	if _, err := r.ReadVerified(d, sha256.Sum256(finals[0])); err != nil {
		t.Fatalf("the real delta still reads: %v", err)
	}
	fl := Loc{Segment: 1, Offset: uint64(len(b)), Len: uint32(len(forged))}
	if _, _, err := r.Read(fl); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a chain record as delta base: %v", err)
	}
	al := Loc{Segment: 1, Offset: uint64(len(b) + len(forged)), Len: uint32(len(ahead))}
	if _, _, err := r.Read(al); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a base ahead of the delta: %v", err)
	}
}

func TestDeltaCache(t *testing.T) {
	c := NewDeltaCache(3)
	for i := range 4 {
		c.Put([32]byte{byte(i + 1)}, Loc{Segment: uint64(i)}, uint64(100+i))
	}
	if _, _, ok := c.Get([32]byte{1}); ok || c.Len() != 3 {
		t.Fatalf("the oldest entry is evicted at capacity: len %d", c.Len())
	}
	if l, id, ok := c.Get([32]byte{4}); !ok || l.Segment != 3 || id != 103 {
		t.Fatal("the newest entry is cached")
	}
	c.Put([32]byte{4}, Loc{Segment: 9}, 109)
	if l, id, _ := c.Get([32]byte{4}); l.Segment != 9 || id != 109 || c.Len() != 3 {
		t.Fatal("re-putting a digest updates it in place")
	}
	off := NewDeltaCache(0)
	off.Put([32]byte{1}, Loc{}, 1)
	if _, _, ok := off.Get([32]byte{1}); ok {
		t.Fatal("capacity 0 disables the cache")
	}
}

// TestWarmFindsPrecertsInRanges: after a restart the cache is refilled from
// the last committed batches; only precerts enter it, keyed so that their
// final certificates find them.
func TestWarmFindsPrecertsInRanges(t *testing.T) {
	dirs := vaultDirs(t, 1)
	g, _ := ctlogtest.NewGenerator()
	w := openWriter(t, dirs, 4<<10, Tail{}, nil)
	var rs []Range
	var finalDigests [][32]byte
	var preLocs []Loc
	var preIDs []uint64
	id := uint64(0)
	for batch := range 3 {
		start := w.Tail()
		for i := range 3 {
			p, f, _ := g.Pair("warm.example.test", uint64(batch*10+i))
			id++
			l, _ := w.AppendCert(KindLeaf, id, p.CertDER, 0)
			id++
			w.AppendCert(KindLeaf, id, f.CertDER, 0)
			preLocs = append(preLocs, l)
			preIDs = append(preIDs, id-1)
			finalDigests = append(finalDigests, leaf.Decode(f.LeafInput, f.ExtraData).IssuanceDigest)
		}
		rs = append(rs, Range{Start: start, End: w.Tail()})
	}
	w.Sync()
	w.Close()
	c := NewDeltaCache(100)
	if err := Warm(dirs, codec(t), c, rs[1:], leaf.PrecertIssuanceDigest); err != nil {
		t.Fatal(err)
	}
	if c.Len() != 6 {
		t.Fatalf("two batches hold 6 precerts (finals are not cached): %d", c.Len())
	}
	if _, _, ok := c.Get(finalDigests[0]); ok {
		t.Fatal("the first batch was outside the warm-up window")
	}
	if l, id, ok := c.Get(finalDigests[4]); !ok || l != preLocs[4] || id != preIDs[4] {
		t.Fatalf("final 4 must find its precert and its cert_id %d: %+v %d %v", preIDs[4], l, id, ok)
	}
}

// TestDeltaCacheNeedsTheFullDigest: two digests sharing their first 16
// bytes never return each other's precert.
func TestDeltaCacheNeedsTheFullDigest(t *testing.T) {
	c := NewDeltaCache(10)
	a, b := [32]byte{7}, [32]byte{7}
	b[31] = 1
	c.Put(a, Loc{Segment: 1}, 1)
	if _, _, ok := c.Get(b); ok {
		t.Fatal("a 16-byte prefix match is not a hit")
	}
	c.Put(b, Loc{Segment: 2}, 2)
	if l, _, ok := c.Get(b); !ok || l.Segment != 2 {
		t.Fatal("the newer of two colliding digests wins")
	}
	if _, _, ok := c.Get(a); ok {
		t.Fatal("the displaced digest misses (stored in full instead)")
	}
	for i := range 20 { // wrap the ring past the displaced slot
		c.Put([32]byte{byte(100 + i)}, Loc{Segment: uint64(i)}, uint64(i))
	}
	if c.Len() != 10 {
		t.Fatalf("len %d after wrapping, want 10", c.Len())
	}
}
