package vault

import "testing"

func TestDeltaCacheReset(t *testing.T) {
	c := NewDeltaCache(4)
	c.Put([32]byte{1}, Loc{Segment: 1}, 1)
	c.Reset()
	if _, _, ok := c.Get([32]byte{1}); ok || c.Len() != 0 {
		t.Fatal("Reset empties the cache")
	}
	for i := range 6 {
		c.Put([32]byte{byte(i + 10)}, Loc{Segment: uint64(i)}, uint64(i))
	}
	if c.Len() != 4 {
		t.Fatalf("a reset cache keeps its capacity: %d", c.Len())
	}
}
