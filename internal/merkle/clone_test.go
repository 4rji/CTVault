package merkle

import "testing"

// TestCloneIsIndependent: appending to a clone must never change the
// original. The compact range's hash list was shared, so a clone's merges
// overwrote the original's last node: an abandoned batch attempt then
// corrupted the committed tip, and every retry failed verification.
func TestCloneIsIndependent(t *testing.T) {
	s := NewState()
	for i := range 3 {
		s.Append(LeafHash([]byte{byte(i)}))
	}
	want, _ := s.Root()
	c := s.Clone()
	for i := range 5 {
		c.Append(LeafHash([]byte{byte(10 + i)}))
	}
	if got, _ := s.Root(); got != want || s.Size() != 3 {
		t.Fatalf("appending to the clone changed the original (size %d)", s.Size())
	}
}
