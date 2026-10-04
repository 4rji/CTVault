package leaf_test

import (
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/merkle"
)

// FuzzDecode: the decoder must never panic (spec §13.3), and its invariants
// hold for any input.
func FuzzDecode(f *testing.F) {
	g, err := ctlogtest.NewGenerator()
	if err != nil {
		f.Fatal(err)
	}
	pre, fin, err := g.PairViaSigner("fuzz.example.test", 1)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(pre.LeafInput, pre.ExtraData)
	f.Add(fin.LeafInput, fin.ExtraData)
	f.Add(ctlogtest.MalformedEntry(1).LeafInput, []byte{})
	f.Fuzz(func(t *testing.T, li, ed []byte) {
		e := leaf.Decode(li, ed)
		if e.LeafHash != merkle.LeafHash(li) {
			t.Fatal("leaf hash must always be computed")
		}
		if e.Code.LeafStructure() && (e.CertDER != nil || e.Chain != nil) {
			t.Fatal("nothing may be kept from an uninterpretable leaf")
		}
		if e.Code == leaf.OK && e.Type == leaf.TypeUnknown {
			t.Fatal("an unknown entry type always carries a code")
		}
	})
}
