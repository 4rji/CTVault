package leaf_test

import (
	"testing"

	"github.com/4rji/ctvault/internal/leaf"
)

func TestPrecertIssuanceDigest(t *testing.T) {
	g := generator(t)
	pre, fin := pair(t, g, false)
	got, ok := leaf.PrecertIssuanceDigest(pre.CertDER)
	if !ok || got != leaf.Decode(fin.LeafInput, fin.ExtraData).IssuanceDigest {
		t.Fatal("a CA-issued precert's own DER must give the digest its final certificate links on")
	}
	if _, ok := leaf.PrecertIssuanceDigest(fin.CertDER); ok {
		t.Fatal("a final certificate (no poison) is not a precert")
	}
	if _, ok := leaf.PrecertIssuanceDigest([]byte{0x30, 0x00}); ok {
		t.Fatal("unparseable DER is not a precert")
	}
	sPre, sFin := pair(t, g, true)
	if d, ok := leaf.PrecertIssuanceDigest(sPre.CertDER); !ok || d == leaf.Decode(sFin.LeafInput, sFin.ExtraData).IssuanceDigest {
		t.Fatal("a signer-issued precert gets a digest that misses (its TBS carries the signer's name)")
	}
}
