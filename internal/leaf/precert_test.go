package leaf_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/leaf"
)

// impostor returns a self-signed certificate with the given subject, a fresh
// key and no subject key ID: a chain certificate that matches by name only.
func impostor(t *testing.T, rawSubject []byte) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(99), RawSubject: rawSubject,
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<32, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestPrecertIssuerByRelationship(t *testing.T) {
	g := generator(t)
	pre, _ := pair(t, g, false)
	sPre, _ := pair(t, g, true)
	ca, _ := x509.ParseCertificate(g.CADER())
	other := generator(t) // an unrelated CA with the same name but another key ID
	for name, tc := range map[string]struct {
		entry ctlogtest.Entry
		chain [][]byte
		want  leaf.Code
	}{
		"issuer after an unrelated cert": {pre, [][]byte{other.CADER(), g.CADER()}, leaf.OK},
		"issuer listed twice":            {pre, [][]byte{g.CADER(), g.CADER()}, leaf.OK},
		"empty chain":                    {pre, nil, leaf.ChainIssuerMissing},
		"only a same-name other CA":      {pre, [][]byte{other.CADER()}, leaf.ChainIssuerMissing},
		"name-only impostor":             {pre, [][]byte{g.CADER(), impostor(t, ca.RawSubject)}, leaf.ChainIssuerAmbiguous},
		"signer, chain reversed":         {sPre, [][]byte{g.CADER(), g.SignerDER()}, leaf.OK},
		"signer without its CA":          {sPre, [][]byte{g.SignerDER()}, leaf.ChainIssuerMissing},
		"signer only CA":                 {sPre, [][]byte{g.CADER()}, leaf.ChainIssuerMissing},
	} {
		e := leaf.Decode(tc.entry.LeafInput, ctlogtest.PrecertExtraData(tc.entry.CertDER, tc.chain...))
		if e.Code != tc.want {
			t.Errorf("%s: code %q, want %q", name, e.Code, tc.want)
		}
		if e.CertDER == nil || !e.HasIssuanceDigest {
			t.Errorf("%s: issuer problems keep the precertificate and the issuance key", name)
		}
	}
}

func TestPrecertCrossChecks(t *testing.T) {
	g := generator(t)
	pre, _ := pair(t, g, false)
	pre2, _ := pair(t, g, false)
	sPre, _ := pair(t, g, true)

	wrongIKH := sha256.Sum256([]byte("not the issuer's key"))
	e := leaf.Decode(ctlogtest.MerkleTreeLeaf(pre.Timestamp, ctlogtest.PrecertEntry, pre.PrecertTBS, wrongIKH), pre.ExtraData)
	if e.Code != leaf.IssuerKeyHashMismatch || e.IssuerKeyHash != wrongIKH {
		t.Fatalf("wrong issuer_key_hash: code %q; the logged value must be kept", e.Code)
	}

	// The log's TBS belongs to another issuance than the precert in extra_data.
	e = leaf.Decode(ctlogtest.MerkleTreeLeaf(pre.Timestamp, ctlogtest.PrecertEntry, pre2.PrecertTBS, pre.IssuerKeyHash), pre.ExtraData)
	if e.Code != leaf.PrecertTBSMismatch {
		t.Fatalf("mismatched TBS: code %q", e.Code)
	}
	if e.IssuanceDigest != sha256.Sum256(pre2.PrecertTBS) {
		t.Fatal("the log's TBS is authoritative: the issuance digest must hash it, not a reconstruction")
	}

	// Via a signer, the log's TBS has the CA's name; a TBS that kept the
	// signer's name and key ID (no §3.2 rewrite) must not match.
	sc, _ := x509.ParseCertificate(sPre.CertDER)
	if e := leaf.Decode(ctlogtest.MerkleTreeLeaf(sPre.Timestamp, ctlogtest.PrecertEntry, sc.RawTBSCertificate, sPre.IssuerKeyHash), sPre.ExtraData); e.Code != leaf.PrecertTBSMismatch {
		t.Fatalf("un-rewritten signer TBS: code %q", e.Code)
	}

	garbage := ctlogtest.PrecertExtraData([]byte{0x30, 0x00}, g.CADER())
	if e := leaf.Decode(pre.LeafInput, garbage); e.Code != leaf.PrecertTBSMismatch || e.CertDER == nil {
		t.Fatalf("an unparseable precertificate is kept as served and flagged: %q", e.Code)
	}
}

func TestX509IssuanceDigest(t *testing.T) {
	g := generator(t)
	ca, _ := x509.ParseCertificate(g.CADER())
	plain := ctlogtest.MerkleTreeLeaf(1, ctlogtest.X509Entry, g.CADER(), [32]byte{})
	e := leaf.Decode(plain, ctlogtest.Chain())
	if e.Code != leaf.OK || e.IssuanceDigest != sha256.Sum256(ca.RawTBSCertificate) {
		t.Fatalf("a certificate without an SCT list hashes its TBS unchanged: %q", e.Code)
	}
	bad := ctlogtest.MerkleTreeLeaf(1, ctlogtest.X509Entry, []byte{0x30, 0x00}, [32]byte{})
	e = leaf.Decode(bad, ctlogtest.Chain())
	if e.Code != leaf.IssuanceKeyUnavailable || e.CertDER == nil || e.HasIssuanceDigest {
		t.Fatalf("unparseable final cert: code %q, cert kept %v, digest %v", e.Code, e.CertDER != nil, e.HasIssuanceDigest)
	}
	if _, ok := e.IssuanceKey(); ok {
		t.Fatal("no issuance key without a digest")
	}
}
