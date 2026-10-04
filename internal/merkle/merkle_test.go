package merkle

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
)

// --- helpers -----------------------------------------------------------------

type sthJSON struct {
	TreeSize  uint64 `json:"tree_size"`
	Timestamp uint64 `json:"timestamp"`
	Root      string `json:"sha256_root_hash"`
	Sig       string `json:"tree_head_signature"`
}

func loadSTH(t *testing.T, name string) SignedTreeHead {
	t.Helper()
	raw, err := os.ReadFile("../testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var j sthJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		t.Fatal(err)
	}
	root, _ := base64.StdEncoding.DecodeString(j.Root)
	sig, _ := base64.StdEncoding.DecodeString(j.Sig)
	sth := SignedTreeHead{TreeSize: j.TreeSize, Timestamp: j.Timestamp, Signature: sig}
	copy(sth.RootHash[:], root)
	return sth
}

// argonKey reads the argon2027h1 public key from the real log list fixture.
func argonKey(t *testing.T) crypto.PublicKey {
	t.Helper()
	raw, err := os.ReadFile("../testdata/log_list_google.json")
	if err != nil {
		t.Fatal(err)
	}
	var ll struct {
		Operators []struct {
			Logs []struct{ URL, Key string } `json:"logs"`
		} `json:"operators"`
	}
	if err := json.Unmarshal(raw, &ll); err != nil {
		t.Fatal(err)
	}
	for _, l := range ll.Operators[0].Logs {
		if l.URL == "https://ct.googleapis.com/logs/us1/argon2027h1/" {
			der, _ := base64.StdEncoding.DecodeString(l.Key)
			pub, err := x509.ParsePKIXPublicKey(der)
			if err != nil {
				t.Fatal(err)
			}
			return pub
		}
	}
	t.Fatal("argon2027h1 missing from fixture")
	return nil
}

// sign builds a DigitallySigned blob over the STH with a test key.
func sign(t *testing.T, key crypto.Signer, sigAlg byte, sth SignedTreeHead) []byte {
	t.Helper()
	digest := sha256.Sum256(treeHeadSignatureInput(sth))
	sig, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	ds := []byte{hashAlgSHA256, sigAlg}
	ds = binary.BigEndian.AppendUint16(ds, uint16(len(sig)))
	return append(ds, sig...)
}

// --- STH signatures ----------------------------------------------------------

func TestVerifySTHRealArgon(t *testing.T) {
	pub := argonKey(t)
	for _, f := range []string{"argon2027h1_sth1.json", "argon2027h1_sth2.json"} {
		sth := loadSTH(t, f)
		if err := VerifySTH(pub, sth); err != nil {
			t.Fatalf("%s should verify: %v", f, err)
		}
		sth.TreeSize++
		if err := VerifySTH(pub, sth); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("%s with tampered size: got %v, want ErrBadSignature", f, err)
		}
	}
}

func TestVerifySTHTestKeys(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	sth := SignedTreeHead{TreeSize: 42, Timestamp: 1700000000000, RootHash: sha256.Sum256([]byte("root"))}

	ecSTH := sth
	ecSTH.Signature = sign(t, ec, sigAlgECDSA, sth)
	if err := VerifySTH(&ec.PublicKey, ecSTH); err != nil {
		t.Fatalf("ECDSA: %v", err)
	}
	rsaSTH := sth
	rsaSTH.Signature = sign(t, rk, sigAlgRSA, sth)
	if err := VerifySTH(&rk.PublicKey, rsaSTH); err != nil {
		t.Fatalf("RSA: %v", err)
	}

	bad := map[string]SignedTreeHead{
		"wrong key":           ecSTH,
		"truncated":           {TreeSize: 42, Signature: []byte{4, 3, 0}},
		"length mismatch":     {TreeSize: 42, Signature: append(append([]byte{}, ecSTH.Signature...), 0)},
		"sha1 hash algorithm": {TreeSize: 42, Signature: append([]byte{2}, ecSTH.Signature[1:]...)},
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, s := range bad {
		pub := crypto.PublicKey(&ec.PublicKey)
		if name == "wrong key" {
			pub = &other.PublicKey
		}
		if err := VerifySTH(pub, s); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: got %v, want ErrBadSignature", name, err)
		}
	}
	mislabeled := rsaSTH
	mislabeled.Signature = append([]byte{hashAlgSHA256, sigAlgECDSA}, rsaSTH.Signature[2:]...)
	if err := VerifySTH(&rk.PublicKey, mislabeled); !errors.Is(err, ErrBadSignature) {
		t.Errorf("RSA key with ECDSA label must fail, got %v", err)
	}
}

// --- compact range -----------------------------------------------------------

// TestStateMatchesRFC6962Vectors checks every tree size against the RFC 6962
// reference vectors shipped with transparency-dev/merkle: the root hash and
// the compact range we persist in _COMMIT.json (spec §8.4).
func TestStateMatchesRFC6962Vectors(t *testing.T) {
	leaves, roots, compacts := testonly.LeafInputs(), testonly.RootHashes(), testonly.CompactTrees()
	s := NewState()
	for size := 0; size <= len(leaves); size++ {
		if size > 0 {
			if err := s.Append(LeafHash(leaves[size-1])); err != nil {
				t.Fatal(err)
			}
		}
		root, err := s.Root()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(root[:], roots[size]) {
			t.Fatalf("size %d: root %x, want %x", size, root, roots[size])
		}
		b, _ := json.Marshal(s)
		var j struct {
			Hashes []string `json:"compact_range"`
		}
		json.Unmarshal(b, &j)
		if len(j.Hashes) != len(compacts[size]) {
			t.Fatalf("size %d: %d compact hashes, want %d", size, len(j.Hashes), len(compacts[size]))
		}
		for i, h := range compacts[size] {
			if j.Hashes[i] != fmt.Sprintf("%x", h) {
				t.Fatalf("size %d: compact hash %d differs", size, i)
			}
		}
	}
}

func TestStateMatchesReferenceTree(t *testing.T) {
	ref := testonly.New(rfc6962.DefaultHasher)
	s := NewState()
	empty, _ := s.Root()
	if string(empty[:]) != string(rfc6962.DefaultHasher.EmptyRoot()) {
		t.Fatal("empty state must have the RFC 6962 empty root")
	}
	for i := 0; i < 70; i++ {
		leaf := []byte(fmt.Sprintf("leaf-%d", i))
		ref.AppendData(leaf)
		if err := s.Append(LeafHash(leaf)); err != nil {
			t.Fatal(err)
		}
		got, err := s.Root()
		if err != nil {
			t.Fatal(err)
		}
		if string(got[:]) != string(ref.Hash()) || s.Size() != uint64(i+1) {
			t.Fatalf("size %d: root mismatch", i+1)
		}
	}
}

func TestStateJSONRoundTripAndClone(t *testing.T) {
	s := NewState()
	for i := 0; i < 13; i++ {
		s.Append(LeafHash([]byte{byte(i)}))
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var back State
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	r1, _ := s.Root()
	r2, _ := back.Root()
	if back.Size() != 13 || r1 != r2 {
		t.Fatalf("round trip changed state (size %d)", back.Size())
	}
	c := s.Clone()
	c.Append(LeafHash([]byte("more")))
	if s.Size() != 13 || c.Size() != 14 {
		t.Fatal("Clone must be independent")
	}
}

func TestStateUnmarshalRejectsGarbage(t *testing.T) {
	for _, in := range []string{
		`{"size": 13, "compact_range": ["zz"]}`,
		`{"size": 13, "compact_range": []}`,
		`{"size": 1, "compact_range": ["` + fmt.Sprintf("%064x", 1) + `", "` + fmt.Sprintf("%064x", 2) + `"]}`,
	} {
		var s State
		if err := json.Unmarshal([]byte(in), &s); err == nil {
			t.Errorf("accepted invalid state %s", in)
		}
	}
}

// --- consistency proofs ------------------------------------------------------

func TestVerifyConsistencyRealArgon(t *testing.T) {
	sth1, sth2 := loadSTH(t, "argon2027h1_sth1.json"), loadSTH(t, "argon2027h1_sth2.json")
	raw, err := os.ReadFile("../testdata/argon2027h1_consistency.json")
	if err != nil {
		t.Fatal(err)
	}
	var cj struct{ Consistency []string }
	json.Unmarshal(raw, &cj)
	p := make([][32]byte, len(cj.Consistency))
	for i, n := range cj.Consistency {
		d, _ := base64.StdEncoding.DecodeString(n)
		copy(p[i][:], d)
	}
	if err := VerifyConsistency(sth1.TreeSize, sth2.TreeSize, sth1.RootHash, sth2.RootHash, p); err != nil {
		t.Fatalf("real Argon proof should verify: %v", err)
	}
	p[0][0] ^= 1
	if err := VerifyConsistency(sth1.TreeSize, sth2.TreeSize, sth1.RootHash, sth2.RootHash, p); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("tampered proof: got %v", err)
	}
}

func TestVerifyConsistencyFromState(t *testing.T) {
	ref := testonly.New(rfc6962.DefaultHasher)
	s := NewState()
	for i := 0; i < 100; i++ {
		leaf := []byte(fmt.Sprintf("e%d", i))
		ref.AppendData(leaf)
		if i < 37 {
			s.Append(LeafHash(leaf))
		}
	}
	nodes, err := ref.ConsistencyProof(37, 100)
	if err != nil {
		t.Fatal(err)
	}
	p := make([][32]byte, len(nodes))
	for i, n := range nodes {
		copy(p[i][:], n)
	}
	var signedRoot [32]byte
	copy(signedRoot[:], ref.Hash())
	ours, _ := s.Root()
	if err := VerifyConsistency(37, 100, ours, signedRoot, p); err != nil {
		t.Fatalf("our prefix should be consistent: %v", err)
	}
	ours[5] ^= 1
	if err := VerifyConsistency(37, 100, ours, signedRoot, p); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("altered prefix must be inconsistent, got %v", err)
	}
}
