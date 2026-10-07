package leaf_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/merkle"
)

func generator(t *testing.T) *ctlogtest.Generator {
	t.Helper()
	g, err := ctlogtest.NewGenerator()
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func pair(t *testing.T, g *ctlogtest.Generator, viaSigner bool) (pre, fin ctlogtest.Entry) {
	t.Helper()
	var err error
	if viaSigner {
		pre, fin, err = g.PairViaSigner("signer.example.test", 1790000000000)
	} else {
		pre, fin, err = g.Pair("a.example.test", 1790000000000)
	}
	if err != nil {
		t.Fatal(err)
	}
	return pre, fin
}

func TestCodesAreStable(t *testing.T) {
	want := []string{"leaf_bad_version", "leaf_bad_leaf_type", "leaf_unknown_entry_type", "leaf_truncated",
		"leaf_trailing_bytes", "extra_truncated", "extra_trailing_bytes", "chain_cert_empty",
		"chain_issuer_missing", "chain_issuer_ambiguous", "issuer_key_hash_mismatch",
		"precert_tbs_mismatch", "issuance_key_unavailable", "leaf_index_mismatch"}
	if len(leaf.Codes) != len(want) {
		t.Fatalf("%d codes, want %d", len(leaf.Codes), len(want))
	}
	for i, c := range leaf.Codes {
		if string(c) != want[i] {
			t.Errorf("code %d = %q, want %q (codes are stored in Parquet and must never change)", i, c, want[i])
		}
	}
	if leaf.TypeX509.String() != "x509" || leaf.TypePrecert.String() != "precert" || leaf.TypeUnknown.String() != "unknown" {
		t.Fatal("entry_type strings must be x509, precert and unknown")
	}
}

func TestDecodeGeneratedPair(t *testing.T) {
	g := generator(t)
	for name, viaSigner := range map[string]bool{"CA-issued": false, "via precert signer": true} {
		pre, fin := pair(t, g, viaSigner)
		p := leaf.Decode(pre.LeafInput, pre.ExtraData)
		f := leaf.Decode(fin.LeafInput, fin.ExtraData)
		if p.Code != leaf.OK || f.Code != leaf.OK {
			t.Fatalf("%s: codes %q / %q, want none", name, p.Code, f.Code)
		}
		if p.Type != leaf.TypePrecert || f.Type != leaf.TypeX509 || p.Timestamp != pre.Timestamp || f.Timestamp != fin.Timestamp {
			t.Fatalf("%s: types or timestamps wrong: %+v %+v", name, p, f)
		}
		if !bytes.Equal(p.CertDER, pre.CertDER) || !bytes.Equal(p.PrecertTBS, pre.PrecertTBS) || !bytes.Equal(f.CertDER, fin.CertDER) {
			t.Fatalf("%s: certificate bytes must be exactly as logged", name)
		}
		if !p.HasIssuerKeyHash || p.IssuerKeyHash != pre.IssuerKeyHash || f.HasIssuerKeyHash {
			t.Fatalf("%s: issuer_key_hash is set for precerts only", name)
		}
		if p.LeafHash != merkle.LeafHash(pre.LeafInput) || f.LeafHash != merkle.LeafHash(fin.LeafInput) {
			t.Fatalf("%s: leaf hash must be RFC 6962 over the exact bytes", name)
		}
		pk, ok1 := p.IssuanceKey()
		fk, ok2 := f.IssuanceKey()
		if !ok1 || !ok2 || pk != fk || p.IssuanceDigest != f.IssuanceDigest {
			t.Fatalf("%s: precert and final cert must share the issuance digest", name)
		}
		if p.IssuanceDigest != sha256.Sum256(pre.PrecertTBS) {
			t.Fatalf("%s: a precert's digest is SHA-256 of the log's TBS", name)
		}
		if !bytes.Equal(f.Chain[0], g.CADER()) {
			t.Fatalf("%s: chain must be decoded in order", name)
		}
	}
}

// leafBytes builds a MerkleTreeLeaf by hand so each structural fault can be
// placed exactly.
func leafBytes(version, leafType byte, entryType uint16, signed []byte, exts []byte) []byte {
	b := []byte{version, leafType}
	b = binary.BigEndian.AppendUint64(b, 1790000000000)
	b = binary.BigEndian.AppendUint16(b, entryType)
	if entryType == 1 {
		b = append(b, make([]byte, 32)...)
	}
	b = append(b, byte(len(signed)>>16), byte(len(signed)>>8), byte(len(signed)))
	b = append(b, signed...)
	return append(b, exts...)
}

func TestLeafStructureCodes(t *testing.T) {
	cert := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	noExt := []byte{0, 0}
	good := leafBytes(0, 0, 0, cert, noExt)
	for name, tc := range map[string]struct {
		leaf   []byte
		want   leaf.Code
		wantTS bool
	}{
		"empty":                  {nil, leaf.Truncated, false},
		"version 1":              {leafBytes(1, 0, 0, cert, noExt), leaf.BadVersion, false},
		"leaf type 1":            {leafBytes(0, 1, 0, cert, noExt), leaf.BadLeafType, false},
		"entry type 2":           {leafBytes(0, 0, 2, cert, noExt), leaf.UnknownEntryType, true},
		"cert cut short":         {good[:14], leaf.Truncated, true},
		"no extensions field":    {good[:len(good)-2], leaf.Truncated, true},
		"trailing byte":          {append(append([]byte(nil), good...), 0), leaf.TrailingBytes, true},
		"zero-length cert":       {leafBytes(0, 0, 0, nil, noExt), leaf.Truncated, true},
		"precert hash cut short": {leafBytes(0, 0, 1, cert, noExt)[:20], leaf.Truncated, true},
		"malformed from fakelog": {ctlogtest.MalformedEntry(1).LeafInput, leaf.BadVersion, false},
	} {
		e := leaf.Decode(tc.leaf, ctlogtest.Chain())
		if e.Code != tc.want || !e.Code.LeafStructure() {
			t.Errorf("%s: code %q, want %q", name, e.Code, tc.want)
		}
		if e.CertDER != nil || e.PrecertTBS != nil || e.Chain != nil || e.HasIssuanceDigest {
			t.Errorf("%s: no field may be kept from an uninterpretable leaf: %+v", name, e)
		}
		if e.LeafHash != merkle.LeafHash(tc.leaf) {
			t.Errorf("%s: the leaf hash is always computed from the exact bytes", name)
		}
		if (e.Timestamp != 0) != tc.wantTS {
			t.Errorf("%s: timestamp %d; it is kept only once version and leaf type are known", name, e.Timestamp)
		}
	}
	if e := leaf.Decode(good, ctlogtest.Chain()); e.Code.LeafStructure() {
		t.Fatalf("control: a well-formed leaf decodes, got %q", e.Code)
	}
}

func TestExtraDataCodes(t *testing.T) {
	g := generator(t)
	pre, fin := pair(t, g, false)
	trunc := func(b []byte) []byte { return b[:len(b)-1] }
	trailing := func(b []byte) []byte { return append(append([]byte(nil), b...), 0) }
	for name, tc := range map[string]struct {
		entry    ctlogtest.Entry
		extra    []byte
		want     leaf.Code
		keepCert bool // x509 certs come from leaf_input, so they survive
	}{
		"x509 chain cut short":    {fin, trunc(fin.ExtraData), leaf.ExtraTruncated, true},
		"x509 trailing byte":      {fin, trailing(fin.ExtraData), leaf.ExtraTrailingBytes, true},
		"x509 empty chain cert":   {fin, ctlogtest.Chain(g.CADER(), nil), leaf.ChainCertEmpty, true},
		"precert cut short":       {pre, trunc(pre.ExtraData), leaf.ExtraTruncated, false},
		"precert trailing byte":   {pre, trailing(pre.ExtraData), leaf.ExtraTrailingBytes, false},
		"precert empty precert":   {pre, ctlogtest.PrecertExtraData(nil, g.CADER()), leaf.ChainCertEmpty, false},
		"precert no chain vector": {pre, pre.ExtraData[:3+len(pre.CertDER)], leaf.ExtraTruncated, false},
	} {
		e := leaf.Decode(tc.entry.LeafInput, tc.extra)
		if e.Code != tc.want || e.Code.LeafStructure() {
			t.Errorf("%s: code %q, want %q", name, e.Code, tc.want)
		}
		if (e.CertDER != nil) != tc.keepCert || e.Chain != nil {
			t.Errorf("%s: cert kept %v (want %v), chain %v (want nil)", name, e.CertDER != nil, tc.keepCert, e.Chain)
		}
		if !e.HasIssuanceDigest {
			t.Errorf("%s: the issuance digest comes from leaf_input and survives extra_data faults", name)
		}
	}
	if e := leaf.Decode(fin.LeafInput, ctlogtest.Chain()); e.Code != leaf.OK || e.Chain == nil || len(e.Chain) != 0 {
		t.Fatalf("an empty chain is valid for x509 entries: %q %v", e.Code, e.Chain)
	}
}

// TestCheckLeafIndex: static-ct-api's leaf_index extension must be present
// once and equal the entry's position; anything else is leaf_index_mismatch,
// and an earlier code is kept (amendment A6 §3.2).
func TestCheckLeafIndex(t *testing.T) {
	ext := func(parts ...[]byte) []byte {
		var b []byte
		for _, p := range parts {
			b = append(b, p...)
		}
		return b
	}
	idx := func(v uint64) []byte {
		return []byte{0, 0, 5, byte(v >> 32), byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	}
	other := []byte{7, 0, 1, 9}
	for name, c := range map[string]struct {
		exts []byte
		want leaf.Code
	}{
		"right":               {idx(1587930800), leaf.OK},
		"right, with another": {ext(other, idx(1587930800)), leaf.OK},
		"missing":             {nil, leaf.LeafIndexMismatch},
		"only another":        {other, leaf.LeafIndexMismatch},
		"wrong":               {idx(1587930801), leaf.LeafIndexMismatch},
		"twice":               {ext(idx(1587930800), idx(1587930800)), leaf.LeafIndexMismatch},
		"another type twice":  {ext(other, other, idx(1587930800)), leaf.LeafIndexMismatch},
		"four bytes":          {[]byte{0, 0, 4, 0x5e, 0xa5, 0x2b, 0xb0}, leaf.LeafIndexMismatch},
		"truncated":           {idx(1587930800)[:6], leaf.LeafIndexMismatch},
	} {
		e := leaf.Entry{}
		leaf.CheckLeafIndex(&e, c.exts, 1587930800)
		if e.Code != c.want {
			t.Errorf("%s: %q, want %q", name, e.Code, c.want)
		}
	}
	e := leaf.Entry{Code: leaf.PrecertTBSMismatch}
	leaf.CheckLeafIndex(&e, nil, 0)
	if e.Code != leaf.PrecertTBSMismatch {
		t.Errorf("an earlier code was replaced by %q", e.Code)
	}
	if leaf.LeafIndexMismatch.Explain() == "" || leaf.LeafIndexMismatch.LeafStructure() {
		t.Error("leaf_index_mismatch needs an explanation and keeps the certificate")
	}
}
