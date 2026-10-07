package extdecode

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

// sctBytes encodes one v1 SCT as RFC 6962 §3.2 serializes it.
func sctBytes(logID byte, ts uint64, ext []byte, sig []byte) []byte {
	b := []byte{0}
	b = append(b, bytes.Repeat([]byte{logID}, 32)...)
	b = binary.BigEndian.AppendUint64(b, ts)
	b = binary.BigEndian.AppendUint16(b, uint16(len(ext)))
	b = append(b, ext...)
	b = append(b, 4, 3)
	b = binary.BigEndian.AppendUint16(b, uint16(len(sig)))
	return append(b, sig...)
}

// sctInner is the TLS SignedCertificateTimestampList of scts.
func sctInner(scts ...[]byte) []byte {
	var list []byte
	for _, s := range scts {
		list = binary.BigEndian.AppendUint16(list, uint16(len(s)))
		list = append(list, s...)
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(list))), list...)
}

// wrap is the extension value: an OCTET STRING holding inner.
func wrap(inner []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1OctetString(inner)
	return b.BytesOrPanic()
}

func sctList(scts ...[]byte) []byte { return wrap(sctInner(scts...)) }

// TestSCTs: v1 SCTs decode in order; another version keeps only its
// version; the framing must be exact (amendment A7 §2).
func TestSCTs(t *testing.T) {
	a := sctBytes(0xaa, 1791346973252, nil, bytes.Repeat([]byte{1}, 70))
	b := sctBytes(0xbb, 1791346973999, []byte{9, 9}, bytes.Repeat([]byte{2}, 71))
	v2 := append([]byte{1}, bytes.Repeat([]byte{7}, 50)...)
	ss, code := SCTs(sctList(a, b, v2))
	if code != "" || len(ss) != 3 || !ss[0].V1 || ss[0].LogID != [32]byte(bytes.Repeat([]byte{0xaa}, 32)) || ss[0].Timestamp != 1791346973252 ||
		ss[0].HashAlg != 4 || ss[0].SigAlg != 3 || ss[1].LogID[0] != 0xbb || ss[2].V1 || ss[2].Version != 1 {
		t.Fatalf("scts %+v %q", ss, code)
	}
	if ss, code := SCTs(sctList()); code != "" || len(ss) != 0 {
		t.Fatalf("an empty list: %+v %q", ss, code)
	}
	for name, v := range map[string][]byte{
		"not an OCTET STRING":    append([]byte{0x30}, sctList(a)[1:]...),
		"list length too long":   func() []byte { x := sctInner(a); x[1]++; return wrap(x) }(),
		"SCT cut short":          sctList(a[:40]),
		"bytes after an SCT":     sctList(append(append([]byte(nil), a...), 0)),
		"signature length wrong": sctList(func() []byte { x := append([]byte(nil), a...); x[45]++; return x }()),
		"bytes after the list":   append(sctList(a), 0),
		"zero-length SCT":        sctList([]byte{}),
	} {
		if _, code := SCTs(v); code != SCTListMalformed {
			t.Errorf("%s: %q", name, code)
		}
	}
}

// TestMalformed: anything a decoder cannot read whole is its code, with no
// partial result (amendment A7 §2).
func TestMalformed(t *testing.T) {
	seq := func(b ...byte) []byte { return append([]byte{0x30, byte(len(b))}, b...) }
	oidDV := []byte{0x06, 0x06, 0x67, 0x81, 0x0c, 0x01, 0x02, 0x01} // 2.23.140.1.2.1
	cases := []struct {
		name string
		f    func([]byte) Code
		v    []byte
		want Code
	}{
		{"policies: not a SEQUENCE", polCode, []byte{0x31, 0x00}, PoliciesMalformed},
		{"policies: cut", polCode, seq(oidDV...)[:5], PoliciesMalformed},
		{"policies: bytes after", polCode, append(seq(seq(oidDV...)...), 0), PoliciesMalformed},
		{"policies: an element that is not a SEQUENCE", polCode, seq(oidDV...), PoliciesMalformed},
		{"policies: a CPS that is not IA5String", polCode, seq(seq(append(oidDV, seq(seq(append([]byte{0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01}, 0x0c, 0x01, 'x')...)...)...)...)...), PoliciesMalformed},
		{"eku: an element that is not an OID", ekuCode, seq(0x02, 0x01, 0x01), EKUMalformed},
		{"eku: bytes after", ekuCode, append(seq(oidDV...), 0), EKUMalformed},
		{"key usage: not a BIT STRING", kuCode, []byte{0x04, 0x01, 0x80}, KeyUsageMalformed},
		{"key usage: unused bits not zero", kuCode, []byte{0x03, 0x02, 0x07, 0x81}, KeyUsageMalformed},
		{"key usage: bytes after", kuCode, []byte{0x03, 0x02, 0x07, 0x80, 0x00}, KeyUsageMalformed},
		{"basic constraints: not a SEQUENCE", bcCode, []byte{0x01, 0x01, 0xff}, BasicConstraintsMalformed},
		{"basic constraints: a negative pathLen", bcCode, seq(0x01, 0x01, 0xff, 0x02, 0x01, 0xff), BasicConstraintsMalformed},
		{"basic constraints: a pathLen over 65535", bcCode, seq(0x01, 0x01, 0xff, 0x02, 0x03, 0x01, 0x00, 0x00), BasicConstraintsMalformed},
		{"basic constraints: a BER TRUE", bcCode, seq(0x01, 0x01, 0x01), BasicConstraintsMalformed},
		{"basic constraints: extra field", bcCode, seq(0x01, 0x01, 0xff, 0x02, 0x01, 0x01, 0x05, 0x00), BasicConstraintsMalformed},
		{"aia: a description without a location", aiaCode, seq(seq(oidDV...)...), AIAMalformed},
		{"aia: a URI that is constructed", aiaCode, seq(seq(append(append([]byte(nil), oidDV...), 0xa6, 0x00)...)...), AIAMalformed},
		{"crl dps: a point that is not a SEQUENCE", crlCode, seq(0x04, 0x00), CRLDPsMalformed},
		{"crl dps: fullName not constructed", crlCode, seq(seq(0xa0, 0x02, 0x80, 0x00)...), CRLDPsMalformed},
		{"crl dps: bytes after", crlCode, append(seq(seq()...), 0), CRLDPsMalformed},
	}
	for _, c := range cases {
		if got := c.f(c.v); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	// What is malformed yields nothing, never part of a list.
	if ps, code := Policies(append(seq(seq(oidDV...)...), 0)); ps != nil || code == "" {
		t.Errorf("a partial result: %+v", ps)
	}
}

func polCode(v []byte) Code { _, c := Policies(v); return c }
func ekuCode(v []byte) Code { _, c := EKUs(v); return c }
func kuCode(v []byte) Code  { _, c := KeyUsage(v); return c }
func bcCode(v []byte) Code  { _, c := BasicConstraints(v); return c }
func aiaCode(v []byte) Code { _, c := AIA(v); return c }
func crlCode(v []byte) Code { _, c := CRLDPs(v); return c }

// TestCheck: the code an extension of each decoded type gets, and none for
// types D does not decode.
func TestCheck(t *testing.T) {
	if Check(OIDKeyUsage, []byte{0x04}) != KeyUsageMalformed || Check("2.5.29.17", []byte{0x00}) != "" || Check(OIDKeyUsage, []byte{0x03, 0x02, 0x07, 0x80}) != "" {
		t.Fatal("Check")
	}
	for _, c := range Codes {
		if c.Explain() == "" {
			t.Errorf("%s has no explanation", c)
		}
	}
	if len(Codes) != 8 || Version != "ctvault-extdecode/1" {
		t.Fatalf("%d codes, version %s", len(Codes), Version)
	}
}
