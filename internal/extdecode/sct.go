package extdecode

import (
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// SCT is one embedded Signed Certificate Timestamp (RFC 6962 §3.2-3.3).
// Only a v1 SCT's fields are decoded; another version keeps its version.
type SCT struct {
	Version   int
	V1        bool
	LogID     [32]byte
	Timestamp uint64 // ms
	HashAlg   uint8
	SigAlg    uint8
}

// SCTs decodes the embedded SCT list: an OCTET STRING holding a TLS
// SignedCertificateTimestampList. The framing must be exact.
func SCTs(v []byte) ([]SCT, Code) {
	s := cryptobyte.String(v)
	var inner, list cryptobyte.String
	if !s.ReadASN1(&inner, cbasn1.OCTET_STRING) || !s.Empty() ||
		!inner.ReadUint16LengthPrefixed(&list) || !inner.Empty() {
		return nil, SCTListMalformed
	}
	var out []SCT
	for !list.Empty() {
		var b cryptobyte.String
		var ver uint8
		if !list.ReadUint16LengthPrefixed(&b) || !b.ReadUint8(&ver) {
			return nil, SCTListMalformed
		}
		if ver != 0 {
			out = append(out, SCT{Version: int(ver)})
			continue
		}
		t := SCT{V1: true}
		var id []byte
		var ext, sig cryptobyte.String
		if !b.ReadBytes(&id, 32) || !b.ReadUint64(&t.Timestamp) || !b.ReadUint16LengthPrefixed(&ext) ||
			!b.ReadUint8(&t.HashAlg) || !b.ReadUint8(&t.SigAlg) || !b.ReadUint16LengthPrefixed(&sig) || !b.Empty() {
			return nil, SCTListMalformed
		}
		copy(t.LogID[:], id)
		out = append(out, t)
	}
	return out, ""
}
