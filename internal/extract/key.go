package extract

import (
	"encoding/asn1"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Key is what certs records about the subject public key.
type Key struct {
	AlgorithmOID string // dotted; "" when the SPKI is unreadable
	Algorithm    string // rsa, ecdsa, ed25519, ed448, dsa or other
	Bits         int    // 0 when unknown
	Curve        string // named curve, or the curve's dotted OID; "" otherwise
}

// bitLen is the bit length of an unsigned big-endian integer.
func bitLen(b []byte) int {
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	if len(b) == 0 {
		return 0
	}
	n := 8 * (len(b) - 1)
	for x := b[0]; x != 0; x >>= 1 {
		n++
	}
	return n
}

// parseKey reads a SubjectPublicKeyInfo element.
func parseKey(el []byte) (Key, []Code) {
	s := cryptobyte.String(el)
	var body, alg, params cryptobyte.String
	var oid asn1.ObjectIdentifier
	var bits asn1.BitString
	if !s.ReadASN1(&body, cbasn1.SEQUENCE) || !s.Empty() || !body.ReadASN1(&alg, cbasn1.SEQUENCE) ||
		!alg.ReadASN1ObjectIdentifier(&oid) || !body.ReadASN1BitString(&bits) || !body.Empty() {
		return Key{}, []Code{SPKIUnreadable}
	}
	params = alg
	k := Key{AlgorithmOID: oid.String()}
	bad := []Code{KeyUnreadable}
	key := cryptobyte.String(bits.RightAlign())
	switch k.AlgorithmOID {
	case oidRSA, oidRSAPSS:
		k.Algorithm = "rsa"
		var rsaKey, n cryptobyte.String
		if !key.ReadASN1(&rsaKey, cbasn1.SEQUENCE) || !rsaKey.ReadASN1(&n, cbasn1.INTEGER) || len(n) == 0 || n[0]&0x80 != 0 {
			return k, bad
		}
		k.Bits = bitLen(n)
	case oidEC:
		k.Algorithm = "ecdsa"
		if len(key) > 1 {
			switch key[0] {
			case 0x04:
				k.Bits = (len(key) - 1) / 2 * 8
			case 0x02, 0x03:
				k.Bits = (len(key) - 1) * 8
			}
		}
		var curve asn1.ObjectIdentifier
		if !params.ReadASN1ObjectIdentifier(&curve) || !params.Empty() {
			return k, bad
		}
		if c, ok := namedCurves[curve.String()]; ok {
			k.Curve, k.Bits = c.name, c.bits
		} else {
			k.Curve = curve.String()
		}
	case oidEd25519, oidEd448:
		k.Algorithm, k.Bits = "ed25519", 256
		size := 32
		if k.AlgorithmOID == oidEd448 {
			k.Algorithm, k.Bits, size = "ed448", 456, 57
		}
		if len(key) != size {
			k.Bits = 0
			return k, bad
		}
	case oidDSA:
		k.Algorithm = "dsa"
		if params.Empty() {
			return k, nil // parameters inherited from the issuer (RFC 3279 §2.3.2)
		}
		var dss, p cryptobyte.String
		if !params.ReadASN1(&dss, cbasn1.SEQUENCE) || !dss.ReadASN1(&p, cbasn1.INTEGER) {
			return k, bad
		}
		k.Bits = bitLen(p)
	default:
		k.Algorithm = "other"
	}
	return k, nil
}
