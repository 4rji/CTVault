package extdecode

import (
	"encoding/asn1"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Policy is one PolicyInformation.
type Policy struct {
	OID        string
	Validation string // dv, ov, iv or ev for the CA/B Forum OIDs, else ""
	CPSURI     string // the first id-qt-cps qualifier, display-escaped
	HasCPS     bool
	Qualifiers int
}

var validation = map[string]string{
	"2.23.140.1.2.1": "dv", "2.23.140.1.2.2": "ov", "2.23.140.1.2.3": "iv", "2.23.140.1.1": "ev",
}

const idQtCPS = "1.3.6.1.5.5.7.2.1"

// Policies decodes certificatePolicies (RFC 5280 §4.2.1.4). Every
// qualifier must be well-formed; a CPS qualifier must be an IA5String.
func Policies(v []byte) ([]Policy, Code) {
	s := cryptobyte.String(v)
	var list cryptobyte.String
	if !s.ReadASN1(&list, cbasn1.SEQUENCE) || !s.Empty() {
		return nil, PoliciesMalformed
	}
	var out []Policy
	for !list.Empty() {
		var pi cryptobyte.String
		if !list.ReadASN1(&pi, cbasn1.SEQUENCE) {
			return nil, PoliciesMalformed
		}
		id, ok := readOID(&pi)
		if !ok {
			return nil, PoliciesMalformed
		}
		p := Policy{OID: id, Validation: validation[id]}
		if !pi.Empty() {
			var quals cryptobyte.String
			if !pi.ReadASN1(&quals, cbasn1.SEQUENCE) || !pi.Empty() {
				return nil, PoliciesMalformed
			}
			for !quals.Empty() {
				var q cryptobyte.String
				if !quals.ReadASN1(&q, cbasn1.SEQUENCE) {
					return nil, PoliciesMalformed
				}
				qid, ok := readOID(&q)
				if !ok {
					return nil, PoliciesMalformed
				}
				var body cryptobyte.String
				if qid == idQtCPS {
					if !q.ReadASN1(&body, cbasn1.IA5String) {
						return nil, PoliciesMalformed
					}
					if !p.HasCPS {
						p.CPSURI, p.HasCPS = display(body), true
					}
				} else {
					var tag cbasn1.Tag
					if !q.ReadAnyASN1(&body, &tag) {
						return nil, PoliciesMalformed
					}
				}
				if !q.Empty() {
					return nil, PoliciesMalformed
				}
				p.Qualifiers++
			}
		}
		out = append(out, p)
	}
	return out, ""
}

// EKU is one KeyPurposeId.
type EKU struct {
	OID  string
	Name string // a short name for the common purposes, else ""
}

var ekuNames = map[string]string{
	"1.3.6.1.5.5.7.3.1": "server_auth", "1.3.6.1.5.5.7.3.2": "client_auth", "1.3.6.1.5.5.7.3.3": "code_signing",
	"1.3.6.1.5.5.7.3.4": "email_protection", "1.3.6.1.5.5.7.3.8": "time_stamping", "1.3.6.1.5.5.7.3.9": "ocsp_signing",
	"2.5.29.37.0": "any", "1.3.6.1.4.1.11129.2.4.4": "precert_signing",
}

// EKUs decodes extKeyUsage (RFC 5280 §4.2.1.12).
func EKUs(v []byte) ([]EKU, Code) {
	s := cryptobyte.String(v)
	var list cryptobyte.String
	if !s.ReadASN1(&list, cbasn1.SEQUENCE) || !s.Empty() {
		return nil, EKUMalformed
	}
	var out []EKU
	for !list.Empty() {
		id, ok := readOID(&list)
		if !ok {
			return nil, EKUMalformed
		}
		out = append(out, EKU{OID: id, Name: ekuNames[id]})
	}
	return out, ""
}

// KeyUsage decodes keyUsage (RFC 5280 §4.2.1.3): bit i of the result is the
// named bit i, digitalSignature (0) to decipherOnly (8), as crypto/x509
// numbers them. Trailing zero bits are accepted; bits past decipherOnly
// have no meaning and are not reported.
func KeyUsage(v []byte) (uint16, Code) {
	s := cryptobyte.String(v)
	var bits asn1.BitString
	if !s.ReadASN1BitString(&bits) || !s.Empty() {
		return 0, KeyUsageMalformed
	}
	var u uint16
	for i := 0; i < 9; i++ {
		if bits.At(i) != 0 {
			u |= 1 << i
		}
	}
	return u, ""
}

// Constraints is a decoded basicConstraints.
type Constraints struct {
	IsCA    bool
	PathLen int // -1 when pathLenConstraint is absent
}

// BasicConstraints decodes basicConstraints (RFC 5280 §4.2.1.9). An
// explicitly encoded cA FALSE is accepted; pathLenConstraint must be in
// 0..65535.
func BasicConstraints(v []byte) (Constraints, Code) {
	s := cryptobyte.String(v)
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !s.Empty() {
		return Constraints{}, BasicConstraintsMalformed
	}
	c := Constraints{PathLen: -1}
	if seq.PeekASN1Tag(cbasn1.BOOLEAN) && !seq.ReadASN1Boolean(&c.IsCA) {
		return Constraints{}, BasicConstraintsMalformed
	}
	if !seq.Empty() {
		var n int64
		if !seq.ReadASN1Integer(&n) || n < 0 || n > 65535 || !seq.Empty() {
			return Constraints{}, BasicConstraintsMalformed
		}
		c.PathLen = int(n)
	}
	return c, ""
}

// Access is one AccessDescription.
type Access struct {
	Method string // ocsp, ca_issuers, or the dotted OID
	URI    string // display-escaped, when the location is a URI
	HasURI bool
}

var methods = map[string]string{"1.3.6.1.5.5.7.48.1": "ocsp", "1.3.6.1.5.5.7.48.2": "ca_issuers"}

// AIA decodes authorityInfoAccess (RFC 5280 §4.2.2.1).
func AIA(v []byte) ([]Access, Code) {
	s := cryptobyte.String(v)
	var list cryptobyte.String
	if !s.ReadASN1(&list, cbasn1.SEQUENCE) || !s.Empty() {
		return nil, AIAMalformed
	}
	var out []Access
	for !list.Empty() {
		var ad cryptobyte.String
		if !list.ReadASN1(&ad, cbasn1.SEQUENCE) {
			return nil, AIAMalformed
		}
		m, ok := readOID(&ad)
		if !ok {
			return nil, AIAMalformed
		}
		var loc cryptobyte.String
		var tag cbasn1.Tag
		if !ad.ReadAnyASN1(&loc, &tag) || !ad.Empty() || !generalName(tag) {
			return nil, AIAMalformed
		}
		a := Access{Method: m}
		if name, ok := methods[m]; ok {
			a.Method = name
		}
		if tag == uriTag {
			a.URI, a.HasURI = display(loc), true
		}
		out = append(out, a)
	}
	return out, ""
}

// DistributionPoint is one DistributionPoint.
type DistributionPoint struct {
	URIs         []string // the fullName's URIs, display-escaped
	HasReasons   bool
	HasCRLIssuer bool
}

// CRLDPs decodes cRLDistributionPoints (RFC 5280 §4.2.1.13).
func CRLDPs(v []byte) ([]DistributionPoint, Code) {
	s := cryptobyte.String(v)
	var list cryptobyte.String
	if !s.ReadASN1(&list, cbasn1.SEQUENCE) || !s.Empty() {
		return nil, CRLDPsMalformed
	}
	var out []DistributionPoint
	for !list.Empty() {
		var dp cryptobyte.String
		if !list.ReadASN1(&dp, cbasn1.SEQUENCE) {
			return nil, CRLDPsMalformed
		}
		var d DistributionPoint
		var name, reasons, issuer cryptobyte.String
		var hasName bool
		if !dp.ReadOptionalASN1(&name, &hasName, cbasn1.Tag(0).Constructed().ContextSpecific()) {
			return nil, CRLDPsMalformed
		}
		if hasName {
			var inner cryptobyte.String
			var tag cbasn1.Tag
			if !name.ReadAnyASN1(&inner, &tag) || !name.Empty() {
				return nil, CRLDPsMalformed
			}
			switch tag {
			case cbasn1.Tag(0).Constructed().ContextSpecific(): // fullName: GeneralNames
				for !inner.Empty() {
					var gn cryptobyte.String
					var gt cbasn1.Tag
					if !inner.ReadAnyASN1(&gn, &gt) || !generalName(gt) {
						return nil, CRLDPsMalformed
					}
					if gt == uriTag {
						d.URIs = append(d.URIs, display(gn))
					}
				}
			case cbasn1.Tag(1).Constructed().ContextSpecific(): // nameRelativeToCRLIssuer: not decoded
			default:
				return nil, CRLDPsMalformed
			}
		}
		if !dp.ReadOptionalASN1(&reasons, &d.HasReasons, cbasn1.Tag(1).ContextSpecific()) ||
			!dp.ReadOptionalASN1(&issuer, &d.HasCRLIssuer, cbasn1.Tag(2).Constructed().ContextSpecific()) || !dp.Empty() {
			return nil, CRLDPsMalformed
		}
		out = append(out, d)
	}
	return out, ""
}
