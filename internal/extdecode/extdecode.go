// Package extdecode decodes the certificate extensions behind research area
// D (amendment A7): certificate policies, extended key usage, key usage,
// basic constraints, authority information access, CRL distribution points
// and the embedded SCT list. Each decoder takes the raw extnValue content the
// extractor keeps, and returns the whole extension or a stable code: an
// extension is never half-decoded.
package extdecode

import (
	"crypto/x509"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/4rji/ctvault/internal/extract"
)

// Version names the decoding rules; it is the D tables' ctvault.decoder,
// and any change to what a decoder returns bumps it, with the version of
// every table it feeds (amendment A7 §3).
const Version = "ctvault-extdecode/1"

// The extensions D decodes.
const (
	OIDPolicies         = "2.5.29.32"
	OIDEKU              = "2.5.29.37"
	OIDKeyUsage         = "2.5.29.15"
	OIDBasicConstraints = "2.5.29.19"
	OIDAIA              = "1.3.6.1.5.5.7.1.1"
	OIDCRLDPs           = "2.5.29.31"
	OIDSCTList          = "1.3.6.1.4.1.11129.2.4.2"
)

// Code is a stable decoding error code, stored in cert_extensions.decode_error.
type Code string

const (
	PoliciesMalformed         Code = "ext_policies_malformed"
	EKUMalformed              Code = "ext_eku_malformed"
	KeyUsageMalformed         Code = "ext_key_usage_malformed"
	BasicConstraintsMalformed Code = "ext_basic_constraints_malformed"
	AIAMalformed              Code = "ext_aia_malformed"
	CRLDPsMalformed           Code = "ext_crl_dps_malformed"
	SCTListMalformed          Code = "ext_sct_list_malformed"
	Duplicate                 Code = "ext_duplicate"
)

// Codes lists every code in a fixed order, for the frozen registry and
// explain-error.
var Codes = []Code{PoliciesMalformed, EKUMalformed, KeyUsageMalformed, BasicConstraintsMalformed,
	AIAMalformed, CRLDPsMalformed, SCTListMalformed, Duplicate}

var explanations = map[Code]string{
	PoliciesMalformed:         "The certificatePolicies extension could not be decoded whole; cert_policies has no rows for it.",
	EKUMalformed:              "The extKeyUsage extension could not be decoded whole; cert_ekus has no rows for it.",
	KeyUsageMalformed:         "The keyUsage extension is not a well-formed BIT STRING; cert_key_usage leaves its bits null.",
	BasicConstraintsMalformed: "The basicConstraints extension could not be decoded whole (for example a negative or oversized pathLenConstraint); cert_key_usage leaves is_ca null.",
	AIAMalformed:              "The authorityInfoAccess extension could not be decoded whole; cert_aia has no rows for it.",
	CRLDPsMalformed:           "The cRLDistributionPoints extension could not be decoded whole; cert_crl_dps has no rows for it.",
	SCTListMalformed:          "The embedded SCT list's framing could not be decoded; cert_scts has no rows for it.",
	Duplicate:                 "A second copy of an extension that D decodes (RFC 5280 forbids repeats); only the first copy is decoded.",
}

// Explain returns the code's explanation for explain-error, or "".
func (c Code) Explain() string { return explanations[c] }

// Decoded reports whether D decodes extensions with oid.
func Decoded(oid string) bool {
	switch oid {
	case OIDPolicies, OIDEKU, OIDKeyUsage, OIDBasicConstraints, OIDAIA, OIDCRLDPs, OIDSCTList:
		return true
	}
	return false
}

// Check returns the code an extension gets from its decoder: "" when it
// decodes, or when D does not decode oid.
func Check(oid string, v []byte) Code {
	var c Code
	switch oid {
	case OIDPolicies:
		_, c = Policies(v)
	case OIDEKU:
		_, c = EKUs(v)
	case OIDKeyUsage:
		_, c = KeyUsage(v)
	case OIDBasicConstraints:
		_, c = BasicConstraints(v)
	case OIDAIA:
		_, c = AIA(v)
	case OIDCRLDPs:
		_, c = CRLDPs(v)
	case OIDSCTList:
		_, c = SCTs(v)
	}
	return c
}

// readOID reads an OBJECT IDENTIFIER as crypto/x509 does, arcs of any size
// included, and returns it dotted.
func readOID(s *cryptobyte.String) (string, bool) {
	var body cryptobyte.String
	if !s.ReadASN1(&body, cbasn1.OBJECT_IDENTIFIER) {
		return "", false
	}
	var o x509.OID
	if err := o.UnmarshalBinary(body); err != nil {
		return "", false
	}
	return o.String(), true
}

// generalName reports whether tag is one of GeneralName's choices, [0] to
// [8]; uniformResourceIdentifier [6] must be primitive (an IA5String).
func generalName(tag cbasn1.Tag) bool {
	uri := cbasn1.Tag(6).ContextSpecific()
	if tag == uri.Constructed() {
		return false
	}
	for n := 0; n <= 8; n++ {
		if tag == cbasn1.Tag(n).ContextSpecific() || tag == cbasn1.Tag(n).ContextSpecific().Constructed() {
			return true
		}
	}
	return false
}

var uriTag = cbasn1.Tag(6).ContextSpecific()

// display renders certificate text as the extractor does.
func display(b []byte) string { return extract.Display(b) }
