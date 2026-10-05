// Package extract reads the fields of an X.509 certificate leniently (spec
// §7.1, amendment A2 §3): each field is read on its own with cryptobyte, a
// malformed field adds a stable error code and extraction goes on, and no
// certificate is ever dropped. The result depends only on the DER bytes.
package extract

// Code is a stable parse error code, stored in certs.parse_errors. Codes are
// only ever added: a published code is never renamed or removed.
type Code string

const (
	// The certificate's structure.
	CertUnreadable      Code = "cert_unreadable"
	CertTrailingData    Code = "cert_trailing_data"
	SignatureUnreadable Code = "signature_unreadable"
	TBSUnreadable       Code = "tbs_unreadable"
	TBSExtraFields      Code = "tbs_extra_fields"
	VersionBad          Code = "version_bad"

	// Serial number.
	SerialUnreadable Code = "serial_unreadable"
	SerialNegative   Code = "serial_negative"
	SerialZero       Code = "serial_zero"
	SerialTooLong    Code = "serial_too_long"
	SerialNotMinimal Code = "serial_not_minimal"

	// Signature algorithm.
	SigAlgUnreadable Code = "sig_alg_unreadable"
	SigAlgMismatch   Code = "sig_alg_mismatch"

	// Names.
	IssuerUnreadable  Code = "issuer_unreadable"
	SubjectUnreadable Code = "subject_unreadable"
	NameBadString     Code = "name_bad_string"

	// Validity.
	ValidityUnreadable Code = "validity_unreadable"
	TimeBadFormat      Code = "time_bad_format"

	// Public key.
	SPKIUnreadable Code = "spki_unreadable"
	KeyUnreadable  Code = "key_unreadable"

	// Extensions.
	ExtensionsUnreadable Code = "extensions_unreadable"
	ExtUnreadable        Code = "ext_unreadable"
	ExtDuplicate         Code = "ext_duplicate"
	SANUnreadable        Code = "san_unreadable"
	SANIPBadLen          Code = "san_ip_bad_len"
	SANDNSBadString      Code = "san_dns_bad_string"
	AKIUnreadable        Code = "aki_unreadable"
	SKIUnreadable        Code = "ski_unreadable"
)

// Codes lists every code in a fixed order, for docs and explain-error.
var Codes = []Code{CertUnreadable, CertTrailingData, SignatureUnreadable, TBSUnreadable, TBSExtraFields, VersionBad,
	SerialUnreadable, SerialNegative, SerialZero, SerialTooLong, SerialNotMinimal,
	SigAlgUnreadable, SigAlgMismatch, IssuerUnreadable, SubjectUnreadable, NameBadString,
	ValidityUnreadable, TimeBadFormat, SPKIUnreadable, KeyUnreadable,
	ExtensionsUnreadable, ExtUnreadable, ExtDuplicate, SANUnreadable, SANIPBadLen, SANDNSBadString,
	AKIUnreadable, SKIUnreadable}

var explanations = map[Code]string{
	CertUnreadable:      "The certificate is not a DER SEQUENCE of TBSCertificate, signatureAlgorithm and signature. Nothing else can be read; parse_status is failed.",
	CertTrailingData:    "Bytes follow the certificate's DER encoding. They are ignored; the certificate itself is read.",
	SignatureUnreadable: "The outer signatureAlgorithm or signatureValue cannot be read. The TBSCertificate's fields are still extracted.",
	TBSUnreadable:       "The TBSCertificate's fixed fields (serial, signature, issuer, validity, subject, subjectPublicKeyInfo) cannot be located. parse_status is failed.",
	TBSExtraFields:      "The TBSCertificate has elements besides RFC 5280's fields. They are ignored; the other fields are read.",
	VersionBad:          "The explicit version is not v1, v2 or v3 (0, 1 or 2), or cannot be read.",

	SerialUnreadable: "The serialNumber is not a readable INTEGER.",
	SerialNegative:   "The serialNumber is negative; RFC 5280 §4.1.2.2 requires a positive integer. Its raw content bytes are kept.",
	SerialZero:       "The serialNumber is zero; RFC 5280 §4.1.2.2 requires a positive integer.",
	SerialTooLong:    "The serialNumber has more than 20 content octets, RFC 5280's limit. Its raw content bytes are kept.",
	SerialNotMinimal: "The serialNumber INTEGER is not minimally encoded (a redundant leading 0x00 or 0xFF), which DER forbids. Its raw content bytes are kept.",

	SigAlgUnreadable: "The signature AlgorithmIdentifier cannot be read.",
	SigAlgMismatch:   "The TBSCertificate's signature algorithm differs from the outer signatureAlgorithm (RFC 5280 §4.1.1.2).",

	IssuerUnreadable:  "The issuer is not a readable Name (a SEQUENCE of RDN SETs of attribute type and value).",
	SubjectUnreadable: "The subject is not a readable Name (a SEQUENCE of RDN SETs of attribute type and value).",
	NameBadString:     "A name attribute's value is not valid for its string type (for example invalid UTF-8, or an odd-length BMPString). It is rendered with \\XX escapes for the bad bytes.",

	ValidityUnreadable: "The validity is not a SEQUENCE of two times.",
	TimeBadFormat:      "A notBefore or notAfter value is not a valid UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ) as RFC 5280 §4.1.2.5 requires. The value is left null.",

	SPKIUnreadable: "The subjectPublicKeyInfo is not a readable SEQUENCE of an AlgorithmIdentifier and a BIT STRING.",
	KeyUnreadable:  "The public key cannot be interpreted for its algorithm (for example an RSA key without a valid modulus, or an unreadable curve). The key size and curve are left empty.",

	ExtensionsUnreadable: "The extensions field cannot be read; no extension is extracted.",
	ExtUnreadable:        "One extension is malformed: it is skipped, or its value could not be decoded.",
	ExtDuplicate:         "An extension OID appears more than once; RFC 5280 §4.2 forbids it. The first occurrence is used.",
	SANUnreadable:        "The subjectAltName value cannot be parsed; no SAN is extracted.",
	SANIPBadLen:          "An iPAddress SAN is neither 4 nor 16 bytes. It is kept as hex and is not a valid address.",
	SANDNSBadString:      "A dNSName SAN contains bytes outside ASCII (IA5String). It is rendered with \\XX escapes for the bad bytes.",
	AKIUnreadable:        "The authorityKeyIdentifier extension cannot be parsed.",
	SKIUnreadable:        "The subjectKeyIdentifier extension cannot be parsed.",
}

// Explain returns the code's explanation, or "" for an unknown code.
func (c Code) Explain() string { return explanations[c] }
