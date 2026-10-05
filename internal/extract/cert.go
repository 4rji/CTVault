package extract

import (
	"bytes"
	"encoding/asn1"
	"slices"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Status is certs.parse_status.
type Status string

const (
	StatusOK      Status = "ok"      // no error code
	StatusPartial Status = "partial" // at least one field could not be read
	StatusFailed  Status = "failed"  // the Certificate or the TBSCertificate cannot be read
)

// Cert is what the extractor read from one certificate. Byte slices alias
// the input. Fields that could not be read are zero, and Errors says why.
type Cert struct {
	Status Status
	Errors []Code // in the order found, each code at most once

	Version            int    // 1, 2 or 3; 0 when unreadable
	Serial             []byte // the raw INTEGER content bytes; nil when unreadable
	SignatureAlgorithm string // the TBSCertificate's: a name, or the dotted OID; "" when unreadable

	Issuer, Subject Name

	NotBefore, NotAfter       time.Time // UTC
	HasNotBefore, HasNotAfter bool

	Key Key

	Extensions     []Extension // every extension, in order
	DNSNames       []string    // dNSName SANs, display-escaped (bytes outside ASCII as \XX)
	IPAddresses    [][]byte    // iPAddress SANs, raw; 4 or 16 bytes when valid
	AuthorityKeyID []byte      // the AKI's keyIdentifier
	SubjectKeyID   []byte
	HasCTPoison    bool // the RFC 6962 precertificate poison extension is present
}

func (c *Cert) add(code Code) {
	if !slices.Contains(c.Errors, code) {
		c.Errors = append(c.Errors, code)
	}
}

var tagVersion = cbasn1.Tag(0).Constructed().ContextSpecific()

// Parse reads der leniently (amendment A2 §3). It never fails and never
// panics: what cannot be read stays zero and adds an error code.
func Parse(der []byte) *Cert {
	c := &Cert{}
	c.parse(der)
	switch {
	case slices.Contains(c.Errors, CertUnreadable), slices.Contains(c.Errors, TBSUnreadable):
		c.Status = StatusFailed
	case len(c.Errors) > 0:
		c.Status = StatusPartial
	default:
		c.Status = StatusOK
	}
	return c
}

func (c *Cert) parse(der []byte) {
	s := cryptobyte.String(der)
	var body, tbs cryptobyte.String
	if !s.ReadASN1(&body, cbasn1.SEQUENCE) || !body.ReadASN1(&tbs, cbasn1.SEQUENCE) {
		c.add(CertUnreadable)
		return
	}
	if !s.Empty() {
		c.add(CertTrailingData)
	}
	var outerAlg cryptobyte.String
	var sig asn1.BitString
	if !body.ReadASN1Element(&outerAlg, cbasn1.SEQUENCE) || !body.ReadASN1BitString(&sig) || !body.Empty() {
		c.add(SignatureUnreadable)
		outerAlg = nil
	}

	var els [][]byte
	var tags []cbasn1.Tag
	for !tbs.Empty() {
		var el cryptobyte.String
		var tag cbasn1.Tag
		if !tbs.ReadAnyASN1Element(&el, &tag) {
			// Past the six fixed fields only the optional ones remain: an
			// unreadable tail loses the extensions, not the certificate.
			fixedSeen := len(els)
			if len(tags) > 0 && tags[0] == tagVersion {
				fixedSeen--
			}
			if fixedSeen < 6 {
				c.add(TBSUnreadable)
				return
			}
			c.add(ExtensionsUnreadable)
			break
		}
		els, tags = append(els, el), append(tags, tag)
	}
	i := 0
	c.Version = 1
	if len(tags) > 0 && tags[0] == tagVersion {
		c.Version = parseVersion(els[0])
		if c.Version == 0 {
			c.add(VersionBad)
		}
		i = 1
	}
	// The six fixed fields come before the optional issuerUniqueID [1],
	// subjectUniqueID [2] and extensions [3].
	fixed := len(els)
	for fixed > i && isOptionalTBSField(tags[fixed-1]) {
		fixed--
	}
	if fixed < i+6 {
		c.Version = 0
		c.add(TBSUnreadable)
		return
	}
	if fixed > i+6 {
		c.add(TBSExtraFields)
	}
	c.parseSerial(els[i])
	c.parseSignatureAlgorithm(els[i+1], outerAlg)
	var ok bool
	if c.Issuer, ok = parseName(els[i+2]); !ok {
		c.add(IssuerUnreadable)
	} else if c.Issuer.badStrings() {
		c.add(NameBadString)
	}
	c.parseValidity(els[i+3])
	if c.Subject, ok = parseName(els[i+4]); !ok {
		c.add(SubjectUnreadable)
	} else if c.Subject.badStrings() {
		c.add(NameBadString)
	}
	var codes []Code
	c.Key, codes = parseKey(els[i+5])
	for _, code := range codes {
		c.add(code)
	}
	c.parseExtensions(els[fixed:])
}

func isOptionalTBSField(t cbasn1.Tag) bool {
	return t == cbasn1.Tag(1).ContextSpecific() || t == cbasn1.Tag(2).ContextSpecific() ||
		t == cbasn1.Tag(1).Constructed().ContextSpecific() || t == cbasn1.Tag(2).Constructed().ContextSpecific() ||
		t == cbasn1.Tag(3).Constructed().ContextSpecific()
}

// parseVersion reads [0] EXPLICIT INTEGER: 0, 1 or 2 are v1-v3; anything
// else is 0.
func parseVersion(el []byte) int {
	s := cryptobyte.String(el)
	var inner cryptobyte.String
	var v int
	if !s.ReadASN1(&inner, tagVersion) || !inner.ReadASN1Integer(&v) || !inner.Empty() || v < 0 || v > 2 {
		return 0
	}
	return v + 1
}

// parseSerial keeps the raw INTEGER content and flags what RFC 5280 and DER
// forbid.
func (c *Cert) parseSerial(el []byte) {
	s := cryptobyte.String(el)
	var v cryptobyte.String
	if !s.ReadASN1(&v, cbasn1.INTEGER) || len(v) == 0 {
		c.add(SerialUnreadable)
		return
	}
	c.Serial = v
	if v[0]&0x80 != 0 {
		c.add(SerialNegative)
	}
	if len(v) > 1 && (v[0] == 0x00 && v[1]&0x80 == 0 || v[0] == 0xFF && v[1]&0x80 != 0) {
		c.add(SerialNotMinimal)
	}
	if bytes.Count(v, []byte{0}) == len(v) {
		c.add(SerialZero)
	}
	if len(v) > 20 {
		c.add(SerialTooLong)
	}
}

// parseSignatureAlgorithm names the TBSCertificate's signature algorithm and
// checks it against the outer one (RFC 5280 §4.1.1.2).
func (c *Cert) parseSignatureAlgorithm(el, outer []byte) {
	s := cryptobyte.String(el)
	var alg cryptobyte.String
	var oid asn1.ObjectIdentifier
	if !s.ReadASN1(&alg, cbasn1.SEQUENCE) || !alg.ReadASN1ObjectIdentifier(&oid) {
		c.add(SigAlgUnreadable)
		return
	}
	c.SignatureAlgorithm = oid.String()
	if name, ok := signatureAlgorithms[c.SignatureAlgorithm]; ok {
		c.SignatureAlgorithm = name
	}
	if outer != nil && !bytes.Equal(el, outer) {
		c.add(SigAlgMismatch)
	}
}

func (c *Cert) parseValidity(el []byte) {
	s := cryptobyte.String(el)
	var v cryptobyte.String
	var nb, na cryptobyte.String
	var nbTag, naTag cbasn1.Tag
	if !s.ReadASN1(&v, cbasn1.SEQUENCE) || !v.ReadAnyASN1(&nb, &nbTag) || !v.ReadAnyASN1(&na, &naTag) || !v.Empty() {
		c.add(ValidityUnreadable)
		return
	}
	var ok bool
	if c.NotBefore, ok = parseTime(nbTag, nb); ok {
		c.HasNotBefore = true
	} else {
		c.add(TimeBadFormat)
	}
	if c.NotAfter, ok = parseTime(naTag, na); ok {
		c.HasNotAfter = true
	} else {
		c.add(TimeBadFormat)
	}
}

// parseTime reads a time as RFC 5280 §4.1.2.5 requires: UTCTime
// YYMMDDHHMMSSZ (YY below 50 is 20YY) or GeneralizedTime YYYYMMDDHHMMSSZ.
func parseTime(tag cbasn1.Tag, b []byte) (time.Time, bool) {
	var digits []byte
	switch {
	case tag == cbasn1.UTCTime && len(b) == 13 && b[12] == 'Z':
		digits = b[:12]
	case tag == cbasn1.GeneralizedTime && len(b) == 15 && b[14] == 'Z':
		digits = b[:14]
	default:
		return time.Time{}, false
	}
	n := make([]int, 0, 7)
	for i := 0; i < len(digits); i += 2 {
		if digits[i] < '0' || digits[i] > '9' || digits[i+1] < '0' || digits[i+1] > '9' {
			return time.Time{}, false
		}
		n = append(n, int(digits[i]-'0')*10+int(digits[i+1]-'0'))
	}
	var year int
	if tag == cbasn1.UTCTime {
		year = 2000 + n[0]
		if n[0] >= 50 {
			year = 1900 + n[0]
		}
		n = n[1:]
	} else {
		year, n = n[0]*100+n[1], n[2:]
	}
	t := time.Date(year, time.Month(n[0]), n[1], n[2], n[3], n[4], 0, time.UTC)
	if t.Year() != year || int(t.Month()) != n[0] || t.Day() != n[1] || t.Hour() != n[2] || t.Minute() != n[3] || t.Second() != n[4] {
		return time.Time{}, false // out of range: month 13, February 30, hour 24
	}
	return t, true
}
