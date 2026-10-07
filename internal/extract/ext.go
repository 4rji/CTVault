package extract

import (
	"encoding/asn1"
	"fmt"
	"strings"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Extension is one extension as encoded.
type Extension struct {
	OID      string // dotted
	Critical bool
	Value    []byte // the extnValue OCTET STRING's content
}

// Extension OIDs the extractor decodes.
const (
	oidSubjectAltName = "2.5.29.17"
	oidSubjectKeyID   = "2.5.29.14"
	oidAuthorityKeyID = "2.5.29.35"
	oidCTPoison       = "1.3.6.1.4.1.11129.2.4.3"
)

var (
	tagExtensions = cbasn1.Tag(3).Constructed().ContextSpecific()
	tagDNSName    = cbasn1.Tag(2).ContextSpecific()
	tagIPAddress  = cbasn1.Tag(7).ContextSpecific()
	tagKeyID      = cbasn1.Tag(0).ContextSpecific()
)

// parseExtensions reads the TBSCertificate's optional trailing fields and
// decodes the extensions in the [3] field. Every extension is listed; the
// decoded fields come from the first occurrence of each OID.
func (c *Cert) parseExtensions(optional [][]byte) {
	var field []byte
	for _, el := range optional {
		if len(el) > 0 && cbasn1.Tag(el[0]) == tagExtensions {
			field = el
		}
	}
	if field == nil {
		return
	}
	s := cryptobyte.String(field)
	var wrapped, list cryptobyte.String
	if !s.ReadASN1(&wrapped, tagExtensions) || !wrapped.ReadASN1(&list, cbasn1.SEQUENCE) || !wrapped.Empty() {
		c.add(ExtensionsUnreadable)
		return
	}
	seen := map[string]bool{}
	for !list.Empty() {
		var el cryptobyte.String
		if !list.ReadASN1(&el, cbasn1.SEQUENCE) {
			c.add(ExtensionsUnreadable)
			return
		}
		var oid asn1.ObjectIdentifier
		var e Extension
		var value cryptobyte.String
		if !el.ReadASN1ObjectIdentifier(&oid) ||
			el.PeekASN1Tag(cbasn1.BOOLEAN) && !el.ReadASN1Boolean(&e.Critical) ||
			!el.ReadASN1(&value, cbasn1.OCTET_STRING) || !el.Empty() {
			c.add(ExtUnreadable)
			continue
		}
		e.OID, e.Value = oid.String(), value
		c.Extensions = append(c.Extensions, e)
		if seen[e.OID] {
			c.add(ExtDuplicate)
			continue
		}
		seen[e.OID] = true
		c.decodeExtension(e)
	}
}

func (c *Cert) decodeExtension(e Extension) {
	v := cryptobyte.String(e.Value)
	switch e.OID {
	case oidSubjectAltName:
		c.parseSAN(v)
	case oidSubjectKeyID:
		var id cryptobyte.String
		if !v.ReadASN1(&id, cbasn1.OCTET_STRING) || !v.Empty() {
			c.add(SKIUnreadable)
			return
		}
		c.SubjectKeyID = id
	case oidAuthorityKeyID:
		var seq, id cryptobyte.String
		var present bool
		if !v.ReadASN1(&seq, cbasn1.SEQUENCE) || !v.Empty() || !seq.ReadOptionalASN1(&id, &present, tagKeyID) {
			c.add(AKIUnreadable)
			return
		}
		if present {
			c.AuthorityKeyID = id
		}
	case oidCTPoison:
		c.HasCTPoison = true
		if string(e.Value) != "\x05\x00" { // RFC 6962 §3.1: an ASN.1 NULL
			c.add(ExtUnreadable)
		}
	}
}

// parseSAN reads dNSName and iPAddress GeneralNames; other kinds are
// skipped. An unreadable SAN yields no names at all.
func (c *Cert) parseSAN(v cryptobyte.String) {
	var names cryptobyte.String
	if !v.ReadASN1(&names, cbasn1.SEQUENCE) || !v.Empty() {
		c.add(SANUnreadable)
		return
	}
	var dns []string
	var ips [][]byte
	var codes []Code
	for !names.Empty() {
		var gn cryptobyte.String
		var tag cbasn1.Tag
		if !names.ReadAnyASN1(&gn, &tag) {
			c.add(SANUnreadable)
			return
		}
		switch tag {
		case tagDNSName:
			name, ok := asciiDisplay(gn)
			if !ok {
				codes = append(codes, SANDNSBadString)
			}
			dns = append(dns, name)
		case tagIPAddress:
			if len(gn) != 4 && len(gn) != 16 {
				codes = append(codes, SANIPBadLen)
			}
			ips = append(ips, gn)
		}
	}
	c.DNSNames, c.IPAddresses = dns, ips
	for _, code := range codes {
		c.add(code)
	}
}

// asciiDisplay renders an IA5String: bytes outside ASCII and control
// characters become \XX, and a backslash is doubled. ok is false when a
// byte is outside ASCII.
// Display renders bytes from a certificate as the extractor renders DNS
// names: bytes outside printable ASCII as \XX, and a backslash doubled.
func Display(b []byte) string {
	s, _ := asciiDisplay(b)
	return s
}

func asciiDisplay(b []byte) (string, bool) {
	ok := true
	var s strings.Builder
	for _, x := range b {
		switch {
		case x >= 0x80:
			ok = false
			fmt.Fprintf(&s, `\%02X`, x)
		case x < 0x20 || x == 0x7f:
			fmt.Fprintf(&s, `\%02X`, x)
		case x == '\\':
			s.WriteString(`\\`)
		default:
			s.WriteByte(x)
		}
	}
	return s.String(), ok
}
