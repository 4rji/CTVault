package extract

import (
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Attribute type OIDs that columns read.
const (
	OIDCommonName   = "2.5.4.3"
	OIDOrganization = "2.5.4.10"
)

// shortNames are RFC 4514's attribute type names, plus serialNumber and
// emailAddress as OpenSSL writes them. Other types render as dotted OIDs.
var shortNames = map[string]string{
	"2.5.4.3": "CN", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.6": "C",
	"2.5.4.9": "STREET", "0.9.2342.19200300.100.1.25": "DC", "0.9.2342.19200300.100.1.1": "UID",
	"2.5.4.5": "serialNumber", "1.2.840.113549.1.9.1": "emailAddress",
}

// Name is an issuer or subject Name (amendment A2 §3.2). Raw, its exact DER
// encoding, is the name's reproducible identity; String is a deterministic
// display and search rendering only.
type Name struct {
	Raw  []byte        // the whole Name element, exactly as encoded
	RDNs [][]Attribute // in DER order
}

// Attribute is one AttributeTypeAndValue.
type Attribute struct {
	Type    string     // dotted OID
	Tag     cbasn1.Tag // the value's tag
	Value   []byte     // the value's content bytes
	Element []byte     // the whole value element
}

// parseName reads a Name. On failure Raw still holds the bytes and ok is
// false.
func parseName(der []byte) (n Name, ok bool) {
	n.Raw = der
	s := cryptobyte.String(der)
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !s.Empty() {
		return n, false
	}
	for !seq.Empty() {
		var set cryptobyte.String
		if !seq.ReadASN1(&set, cbasn1.SET) || set.Empty() {
			return Name{Raw: der}, false
		}
		var rdn []Attribute
		for !set.Empty() {
			var body cryptobyte.String
			var oid asn1.ObjectIdentifier
			var a Attribute
			var elem cryptobyte.String
			if !set.ReadASN1(&body, cbasn1.SEQUENCE) || !body.ReadASN1ObjectIdentifier(&oid) ||
				!body.ReadAnyASN1Element(&elem, &a.Tag) || !body.Empty() {
				return Name{Raw: der}, false
			}
			var content cryptobyte.String
			e := elem
			if !e.ReadAnyASN1(&content, &a.Tag) {
				return Name{Raw: der}, false
			}
			a.Type, a.Value, a.Element = oid.String(), content, elem
			rdn = append(rdn, a)
		}
		n.RDNs = append(n.RDNs, rdn)
	}
	return n, true
}

// decoded is a string value as runes, with each undecodable byte kept apart
// so it can be escaped as \XX.
type decoded struct {
	parts []piece
	bad   bool
}

type piece struct {
	r      rune
	rawHex bool // r is a raw byte to render as \XX
}

// decode reads a string-typed value. isString is false for any other type.
func decode(tag cbasn1.Tag, b []byte) (d decoded, isString bool) {
	raw := func(x byte) { d.parts = append(d.parts, piece{rune(x), true}) }
	switch tag {
	case cbasn1.UTF8String:
		for len(b) > 0 {
			r, n := utf8.DecodeRune(b)
			if r == utf8.RuneError && n <= 1 {
				raw(b[0])
				d.bad, b = true, b[1:]
				continue
			}
			d.parts = append(d.parts, piece{r: r})
			b = b[n:]
		}
	case cbasn1.PrintableString, cbasn1.IA5String, cbasn1.Tag(18), cbasn1.Tag(26): // Numeric, Visible
		for _, x := range b {
			if x >= 0x80 {
				raw(x)
				d.bad = true
				continue
			}
			d.parts = append(d.parts, piece{r: rune(x)})
		}
	case cbasn1.Tag(20): // TeletexString, read as ISO 8859-1
		for _, x := range b {
			d.parts = append(d.parts, piece{r: rune(x)})
		}
	case cbasn1.Tag(30): // BMPString, UCS-2 big-endian
		for len(b) >= 2 {
			u := rune(binary.BigEndian.Uint16(b))
			if u >= 0xD800 && u <= 0xDFFF {
				raw(b[0])
				raw(b[1])
				d.bad = true
			} else {
				d.parts = append(d.parts, piece{r: u})
			}
			b = b[2:]
		}
		for _, x := range b {
			raw(x)
			d.bad = true
		}
	case cbasn1.Tag(28): // UniversalString, UCS-4 big-endian
		for len(b) >= 4 {
			u := rune(binary.BigEndian.Uint32(b))
			if u > utf8.MaxRune || (u >= 0xD800 && u <= 0xDFFF) {
				for _, x := range b[:4] {
					raw(x)
				}
				d.bad = true
			} else {
				d.parts = append(d.parts, piece{r: u})
			}
			b = b[4:]
		}
		for _, x := range b {
			raw(x)
			d.bad = true
		}
	default:
		return d, false
	}
	return d, true
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// display renders a decoded value for a column: characters as they are,
// except that a backslash is doubled and control characters and
// undecodable bytes become \XX.
func (d decoded) display() string {
	var b strings.Builder
	for _, p := range d.parts {
		switch {
		case p.rawHex, isControl(p.r):
			fmt.Fprintf(&b, `\%02X`, p.r)
		case p.r == '\\':
			b.WriteString(`\\`)
		default:
			b.WriteRune(p.r)
		}
	}
	return b.String()
}

// rfc4514 renders a decoded value with RFC 4514 §2.4 escaping.
func (d decoded) rfc4514() string {
	var b strings.Builder
	for i, p := range d.parts {
		switch {
		case p.rawHex, isControl(p.r):
			fmt.Fprintf(&b, `\%02X`, p.r)
		case strings.ContainsRune(`"+,;<>\`, p.r),
			i == 0 && (p.r == '#' || p.r == ' '),
			i == len(d.parts)-1 && p.r == ' ':
			b.WriteByte('\\')
			b.WriteRune(p.r)
		default:
			b.WriteRune(p.r)
		}
	}
	return b.String()
}

// String renders the name as RFC 4514 does: RDNs in reverse DER order,
// multi-valued RDNs joined with "+" in DER order, and non-string values as
// "#" followed by the hex of their whole element.
func (n Name) String() string {
	var rdns []string
	for i := len(n.RDNs) - 1; i >= 0; i-- {
		var parts []string
		for _, a := range n.RDNs[i] {
			typ := a.Type
			if s, ok := shortNames[typ]; ok {
				typ = s
			}
			v := "#" + hex.EncodeToString(a.Element)
			if d, ok := decode(a.Tag, a.Value); ok {
				v = d.rfc4514()
			}
			parts = append(parts, typ+"="+v)
		}
		rdns = append(rdns, strings.Join(parts, "+"))
	}
	return strings.Join(rdns, ",")
}

// First returns the display value of the first attribute of type oid, in
// DER order. A non-string value is "#" followed by its hex.
func (n Name) First(oid string) (string, bool) {
	for _, rdn := range n.RDNs {
		for _, a := range rdn {
			if a.Type != oid {
				continue
			}
			if d, ok := decode(a.Tag, a.Value); ok {
				return d.display(), true
			}
			return "#" + hex.EncodeToString(a.Element), true
		}
	}
	return "", false
}

// badStrings reports whether any string value has bytes invalid for its
// type (NameBadString).
func (n Name) badStrings() bool {
	for _, rdn := range n.RDNs {
		for _, a := range rdn {
			if d, ok := decode(a.Tag, a.Value); ok && d.bad {
				return true
			}
		}
	}
	return false
}
