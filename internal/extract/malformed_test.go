package extract

import (
	"bytes"
	"encoding/asn1"
	"slices"
	"testing"

	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// fixedParts is a well-formed certificate built from fixed bytes, so the
// malformed corpus derived from it is deterministic.
func fixedParts() parts {
	pattern := func(n int, seed byte) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = seed + byte(i*7)
		}
		return b
	}
	sha256RSA := seq(oidElem(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}), []byte{0x05, 0x00})
	modulus := append([]byte{0x00, 0xC5}, pattern(255, 3)...)
	rsaKey := seq(element(cbasn1.INTEGER, modulus), element(cbasn1.INTEGER, []byte{1, 0, 1}))
	return parts{
		version:     element(cbasn1.Tag(0).Constructed().ContextSpecific(), element(cbasn1.INTEGER, []byte{2})),
		serial:      element(cbasn1.INTEGER, []byte{0x01, 0x23, 0x45}),
		sigAlg:      sha256RSA,
		issuer:      buildName([]atv{{oidC, str(tagPrintable, "US")}}, []atv{{oidO, str(tagUTF8, "CTVault Test")}}, []atv{{oidCN, str(tagUTF8, "CTVault Test CA")}}),
		validity:    seq(element(cbasn1.UTCTime, []byte("260101000000Z")), element(cbasn1.UTCTime, []byte("260401000000Z"))),
		subject:     buildName([]atv{{oidCN, str(tagUTF8, "leaf.example")}}),
		spki:        spki(seq(oidElem(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}), []byte{0x05, 0x00}), rsaKey),
		extra:       [][]byte{extsField(ext(oidSAN, false, san(dnsName("leaf.example"))))},
		outerSigAlg: sha256RSA,
		signature:   element(cbasn1.BIT_STRING, append([]byte{0x00}, pattern(256, 9)...)),
	}
}

type malformed struct {
	name  string
	der   []byte
	codes []Code // codes the case must produce (the golden holds the full result)
}

// malformedCorpus is one well-formed certificate and one variant per
// malformation the lenient extractor must handle (amendment A2 §3.4).
func malformedCorpus() []malformed {
	with := func(edit func(*parts)) []byte {
		p := fixedParts()
		edit(&p)
		return p.der()
	}
	serial := func(b ...byte) []byte { return with(func(p *parts) { p.serial = element(cbasn1.INTEGER, b) }) }
	notBefore := func(tag cbasn1.Tag, s string) []byte {
		return with(func(p *parts) {
			p.validity = seq(element(tag, []byte(s)), element(cbasn1.UTCTime, []byte("260401000000Z")))
		})
	}
	sanExt := func(names ...[]byte) []byte {
		return with(func(p *parts) { p.extra = [][]byte{extsField(ext(oidSAN, false, san(names...)))} })
	}
	unknownAlg := seq(oidElem(asn1.ObjectIdentifier{1, 2, 3, 4, 5}))
	return []malformed{
		{"well-formed", with(func(*parts) {}), nil},

		{"serial negative", serial(0x80, 0x01), []Code{SerialNegative}},
		{"serial zero", serial(0x00), []Code{SerialZero}},
		{"serial of 21 octets", serial(bytes.Repeat([]byte{0x01}, 21)...), []Code{SerialTooLong}},
		{"serial not minimal", serial(0x00, 0x01), []Code{SerialNotMinimal}},

		{"UTCTime without seconds", notBefore(cbasn1.UTCTime, "2601010000Z"), []Code{TimeBadFormat}},
		{"UTCTime with an offset", notBefore(cbasn1.UTCTime, "260101000000+0100"), []Code{TimeBadFormat}},
		{"GeneralizedTime with a fraction", notBefore(cbasn1.GeneralizedTime, "20260101000000.5Z"), []Code{TimeBadFormat}},
		{"GeneralizedTime month 13", notBefore(cbasn1.GeneralizedTime, "20261301000000Z"), []Code{TimeBadFormat}},

		{"duplicate SAN extension", with(func(p *parts) {
			p.extra = [][]byte{extsField(ext(oidSAN, false, san(dnsName("first.example"))), ext(oidSAN, false, san(dnsName("second.example"))))}
		}), []Code{ExtDuplicate}},
		{"truncated extension list", with(func(p *parts) {
			p.extra = [][]byte{element(cbasn1.Tag(3).Constructed().ContextSpecific(),
				element(cbasn1.SEQUENCE, append(ext(oidSKIx, false, element(cbasn1.OCTET_STRING, []byte{1})), 0x30, 0x0a, 0x06, 0x03)))}
		}), []Code{ExtensionsUnreadable}},
		{"extensions field running past the TBS", with(func(p *parts) {
			p.extra = [][]byte{{0xA3, 0x10, 0x30, 0x01}}
		}), []Code{ExtensionsUnreadable}},
		{"truncated SAN", with(func(p *parts) {
			p.extra = [][]byte{extsField(ext(oidSAN, false, []byte{0x30, 0x10, 0x82, 0x03, 'a', '.', 'b'}))}
		}), []Code{SANUnreadable}},

		{"CN that is not a DNS name, no SAN", with(func(p *parts) {
			p.subject = buildName([]atv{{oidCN, str(tagUTF8, "Example Device 42")}})
			p.extra = nil
		}), nil},
		{"CN that is an IP literal", with(func(p *parts) {
			p.subject = buildName([]atv{{oidCN, str(tagUTF8, "192.0.2.7")}})
		}), nil},

		{"IP SANs of every odd length", sanExt(ipName(nil), ipName([]byte{1}), ipName([]byte{192, 0, 2, 1}), ipName([]byte{1, 2, 3, 4, 5}),
			ipName(make([]byte, 8)), ipName(make([]byte, 16)), ipName(make([]byte, 17))), []Code{SANIPBadLen}},

		{"unknown signature algorithm", with(func(p *parts) { p.sigAlg, p.outerSigAlg = unknownAlg, unknownAlg }), nil},
		{"signature algorithm mismatch", with(func(p *parts) {
			p.outerSigAlg = seq(oidElem(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}), []byte{0x05, 0x00})
		}), []Code{SigAlgMismatch}},
		{"unknown SPKI algorithm", with(func(p *parts) {
			p.spki = spki(seq(oidElem(asn1.ObjectIdentifier{1, 2, 3, 4, 6})), []byte{0xAA, 0xBB})
		}), nil},

		{"issuer CN with invalid UTF-8", with(func(p *parts) {
			p.issuer = buildName([]atv{{oidCN, str(tagUTF8, "Bad\xffIssuer")}})
		}), []Code{NameBadString}},
		{"subject CN as odd-length BMPString", with(func(p *parts) {
			p.subject = buildName([]atv{{oidCN, str(tagBMP, "\x00l\x00e\x00")}})
		}), []Code{NameBadString}},
		{"subject CN PrintableString with a non-ASCII byte", with(func(p *parts) {
			p.subject = buildName([]atv{{oidCN, str(tagPrintable, "caf\xe9")}})
		}), []Code{NameBadString}},
		{"issuer that is a SET", with(func(p *parts) { p.issuer = element(cbasn1.SET, nil) }), []Code{IssuerUnreadable}},

		{"trailing data after the certificate", with(func(p *parts) { p.trailing = []byte{0x00, 0x00} }), []Code{CertTrailingData}},
		{"extra TBS field", with(func(p *parts) { p.extra = append([][]byte{seq()}, p.extra...) }), []Code{TBSExtraFields}},
		{"TBS without a public key", with(func(p *parts) { p.spki = nil }), []Code{TBSUnreadable}},
		{"not a certificate", element(cbasn1.OCTET_STRING, []byte("not a certificate")), []Code{CertUnreadable}},
	}
}

// TestMalformedCorpus: each malformation produces its code, and the whole
// result matches testdata/malformed.golden.
func TestMalformedCorpus(t *testing.T) {
	var lines []string
	for _, m := range malformedCorpus() {
		c := Parse(m.der)
		for _, code := range m.codes {
			if !slices.Contains(c.Errors, code) {
				t.Errorf("%s: codes %v lack %s", m.name, c.Errors, code)
			}
		}
		if m.codes == nil && len(c.Errors) > 0 {
			t.Errorf("%s: unexpected codes %v", m.name, c.Errors)
		}
		lines = append(lines, m.name+"\t"+jsonLine(t, summarize(m.der)))
	}
	checkGolden(t, "malformed.golden", lines, false)
}
