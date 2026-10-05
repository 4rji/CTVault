package extract

import (
	"bytes"
	"encoding/asn1"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// atv is one attribute for building test names: an OID and a value element.
type atv struct {
	oid   asn1.ObjectIdentifier
	value []byte // a complete DER element (tag, length, content)
}

func str(tag cbasn1.Tag, content string) []byte {
	var b cryptobyte.Builder
	b.AddASN1(tag, func(b *cryptobyte.Builder) { b.AddBytes([]byte(content)) })
	return b.BytesOrPanic()
}

// buildName encodes a Name: a SEQUENCE of RDN SETs, in the given order.
func buildName(rdns ...[]atv) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, rdn := range rdns {
			b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
				for _, a := range rdn {
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1ObjectIdentifier(a.oid)
						b.AddBytes(a.value)
					})
				}
			})
		}
	})
	return b.BytesOrPanic()
}

var (
	oidCN    = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidO     = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidC     = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidUID   = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
	oidEmail = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	oidOther = asn1.ObjectIdentifier{1, 2, 3, 4}
)

const (
	tagUTF8      = cbasn1.UTF8String
	tagPrintable = cbasn1.PrintableString
	tagIA5       = cbasn1.IA5String
	tagTeletex   = cbasn1.Tag(20)
	tagBMP       = cbasn1.Tag(30)
	tagUniversal = cbasn1.Tag(28)
)

func TestNameRendering(t *testing.T) {
	for _, c := range []struct {
		name string
		rdns [][]atv
		want string
		bad  bool
	}{
		{"reverse DER order", [][]atv{{{oidC, str(tagPrintable, "US")}}, {{oidO, str(tagUTF8, "Acme")}}, {{oidCN, str(tagUTF8, "example.com")}}},
			"CN=example.com,O=Acme,C=US", false},
		{"multi-valued RDN in DER order", [][]atv{{{oidCN, str(tagUTF8, "a")}, {oidUID, str(tagUTF8, "b")}}}, "CN=a+UID=b", false},
		{"special characters", [][]atv{{{oidCN, str(tagUTF8, `a,b+c"d\e;<>`)}}}, `CN=a\,b\+c\"d\\e\;\<\>`, false},
		{"leading hash and trailing space", [][]atv{{{oidCN, str(tagUTF8, "#x ")}}}, `CN=\#x\ `, false},
		{"leading space", [][]atv{{{oidCN, str(tagUTF8, " y")}}}, `CN=\ y`, false},
		{"control character", [][]atv{{{oidCN, str(tagUTF8, "a\x07b")}}}, `CN=a\07b`, false},
		{"emailAddress", [][]atv{{{oidEmail, str(tagIA5, "a@b.example")}}}, "emailAddress=a@b.example", false},
		{"unknown type, string value", [][]atv{{{oidOther, str(tagUTF8, "v")}}}, "1.2.3.4=v", false},
		{"non-string value", [][]atv{{{oidOther, []byte{0x02, 0x01, 0x05}}}}, "1.2.3.4=#020105", false},
		{"Teletex as ISO 8859-1", [][]atv{{{oidCN, str(tagTeletex, "caf\xe9")}}}, "CN=café", false},
		{"BMPString", [][]atv{{{oidCN, str(tagBMP, "\x00c\x00a\x00f\x00\xe9")}}}, "CN=café", false},
		{"UniversalString", [][]atv{{{oidCN, str(tagUniversal, "\x00\x00\x00c\x00\x00\x00\xe9")}}}, "CN=cé", false},
		{"invalid UTF-8", [][]atv{{{oidCN, str(tagUTF8, "a\xffb")}}}, `CN=a\FFb`, true},
		{"odd-length BMPString", [][]atv{{{oidCN, str(tagBMP, "\x00a\x00")}}}, `CN=a\00`, true},
		{"BMPString surrogate", [][]atv{{{oidCN, str(tagBMP, "\xd8\x00")}}}, `CN=\D8\00`, true},
		{"non-ASCII PrintableString", [][]atv{{{oidCN, str(tagPrintable, "a\xc3b")}}}, `CN=a\C3b`, true},
		{"empty name", nil, "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			der := buildName(c.rdns...)
			n, ok := parseName(der)
			if !ok {
				t.Fatal("did not parse")
			}
			if !bytes.Equal(n.Raw, der) {
				t.Fatal("Raw is not the exact DER")
			}
			if got := n.String(); got != c.want {
				t.Errorf("String() = %q, want %q", got, c.want)
			}
			if n.badStrings() != c.bad {
				t.Errorf("badStrings() = %v, want %v", n.badStrings(), c.bad)
			}
		})
	}
}

func TestNameFirst(t *testing.T) {
	n, _ := parseName(buildName([]atv{{oidO, str(tagUTF8, "Acme, Inc.")}}, []atv{{oidCN, str(tagUTF8, `one\two`)}}, []atv{{oidCN, str(tagUTF8, "second\xff")}}))
	if v, ok := n.First(OIDCommonName); !ok || v != `one\\two` {
		t.Errorf("First(CN) = %q, %v", v, ok)
	}
	if v, ok := n.First(OIDOrganization); !ok || v != "Acme, Inc." {
		t.Errorf("First(O) = %q, %v: display values escape only backslashes and bad bytes", v, ok)
	}
	if _, ok := n.First("2.5.4.11"); ok {
		t.Error("First of a missing attribute")
	}
	m, _ := parseName(buildName([]atv{{oidCN, str(tagUTF8, "bad\xff")}}))
	if v, _ := m.First(OIDCommonName); v != `bad\FF` {
		t.Errorf("bad bytes: %q", v)
	}
}

func TestNameUnreadable(t *testing.T) {
	notSet := func() []byte {
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {})
		})
		return b.BytesOrPanic()
	}()
	emptyRDN := buildName([]atv{})
	for name, der := range map[string][]byte{
		"not a SEQUENCE":    {0x31, 0x00},
		"RDN not a SET":     notSet,
		"empty RDN":         emptyRDN,
		"truncated":         buildName([]atv{{oidCN, str(tagUTF8, "x")}})[:5],
		"trailing in value": buildName([]atv{{oidCN, append(str(tagUTF8, "x"), 0x05, 0x00)}}),
	} {
		if n, ok := parseName(der); ok {
			t.Errorf("%s: parsed as %q", name, n.String())
		} else if !bytes.Equal(n.Raw, der) {
			t.Errorf("%s: Raw must still hold the bytes", name)
		}
	}
}
