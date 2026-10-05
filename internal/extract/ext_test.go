package extract

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"net"
	"slices"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidSAN    = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidSKIx   = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidAKIx   = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidPoison = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
)

// ext encodes one Extension.
func ext(oid asn1.ObjectIdentifier, critical bool, value []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
		if critical {
			b.AddASN1Boolean(true)
		}
		b.AddASN1OctetString(value)
	})
	return b.BytesOrPanic()
}

// extsField is the TBSCertificate's [3] extensions field.
func extsField(exts ...[]byte) []byte {
	return element(cbasn1.Tag(3).Constructed().ContextSpecific(), seq(exts...))
}

func san(names ...[]byte) []byte { return seq(names...) }
func dnsName(s string) []byte    { return element(cbasn1.Tag(2).ContextSpecific(), []byte(s)) }
func ipName(b []byte) []byte     { return element(cbasn1.Tag(7).ContextSpecific(), b) }

func withExtensions(t *testing.T, exts ...[]byte) *Cert {
	t.Helper()
	p := validParts(t)
	p.extra = [][]byte{extsField(exts...)}
	return Parse(p.der())
}

func TestExtensionsFromX509(t *testing.T) {
	der := selfSigned(t, testRSA, func(c *x509.Certificate) {
		c.DNSNames = []string{"a.example", "*.b.example"}
		c.IPAddresses = []net.IP{net.ParseIP("192.0.2.1").To4(), net.ParseIP("2001:db8::1")}
		c.SubjectKeyId = []byte{1, 2, 3}
		c.AuthorityKeyId = []byte{4, 5, 6}
	})
	ref, _ := x509.ParseCertificate(der)
	got := Parse(der)
	if got.Status != StatusOK {
		t.Fatalf("%s %v", got.Status, got.Errors)
	}
	if !slices.Equal(got.DNSNames, ref.DNSNames) || len(got.IPAddresses) != 2 ||
		!net.IP(got.IPAddresses[0]).Equal(ref.IPAddresses[0]) || !net.IP(got.IPAddresses[1]).Equal(ref.IPAddresses[1]) {
		t.Errorf("SANs %v %x", got.DNSNames, got.IPAddresses)
	}
	if !bytes.Equal(got.SubjectKeyID, ref.SubjectKeyId) || !bytes.Equal(got.AuthorityKeyID, ref.AuthorityKeyId) {
		t.Errorf("key IDs %x %x", got.SubjectKeyID, got.AuthorityKeyID)
	}
	if len(got.Extensions) != len(ref.Extensions) {
		t.Fatalf("%d extensions, want %d", len(got.Extensions), len(ref.Extensions))
	}
	for i, e := range ref.Extensions {
		if g := got.Extensions[i]; g.OID != e.Id.String() || g.Critical != e.Critical || !bytes.Equal(g.Value, e.Value) {
			t.Errorf("extension %d: %+v, want %s %v", i, g, e.Id, e.Critical)
		}
	}
}

func TestExtensionProblems(t *testing.T) {
	good := ext(oidSAN, false, san(dnsName("first.example")))
	for _, c := range []struct {
		name  string
		exts  [][]byte
		codes []Code
		check func(*Cert) bool
	}{
		{"duplicate: the first is used", [][]byte{good, ext(oidSAN, false, san(dnsName("second.example")))}, []Code{ExtDuplicate},
			func(c *Cert) bool {
				return slices.Equal(c.DNSNames, []string{"first.example"}) && len(c.Extensions) == 2
			}},
		{"one malformed extension is skipped", [][]byte{seq(oidElem(oidSAN)), good}, []Code{ExtUnreadable},
			func(c *Cert) bool {
				return slices.Equal(c.DNSNames, []string{"first.example"}) && len(c.Extensions) == 1
			}},
		{"IP SAN of 5 bytes is kept", [][]byte{ext(oidSAN, false, san(ipName([]byte{1, 2, 3, 4, 5})))}, []Code{SANIPBadLen},
			func(c *Cert) bool { return len(c.IPAddresses) == 1 && len(c.IPAddresses[0]) == 5 }},
		{"non-ASCII dNSName", [][]byte{ext(oidSAN, false, san(dnsName("caf\xc3\xa9.example")))}, []Code{SANDNSBadString},
			func(c *Cert) bool { return slices.Equal(c.DNSNames, []string{`caf\C3\A9.example`}) }},
		{"an unreadable SAN yields no names", [][]byte{ext(oidSAN, false, append(san(dnsName("x.example")), 0xff))}, []Code{SANUnreadable},
			func(c *Cert) bool { return len(c.DNSNames) == 0 }},
		{"other GeneralNames are skipped", [][]byte{ext(oidSAN, false, san(element(cbasn1.Tag(1).ContextSpecific(), []byte("a@b")), dnsName("y.example")))}, nil,
			func(c *Cert) bool { return slices.Equal(c.DNSNames, []string{"y.example"}) }},
		{"unreadable AKI", [][]byte{ext(oidAKIx, false, []byte{0x04, 0x01, 0x00})}, []Code{AKIUnreadable},
			func(c *Cert) bool { return c.AuthorityKeyID == nil }},
		{"unreadable SKI", [][]byte{ext(oidSKIx, false, []byte{0x30, 0x00})}, []Code{SKIUnreadable},
			func(c *Cert) bool { return c.SubjectKeyID == nil }},
		{"CT poison", [][]byte{ext(oidPoison, true, []byte{0x05, 0x00})}, nil,
			func(c *Cert) bool { return c.HasCTPoison && c.Extensions[0].Critical }},
		{"CT poison that is not NULL", [][]byte{ext(oidPoison, true, []byte{0x04, 0x00})}, []Code{ExtUnreadable},
			func(c *Cert) bool { return c.HasCTPoison }},
	} {
		got := withExtensions(t, c.exts...)
		if !slices.Equal(got.Errors, c.codes) || !c.check(got) {
			t.Errorf("%s: codes %v, DNS %q, IPs %x, %d extensions", c.name, got.Errors, got.DNSNames, got.IPAddresses, len(got.Extensions))
		}
	}
	p := validParts(t)
	p.extra = [][]byte{element(cbasn1.Tag(3).Constructed().ContextSpecific(), []byte{0x05, 0x00})}
	if got := Parse(p.der()); !slices.Equal(got.Errors, []Code{ExtensionsUnreadable}) || got.Extensions != nil {
		t.Errorf("unreadable extensions field: %v", got.Errors)
	}
}
