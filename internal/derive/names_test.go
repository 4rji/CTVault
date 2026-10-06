package derive

import (
	"reflect"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/extract"
)

func TestNormalizeDNS(t *testing.T) {
	for _, c := range []struct {
		in, name    string
		valid, wild bool
		tld, etld1  any // nil or string
	}{
		{"WWW.Example.COM.", "www.example.com", true, false, "com", "example.com"},
		{"*.example.co.uk", "*.example.co.uk", true, true, "co.uk", "example.co.uk"},
		{"foo_bar.example.com", "foo_bar.example.com", true, false, "com", "example.com"},
		{"xn--caf-dma.example", "xn--caf-dma.example", true, false, "example", "xn--caf-dma.example"},
		{"com", "com", true, false, "com", nil},
		{"localhost", "localhost", true, false, "localhost", nil},
		{"a..b.example", "a..b.example", false, false, nil, nil},
		{strings.Repeat("a", 64) + ".example.com", strings.Repeat("a", 64) + ".example.com", false, false, nil, nil},
		{strings.Repeat("abcdefghi.", 26) + "com", strings.Repeat("abcdefghi.", 26) + "com", false, false, nil, nil},
		{"*.*.example.com", "*.*.example.com", false, false, nil, nil},
		{"bad\\C3\\A9.example", "bad\\C3\\A9.example", false, false, nil, nil},
		{"has space.example", "has space.example", false, false, nil, nil},
	} {
		got := dnsRow(7, "san_dns", c.in)
		want := Row{uint64(7), "san_dns", c.name, c.valid, c.wild, c.tld, c.etld1}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %v, want %v", c.in, got, want)
		}
	}
}

func TestIPNames(t *testing.T) {
	for _, c := range []struct {
		in   []byte
		want string
	}{
		{[]byte{192, 0, 2, 1}, "192.0.2.1"},
		{[]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, "2001:db8::1"},
		{[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1}, "::ffff:192.0.2.1"},
		{[]byte{1, 2, 3, 4, 5}, "0102030405"},
	} {
		if got := ipRow(3, c.in); !reflect.DeepEqual(got, Row{uint64(3), "san_ip", c.want, false, false, nil, nil}) {
			t.Errorf("%x: %v", c.in, got)
		}
	}
}

// cert builds an extract.Cert with the names fields set, for the names
// builder: subject CNs and SANs.
func cert(t *testing.T, cns []string, dns []string, ips [][]byte) *extract.Cert {
	t.Helper()
	c := extract.Parse(nameCert(t, cns))
	c.DNSNames, c.IPAddresses = dns, ips
	return c
}

func TestNameRows(t *testing.T) {
	c := cert(t, []string{"www.example.com", "Example Device 42", "192.0.2.7", "R3", "WWW.example.com"},
		[]string{"www.example.com", "*.example.com"}, [][]byte{{192, 0, 2, 1}})
	got := Names{}.Build(c, Context{CertID: 9})
	want := []Row{
		{uint64(9), "san_dns", "www.example.com", true, false, "com", "example.com"},
		{uint64(9), "san_dns", "*.example.com", true, true, "com", "example.com"},
		{uint64(9), "san_ip", "192.0.2.1", false, false, nil, nil},
		{uint64(9), "cn", "Example Device 42", false, false, nil, nil},
		{uint64(9), "cn", "192.0.2.7", false, false, nil, nil},
		{uint64(9), "cn", "R3", false, false, nil, nil},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rows:\n%v\nwant\n%v", got, want)
	}
	// A CN that only repeats a SAN (after normalization) gets no row, and an
	// IP literal CN that equals an IP SAN is not repeated either.
	c = cert(t, []string{"192.0.2.1"}, nil, [][]byte{{192, 0, 2, 1}})
	if got := (Names{}).Build(c, Context{CertID: 1}); len(got) != 1 {
		t.Errorf("IP CN repeating the SAN: %v", got)
	}
	c = cert(t, []string{"Shop.Example.org"}, nil, nil)
	if got := (Names{}).Build(c, Context{CertID: 1}); !reflect.DeepEqual(got, []Row{{uint64(1), "cn", "shop.example.org", true, false, "org", "example.org"}}) {
		t.Errorf("DNS CN without SANs: %v", got)
	}
}

// TestNormalizeNameMatchesIngest: the exported helpers give what ingest
// stores.
func TestNormalizeNameMatchesIngest(t *testing.T) {
	name, valid, wild, base := NormalizeName("*.API.Example.COM.")
	if name != "*.api.example.com" || !valid || !wild || base != "api.example.com" {
		t.Fatalf("NormalizeName: %q %v %v %q", name, valid, wild, base)
	}
	if e, ok := ETLD1(base); !ok || e != "example.com" {
		t.Fatalf("ETLD1: %q %v", e, ok)
	}
	if _, ok := ETLD1("com"); ok {
		t.Fatal("a public suffix has no registrable domain")
	}
}
