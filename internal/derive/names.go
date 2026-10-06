package derive

import (
	"encoding/hex"
	"net/netip"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/4rji/ctvault/internal/extract"
)

// NamesV1 is the names table, version 1 (spec §7.4): one row per name per
// certificate, in order: dNSName SANs, then iPAddress SANs, both in SAN
// order, then the subject CNs that differ from every SAN.
var NamesV1 = Table{Name: "names", Version: 1, PSL: PSLSnapshot, Columns: []Column{
	{"cert_id", "UBIGINT"}, {"source", "VARCHAR"}, {"name", "VARCHAR"}, {"dns_valid", "BOOLEAN"},
	{"is_wildcard", "BOOLEAN"}, {"tld", "VARCHAR"}, {"etld1", "VARCHAR"},
}}

// Names builds names v1.
type Names struct{}

func (Names) Table() Table { return NamesV1 }

// Build returns the certificate's names rows.
func (Names) Build(c *extract.Cert, ctx Context) []Row {
	var rows []Row
	seen := map[string]bool{}
	for _, n := range c.DNSNames {
		r := dnsRow(ctx.CertID, "san_dns", n)
		rows = append(rows, r)
		seen[r[2].(string)] = true
	}
	for _, ip := range c.IPAddresses {
		r := ipRow(ctx.CertID, ip)
		rows = append(rows, r)
		seen[r[2].(string)] = true
	}
	for _, cn := range c.Subject.Values(extract.OIDCommonName) {
		r := cnRow(ctx.CertID, cn)
		if name := r[2].(string); !seen[name] {
			rows = append(rows, r)
			seen[name] = true
		}
	}
	return rows
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func validLabel(l string) bool {
	if len(l) < 1 || len(l) > 63 {
		return false
	}
	for i := range len(l) {
		c := l[i]
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// normalizeDNS lowercases ASCII and strips one trailing dot (spec §7.4).
// dns_valid is lenient: labels of 1-63 letters, digits, "-" and "_", at most
// 253 characters, and a leftmost "*" label sets is_wildcard. base is the
// name without "*.". A name that already carries \XX escapes (undecodable
// bytes) is kept as is and is not valid.
func normalizeDNS(s string) (name string, valid, wild bool, base string) {
	if strings.ContainsRune(s, '\\') {
		return s, false, false, ""
	}
	name = strings.TrimSuffix(lowerASCII(s), ".")
	labels := strings.Split(name, ".")
	if len(labels) > 1 && labels[0] == "*" {
		wild, labels = true, labels[1:]
	}
	valid = len(name) <= 253
	for _, l := range labels {
		valid = valid && validLabel(l)
	}
	if !valid {
		return name, false, false, ""
	}
	return name, true, wild, strings.Join(labels, ".")
}

// suffixes returns tld (the public suffix) and etld1 for a valid base name;
// etld1 is nil when the name has no registrable domain.
func suffixes(base string) (tld, etld1 any) {
	suffix, _ := publicsuffix.PublicSuffix(base)
	tld = suffix
	if d, err := publicsuffix.EffectiveTLDPlusOne(base); err == nil {
		etld1 = d
	}
	return tld, etld1
}

func dnsRow(certID uint64, source, s string) Row {
	name, valid, wild, base := normalizeDNS(s)
	if !valid {
		return Row{certID, source, name, false, false, nil, nil}
	}
	tld, etld1 := suffixes(base)
	return Row{certID, source, name, true, wild, tld, etld1}
}

// ipRow renders an iPAddress SAN: 4 bytes as a dotted quad, 16 bytes in RFC
// 5952 form, any other length as hex (the certificate carries
// san_ip_bad_len).
func ipRow(certID uint64, b []byte) Row {
	var name string
	switch len(b) {
	case 4:
		name = netip.AddrFrom4([4]byte(b)).String()
	case 16:
		name = netip.AddrFrom16([16]byte(b)).String()
	default:
		name = hex.EncodeToString(b)
	}
	return Row{certID, "san_ip", name, false, false, nil, nil}
}

// cnRow normalizes a subject CN: an IP literal in canonical form, a DNS name
// (one with a dot, or a wildcard) like a dNSName SAN, and anything else
// exactly as decoded with dns_valid false.
func cnRow(certID uint64, cn string) Row {
	if !strings.ContainsRune(cn, '\\') {
		if a, err := netip.ParseAddr(cn); err == nil {
			return Row{certID, "cn", a.String(), false, false, nil, nil}
		}
		if name, valid, wild, base := normalizeDNS(cn); valid && (wild || strings.Contains(base, ".")) {
			tld, etld1 := suffixes(base)
			return Row{certID, "cn", name, true, wild, tld, etld1}
		}
	}
	return Row{certID, "cn", cn, false, false, nil, nil}
}

// NormalizeName normalizes a name as ingest does for dNSName SANs, so a
// search argument and the stored names compare equal (amendment A3 §3.1).
// base is the name without a leading "*.".
func NormalizeName(s string) (name string, valid, wildcard bool, base string) {
	return normalizeDNS(s)
}

// ETLD1 is the registrable domain of a valid base name, as names.etld1
// stores it; ok is false when the name has none.
func ETLD1(base string) (string, bool) {
	_, e := suffixes(base)
	s, ok := e.(string)
	return s, ok
}
