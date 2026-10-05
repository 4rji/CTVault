package extract

import (
	"bytes"
	"crypto/dsa" //nolint:staticcheck // the reference parser still returns DSA keys
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
)

// x509SigAlgs maps crypto/x509's signature algorithms to the extractor's
// names.
var x509SigAlgs = map[x509.SignatureAlgorithm]string{
	x509.MD2WithRSA: "md2WithRSAEncryption", x509.MD5WithRSA: "md5WithRSAEncryption",
	x509.SHA1WithRSA: "sha1WithRSAEncryption", x509.SHA256WithRSA: "sha256WithRSAEncryption",
	x509.SHA384WithRSA: "sha384WithRSAEncryption", x509.SHA512WithRSA: "sha512WithRSAEncryption",
	x509.SHA256WithRSAPSS: "rsassaPss", x509.SHA384WithRSAPSS: "rsassaPss", x509.SHA512WithRSAPSS: "rsassaPss",
	x509.DSAWithSHA1: "dsa-with-SHA1", x509.DSAWithSHA256: "dsa-with-SHA256",
	x509.ECDSAWithSHA1: "ecdsa-with-SHA1", x509.ECDSAWithSHA256: "ecdsa-with-SHA256",
	x509.ECDSAWithSHA384: "ecdsa-with-SHA384", x509.ECDSAWithSHA512: "ecdsa-with-SHA512",
	x509.PureEd25519: "Ed25519",
}

// plainASCII reports whether a display value is plain ASCII with no escape,
// so it can be compared with crypto/x509's string as is.
func plainASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= 0x80 || s[i] < 0x20 || s[i] == '\\' {
			return false
		}
	}
	return true
}

// count is how many attributes of type oid the name has.
func count(n Name, oid string) int {
	k := 0
	for _, rdn := range n.RDNs {
		for _, a := range rdn {
			if a.Type == oid {
				k++
			}
		}
	}
	return k
}

// compareX509 checks the extractor against crypto/x509 on a certificate both
// parse (amendment A2 §3.4). compared is false when either one fails.
func compareX509(der []byte) (compared bool, diffs []string) {
	ref, err := x509.ParseCertificate(der)
	c := Parse(der)
	if err != nil || c.Status == StatusFailed {
		return false, nil
	}
	diff := func(field string, got, want any) {
		diffs = append(diffs, fmt.Sprintf("%s: %v, crypto/x509 %v", field, got, want))
	}
	if c.Serial != nil && !slices.Contains(c.Errors, SerialNegative) && new(big.Int).SetBytes(c.Serial).Cmp(ref.SerialNumber) != 0 {
		diff("serial", fmt.Sprintf("%x", c.Serial), ref.SerialNumber)
	}
	if !bytes.Equal(c.Issuer.Raw, ref.RawIssuer) {
		diff("issuer DER", fmt.Sprintf("%x", c.Issuer.Raw), fmt.Sprintf("%x", ref.RawIssuer))
	}
	if !bytes.Equal(c.Subject.Raw, ref.RawSubject) {
		diff("subject DER", fmt.Sprintf("%x", c.Subject.Raw), fmt.Sprintf("%x", ref.RawSubject))
	}
	names := []struct {
		field string
		n     Name
		oid   string
		want  []string
	}{
		{"subject CN", c.Subject, OIDCommonName, []string{ref.Subject.CommonName}},
		{"subject O", c.Subject, OIDOrganization, ref.Subject.Organization},
		{"issuer CN", c.Issuer, OIDCommonName, []string{ref.Issuer.CommonName}},
		{"issuer O", c.Issuer, OIDOrganization, ref.Issuer.Organization},
	}
	for _, n := range names {
		want := ""
		if len(n.want) > 0 {
			want = n.want[0]
		}
		if n.oid == OIDCommonName && count(n.n, n.oid) > 1 {
			continue // crypto/x509 keeps the last CN; the extractor reports the first
		}
		switch got, ok := n.n.First(n.oid); {
		case !ok && want != "":
			diff(n.field, "(none)", want)
		case ok && plainASCII(got) && want != "" && got != want:
			diff(n.field, got, want)
		}
	}
	if c.HasNotBefore && !c.NotBefore.Equal(ref.NotBefore) {
		diff("not_before", c.NotBefore, ref.NotBefore)
	}
	if c.HasNotAfter && !c.NotAfter.Equal(ref.NotAfter) {
		diff("not_after", c.NotAfter, ref.NotAfter)
	}
	if !slices.Contains(c.Errors, SANUnreadable) && !slices.Contains(c.Errors, SANDNSBadString) &&
		!slices.ContainsFunc(c.DNSNames, func(s string) bool { return strings.Contains(s, `\`) }) && !slices.Equal(c.DNSNames, ref.DNSNames) {
		diff("DNS SANs", c.DNSNames, ref.DNSNames)
	}
	if !slices.Contains(c.Errors, SANIPBadLen) {
		var ips []net.IP
		for _, ip := range c.IPAddresses {
			ips = append(ips, ip)
		}
		if !slices.EqualFunc(ips, ref.IPAddresses, func(a, b net.IP) bool { return a.Equal(b) }) {
			diff("IP SANs", ips, ref.IPAddresses)
		}
	}
	if want, ok := x509SigAlgs[ref.SignatureAlgorithm]; ok && c.SignatureAlgorithm != want {
		diff("signature algorithm", c.SignatureAlgorithm, want)
	}
	var want Key
	switch pk := ref.PublicKey.(type) {
	case *rsa.PublicKey:
		want = Key{Algorithm: "rsa", Bits: pk.N.BitLen()}
	case *ecdsa.PublicKey:
		want = Key{Algorithm: "ecdsa", Bits: pk.Curve.Params().BitSize, Curve: pk.Curve.Params().Name}
	case ed25519.PublicKey:
		want = Key{Algorithm: "ed25519", Bits: 256}
	case *dsa.PublicKey:
		want = Key{Algorithm: "dsa", Bits: pk.P.BitLen()}
	}
	if want.Algorithm != "" {
		if got := (Key{Algorithm: c.Key.Algorithm, Bits: c.Key.Bits, Curve: c.Key.Curve}); got != want {
			diff("key", got, want)
		}
	}
	if !slices.Contains(c.Errors, SKIUnreadable) && !bytes.Equal(c.SubjectKeyID, ref.SubjectKeyId) {
		diff("SKI", fmt.Sprintf("%x", c.SubjectKeyID), fmt.Sprintf("%x", ref.SubjectKeyId))
	}
	if !slices.Contains(c.Errors, AKIUnreadable) && !bytes.Equal(c.AuthorityKeyID, ref.AuthorityKeyId) {
		diff("AKI", fmt.Sprintf("%x", c.AuthorityKeyID), fmt.Sprintf("%x", ref.AuthorityKeyId))
	}
	return true, diffs
}

// TestDifferentialCorpus: on every corpus certificate that both parse, the
// extractor agrees with crypto/x509.
func TestDifferentialCorpus(t *testing.T) {
	compared := 0
	for i, der := range corpus(t) {
		ok, diffs := compareX509(der)
		if ok {
			compared++
		}
		for _, d := range diffs {
			t.Errorf("certificate %d (%s): %s", i, shaHex(der)[:16], d)
		}
	}
	t.Logf("compared %d certificates with crypto/x509", compared)
	if compared == 0 {
		t.Fatal("nothing was compared")
	}
}
