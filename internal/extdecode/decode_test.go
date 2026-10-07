package extdecode

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/4rji/ctvault/internal/extract"
)

// issue makes a certificate from tmpl with Go's own encoder and returns its
// extensions as the extractor keeps them.
func issue(t *testing.T, tmpl *x509.Certificate) []extract.Extension {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.SerialNumber = big.NewInt(7)
	tmpl.Subject = pkix.Name{CommonName: "d.example.test"}
	tmpl.NotBefore, tmpl.NotAfter = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c := extract.Parse(der)
	if c.Status != extract.StatusOK {
		t.Fatalf("extract: %v", c.Errors)
	}
	return c.Extensions
}

func value(t *testing.T, exts []extract.Extension, oid string) []byte {
	t.Helper()
	for _, e := range exts {
		if e.OID == oid {
			return e.Value
		}
	}
	t.Fatalf("no extension %s", oid)
	return nil
}

func oid(t *testing.T, s string) x509.OID {
	o, err := x509.ParseOID(s)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// TestRoundTrips: what Go's encoder writes, the decoders read back
// (amendment A7 §4.1).
func TestRoundTrips(t *testing.T) {
	exts := issue(t, &x509.Certificate{
		Policies:              []x509.OID{oid(t, "2.23.140.1.2.1"), oid(t, "1.3.6.1.4.1.44947.1.1.1"), oid(t, "2.23.140.1.1")},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageAny},
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 11129, 2, 4, 4}, {1, 2, 3, 4}},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCRLSign | x509.KeyUsageDecipherOnly,
		BasicConstraintsValid: true, IsCA: true, MaxPathLen: 3,
		OCSPServer:            []string{"http://ocsp.example.test"},
		IssuingCertificateURL: []string{"http://ca.example.test/i.der", "http://ca2.example.test/i.der"},
		CRLDistributionPoints: []string{"http://crl.example.test/1.crl", "http://crl.example.test/2.crl"},
	})

	ps, code := Policies(value(t, exts, OIDPolicies))
	if code != "" || len(ps) != 3 || ps[0].OID != "2.23.140.1.2.1" || ps[0].Validation != "dv" ||
		ps[1].Validation != "" || ps[2].Validation != "ev" || ps[0].HasCPS || ps[0].Qualifiers != 0 {
		t.Fatalf("policies %+v %q", ps, code)
	}
	es, code := EKUs(value(t, exts, OIDEKU))
	var names, oids []string
	for _, e := range es {
		names, oids = append(names, e.Name), append(oids, e.OID)
	}
	if code != "" || !slices.Equal(names, []string{"server_auth", "client_auth", "any", "precert_signing", ""}) || oids[4] != "1.2.3.4" {
		t.Fatalf("ekus %+v %q", es, code)
	}
	ku, code := KeyUsage(value(t, exts, OIDKeyUsage))
	if code != "" || ku != uint16(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment|x509.KeyUsageCRLSign|x509.KeyUsageDecipherOnly) {
		t.Fatalf("key usage %09b %q", ku, code)
	}
	bc, code := BasicConstraints(value(t, exts, OIDBasicConstraints))
	if code != "" || !bc.IsCA || bc.PathLen != 3 {
		t.Fatalf("basic constraints %+v %q", bc, code)
	}
	as, code := AIA(value(t, exts, OIDAIA))
	if code != "" || len(as) != 3 || as[0] != (Access{Method: "ocsp", URI: "http://ocsp.example.test", HasURI: true}) || as[2].Method != "ca_issuers" || as[2].URI != "http://ca2.example.test/i.der" {
		t.Fatalf("aia %+v %q", as, code)
	}
	dps, code := CRLDPs(value(t, exts, OIDCRLDPs))
	if code != "" || len(dps) != 2 || !slices.Equal(dps[1].URIs, []string{"http://crl.example.test/2.crl"}) || dps[0].HasReasons || dps[0].HasCRLIssuer {
		t.Fatalf("crl dps %+v %q", dps, code)
	}

	leafExts := issue(t, &x509.Certificate{BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature})
	if bc, code := BasicConstraints(value(t, leafExts, OIDBasicConstraints)); code != "" || bc.IsCA || bc.PathLen != -1 {
		t.Fatalf("a leaf's basic constraints %+v %q", bc, code)
	}
	zero := issue(t, &x509.Certificate{BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true})
	if bc, code := BasicConstraints(value(t, zero, OIDBasicConstraints)); code != "" || bc.PathLen != 0 {
		t.Fatalf("pathLen 0 %+v %q", bc, code)
	}
}

// der builds DER with a cryptobyte builder.
func der(f func(b *cryptobyte.Builder)) []byte {
	var b cryptobyte.Builder
	f(&b)
	return b.BytesOrPanic()
}

// TestQualifiersAndPoints: CPS qualifiers, and CRL points with reasons, a
// cRLIssuer and a name that is not a URI, which Go's encoder never writes.
func TestQualifiersAndPoints(t *testing.T) {
	cps := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1}
	notice := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 2}
	v := der(func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{2, 23, 140, 1, 2, 2})
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // a user notice first
						b.AddASN1ObjectIdentifier(notice)
						b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {})
					})
					for _, u := range []string{"https://cps.example.test/\xe9", "https://second.example.test/"} {
						b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
							b.AddASN1ObjectIdentifier(cps)
							b.AddASN1(cbasn1.IA5String, func(b *cryptobyte.Builder) { b.AddBytes([]byte(u)) })
						})
					}
				})
			})
		})
	})
	ps, code := Policies(v)
	if code != "" || len(ps) != 1 || ps[0].Validation != "ov" || !ps[0].HasCPS || ps[0].CPSURI != `https://cps.example.test/\E9` || ps[0].Qualifiers != 3 {
		t.Fatalf("policies %+v %q", ps, code)
	}

	uri := cbasn1.Tag(6).ContextSpecific()
	dns := cbasn1.Tag(2).ContextSpecific()
	v = der(func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // a DNS name, then a URI, reasons, cRLIssuer
				b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
					b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddASN1(dns, func(b *cryptobyte.Builder) { b.AddBytes([]byte("crl.example.test")) })
						b.AddASN1(uri, func(b *cryptobyte.Builder) { b.AddBytes([]byte("http://crl.example.test/a.crl")) })
					})
				})
				b.AddASN1(cbasn1.Tag(1).ContextSpecific(), func(b *cryptobyte.Builder) { b.AddBytes([]byte{7, 0x80}) })
				b.AddASN1(cbasn1.Tag(2).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
					b.AddASN1(uri, func(b *cryptobyte.Builder) { b.AddBytes([]byte("http://issuer.example.test/")) })
				})
			})
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // only a cRLIssuer: no URI
				b.AddASN1(cbasn1.Tag(2).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
					b.AddASN1(dns, func(b *cryptobyte.Builder) { b.AddBytes([]byte("issuer.example.test")) })
				})
			})
		})
	})
	dps, code := CRLDPs(v)
	if code != "" || len(dps) != 2 || !slices.Equal(dps[0].URIs, []string{"http://crl.example.test/a.crl"}) || !dps[0].HasReasons || !dps[0].HasCRLIssuer ||
		len(dps[1].URIs) != 0 || dps[1].HasReasons || !dps[1].HasCRLIssuer {
		t.Fatalf("crl dps %+v %q", dps, code)
	}

	// An AIA location that is not a URI keeps its method, without a URI.
	v = der(func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 5})
				b.AddASN1(dns, func(b *cryptobyte.Builder) { b.AddBytes([]byte("repo.example.test")) })
			})
		})
	})
	if as, code := AIA(v); code != "" || len(as) != 1 || as[0] != (Access{Method: "1.3.6.1.5.5.7.48.5"}) {
		t.Fatalf("aia %+v %q", as, code)
	}
}

// TestMeaningNeutral: an explicit cA FALSE (DER omits defaults) and a
// keyUsage with trailing zero bits decode (amendment A7 §2).
func TestMeaningNeutral(t *testing.T) {
	explicit := der(func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1Boolean(false) })
	})
	if bc, code := BasicConstraints(explicit); code != "" || bc.IsCA || bc.PathLen != -1 {
		t.Fatalf("explicit cA FALSE: %+v %q", bc, code)
	}
	// digitalSignature with 7 trailing zero bits spelled out in a second byte.
	if ku, code := KeyUsage([]byte{0x03, 0x03, 0x00, 0x80, 0x00}); code != "" || ku != 1 {
		t.Fatalf("trailing zero bits: %b %q", ku, code)
	}
}
