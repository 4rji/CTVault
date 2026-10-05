package extract

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"reflect"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var testRSA = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

// selfSigned makes a certificate with crypto/x509, the reference parser.
func selfSigned(t *testing.T, key crypto.Signer, edit func(*x509.Certificate)) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x1234567890),
		Subject:      pkix.Name{CommonName: "leaf.example.com", Organization: []string{"Example Org"}},
		Issuer:       pkix.Name{CommonName: "leaf.example.com", Organization: []string{"Example Org"}},
		NotBefore:    time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		NotAfter:     time.Date(2026, 4, 2, 3, 4, 5, 0, time.UTC),
		DNSNames:     []string{"leaf.example.com"},
	}
	if edit != nil {
		edit(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParseValidCertificates(t *testing.T) {
	ec256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ec384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	for _, c := range []struct {
		name   string
		key    crypto.Signer
		sigAlg string
		key2   Key
	}{
		{"rsa", testRSA, "sha256WithRSAEncryption", Key{AlgorithmOID: "1.2.840.113549.1.1.1", Algorithm: "rsa", Bits: 2048}},
		{"p256", ec256, "ecdsa-with-SHA256", Key{AlgorithmOID: "1.2.840.10045.2.1", Algorithm: "ecdsa", Bits: 256, Curve: "P-256"}},
		{"p384", ec384, "ecdsa-with-SHA384", Key{AlgorithmOID: "1.2.840.10045.2.1", Algorithm: "ecdsa", Bits: 384, Curve: "P-384"}},
		{"ed25519", ed, "Ed25519", Key{AlgorithmOID: "1.3.101.112", Algorithm: "ed25519", Bits: 256}},
	} {
		t.Run(c.name, func(t *testing.T) {
			der := selfSigned(t, c.key, nil)
			ref, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			got := Parse(der)
			if got.Status != StatusOK || len(got.Errors) != 0 {
				t.Fatalf("status %s, errors %v", got.Status, got.Errors)
			}
			if got.Version != 3 || !bytes.Equal(got.Serial, ref.SerialNumber.Bytes()) || got.SignatureAlgorithm != c.sigAlg {
				t.Errorf("version %d, serial %x, sig %q", got.Version, got.Serial, got.SignatureAlgorithm)
			}
			if !bytes.Equal(got.Issuer.Raw, ref.RawIssuer) || !bytes.Equal(got.Subject.Raw, ref.RawSubject) {
				t.Error("names are not the exact DER")
			}
			if cn, _ := got.Subject.First(OIDCommonName); cn != "leaf.example.com" {
				t.Errorf("subject CN %q", cn)
			}
			if !got.HasNotBefore || !got.NotBefore.Equal(ref.NotBefore) || !got.HasNotAfter || !got.NotAfter.Equal(ref.NotAfter) {
				t.Errorf("validity %v %v", got.NotBefore, got.NotAfter)
			}
			if got.Key != c.key2 {
				t.Errorf("key %+v, want %+v", got.Key, c.key2)
			}
			if again := Parse(der); !reflect.DeepEqual(got, again) {
				t.Error("two parses differ")
			}
		})
	}
}

// parts are a certificate's elements, so a test can replace one of them.
type parts struct {
	version, serial, sigAlg, issuer, validity, subject, spki []byte
	extra                                                    [][]byte
	outerSigAlg, signature                                   []byte
	trailing                                                 []byte
}

func element(tag cbasn1.Tag, content []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(tag, func(b *cryptobyte.Builder) { b.AddBytes(content) })
	return b.BytesOrPanic()
}

func seq(elems ...[]byte) []byte { return element(cbasn1.SEQUENCE, bytes.Join(elems, nil)) }

func oidElem(oid asn1.ObjectIdentifier) []byte {
	var b cryptobyte.Builder
	b.AddASN1ObjectIdentifier(oid)
	return b.BytesOrPanic()
}

func validParts(t *testing.T) parts {
	t.Helper()
	ref, _ := x509.ParseCertificate(selfSigned(t, testRSA, nil))
	s := cryptobyte.String(ref.RawTBSCertificate)
	var tbs cryptobyte.String
	s.ReadASN1(&tbs, cbasn1.SEQUENCE)
	var els [][]byte
	for !tbs.Empty() {
		var e cryptobyte.String
		var tag cbasn1.Tag
		tbs.ReadAnyASN1Element(&e, &tag)
		els = append(els, e)
	}
	sigAlg := seq(oidElem(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}), []byte{0x05, 0x00})
	return parts{version: els[0], serial: els[1], sigAlg: els[2], issuer: els[3], validity: els[4], subject: els[5], spki: els[6],
		extra: els[7:], outerSigAlg: sigAlg, signature: element(cbasn1.BIT_STRING, []byte{0x00, 0xAA})}
}

func (p parts) der() []byte {
	tbs := seq(append([][]byte{p.version, p.serial, p.sigAlg, p.issuer, p.validity, p.subject, p.spki}, p.extra...)...)
	return append(seq(tbs, p.outerSigAlg, p.signature), p.trailing...)
}

func TestParseFailsOnlyOnStructure(t *testing.T) {
	if c := Parse([]byte{0x31, 0x00}); c.Status != StatusFailed || !slices.Equal(c.Errors, []Code{CertUnreadable}) {
		t.Errorf("not a SEQUENCE: %s %v", c.Status, c.Errors)
	}
	if c := Parse(nil); c.Status != StatusFailed {
		t.Errorf("empty input: %s", c.Status)
	}
	p := validParts(t)
	p.spki = nil // five TBS fields only
	if c := Parse(p.der()); c.Status != StatusFailed || !slices.Equal(c.Errors, []Code{TBSUnreadable}) {
		t.Errorf("short TBS: %s %v", c.Status, c.Errors)
	}
	p = validParts(t)
	p.extra = append([][]byte{seq()}, p.extra...) // an unknown element before the extensions
	if c := Parse(p.der()); c.Status != StatusPartial || !slices.Equal(c.Errors, []Code{TBSExtraFields}) || c.Key.Bits != 2048 {
		t.Errorf("extra TBS field: %s %v", c.Status, c.Errors)
	}
	p = validParts(t)
	p.extra = [][]byte{{0xA3, 0x10, 0x30, 0x01}} // an extensions field whose length runs past the TBS
	if c := Parse(p.der()); c.Status != StatusPartial || !slices.Equal(c.Errors, []Code{ExtensionsUnreadable}) || c.Key.Bits != 2048 {
		t.Errorf("unreadable element after the fixed fields: %s %v %+v", c.Status, c.Errors, c.Key)
	}
	p = validParts(t)
	p.trailing = []byte{0x00}
	if c := Parse(p.der()); c.Status != StatusPartial || !slices.Equal(c.Errors, []Code{CertTrailingData}) || c.Key.Bits != 2048 {
		t.Errorf("trailing data: %s %v %+v", c.Status, c.Errors, c.Key)
	}
	p = validParts(t)
	p.signature = element(cbasn1.OCTET_STRING, []byte{1})
	if c := Parse(p.der()); c.Status != StatusPartial || !slices.Equal(c.Errors, []Code{SignatureUnreadable}) || c.Serial == nil {
		t.Errorf("bad signature value: %s %v", c.Status, c.Errors)
	}
}

func TestSerialChecks(t *testing.T) {
	long := bytes.Repeat([]byte{0x01}, 21)
	for _, c := range []struct {
		content []byte
		codes   []Code
	}{
		{[]byte{0x01}, nil},
		{[]byte{0x00, 0x80}, nil}, // minimal: the 0x00 keeps it positive
		{[]byte{0x00}, []Code{SerialZero}},
		{[]byte{0x80}, []Code{SerialNegative}},
		{[]byte{0x00, 0x01}, []Code{SerialNotMinimal}},
		{[]byte{0xFF, 0x80}, []Code{SerialNegative, SerialNotMinimal}},
		{long, []Code{SerialTooLong}},
		{[]byte{}, []Code{SerialUnreadable}},
	} {
		p := validParts(t)
		p.serial = element(cbasn1.INTEGER, c.content)
		got := Parse(p.der())
		if !slices.Equal(got.Errors, c.codes) {
			t.Errorf("serial %x: codes %v, want %v", c.content, got.Errors, c.codes)
		}
		if len(c.content) > 0 && !bytes.Equal(got.Serial, c.content) {
			t.Errorf("serial %x: kept %x, want the raw content", c.content, got.Serial)
		}
	}
	p := validParts(t)
	p.serial = element(cbasn1.OCTET_STRING, []byte{1})
	if got := Parse(p.der()); got.Serial != nil || !slices.Equal(got.Errors, []Code{SerialUnreadable}) {
		t.Errorf("wrong tag: %x %v", got.Serial, got.Errors)
	}
}

func TestVersion(t *testing.T) {
	explicit := func(v byte) []byte {
		return element(cbasn1.Tag(0).Constructed().ContextSpecific(), element(cbasn1.INTEGER, []byte{v}))
	}
	for _, c := range []struct {
		version []byte
		want    int
		codes   []Code
	}{
		{explicit(2), 3, nil},
		{explicit(0), 1, nil},
		{explicit(5), 0, []Code{VersionBad}},
	} {
		p := validParts(t)
		p.version = c.version
		if got := Parse(p.der()); got.Version != c.want || !slices.Equal(got.Errors, c.codes) {
			t.Errorf("version element %x: %d %v", c.version, got.Version, got.Errors)
		}
	}
	p := validParts(t)
	p.version = nil // absent: v1
	if got := Parse(p.der()); got.Version != 1 || len(got.Errors) != 0 || got.Key.Bits != 2048 {
		t.Errorf("absent version: %d %v", got.Version, got.Errors)
	}
}

func TestValidityTimes(t *testing.T) {
	utc := func(s string) []byte { return element(cbasn1.UTCTime, []byte(s)) }
	gen := func(s string) []byte { return element(cbasn1.GeneralizedTime, []byte(s)) }
	good := utc("260102030405Z")
	for _, c := range []struct {
		name string
		t    []byte
		want time.Time
		ok   bool
	}{
		{"UTCTime 20xx", utc("250101000000Z"), time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), true},
		{"UTCTime 19xx", utc("500101000000Z"), time.Date(1950, 1, 1, 0, 0, 0, 0, time.UTC), true},
		{"GeneralizedTime", gen("20500101000000Z"), time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC), true},
		{"no seconds", utc("2501010000Z"), time.Time{}, false},
		{"offset", utc("250101000000+0000"), time.Time{}, false},
		{"fraction", gen("20500101000000.5Z"), time.Time{}, false},
		{"month 13", utc("251301000000Z"), time.Time{}, false},
		{"February 30", utc("250230000000Z"), time.Time{}, false},
		{"not digits", utc("25010100000AZ"), time.Time{}, false},
		{"wrong tag", element(cbasn1.OCTET_STRING, []byte("250101000000Z")), time.Time{}, false},
	} {
		p := validParts(t)
		p.validity = seq(c.t, good)
		got := Parse(p.der())
		if got.HasNotBefore != c.ok || !got.NotBefore.Equal(c.want) {
			t.Errorf("%s: %v %v", c.name, got.HasNotBefore, got.NotBefore)
		}
		if c.ok == slices.Contains(got.Errors, TimeBadFormat) {
			t.Errorf("%s: codes %v", c.name, got.Errors)
		}
		if !got.HasNotAfter {
			t.Errorf("%s: notAfter lost", c.name)
		}
	}
	p := validParts(t)
	p.validity = seq(good)
	if got := Parse(p.der()); !slices.Equal(got.Errors, []Code{ValidityUnreadable}) || got.HasNotBefore || got.HasNotAfter {
		t.Errorf("one time only: %v", got.Errors)
	}
}

func TestSignatureAlgorithm(t *testing.T) {
	p := validParts(t)
	p.outerSigAlg = seq(oidElem(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}), []byte{0x05, 0x00})
	if got := Parse(p.der()); !slices.Equal(got.Errors, []Code{SigAlgMismatch}) || got.SignatureAlgorithm != "sha256WithRSAEncryption" {
		t.Errorf("mismatch: %v %q", got.Errors, got.SignatureAlgorithm)
	}
	p = validParts(t)
	p.sigAlg = seq(oidElem(asn1.ObjectIdentifier{1, 2, 3, 4}))
	p.outerSigAlg = p.sigAlg
	if got := Parse(p.der()); len(got.Errors) != 0 || got.SignatureAlgorithm != "1.2.3.4" {
		t.Errorf("unknown algorithm: %v %q", got.Errors, got.SignatureAlgorithm)
	}
	p = validParts(t)
	p.sigAlg = element(cbasn1.OCTET_STRING, nil)
	if got := Parse(p.der()); !slices.Contains(got.Errors, SigAlgUnreadable) || got.SignatureAlgorithm != "" {
		t.Errorf("unreadable: %v %q", got.Errors, got.SignatureAlgorithm)
	}
}

func TestNamesInACertificate(t *testing.T) {
	p := validParts(t)
	p.issuer = element(cbasn1.SET, nil)
	if got := Parse(p.der()); !slices.Equal(got.Errors, []Code{IssuerUnreadable}) || !bytes.Equal(got.Issuer.Raw, p.issuer) {
		t.Errorf("issuer: %v", got.Errors)
	}
	p = validParts(t)
	p.subject = buildName([]atv{{oidCN, str(tagUTF8, "bad\xff")}})
	if got := Parse(p.der()); !slices.Equal(got.Errors, []Code{NameBadString}) {
		t.Errorf("subject: %v", got.Errors)
	}
}

func spki(alg []byte, key []byte) []byte {
	return seq(alg, element(cbasn1.BIT_STRING, append([]byte{0x00}, key...)))
}

func TestPublicKeys(t *testing.T) {
	rsaKey := func(modulus []byte) []byte {
		return seq(element(cbasn1.INTEGER, modulus), element(cbasn1.INTEGER, []byte{1, 0, 1}))
	}
	rsaAlg := seq(oidElem(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}), []byte{0x05, 0x00})
	ecAlg := func(curve asn1.ObjectIdentifier) []byte {
		return seq(oidElem(asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}), oidElem(curve))
	}
	point := append([]byte{0x04}, make([]byte, 64)...)
	dsaParams := seq(element(cbasn1.INTEGER, append([]byte{0x00, 0x80}, make([]byte, 127)...)), element(cbasn1.INTEGER, []byte{1}), element(cbasn1.INTEGER, []byte{2}))
	for _, c := range []struct {
		name  string
		spki  []byte
		want  Key
		codes []Code
	}{
		{"rsa with a sign byte", spki(rsaAlg, rsaKey(append([]byte{0x00, 0xC0}, make([]byte, 255)...))),
			Key{AlgorithmOID: "1.2.840.113549.1.1.1", Algorithm: "rsa", Bits: 2048}, nil},
		{"rsa unreadable", spki(rsaAlg, []byte{0x01}), Key{AlgorithmOID: "1.2.840.113549.1.1.1", Algorithm: "rsa"}, []Code{KeyUnreadable}},
		{"secp256k1", spki(ecAlg(asn1.ObjectIdentifier{1, 3, 132, 0, 10}), point),
			Key{AlgorithmOID: "1.2.840.10045.2.1", Algorithm: "ecdsa", Bits: 256, Curve: "secp256k1"}, nil},
		{"unknown curve", spki(ecAlg(asn1.ObjectIdentifier{1, 2, 3}), point),
			Key{AlgorithmOID: "1.2.840.10045.2.1", Algorithm: "ecdsa", Bits: 256, Curve: "1.2.3"}, nil},
		{"explicit curve parameters", spki(seq(oidElem(asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}), seq()), point),
			Key{AlgorithmOID: "1.2.840.10045.2.1", Algorithm: "ecdsa", Bits: 256}, []Code{KeyUnreadable}},
		{"ed448", spki(seq(oidElem(asn1.ObjectIdentifier{1, 3, 101, 113})), make([]byte, 57)),
			Key{AlgorithmOID: "1.3.101.113", Algorithm: "ed448", Bits: 456}, nil},
		{"ed25519 wrong length", spki(seq(oidElem(asn1.ObjectIdentifier{1, 3, 101, 112})), make([]byte, 31)),
			Key{AlgorithmOID: "1.3.101.112", Algorithm: "ed25519"}, []Code{KeyUnreadable}},
		{"dsa", spki(seq(oidElem(asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}), dsaParams), element(cbasn1.INTEGER, []byte{5})),
			Key{AlgorithmOID: "1.2.840.10040.4.1", Algorithm: "dsa", Bits: 1024}, nil},
		{"other", spki(seq(oidElem(asn1.ObjectIdentifier{1, 2, 3, 4, 5})), []byte{1, 2}),
			Key{AlgorithmOID: "1.2.3.4.5", Algorithm: "other"}, nil},
		{"unreadable", element(cbasn1.OCTET_STRING, nil), Key{}, []Code{SPKIUnreadable}},
	} {
		p := validParts(t)
		p.spki = c.spki
		got := Parse(p.der())
		if got.Key != c.want || !slices.Equal(got.Errors, c.codes) {
			t.Errorf("%s: %+v %v, want %+v %v", c.name, got.Key, got.Errors, c.want, c.codes)
		}
	}
}
