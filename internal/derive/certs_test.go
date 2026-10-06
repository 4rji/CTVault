package derive

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/extract"
	"github.com/4rji/ctvault/internal/vault"
)

var testKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

// makeCert issues a certificate with crypto/x509.
func makeCert(t *testing.T, edit func(*x509.Certificate)) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x0abc),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		Issuer:       pkix.Name{CommonName: "Test CA", Organization: []string{"Test Org"}},
		NotBefore:    time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		NotAfter:     time.Date(2026, 4, 2, 3, 4, 5, 0, time.UTC),
	}
	if edit != nil {
		edit(tmpl)
	}
	parent := &x509.Certificate{Subject: tmpl.Issuer}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, testKey.Public(), testKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// nameCert issues a certificate whose subject holds these CNs, in order.
func nameCert(t *testing.T, cns []string) []byte {
	return makeCert(t, func(c *x509.Certificate) {
		c.Subject = pkix.Name{}
		for _, cn := range cns {
			c.Subject.ExtraNames = append(c.Subject.ExtraNames, pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: cn})
		}
	})
}

// byName maps a row to its table's column names.
func byName(tb Table, r Row) map[string]any {
	m := map[string]any{}
	for i, c := range tb.Columns {
		m[c.Name] = r[i]
	}
	return m
}

func TestCertRow(t *testing.T) {
	der := makeCert(t, func(c *x509.Certificate) {
		c.DNSNames = []string{"leaf.example.com", "*.leaf.example.com"}
		c.IPAddresses = []net.IP{net.ParseIP("192.0.2.1").To4()}
		c.SubjectKeyId, c.AuthorityKeyId = []byte{1, 2}, []byte{3, 4}
	})
	sum := sha256.Sum256(der)
	ctx := Context{CertID: 5, SHA256: sum, Kind: KindFinal, Loc: vault.Loc{Segment: 2, Offset: 100, Len: 900}, DeltaBaseCertID: 3}
	rows := Certs{}.Build(extract.Parse(der), ctx)
	if len(rows) != 1 || len(rows[0]) != len(CertsV1.Columns) {
		t.Fatalf("rows %v", rows)
	}
	got := byName(CertsV1, rows[0])
	want := map[string]any{
		"cert_id": uint64(5), "sha256": hex.EncodeToString(sum[:]), "kind": "final", "has_ct_poison": false,
		"vault_seg": uint32(2), "vault_off": uint64(100), "vault_len": uint32(900), "delta_base_cert_id": uint64(3),
		"parse_status": "ok", "parse_errors": []string{}, "serial": "0abc",
		"issuer_dn": "CN=Test CA,O=Test Org", "issuer_o": "Test Org", "issuer_cn": "Test CA",
		"authority_key_id": "0304",
		"not_before":       time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), "not_after": time.Date(2026, 4, 2, 3, 4, 5, 0, time.UTC),
		"key_alg": "ecdsa", "key_bits": uint16(256), "key_curve": "P-256", "spki_alg_oid": "1.2.840.10045.2.1",
		"sig_alg": "ecdsa-with-SHA256", "subject_cn": "leaf.example.com", "n_dns_names": uint16(2), "n_ip_names": uint16(1),
		"has_wildcard": true, "subject_key_id": nil, "subject_der": nil,
	}
	ref, _ := x509.ParseCertificate(der)
	want["issuer_der"] = hex.EncodeToString(ref.RawIssuer)
	for k, v := range want {
		if !reflect.DeepEqual(got[k], v) {
			t.Errorf("%s = %#v, want %#v", k, got[k], v)
		}
	}
	if len(want) != len(CertsV1.Columns) {
		t.Errorf("the test checks %d of %d columns", len(want), len(CertsV1.Columns))
	}

	// A chain certificate also records its subject key ID and subject DER.
	ctx.Kind, ctx.DeltaBaseCertID = KindChain, 0
	chain := byName(CertsV1, Certs{}.Build(extract.Parse(der), ctx)[0])
	if chain["subject_key_id"] != "0102" || chain["subject_der"] != hex.EncodeToString(ref.RawSubject) || chain["delta_base_cert_id"] != nil {
		t.Errorf("chain columns: %v %v %v", chain["subject_key_id"], chain["subject_der"], chain["delta_base_cert_id"])
	}
}

// TestFailedCertRow: a certificate nothing can be read from still gets its
// row (spec §7.1: no certificate is ever dropped).
func TestFailedCertRow(t *testing.T) {
	sum := sha256.Sum256([]byte("garbage"))
	row := byName(CertsV1, Certs{}.Build(extract.Parse([]byte("garbage")), Context{CertID: 1, SHA256: sum, Kind: KindPrecert})[0])
	if row["parse_status"] != "failed" || !reflect.DeepEqual(row["parse_errors"], []string{"cert_unreadable"}) || row["kind"] != "precert" {
		t.Fatalf("row %v", row)
	}
	for _, col := range []string{"serial", "issuer_dn", "issuer_der", "not_before", "key_alg", "key_bits", "sig_alg", "subject_cn"} {
		if row[col] != nil {
			t.Errorf("%s = %v, want NULL", col, row[col])
		}
	}
	if row["n_dns_names"] != uint16(0) || row["has_wildcard"] != false {
		t.Errorf("summary columns %v %v", row["n_dns_names"], row["has_wildcard"])
	}
}
