// Package ctlogtest is an in-process fake RFC 6962 CT log backed by a real
// Merkle tree, with fault injection for tests (spec §13.4). It is test
// infrastructure only and must never be imported by production code.
package ctlogtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"
)

// EntryType is the RFC 6962 LogEntryType.
type EntryType uint16

const (
	X509Entry    EntryType = 0
	PrecertEntry EntryType = 1
)

// Entry is one log entry, with both the wire bytes and the parts tests check.
type Entry struct {
	Type          EntryType
	Timestamp     uint64 // ms
	CertDER       []byte // final certificate, or the precertificate for PrecertEntry
	PrecertTBS    []byte // PrecertEntry only: TBS with the poison extension removed
	IssuerKeyHash [32]byte
	LeafInput     []byte // MerkleTreeLeaf
	ExtraData     []byte
}

var (
	poisonOID  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	sctListOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

func appendU24(b, data []byte) []byte {
	n := len(data)
	return append(append(b, byte(n>>16), byte(n>>8), byte(n)), data...)
}

// MerkleTreeLeaf encodes an RFC 6962 §3.4 MerkleTreeLeaf: version v1,
// timestamped_entry, the signed entry, and empty CtExtensions.
func MerkleTreeLeaf(ts uint64, typ EntryType, certOrTBS []byte, issuerKeyHash [32]byte) []byte {
	b := []byte{0, 0}
	b = binary.BigEndian.AppendUint64(b, ts)
	b = binary.BigEndian.AppendUint16(b, uint16(typ))
	if typ == PrecertEntry {
		b = append(b, issuerKeyHash[:]...)
	}
	b = appendU24(b, certOrTBS)
	return binary.BigEndian.AppendUint16(b, 0)
}

// chain encodes a TLS vector<ASN.1Cert> with a 24-bit total length.
func chain(certs ...[]byte) []byte {
	var body []byte
	for _, c := range certs {
		body = appendU24(body, c)
	}
	return appendU24(nil, body)
}

// Generator issues certificates from a throwaway ECDSA CA.
type Generator struct {
	caKey  *ecdsa.PrivateKey
	ca     *x509.Certificate
	serial int64
	t0     time.Time
}

// NewGenerator creates a self-signed test CA.
func NewGenerator() (*Generator, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CTVault Test CA", Organization: []string{"CTVault Tests"}},
		NotBefore: t0.Add(-24 * time.Hour), NotAfter: t0.Add(5 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Generator{caKey: key, ca: ca, serial: 1, t0: t0}, nil
}

// CADER returns the CA certificate.
func (g *Generator) CADER() []byte { return g.ca.Raw }

// Pair issues one certificate as a precert entry and its final x509 entry,
// exactly as RFC 6962 §3.1 describes: the precert TBS with the poison
// extension removed equals the final cert TBS without the SCT list.
func (g *Generator) Pair(name string, ts uint64) (pre, final Entry, err error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return pre, final, err
	}
	g.serial++
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(g.serial), Subject: pkix.Name{CommonName: name},
		DNSNames:  []string{name, "www." + name},
		NotBefore: g.t0, NotAfter: g.t0.Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	issue := func(extra ...pkix.Extension) ([]byte, error) {
		t := tmpl
		t.ExtraExtensions = extra
		return x509.CreateCertificate(rand.Reader, &t, g.ca, &leafKey.PublicKey, g.caKey)
	}
	plainDER, err := issue()
	if err != nil {
		return pre, final, err
	}
	plain, err := x509.ParseCertificate(plainDER)
	if err != nil {
		return pre, final, err
	}
	preDER, err := issue(pkix.Extension{Id: poisonOID, Critical: true, Value: []byte{0x05, 0x00}})
	if err != nil {
		return pre, final, err
	}
	// An empty SignedCertificateTimestampList wrapped in an OCTET STRING.
	finDER, err := issue(pkix.Extension{Id: sctListOID, Value: []byte{0x04, 0x02, 0x00, 0x00}})
	if err != nil {
		return pre, final, err
	}
	ikh := sha256.Sum256(g.ca.RawSubjectPublicKeyInfo)
	pre = Entry{Type: PrecertEntry, Timestamp: ts, CertDER: preDER, PrecertTBS: plain.RawTBSCertificate, IssuerKeyHash: ikh}
	pre.LeafInput = MerkleTreeLeaf(ts, PrecertEntry, plain.RawTBSCertificate, ikh)
	pre.ExtraData = append(appendU24(nil, preDER), chain(g.ca.Raw)...)
	final = Entry{Type: X509Entry, Timestamp: ts + 1000, CertDER: finDER}
	final.LeafInput = MerkleTreeLeaf(ts+1000, X509Entry, finDER, [32]byte{})
	final.ExtraData = chain(g.ca.Raw)
	return pre, final, nil
}

// Entries issues n entries as alternating precert/final pairs (a trailing odd
// entry is a lone precert), named host<i>.example.test.
func (g *Generator) Entries(n int) ([]Entry, error) {
	out := make([]Entry, 0, n)
	for i := 0; len(out) < n; i++ {
		pre, fin, err := g.Pair(fmt.Sprintf("host%d.example.test", i), 1790000000000+uint64(i)*2000)
		if err != nil {
			return nil, err
		}
		out = append(out, pre)
		if len(out) < n {
			out = append(out, fin)
		}
	}
	return out, nil
}
