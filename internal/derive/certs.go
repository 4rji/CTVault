package derive

import (
	"encoding/hex"
	"slices"
	"strings"

	"github.com/4rji/ctvault/internal/extract"
)

// CertsV1 is the certs table, version 1: spec §7.3's columns plus
// issuer_der and the chain-only subject_der (amendment A2 §4.2). One row per
// unique certificate, in the batch that first vaulted it.
var CertsV1 = Table{Name: "certs", Version: 1, Columns: []Column{
	{"cert_id", "UBIGINT"}, {"sha256", "VARCHAR"}, {"kind", "VARCHAR"}, {"has_ct_poison", "BOOLEAN"},
	{"vault_seg", "UINTEGER"}, {"vault_off", "UBIGINT"}, {"vault_len", "UINTEGER"}, {"delta_base_cert_id", "UBIGINT"},
	{"parse_status", "VARCHAR"}, {"parse_errors", "VARCHAR[]"},
	{"serial", "VARCHAR"}, {"issuer_dn", "VARCHAR"}, {"issuer_o", "VARCHAR"}, {"issuer_cn", "VARCHAR"}, {"issuer_der", "VARCHAR"},
	{"authority_key_id", "VARCHAR"}, {"not_before", "TIMESTAMP"}, {"not_after", "TIMESTAMP"},
	{"key_alg", "VARCHAR"}, {"key_bits", "USMALLINT"}, {"key_curve", "VARCHAR"}, {"spki_alg_oid", "VARCHAR"}, {"sig_alg", "VARCHAR"},
	{"subject_cn", "VARCHAR"}, {"n_dns_names", "USMALLINT"}, {"n_ip_names", "USMALLINT"}, {"has_wildcard", "BOOLEAN"},
	{"subject_key_id", "VARCHAR"}, {"subject_der", "VARCHAR"},
}}

// Certs builds certs v1.
type Certs struct{}

func (Certs) Table() Table { return CertsV1 }

// orNil returns nil for a zero value, so it is written as NULL.
func orNil[T comparable](v T) any {
	var zero T
	if v == zero {
		return nil
	}
	return v
}

func hexOrNil(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return hex.EncodeToString(b)
}

func count16(n int) uint16 { return uint16(min(n, 0xffff)) }

// Build returns the certificate's single certs row.
func (Certs) Build(c *extract.Cert, ctx Context) []Row {
	errs := make([]string, len(c.Errors))
	for i, e := range c.Errors {
		errs[i] = string(e)
	}
	var issuerDN, issuerO, issuerCN, subjectCN any
	if len(c.Issuer.RDNs) > 0 {
		issuerDN = c.Issuer.String()
	}
	if v, ok := c.Issuer.First(extract.OIDOrganization); ok {
		issuerO = v
	}
	if v, ok := c.Issuer.First(extract.OIDCommonName); ok {
		issuerCN = v
	}
	if v, ok := c.Subject.First(extract.OIDCommonName); ok {
		subjectCN = v
	}
	var notBefore, notAfter any
	if c.HasNotBefore {
		notBefore = c.NotBefore
	}
	if c.HasNotAfter {
		notAfter = c.NotAfter
	}
	var keyBits any
	if c.Key.Bits > 0 {
		keyBits = uint16(min(c.Key.Bits, 0xffff))
	}
	wildcard := slices.ContainsFunc(c.DNSNames, func(n string) bool { return strings.HasPrefix(n, "*.") })
	var subjectKeyID, subjectDER any
	if ctx.Kind == KindChain {
		subjectKeyID, subjectDER = hexOrNil(c.SubjectKeyID), hexOrNil(c.Subject.Raw)
	}
	var serial any
	if c.Serial != nil {
		serial = hex.EncodeToString(c.Serial)
	}
	return []Row{{
		ctx.CertID, hex.EncodeToString(ctx.SHA256[:]), ctx.Kind, c.HasCTPoison,
		uint32(ctx.Loc.Segment), ctx.Loc.Offset, ctx.Loc.Len, orNil(ctx.DeltaBaseCertID),
		string(c.Status), errs,
		serial, issuerDN, issuerO, issuerCN, hexOrNil(c.Issuer.Raw),
		hexOrNil(c.AuthorityKeyID), notBefore, notAfter,
		orNil(c.Key.Algorithm), keyBits, orNil(c.Key.Curve), orNil(c.Key.AlgorithmOID), orNil(c.SignatureAlgorithm),
		subjectCN, count16(len(c.DNSNames)), count16(len(c.IPAddresses)), wildcard,
		subjectKeyID, subjectDER,
	}}
}
