package derive

import (
	"encoding/hex"
	"time"

	"github.com/4rji/ctvault/internal/extdecode"
	"github.com/4rji/ctvault/internal/extract"
)

// The D tables (amendment A7): built from the extensions the extractor
// keeps, decoded by internal/extdecode. Rows cover every unique certificate,
// in extension or list order. An extension that does not decode gives no
// rows in its table, only its code in cert_extensions.

var (
	CertExtensionsV1 = Table{Name: "cert_extensions", Version: 1, Decoder: extdecode.Version, Columns: []Column{
		{"cert_id", "UBIGINT"}, {"position", "UINTEGER"}, {"oid", "VARCHAR"}, {"critical", "BOOLEAN"},
		{"length", "UINTEGER"}, {"decode_error", "VARCHAR"},
	}}
	CertPoliciesV1 = Table{Name: "cert_policies", Version: 1, Decoder: extdecode.Version, Columns: []Column{
		{"cert_id", "UBIGINT"}, {"position", "UINTEGER"}, {"policy_oid", "VARCHAR"}, {"validation", "VARCHAR"},
		{"cps_uri", "VARCHAR"}, {"n_qualifiers", "UINTEGER"},
	}}
	CertEKUsV1 = Table{Name: "cert_ekus", Version: 1, Decoder: extdecode.Version, Columns: []Column{
		{"cert_id", "UBIGINT"}, {"position", "UINTEGER"}, {"eku_oid", "VARCHAR"}, {"eku_name", "VARCHAR"},
	}}
	CertKeyUsageV1 = Table{Name: "cert_key_usage", Version: 1, Decoder: extdecode.Version, Columns: []Column{
		{"cert_id", "UBIGINT"}, {"digital_signature", "BOOLEAN"}, {"content_commitment", "BOOLEAN"},
		{"key_encipherment", "BOOLEAN"}, {"data_encipherment", "BOOLEAN"}, {"key_agreement", "BOOLEAN"},
		{"key_cert_sign", "BOOLEAN"}, {"crl_sign", "BOOLEAN"}, {"encipher_only", "BOOLEAN"}, {"decipher_only", "BOOLEAN"},
		{"is_ca", "BOOLEAN"}, {"path_len", "USMALLINT"},
	}}
	CertAIAV1 = Table{Name: "cert_aia", Version: 1, Decoder: extdecode.Version, Columns: []Column{
		{"cert_id", "UBIGINT"}, {"position", "UINTEGER"}, {"method", "VARCHAR"}, {"uri", "VARCHAR"},
	}}
	CertCRLDPsV1 = Table{Name: "cert_crl_dps", Version: 1, Decoder: extdecode.Version, Columns: []Column{
		{"cert_id", "UBIGINT"}, {"dp_index", "UINTEGER"}, {"uri", "VARCHAR"}, {"has_reasons", "BOOLEAN"}, {"has_crl_issuer", "BOOLEAN"},
	}}
	CertSCTsV1 = Table{Name: "cert_scts", Version: 1, Decoder: extdecode.Version, Columns: []Column{
		{"cert_id", "UBIGINT"}, {"position", "UINTEGER"}, {"version", "USMALLINT"}, {"log_id", "VARCHAR"},
		{"timestamp", "TIMESTAMP"}, {"hash_alg", "USMALLINT"}, {"sig_alg", "USMALLINT"},
	}}
)

// first returns the value of the certificate's first extension with oid.
func first(c *extract.Cert, oid string) ([]byte, bool) {
	for _, e := range c.Extensions {
		if e.OID == oid {
			return e.Value, true
		}
	}
	return nil, false
}

func strOrNil(s string, ok bool) any {
	if !ok {
		return nil
	}
	return s
}

// CertExtensions builds cert_extensions v1: every extension, and the code
// of each one D decodes that did not decode or repeats an earlier one.
type CertExtensions struct{}

func (CertExtensions) Table() Table { return CertExtensionsV1 }

func (CertExtensions) Build(c *extract.Cert, ctx Context) []Row {
	rows := make([]Row, 0, len(c.Extensions))
	seen := map[string]bool{}
	for i, e := range c.Extensions {
		var code extdecode.Code
		if extdecode.Decoded(e.OID) {
			if seen[e.OID] {
				code = extdecode.Duplicate
			} else {
				code = extdecode.Check(e.OID, e.Value)
			}
			seen[e.OID] = true
		}
		rows = append(rows, Row{ctx.CertID, uint32(i), e.OID, e.Critical, uint32(len(e.Value)), strOrNil(string(code), code != "")})
	}
	return rows
}

// CertPolicies builds cert_policies v1.
type CertPolicies struct{}

func (CertPolicies) Table() Table { return CertPoliciesV1 }

func (CertPolicies) Build(c *extract.Cert, ctx Context) []Row {
	v, ok := first(c, extdecode.OIDPolicies)
	if !ok {
		return nil
	}
	ps, code := extdecode.Policies(v)
	if code != "" {
		return nil
	}
	rows := make([]Row, len(ps))
	for i, p := range ps {
		rows[i] = Row{ctx.CertID, uint32(i), p.OID, strOrNil(p.Validation, p.Validation != ""), strOrNil(p.CPSURI, p.HasCPS), uint32(p.Qualifiers)}
	}
	return rows
}

// CertEKUs builds cert_ekus v1.
type CertEKUs struct{}

func (CertEKUs) Table() Table { return CertEKUsV1 }

func (CertEKUs) Build(c *extract.Cert, ctx Context) []Row {
	v, ok := first(c, extdecode.OIDEKU)
	if !ok {
		return nil
	}
	es, code := extdecode.EKUs(v)
	if code != "" {
		return nil
	}
	rows := make([]Row, len(es))
	for i, e := range es {
		rows[i] = Row{ctx.CertID, uint32(i), e.OID, strOrNil(e.Name, e.Name != "")}
	}
	return rows
}

// CertKeyUsage builds cert_key_usage v1: one row for a certificate whose
// keyUsage or basicConstraints decodes, with the other's columns null.
type CertKeyUsage struct{}

func (CertKeyUsage) Table() Table { return CertKeyUsageV1 }

func (CertKeyUsage) Build(c *extract.Cert, ctx Context) []Row {
	row := Row{ctx.CertID, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil}
	have := false
	if v, ok := first(c, extdecode.OIDKeyUsage); ok {
		if ku, code := extdecode.KeyUsage(v); code == "" {
			for i := 0; i < 9; i++ {
				row[1+i] = ku&(1<<i) != 0
			}
			have = true
		}
	}
	if v, ok := first(c, extdecode.OIDBasicConstraints); ok {
		if bc, code := extdecode.BasicConstraints(v); code == "" {
			row[10] = bc.IsCA
			if bc.PathLen >= 0 {
				row[11] = uint16(bc.PathLen)
			}
			have = true
		}
	}
	if !have {
		return nil
	}
	return []Row{row}
}

// CertAIA builds cert_aia v1.
type CertAIA struct{}

func (CertAIA) Table() Table { return CertAIAV1 }

func (CertAIA) Build(c *extract.Cert, ctx Context) []Row {
	v, ok := first(c, extdecode.OIDAIA)
	if !ok {
		return nil
	}
	as, code := extdecode.AIA(v)
	if code != "" {
		return nil
	}
	rows := make([]Row, len(as))
	for i, a := range as {
		rows[i] = Row{ctx.CertID, uint32(i), a.Method, strOrNil(a.URI, a.HasURI)}
	}
	return rows
}

// CertCRLDPs builds cert_crl_dps v1: a row per URI in a point's fullName,
// and one null row for a point without a URI.
type CertCRLDPs struct{}

func (CertCRLDPs) Table() Table { return CertCRLDPsV1 }

func (CertCRLDPs) Build(c *extract.Cert, ctx Context) []Row {
	v, ok := first(c, extdecode.OIDCRLDPs)
	if !ok {
		return nil
	}
	dps, code := extdecode.CRLDPs(v)
	if code != "" {
		return nil
	}
	var rows []Row
	for i, d := range dps {
		if len(d.URIs) == 0 {
			rows = append(rows, Row{ctx.CertID, uint32(i), nil, d.HasReasons, d.HasCRLIssuer})
		}
		for _, u := range d.URIs {
			rows = append(rows, Row{ctx.CertID, uint32(i), u, d.HasReasons, d.HasCRLIssuer})
		}
	}
	return rows
}

// maxSCTTime is the last instant a TIMESTAMP column holds without
// question; an SCT claiming a later time keeps its other fields and a null
// timestamp.
var maxSCTTime = uint64(time.Date(9999, 12, 31, 23, 59, 59, 999000000, time.UTC).UnixMilli())

// CertSCTs builds cert_scts v1: every embedded SCT; one of another version
// keeps only its version.
type CertSCTs struct{}

func (CertSCTs) Table() Table { return CertSCTsV1 }

func (CertSCTs) Build(c *extract.Cert, ctx Context) []Row {
	v, ok := first(c, extdecode.OIDSCTList)
	if !ok {
		return nil
	}
	ss, code := extdecode.SCTs(v)
	if code != "" {
		return nil
	}
	rows := make([]Row, len(ss))
	for i, s := range ss {
		if !s.V1 {
			rows[i] = Row{ctx.CertID, uint32(i), uint16(s.Version), nil, nil, nil, nil}
			continue
		}
		var ts any
		if s.Timestamp <= maxSCTTime {
			ts = time.UnixMilli(int64(s.Timestamp)).UTC()
		}
		rows[i] = Row{ctx.CertID, uint32(i), uint16(0), hex.EncodeToString(s.LogID[:]), ts, uint16(s.HashAlg), uint16(s.SigAlg)}
	}
	return rows
}
