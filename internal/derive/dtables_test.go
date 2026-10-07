package derive

import (
	"bytes"
	"encoding/binary"
	"slices"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/extdecode"
	"github.com/4rji/ctvault/internal/extract"
)

// TestRegistryOrder: the D tables follow certs and names (amendment A7 §3).
func TestRegistryOrder(t *testing.T) {
	var names []string
	for _, b := range Builders {
		names = append(names, b.Table().Name)
	}
	want := []string{"certs", "names", "cert_extensions", "cert_policies", "cert_ekus", "cert_key_usage", "cert_aia", "cert_crl_dps", "cert_scts"}
	if !slices.Equal(names, want) {
		t.Fatalf("registry %v", names)
	}
}

// TestDecoderMetadata: D tables record ctvault.decoder; certs and names
// keep their metadata, so their files keep their bytes (amendment A7 §3).
func TestDecoderMetadata(t *testing.T) {
	for _, b := range Builders {
		tb := b.Table()
		var decoder string
		n := 0
		for _, kv := range tb.KV() {
			if kv[0] == "ctvault.decoder" {
				decoder = kv[1]
				n++
			}
		}
		switch tb.Name {
		case "certs", "names":
			if n != 0 || len(tb.KV()) != 5 {
				t.Errorf("%s gained metadata: %v", tb.Name, tb.KV())
			}
		default:
			if decoder != extdecode.Version || n != 1 || tb.KV()[5][0] != "ctvault.decoder" {
				t.Errorf("%s decoder metadata: %v", tb.Name, tb.KV())
			}
		}
	}
}

func ext(oid string, critical bool, v []byte) extract.Extension {
	return extract.Extension{OID: oid, Critical: critical, Value: v}
}

func scts(items ...[]byte) []byte {
	var list []byte
	for _, s := range items {
		list = binary.BigEndian.AppendUint16(list, uint16(len(s)))
		list = append(list, s...)
	}
	inner := append(binary.BigEndian.AppendUint16(nil, uint16(len(list))), list...)
	return append([]byte{0x04, byte(len(inner))}, inner...)
}

func sct(id byte, ts uint64) []byte {
	b := append([]byte{0}, bytes.Repeat([]byte{id}, 32)...)
	b = binary.BigEndian.AppendUint64(b, ts)
	return append(b, 0, 0, 4, 3, 0, 1, 9)
}

// build runs every D builder on one certificate.
func build(c *extract.Cert) map[string][]Row {
	out := map[string][]Row{}
	for _, b := range Builders {
		if n := b.Table().Name; n != "certs" && n != "names" {
			out[n] = b.Build(c, Context{CertID: 42, Kind: KindFinal})
		}
	}
	return out
}

// TestDRows: one certificate per rule of amendment A7 §1-§2.
func TestDRows(t *testing.T) {
	ku := []byte{0x03, 0x02, 0x05, 0xa0}                                                  // digitalSignature, keyEncipherment
	bcCA := []byte{0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x02}                        // CA, pathLen 2
	eku := []byte{0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01} // serverAuth
	policies := []byte{0x30, 0x0a, 0x30, 0x08, 0x06, 0x06, 0x67, 0x81, 0x0c, 0x01, 0x02, 0x01}
	aia := []byte{0x30, 0x24, 0x30, 0x22, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x16,
		'h', 't', 't', 'p', ':', '/', '/', 'c', 'a', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '/', 'i', '.', 'c', 'r'}
	crlNoURI := []byte{0x30, 0x02, 0x30, 0x00} // one point with no name at all
	far := uint64(300000000000000)             // after year 9999

	c := &extract.Cert{Extensions: []extract.Extension{
		ext(extdecode.OIDKeyUsage, true, ku),
		ext(extdecode.OIDBasicConstraints, true, bcCA),
		ext(extdecode.OIDEKU, false, eku),
		ext(extdecode.OIDPolicies, false, policies),
		ext(extdecode.OIDAIA, false, aia),
		ext(extdecode.OIDCRLDPs, false, crlNoURI),
		ext(extdecode.OIDSCTList, false, scts(sct(0xaa, 1791346973252), append([]byte{1}, 1, 2, 3), sct(0xbb, far))),
		ext(extdecode.OIDEKU, false, []byte{0x30, 0x00}), // a second EKU: ext_duplicate
		ext("2.5.29.17", false, []byte{0x30, 0x00}),
	}}
	r := build(c)
	if got := r["cert_extensions"]; len(got) != 9 || got[0][1] != uint32(0) || got[0][2] != extdecode.OIDKeyUsage || got[0][3] != true || got[0][4] != uint32(4) ||
		got[0][5] != nil || got[7][5] != string(extdecode.Duplicate) || got[8][5] != nil {
		t.Fatalf("cert_extensions %v", got)
	}
	if got := r["cert_key_usage"]; len(got) != 1 || !slices.Equal(got[0], Row{uint64(42), true, false, true, false, false, false, false, false, false, true, uint16(2)}) {
		t.Fatalf("cert_key_usage %v", got)
	}
	if got := r["cert_ekus"]; len(got) != 1 || !slices.Equal(got[0], Row{uint64(42), uint32(0), "1.3.6.1.5.5.7.3.1", "server_auth"}) {
		t.Fatalf("cert_ekus %v", got)
	}
	if got := r["cert_policies"]; len(got) != 1 || !slices.Equal(got[0], Row{uint64(42), uint32(0), "2.23.140.1.2.1", "dv", nil, uint32(0)}) {
		t.Fatalf("cert_policies %v", got)
	}
	if got := r["cert_aia"]; len(got) != 1 || !slices.Equal(got[0], Row{uint64(42), uint32(0), "ca_issuers", "http://ca.example/i.cr"}) {
		t.Fatalf("cert_aia %v", got)
	}
	if got := r["cert_crl_dps"]; len(got) != 1 || !slices.Equal(got[0], Row{uint64(42), uint32(0), nil, false, false}) {
		t.Fatalf("cert_crl_dps %v", got)
	}
	got := r["cert_scts"]
	if len(got) != 3 || got[0][3] == nil || got[0][4] != time.UnixMilli(1791346973252).UTC() || got[0][5] != uint16(4) ||
		!slices.Equal(got[1], Row{uint64(42), uint32(1), uint16(1), nil, nil, nil, nil}) || got[2][4] != nil || got[2][3] == nil {
		t.Fatalf("cert_scts %v", got)
	}

	// A malformed extension: its code, and no rows in its table; keyUsage
	// alone fills its bits and leaves is_ca and path_len null.
	m := &extract.Cert{Extensions: []extract.Extension{
		ext(extdecode.OIDPolicies, false, []byte{0x30, 0x01}),
		ext(extdecode.OIDKeyUsage, true, ku),
	}}
	r = build(m)
	if len(r["cert_policies"]) != 0 || r["cert_extensions"][0][5] != string(extdecode.PoliciesMalformed) {
		t.Fatalf("malformed policies: %v %v", r["cert_policies"], r["cert_extensions"])
	}
	if got := r["cert_key_usage"]; len(got) != 1 || got[0][10] != nil || got[0][11] != nil || got[0][1] != true {
		t.Fatalf("keyUsage alone: %v", got)
	}
	// Neither keyUsage nor basicConstraints: no cert_key_usage row; nothing
	// at all for a certificate without extensions.
	for name, rows := range build(&extract.Cert{}) {
		if len(rows) != 0 {
			t.Errorf("%s has rows for a certificate without extensions: %v", name, rows)
		}
	}
	// basicConstraints alone: is_ca without a path length, the bits null.
	r = build(&extract.Cert{Extensions: []extract.Extension{ext(extdecode.OIDBasicConstraints, true, []byte{0x30, 0x00})}})
	if got := r["cert_key_usage"]; len(got) != 1 || got[0][1] != nil || got[0][10] != false || got[0][11] != nil {
		t.Fatalf("basicConstraints alone: %v", got)
	}
}
