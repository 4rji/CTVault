package query

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/4rji/ctvault/internal/extract"
)

// Dump is fetch's text format (amendment A3 §4.2): a deterministic,
// CTVault-specific listing of what the extractor reads, which works even
// for certificates other tools reject. It is not openssl's format.
func Dump(c *Cert) string {
	x := extract.Parse(c.DER)
	var b strings.Builder
	line := func(k, v string) { fmt.Fprintf(&b, "%-11s %s\n", k+":", v) }
	line("sha256", hex.EncodeToString(c.SHA256[:]))
	line("cert_id", fmt.Sprintf("%d (batch %s)", c.CertID, c.Batch))
	line("kind", fmt.Sprint(c.Row["kind"]))
	line("parse", string(x.Status))
	line("version", fmt.Sprint(x.Version))
	line("serial", hex.EncodeToString(x.Serial))
	line("subject", x.Subject.String())
	line("issuer", x.Issuer.String())
	validity := "unreadable"
	if x.HasNotBefore && x.HasNotAfter {
		validity = x.NotBefore.Format(time.RFC3339) + " → " + x.NotAfter.Format(time.RFC3339)
	}
	line("validity", validity)
	key := x.Key.Algorithm
	if x.Key.Curve != "" {
		key += " " + x.Key.Curve
	}
	if x.Key.Bits > 0 {
		key += fmt.Sprintf(" (%d bits)", x.Key.Bits)
	}
	line("key", strings.TrimSpace(key+" "+x.Key.AlgorithmOID))
	line("signature", x.SignatureAlgorithm)
	line("dns names", strings.Join(x.DNSNames, ", "))
	var ips []string
	for _, ip := range x.IPAddresses {
		if a, ok := netip.AddrFromSlice(ip); ok {
			ips = append(ips, a.String())
		} else {
			ips = append(ips, hex.EncodeToString(ip))
		}
	}
	line("ip names", strings.Join(ips, ", "))
	line("aki", hex.EncodeToString(x.AuthorityKeyID))
	line("ski", hex.EncodeToString(x.SubjectKeyID))
	line("ct poison", fmt.Sprint(x.HasCTPoison))
	var exts []string
	for _, e := range x.Extensions {
		s := e.OID
		if e.Critical {
			s += " (critical)"
		}
		exts = append(exts, s)
	}
	line("extensions", strings.Join(exts, ", "))
	for _, code := range x.Errors {
		line("error", string(code)+": "+code.Explain())
	}
	return b.String()
}
