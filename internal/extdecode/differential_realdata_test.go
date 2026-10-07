//go:build realdata

package extdecode

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"slices"
	"sort"
	"testing"

	"github.com/4rji/ctvault/internal/extract"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/loglist"
	"github.com/4rji/ctvault/internal/sample"
	"github.com/4rji/ctvault/internal/sampletest"
)

// x509EKU is crypto/x509's own table of the purposes it names.
var x509EKU = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny: "2.5.29.37.0", x509.ExtKeyUsageServerAuth: "1.3.6.1.5.5.7.3.1", x509.ExtKeyUsageClientAuth: "1.3.6.1.5.5.7.3.2",
	x509.ExtKeyUsageCodeSigning: "1.3.6.1.5.5.7.3.3", x509.ExtKeyUsageEmailProtection: "1.3.6.1.5.5.7.3.4",
	x509.ExtKeyUsageIPSECEndSystem: "1.3.6.1.5.5.7.3.5", x509.ExtKeyUsageIPSECTunnel: "1.3.6.1.5.5.7.3.6", x509.ExtKeyUsageIPSECUser: "1.3.6.1.5.5.7.3.7",
	x509.ExtKeyUsageTimeStamping: "1.3.6.1.5.5.7.3.8", x509.ExtKeyUsageOCSPSigning: "1.3.6.1.5.5.7.3.9",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto: "1.3.6.1.4.1.311.10.3.3", x509.ExtKeyUsageNetscapeServerGatedCrypto: "2.16.840.1.113730.4.1",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "1.3.6.1.4.1.311.2.1.22", x509.ExtKeyUsageMicrosoftKernelCodeSigning: "1.3.6.1.4.1.311.61.1.1",
}

func escaped(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = extract.Display([]byte(s))
	}
	return out
}

// knownLogs is every log ID in the cached log lists, of both kinds.
func knownLogs(t *testing.T) map[[32]byte]bool {
	ids := map[[32]byte]bool{}
	for _, f := range []string{"../testdata/log_list_v93.6_full.json", "../testdata/log_list_v93.3_full.json"} {
		l, err := loglist.Fetch(context.Background(), http.DefaultClient, f)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range l.All() {
			b, _ := base64.StdEncoding.DecodeString(r.Log.LogID)
			ids[[32]byte(b)] = true
		}
	}
	return ids
}

// TestDifferentialOnRealData is amendment A7 §4.2: every unique
// certificate of every cached sample, decoded here and by crypto/x509,
// must agree wherever crypto/x509 parses it. SCT log IDs are looked up in
// the log lists and reported, never failed.
func TestDifferentialOnRealData(t *testing.T) {
	var samples []*sample.Sample
	for _, log := range []string{"argon2027h1", "parcelyard2027h1", "parcelyard2026h2"} {
		samples = append(samples, sampletest.Representatives(t, log)...)
		t.Run("canonical "+log, func(t *testing.T) { samples = append(samples, sampletest.Canonical(t, log)) })
	}
	if len(samples) == 0 {
		t.Skip("no cached samples")
	}
	logs := knownLogs(t)
	seen := map[[32]byte]bool{}
	var certs, refused, decoded, differences, scts, unknownSCTs int
	codes := map[Code]int{}
	unknown := map[[32]byte]int{}
	differ := func(der []byte, what string, got, want any) {
		differences++
		if differences <= 10 {
			t.Errorf("certificate %x: %s: decoded %v, crypto/x509 %v", sha256.Sum256(der), what, got, want)
		}
	}
	for _, s := range samples {
		err := s.Each(func(e sample.Entry) error {
			l := leaf.Decode(e.LeafInput, e.ExtraData)
			ders := slices.Clone(l.Chain)
			if l.CertDER != nil {
				ders = append(ders, l.CertDER)
			}
			for _, der := range ders {
				h := sha256.Sum256(der)
				if seen[h] {
					continue
				}
				seen[h] = true
				certs++
				c := extract.Parse(der)
				first := map[string][]byte{}
				for _, x := range c.Extensions {
					if Decoded(x.OID) {
						if _, dup := first[x.OID]; !dup {
							first[x.OID] = x.Value
							if code := Check(x.OID, x.Value); code != "" {
								codes[code]++
							}
						}
					}
				}
				if v, ok := first[OIDSCTList]; ok {
					if ss, code := SCTs(v); code == "" {
						for _, sc := range ss {
							scts++
							if sc.V1 && !logs[sc.LogID] {
								unknownSCTs++
								unknown[sc.LogID]++
							}
						}
					}
				}
				xc, err := x509.ParseCertificate(der)
				if err != nil {
					refused++
					continue
				}
				decoded++
				if v, ok := first[OIDPolicies]; ok {
					ps, code := Policies(v)
					var got, want []string
					for _, p := range ps {
						got = append(got, p.OID)
					}
					for _, o := range xc.Policies {
						want = append(want, o.String())
					}
					if code != "" || !slices.Equal(got, want) {
						differ(der, "policies", got, want)
					}
				}
				if v, ok := first[OIDEKU]; ok {
					es, code := EKUs(v)
					var got, want []string
					for _, e := range es {
						got = append(got, e.OID)
					}
					for _, k := range xc.ExtKeyUsage {
						want = append(want, x509EKU[k])
					}
					for _, o := range xc.UnknownExtKeyUsage {
						want = append(want, o.String())
					}
					sort.Strings(got)
					sort.Strings(want)
					if code != "" || !slices.Equal(got, want) {
						differ(der, "ekus", got, want)
					}
				}
				if v, ok := first[OIDKeyUsage]; ok {
					if ku, code := KeyUsage(v); code != "" || ku != uint16(xc.KeyUsage) {
						differ(der, "key usage", ku, xc.KeyUsage)
					}
				}
				if v, ok := first[OIDBasicConstraints]; ok {
					bc, code := BasicConstraints(v)
					want := Constraints{IsCA: xc.IsCA, PathLen: -1}
					if xc.MaxPathLen > 0 || xc.MaxPathLenZero {
						want.PathLen = xc.MaxPathLen
					}
					if code != "" || !xc.BasicConstraintsValid || bc != want {
						differ(der, "basic constraints", bc, want)
					}
				}
				if v, ok := first[OIDAIA]; ok {
					as, code := AIA(v)
					var ocsp, issuers []string
					for _, a := range as {
						switch {
						case a.Method == "ocsp" && a.HasURI:
							ocsp = append(ocsp, a.URI)
						case a.Method == "ca_issuers" && a.HasURI:
							issuers = append(issuers, a.URI)
						}
					}
					if code != "" || !slices.Equal(ocsp, escaped(xc.OCSPServer)) || !slices.Equal(issuers, escaped(xc.IssuingCertificateURL)) {
						differ(der, "aia", as, [][]string{xc.OCSPServer, xc.IssuingCertificateURL})
					}
				}
				if v, ok := first[OIDCRLDPs]; ok {
					dps, code := CRLDPs(v)
					var got []string
					for _, d := range dps {
						got = append(got, d.URIs...)
					}
					if code != "" || !slices.Equal(got, escaped(xc.CRLDistributionPoints)) {
						differ(der, "crl dps", got, xc.CRLDistributionPoints)
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("%d samples, %d unique certificates: %d parsed by crypto/x509 and compared, %d refused by it; %d differences", len(samples), certs, decoded, refused, differences)
	t.Logf("decoding codes: %v", codes)
	t.Logf("%d embedded SCTs; %d from %d log IDs not in the v93.3 or v93.6 lists", scts, unknownSCTs, len(unknown))
	for id, n := range unknown {
		t.Logf("  unknown log ID %x: %d SCTs", id, n)
	}
	if certs < 100000 {
		t.Fatalf("only %d certificates: the samples are missing", certs)
	}
}
