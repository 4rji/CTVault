package extract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/")

// corpus reads testdata/corpus.bin.zst: real certificates from the cached
// samples (written by TestWriteGoldenCorpus under -tags realdata).
func corpus(t testing.TB) [][]byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "corpus.bin.zst"))
	if err != nil {
		t.Fatal(err)
	}
	dec, _ := zstd.NewReader(nil)
	defer dec.Close()
	raw, err := dec.DecodeAll(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for len(raw) > 0 {
		n, k := binary.Uvarint(raw)
		if k <= 0 || uint64(len(raw)-k) < n {
			t.Fatal("corrupt corpus")
		}
		out = append(out, raw[k:k+int(n)])
		raw = raw[k+int(n):]
	}
	return out
}

// row is one golden line: everything Parse returns, compactly.
type row struct {
	SHA256      string   `json:"sha256"`
	Status      Status   `json:"status"`
	Errors      []Code   `json:"errors,omitempty"`
	Version     int      `json:"version"`
	Serial      string   `json:"serial"`
	SigAlg      string   `json:"sig_alg"`
	Issuer      string   `json:"issuer"`
	IssuerCN    string   `json:"issuer_cn,omitempty"`
	IssuerO     string   `json:"issuer_o,omitempty"`
	SubjectCN   string   `json:"subject_cn,omitempty"`
	IssuerRaw   string   `json:"issuer_raw_sha256"`
	Subject     string   `json:"subject"`
	SubjectRaw  string   `json:"subject_raw_sha256"`
	NotBefore   string   `json:"not_before,omitempty"`
	NotAfter    string   `json:"not_after,omitempty"`
	Key         Key      `json:"key"`
	Extensions  []string `json:"extensions,omitempty"` // "oid" or "oid!" when critical
	DNSNames    []string `json:"dns,omitempty"`
	IPAddresses []string `json:"ips,omitempty"`
	AKI         string   `json:"aki,omitempty"`
	SKI         string   `json:"ski,omitempty"`
	Poison      bool     `json:"poison,omitempty"`
}

func shaHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func summarize(der []byte) row {
	c := Parse(der)
	r := row{SHA256: shaHex(der), Status: c.Status, Errors: c.Errors, Version: c.Version, Serial: hex.EncodeToString(c.Serial),
		SigAlg: c.SignatureAlgorithm, Issuer: c.Issuer.String(), IssuerRaw: shaHex(c.Issuer.Raw), Subject: c.Subject.String(),
		SubjectRaw: shaHex(c.Subject.Raw), Key: c.Key, DNSNames: c.DNSNames, AKI: hex.EncodeToString(c.AuthorityKeyID),
		SKI: hex.EncodeToString(c.SubjectKeyID), Poison: c.HasCTPoison}
	r.IssuerCN, _ = c.Issuer.First(OIDCommonName)
	r.IssuerO, _ = c.Issuer.First(OIDOrganization)
	r.SubjectCN, _ = c.Subject.First(OIDCommonName)
	if c.HasNotBefore {
		r.NotBefore = c.NotBefore.Format(time.RFC3339)
	}
	if c.HasNotAfter {
		r.NotAfter = c.NotAfter.Format(time.RFC3339)
	}
	for _, e := range c.Extensions {
		s := e.OID
		if e.Critical {
			s += "!"
		}
		r.Extensions = append(r.Extensions, s)
	}
	for _, ip := range c.IPAddresses {
		r.IPAddresses = append(r.IPAddresses, hex.EncodeToString(ip))
	}
	return r
}

// checkGolden compares lines with the golden file, or rewrites it with
// -update. compressed files are zstd frames.
func checkGolden(t *testing.T, name string, lines []string, compressed bool) {
	t.Helper()
	got := []byte(strings.Join(lines, "\n") + "\n")
	path := filepath.Join("testdata", name)
	if *update {
		out := got
		if compressed {
			enc, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression), zstd.WithEncoderConcurrency(1))
			out = enc.EncodeAll(got, nil)
		}
		if err := os.WriteFile(path, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if compressed {
		dec, _ := zstd.NewReader(nil)
		defer dec.Close()
		if want, err = dec.DecodeAll(want, nil); err != nil {
			t.Fatal(err)
		}
	}
	if bytes.Equal(got, want) {
		return
	}
	g, w := strings.Split(string(got), "\n"), strings.Split(string(want), "\n")
	for i := range min(len(g), len(w)) {
		if g[i] != w[i] {
			t.Fatalf("%s line %d differs:\n got  %s\n want %s", name, i+1, g[i], w[i])
		}
	}
	t.Fatalf("%s: %d lines, want %d", name, len(g), len(w))
}

func jsonLine(t *testing.T, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestGoldenCorpus: every real certificate in the corpus extracts to its
// golden line. A change to any extracted value shows up here first.
func TestGoldenCorpus(t *testing.T) {
	var lines []string
	statuses := map[Status]int{}
	for _, der := range corpus(t) {
		r := summarize(der)
		statuses[r.Status]++
		lines = append(lines, jsonLine(t, r))
	}
	t.Logf("%d certificates: %v", len(lines), statuses)
	checkGolden(t, "corpus.golden.zst", lines, true)
}

// TestDeterminism: the same DER gives the same result every time, whatever
// GOMAXPROCS is (spec §7.2).
func TestDeterminism(t *testing.T) {
	certs := corpus(t)
	first := make([]string, len(certs))
	for i, der := range certs {
		first[i] = fmt.Sprintf("%+v", *Parse(der))
	}
	done := make(chan bool)
	for range 4 {
		go func() {
			for i, der := range certs {
				if fmt.Sprintf("%+v", *Parse(der)) != first[i] {
					t.Errorf("certificate %d extracts differently on another run", i)
				}
			}
			done <- true
		}()
	}
	for range 4 {
		<-done
	}
}

func BenchmarkParse(b *testing.B) {
	certs := corpus(b)
	b.ResetTimer()
	for i := range b.N {
		Parse(certs[i%len(certs)])
	}
}
