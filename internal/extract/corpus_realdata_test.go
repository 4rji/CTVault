//go:build realdata

package extract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/sample"
	"github.com/4rji/ctvault/internal/sampletest"
)

var writeCorpus = flag.Bool("write-corpus", false, "rewrite testdata/corpus.bin.zst from the cached samples")

// realCerts returns the cached samples' certificates: every leaf certificate
// (precert or final) and every chain certificate, each once.
func realCerts(t *testing.T) (leaves [][]byte, chains [][]byte, leafEvery100 [][]byte) {
	t.Helper()
	samples := append([]*sample.Sample{sampletest.Canonical(t, "argon2027h1")}, sampletest.Representatives(t, "argon2027h1")...)
	seen := map[[32]byte]bool{}
	for _, s := range samples {
		n := 0
		err := s.Each(func(e sample.Entry) error {
			l := leaf.Decode(e.LeafInput, e.ExtraData)
			if l.CertDER != nil && !seen[sha256.Sum256(l.CertDER)] {
				seen[sha256.Sum256(l.CertDER)] = true
				leaves = append(leaves, l.CertDER)
				if n%100 == 0 {
					leafEvery100 = append(leafEvery100, l.CertDER)
				}
				n++
			}
			for _, c := range l.Chain {
				if !seen[sha256.Sum256(c)] {
					seen[sha256.Sum256(c)] = true
					chains = append(chains, c)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return leaves, chains, leafEvery100
}

// TestWriteGoldenCorpus writes testdata/corpus.bin.zst: one leaf
// certificate in every 100 distinct ones of each cached sample, then every
// distinct chain certificate in SHA-256 order. Run it once with
// -write-corpus; the file is checked in.
func TestWriteGoldenCorpus(t *testing.T) {
	if !*writeCorpus {
		t.Skip("run with -args -write-corpus to rewrite testdata/corpus.bin.zst")
	}
	_, chains, every100 := realCerts(t)
	slices.SortFunc(chains, func(a, b []byte) int {
		ha, hb := sha256.Sum256(a), sha256.Sum256(b)
		return bytes.Compare(ha[:], hb[:])
	})
	var raw []byte
	for _, c := range append(every100, chains...) {
		raw = binary.AppendUvarint(raw, uint64(len(c)))
		raw = append(raw, c...)
	}
	enc, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression), zstd.WithEncoderConcurrency(1))
	out := enc.EncodeAll(raw, nil)
	if err := os.WriteFile(filepath.Join("testdata", "corpus.bin.zst"), out, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d leaf + %d chain certificates, %d bytes raw, %d compressed", len(every100), len(chains), len(raw), len(out))
}

// TestDifferentialRealSamples compares the extractor with crypto/x509 on
// every certificate of the cached samples, leaf and chain (amendment A2
// §3.4).
func TestDifferentialRealSamples(t *testing.T) {
	leaves, chains, _ := realCerts(t)
	statuses := map[Status]int{}
	codes := map[Code]int{}
	compared, failures := 0, 0
	for _, der := range append(leaves, chains...) {
		c := Parse(der)
		statuses[c.Status]++
		for _, code := range c.Errors {
			codes[code]++
		}
		ok, diffs := compareX509(der)
		if ok {
			compared++
		}
		for _, d := range diffs {
			if failures++; failures <= 20 {
				t.Errorf("%s: %s", shaHex(der)[:16], d)
			}
		}
	}
	t.Logf("%d leaf + %d chain certificates; statuses %v; codes %v; %d compared with crypto/x509, %d differences",
		len(leaves), len(chains), statuses, codes, compared, failures)
}
