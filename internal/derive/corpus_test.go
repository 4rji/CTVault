package derive

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/4rji/ctvault/internal/extract"
)

var update = flag.Bool("update", false, "rewrite the corpus golden files in testdata")

// goldens are the corpus golden files and the tables each holds: certs and
// names in the file they always had, so adding a table leaves it byte for
// byte (amendment A7 §4.4), and the D tables in their own.
var goldens = []struct {
	file   string
	tables map[string]bool
}{
	{"corpus_rows.golden.zst", map[string]bool{"certs": true, "names": true}},
	{"corpus_d_rows.golden.zst", map[string]bool{"cert_extensions": true, "cert_policies": true, "cert_ekus": true,
		"cert_key_usage": true, "cert_aia": true, "cert_crl_dps": true, "cert_scts": true}},
}

// realCorpus reads the extractor's corpus of real certificates: 2,000
// leaves, then 710 chain certificates.
func realCorpus(t *testing.T) [][]byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "extract", "testdata", "corpus.bin.zst"))
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
		out = append(out, raw[k:k+int(n)])
		raw = raw[k+int(n):]
	}
	return out
}

// TestCorpusRowsGolden: every builder's rows for the real corpus match the
// golden files, so a change to the extractor, the decoders, the
// normalization or the public-suffix list shows up here and must bump a
// table version.
func TestCorpusRowsGolden(t *testing.T) {
	certs := realCorpus(t)
	lines := make([][]string, len(goldens))
	stats := map[string]int{}
	for i, der := range certs {
		c := extract.Parse(der)
		kind := KindFinal
		switch {
		case i >= 2000:
			kind = KindChain
		case c.HasCTPoison:
			kind = KindPrecert
		}
		ctx := Context{CertID: uint64(i + 1), SHA256: sha256.Sum256(der), Kind: kind}
		for _, b := range Builders {
			for _, r := range b.Build(c, ctx) {
				line, err := json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
				placed := false
				for g := range goldens {
					if goldens[g].tables[b.Table().Name] {
						lines[g] = append(lines[g], b.Table().Name+" "+string(line))
						placed = true
					}
				}
				if !placed {
					t.Fatalf("table %s is in no golden file", b.Table().Name)
				}
				stats[b.Table().Name]++
				if b.Table().Name == "names" && r[3] == true {
					stats["names dns_valid"]++
				}
			}
		}
	}
	t.Logf("%d certificates: %v", len(certs), stats)
	for g, gold := range goldens {
		checkGolden(t, filepath.Join("testdata", gold.file), []byte(strings.Join(lines[g], "\n")+"\n"))
	}
}

func checkGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		enc, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression), zstd.WithEncoderConcurrency(1))
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, enc.EncodeAll(got, nil), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	dec, _ := zstd.NewReader(nil)
	defer dec.Close()
	want, err := dec.DecodeAll(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		g, w := strings.Split(string(got), "\n"), strings.Split(string(want), "\n")
		for i := range min(len(g), len(w)) {
			if g[i] != w[i] {
				t.Fatalf("%s line %d differs:\n got  %s\n want %s", path, i+1, g[i], w[i])
			}
		}
		t.Fatalf("%s: %d lines, want %d", path, len(g), len(w))
	}
}
