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

var update = flag.Bool("update", false, "rewrite testdata/corpus_rows.golden.zst")

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
// golden file, so a change to the extractor, the normalization or the
// public-suffix list shows up here and must bump a table version.
func TestCorpusRowsGolden(t *testing.T) {
	certs := realCorpus(t)
	var lines []string
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
				lines = append(lines, b.Table().Name+" "+string(line))
				stats[b.Table().Name]++
				if b.Table().Name == "names" && r[3] == true {
					stats["names dns_valid"]++
				}
			}
		}
	}
	t.Logf("%d certificates: %v", len(certs), stats)
	got := []byte(strings.Join(lines, "\n") + "\n")
	path := filepath.Join("testdata", "corpus_rows.golden.zst")
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
				t.Fatalf("line %d differs:\n got  %s\n want %s", i+1, g[i], w[i])
			}
		}
		t.Fatalf("%d lines, want %d", len(g), len(w))
	}
}
