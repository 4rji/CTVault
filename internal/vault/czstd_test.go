package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// TestCFramesDecodeWithKlauspost: full records are C zstd level-9 frames
// with a content checksum and the record's dictionary ID, and an
// independent klauspost decoder reads them, with and without a
// libzstd-trained dictionary (amendment A2 §2.1, §2.4).
func TestCFramesDecodeWithKlauspost(t *testing.T) {
	cs := certs(t, 300)
	content, err := Train(cs[:250], 7)
	if err != nil {
		t.Fatal(err)
	}
	c := codec(t)
	if err := c.AddDict(7, content); err != nil {
		t.Fatal(err)
	}
	dec, _ := zstd.NewReader(nil, zstd.WithDecoderDicts(content), zstd.WithDecoderConcurrency(1))
	defer dec.Close()
	for _, id := range []uint64{0, 7} {
		for _, der := range cs[250:] {
			frame, err := c.Compress(der, id)
			if err != nil {
				t.Fatal(err)
			}
			var h zstd.Header
			if err := h.Decode(frame); err != nil || !h.HasCheckSum || uint64(h.DictionaryID) != id {
				t.Fatalf("dictionary %d: frame header %+v (%v): want a checksum and dictionary ID %d", id, h, err, id)
			}
			if got, err := dec.DecodeAll(frame, nil); err != nil || !bytes.Equal(got, der) {
				t.Fatalf("dictionary %d: klauspost decodes the C frame as %d bytes (%v)", id, len(got), err)
			}
			if got, err := c.Decompress(frame, id); err != nil || !bytes.Equal(got, der) {
				t.Fatalf("dictionary %d: the codec decodes the C frame as %d bytes (%v)", id, len(got), err)
			}
		}
	}
}

// pinnedCorpus is the training corpus the determinism test pins: the first
// 2,000 certificates of the extractor's checked-in golden corpus.
func pinnedCorpus(t *testing.T) [][]byte {
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
	for len(out) < 2000 {
		l, k := binary.Uvarint(raw)
		out = append(out, raw[k:k+int(l)])
		raw = raw[k+int(l):]
	}
	return out
}

// pinnedDictSHA256 is the dictionary libzstd 1.5.7 trains from the pinned
// corpus with the vault's parameters, ID 1 written into its header.
const pinnedDictSHA256 = "cc99954ae7ebe51a1dcef221a6c2a0ade517339fc770007b61e999b48faf2429"

// TestTrainIsReproducible: the same samples, library version and parameters
// give the same dictionary bytes, with the vault dictionary ID in the
// dictionary header (amendment A2 §2.2, §2.4).
func TestTrainIsReproducible(t *testing.T) {
	if v := ZstdVersion(); v != "1.5.7" {
		t.Fatalf("libzstd %s, want the pinned 1.5.7", v)
	}
	samples := pinnedCorpus(t)
	a, err := Train(samples, 1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Train(samples, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("two trainings on the same samples differ")
	}
	if id := binary.LittleEndian.Uint32(a[4:8]); id != 1 {
		t.Fatalf("the dictionary header carries ID %d, want 1", id)
	}
	sum := sha256.Sum256(a)
	if got := hex.EncodeToString(sum[:]); got != pinnedDictSHA256 {
		t.Fatalf("the pinned corpus trains to %s (%d bytes), want %s", got, len(a), pinnedDictSHA256)
	}
}
