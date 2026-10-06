package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/dict"
	"github.com/klauspost/compress/zstd"

	"github.com/4rji/ctvault/internal/ctlogtest"
)

var updateCompat = flag.Bool("update-compat", false, "write testdata/plan2_frames.json with Plan 2's klauspost encoder")

// plan2Frames is a fixture written by Plan 2's encoder (klauspost, better
// level, content checksum) and a klauspost-trained dictionary with ID 1.
type plan2Frames struct {
	Dict   []byte `json:"dict"`
	Frames []struct {
		DictID uint64 `json:"dict_id"`
		Frame  []byte `json:"frame"`
		SHA256 string `json:"sha256"`
	} `json:"frames"`
}

const plan2FramesFile = "testdata/plan2_frames.json"

// writePlan2Frames generates the fixture once, from Plan 2's settings; it is
// checked in, so later encoders never affect it.
func writePlan2Frames(t *testing.T) {
	g, err := ctlogtest.NewGenerator()
	if err != nil {
		t.Fatal(err)
	}
	es, err := g.Entries(300)
	if err != nil {
		t.Fatal(err)
	}
	var samples [][]byte
	for _, e := range es[:250] {
		samples = append(samples, e.CertDER)
	}
	d, err := dict.BuildZstdDict(samples, dict.Options{MaxDictSize: 8 << 10, HashBytes: 6, ZstdDictID: 1})
	if err != nil {
		t.Fatal(err)
	}
	f := plan2Frames{Dict: d}
	plain, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBetterCompression), zstd.WithEncoderCRC(true), zstd.WithEncoderConcurrency(1))
	withDict, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBetterCompression), zstd.WithEncoderCRC(true),
		zstd.WithEncoderConcurrency(1), zstd.WithEncoderDict(d))
	for i, e := range es[250:] {
		enc, id := plain, uint64(0)
		if i%2 == 1 {
			enc, id = withDict, 1
		}
		sum := sha256.Sum256(e.CertDER)
		f.Frames = append(f.Frames, struct {
			DictID uint64 `json:"dict_id"`
			Frame  []byte `json:"frame"`
			SHA256 string `json:"sha256"`
		}{id, enc.EncodeAll(e.CertDER, nil), hex.EncodeToString(sum[:])})
	}
	b, _ := json.Marshal(f)
	os.MkdirAll("testdata", 0o755)
	if err := os.WriteFile(plan2FramesFile, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestPlan2FramesStillDecode: frames Plan 2 wrote, with and without its
// klauspost-trained dictionary, decode with today's codec (amendment A2
// §2.4: old frames and old dictionaries stay readable forever).
func TestPlan2FramesStillDecode(t *testing.T) {
	if *updateCompat {
		writePlan2Frames(t)
	}
	b, err := os.ReadFile(filepath.Clean(plan2FramesFile))
	if err != nil {
		t.Fatalf("%v (generate it once with -update-compat)", err)
	}
	var f plan2Frames
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	c, err := NewCodec()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.AddDict(1, f.Dict); err != nil {
		t.Fatal(err)
	}
	withDict := 0
	for i, fr := range f.Frames {
		der, err := c.Decompress(fr.Frame, fr.DictID)
		if err != nil {
			t.Fatalf("frame %d (dictionary %d): %v", i, fr.DictID, err)
		}
		if sum := sha256.Sum256(der); hex.EncodeToString(sum[:]) != fr.SHA256 {
			t.Fatalf("frame %d decodes to the wrong certificate", i)
		}
		if fr.DictID == 1 {
			withDict++
		}
	}
	if len(f.Frames) != 50 || withDict != 25 {
		t.Fatalf("%d frames, %d with the dictionary", len(f.Frames), withDict)
	}
}
