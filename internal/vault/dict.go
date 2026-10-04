package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/dict"

	"github.com/4rji/ctvault/internal/fsutil"
)

// Dictionary training (spec §6.2, amendment A1 §5).
const (
	TrainingSamples = 20000     // the first 20,000 leaf certificates in vault order
	MaxDictSize     = 110 << 10 // spec §3.4: a global 110 KB dictionary
)

// DictManifest is dict/<id>.json, written next to dict/<id>.zdict in every
// vault directory. Nothing assumes that retraining with another library
// version would reproduce the same bytes.
type DictManifest struct {
	Format    int       `json:"format"`
	ID        uint64    `json:"id"`
	SHA256    string    `json:"sha256"`
	Bytes     int       `json:"bytes"`
	Library   string    `json:"library"` // e.g. "github.com/klauspost/compress v1.20.1"
	Training  Training  `json:"training"`
	CreatedAt time.Time `json:"created_at"`
}

// Training records which certificates a dictionary was trained on.
type Training struct {
	Records     int    `json:"records"`
	FirstCertID uint64 `json:"first_cert_id"`
	LastCertID  uint64 `json:"last_cert_id"`
}

// Dict is a verified dictionary.
type Dict struct {
	Manifest DictManifest
	Content  []byte
}

// LibraryVersion names the zstd implementation in this binary.
func LibraryVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/klauspost/compress" {
				return d.Path + " " + d.Version
			}
		}
	}
	return "github.com/klauspost/compress (version unknown)"
}

func dictFiles(dir string, id uint64) (content, manifest string) {
	base := filepath.Join(dir, DictDir, strconv.FormatUint(id, 10))
	return base + ".zdict", base + ".json"
}

// LoadDicts reads every dictionary, checks each against its manifest, and
// repairs replicas that an interrupted install left missing. Dictionaries
// are immutable: two different copies of one ID are corruption.
func LoadDicts(dirs []string) ([]Dict, error) {
	found := map[uint64]Dict{}
	for _, d := range dirs {
		names, err := os.ReadDir(filepath.Join(d, DictDir))
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			base, ok := strings.CutSuffix(n.Name(), ".json")
			if !ok {
				continue
			}
			id, err := strconv.ParseUint(base, 10, 64)
			if err != nil || id == 0 {
				return nil, corrupt("unexpected dictionary manifest %s in %s", n.Name(), d)
			}
			got, err := readDict(d, id)
			if err != nil {
				return nil, err
			}
			if prev, ok := found[id]; ok && !bytes.Equal(prev.Content, got.Content) {
				return nil, corrupt("dictionary %d differs between vault directories", id)
			}
			found[id] = got
		}
	}
	var out []Dict
	for _, dct := range found {
		out = append(out, dct)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Manifest.ID < out[j].Manifest.ID })
	for _, dct := range out {
		if err := replicate(dirs, dct); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func readDict(dir string, id uint64) (Dict, error) {
	cp, mp := dictFiles(dir, id)
	mb, err := os.ReadFile(mp)
	if err != nil {
		return Dict{}, err
	}
	var m DictManifest
	if err := json.Unmarshal(mb, &m); err != nil || m.ID != id {
		return Dict{}, corrupt("dictionary manifest %s is unreadable", mp)
	}
	content, err := os.ReadFile(cp)
	if err != nil {
		return Dict{}, corrupt("dictionary %d content: %v", id, err)
	}
	sum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) != m.SHA256 || len(content) != m.Bytes {
		return Dict{}, corrupt("dictionary %d in %s does not match its manifest", id, dir)
	}
	return Dict{Manifest: m, Content: content}, nil
}

// replicate writes dct to every directory that lacks it: content first, then
// the manifest, which marks the copy complete.
func replicate(dirs []string, dct Dict) error {
	mb, err := json.MarshalIndent(dct.Manifest, "", " ")
	if err != nil {
		return err
	}
	for _, d := range dirs {
		cp, mp := dictFiles(d, dct.Manifest.ID)
		if _, err := os.Stat(mp); err == nil {
			continue
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := fsutil.WriteFileAtomic(cp, dct.Content, 0o444); err != nil {
			return err
		}
		if err := fsutil.WriteFileAtomic(mp, mb, 0o444); err != nil {
			return err
		}
	}
	return nil
}

// InstallDict persists a new dictionary in every vault directory. Records may
// use it only after InstallDict returns.
func InstallDict(dirs []string, id uint64, content []byte, t Training, now time.Time) (Dict, error) {
	for _, d := range dirs {
		if _, mp := dictFiles(d, id); fileExists(mp) {
			return Dict{}, fmt.Errorf("vault: dictionary %d already exists; dictionaries are immutable", id)
		}
	}
	sum := sha256.Sum256(content)
	dct := Dict{Content: content, Manifest: DictManifest{Format: 1, ID: id, SHA256: hex.EncodeToString(sum[:]),
		Bytes: len(content), Library: LibraryVersion(), Training: t, CreatedAt: now.UTC()}}
	return dct, replicate(dirs, dct)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// Train builds a dictionary from samples and checks that it helps: the
// samples must compress smaller with it than without. A library panic, an
// error or an unhelpful dictionary is reported as an error, and ingestion
// continues with dictionary 0 (amendment A1 §5).
func Train(samples [][]byte, id uint64) (content []byte, err error) {
	defer func() {
		if p := recover(); p != nil {
			content, err = nil, fmt.Errorf("vault: dictionary training panicked: %v", p)
		}
	}()
	content, err = dict.BuildZstdDict(samples, dict.Options{MaxDictSize: MaxDictSize, HashBytes: 6, ZstdDictID: uint32(id)})
	if err != nil {
		return nil, fmt.Errorf("vault: dictionary training: %w", err)
	}
	c, err := NewCodec()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if err := c.AddDict(id, content); err != nil {
		return nil, err
	}
	var with, without int
	for _, s := range samples {
		a, _ := c.Compress(s, id)
		b, _ := c.Compress(s, 0)
		with, without = with+len(a), without+len(b)
	}
	if with >= without {
		return nil, fmt.Errorf("vault: trained dictionary does not help (%d bytes with it, %d without)", with, without)
	}
	return content, nil
}

// TrainingSet reads the first n leaf records in vault order, up to the
// committed tail, from committed data only, so training is crash-safe.
func TrainingSet(dirs []string, codec *Codec, tail Tail, n int) ([][]byte, Training, error) {
	var out [][]byte
	var t Training
	stop := errors.New("enough")
	err := Scan(dirs, Tail{}, tail, func(loc Loc, rec Record) error {
		if rec.Kind != KindLeaf {
			return nil
		}
		der, err := codec.Decompress(rec.Frame, rec.DictID)
		if err != nil {
			return err
		}
		if t.Records == 0 {
			t.FirstCertID = rec.CertID
		}
		out = append(out, der)
		t.Records, t.LastCertID = t.Records+1, rec.CertID
		if len(out) == n {
			return stop
		}
		return nil
	})
	if err != nil && !errors.Is(err, stop) {
		return nil, t, err
	}
	return out, t, nil
}
