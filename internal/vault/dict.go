package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/4rji/ctvault/internal/fsutil"
)

// Dictionary training (spec §6.2, amendment A1 §5).
const (
	TrainingSamples = 20000     // the first 20,000 leaf certificates in vault order
	MaxDictSize     = 110 << 10 // spec §3.4: a global 110 KB dictionary
)

// The trainer (amendment A2 §2.1-2.2). CTVault records the API it calls,
// and every parameter that API sets in libzstd 1.5.7.
const (
	DictBinding        = "github.com/DataDog/zstd v1.5.7"
	DictAPI            = "ZDICT_trainFromBuffer"
	DictImplementation = "ZDICT_optimizeTrainFromBuffer_fastCover, which ZDICT_trainFromBuffer calls in libzstd 1.5.7"
	TrainingOrder      = "the first full leaf records in vault order (amendment A1 §5)"
)

// DictParameters are the ZDICT_fastCover_params_t fields ZDICT_trainFromBuffer
// sets in libzstd 1.5.7. A 0 means zdict.h's default: k is searched, f is
// 20, splitPoint is 0.75, accel is 1, no shrinking, an automatic ID.
type DictParameters struct {
	K                       int `json:"k"`
	D                       int `json:"d"`
	F                       int `json:"f"`
	Steps                   int `json:"steps"`
	NbThreads               int `json:"nb_threads"`
	SplitPoint              int `json:"split_point"`
	Accel                   int `json:"accel"`
	ShrinkDict              int `json:"shrink_dict"`
	ShrinkDictMaxRegression int `json:"shrink_dict_max_regression"`
	CompressionLevel        int `json:"compression_level"`
	NotificationLevel       int `json:"notification_level"`
	DictID                  int `json:"dict_id"`
}

// TrainParameters are the parameters every libzstd-trained dictionary uses.
var TrainParameters = DictParameters{D: 8, Steps: 4, CompressionLevel: 3}

// DictManifest is dict/<id>.json, written next to dict/<id>.zdict in every
// vault directory. It records every input that determines the dictionary
// bytes (amendment A2 §2.2). Dictionaries trained before Plan 3 (klauspost)
// have only Library and Training; they stay valid and readable forever.
type DictManifest struct {
	Format         int             `json:"format"`
	ID             uint64          `json:"id"`
	SHA256         string          `json:"sha256"`
	Bytes          int             `json:"bytes"`
	Capacity       int             `json:"capacity,omitempty"`
	Library        string          `json:"library"` // "libzstd 1.5.7"; Plan 2: "github.com/klauspost/compress v1.20.1"
	Binding        string          `json:"binding,omitempty"`
	API            string          `json:"api,omitempty"`
	Implementation string          `json:"implementation,omitempty"`
	Parameters     *DictParameters `json:"parameters,omitempty"`
	Training       Training        `json:"training"`
	CreatedAt      time.Time       `json:"created_at"`
}

// Training records which certificates a dictionary was trained on, in which
// order, and the SHA-256 of their concatenation.
type Training struct {
	Records       int    `json:"records"`
	FirstCertID   uint64 `json:"first_cert_id"`
	LastCertID    uint64 `json:"last_cert_id"`
	Order         string `json:"order,omitempty"`
	SamplesSHA256 string `json:"samples_sha256,omitempty"`
}

// Dict is a verified dictionary.
type Dict struct {
	Manifest DictManifest
	Content  []byte
}

// LibraryVersion names the zstd library that trains dictionaries and
// compresses full records, read at run time.
func LibraryVersion() string { return "libzstd " + ZstdVersion() }

func dictFiles(dir string, id uint64) (content, manifest string) {
	base := filepath.Join(dir, DictDir, strconv.FormatUint(id, 10))
	return base + ".zdict", base + ".json"
}

// LoadDicts reads every dictionary, checks each against its manifest, and
// repairs replicas that an interrupted install left missing. Dictionaries
// are immutable: two different copies of one ID are corruption. Only the
// writer calls it; readers use ReadDicts.
func LoadDicts(dirs []string) ([]Dict, error) {
	out, err := ReadDicts(dirs)
	if err != nil {
		return nil, err
	}
	for _, dct := range out {
		if err := replicate(dirs, dct); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ReadDicts reads and checks every dictionary like LoadDicts, and never
// writes (amendment A3 §2.3).
func ReadDicts(dirs []string) ([]Dict, error) {
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
	p := TrainParameters
	dct := Dict{Content: content, Manifest: DictManifest{Format: 1, ID: id, SHA256: hex.EncodeToString(sum[:]),
		Bytes: len(content), Capacity: MaxDictSize, Library: LibraryVersion(), Binding: DictBinding, API: DictAPI,
		Implementation: DictImplementation, Parameters: &p, Training: t, CreatedAt: now.UTC()}}
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
	if id == 0 || id > 0xffffffff {
		return nil, fmt.Errorf("vault: dictionary ID %d does not fit a zstd dictionary header", id)
	}
	content, err = zdictTrain(samples, MaxDictSize)
	if err != nil {
		return nil, fmt.Errorf("vault: dictionary training: %w", err)
	}
	if len(content) < 8 || binary.LittleEndian.Uint32(content[:4]) != 0xEC30A437 {
		return nil, errors.New("vault: dictionary training produced no zstd dictionary")
	}
	// libzstd chose the header's Dictionary_ID (RFC 8878 §5); the codec
	// requires every frame's ID to be the vault dictionary ID, so it is
	// written there. The recorded SHA-256 covers these final bytes.
	binary.LittleEndian.PutUint32(content[4:8], uint32(id))
	if err := checkHelps(content, id, samples); err != nil {
		return nil, err
	}
	return content, nil
}

// checkHelps requires samples to compress smaller with the dictionary than
// without it; otherwise the dictionary is unusable.
func checkHelps(content []byte, id uint64, samples [][]byte) error {
	c, err := NewCodec()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.AddDict(id, content); err != nil {
		return err
	}
	var with, without int
	for _, s := range samples {
		a, err := c.Compress(s, id)
		if err != nil {
			return err
		}
		b, err := c.Compress(s, 0)
		if err != nil {
			return err
		}
		with, without = with+len(a), without+len(b)
	}
	if with >= without {
		return fmt.Errorf("vault: trained dictionary does not help (%d bytes with it, %d without)", with, without)
	}
	return nil
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
	h := sha256.New()
	for _, s := range out {
		h.Write(s)
	}
	t.Order, t.SamplesSHA256 = TrainingOrder, hex.EncodeToString(h.Sum(nil))
	return out, t, nil
}
