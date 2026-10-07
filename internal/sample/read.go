package sample

import (
	"bufio"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"

	"github.com/4rji/ctvault/internal/loglist"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/merkle"
)

// ErrCorrupt means a sample failed verification: a checksum, the signed
// head, an entry or a Merkle proof. A corrupt sample is never used.
var ErrCorrupt = errors.New("sample failed verification")

// maxLine bounds one entries.ndjson line (an entry with a long chain is a few
// tens of KiB in base64).
const maxLine = 16 << 20

// Entry is one sampled log entry, bytes exactly as served.
type Entry = line

// Sample is a verified sample.
type Sample struct {
	Dir      string
	Manifest Manifest
	Head     merkle.SignedTreeHead
	Proofs   Proofs
	pub      crypto.PublicKey
	start    *merkle.State // tiled samples: the verified compact range at Start
}

// Open loads and fully verifies the sample in dir (amendment A1 §2.4):
// file checksums, the signed head with the pinned key, every entry, and the
// Merkle proofs that tie every leaf_input to the signed root. extra_data is
// not part of a CT log's Merkle tree, so only the checksums protect it.
func Open(dir string) (*Sample, error) {
	s, err := load(dir)
	if err != nil {
		return nil, err
	}
	if s.Tiled() {
		err = s.verifyTiled(context.Background())
	} else {
		err = s.verifyMerkle()
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Tiled reports whether the sample mirrors a tiled log (amendment A6 §5).
func (s *Sample) Tiled() bool { return s.Manifest.Protocol == ProtocolTiled }

func corrupt(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(format, args...))
}

func load(dir string) (*Sample, error) {
	s := &Sample{Dir: dir}
	b, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.Manifest); err != nil {
		return nil, corrupt("%s: %v", ManifestFile, err)
	}
	m := s.Manifest
	if m.Format != Format {
		return nil, corrupt("unsupported format %d", m.Format)
	}
	switch m.Protocol {
	case ProtocolTiled:
		if err := loadTiled(dir, s); err != nil {
			return nil, err
		}
		return s, nil
	case "":
	default:
		return nil, corrupt("unknown protocol %q", m.Protocol)
	}
	lim := Limits{Boundary: m.Boundary, Min: 1, Max: ^uint64(0)}
	if m.Boundary == 0 || lim.Check(m.Kind, m.Start, m.Count) != nil || uint64(len(m.Frames)) != m.Count/m.Boundary {
		return nil, corrupt("inconsistent range: start %d, count %d, boundary %d, %d frames", m.Start, m.Count, m.Boundary, len(m.Frames))
	}
	for _, name := range []string{EntriesFile, ProofsFile} {
		want, ok := m.Files[name]
		got, err := fileSum(filepath.Join(dir, name))
		if errors.Is(err, fs.ErrNotExist) {
			return nil, corrupt("%s is missing (an incomplete copy?)", name)
		}
		if err != nil {
			return nil, err
		}
		if !ok || got != want {
			return nil, corrupt("%s: sha256 %s (%d bytes), manifest records %s (%d bytes)", name, got.SHA256, got.Bytes, want.SHA256, want.Bytes)
		}
	}
	if s.pub, err = loglist.ParseKey(m.Log.Key, m.Log.LogID); err != nil {
		return nil, corrupt("pinned key: %v", err)
	}
	var head struct {
		TreeSize  *uint64 `json:"tree_size"`
		Timestamp uint64  `json:"timestamp"`
		Root      []byte  `json:"sha256_root_hash"`
		Sig       []byte  `json:"tree_head_signature"`
	}
	if err := json.Unmarshal(m.HeadRaw, &head); err != nil || head.TreeSize == nil || len(head.Root) != 32 {
		return nil, corrupt("signed head is unreadable")
	}
	s.Head = merkle.SignedTreeHead{TreeSize: *head.TreeSize, Timestamp: head.Timestamp, Signature: head.Sig}
	copy(s.Head.RootHash[:], head.Root)
	if err := merkle.VerifySTH(s.pub, s.Head); err != nil {
		return nil, corrupt("signed head: %v", err)
	}
	if m.Start+m.Count > s.Head.TreeSize {
		return nil, corrupt("entries end at %d, beyond the signed tree of %d", m.Start+m.Count, s.Head.TreeSize)
	}
	pb, err := os.ReadFile(filepath.Join(dir, ProofsFile))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(pb, &s.Proofs); err != nil {
		return nil, corrupt("%s: %v", ProofsFile, err)
	}
	return s, nil
}

// Frame decodes frame k: entries [Start + k*Boundary, Start + (k+1)*Boundary).
func (s *Sample) Frame(k int) ([]Entry, error) {
	m := s.Manifest
	if k < 0 || k >= len(m.Frames) {
		return nil, fmt.Errorf("sample: no frame %d", k)
	}
	end := m.Files[EntriesFile].Bytes
	if k+1 < len(m.Frames) {
		end = m.Frames[k+1]
	}
	f, err := os.Open(filepath.Join(s.Dir, EntriesFile))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if m.Frames[k] < 0 || end < m.Frames[k] {
		return nil, corrupt("frame %d has offsets %d-%d", k, m.Frames[k], end)
	}
	dec, err := zstd.NewReader(io.NewSectionReader(f, m.Frames[k], end-m.Frames[k]), zstd.WithDecoderConcurrency(1))
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	first := m.Start + uint64(k)*m.Boundary
	out := make([]Entry, 0, m.Boundary)
	sc := bufio.NewScanner(dec)
	sc.Buffer(make([]byte, 64<<10), maxLine)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, corrupt("frame %d line %d: %v", k, len(out)+1, err)
		}
		if e.Index != first+uint64(len(out)) || e.LeafInput == nil || e.ExtraData == nil {
			return nil, corrupt("frame %d: entry %d out of place", k, e.Index)
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, corrupt("frame %d: %v", k, err)
	}
	if uint64(len(out)) != m.Boundary {
		return nil, corrupt("frame %d holds %d entries, want %d", k, len(out), m.Boundary)
	}
	return out, nil
}

// Each calls fn for every entry in index order.
func (s *Sample) Each(fn func(Entry) error) error {
	if s.Tiled() {
		return s.eachTiled(fn)
	}
	for k := range s.Manifest.Frames {
		entries, err := s.Frame(k)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := fn(e); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkpoint verifies the accumulated range at size m against the head.
func (s *Sample) checkpoint(st *merkle.State) error {
	m, size := st.Size(), s.Head.TreeSize
	root, err := st.Root()
	if err != nil {
		return err
	}
	if m == size {
		if root != s.Head.RootHash {
			return corrupt("root at %d differs from the signed root", m)
		}
		return nil
	}
	c, ok := s.Proofs.find(m, size)
	if !ok {
		return corrupt("no consistency proof from %d to %d", m, size)
	}
	if err := merkle.VerifyConsistency(m, size, root, s.Head.RootHash, hashes(c.Nodes)); err != nil {
		return corrupt("entries up to %d: %v", m, err)
	}
	return nil
}

// StartState returns the authenticated compact range of [0, Start): empty
// for a canonical sample, and for a representative one the left siblings of
// the inclusion proof of leaf Start (amendment A1 §2.4).
func (s *Sample) StartState() (*merkle.State, error) {
	m := s.Manifest
	if m.Kind == Canonical {
		return merkle.NewState(), nil
	}
	if s.Tiled() { // read from hash tiles and verified by Open (amendment A6 §5)
		if s.start == nil {
			return nil, corrupt("the start state was not verified")
		}
		return s.start.Clone(), nil
	}
	inc := s.Proofs.Inclusion
	if inc == nil || inc.LeafIndex != m.Start || inc.TreeSize != s.Head.TreeSize {
		return nil, corrupt("representative sample lacks the inclusion proof of leaf %d", m.Start)
	}
	st, err := merkle.StateFromInclusion(m.Start, s.Head.TreeSize, inc.LeafHash, s.Head.RootHash, hashes(inc.AuditPath))
	if err != nil {
		return nil, corrupt("%v", err)
	}
	return st, nil
}

func (s *Sample) verifyMerkle() error {
	m := s.Manifest
	st, err := s.StartState()
	if err != nil {
		return err
	}
	err = s.Each(func(e Entry) error {
		h := merkle.LeafHash(e.LeafInput)
		if e.Index == m.Start && m.Kind == Representative && h != s.Proofs.Inclusion.LeafHash {
			return corrupt("entry %d is not the leaf the inclusion proof covers", e.Index)
		}
		if err := st.Append(h); err != nil {
			return err
		}
		if m.Kind == Canonical && (e.Index+1-m.Start)%m.Boundary == 0 {
			return s.checkpoint(st)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if m.Kind == Representative {
		return s.checkpoint(st)
	}
	return nil
}

// LogInfo returns the sampled log with its pinned key, served at url.
func (s *Sample) LogInfo(url string) logsource.LogInfo {
	info := logsource.LogInfo{Name: s.Manifest.Log.Name, Kind: loglist.KindRFC6962, LogID: s.LogIDBytes(), PublicKey: s.pub, URL: url}
	if s.Tiled() {
		info.Kind, info.Origin = loglist.KindTiled, s.Manifest.Log.Origin
	}
	return info
}

// SignedHead is the sample's pinned head with its raw bytes, as a source
// that never fetched it accepts it.
func (s *Sample) SignedHead() logsource.SignedHead {
	return logsource.SignedHead{SignedTreeHead: s.Head, Raw: s.Manifest.HeadRaw}
}

// LogIDBytes returns the sampled log's ID.
func (s *Sample) LogIDBytes() [32]byte {
	var id [32]byte
	b, _ := base64.StdEncoding.DecodeString(s.Manifest.Log.LogID)
	copy(id[:], b)
	return id
}
