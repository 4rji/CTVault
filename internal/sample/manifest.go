// Package sample captures, verifies and replays real-data samples of a CT log
// (amendment A1 §2). It is dev-only: production binaries must never import it
// (cmd/ctvault's guard test enforces this).
//
// A sample is a read-only folder:
//
//	sample.json          the manifest (Manifest)
//	entries.ndjson.zst   one JSON line per entry, {"i", "leaf_input", "extra_data"}, bytes exactly
//	                     as served; one zstd frame per Boundary entries, offsets in Manifest.Frames
//	proofs.json          the Merkle proofs that authenticate every entry's leaf_input against the
//	                     signed head (extra_data is not in the Merkle tree; checksums protect it)
package sample

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Format is the sample format version.
const Format = 1

// File names inside a sample folder.
const (
	ManifestFile = "sample.json"
	EntriesFile  = "entries.ndjson.zst"
	ProofsFile   = "proofs.json"
)

// Kind is canonical (fixed forever, may feed a dev vault) or representative
// (a window for measurements only).
type Kind string

const (
	Canonical      Kind = "canonical"
	Representative Kind = "representative"
)

// Limits are the size rules: Min <= count <= Max, and start and count are
// multiples of Boundary.
type Limits struct {
	Boundary, Min, Max uint64
}

// DefaultLimits are amendment A1 §2.1's rules.
var DefaultLimits = Limits{Boundary: 5000, Min: 50_000, Max: 500_000}

// Check validates a sample's start and count.
func (l Limits) Check(kind Kind, start, count uint64) error {
	switch {
	case kind != Canonical && kind != Representative:
		return fmt.Errorf("sample: unknown kind %q", kind)
	case count < l.Min || count > l.Max || count%l.Boundary != 0:
		return fmt.Errorf("sample: --entries must be %d-%d and a multiple of %d, got %d", l.Min, l.Max, l.Boundary, count)
	case kind == Canonical && start != 0:
		return errors.New("sample: a canonical sample starts at index 0")
	case start%l.Boundary != 0:
		return fmt.Errorf("sample: --start must be a multiple of %d, got %d", l.Boundary, start)
	}
	return nil
}

// StartForHead is "--start head": the last whole window that fits under the
// tree, floor((treeSize - count) / boundary) * boundary.
func (l Limits) StartForHead(treeSize, count uint64) (uint64, error) {
	if treeSize < count {
		return 0, fmt.Errorf("sample: the log has %d entries, fewer than the %d requested", treeSize, count)
	}
	return (treeSize - count) / l.Boundary * l.Boundary, nil
}

var validSuffix = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// DirName is "<first>-<last>" with 12-digit indexes (last inclusive, as in
// batch IDs), plus "_<suffix>" when given.
func DirName(start, count uint64, suffix string) (string, error) {
	name := fmt.Sprintf("%012d-%012d", start, start+count-1)
	if suffix == "" {
		return name, nil
	}
	if !validSuffix.MatchString(suffix) {
		return "", fmt.Errorf("sample: --suffix must match %s", validSuffix)
	}
	return name + "_" + suffix, nil
}

// LogRef identifies the log as pinned from Chrome's log list at capture.
type LogRef struct {
	Name           string `json:"name"`
	LogID          string `json:"log_id"` // base64, SHA-256 of Key
	Key            string `json:"key"`    // base64 SubjectPublicKeyInfo
	URL            string `json:"url"`
	Origin         string `json:"origin,omitempty"` // tiled samples: the checkpoint origin
	LogListVersion string `json:"log_list_version"`
}

// FileSum is a file's size and SHA-256.
type FileSum struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// HeadSummary repeats the signed head's fields for people reading the
// manifest; HeadRaw is the authoritative copy.
type HeadSummary struct {
	TreeSize  uint64 `json:"tree_size"`
	Timestamp uint64 `json:"timestamp"`
	RootHash  string `json:"sha256_root_hash"`
}

// Manifest is sample.json.
type Manifest struct {
	Format         int                `json:"format"`
	Protocol       string             `json:"protocol,omitempty"` // ProtocolTiled, or empty for RFC 6962
	Kind           Kind               `json:"kind"`
	Log            LogRef             `json:"log"`
	HeadRaw        []byte             `json:"head_raw"` // get-sth body exactly as received (base64 in JSON)
	Head           HeadSummary        `json:"head"`
	Start          uint64             `json:"start"`
	Count          uint64             `json:"count"`
	Boundary       uint64             `json:"boundary"`
	PageSize       int                `json:"page_size"` // most entries the log served per get-entries
	Frames         []int64            `json:"frames"`    // offset of each zstd frame in EntriesFile
	CapturedAt     time.Time          `json:"captured_at"`
	CTVaultVersion string             `json:"ctvault_version"`
	Files          map[string]FileSum `json:"files"`
}

// ID is "<log>/<folder name>", the sample ID used in measurement reports.
func (m Manifest) ID(dirName string) string { return m.Log.Name + "/" + dirName }

// Node is a Merkle hash, base64 in JSON.
type Node [32]byte

func (n Node) MarshalText() ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(n[:])), nil
}

func (n *Node) UnmarshalText(b []byte) error {
	d, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil || len(d) != 32 {
		return errors.New("sample: a proof node is not a base64 32-byte hash")
	}
	copy(n[:], d)
	return nil
}

func nodes(p [][32]byte) []Node {
	out := make([]Node, len(p))
	for i := range p {
		out[i] = p[i]
	}
	return out
}

func hashes(p []Node) [][32]byte {
	out := make([][32]byte, len(p))
	for i := range p {
		out[i] = p[i]
	}
	return out
}

// Consistency is a consistency proof from First to Second.
type Consistency struct {
	First  uint64 `json:"first"`
	Second uint64 `json:"second"`
	Nodes  []Node `json:"nodes"`
}

// Inclusion is the inclusion proof of the representative window's first leaf.
type Inclusion struct {
	LeafIndex uint64 `json:"leaf_index"`
	TreeSize  uint64 `json:"tree_size"`
	LeafHash  Node   `json:"leaf_hash"`
	AuditPath []Node `json:"audit_path"`
}

// Proofs is proofs.json.
type Proofs struct {
	Consistency []Consistency `json:"consistency"`
	Inclusion   *Inclusion    `json:"inclusion,omitempty"`
}

func (p Proofs) find(first, second uint64) (Consistency, bool) {
	for _, c := range p.Consistency {
		if c.First == first && c.Second == second {
			return c, true
		}
	}
	return Consistency{}, false
}
