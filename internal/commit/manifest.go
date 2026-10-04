package commit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

// ManifestFile is the commit marker inside a batch directory (spec §8.4).
const (
	ManifestFile   = "_COMMIT.json"
	QuarantineFile = "quarantine.ndjson"
	ManifestFormat = 1
)

// BatchID names a batch: "<log>/<first>-<last>", indexes inclusive and
// zero-padded to 12 digits (spec §6.1).
type BatchID struct {
	Log         string
	First, Last uint64
}

func (b BatchID) span() string { return fmt.Sprintf("%012d-%012d", b.First, b.Last) }

// String is the batch ID as written in _COMMIT.json.
func (b BatchID) String() string { return b.Log + "/" + b.span() }

// file is the batch ID as a single path element (intents, staging).
func (b BatchID) file() string { return b.Log + "__" + b.span() }

// Paths locates the commit protocol's files under a vault root.
type Paths struct{ Root string }

func (p Paths) BatchDir(b BatchID) string {
	return filepath.Join(p.Root, "dataset", "log="+b.Log, "batch="+b.span())
}
func (p Paths) StageDir(b BatchID) string { return filepath.Join(p.Root, "tmp", "stage", b.file()) }
func (p Paths) IntentPath(b BatchID) string {
	return filepath.Join(p.Root, "state", "intent", b.file()+".json")
}
func (p Paths) StateDir() string { return filepath.Join(p.Root, "state") }

// STH is the pinned signed tree head a batch was verified against.
type STH struct {
	TreeSize  uint64 `json:"tree_size"`
	Timestamp uint64 `json:"timestamp"`
	RootHash  string `json:"root_hash"` // hex
	Signature string `json:"signature"` // base64 DigitallySigned
}

// Verified records how the batch was checked against the STH (spec §5.5).
type Verified struct {
	Method     string `json:"method"` // "consistency_proof" or "root_equals_sth"
	ProofNodes int    `json:"proof_nodes"`
}

// Span is a vault range [Start, End).
type Span struct {
	Start vault.Tail `json:"start"`
	End   vault.Tail `json:"end"`
}

// Counts summarise a batch. VaultBytes feeds the disk guard's per-entry
// history (spec §10.1).
type Counts struct {
	Entries      int    `json:"entries"`
	NewCerts     int    `json:"new_certs"` // leaf and chain certificates vaulted by this batch
	DeltaRecords int    `json:"delta_records"`
	LeafErrors   int    `json:"leaf_errors"`
	VaultBytes   uint64 `json:"vault_bytes"`
}

// DictInfo records the dictionary new records used and any training
// failure (amendment A1 §5).
type DictInfo struct {
	ID            uint64 `json:"id"`
	TrainingError string `json:"training_error,omitempty"`
}

// Manifest is _COMMIT.json (spec §8.4, Plan 2 subset: no derived builders yet).
type Manifest struct {
	Format         int                         `json:"format"`
	CommitSeq      uint64                      `json:"commit_seq"`
	BatchID        string                      `json:"batch_id"`
	Log            string                      `json:"log"`
	First          uint64                      `json:"first"`
	Last           uint64                      `json:"last"`
	STH            STH                         `json:"sth"`
	MerkleAfter    *merkle.State               `json:"merkle_after"`
	Verified       Verified                    `json:"verified"`
	CertIDRange    *[2]uint64                  `json:"cert_id_range"` // first and last assigned; null if none
	NextCertID     uint64                      `json:"next_cert_id"`
	Vault          Span                        `json:"vault"`
	Builders       map[string]int              `json:"builders"`
	Files          map[string]dataset.FileInfo `json:"files"`
	Counts         Counts                      `json:"counts"`
	Dictionary     DictInfo                    `json:"dictionary"`
	CTVaultVersion string                      `json:"ctvault_version"`
	CommittedAt    time.Time                   `json:"committed_at"`
}

// ID returns the manifest's batch ID.
func (m Manifest) ID() BatchID { return BatchID{Log: m.Log, First: m.First, Last: m.Last} }

func corrupt(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(format, args...))
}

// readManifest reads and checks a committed batch directory: its manifest
// must be complete and consistent with the directory name, and every listed
// file must exist with its recorded size. Full checksums are left to
// "ctvault verify" (amendment decision, Plan 2B).
func readManifest(dir, log, span string) (Manifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		return Manifest{}, corrupt("committed batch %s has no readable %s: %v", dir, ManifestFile, err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return m, corrupt("%s/%s: %v", dir, ManifestFile, err)
	}
	if m.Format != ManifestFormat || m.Log != log || m.ID().span() != span || m.BatchID != m.ID().String() ||
		m.First > m.Last || m.CommitSeq == 0 || m.MerkleAfter == nil || m.MerkleAfter.Size() != m.Last+1 {
		return m, corrupt("%s/%s is inconsistent with its directory", dir, ManifestFile)
	}
	for _, name := range []string{dataset.EntriesFile, dataset.ChainsFile} {
		if _, ok := m.Files[name]; !ok {
			return m, corrupt("%s/%s does not list %s", dir, ManifestFile, name)
		}
	}
	for name, fi := range m.Files {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil || st.Size() != fi.Bytes {
			return m, corrupt("%s/%s is missing or has the wrong size", dir, name)
		}
	}
	return m, nil
}

// ListCommitted reads every committed batch, ordered by commit_seq, and
// checks that each log's batches are contiguous from index 0 and that
// commit_seq values are unique.
func ListCommitted(root string) ([]Manifest, error) {
	logs, err := os.ReadDir(filepath.Join(root, "dataset"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var all []Manifest
	for _, l := range logs {
		log, ok := strings.CutPrefix(l.Name(), "log=")
		if !ok || !l.IsDir() {
			continue
		}
		batches, err := os.ReadDir(filepath.Join(root, "dataset", l.Name()))
		if err != nil {
			return nil, err
		}
		var mine []Manifest
		for _, b := range batches {
			span, ok := strings.CutPrefix(b.Name(), "batch=")
			if !ok || !b.IsDir() {
				continue
			}
			m, err := readManifest(filepath.Join(root, "dataset", l.Name(), b.Name()), log, span)
			if err != nil {
				return nil, err
			}
			mine = append(mine, m)
		}
		sort.Slice(mine, func(i, j int) bool { return mine[i].First < mine[j].First })
		next := uint64(0)
		for _, m := range mine {
			if m.First != next {
				return nil, corrupt("log %s: batches are not contiguous at index %d (next batch starts at %d)", log, next, m.First)
			}
			next = m.Last + 1
		}
		all = append(all, mine...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].CommitSeq < all[j].CommitSeq })
	for i := 1; i < len(all); i++ {
		if all[i].CommitSeq == all[i-1].CommitSeq {
			return nil, corrupt("commit_seq %d appears twice", all[i].CommitSeq)
		}
	}
	return all, nil
}

// LogTip is a log's committed position.
type LogTip struct {
	Next  uint64        // first index not yet committed
	State *merkle.State // compact range of [0, Next)
}

// Tips returns each log's committed position.
func Tips(committed []Manifest) map[string]LogTip {
	out := map[string]LogTip{}
	for _, m := range committed {
		if t, ok := out[m.Log]; !ok || m.Last+1 > t.Next {
			out[m.Log] = LogTip{Next: m.Last + 1, State: m.MerkleAfter}
		}
	}
	return out
}
