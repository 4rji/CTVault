package logsource

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/merkle"
)

// HeadsDir holds each log's last accepted signed head, state/heads/<log>.json
// (Plan 2B decision: the persisted head is the last signed head, amendment
// A1 §3; it never changes on --until).
const HeadsDir = "heads"

type headFile struct {
	TreeSize   uint64    `json:"tree_size"`
	Timestamp  uint64    `json:"timestamp"`
	RootHash   string    `json:"root_hash"` // hex
	Signature  string    `json:"signature"` // base64 DigitallySigned
	Raw        string    `json:"raw"`       // base64 of the response as received
	AcceptedAt time.Time `json:"accepted_at"`
}

func headPath(stateDir, log string) string { return filepath.Join(stateDir, HeadsDir, log+".json") }

// SaveHead records h as log's last accepted head, durably.
func SaveHead(stateDir, log string, h SignedHead, now time.Time) error {
	if err := fsutil.MkdirAllSync(filepath.Join(stateDir, HeadsDir), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(headFile{TreeSize: h.TreeSize, Timestamp: h.Timestamp,
		RootHash: hex.EncodeToString(h.RootHash[:]), Signature: base64.StdEncoding.EncodeToString(h.Signature),
		Raw: base64.StdEncoding.EncodeToString(h.Raw), AcceptedAt: now.UTC()}, "", " ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(headPath(stateDir, log), b, 0o644)
}

// ErrBadHeadFile means a stored head is unreadable or no longer verifies.
var ErrBadHeadFile = errors.New("stored signed head is damaged")

// LoadHead returns log's last accepted head, nil if none, after checking its
// signature with the pinned key again.
func LoadHead(stateDir, log string, info LogInfo) (*SignedHead, error) {
	b, err := os.ReadFile(headPath(stateDir, log))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f headFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrBadHeadFile, headPath(stateDir, log), err)
	}
	root, err1 := hex.DecodeString(f.RootHash)
	sig, err2 := base64.StdEncoding.DecodeString(f.Signature)
	raw, err3 := base64.StdEncoding.DecodeString(f.Raw)
	if err1 != nil || err2 != nil || err3 != nil || len(root) != 32 {
		return nil, fmt.Errorf("%w: %s", ErrBadHeadFile, headPath(stateDir, log))
	}
	h := SignedHead{SignedTreeHead: merkle.SignedTreeHead{TreeSize: f.TreeSize, Timestamp: f.Timestamp, Signature: sig}, Raw: raw}
	copy(h.RootHash[:], root)
	if err := merkle.VerifySTH(info.PublicKey, h.SignedTreeHead); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrBadHeadFile, headPath(stateDir, log), err)
	}
	return &h, nil
}
