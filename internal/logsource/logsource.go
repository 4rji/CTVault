// Package logsource defines how CTVault reads one CT log (spec §5.1): the
// LogSource interface, the entries it yields, signed-head checks shared by
// every implementation, the per-batch chain cache, and the HTTP errors both
// implementations report. The RFC 6962 implementation lives in
// logsource/rfc6962, the tiled one (static-ct-api, amendment A6) in
// logsource/tiled.
package logsource

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/logreg"
	"github.com/4rji/ctvault/internal/merkle"
)

// LogInfo is a pinned log's identity. URL is where CTVault reads: the log
// URL, or a tiled log's monitoring prefix (amendment A6 §1).
type LogInfo struct {
	Name      string
	Kind      string // loglist.KindRFC6962 or loglist.KindTiled
	LogID     [32]byte
	PublicKey crypto.PublicKey
	URL       string
	Origin    string // tiled only: the checkpoint origin pinned with the log
}

// InfoFromRecord turns a pinned log into a LogInfo, re-checking that the key
// hashes to the log ID and that the kind's fields agree.
func InfoFromRecord(r logreg.Record) (LogInfo, error) {
	pub, err := r.PublicKey()
	if err != nil {
		return LogInfo{}, fmt.Errorf("log %s: %w", r.Name, err)
	}
	if err := r.CheckKind(); err != nil {
		return LogInfo{}, err
	}
	id, err := base64.StdEncoding.DecodeString(r.LogID)
	if err != nil || len(id) != 32 {
		return LogInfo{}, fmt.Errorf("log %s: log_id is not a base64 32-byte hash", r.Name)
	}
	info := LogInfo{Name: r.Name, Kind: r.LogKind(), PublicKey: pub, URL: r.URL, Origin: r.Origin}
	copy(info.LogID[:], id)
	return info, nil
}

// SignedHead is a verified signed tree head and the response that carried it.
type SignedHead struct {
	merkle.SignedTreeHead
	Raw []byte // the response body exactly as received
}

// RawEntry is one log entry with its index taken from request position
// (spec §5.2), its exact bytes, and its decoded fields.
type RawEntry struct {
	Index     uint64
	LeafInput []byte
	ExtraData []byte
	Leaf      leaf.Entry
	Chain     [][32]byte // chain certificates by SHA-256; nil if the chain could not be decoded
	// TileLeaf is a tiled log's entry exactly as served; LeafInput and
	// ExtraData are then its RFC 6962 form, ExtraData rebuilt from the
	// issuers (amendment A6 §3). Nil for RFC 6962 logs.
	TileLeaf []byte
}

// Size is the entry's weight in the fetcher's byte-bounded reorder buffer.
func (e *RawEntry) Size() int { return len(e.LeafInput) + len(e.ExtraData) + len(e.TileLeaf) }

// LogSource reads one log. Fetch covers [start, end) and may return fewer
// entries than asked, but at least one; it never returns more.
type LogSource interface {
	Info() LogInfo
	Head(ctx context.Context) (SignedHead, error)
	Fetch(ctx context.Context, start, end uint64) ([]RawEntry, error)
	ConsistencyProof(ctx context.Context, first, second uint64) ([][32]byte, error)
	Issuer(ctx context.Context, fp [32]byte) ([]byte, error)
}

// PageSizer is a LogSource that states the size its requests should align
// to: a tiled log is read one 256-entry tile per request (amendment A6
// §4.4). The fetcher uses it instead of its configured page size.
type PageSizer interface {
	PageSize() int
}

// ErrIncident is matched by every *IncidentError: log misbehaviour that must
// stop ingestion with exit 5 (spec §12, amendment A1 §4).
var ErrIncident = errors.New("CT log misbehaviour")

// Incident kinds.
const (
	TreeShrank         = "tree_shrank"
	RootChanged        = "root_changed"
	TimestampBackwards = "timestamp_backwards"
)

// IncidentError records two signed heads that cannot both be honest.
type IncidentError struct {
	Kind      string
	Last, Got SignedHead
}

func (e *IncidentError) Error() string {
	return fmt.Sprintf("%v: %s (last accepted head: size %d, timestamp %d; new head: size %d, timestamp %d)",
		ErrIncident, e.Kind, e.Last.TreeSize, e.Last.Timestamp, e.Got.TreeSize, e.Got.Timestamp)
}

func (e *IncidentError) Is(target error) bool { return target == ErrIncident }

// CheckHead compares a newly verified head with the last accepted one. A
// smaller tree, a different root for the same size, or an older timestamp is
// an incident. last may be nil when no head was accepted yet.
func CheckHead(last *SignedHead, got SignedHead) error {
	if last == nil {
		return nil
	}
	kind := ""
	switch {
	case got.TreeSize < last.TreeSize:
		kind = TreeShrank
	case got.TreeSize == last.TreeSize && got.RootHash != last.RootHash:
		kind = RootChanged
	case got.Timestamp < last.Timestamp:
		kind = TimestampBackwards
	default:
		return nil
	}
	return &IncidentError{Kind: kind, Last: *last, Got: got}
}

// ErrIssuerUnknown means a chain certificate is not in the cache.
var ErrIssuerUnknown = errors.New("chain certificate not cached")

// FingerprintChain hashes each chain certificate and stores it in the cache.
func FingerprintChain(c *ChainCache, chain [][]byte) ([][32]byte, error) {
	if chain == nil {
		return nil, nil
	}
	fps := make([][32]byte, len(chain))
	for i, der := range chain {
		fps[i] = sha256.Sum256(der)
		if err := c.Put(fps[i], der); err != nil {
			return nil, err
		}
	}
	return fps, nil
}
