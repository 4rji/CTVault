// Package tiled is CTVault's client for static-ct-api (tiled) CT logs and
// the LogSource built on it (amendment A6): checkpoints, hash tiles, data
// tiles and issuers under a log's monitoring prefix. Every tiled entry
// becomes the RawEntry the RFC 6962 source would produce for it.
package tiled

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/merkle"
)

// Source is the tiled LogSource.
type Source struct {
	client    *Client
	info      logsource.LogInfo
	issuers   *issuers
	fallbacks atomic.Int64

	mu   sync.Mutex
	last *logsource.SignedHead
}

var (
	_ logsource.LogSource = (*Source)(nil)
	_ logsource.PageSizer = (*Source)(nil)
)

// NewSource reads the tiled log described by info, whose URL is the
// monitoring prefix and Origin the pinned checkpoint origin. last is the
// last head accepted for this log (nil if none): Head refuses any head
// inconsistent with it, and Fetch sizes partial data tiles by the latest.
func NewSource(info logsource.LogInfo, hc *http.Client, last *logsource.SignedHead) *Source {
	c := NewClient(info.URL, hc)
	return &Source{client: c, info: info, issuers: newIssuers(c, logsource.DefaultChainCacheBytes), last: last}
}

// Info returns the pinned log identity.
func (s *Source) Info() logsource.LogInfo { return s.info }

// PageSize makes the fetcher read one data tile per request.
func (s *Source) PageSize() int { return PageSize }

// Client exposes the HTTP client, for sample capture.
func (s *Source) Client() *Client { return s.client }

// Counters are what a source did beyond one request per tile.
type Counters struct {
	IssuersFetched   int64 // issuer certificates fetched from the log
	PartialFallbacks int64 // partial tiles that answered 404 and were read from the full tile
}

// Counters reports the source's counters so far.
func (s *Source) Counters() Counters {
	return Counters{IssuersFetched: s.issuers.fetched.Load(), PartialFallbacks: s.fallbacks.Load()}
}

// Head fetches the checkpoint, checks it (amendment A6 §2), verifies its
// signature with the pinned key and checks it against the last accepted
// head. Only a head that passes all of these becomes the new last accepted
// head. The returned head carries the raw checkpoint even on failure, for
// incident evidence.
func (s *Source) Head(ctx context.Context) (logsource.SignedHead, error) {
	raw, err := s.client.Get(ctx, "checkpoint", MaxCheckpointBytes)
	if err != nil {
		return logsource.SignedHead{}, err
	}
	sth, err := ParseCheckpoint(raw, s.info.Origin, s.info.LogID)
	h := logsource.SignedHead{SignedTreeHead: sth, Raw: raw}
	if err != nil {
		return h, fmt.Errorf("log %s: %w", s.info.Name, err)
	}
	if err := merkle.VerifySTH(s.info.PublicKey, sth); err != nil {
		return h, fmt.Errorf("log %s: %w", s.info.Name, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := logsource.CheckHead(s.last, h); err != nil {
		return h, fmt.Errorf("log %s: %w", s.info.Name, err)
	}
	s.last = &h
	return h, nil
}

// Fetch returns entries [start, start+n) for some 1 <= n <= end-start, from
// the data tile holding start (amendment A6 §3). The tile is read as it
// exists in the latest verified head: full when it is full there, else the
// partial, falling back to the full tile. Issuers are resolved before any
// entry is decoded.
func (s *Source) Fetch(ctx context.Context, start, end uint64) ([]logsource.RawEntry, error) {
	if end <= start {
		return nil, fmt.Errorf("fetch: empty range [%d, %d)", start, end)
	}
	s.mu.Lock()
	last := s.last
	s.mu.Unlock()
	if last == nil {
		return nil, fmt.Errorf("log %s: no verified checkpoint yet to read tiles against", s.info.Name)
	}
	if end > last.TreeSize {
		return nil, fmt.Errorf("log %s: fetch [%d, %d) beyond the verified tree of %d entries", s.info.Name, start, end, last.TreeSize)
	}
	n := start / Width
	body, w, served, err := s.client.fetchTile(ctx, -1, n, last.TreeSize, maxDataBytes, &s.fallbacks)
	if err != nil {
		return nil, err
	}
	leaves, err := parseDataTile(body, served, DataPath(n, served))
	if err != nil {
		return nil, err
	}
	first := n * Width
	leaves = leaves[start-first : min(end, first+uint64(w))-first]
	fps := map[[32]byte]bool{}
	for _, l := range leaves {
		for _, fp := range l.chain {
			fps[fp] = true
		}
	}
	ders, err := s.issuers.resolve(ctx, fps)
	if err != nil {
		return nil, err
	}
	out := make([]logsource.RawEntry, len(leaves))
	for k, l := range leaves {
		chain := make([][]byte, len(l.chain))
		for j, fp := range l.chain {
			chain[j] = ders[fp]
		}
		idx := start + uint64(k)
		li, ed := l.leafInput(), l.extraData(chain)
		e := logsource.RawEntry{Index: idx, LeafInput: li, ExtraData: ed, Leaf: leaf.Decode(li, ed), Chain: l.chain, TileLeaf: l.raw}
		leaf.CheckLeafIndex(&e.Leaf, l.extensions, idx)
		out[k] = e
	}
	return out, nil
}

// ConsistencyProof computes the proof from first to second from hash tiles
// (amendment A6 §4.1). Sizes 0 and equal sizes need no proof and make no
// request.
func (s *Source) ConsistencyProof(ctx context.Context, first, second uint64) ([][32]byte, error) {
	return s.client.ConsistencyProof(ctx, first, second, &s.fallbacks)
}

// Issuer returns a chain certificate from the issuer cache, fetching it from
// the log if this run has not seen it.
func (s *Source) Issuer(ctx context.Context, fp [32]byte) ([]byte, error) {
	return s.issuers.get(ctx, fp)
}
