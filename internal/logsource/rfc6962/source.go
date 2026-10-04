package rfc6962

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/merkle"
)

// Source is the RFC 6962 LogSource. Chains arrive inline with every entry, so
// it hashes them and serves Issuer from the per-batch chain cache.
type Source struct {
	client *Client
	info   logsource.LogInfo
	chains *logsource.ChainCache

	mu   sync.Mutex
	last *logsource.SignedHead
}

var _ logsource.LogSource = (*Source)(nil)

// NewSource reads the log described by info. last is the last head accepted
// for this log (nil if none); Head refuses any head inconsistent with it.
func NewSource(info logsource.LogInfo, hc *http.Client, chains *logsource.ChainCache, last *logsource.SignedHead) *Source {
	return &Source{client: New(info.URL, hc), info: info, chains: chains, last: last}
}

// Info returns the pinned log identity.
func (s *Source) Info() logsource.LogInfo { return s.info }

// Client exposes the HTTP client for calls outside the LogSource interface,
// such as get-proof-by-hash.
func (s *Source) Client() *Client { return s.client }

// Head fetches the signed tree head, verifies its signature with the pinned
// key and checks it against the last accepted head. Only a head that passes
// both becomes the new last accepted head.
func (s *Source) Head(ctx context.Context) (logsource.SignedHead, error) {
	sth, raw, err := s.client.GetSTHRaw(ctx)
	if err != nil {
		return logsource.SignedHead{}, err
	}
	h := logsource.SignedHead{SignedTreeHead: sth, Raw: raw}
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

// Fetch returns entries [start, start+n) for some 1 <= n <= end-start. Each
// entry's index is its request position, never derived from counts.
func (s *Source) Fetch(ctx context.Context, start, end uint64) ([]logsource.RawEntry, error) {
	if end <= start {
		return nil, fmt.Errorf("fetch: empty range [%d, %d)", start, end)
	}
	wire, err := s.client.GetEntries(ctx, start, end-1)
	if err != nil {
		return nil, err
	}
	out := make([]logsource.RawEntry, len(wire))
	for i, w := range wire {
		e := logsource.RawEntry{Index: start + uint64(i), LeafInput: w.LeafInput, ExtraData: w.ExtraData,
			Leaf: leaf.Decode(w.LeafInput, w.ExtraData)}
		if e.Chain, err = logsource.FingerprintChain(s.chains, e.Leaf.Chain); err != nil {
			return nil, err
		}
		out[i] = e
	}
	return out, nil
}

// ConsistencyProof fetches the proof from first to second. Sizes 0 and equal
// sizes need no proof, so no request is made.
func (s *Source) ConsistencyProof(ctx context.Context, first, second uint64) ([][32]byte, error) {
	if first == 0 || first == second {
		return nil, nil
	}
	return s.client.GetSTHConsistency(ctx, first, second)
}

// Issuer returns a chain certificate seen in the current batch.
func (s *Source) Issuer(_ context.Context, fp [32]byte) ([]byte, error) {
	if der, ok := s.chains.Get(fp); ok {
		return der, nil
	}
	return nil, fmt.Errorf("%w: %x", logsource.ErrIssuerUnknown, fp)
}
