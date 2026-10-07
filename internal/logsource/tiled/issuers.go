package tiled

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/4rji/ctvault/internal/logsource"
)

// IssuerConcurrency bounds the issuer requests one source has in flight
// (amendment A6 §3.1).
const IssuerConcurrency = 4

// issuers is a tiled source's issuer cache: filled from <prefix>/issuer/<fp>
// and never emptied during a run (A6 §3.1). Concurrent requests for one
// fingerprint share one fetch.
type issuers struct {
	c        *Client
	cache    *logsource.ChainCache
	sem      chan struct{}
	fetched  atomic.Int64
	mu       sync.Mutex
	inflight map[[32]byte]*issuerCall
}

type issuerCall struct {
	done chan struct{}
	der  []byte
	err  error
}

func newIssuers(c *Client, maxBytes int) *issuers {
	return &issuers{c: c, cache: logsource.NewChainCache(maxBytes), sem: make(chan struct{}, IssuerConcurrency),
		inflight: map[[32]byte]*issuerCall{}}
}

// get returns the issuer with SHA-256 fp, from the cache or the log.
func (is *issuers) get(ctx context.Context, fp [32]byte) ([]byte, error) {
	if der, ok := is.cache.Get(fp); ok {
		return der, nil
	}
	is.mu.Lock()
	if c, ok := is.inflight[fp]; ok {
		is.mu.Unlock()
		select {
		case <-c.done:
			return c.der, c.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	c := &issuerCall{done: make(chan struct{})}
	is.inflight[fp] = c
	is.mu.Unlock()
	c.der, c.err = is.fetch(ctx, fp)
	is.mu.Lock()
	delete(is.inflight, fp)
	is.mu.Unlock()
	close(c.done)
	return c.der, c.err
}

func (is *issuers) fetch(ctx context.Context, fp [32]byte) ([]byte, error) {
	select {
	case is.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-is.sem }()
	if der, ok := is.cache.Get(fp); ok {
		return der, nil
	}
	der, err := is.c.Get(ctx, IssuerPath(fp), maxIssuerSize)
	if err != nil {
		return nil, err
	}
	if sha256.Sum256(der) != fp {
		return nil, fmt.Errorf("%w: issuer %x: the certificate served does not hash to its fingerprint", logsource.ErrMalformed, fp)
	}
	is.fetched.Add(1)
	if err := is.cache.Put(fp, der); err != nil {
		return nil, err
	}
	return der, nil
}

// resolve returns the DER of every fingerprint in fps, fetching the missing
// ones concurrently. The first error cancels the rest and is returned.
func (is *issuers) resolve(ctx context.Context, fps map[[32]byte]bool) (map[[32]byte][]byte, error) {
	out := make(map[[32]byte][]byte, len(fps))
	var missing [][32]byte
	for fp := range fps {
		if der, ok := is.cache.Get(fp); ok {
			out[fp] = der
		} else {
			missing = append(missing, fp)
		}
	}
	if len(missing) == 0 {
		return out, nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	var mu sync.Mutex
	var first error
	for _, fp := range missing {
		wg.Add(1)
		go func() {
			defer wg.Done()
			der, err := is.get(ctx, fp)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if first == nil {
					first = err
					cancel()
				}
				return
			}
			out[fp] = der
		}()
	}
	wg.Wait()
	if first != nil {
		return nil, first
	}
	return out, nil
}
