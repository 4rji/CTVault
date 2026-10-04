package logsource

import (
	"errors"
	"fmt"
	"sync"
)

// DefaultChainCacheBytes bounds the chain cache. Measured on 32,768
// contiguous real argon2027h1 entries: 167 distinct chain certificates,
// 184 KiB in total, so the bound leaves about 350x headroom.
const DefaultChainCacheBytes = 64 << 20

// ErrChainCacheFull means a batch referenced more distinct chain bytes than
// the bound allows. The batch is abandoned rather than dropping anything.
var ErrChainCacheFull = errors.New("chain cache full")

// ChainCache holds chain certificate DER by SHA-256 for the batch in flight
// (amendment A1 §4). It is safe for concurrent use. Entries are removed only
// by Reset, which the writer calls after the batch commits, so the cache
// never grows across batches.
type ChainCache struct {
	mu    sync.Mutex
	max   int
	bytes int
	certs map[[32]byte][]byte
}

// NewChainCache returns a cache holding at most maxBytes of DER.
func NewChainCache(maxBytes int) *ChainCache {
	return &ChainCache{max: maxBytes, certs: map[[32]byte][]byte{}}
}

// Put stores a copy of der under fp; storing a known fp is free.
func (c *ChainCache) Put(fp [32]byte, der []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.certs[fp]; ok {
		return nil
	}
	if c.bytes+len(der) > c.max {
		return fmt.Errorf("%w: %d bytes cached, limit %d", ErrChainCacheFull, c.bytes, c.max)
	}
	c.certs[fp] = append([]byte(nil), der...)
	c.bytes += len(der)
	return nil
}

// Get returns the DER stored under fp.
func (c *ChainCache) Get(fp [32]byte) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	der, ok := c.certs[fp]
	return der, ok
}

// Len and Bytes report the cache's contents.
func (c *ChainCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.certs)
}

func (c *ChainCache) Bytes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytes
}

// Reset empties the cache. Call it only after the batch has committed.
func (c *ChainCache) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.certs = map[[32]byte][]byte{}
	c.bytes = 0
}
