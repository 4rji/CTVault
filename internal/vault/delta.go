package vault

// DeltaCache maps a precert's full 32-byte issuance digest to its vault
// record and cert_id (the final certificate's certs.delta_base_cert_id),
// for recently vaulted precerts (spec §6.2, amendment A1 §5). It is
// an optimization only: an eviction or a restart simply stores the final
// certificate in full. Entries are evicted oldest first, which for
// precerts inserted once and looked up once behaves like an LRU.
//
// Layout: a ring of (full digest, location) and a map from the digest's
// first 16 bytes to a ring slot. A hit requires all 32 bytes to match. On a
// 16-byte prefix collision the newer precert wins, which only costs a
// delta. The default 2M entries take 207 MiB of heap (measured 2026-10-04;
// spec §6.2 estimated about 128 MB), against 317 MiB for a map keyed by the
// full digest. Lower ingest.delta_lru_entries on small machines.
type DeltaCache struct {
	idx  map[[16]byte]int32
	ring []cacheSlot
	next int
}

type cacheSlot struct {
	digest [32]byte
	loc    Loc
	certID uint64
	used   bool
}

// NewDeltaCache holds at most capacity entries (ingest.delta_lru_entries);
// capacity 0 disables the cache.
func NewDeltaCache(capacity int) *DeltaCache {
	return &DeltaCache{idx: make(map[[16]byte]int32, capacity), ring: make([]cacheSlot, capacity)}
}

func prefix(d [32]byte) (p [16]byte) {
	copy(p[:], d[:16])
	return p
}

// Put records a precert's location and cert_id, evicting the oldest entry
// when full.
func (c *DeltaCache) Put(digest [32]byte, loc Loc, certID uint64) {
	if len(c.ring) == 0 {
		return
	}
	k := prefix(digest)
	if i, ok := c.idx[k]; ok && c.ring[i].digest == digest {
		c.ring[i].loc, c.ring[i].certID = loc, certID
		return
	}
	slot := &c.ring[c.next]
	if slot.used {
		if old := prefix(slot.digest); c.idx[old] == int32(c.next) {
			delete(c.idx, old)
		}
	}
	*slot = cacheSlot{digest: digest, loc: loc, certID: certID, used: true}
	c.idx[k] = int32(c.next)
	c.next = (c.next + 1) % len(c.ring)
}

// Get returns the precert record and cert_id for digest.
func (c *DeltaCache) Get(digest [32]byte) (Loc, uint64, bool) {
	i, ok := c.idx[prefix(digest)]
	if !ok || c.ring[i].digest != digest {
		return Loc{}, 0, false
	}
	return c.ring[i].loc, c.ring[i].certID, true
}

// Len returns the number of cached precerts.
func (c *DeltaCache) Len() int { return len(c.idx) }

// Reset empties the cache and keeps its memory for reuse.
func (c *DeltaCache) Reset() {
	clear(c.idx)
	clear(c.ring)
	c.next = 0
}

// Range is a span of the vault, [Start, End), as recorded in _COMMIT.json.
type Range struct {
	Start, End Tail
}

// Warm refills the cache from the leaf records in ranges, normally the last
// delta.warm_batches committed batches. digest returns a precert's issuance
// digest, or false for any other certificate.
func Warm(dirs []string, codec *Codec, c *DeltaCache, ranges []Range, digest func(der []byte) ([32]byte, bool)) error {
	// Consecutive batches are contiguous in the vault: scan them as one range,
	// so a segment shared by several batches is read once.
	var merged []Range
	for _, rg := range ranges {
		if n := len(merged); n > 0 && merged[n-1].End == rg.Start {
			merged[n-1].End = rg.End
			continue
		}
		merged = append(merged, rg)
	}
	for _, rg := range merged {
		err := Scan(dirs, rg.Start, rg.End, func(loc Loc, rec Record) error {
			if rec.Kind != KindLeaf {
				return nil
			}
			der, err := codec.Decompress(rec.Frame, rec.DictID)
			if err != nil {
				return err
			}
			if d, ok := digest(der); ok {
				c.Put(d, loc, rec.CertID)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}
