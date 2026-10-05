// Package index is the writer-private Pebble database (spec §6.3): it maps
// each vaulted certificate's SHA-256 to its cert_id and vault location for
// deduplication, remembers which chains were already written, and records
// the last commit_seq applied per log. Readers never open it (D18), and it
// is rebuildable from the vault.
package index

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/cockroachdb/pebble/v2"

	"github.com/4rji/ctvault/internal/vault"
)

// Key prefixes. "ch/" (chains already written to chains.parquet) is new in
// Plan 2B; it is rebuildable from the committed chains.parquet files.
const (
	prefixCert    = "c/"
	prefixChain   = "ch/"
	prefixApplied = "applied/"
)

// Ref is a vaulted certificate.
type Ref struct {
	CertID uint64
	Loc    vault.Loc
}

func certKey(sha [32]byte) []byte  { return append([]byte(prefixCert), sha[:]...) }
func chainKey(id [32]byte) []byte  { return append([]byte(prefixChain), id[:]...) }
func appliedKey(log string) []byte { return []byte(prefixApplied + log) }

func encodeRef(r Ref) []byte {
	b := binary.AppendUvarint(nil, r.CertID)
	b = binary.AppendUvarint(b, r.Loc.Segment)
	b = binary.AppendUvarint(b, r.Loc.Offset)
	return binary.AppendUvarint(b, uint64(r.Loc.Len))
}

func decodeRef(b []byte) (Ref, error) {
	var vals [4]uint64
	for i := range vals {
		v, n := binary.Uvarint(b)
		if n <= 0 {
			return Ref{}, errors.New("index: malformed certificate entry")
		}
		vals[i], b = v, b[n:]
	}
	if len(b) != 0 || vals[3] > 1<<32-1 {
		return Ref{}, errors.New("index: malformed certificate entry")
	}
	return Ref{CertID: vals[0], Loc: vault.Loc{Segment: vals[1], Offset: vals[2], Len: uint32(vals[3])}}, nil
}

// quiet drops Pebble's informational log lines ("Found 0 WALs") but keeps
// its fatal errors.
type quiet struct{}

func (quiet) Infof(string, ...any)  {}
func (quiet) Errorf(string, ...any) {}
func (quiet) Fatalf(format string, args ...any) {
	panic(fmt.Sprintf(format, args...))
}

// Index is an open Pebble database.
type Index struct {
	db *pebble.DB
}

// Open opens (or creates) the database in dir (state/pebble).
func Open(dir string) (*Index, error) {
	db, err := pebble.Open(dir, &pebble.Options{Logger: quiet{}})
	if err != nil {
		return nil, fmt.Errorf("opening index %s: %w", dir, err)
	}
	return &Index{db: db}, nil
}

// Close closes the database.
func (x *Index) Close() error { return x.db.Close() }

func lookup(get func([]byte) ([]byte, io.Closer, error), sha [32]byte) (Ref, bool, error) {
	v, cl, err := get(certKey(sha))
	if errors.Is(err, pebble.ErrNotFound) {
		return Ref{}, false, nil
	}
	if err != nil {
		return Ref{}, false, err
	}
	defer cl.Close()
	r, err := decodeRef(v)
	return r, err == nil, err
}

// Lookup finds a committed certificate.
func (x *Index) Lookup(sha [32]byte) (Ref, bool, error) {
	return lookup(func(k []byte) ([]byte, io.Closer, error) { return x.db.Get(k) }, sha)
}

// Applied returns the last commit_seq applied for log, 0 if none.
func (x *Index) Applied(log string) (uint64, error) {
	v, cl, err := x.db.Get(appliedKey(log))
	if errors.Is(err, pebble.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer cl.Close()
	n, k := binary.Uvarint(v)
	if k <= 0 {
		return 0, errors.New("index: malformed applied entry")
	}
	return n, nil
}

// AppliedLogs returns the last commit_seq applied for every log.
func (x *Index) AppliedLogs() (map[string]uint64, error) {
	it, err := x.db.NewIter(&pebble.IterOptions{LowerBound: []byte(prefixApplied), UpperBound: []byte(prefixApplied + "\xff")})
	if err != nil {
		return nil, err
	}
	defer it.Close()
	out := map[string]uint64{}
	for it.First(); it.Valid(); it.Next() {
		n, k := binary.Uvarint(it.Value())
		if k <= 0 {
			return nil, errors.New("index: malformed applied entry")
		}
		out[string(it.Key()[len(prefixApplied):])] = n
	}
	return out, it.Error()
}

// EachCert calls fn for every vaulted certificate, in SHA-256 order (for
// checks that compare the index with the vault).
func (x *Index) EachCert(fn func(sha [32]byte, r Ref) error) error {
	upper := []byte(prefixCert)
	upper[len(upper)-1]++ // "c0": just past every "c/" key, before "ch/"
	it, err := x.db.NewIter(&pebble.IterOptions{LowerBound: []byte(prefixCert), UpperBound: upper})
	if err != nil {
		return err
	}
	defer it.Close()
	for it.First(); it.Valid(); it.Next() {
		k := it.Key()
		if len(k) != len(prefixCert)+32 {
			return errors.New("index: malformed certificate key")
		}
		r, err := decodeRef(it.Value())
		if err != nil {
			return err
		}
		var sha [32]byte
		copy(sha[:], k[len(prefixCert):])
		if err := fn(sha, r); err != nil {
			return err
		}
	}
	return it.Error()
}

// Batch holds one batch's index writes in memory until the commit point
// (spec §6.3: "an in-memory indexed batch until commit, which also catches
// duplicates within a batch").
type Batch struct {
	b *pebble.Batch
}

// NewBatch starts an indexed batch.
func (x *Index) NewBatch() *Batch { return &Batch{b: x.db.NewIndexedBatch()} }

// Lookup sees the batch's own writes over the committed database.
func (b *Batch) Lookup(sha [32]byte) (Ref, bool, error) {
	return lookup(func(k []byte) ([]byte, io.Closer, error) { return b.b.Get(k) }, sha)
}

// AddCert records a newly vaulted certificate.
func (b *Batch) AddCert(sha [32]byte, r Ref) error { return b.b.Set(certKey(sha), encodeRef(r), nil) }

// HasChain reports whether chain id was written before or in this batch.
func (b *Batch) HasChain(id [32]byte) (bool, error) {
	_, cl, err := b.b.Get(chainKey(id))
	if errors.Is(err, pebble.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	cl.Close()
	return true, nil
}

// AddChain records a chain written to this batch's chains.parquet.
func (b *Batch) AddChain(id [32]byte) error { return b.b.Set(chainKey(id), nil, nil) }

// SetApplied records the batch's commit_seq for its log (spec §8.3 P9).
func (b *Batch) SetApplied(log string, seq uint64) error {
	return b.b.Set(appliedKey(log), binary.AppendUvarint(nil, seq), nil)
}

// Commit applies the batch durably (Sync = true).
func (b *Batch) Commit() error { return b.b.Commit(pebble.Sync) }

// Close discards an uncommitted batch, or releases a committed one.
func (b *Batch) Close() error { return b.b.Close() }
