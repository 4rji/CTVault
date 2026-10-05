package dataset

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"slices"
	"time"
)

// ErrCanary means a staged file does not hold what was written; the batch is
// not committed (spec §8.3 P6).
var ErrCanary = errors.New("canary failed")

func canaryErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCanary, fmt.Sprintf(format, args...))
}

// expected column types, as DuckDB reads them back. ct_ts is checked again
// in the Parquet schema, because DuckDB reads TIMESTAMP_MS back as TIMESTAMP.
var (
	entriesSchema = []string{"idx UBIGINT", "ct_ts TIMESTAMP", "entry_type VARCHAR", "cert_id UBIGINT",
		"leaf_hash BLOB", "issuance_key BLOB", "issuer_key_hash BLOB", "chain_id BLOB", "leaf_error VARCHAR"}
	chainsSchema = []string{"chain_id BLOB", "position USMALLINT", "cert_id UBIGINT"}
)

// Canary checks staged files against the rows they were written from:
// column names and types, no bloom filter anywhere, row counts, n random
// rows read back field by field through literal BLOB lookups, the path
// readers use, and cert_id range counts (spec §8.3 P6(e)): the batch's
// whole range and n random sub-ranges.
func (s *Stager) Canary(ctx context.Context, dir string, entries []EntryRow, chains []ChainRow, n int, rnd *rand.Rand) error {
	ep, cp := filepath.Join(dir, EntriesFile), filepath.Join(dir, ChainsFile)
	for _, f := range []struct {
		path   string
		schema []string
		rows   int
	}{{ep, entriesSchema, len(entries)}, {cp, chainsSchema, len(chains)}} {
		if err := s.checkSchema(ctx, f.path, f.schema); err != nil {
			return err
		}
		var blooms, rows int
		if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM parquet_metadata(`+quote(f.path)+`) WHERE bloom_filter_offset IS NOT NULL`).Scan(&blooms); err != nil {
			return err
		}
		if blooms != 0 {
			return canaryErr("%s has %d bloom filters; none are allowed", filepath.Base(f.path), blooms)
		}
		if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM read_parquet(`+quote(f.path)+`)`).Scan(&rows); err != nil {
			return err
		}
		if rows != f.rows {
			return canaryErr("%s has %d rows, want %d", filepath.Base(f.path), rows, f.rows)
		}
	}
	var unit string
	if err := s.db.QueryRowContext(ctx, `SELECT logical_type FROM parquet_schema(`+quote(ep)+`) WHERE name = 'ct_ts'`).Scan(&unit); err != nil {
		return err
	}
	if !bytes.Contains([]byte(unit), []byte("MILLIS=MilliSeconds")) {
		return canaryErr("ct_ts is %q, want TIMESTAMP_MS", unit)
	}
	for range min(n, len(entries)) {
		if err := s.checkEntry(ctx, ep, entries[rnd.IntN(len(entries))]); err != nil {
			return err
		}
	}
	if err := s.checkCertRanges(ctx, ep, entries, n, rnd); err != nil {
		return err
	}
	for range min(n, len(chains)) {
		r := chains[rnd.IntN(len(chains))]
		var cert uint64
		err := s.db.QueryRowContext(ctx, `SELECT cert_id FROM read_parquet(`+quote(cp)+`) WHERE chain_id = ?::BLOB AND position = ?`,
			r.ChainID[:], r.Position).Scan(&cert)
		if err != nil || cert != r.CertID {
			return canaryErr("chain %x position %d: cert_id %d, %v; want %d", r.ChainID[:4], r.Position, cert, err, r.CertID)
		}
	}
	return nil
}

// checkCertRanges counts rows by cert_id range, as readers select them.
func (s *Stager) checkCertRanges(ctx context.Context, path string, entries []EntryRow, n int, rnd *rand.Rand) error {
	var ids []uint64
	for _, e := range entries {
		if e.CertID != 0 {
			ids = append(ids, e.CertID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	slices.Sort(ids)
	ranges := [][2]uint64{{ids[0], ids[len(ids)-1]}}
	for range min(n, len(ids)) {
		a, b := ids[rnd.IntN(len(ids))], ids[rnd.IntN(len(ids))]
		ranges = append(ranges, [2]uint64{min(a, b), max(a, b)})
	}
	for _, r := range ranges {
		lo, _ := slices.BinarySearch(ids, r[0]) // the first id >= r[0]
		hi, _ := slices.BinarySearch(ids, r[1]+1)
		var got int
		if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM read_parquet(`+quote(path)+`) WHERE cert_id BETWEEN ? AND ?`, r[0], r[1]).Scan(&got); err != nil {
			return err
		}
		if got != hi-lo {
			return canaryErr("cert_id range [%d, %d] has %d rows, want %d", r[0], r[1], got, hi-lo)
		}
	}
	return nil
}

func (s *Stager) checkSchema(ctx context.Context, path string, want []string) error {
	rows, err := s.db.QueryContext(ctx, `SELECT column_name, column_type FROM (DESCRIBE SELECT * FROM read_parquet(`+quote(path)+`))`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var name, typ string
		if err := rows.Scan(&name, &typ); err != nil {
			return err
		}
		got = append(got, name+" "+typ)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		return canaryErr("%s schema %v, want %v", filepath.Base(path), got, want)
	}
	return rows.Err()
}

// checkEntry finds a row by its leaf hash literal and compares every field.
func (s *Stager) checkEntry(ctx context.Context, path string, want EntryRow) error {
	var idx uint64
	var ts sql.NullTime
	var etype string
	var cert sql.NullInt64
	var ikey, ikh, chain []byte
	var lerr sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT idx, ct_ts, entry_type, cert_id, issuance_key, issuer_key_hash, chain_id, leaf_error
		FROM read_parquet(`+quote(path)+`) WHERE leaf_hash = ?::BLOB AND idx = ?`, want.LeafHash[:], want.Idx).
		Scan(&idx, &ts, &etype, &cert, &ikey, &ikh, &chain, &lerr)
	if err != nil {
		return canaryErr("entry %d: %v", want.Idx, err)
	}
	wantTS := sql.NullTime{}
	if want.CTTimestamp != 0 {
		wantTS = sql.NullTime{Time: time.UnixMilli(int64(want.CTTimestamp)).UTC(), Valid: true}
	}
	ok := idx == want.Idx && ts.Valid == wantTS.Valid && ts.Time.Equal(wantTS.Time) && etype == want.EntryType &&
		cert.Valid == (want.CertID != 0) && uint64(cert.Int64) == want.CertID &&
		blobIs(ikey, want.HasIssuanceKey, want.IssuanceKey[:]) && blobIs(ikh, want.HasIssuerKeyHash, want.IssuerKeyHash[:]) &&
		blobIs(chain, want.HasChainID, want.ChainID[:]) && lerr.String == want.LeafError && lerr.Valid == (want.LeafError != "")
	if !ok {
		return canaryErr("entry %d reads back differently", want.Idx)
	}
	return nil
}

func blobIs(got []byte, has bool, want []byte) bool {
	if !has {
		return got == nil
	}
	return bytes.Equal(got, want)
}
