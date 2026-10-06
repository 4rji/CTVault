// Package dataset writes the source-layer Parquet files of a batch through
// embedded DuckDB (spec §6.4-6.5, amendment A1 §6), checks them (the canary,
// spec §8.3 P6) and generates views.sql (spec §7.6).
package dataset

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	duckdb "github.com/duckdb/duckdb-go/v2"

	"github.com/4rji/ctvault/internal/fsutil"
)

// File names in a batch directory.
const (
	EntriesFile = "entries.parquet"
	ChainsFile  = "chains.parquet"
)

// EntryRow is one entries.parquet row (amendment A1 §6). Zero-valued
// optional fields are written as NULL.
type EntryRow struct {
	Idx              uint64
	CTTimestamp      uint64 // ms since the epoch; 0 = unknown (NULL)
	EntryType        string // "x509", "precert" or "unknown"
	CertID           uint64 // 0 = no certificate (NULL)
	LeafHash         [32]byte
	IssuanceKey      [16]byte
	HasIssuanceKey   bool
	IssuerKeyHash    [32]byte
	HasIssuerKeyHash bool
	ChainID          [32]byte
	HasChainID       bool
	LeafError        string // "" = NULL
}

// ChainRow is one chains.parquet row: chains first seen in the batch.
type ChainRow struct {
	ChainID  [32]byte
	Position uint16
	CertID   uint64
}

// FileInfo describes a staged file for _COMMIT.json.
type FileInfo struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Rows   int    `json:"rows"`
}

// Options configure the embedded DuckDB session.
type Options struct {
	TempDir      string // <root>/tmp/duckdb-<pid> (spec §10.1)
	MaxTempBytes uint64 // max_temp_directory_size: headroom below the cap minus 1 GiB
	Threads      int    // 0 = 1: one thread makes staged files byte-identical for the same rows (spec §7.2)
}

// Stager owns one in-memory DuckDB session. Not safe for concurrent use.
type Stager struct {
	connector *duckdb.Connector
	db        *sql.DB
}

// NewStager opens an in-memory DuckDB session with spill confined to
// o.TempDir and capped at o.MaxTempBytes.
func NewStager(o Options) (*Stager, error) {
	if err := os.MkdirAll(o.TempDir, 0o755); err != nil {
		return nil, err
	}
	settings := []string{
		fmt.Sprintf("SET temp_directory = %s", quote(o.TempDir)),
		fmt.Sprintf("SET max_temp_directory_size = '%dB'", o.MaxTempBytes),
	}
	settings = append(settings, fmt.Sprintf("SET threads = %d", max(o.Threads, 1)),
		"SET preserve_insertion_order = true") // derived files keep the order rows were added in
	c, err := duckdb.NewConnector("", func(execer driver.ExecerContext) error {
		for _, q := range settings {
			if _, err := execer.ExecContext(context.Background(), q, nil); err != nil {
				return fmt.Errorf("duckdb %q: %w", q, err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &Stager{connector: c, db: sql.OpenDB(c)}, nil
}

// DB is the session's database, for the writer's post-commit audit, which
// reads through the query package (amendment A3 §6).
func (s *Stager) DB() *sql.DB { return s.db }

// Close closes the session.
func (s *Stager) Close() error {
	err := s.db.Close()
	if cerr := s.connector.Close(); err == nil {
		err = cerr
	}
	return err
}

// quote makes a SQL string literal.
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

const entriesDDL = `CREATE OR REPLACE TABLE entries_stage (
	idx UBIGINT, ct_ts TIMESTAMP_MS, entry_type VARCHAR, cert_id UBIGINT,
	leaf_hash BLOB, issuance_key BLOB, issuer_key_hash BLOB, chain_id BLOB, leaf_error VARCHAR)`

const chainsDDL = `CREATE OR REPLACE TABLE chains_stage (chain_id BLOB, position USMALLINT, cert_id UBIGINT)`

// copyOptions writes zstd Parquet with no bloom filter on any column:
// DuckDB 1.5.6 returns wrong answers for literal lookups on bloom-filtered
// BLOB columns (spec §3.6, amendment A1 §6).
const copyOptions = `(FORMAT parquet, COMPRESSION zstd, WRITE_BLOOM_FILTER false)`

func nullable(ok bool, v any) any {
	if !ok {
		return nil
	}
	return v
}

func entryValues(r EntryRow) []driver.Value {
	var ts, cert, lerr any
	if r.CTTimestamp != 0 {
		ts = time.UnixMilli(int64(r.CTTimestamp)).UTC()
	}
	if r.CertID != 0 {
		cert = r.CertID
	}
	if r.LeafError != "" {
		lerr = r.LeafError
	}
	return []driver.Value{r.Idx, ts, r.EntryType, cert, r.LeafHash[:],
		nullable(r.HasIssuanceKey, r.IssuanceKey[:]), nullable(r.HasIssuerKeyHash, r.IssuerKeyHash[:]),
		nullable(r.HasChainID, r.ChainID[:]), lerr}
}

// load appends rows into the temp tables of one connection.
func (s *Stager) load(ctx context.Context, conn *sql.Conn, entries []EntryRow, chains []ChainRow) error {
	for _, q := range []string{entriesDDL, chainsDDL} {
		if _, err := conn.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return conn.Raw(func(dc any) error {
		ea, err := duckdb.NewAppenderFromConn(dc.(driver.Conn), "", "entries_stage")
		if err != nil {
			return err
		}
		for _, r := range entries {
			if err := ea.AppendRow(entryValues(r)...); err != nil {
				ea.Close()
				return fmt.Errorf("staging entry %d: %w", r.Idx, err)
			}
		}
		if err := ea.Close(); err != nil {
			return err
		}
		ca, err := duckdb.NewAppenderFromConn(dc.(driver.Conn), "", "chains_stage")
		if err != nil {
			return err
		}
		for _, r := range chains {
			if err := ca.AppendRow(r.ChainID[:], r.Position, r.CertID); err != nil {
				ca.Close()
				return err
			}
		}
		return ca.Close()
	})
}

// Stage writes entries.parquet and chains.parquet into dir (tmp/stage/<batch>)
// and syncs them (spec §8.3 P5). Rows are written in index order, and chains
// by chain_id then position.
func (s *Stager) Stage(ctx context.Context, dir string, entries []EntryRow, chains []ChainRow) (map[string]FileInfo, error) {
	if err := fsutil.MkdirAllSync(dir, 0o755); err != nil {
		return nil, err
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := s.load(ctx, conn, entries, chains); err != nil {
		return nil, err
	}
	out := map[string]FileInfo{}
	for _, f := range []struct {
		name, query string
		rows        int
	}{
		{EntriesFile, `SELECT * FROM entries_stage ORDER BY idx`, len(entries)},
		{ChainsFile, `SELECT * FROM chains_stage ORDER BY chain_id, position`, len(chains)},
	} {
		p := filepath.Join(dir, f.name)
		if _, err := conn.ExecContext(ctx, fmt.Sprintf("COPY (%s) TO %s %s", f.query, quote(p), copyOptions)); err != nil {
			return nil, fmt.Errorf("writing %s: %w", f.name, err)
		}
		info, err := syncAndSum(p)
		if err != nil {
			return nil, err
		}
		info.Rows = f.rows
		out[f.name] = info
	}
	if _, err := conn.ExecContext(ctx, `DROP TABLE entries_stage; DROP TABLE chains_stage`); err != nil {
		return nil, err
	}
	return out, fsutil.SyncDir(dir)
}

// syncAndSum fsyncs a file and returns its size and SHA-256.
func syncAndSum(p string) (FileInfo, error) {
	f, err := os.Open(p)
	if err != nil {
		return FileInfo{}, err
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return FileInfo{}, err
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return FileInfo{}, err
	}
	return FileInfo{SHA256: hex.EncodeToString(h.Sum(nil)), Bytes: n}, nil
}

// Sum returns a committed file's size and SHA-256, for recovery and verify.
func Sum(p string) (FileInfo, error) { return syncAndSum(p) }

// EntryTypes reads, from a committed entries.parquet, the distinct entry
// types of the entries that reference each cert_id, sorted (a rebuild
// cross-checks certificate kinds with them, amendment A2 §5.2).
func (s *Stager) EntryTypes(path string) (map[uint64][]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT cert_id, entry_type FROM read_parquet(` + quote(path) + `) WHERE cert_id IS NOT NULL ORDER BY 1, 2`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uint64][]string{}
	for rows.Next() {
		var id uint64
		var typ string
		if err := rows.Scan(&id, &typ); err != nil {
			return nil, err
		}
		out[id] = append(out[id], typ)
	}
	return out, rows.Err()
}

// ChainCertIDs reads the distinct cert_id values of a committed
// chains.parquet.
func (s *Stager) ChainCertIDs(path string) (map[uint64]bool, error) {
	rows, err := s.db.Query(`SELECT DISTINCT cert_id FROM read_parquet(` + quote(path) + `)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uint64]bool{}
	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// ChainIDs reads the distinct chain_id values of a committed chains.parquet
// (recovery re-applies them to the index).
func (s *Stager) ChainIDs(path string) ([][32]byte, error) {
	rows, err := s.db.Query(`SELECT DISTINCT chain_id FROM read_parquet(` + quote(path) + `)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][32]byte
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		if len(b) != 32 {
			return nil, fmt.Errorf("%s: chain_id of %d bytes", path, len(b))
		}
		out = append(out, [32]byte(b))
	}
	return out, rows.Err()
}
