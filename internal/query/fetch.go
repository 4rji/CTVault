package query

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/vault"
)

// ErrNotFound means the certificate is not in the snapshot.
var ErrNotFound = errors.New("not in this vault's committed snapshot")

// Cert is a fetched certificate, verified against its SHA-256.
type Cert struct {
	CertID uint64
	SHA256 [32]byte
	DER    []byte
	Loc    vault.Loc
	Batch  string         // the batch that first vaulted it
	Row    map[string]any // its certs row
}

// Entry is one log entry that references a certificate.
type Entry struct {
	Log       string    `json:"log"`
	Idx       uint64    `json:"idx"`
	CTTime    time.Time `json:"ct_ts"`
	EntryType string    `json:"entry_type"`
}

// Fetcher reads certificates from a snapshot's vault (amendment A3 §4).
type Fetcher struct {
	s     *Snapshot
	sess  *Session
	codec *vault.Codec
	r     *vault.Reader
}

// NewFetcher needs the certs table readable; it loads the dictionaries
// read-only.
func NewFetcher(s *Snapshot, sess *Session, vaultDirs []string) (*Fetcher, error) {
	if _, err := s.Table("certs"); err != nil {
		return nil, err
	}
	codec, err := vault.NewCodec()
	if err != nil {
		return nil, err
	}
	ds, err := vault.ReadDicts(vaultDirs)
	if err != nil {
		codec.Close()
		return nil, err
	}
	for _, d := range ds {
		if err := codec.AddDict(d.Manifest.ID, d.Content); err != nil {
			codec.Close()
			return nil, err
		}
	}
	r, err := vault.OpenReader(vaultDirs, codec)
	if err != nil {
		codec.Close()
		return nil, err
	}
	return &Fetcher{s: s, sess: sess, codec: codec, r: r}, nil
}

// Close releases the vault reader.
func (f *Fetcher) Close() {
	f.r.Close()
	f.codec.Close()
}

// BySHA256 finds a certificate through the bloom filters on certs.sha256.
// The hex literal is inlined so DuckDB can prune with it.
func (f *Fetcher) BySHA256(ctx context.Context, sha [32]byte) (*Cert, error) {
	return f.lookup(ctx, f.s.TableFiles("certs"), "sha256 = "+quote(hex.EncodeToString(sha[:])))
}

// Locate finds a certificate's certs row by SHA-256 without reading the
// vault: the part of fetch whose cost grows with the dataset (amendment A3
// §7.1 measures it).
func (f *Fetcher) Locate(ctx context.Context, sha [32]byte) (map[string]any, error) {
	return locate(ctx, f.s, f.sess, sha)
}

func locate(ctx context.Context, s *Snapshot, sess *Session, sha [32]byte) (map[string]any, error) {
	files := s.TableFiles("certs")
	if len(files) == 0 {
		return nil, ErrNotFound
	}
	rows, err := scanMaps(ctx, sess.db, `SELECT * FROM read_parquet(`+fileList(files)+s.unionOpt("certs")+`, hive_partitioning = true) WHERE sha256 = `+
		quote(hex.EncodeToString(sha[:])))
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	return rows[0], nil
}

// Locate is Fetcher.Locate without a vault: for benchmarks over certs files
// whose records are not in any vault.
func Locate(ctx context.Context, s *Snapshot, sess *Session, sha [32]byte) (map[string]any, error) {
	return locate(ctx, s, sess, sha)
}

// ByCertID reads only the batch whose cert_id_range holds id.
func (f *Fetcher) ByCertID(ctx context.Context, id uint64) (*Cert, error) {
	p := commit.Paths{Root: f.s.Root}
	for _, m := range f.s.Batches {
		if m.CertIDRange == nil || id < m.CertIDRange[0] || id > m.CertIDRange[1] {
			continue
		}
		file, ok := f.s.batchFile(m, "certs")
		if !ok {
			return nil, fmt.Errorf("certs of batch %s: %w", m.BatchID, ErrBuilding)
		}
		return f.lookup(ctx, []string{filepath.Join(p.BatchDir(m.ID()), file)}, "cert_id = "+strconv.FormatUint(id, 10))
	}
	return nil, fmt.Errorf("cert_id %d is %w", id, ErrNotFound)
}

func (f *Fetcher) lookup(ctx context.Context, files []string, where string) (*Cert, error) {
	if len(files) == 0 {
		return nil, ErrNotFound
	}
	rows, err := scanMaps(ctx, f.sess.db, `SELECT * FROM read_parquet(`+fileList(files)+f.s.unionOpt("certs")+`, hive_partitioning = true) WHERE `+where)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	row := rows[0]
	c := &Cert{Row: row, CertID: row["cert_id"].(uint64), Batch: fmt.Sprint(row["log"]) + "/" + fmt.Sprint(row["batch"]),
		Loc: vault.Loc{Segment: uint64(row["vault_seg"].(uint32)), Offset: row["vault_off"].(uint64), Len: row["vault_len"].(uint32)}}
	want, err := hex.DecodeString(row["sha256"].(string))
	if err != nil || len(want) != 32 {
		return nil, fmt.Errorf("%w: certs row of cert_id %d has a malformed sha256", vault.ErrCorrupt, c.CertID)
	}
	copy(c.SHA256[:], want)
	der, _, err := f.r.Read(c.Loc)
	if err != nil {
		return nil, err
	}
	if sha256.Sum256(der) != c.SHA256 {
		return nil, fmt.Errorf("%w: the record of cert_id %d at %d:%d does not match its SHA-256", vault.ErrCorrupt, c.CertID, c.Loc.Segment, c.Loc.Offset)
	}
	c.DER = der
	return c, nil
}

// Names returns the certificate's names rows, in the order ingest wrote
// them.
func (f *Fetcher) Names(ctx context.Context, c *Cert) ([]map[string]any, error) {
	if _, err := f.s.Table("names"); err != nil {
		return nil, err
	}
	files := f.s.TableFiles("names")
	if len(files) == 0 {
		return nil, nil
	}
	return scanMaps(ctx, f.sess.db, `SELECT source, name, dns_valid, is_wildcard, tld, etld1 FROM read_parquet(`+fileList(files)+f.s.unionOpt("names")+
		`, file_row_number = true) WHERE cert_id = `+strconv.FormatUint(c.CertID, 10)+` ORDER BY file_row_number`)
}

// Chains returns every distinct chain the log served with the certificate,
// as cert_ids from position 0, in order of first appearance (amendment A3
// §4.3). It scans the entries files' cert_id column.
func (f *Fetcher) Chains(ctx context.Context, certID uint64) ([][]uint64, error) {
	entries := f.s.Files(dataset.EntriesFile)
	if len(entries) == 0 {
		return nil, nil
	}
	q := `SELECT chain_id FROM read_parquet(` + fileList(entries) + `, filename = true)
		WHERE cert_id = ` + strconv.FormatUint(certID, 10) + ` AND chain_id IS NOT NULL
		GROUP BY chain_id ORDER BY min(list_position(` + fileList(entries) + `, filename) * 1000000000000 + idx)`
	rows, err := f.sess.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	var ids [][]byte
	for rows.Next() {
		var id []byte
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out [][]uint64
	files := f.s.Files(dataset.ChainsFile)
	for _, id := range ids {
		crs, err := f.sess.db.QueryContext(ctx, `SELECT cert_id FROM read_parquet(`+fileList(files)+`) WHERE chain_id = from_hex(`+
			quote(hex.EncodeToString(id))+`) ORDER BY position`)
		if err != nil {
			return nil, err
		}
		var chain []uint64
		for crs.Next() {
			var c uint64
			if err := crs.Scan(&c); err != nil {
				crs.Close()
				return nil, err
			}
			chain = append(chain, c)
		}
		crs.Close()
		out = append(out, chain)
	}
	return out, nil
}

// Entries lists the log entries that reference the certificate, by log and
// index. It scans the entries files' cert_id column (amendment A3 §4.3).
func (f *Fetcher) Entries(ctx context.Context, certID uint64) ([]Entry, error) {
	files := f.s.Files(dataset.EntriesFile)
	if len(files) == 0 {
		return nil, nil
	}
	rows, err := f.sess.db.QueryContext(ctx, `SELECT log, idx, ct_ts, entry_type FROM read_parquet(`+fileList(files)+
		`, hive_partitioning = true) WHERE cert_id = `+strconv.FormatUint(certID, 10)+` ORDER BY log, idx`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		var ts sql.NullTime
		if err := rows.Scan(&e.Log, &e.Idx, &ts, &e.EntryType); err != nil {
			return nil, err
		}
		e.CTTime = ts.Time.UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

// scanMaps runs q and returns each row as column → value.
func scanMaps(ctx context.Context, db *sql.DB, q string) ([]map[string]any, error) {
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		m := map[string]any{}
		for i, c := range cols {
			m[c] = vals[i]
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// CountNames counts the names rows whose column (name or etld1) equals
// value, through the bloom-filtered path search uses.
func CountNames(ctx context.Context, s *Snapshot, sess *Session, column, value string) (int64, error) {
	if column != "name" && column != "etld1" {
		return 0, fmt.Errorf("query: CountNames on %q", column)
	}
	files := s.TableFiles("names")
	if len(files) == 0 {
		return 0, nil
	}
	var n int64
	err := sess.db.QueryRowContext(ctx, `SELECT count(*) FROM read_parquet(`+fileList(files)+s.unionOpt("names")+`) WHERE `+column+` = `+quote(value)).Scan(&n)
	return n, err
}

// linkWindow bounds the issuance-key search for a precert↔final link
// (spec §11.4).
const linkWindow = 7 * 24 * time.Hour

// Linked returns the other half of a certificate's issuance: a final's
// precert or a precert's final; nil when there is none or the certificate
// is a chain certificate (amendment A4 §3). It uses delta_base_cert_id
// first, then the issuance key within 7 days: before a final, after a
// precert. The entries reads are pruned by their ct_ts statistics.
func (f *Fetcher) Linked(ctx context.Context, c *Cert) (*Cert, error) {
	id := strconv.FormatUint(c.CertID, 10)
	switch c.Row["kind"] {
	case derive.KindFinal:
		if base, ok := c.Row["delta_base_cert_id"].(uint64); ok {
			return f.ByCertID(ctx, base)
		}
	case derive.KindPrecert:
		var final uint64
		err := f.sess.db.QueryRowContext(ctx, `SELECT cert_id FROM read_parquet(`+fileList(f.s.TableFiles("certs"))+f.s.unionOpt("certs")+
			`) WHERE delta_base_cert_id = `+id+` ORDER BY cert_id LIMIT 1`).Scan(&final)
		if err == nil {
			return f.ByCertID(ctx, final)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	default:
		return nil, nil
	}
	own := f.batchFile(c, dataset.EntriesFile)
	if own == "" {
		return nil, nil
	}
	var key []byte
	var at time.Time
	var typ string
	err := f.sess.db.QueryRowContext(ctx, `SELECT issuance_key, ct_ts, entry_type FROM read_parquet(`+quote(own)+`) WHERE cert_id = `+id+
		` AND issuance_key IS NOT NULL ORDER BY idx LIMIT 1`).Scan(&key, &at, &typ)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	from, to, want := at.Add(-linkWindow), at, "precert"
	if typ == "precert" {
		from, to, want = at, at.Add(linkWindow), "x509"
	}
	var other uint64
	err = f.sess.db.QueryRowContext(ctx, `SELECT cert_id FROM read_parquet(`+fileList(f.s.Files(dataset.EntriesFile))+`)
		WHERE issuance_key = from_hex(`+quote(hex.EncodeToString(key))+`) AND entry_type = `+quote(want)+` AND cert_id <> `+id+`
		AND ct_ts BETWEEN `+ts(from)+` AND `+ts(to)+` ORDER BY ct_ts, cert_id LIMIT 1`).Scan(&other)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return f.ByCertID(ctx, other)
}

// batchFile is the path of a listed file of the batch that first vaulted c.
func (f *Fetcher) batchFile(c *Cert, name string) string {
	p := commit.Paths{Root: f.s.Root}
	for _, m := range f.s.Batches {
		if fmt.Sprint(c.Row["log"]) == m.Log && fmt.Sprint(c.Row["batch"]) == fmt.Sprintf("%012d-%012d", m.First, m.Last) {
			if _, ok := m.Listed(name); ok {
				return filepath.Join(p.BatchDir(m.ID()), name)
			}
		}
	}
	return ""
}
