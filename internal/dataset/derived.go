package dataset

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"strings"

	duckdb "github.com/duckdb/duckdb-go/v2"

	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/fsutil"
)

// DerivedStage stages one batch's derived tables (amendment A2 §4.3-4.5).
// The batch adds each new certificate's rows as it vaults it (P2), and they
// go straight into DuckDB: collecting them in Go first measured about 4 KB
// of heap per certificate (400 MiB for a batch of 100,000 real entries).
// Each table keeps a uniform sample of its rows (reservoir sampling) for
// the canary. Write stages the files (P5) and Canary checks them (P6). Not
// safe for concurrent use.
type DerivedStage struct {
	s      *Stager
	conn   driver.Conn
	rnd    *rand.Rand
	keep   int
	tables []*stagedTable
}

type stagedTable struct {
	table   derive.Table
	stage   string
	app     *duckdb.Appender
	vals    []driver.Value
	rows    int
	sample  []derive.Row
	dropped bool
}

// derivedOptions are the derived files' writer settings (amendment A2
// §4.4): dictionary encoding up to the row group size, so DuckDB writes a
// bloom filter on every column (D19: these files hold no BLOB column).
const derivedOptions = `FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 122880, DICTIONARY_SIZE_LIMIT 122880`

// bloomColumns are the columns readers look up by literal value; the canary
// requires their bloom filters (amendment A2 §4.5).
var bloomColumns = map[string][]string{"certs": {"sha256"}, "names": {"name", "etld1"}}

func kvLiteral(t derive.Table) string {
	var parts []string
	for _, p := range t.KV() {
		parts = append(parts, quote(p[0])+": "+quote(p[1]))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// BeginDerived creates an empty staging table for each table, on a
// connection of its own. Each table samples keep of its rows for the
// canary, chosen with rnd.
func (s *Stager) BeginDerived(ctx context.Context, tables []derive.Table, keep int, rnd *rand.Rand) (*DerivedStage, error) {
	conn, err := s.connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	d := &DerivedStage{s: s, conn: conn, rnd: rnd, keep: keep}
	for _, t := range tables {
		st := &stagedTable{table: t, stage: t.Name + "_stage"}
		d.tables = append(d.tables, st)
		var cols []string
		for _, c := range t.Columns {
			cols = append(cols, c.Name+" "+c.Type)
		}
		if err := d.exec(ctx, fmt.Sprintf("CREATE OR REPLACE TABLE %s (%s)", st.stage, strings.Join(cols, ", "))); err != nil {
			d.Close()
			return nil, err
		}
		if st.app, err = duckdb.NewAppenderFromConn(conn, "", st.stage); err != nil {
			d.Close()
			return nil, err
		}
	}
	return d, nil
}

func (d *DerivedStage) exec(ctx context.Context, q string) error {
	_, err := d.conn.(driver.ExecerContext).ExecContext(ctx, q, nil)
	return err
}

// Add appends rows to table i, after the rows already added.
func (d *DerivedStage) Add(i int, rows []derive.Row) error {
	st := d.tables[i]
	for _, r := range rows {
		st.vals = st.vals[:0]
		for _, v := range r {
			st.vals = append(st.vals, v)
		}
		if err := st.app.AppendRow(st.vals...); err != nil {
			return fmt.Errorf("staging %s row %d: %w", st.table.Name, st.rows, err)
		}
		// Algorithm R: the k-th row (from 0) replaces a sampled row with
		// probability keep/(k+1), so every row is kept with equal chance.
		if len(st.sample) < d.keep {
			st.sample = append(st.sample, r)
		} else if j := d.rnd.IntN(st.rows + 1); j < d.keep {
			st.sample[j] = r
		}
		st.rows++
	}
	return nil
}

// Write flushes each table, writes its file into dir (P5) and syncs it, then
// drops the staging table to free its memory. The file keeps the order the
// rows were added in: the session preserves insertion order, so no sort
// (which would copy the whole table) is needed, and its single thread makes
// the files byte-identical for the same rows (spec §7.2).
func (d *DerivedStage) Write(ctx context.Context, dir string) (map[string]FileInfo, error) {
	if err := fsutil.MkdirAllSync(dir, 0o755); err != nil {
		return nil, err
	}
	out := map[string]FileInfo{}
	for _, st := range d.tables {
		err := st.app.Close() // flushes the appended rows
		st.app = nil
		if err != nil {
			return nil, fmt.Errorf("staging %s: %w", st.table.Name, err)
		}
		var names []string
		for _, c := range st.table.Columns {
			names = append(names, c.Name)
		}
		p := filepath.Join(dir, st.table.File())
		q := fmt.Sprintf("COPY (SELECT %s FROM %s) TO %s (%s, KV_METADATA %s)",
			strings.Join(names, ", "), st.stage, quote(p), derivedOptions, kvLiteral(st.table))
		if err := d.exec(ctx, q); err != nil {
			return nil, fmt.Errorf("writing %s: %w", st.table.File(), err)
		}
		if err := d.exec(ctx, "DROP TABLE "+st.stage); err != nil {
			return nil, err
		}
		st.dropped = true
		info, err := syncAndSum(p)
		if err != nil {
			return nil, err
		}
		info.Rows = st.rows
		out[st.table.File()] = info
	}
	return out, fsutil.SyncDir(dir)
}

// Canary checks the written files against what was added (amendment A2
// §4.5): exact columns and types, the KV metadata, bloom filters on the
// lookup columns wherever they hold a value, the row count, and every
// sampled row read back through literal lookups.
func (d *DerivedStage) Canary(ctx context.Context, dir string) error {
	for _, st := range d.tables {
		p := filepath.Join(dir, st.table.File())
		if err := d.s.checkSchema(ctx, p, typed(st.table)); err != nil {
			return err
		}
		if err := d.s.checkKV(ctx, p, st.table); err != nil {
			return err
		}
		if err := d.s.checkBloom(ctx, p, bloomColumns[st.table.Name]); err != nil {
			return err
		}
		var rows int
		if err := d.s.db.QueryRowContext(ctx, `SELECT count(*) FROM read_parquet(`+quote(p)+`)`).Scan(&rows); err != nil {
			return err
		}
		if rows != st.rows {
			return canaryErr("%s has %d rows, staged %d", st.table.File(), rows, st.rows)
		}
		for _, r := range st.sample {
			if err := d.s.checkDerivedRow(ctx, p, st.table, r); err != nil {
				return err
			}
		}
	}
	return nil
}

// Close drops the staging tables Write did not and releases the
// connection. A batch attempt that fails before Write ends here.
func (d *DerivedStage) Close() error {
	var errs []error
	for _, st := range d.tables {
		if st.app != nil {
			errs = append(errs, st.app.Close())
			st.app = nil
		}
		if !st.dropped {
			errs = append(errs, d.exec(context.Background(), "DROP TABLE IF EXISTS "+st.stage))
			st.dropped = true
		}
	}
	return errors.Join(append(errs, d.conn.Close())...)
}

// typed lists "name type" per column, as checkSchema compares them.
func typed(t derive.Table) []string {
	out := make([]string, len(t.Columns))
	for i, c := range t.Columns {
		out[i] = c.Name + " " + c.Type
	}
	return out
}

func (s *Stager) checkKV(ctx context.Context, path string, t derive.Table) error {
	got := map[string]string{}
	rows, err := s.db.QueryContext(ctx, `SELECT decode(key), decode(value) FROM parquet_kv_metadata(`+quote(path)+`)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return err
		}
		got[k] = v
	}
	for _, p := range t.KV() {
		if got[p[0]] != p[1] {
			return canaryErr("%s: metadata %s is %q, want %q", filepath.Base(path), p[0], got[p[0]], p[1])
		}
	}
	return rows.Err()
}

// checkBloom requires a bloom filter in every row group where a lookup
// column holds at least one value.
func (s *Stager) checkBloom(ctx context.Context, path string, cols []string) error {
	for _, c := range cols {
		var missing int
		err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM parquet_metadata(`+quote(path)+`)
			WHERE path_in_schema = ? AND coalesce(stats_null_count, 0) < num_values AND coalesce(bloom_filter_length, 0) = 0`, c).Scan(&missing)
		if err != nil {
			return err
		}
		if missing > 0 {
			return canaryErr("%s: column %s lacks its bloom filter in %d row groups", filepath.Base(path), c, missing)
		}
	}
	return nil
}

// checkDerivedRow reads one row back by literal values: a certs row by its
// sha256 (the reader's lookup), a names row by cert_id and name.
func (s *Stager) checkDerivedRow(ctx context.Context, path string, t derive.Table, r derive.Row) error {
	switch t.Name {
	case "certs":
		var id uint64
		var seg, length uint32
		var off uint64
		err := s.db.QueryRowContext(ctx, `SELECT cert_id, vault_seg, vault_off, vault_len FROM read_parquet(`+quote(path)+`) WHERE sha256 = '`+r[1].(string)+`'`).
			Scan(&id, &seg, &off, &length)
		if err == sql.ErrNoRows || err == nil && (id != r[0].(uint64) || seg != r[4].(uint32) || off != r[5].(uint64) || length != r[6].(uint32)) {
			return canaryErr("%s: sha256 %s reads back as cert_id %d at %d:%d+%d, staged %v", filepath.Base(path), r[1], id, seg, off, length, r[:7])
		}
		return err
	case "names":
		var k int
		err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM read_parquet(`+quote(path)+`) WHERE cert_id = ? AND name = ?`, r[0], r[2]).Scan(&k)
		if err == nil && k == 0 {
			return canaryErr("%s: name %q of cert_id %d does not read back", filepath.Base(path), r[2], r[0])
		}
		return err
	}
	return nil
}
