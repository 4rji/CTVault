package query

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// Results are a search's rows, computed once and held in the reader
// session's database, so that explore's pages, sorts and / filter read the
// held rows instead of the vault (amendment A4 §2.2, as revised in Plan 5's
// summary). Held rows that outgrow memory spill to the session's
// tmp/duckdb-<pid>/ like any other DuckDB data; Close drops them, and so
// does the session's end.
//
// The held rows never change, so a page is a range of their row numbers:
// pages never repeat or skip a row, as keyset pages do not.
type Results struct {
	s     *Snapshot
	q     Query // normalized; Sort and Filter are this order's
	base  *held // every row in the first sort, unfiltered; nil when none
	table string
	n     int

	mu      sync.Mutex
	closed  bool
	reading int // reads that run; the last one drops a closed result's table
}

// held is a table of a search's rows. The Results reordered from it share
// it; the last one's Close drops it.
type held struct {
	sess *Session
	name string
	sort string // the order its __ctv_row follows
	n    int

	mu   sync.Mutex
	refs int
}

// heldPrefix names held tables, which no one else creates in a reader
// session.
const heldPrefix = "__ctv_held_"

var errClosed = errors.New("the query's results are closed")

// Hold runs q once and holds its rows. q.Limit is ignored, as in
// SearchPage.
func Hold(ctx context.Context, s *Snapshot, sess *Session, vaultDirs []string, q Query) (*Results, error) {
	filter := q.Filter
	q.Filter, q.Limit = "", 0
	c, err := compile(ctx, s, sess, vaultDirs, &q)
	if err != nil {
		return nil, err
	}
	r := &Results{s: s, q: q}
	if c.body != "" {
		sort, desc := sortOf(&q)
		h, err := sess.hold(ctx, c.with+"\nSELECT *, row_number() OVER (ORDER BY "+orderBy(sort, desc, c.g.tiebreak)+") AS __ctv_row FROM ("+c.body+") AS g", q.Sort)
		if err != nil {
			return nil, err
		}
		r.base, r.table, r.n = h, h.name, h.n
	}
	if filter == "" {
		return r, nil
	}
	defer r.Close()
	return r.Reorder(ctx, q.Sort, filter)
}

// hold creates a table of the rows sql selects, in __ctv_row's order, so
// that a range of row numbers reads only the row groups that hold it.
func (s *Session) hold(ctx context.Context, sql, sort string) (*held, error) {
	name := fmt.Sprintf("%s%d", heldPrefix, s.held.Add(1))
	if _, err := s.db.ExecContext(ctx, "CREATE TABLE "+name+" AS "+sql+" ORDER BY __ctv_row"); err != nil {
		return nil, err
	}
	h := &held{sess: s, name: name, sort: sort, refs: 1}
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM "+name).Scan(&h.n); err != nil {
		h.release()
		return nil, err
	}
	return h, nil
}

// Held counts the session's held tables.
func (s *Session) Held(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM duckdb_tables() WHERE starts_with(table_name, "+quote(heldPrefix)+")").Scan(&n)
	return n, err
}

func (h *held) acquire() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.refs == 0 {
		return false
	}
	h.refs++
	return true
}

func (h *held) release() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.refs--; h.refs > 0 {
		return nil
	}
	return h.sess.drop(h.name)
}

// drop removes a held table, even when the operation that used it was
// cancelled.
func (s *Session) drop(name string) error {
	_, err := s.db.ExecContext(context.Background(), "DROP TABLE IF EXISTS "+name)
	return err
}

// Query is the results' query, with defaults filled in.
func (r *Results) Query() Query { return r.q }

// AsOf is the commit the rows come from.
func (r *Results) AsOf() uint64 { return r.s.AsOf }

// Len is how many rows there are.
func (r *Results) Len() int { return r.n }

// Reorder returns the same rows in another sort and with another / filter
// (both as Query's Sort and Filter), from the held rows: the vault is not
// read again. r stays open; the caller closes both.
func (r *Results) Reorder(ctx context.Context, sort, filter string) (*Results, error) {
	q := r.q
	q.Sort, q.Filter = sort, filter
	g, err := q.normalize()
	if err != nil {
		return nil, err
	}
	// Hold a reference to the rows: r may close while the new order is
	// built.
	r.mu.Lock()
	ok := !r.closed && (r.base == nil || r.base.acquire())
	r.mu.Unlock()
	if !ok {
		return nil, errClosed
	}
	nr := &Results{s: r.s, q: q}
	if r.base == nil {
		return nr, nil
	}
	nr.base, nr.table, nr.n = r.base, r.base.name, r.base.n
	if q.Filter == "" && q.Sort == r.base.sort {
		return nr, nil
	}
	col, desc := sortOf(&q)
	sql := "SELECT * EXCLUDE (__ctv_row), row_number() OVER (ORDER BY " + orderBy(col, desc, g.tiebreak) + ") AS __ctv_row FROM " + r.base.name
	if q.Filter != "" {
		sql += " WHERE " + filterPredicate(q.Columns(), q.Filter)
	}
	h, err := r.base.sess.hold(ctx, sql, q.Sort)
	if err != nil {
		r.base.release()
		return nil, err
	}
	nr.table, nr.n = h.name, h.n
	return nr, nil
}

// Page returns up to n rows from position from (0: the first). Next is the
// last row's cursor while rows remain.
func (r *Results) Page(ctx context.Context, from, n int) (*Page, error) {
	p := &Page{Columns: r.q.Columns(), Query: r.q}
	var last Cursor
	err := r.scan(ctx, fmt.Sprintf("__ctv_row > %d AND __ctv_row <= %d", from, from+n), func(_ []string, row []any, c Cursor) error {
		p.Rows = append(p.Rows, row)
		last = c
		return nil
	})
	if err != nil {
		return nil, err
	}
	if from+len(p.Rows) < r.n && len(p.Rows) > 0 {
		p.Next = &last
	}
	return p, nil
}

// scan reads the held rows that where selects ("": all), in order.
func (r *Results) scan(ctx context.Context, where string, fn rowFunc) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return errClosed
	}
	r.reading++
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.reading--; r.reading == 0 && r.closed {
			r.release()
		}
	}()
	if r.base == nil {
		return nil
	}
	col, _ := sortOf(&r.q)
	cols := r.q.Columns()
	sql := "SELECT " + strings.Join(cols, ", ") + ", " + col + " AS __ctv_sort, " + groups[r.q.Group].tiebreak + " AS __ctv_tie FROM " + r.table
	if where != "" {
		sql += " WHERE " + where
	}
	return scanRows(ctx, r.base.sess, sql+" ORDER BY __ctv_row", len(cols), cols, fn)
}

// Export writes the held rows as Export writes a search's: the same bytes
// for the same query and snapshot.
func (r *Results) Export(ctx context.Context, o ExportOptions) error {
	q := r.q
	return export(r.s, &q, o, func(fn rowFunc) error { return r.scan(ctx, "", fn) })
}

// Close drops the rows when no other Results share them. It never waits:
// a read that runs keeps the rows until it ends. Closing twice is
// harmless; a closed Results gives no pages.
func (r *Results) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	if r.reading > 0 {
		return nil // the last read releases them
	}
	return r.release()
}

// release drops this order's table and r's reference to the rows.
func (r *Results) release() error {
	if r.base == nil {
		return nil
	}
	var err error
	if r.table != r.base.name {
		err = r.base.sess.drop(r.table)
	}
	if rerr := r.base.release(); err == nil {
		err = rerr
	}
	return err
}
