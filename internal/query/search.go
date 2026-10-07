package query

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/derive"
)

// ErrUsage marks a query the user must correct (exit 2).
var ErrUsage = errors.New("invalid query")

func usage(format string, args ...any) error {
	return fmt.Errorf("%s: %w", fmt.Sprintf(format, args...), ErrUsage)
}

// Mode is how a search matches names (amendment A3 §3.1).
type Mode string

// The search modes.
const (
	ModeDomain   Mode = "etld1"
	ModeSuffix   Mode = "suffix"
	ModeExact    Mode = "exact"
	ModeIP       Mode = "ip"
	ModeContains Mode = "contains"
	ModeRegex    Mode = "regex"
)

// Query is a search. Exports record it whole, so it is reproducible.
type Query struct {
	Mode        Mode       `json:"mode"`
	Text        string     `json:"text"`
	Issuer      string     `json:"issuer,omitempty"`
	IssuerOrg   string     `json:"issuer_org,omitempty"`
	IssuedBy    string     `json:"issued_by,omitempty"`
	KeyAlg      string     `json:"key_alg,omitempty"`
	Kinds       []string   `json:"kinds,omitempty"`
	ParseStatus string     `json:"parse_status,omitempty"`
	ValidAt     *time.Time `json:"valid_at,omitempty"`
	Wildcard    bool       `json:"wildcard,omitempty"`
	Log         string     `json:"log,omitempty"`
	Since       *time.Time `json:"since,omitempty"`
	Until       *time.Time `json:"until,omitempty"`
	ByNotBefore bool       `json:"by_not_before,omitempty"`
	Group       string     `json:"group"`
	Sort        string     `json:"sort"`
	Fields      []string   `json:"fields,omitempty"`
	Limit       int        `json:"limit,omitempty"`
	Filter      string     `json:"filter,omitempty"` // explore's /: a text match over the displayed columns (amendment A4 §3)
	AsOf        uint64     `json:"-"`                // the snapshot's, recorded separately
}

// Result is a search's rows, in order.
type Result struct {
	Columns []string
	Rows    [][]any
	AsOf    uint64
	Query   Query // with defaults filled in
}

// Index returns a column's position, -1 if absent.
func (r *Result) Index(name string) int { return slices.Index(r.Columns, name) }

type group struct {
	columns  []string
	sort     string // the default sort
	tiebreak string // a unique key that ends every sort
}

var groups = map[string]group{
	"names":     {[]string{"name", "first_seen", "last_seen", "certs", "issuers"}, "last_seen desc", "name"},
	"certs":     {[]string{"sha256", "cert_id", "kind", "issuer_cn", "not_before", "not_after", "names", "first_seen", "last_seen", "logs"}, "first_seen desc", "cert_id"},
	"issuances": {[]string{"issuance_key", "first_seen", "last_seen", "certs", "precert", "final", "issuers"}, "first_seen desc", "issuance_key"},
}

// DefaultSort is a group's sort when the query names none. "" for an
// unknown group.
func DefaultSort(group string) string { return groups[group].sort }

// KeyColumn is the column that identifies a group's rows: its sort's
// tie-breaker. "" for an unknown group.
func KeyColumn(group string) string { return groups[group].tiebreak }

var kinds = map[string]bool{derive.KindPrecert: true, derive.KindFinal: true, derive.KindChain: true}

var statuses = map[string]bool{"ok": true, "partial": true, "failed": true}

// namePredicate compiles the mode into a predicate on names. Values the
// bloom filters prune with are inlined as literals.
func (q *Query) namePredicate() (string, error) {
	switch q.Mode {
	case ModeDomain:
		_, valid, wild, base := derive.NormalizeName(q.Text)
		if e, ok := derive.ETLD1(base); !valid || wild || !ok || e != base {
			return "", usage("%q is not a registrable domain; search names under it with --suffix %s, or one name with --exact %s", q.Text, q.Text, q.Text)
		}
		return "etld1 = " + quote(base), nil
	case ModeSuffix:
		name, valid, wild, base := derive.NormalizeName(q.Text)
		e, ok := derive.ETLD1(base)
		if !valid || wild || !ok {
			return "", usage("--suffix needs a DNS name under a registrable domain, not %q", q.Text)
		}
		return fmt.Sprintf("etld1 = %s AND (name = %s OR ends_with(name, %s))", quote(e), quote(name), quote("."+name)), nil
	case ModeExact:
		name, valid, _, _ := derive.NormalizeName(q.Text)
		if !valid {
			name = q.Text // a CN that is not a DNS name is stored exactly as decoded
		}
		return "name = " + quote(name), nil
	case ModeIP:
		a, err := netip.ParseAddr(q.Text)
		if err != nil {
			return "", usage("--ip: %v", err)
		}
		return "name = " + quote(a.String()) + " AND source IN ('san_ip', 'cn')", nil
	case ModeContains:
		if q.Text == "" {
			return "", usage("--contains needs a non-empty string")
		}
		return "strpos(lower(name), " + quote(strings.ToLower(q.Text)) + ") > 0", nil
	case ModeRegex:
		if _, err := regexp.Compile(q.Text); err != nil {
			return "", usage("--regex: %v", err)
		}
		return "regexp_matches(name, " + quote(q.Text) + ")", nil
	}
	return "", usage("unknown search mode %q", q.Mode)
}

func ts(t time.Time) string { return "TIMESTAMP " + quote(t.UTC().Format("2006-01-02 15:04:05.000")) }

// FullScan reports whether the mode reads every names row (no pruning).
func (q *Query) FullScan() bool { return q.Mode == ModeContains || q.Mode == ModeRegex }

// normalize fills defaults and validates everything but the mode.
func (q *Query) normalize() (group, error) {
	if q.Group == "" {
		q.Group = "names"
	}
	g, ok := groups[q.Group]
	if !ok {
		return g, usage("unknown group %q (names, certs or issuances)", q.Group)
	}
	if len(q.Kinds) == 0 {
		q.Kinds = []string{derive.KindPrecert, derive.KindFinal}
	}
	for _, k := range q.Kinds {
		if !kinds[k] {
			return g, usage("unknown kind %q (precert, final or chain)", k)
		}
	}
	if q.ParseStatus != "" && !statuses[q.ParseStatus] {
		return g, usage("unknown parse status %q (ok, partial or failed)", q.ParseStatus)
	}
	if q.Sort == "" {
		q.Sort = g.sort
	}
	f := strings.Fields(q.Sort)
	if len(f) == 0 || len(f) > 2 || !slices.Contains(g.columns, f[0]) || (len(f) == 2 && f[1] != "asc" && f[1] != "desc") {
		return g, usage("--sort %q: a column of the %s group (%s), then asc or desc", q.Sort, q.Group, strings.Join(g.columns, ", "))
	}
	for _, c := range q.Fields {
		if !slices.Contains(g.columns, c) {
			return g, usage("--fields: %q is not a column of the %s group (%s)", c, q.Group, strings.Join(g.columns, ", "))
		}
	}
	if q.Limit < 0 {
		return g, usage("--limit must not be negative")
	}
	return g, nil
}

// Search runs q over the snapshot (amendment A3 §3).
func Search(ctx context.Context, s *Snapshot, sess *Session, vaultDirs []string, q Query) (*Result, error) {
	r := &Result{AsOf: s.AsOf}
	err := SearchEach(ctx, s, sess, vaultDirs, &q, func(cols []string, row []any) error {
		r.Columns = cols
		r.Rows = append(r.Rows, row)
		return nil
	})
	if r.Columns == nil {
		r.Columns = q.Columns()
	}
	r.Query = q
	return r, err
}

// Columns are the result's columns: --fields, or the group's.
func (q *Query) Columns() []string {
	if len(q.Fields) > 0 {
		return q.Fields
	}
	return groups[q.Group].columns
}

// SearchEach runs q and calls fn for every row in order, without holding
// the result in memory. q gains its defaults.
func SearchEach(ctx context.Context, s *Snapshot, sess *Session, vaultDirs []string, q *Query, fn func(cols []string, row []any) error) error {
	return run(ctx, s, sess, vaultDirs, q, nil, q.Limit, func(cols []string, row []any, _ Cursor) error { return fn(cols, row) })
}

// Cursor is where a page ends: the last row's sort key and tie-breaker.
type Cursor struct {
	Sort, Tie any
}

// Page is one page of a search's rows. Next is nil after the last page.
type Page struct {
	Columns []string
	Rows    [][]any
	Next    *Cursor
	Query   Query // with defaults filled in
}

// SearchPage returns up to n rows after the cursor (nil: from the start),
// by keyset: pages never repeat or skip a row (amendment A4 §2.2). q.Limit
// is ignored.
func SearchPage(ctx context.Context, s *Snapshot, sess *Session, vaultDirs []string, q Query, after *Cursor, n int) (*Page, error) {
	p := &Page{}
	var curs []Cursor
	err := run(ctx, s, sess, vaultDirs, &q, after, n+1, func(cols []string, row []any, c Cursor) error {
		p.Columns = cols
		p.Rows = append(p.Rows, row)
		curs = append(curs, c)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if p.Columns == nil {
		p.Columns = q.Columns()
	}
	if len(p.Rows) > n {
		p.Rows = p.Rows[:n]
		p.Next = &curs[n-1]
	}
	p.Query = q
	return p, nil
}

// rowFunc receives a search's rows in order, with each row's cursor.
type rowFunc func(cols []string, row []any, c Cursor) error

// compiled is a search as SQL: a WITH clause and the group's rows, one
// column per group column. body is "" when no row can match.
type compiled struct {
	g          group
	with, body string
}

// compile normalizes q and builds its SQL. It reads the names files to
// find the matched cert_ids it prunes with (amendment A3 §7.1).
func compile(ctx context.Context, s *Snapshot, sess *Session, vaultDirs []string, q *Query) (compiled, error) {
	g, err := q.normalize()
	if err != nil {
		return compiled{}, err
	}
	pred, err := q.namePredicate()
	if err != nil {
		return compiled{}, err
	}
	for _, t := range []string{"certs", "names"} {
		if _, err := s.Table(t); err != nil {
			return compiled{}, err
		}
	}
	none := compiled{g: g}
	names, certs := s.TableFiles("names"), s.TableFiles("certs")
	entries, chains := s.Files(dataset.EntriesFile), s.Files(dataset.ChainsFile)
	if len(names) == 0 || len(entries) == 0 {
		return none, nil // nothing committed
	}

	nameWhere := pred
	if q.Wildcard {
		nameWhere += " AND is_wildcard"
	}
	quoted := make([]string, len(q.Kinds))
	for i, k := range q.Kinds {
		quoted[i] = quote(k)
	}
	certWhere := []string{"cert_id IN (SELECT cert_id FROM n)", "kind IN (" + strings.Join(quoted, ", ") + ")"}
	if q.Issuer != "" {
		certWhere = append(certWhere, "lower(issuer_cn) = "+quote(strings.ToLower(q.Issuer)))
	}
	if q.IssuerOrg != "" {
		certWhere = append(certWhere, "lower(issuer_o) = "+quote(strings.ToLower(q.IssuerOrg)))
	}
	if q.KeyAlg != "" {
		certWhere = append(certWhere, "key_alg = "+quote(q.KeyAlg))
	}
	if q.ParseStatus != "" {
		certWhere = append(certWhere, "parse_status = "+quote(q.ParseStatus))
	}
	if q.ValidAt != nil {
		certWhere = append(certWhere, "not_before <= "+ts(*q.ValidAt), ts(*q.ValidAt)+" < not_after")
	}
	var entryWhere []string
	if q.Log != "" {
		entryWhere = append(entryWhere, "log = "+quote(q.Log))
	}
	col := "ct_ts"
	where := &entryWhere
	if q.ByNotBefore {
		col, where = "not_before", &certWhere
	}
	if q.Since != nil {
		*where = append(*where, col+" >= "+ts(*q.Since))
	}
	if q.Until != nil {
		*where = append(*where, col+" < "+ts(*q.Until))
	}
	if q.IssuedBy != "" {
		p, err := issuedBy(ctx, s, sess, vaultDirs, q.IssuedBy, entries, chains)
		if err != nil {
			return compiled{}, err
		}
		certWhere = append(certWhere, p)
	}
	// Prune with the matched cert_ids (amendment A3 §7.1): only the batches
	// whose cert_id_range holds one can hold its certs row, and only those
	// batches and later ones can hold an entry that references it.
	ids, err := matchedCertIDs(ctx, sess, fileList(names)+s.unionOpt("names"), nameWhere)
	if err != nil {
		return compiled{}, err
	}
	if len(ids) == 0 {
		return none, nil
	}
	certs, entries = s.filesFor(ids)
	if len(certs) == 0 {
		return none, nil
	}
	idFilter := "cert_id IN (SELECT cert_id FROM n)"
	if len(ids) <= maxLiteralIDs {
		lits := make([]string, len(ids))
		for i, id := range ids {
			lits[i] = strconv.FormatUint(id, 10)
		}
		idFilter = "cert_id IN (" + strings.Join(lits, ", ") + ")"
	}
	certWhere[0] = idFilter
	eFilter := ""
	if len(entryWhere) > 0 {
		eFilter = " AND " + strings.Join(entryWhere, " AND ")
	}
	join := "LEFT JOIN"
	if len(entryWhere) > 0 {
		join = "JOIN" // only certificates with an entry that passes the filters
	}

	with := fmt.Sprintf(`WITH n AS (SELECT cert_id, name FROM read_parquet(%s) WHERE %s),
c AS (SELECT cert_id, sha256, kind, issuer_cn, not_before, not_after, n_dns_names + n_ip_names AS names
      FROM read_parquet(%s) WHERE %s),
e AS (SELECT cert_id, min(ct_ts) AS first_seen, max(ct_ts) AS last_seen, list_sort(list_distinct(list(log))) AS logs
      FROM read_parquet(%s, hive_partitioning = true) WHERE %s%s GROUP BY cert_id)`,
		fileList(names)+s.unionOpt("names"), nameWhere, fileList(certs)+s.unionOpt("certs"), strings.Join(certWhere, " AND "), fileList(entries), idFilter, eFilter)
	var body string
	switch q.Group {
	case "names":
		body = `SELECT n.name AS name, min(e.first_seen) AS first_seen, max(e.last_seen) AS last_seen, count(DISTINCT n.cert_id) AS certs,
       list_slice(list_sort(list_distinct(list(c.issuer_cn))), 1, 5) AS issuers
FROM n JOIN c USING (cert_id) ` + join + ` e USING (cert_id) GROUP BY n.name`
	case "certs":
		body = `SELECT c.sha256, c.cert_id, c.kind, c.issuer_cn, c.not_before, c.not_after, c.names, e.first_seen, e.last_seen, e.logs
FROM c ` + join + ` e USING (cert_id)`
	case "issuances":
		with += fmt.Sprintf(`,
ei AS (SELECT issuance_key, cert_id, entry_type, ct_ts FROM read_parquet(%s, hive_partitioning = true)
       WHERE %s AND issuance_key IS NOT NULL%s)`, fileList(entries), idFilter, eFilter)
		body = `SELECT lower(hex(ei.issuance_key)) AS issuance_key, min(ei.ct_ts) AS first_seen, max(ei.ct_ts) AS last_seen,
       count(DISTINCT ei.cert_id) AS certs, bool_or(ei.entry_type = 'precert') AS precert, bool_or(ei.entry_type = 'x509') AS final,
       list_slice(list_sort(list_distinct(list(c.issuer_cn))), 1, 5) AS issuers
FROM ei JOIN c USING (cert_id) GROUP BY ei.issuance_key`
	}
	return compiled{g: g, with: with, body: body}, nil
}

func run(ctx context.Context, s *Snapshot, sess *Session, vaultDirs []string, q *Query, after *Cursor, limit int, fn rowFunc) error {
	c, err := compile(ctx, s, sess, vaultDirs, q)
	if err != nil || c.body == "" {
		return err
	}
	g := c.g
	sort, desc := sortOf(q)
	cols := q.Columns()
	var outer []string
	if q.Filter != "" {
		outer = append(outer, filterPredicate(cols, q.Filter))
	}
	if after != nil {
		outer = append(outer, keyset(sort, g.tiebreak, desc, *after))
	}
	sql := c.with + "\nSELECT " + strings.Join(cols, ", ") + ", " + sort + " AS __ctv_sort, " + g.tiebreak + " AS __ctv_tie FROM (" + c.body + ") AS g"
	if len(outer) > 0 {
		sql += " WHERE " + strings.Join(outer, " AND ")
	}
	sql += " ORDER BY " + orderBy("__ctv_sort", desc, "__ctv_tie")
	if limit > 0 {
		sql += " LIMIT " + strconv.Itoa(limit)
	}
	return scanRows(ctx, sess, sql, len(cols), cols, fn)
}

// sortOf is a normalized query's sort column and direction.
func sortOf(q *Query) (col string, desc bool) {
	f := strings.Fields(q.Sort)
	return f[0], len(f) == 2 && f[1] == "desc"
}

// orderBy is every search's order: the sort, NULLs last, then the unique
// tie-breaker.
func orderBy(sort string, desc bool, tie string) string {
	if desc {
		sort += " DESC"
	}
	return sort + " NULLS LAST, " + tie
}

// filterPredicate is explore's /: a case-insensitive text match over the
// displayed columns (amendment A4 §3).
func filterPredicate(cols []string, text string) string {
	cast := make([]string, len(cols))
	for i, c := range cols {
		cast[i] = "CAST(" + c + " AS VARCHAR)"
	}
	return "strpos(lower(concat_ws(' ', " + strings.Join(cast, ", ") + ")), " + quote(strings.ToLower(text)) + ") > 0"
}

// scanRows runs sql, whose columns are cols then the sort key and the
// tie-breaker, and calls fn for every row.
func scanRows(ctx context.Context, sess *Session, sql string, n int, cols []string, fn rowFunc) error {
	rows, err := sess.db.QueryContext(ctx, sql)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		vals := make([]any, n+2)
		ptrs := make([]any, len(vals))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		if err := fn(cols, vals[:n:n], Cursor{Sort: vals[n], Tie: vals[n+1]}); err != nil {
			return err
		}
	}
	return rows.Err()
}

// keyset is the predicate for the rows after c, in an order by sort (asc
// or desc, NULLs last) and then tie (asc, unique).
func keyset(sort, tie string, desc bool, c Cursor) string {
	t := tie + " > " + sqlLiteral(c.Tie)
	if c.Sort == nil {
		return "(" + sort + " IS NULL AND " + t + ")"
	}
	op := " > "
	if desc {
		op = " < "
	}
	v := sqlLiteral(c.Sort)
	return "(" + sort + op + v + " OR (" + sort + " = " + v + " AND " + t + ") OR " + sort + " IS NULL)"
}

// sqlLiteral renders a value scanned from DuckDB back as a literal.
func sqlLiteral(v any) string {
	switch x := v.(type) {
	case nil:
		return "NULL"
	case string:
		return quote(x)
	case bool:
		return strconv.FormatBool(x)
	case time.Time:
		return "TIMESTAMP " + quote(x.UTC().Format("2006-01-02 15:04:05.999999"))
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = sqlLiteral(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	return fmt.Sprint(v)
}

// issuedBy compiles --issued-by (amendment A3 §3.2): the certificate's
// issuer_der equals the CA's subject_der, and the log served it with a
// chain whose position 0 is the CA, or its AKI equals the CA's SKI.
func issuedBy(ctx context.Context, s *Snapshot, sess *Session, vaultDirs []string, arg string, entries, chains []string) (string, error) {
	f, err := NewFetcher(s, sess, vaultDirs)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var ca *Cert
	if sha256Hex.MatchString(arg) {
		var sha [32]byte
		b, _ := hex.DecodeString(strings.ToLower(arg))
		copy(sha[:], b)
		ca, err = f.BySHA256(ctx, sha)
	} else if id, perr := strconv.ParseUint(arg, 10, 64); perr == nil {
		ca, err = f.ByCertID(ctx, id)
	} else {
		return "", usage("--issued-by: %q is neither a SHA-256 nor a cert_id", arg)
	}
	if errors.Is(err, ErrNotFound) {
		return "", usage("--issued-by: %s: %v", arg, err)
	}
	if err != nil {
		return "", err
	}
	subject, ok := ca.Row["subject_der"].(string)
	if !ok {
		return "", usage("--issued-by: %s is not a CA certificate a log served in a chain (it has no subject_der)", arg)
	}
	rel := []string{fmt.Sprintf("cert_id IN (SELECT cert_id FROM read_parquet(%s) WHERE chain_id IN "+
		"(SELECT chain_id FROM read_parquet(%s) WHERE position = 0 AND cert_id = %d))", fileList(entries), fileList(chains), ca.CertID)}
	if ski, ok := ca.Row["subject_key_id"].(string); ok {
		rel = append(rel, "authority_key_id = "+quote(ski))
	}
	return "issuer_der = " + quote(subject) + " AND (" + strings.Join(rel, " OR ") + ")", nil
}

var sha256Hex = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// maxLiteralIDs bounds the cert_ids inlined into a search as a literal
// list, which lets DuckDB prune row groups by their statistics. A larger
// match uses a subquery, faster for DuckDB at that size (measured: 15,000
// literals took 1.2 s against 75 ms), over the same pruned files.
const maxLiteralIDs = 1000

// matchedCertIDs returns the distinct cert_ids of the names rows that
// match, sorted.
func matchedCertIDs(ctx context.Context, sess *Session, names, where string) ([]uint64, error) {
	rows, err := sess.db.QueryContext(ctx, `SELECT DISTINCT cert_id FROM read_parquet(`+names+`) WHERE `+where+` ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uint64
	for rows.Next() {
		var id uint64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// filesFor returns the certs files of the batches whose cert_id_range holds
// one of ids (sorted), and the entries files of those batches and every
// later one: an entry can only reference a certificate already vaulted.
func (s *Snapshot) filesFor(ids []uint64) (certs, entries []string) {
	p := commit.Paths{Root: s.Root}
	first := -1
	for i, m := range s.Batches {
		r := m.CertIDRange
		if r == nil {
			continue
		}
		if j, _ := slices.BinarySearch(ids, r[0]); j < len(ids) && ids[j] <= r[1] {
			if f, ok := s.batchFile(m, "certs"); ok {
				certs = append(certs, filepath.Join(p.BatchDir(m.ID()), f))
			}
			if first < 0 {
				first = i
			}
		}
	}
	if first < 0 {
		return nil, nil
	}
	for _, m := range s.Batches[first:] {
		if _, ok := m.Listed(dataset.EntriesFile); ok {
			entries = append(entries, filepath.Join(p.BatchDir(m.ID()), dataset.EntriesFile))
		}
	}
	return certs, entries
}
