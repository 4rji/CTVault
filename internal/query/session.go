package query

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"

	duckdb "github.com/duckdb/duckdb-go/v2"

	"github.com/4rji/ctvault/internal/diskguard"
)

// Session is a reader's DuckDB session (amendment A3 §2.2): in memory,
// every core, the Parquet metadata cache on, and spill confined to its own
// tmp/duckdb-<pid>/, removed on Close.
type Session struct {
	connector *duckdb.Connector // nil for a borrowed database
	db        *sql.DB
	spill     string
	held      atomic.Uint64 // names held tables (results.go)
}

// SessionOn reads through a database the caller owns, such as the writer's
// own session for the post-commit audit. Close leaves it open.
func SessionOn(db *sql.DB) *Session { return &Session{db: db} }

// spillPrefix names readers' spill folders under tmp/ (spec §10.1).
const spillPrefix = "duckdb-"

// NewSession opens a reader session for the vault at root. It first
// removes the spill folders of readers that no longer run.
func NewSession(root string, g diskguard.Guard) (*Session, error) {
	tmp := filepath.Join(root, "tmp")
	removeDeadSpill(tmp)
	spill := filepath.Join(tmp, spillPrefix+strconv.Itoa(os.Getpid()))
	if err := os.MkdirAll(spill, 0o755); err != nil {
		return nil, err
	}
	settings := []string{
		"SET temp_directory = " + quote(spill),
		fmt.Sprintf("SET max_temp_directory_size = '%dB'", spillLimit(root, g)),
		"SET parquet_metadata_cache = true",
	}
	c, err := duckdb.NewConnector("", func(execer driver.ExecerContext) error {
		for _, q := range settings {
			if _, err := execer.ExecContext(context.Background(), q, nil); err != nil {
				return fmt.Errorf("duckdb %q: %w", q, err)
			}
		}
		return nil
	})
	if err != nil {
		os.RemoveAll(spill)
		return nil, err
	}
	return &Session{connector: c, db: sql.OpenDB(c), spill: spill}, nil
}

// DB is the session's database, for read-only checks that go beyond
// search (verify --full). Its queries spill into the session's folder.
func (s *Session) DB() *sql.DB { return s.db }

// Close ends the session and removes its spill folder.
func (s *Session) Close() error {
	if s.connector == nil {
		return nil
	}
	err := s.db.Close()
	if cerr := s.connector.Close(); err == nil {
		err = cerr
	}
	s.connector = nil
	if rerr := os.RemoveAll(s.spill); err == nil {
		err = rerr
	}
	return err
}

// spillLimit is spec §10.1's reader limit: the headroom below the cap minus
// 1 GiB, at least 64 MiB.
func spillLimit(root string, g diskguard.Guard) uint64 {
	const margin, floor = 1 << 30, 64 << 20
	if g.Stat == nil {
		return floor
	}
	u, err := g.Stat(root)
	if err != nil || u.Total == 0 {
		return floor
	}
	lim := uint64(g.Cap * float64(u.Total))
	if used := u.Used(); lim > used+margin+floor {
		return lim - used - margin
	}
	return floor
}

// removeDeadSpill deletes tmp/duckdb-<pid>/ folders whose process no longer
// exists (amendment A3 §2.3). A live process's folder, and the writer's
// tmp/duckdb-writer/, are never touched.
func removeDeadSpill(tmp string) {
	es, _ := os.ReadDir(tmp)
	for _, e := range es {
		pid, ok := strings.CutPrefix(e.Name(), spillPrefix)
		if !ok || !e.IsDir() {
			continue
		}
		n, err := strconv.Atoi(pid)
		if err != nil || n <= 0 || n == os.Getpid() {
			continue
		}
		if err := syscall.Kill(n, 0); err == syscall.ESRCH {
			os.RemoveAll(filepath.Join(tmp, e.Name()))
		}
	}
}

// quote makes a SQL string literal.
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// fileList renders paths as a DuckDB list literal for read_parquet.
func fileList(paths []string) string {
	q := make([]string, len(paths))
	for i, p := range paths {
		q[i] = quote(p)
	}
	return "[" + strings.Join(q, ", ") + "]"
}
