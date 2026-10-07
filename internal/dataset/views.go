package dataset

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/fsutil"
)

// ViewsFile is generated at the vault root for the DuckDB CLI and Jupyter.
const ViewsFile = "views.sql"

// baseViews is the start of views.sql for a vault at root (absolute), Plan
// 2's minimal set: entries, chains and batches over committed batch directories only;
// staging lives in tmp/, never under dataset/. Until the first batch
// commits, the globs would match nothing and DuckDB would refuse to load
// the file, so the views are empty with the committed columns instead.
func baseViews(root string, committed bool) string {
	head := fmt.Sprintf(viewsHead+"%s\n", filepath.Join(root, ViewsFile))
	if !committed {
		return head + `-- No batch is committed yet: the views are empty. ctvault rewrites this
-- file when the first batch commits.
CREATE OR REPLACE VIEW entries AS
  SELECT NULL::UBIGINT AS idx, NULL::TIMESTAMP AS ct_ts, NULL::VARCHAR AS entry_type, NULL::UBIGINT AS cert_id,
    NULL::BLOB AS leaf_hash, NULL::BLOB AS issuance_key, NULL::BLOB AS issuer_key_hash, NULL::BLOB AS chain_id,
    NULL::VARCHAR AS leaf_error, NULL::VARCHAR AS batch, NULL::VARCHAR AS log
  WHERE false;
CREATE OR REPLACE VIEW chains AS
  SELECT NULL::BLOB AS chain_id, NULL::USMALLINT AS position, NULL::UBIGINT AS cert_id,
    NULL::VARCHAR AS batch, NULL::VARCHAR AS log
  WHERE false;
CREATE OR REPLACE VIEW batches AS
  SELECT NULL::UBIGINT AS commit_seq, NULL::VARCHAR AS batch_id, NULL::VARCHAR AS log,
    NULL::UBIGINT AS first, NULL::UBIGINT AS last
  WHERE false;
`
	}
	ds := filepath.Join(root, "dataset")
	glob := func(name string) string { return quote(filepath.Join(ds, "log=*", "batch=*", name)) }
	return head + fmt.Sprintf(`-- Globs see a commit at once, but a join running while a batch commits can
-- see it in one table and not yet in another (spec §7.6).
CREATE OR REPLACE VIEW entries AS
  SELECT * FROM read_parquet(%s, hive_partitioning = true, union_by_name = true);
CREATE OR REPLACE VIEW chains AS
  SELECT * FROM read_parquet(%s, hive_partitioning = true, union_by_name = true);
CREATE OR REPLACE VIEW batches AS
  SELECT * FROM read_json(%s, format = 'auto', union_by_name = true);
`, glob(EntriesFile), glob(ChainsFile), glob("_COMMIT.json"))
}

// Views returns views.sql for a vault at root (absolute): the source-layer
// views, then the derived tables as ACTIVE.json says (amendment A2 §4.7, A5
// §7, §10). A readable table (an active version, not mixed) is exposed under
// its name at its active version, with entry_certs and logging_delay
// joining certs; a version being built as <table>_building; a mixed table
// only as <table>_building and <table>_previous, never under its name.
// present names the derived files at least one committed batch holds; a
// view over a file no batch holds yet is empty with the table's columns.
func Views(root string, committed bool, a derive.Active, present map[string]bool) []byte {
	var b strings.Builder
	b.WriteString(baseViews(root, committed))
	glob := func(name string) string {
		return quote(filepath.Join(root, "dataset", "log=*", "batch=*", name))
	}
	view := func(name string, tb derive.Table) {
		file := tb.File()
		if present[file] {
			fmt.Fprintf(&b, "CREATE OR REPLACE VIEW %s AS\n  SELECT * FROM read_parquet(%s, hive_partitioning = true, union_by_name = true);\n", name, glob(file))
			return
		}
		var cols []string
		for _, c := range tb.Columns {
			cols = append(cols, fmt.Sprintf("NULL::%s AS %s", c.Type, c.Name))
		}
		cols = append(cols, "NULL::VARCHAR AS batch", "NULL::VARCHAR AS log")
		fmt.Fprintf(&b, "CREATE OR REPLACE VIEW %s AS\n  SELECT %s\n  WHERE false;\n", name, strings.Join(cols, ", "))
	}
	for _, bl := range derive.Builders {
		name := bl.Table().Name
		st := a.Tables[name]
		if tb, ok := a.Readable(name); ok {
			view(name, tb)
		}
		if st.Building != nil {
			view(name+"_building", derive.BuilderOf(name, *st.Building).Table())
		}
		if st.Status == derive.StatusMixed && st.Active != nil {
			view(name+"_previous", tableAt(name, *st.Active))
		}
	}
	if _, ok := a.Readable(derive.CertsV1.Name); ok {
		b.WriteString(`CREATE OR REPLACE VIEW entry_certs AS
  SELECT e.*, c.* EXCLUDE (cert_id, batch, log) FROM entries e JOIN certs c USING (cert_id);
CREATE OR REPLACE VIEW logging_delay AS
  SELECT e.log, e.idx, e.cert_id, e.ct_ts, c.not_before, CAST(e.ct_ts AS TIMESTAMP) - c.not_before AS logging_delay
  FROM entries e JOIN certs c USING (cert_id);
`)
	}
	return []byte(b.String())
}

// tableAt is a version's definition when this binary carries it, else its
// name and version (an empty view then has no columns but batch and log).
func tableAt(name string, version int) derive.Table {
	if b := derive.BuilderOf(name, version); b != nil {
		return b.Table()
	}
	return derive.Table{Name: name, Version: version}
}

// viewsHead begins views.sql's first line, which names the file's path.
const viewsHead = "-- Generated by ctvault; do not edit. Load with: .read "

// ViewsRoot returns the vault root a views.sql was written for: the writer
// names the root as it was given, so the same vault reached by another
// path (a symlink) has the same views under another spelling.
func ViewsRoot(views []byte) (string, bool) {
	line, _, _ := strings.Cut(string(views), "\n")
	p, ok := strings.CutPrefix(line, viewsHead)
	if !ok || filepath.Base(p) != ViewsFile {
		return "", false
	}
	return filepath.Dir(p), true
}

// ExpectedViews is the views.sql the committed batches and ACTIVE.json's
// state a call for (verify compares it with the file).
func ExpectedViews(root string, a derive.Active) ([]byte, error) {
	done, err := filepath.Glob(filepath.Join(root, "dataset", "log=*", "batch=*", "_COMMIT.json"))
	if err != nil {
		return nil, err
	}
	present := map[string]bool{}
	for _, d := range done {
		files, err := os.ReadDir(filepath.Dir(d))
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			present[f.Name()] = true
		}
	}
	return Views(root, len(done) > 0, a, present), nil
}

// WriteViews regenerates views.sql from ACTIVE.json's state a and replaces
// it atomically only when its contents change (amendment A1 §7). It reports
// whether it wrote. The writer calls it at start, after every commit and
// whenever ACTIVE.json changes.
func WriteViews(root string, a derive.Active) (bool, error) {
	want, err := ExpectedViews(root, a)
	if err != nil {
		return false, err
	}
	p := filepath.Join(root, ViewsFile)
	got, err := os.ReadFile(p)
	if err == nil && bytes.Equal(got, want) {
		return false, nil
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	return true, fsutil.WriteFileAtomic(p, want, 0o644)
}
