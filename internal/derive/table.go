// Package derive builds the derived tables, certs and names, from extracted
// certificates (spec §7.2-7.5, amendment A2 §4). A row depends only on the
// certificate's DER and its vault context, so the same batch always derives
// the same rows, at ingest or in a later local rebuild.
package derive

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/4rji/ctvault/internal/extract"
	"github.com/4rji/ctvault/internal/vault"
)

// ExtractorVersion names the extractor's output. Any change to what
// extract.Parse returns bumps it, and with it every table's version (spec
// §7.2).
const ExtractorVersion = "ctvault-extract/1"

// PSLSnapshot is the public-suffix list that names' tld and etld1 come
// from: the pinned golang.org/x/net and its embedded list (spec §7.2).
const PSLSnapshot = "golang.org/x/net v0.59.0, public_suffix_list.dat d6c92f1bbb7433e5db7b8405c25d4035fb8ff376 (2026-02-06T07:36:33Z)"

// Column is one column of a derived table: a DuckDB type, never BLOB (D19:
// these files carry bloom filters).
type Column struct{ Name, Type string }

// Table is one version of a derived table.
type Table struct {
	Name    string
	Version int
	Columns []Column
	PSL     string // the public-suffix snapshot, for tables that use eTLD+1
}

// File is the table's file name in a batch directory, e.g. certs.p1.parquet.
func (t Table) File() string { return fmt.Sprintf("%s.p%d.parquet", t.Name, t.Version) }

// SchemaSHA256 hashes the column list, "name type\n" per column.
func (t Table) SchemaSHA256() string {
	h := sha256.New()
	for _, c := range t.Columns {
		fmt.Fprintf(h, "%s %s\n", c.Name, c.Type)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// KV is the Parquet key-value metadata every file of the table carries
// (spec §7.2), in a fixed order.
func (t Table) KV() [][2]string {
	return [][2]string{
		{"ctvault.table", t.Name},
		{"ctvault.version", strconv.Itoa(t.Version)},
		{"ctvault.extractor", ExtractorVersion},
		{"ctvault.schema_sha256", t.SchemaSHA256()},
		{"ctvault.psl", t.PSL},
	}
}

// Row is one row: values in the table's column order, nil for NULL.
type Row []any

// Certificate kinds: how a certificate was first vaulted (spec §7.3).
const (
	KindPrecert = "precert"
	KindFinal   = "final"
	KindChain   = "chain"
)

// Context is what a builder knows about a certificate besides its DER.
type Context struct {
	CertID          uint64
	SHA256          [32]byte
	Kind            string
	Loc             vault.Loc
	DeltaBaseCertID uint64 // 0 unless the record is a leaf-delta
}

// Builder derives one table's rows from a certificate (spec §7.5).
type Builder interface {
	Table() Table
	Build(c *extract.Cert, ctx Context) []Row
}

// Builders are the current version of each table this binary carries, in
// the registry's order.
var Builders = current(Registry)
