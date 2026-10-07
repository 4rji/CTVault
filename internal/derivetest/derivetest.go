// Package derivetest carries test-only table versions, for tests of
// version transitions (amendment A5 §11): no production binary carries
// them.
package derivetest

import (
	"slices"
	"testing"

	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/extract"
)

// CertsV2 is a test-only certs v2: v1's columns and one more, so it keeps
// every column the queries use, as a new version must.
type CertsV2 struct{}

// Table is certs v2.
func (CertsV2) Table() derive.Table {
	t := derive.CertsV1
	t.Version = 2
	t.Columns = append(append([]derive.Column{}, derive.CertsV1.Columns...), derive.Column{Name: "v2_marker", Type: "BOOLEAN"})
	return t
}

// Build is v1's row and true.
func (CertsV2) Build(c *extract.Cert, ctx derive.Context) []derive.Row {
	rows := derive.Certs{}.Build(c, ctx)
	for i := range rows {
		rows[i] = append(rows[i], true)
	}
	return rows
}

// Flags is a test-only new table, flags v1: one row per certificate.
type Flags struct{}

// FlagsV1 is its definition.
var FlagsV1 = derive.Table{Name: "flags", Version: 1, Columns: []derive.Column{{Name: "cert_id", Type: "UBIGINT"}, {Name: "is_chain", Type: "BOOLEAN"}}}

// Table is flags v1.
func (Flags) Table() derive.Table { return FlagsV1 }

// Build is the certificate's ID and whether it is a chain certificate.
func (Flags) Build(_ *extract.Cert, ctx derive.Context) []derive.Row {
	return []derive.Row{{ctx.CertID, ctx.Kind == derive.KindChain}}
}

// Registries name the test registries, for crash children that set theirs
// from their configuration.
var Registries = map[string][]derive.Versions{
	"v2":        withCerts(derive.Versions{Current: CertsV2{}, Previous: derive.Certs{}}),
	"v2-only":   withCerts(derive.Versions{Current: CertsV2{}}),
	"new-table": withCerts(derive.Versions{Current: derive.Certs{}}, derive.Versions{Current: Flags{}}),
}

// withCerts is the binary's own registry, the D tables included, with certs
// replaced and extra tables appended.
func withCerts(certs derive.Versions, extra ...derive.Versions) []derive.Versions {
	r := slices.Clone(derive.Registry)
	for i, v := range r {
		if v.Current.Table().Name == "certs" {
			r[i] = certs
		}
	}
	return append(r, extra...)
}

// Use makes the binary carry a test registry until the test ends.
func Use(t testing.TB, name string) {
	t.Helper()
	r, ok := Registries[name]
	if !ok {
		t.Fatalf("no test registry %q", name)
	}
	t.Cleanup(derive.SetRegistry(r))
}
