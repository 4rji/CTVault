package derive

// Versions are the builders a binary carries for one table: its current
// version N and, in the release after a change, N−1, so that ingestion can
// build both while the old batches are rebuilt (spec §7.5, amendment A5 §7).
type Versions struct {
	Current  Builder
	Previous Builder // nil unless the binary carries N−1
}

// Registry is this binary's tables, in a fixed order.
var Registry = []Versions{{Current: Certs{}}, {Current: Names{}},
	{Current: CertExtensions{}}, {Current: CertPolicies{}}, {Current: CertEKUs{}}, {Current: CertKeyUsage{}},
	{Current: CertAIA{}}, {Current: CertCRLDPs{}}, {Current: CertSCTs{}}}

func current(r []Versions) []Builder {
	out := make([]Builder, len(r))
	for i, v := range r {
		out[i] = v.Current
	}
	return out
}

// SetRegistry replaces the registry and returns a function that restores
// it. Only tests call it, to carry a test-only version.
func SetRegistry(r []Versions) (restore func()) {
	oldR, oldB := Registry, Builders
	Registry, Builders = r, current(r)
	return func() { Registry, Builders = oldR, oldB }
}

// BuilderOf returns the builder of a table's version, or nil when this binary
// does not carry that version.
func BuilderOf(name string, version int) Builder {
	for _, v := range Registry {
		for _, b := range []Builder{v.Current, v.Previous} {
			if b != nil && b.Table().Name == name && b.Table().Version == version {
				return b
			}
		}
	}
	return nil
}

// versions returns a table's current and previous versions (0 if none),
// and whether the binary carries the table.
func versions(name string) (cur, prev int, ok bool) {
	for _, v := range Registry {
		if v.Current.Table().Name == name {
			cur = v.Current.Table().Version
			if v.Previous != nil {
				prev = v.Previous.Table().Version
			}
			return cur, prev, true
		}
	}
	return 0, 0, false
}
