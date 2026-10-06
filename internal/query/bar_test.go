package query_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	. "github.com/4rji/ctvault/internal/query"
)

// TestParseBar: the bar's terms, short and long names, quoting, and its
// errors (amendment A4 §2.1).
func TestParseBar(t *testing.T) {
	oct := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	q, err := ParseBar(`suffix:api.example.com issuer:"Let's Encrypt" since:2026-10 kind:final,precert org:"A \"B\"" wildcard by:not-before`)
	if err != nil {
		t.Fatal(err)
	}
	want := Query{Mode: ModeSuffix, Text: "api.example.com", Issuer: "Let's Encrypt", Since: &oct, Kinds: []string{"final", "precert"},
		IssuerOrg: `A "B"`, Wildcard: true, ByNotBefore: true}
	if !reflect.DeepEqual(q, want) {
		t.Fatalf("parsed %+v\nwant   %+v", q, want)
	}
	long, err := ParseBar("example.com issuer-org:X key-alg:rsa parse-status:partial")
	if err != nil || long.Mode != ModeDomain || long.Text != "example.com" || long.IssuerOrg != "X" || long.KeyAlg != "rsa" || long.ParseStatus != "partial" {
		t.Fatalf("long names: %+v %v", long, err)
	}
	for _, bad := range []string{"", "a.com b.com", "foo:bar", "example.com since:yesterday", "example.com by:other",
		`issuer:"open`, "issuer:x", "exact:a.com suffix:b.com"} {
		if _, err := ParseBar(bad); !errors.Is(err, ErrUsage) {
			t.Errorf("%q: %v, want a usage error", bad, err)
		}
	}
}

// TestBarRoundTrip: Bar renders a query that parses back to itself.
func TestBarRoundTrip(t *testing.T) {
	for _, s := range []string{
		"example.com",
		`exact:"*.a.example.com" issuer:"Let's Encrypt" org:"A \"B\"" issued-by:42 key:ecdsa kind:final status:ok valid-at:2026-10-15 wildcard log:argon2027h1 since:2026-10-01 until:2027-01-01T12:00:00Z by:not-before`,
		"regex:^a.*$ kind:chain",
		"ip:192.0.2.1",
	} {
		q, err := ParseBar(s)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		again, err := ParseBar(q.Bar())
		if err != nil || !reflect.DeepEqual(again, q) {
			t.Fatalf("%q renders as %q, which parses to %+v (%v)", s, q.Bar(), again, err)
		}
	}
}

// TestIsBarKey: every key IsBarKey accepts is a term ParseBar knows.
func TestIsBarKey(t *testing.T) {
	for _, k := range []string{"suffix", "exact", "ip", "contains", "regex", "issuer", "org", "issuer-org", "issued-by", "key", "key-alg",
		"kind", "status", "parse-status", "valid-at", "log", "since", "until", "by"} {
		if !IsBarKey(k) {
			t.Errorf("%s: not a bar key", k)
		}
		if _, err := ParseBar("example.test " + k + ":x"); err != nil && strings.Contains(err.Error(), "unknown term") {
			t.Errorf("%s: %v", k, err)
		}
	}
	for _, k := range []string{"", "wildcard", "group", "Issuer"} {
		if IsBarKey(k) {
			t.Errorf("%q is not a bar key", k)
		}
	}
}
