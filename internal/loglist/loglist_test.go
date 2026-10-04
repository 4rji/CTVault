package loglist

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const fixture = "../testdata/log_list_google.json"

func load(t *testing.T) *List {
	t.Helper()
	l, err := Fetch(context.Background(), http.DefaultClient, fixture)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestFindArgon2027h1(t *testing.T) {
	r, err := load(t).Find("Argon2027h1")
	if err != nil {
		t.Fatal(err)
	}
	if r.Name != "argon2027h1" || r.Log.URL != "https://ct.googleapis.com/logs/us1/argon2027h1/" || r.Operator != "Google" {
		t.Fatalf("resolved %+v", r)
	}
	if r.Log.CurrentState() != "usable" || r.Log.TemporalInterval == nil {
		t.Fatalf("state %q interval %v", r.Log.CurrentState(), r.Log.TemporalInterval)
	}
	pub, err := ParseKey(r.Log.Key, r.Log.LogID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Fatalf("argon2027h1 uses ECDSA, got %T", pub)
	}
}

func TestFindErrors(t *testing.T) {
	l := load(t)
	if _, err := l.Find("parcelyard2027h1"); !errors.Is(err, ErrTiledUnsupported) {
		t.Fatalf("tiled log: got %v", err)
	}
	if _, err := l.Find("argon2099h1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown log: got %v", err)
	}
	dup := *l
	dup.Operators = append(dup.Operators, Operator{Name: "Copycat", Logs: []Log{{URL: "https://example.test/ct/argon2027h1/"}}})
	if _, err := dup.Find("argon2027h1"); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("duplicate name: got %v", err)
	}
}

func TestRFC6962LogsSorted(t *testing.T) {
	logs := load(t).RFC6962Logs()
	var names []string
	for _, r := range logs {
		names = append(names, r.Name)
	}
	if strings.Join(names, ",") != "argon2026h2,argon2027h1,xenon2026h2,xenon2027h1" {
		t.Fatalf("names = %v", names)
	}
}

func TestParseKeyRejectsMismatchedLogID(t *testing.T) {
	r, _ := load(t).Find("argon2027h1")
	other, _ := load(t).Find("xenon2027h1")
	if _, err := ParseKey(r.Log.Key, other.Log.LogID); !errors.Is(err, ErrBadKey) {
		t.Fatalf("want ErrBadKey, got %v", err)
	}
}

func TestFetchOverHTTPAndHTMLPage(t *testing.T) {
	good, _ := os.ReadFile(fixture)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/portal" {
			w.Write([]byte("<html><body>Hotel Wi-Fi login</body></html>"))
			return
		}
		w.Write(good)
	}))
	defer srv.Close()
	if _, err := Fetch(context.Background(), srv.Client(), srv.URL+"/log_list.json"); err != nil {
		t.Fatalf("HTTP fetch: %v", err)
	}
	_, err := Fetch(context.Background(), srv.Client(), srv.URL+"/portal")
	if err == nil || !strings.Contains(err.Error(), "not valid JSON") || !strings.Contains(err.Error(), "<html>") {
		t.Fatalf("HTML page must give a clear error, got %v", err)
	}
	if _, err := Parse([]byte(`{"version":"1"}`)); err == nil {
		t.Fatal("list without operators must be rejected")
	}
}

func TestTiledName(t *testing.T) {
	cases := map[string]string{
		"https://storage.googleapis.com/parcelyard2027h1.prod.certificate.transparency.goog/": "parcelyard2027h1",
		"https://sycamore2027h1.ct.example.org/":                                              "sycamore2027h1",
	}
	for in, want := range cases {
		if got := TiledName(in); got != want {
			t.Errorf("TiledName(%q) = %q, want %q", in, got, want)
		}
	}
}
