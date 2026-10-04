package loglist

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
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

func TestLogName(t *testing.T) {
	cases := []struct{ description, url, want string }{
		{"Google 'Argon2027h1'", "https://ct.googleapis.com/logs/us1/argon2027h1/", "argon2027h1"},
		{"DigiCert 'Wyvern2027h1'", "https://wyvern.ct.digicert.com/2027h1/", "wyvern2027h1"},
		{"DigiCert 'sphinx2027h1'", "https://sphinx.ct.digicert.com/2027h1/", "sphinx2027h1"},
		{"Let's Encrypt 'Oak2026h2'", "https://oak.ct.letsencrypt.org/2026h2/", "oak2026h2"},
		{"Geomys Tuscolo2028h1", "https://tuscolo2028h1.sunlight.geomys.org/", "tuscolo2028h1"},
		{"GoDaddy Aquamarine2026h2", "https://ct-log-api.godaddy.com/aquamarine2026h2/", "aquamarine2026h2"},
		{"TrustAsia Luoshu2027", "https://luoshu2027.trustasia.com/luoshu2027/", "luoshu2027"},
		{"Bogus placeholder log", "https://ct.example.com/bogus/", "ct-example-com-bogus"},
		{"Bogus RFC6962 log", "https://ct.example.com/bogus/ipng/", "ct-example-com-bogus-ipng"},
	}
	for _, c := range cases {
		if got := LogName(c.description, c.url); got != c.want {
			t.Errorf("LogName(%q, %q) = %q, want %q", c.description, c.url, got, c.want)
		}
	}
}

func loadFull(t *testing.T) *List {
	t.Helper()
	l, err := Fetch(context.Background(), http.DefaultClient, "../testdata/log_list_v93.3_full.json")
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// TestEveryLogInFullListHasAUniqueName: names become permanent on disk in
// Plan 2 (partition paths, batch IDs, _COMMIT.json), so every RFC 6962 and
// tiled log in the real v93.3 list must get a distinct, path-safe name.
func TestEveryLogInFullListHasAUniqueName(t *testing.T) {
	valid := regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	seen := map[string]string{}
	add := func(name, what string) {
		if !valid.MatchString(name) {
			t.Errorf("%s: name %q is not path-safe", what, name)
		}
		if prev, dup := seen[name]; dup {
			t.Errorf("name %q is used by both %s and %s", name, prev, what)
		}
		seen[name] = what
	}
	l := loadFull(t)
	for _, op := range l.Operators {
		for _, lg := range op.Logs {
			add(lg.Name(), lg.Description)
		}
		for _, tl := range op.TiledLogs {
			add(tl.Name(), tl.Description)
		}
	}
	if len(seen) < 60 {
		t.Fatalf("only %d logs checked; fixture not the full list?", len(seen))
	}
}

func TestFindNonGoogleLogs(t *testing.T) {
	l := loadFull(t)
	for name, wantURL := range map[string]string{
		"wyvern2027h1":  "https://wyvern.ct.digicert.com/2027h1/",
		"sphinx2027h1":  "https://sphinx.ct.digicert.com/2027h1/",
		"oak2026h2":     "https://oak.ct.letsencrypt.org/2026h2/",
		"mammoth2026h2": "https://mammoth2026h2.ct.sectigo.com/",
		"argon2027h1":   "https://ct.googleapis.com/logs/us1/argon2027h1/",
	} {
		r, err := l.Find(name)
		if err != nil || r.Log.URL != wantURL {
			t.Errorf("Find(%q) = %q, %v; want %s", name, r.Log.URL, err, wantURL)
		}
	}
	if _, err := l.Find("2027h1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a bare shard name must not match any log, got %v", err)
	}
	for _, tiled := range []string{"sycamore2027h1", "aquamarine2026h2", "tuscolo2028h1"} {
		if _, err := l.Find(tiled); !errors.Is(err, ErrTiledUnsupported) {
			t.Errorf("Find(%q): want ErrTiledUnsupported, got %v", tiled, err)
		}
	}
}
