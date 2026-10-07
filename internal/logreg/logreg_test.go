package logreg

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/loglist"
)

func setup(t *testing.T) (string, *loglist.List) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(Dir(root), 0o755); err != nil {
		t.Fatal(err)
	}
	l, err := loglist.Fetch(context.Background(), http.DefaultClient, "../testdata/log_list_google.json")
	if err != nil {
		t.Fatal(err)
	}
	return root, l
}

func TestAddGetList(t *testing.T) {
	root, l := setup(t)
	now := time.Date(2026, 10, 4, 7, 0, 0, 0, time.UTC)
	for _, name := range []string{"xenon2027h1", "argon2027h1"} {
		r, err := l.Find(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := Add(root, FromList(l, r, now)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Get(root, "Argon2027h1")
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != "https://ct.googleapis.com/logs/us1/argon2027h1/" || got.LogListVersion != "93.3" || !got.PinnedAt.Equal(now) {
		t.Fatalf("record = %+v", got)
	}
	if _, err := got.PublicKey(); err != nil {
		t.Fatal(err)
	}
	all, err := List(root)
	if err != nil || len(all) != 2 || all[0].Name != "argon2027h1" {
		t.Fatalf("List = %v, %v", all, err)
	}
}

func TestAddRefusesDuplicatesAndBadKeys(t *testing.T) {
	root, l := setup(t)
	r, _ := l.Find("argon2027h1")
	rec := FromList(l, r, time.Now())
	if err := Add(root, rec); err != nil {
		t.Fatal(err)
	}
	if err := Add(root, rec); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate: got %v", err)
	}
	other, _ := l.Find("xenon2027h1")
	forged := FromList(l, other, time.Now())
	forged.LogID = rec.LogID // key no longer hashes to the log ID
	if err := Add(root, forged); !errors.Is(err, loglist.ErrBadKey) {
		t.Fatalf("forged record: got %v", err)
	}
}

func TestGetUnknownAndInvalidName(t *testing.T) {
	root, _ := setup(t)
	if _, err := Get(root, "argon2027h1"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("unknown: got %v", err)
	}
	if _, err := Get(root, "../../etc/passwd"); err == nil {
		t.Fatal("path traversal must be rejected")
	}
}

// TestTiledRecord: a tiled log pins with its kind, the monitoring prefix as
// url, the submission URL and the origin computed once (amendment A6 §1).
func TestTiledRecord(t *testing.T) {
	root, l := setup(t)
	r, err := l.Find("parcelyard2027h1")
	if err != nil {
		t.Fatal(err)
	}
	rec := FromList(l, r, time.Now())
	if err := Add(root, rec); err != nil {
		t.Fatal(err)
	}
	got, err := Get(root, "parcelyard2027h1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != loglist.KindTiled || got.LogKind() != loglist.KindTiled ||
		got.URL != "https://storage.googleapis.com/parcelyard2027h1.prod.certificate.transparency.goog/" ||
		got.SubmissionURL != "https://parcelyard2027h1.prod.certificate.transparency.goog/" ||
		got.Origin != "parcelyard2027h1.prod.certificate.transparency.goog" || got.MMD != 60 || got.State != "usable" {
		t.Fatalf("record = %+v", got)
	}
	b, _ := os.ReadFile(filepath.Join(Dir(root), "parcelyard2027h1.json"))
	for _, want := range []string{`"kind": "tiled"`, `"origin": "parcelyard2027h1.prod.certificate.transparency.goog"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("the record file lacks %s:\n%s", want, b)
		}
	}
	argon, _ := l.Find("argon2027h1")
	if a := FromList(l, argon, time.Now()); a.Kind != loglist.KindRFC6962 || a.Origin != "" || a.SubmissionURL != "" {
		t.Fatalf("an RFC 6962 record: %+v", a)
	}
}

// TestRecordWithoutKindIsRFC6962: records pinned before amendment A6 have no
// kind and are read unchanged.
func TestRecordWithoutKindIsRFC6962(t *testing.T) {
	root, _ := setup(t)
	old := `{"name":"argon2027h1","url":"https://ct.googleapis.com/logs/us1/argon2027h1/","log_id":"x","key":"y"}`
	if err := os.WriteFile(filepath.Join(Dir(root), "argon2027h1.json"), []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Get(root, "argon2027h1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != "" || got.LogKind() != loglist.KindRFC6962 {
		t.Fatalf("kind %q, LogKind %q", got.Kind, got.LogKind())
	}
}

func TestAddRefusesInconsistentKinds(t *testing.T) {
	root, l := setup(t)
	r, _ := l.Find("parcelyard2027h1")
	good := FromList(l, r, time.Now())
	for name, mutate := range map[string]func(*Record){
		"unknown kind":             func(r *Record) { r.Kind = "sunlight" },
		"tiled, no origin":         func(r *Record) { r.Origin = "" },
		"tiled, wrong origin":      func(r *Record) { r.Origin = "plumbersarms2027h1.prod.certificate.transparency.goog" },
		"tiled, no submission URL": func(r *Record) { r.SubmissionURL = "" },
		"rfc6962 with an origin":   func(r *Record) { r.Kind = loglist.KindRFC6962 },
	} {
		rec := good
		mutate(&rec)
		if err := Add(root, rec); err == nil {
			t.Errorf("%s: pinned", name)
		}
	}
}
