package logreg

import (
	"context"
	"errors"
	"net/http"
	"os"
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
