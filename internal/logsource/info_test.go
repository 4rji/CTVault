package logsource

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/loglist"
	"github.com/4rji/ctvault/internal/logreg"
)

// TestInfoFromRecordKinds: LogInfo carries the kind and, for a tiled log,
// the pinned origin; a record whose kind fields disagree is refused
// (amendment A6 §1).
func TestInfoFromRecordKinds(t *testing.T) {
	l, err := loglist.Fetch(context.Background(), http.DefaultClient, "../testdata/log_list_google.json")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]LogInfo{
		"argon2027h1":      {Kind: loglist.KindRFC6962, URL: "https://ct.googleapis.com/logs/us1/argon2027h1/"},
		"parcelyard2027h1": {Kind: loglist.KindTiled, URL: "https://storage.googleapis.com/parcelyard2027h1.prod.certificate.transparency.goog/", Origin: "parcelyard2027h1.prod.certificate.transparency.goog"},
	} {
		r, err := l.Find(name)
		if err != nil {
			t.Fatal(err)
		}
		rec := logreg.FromList(l, r, time.Now())
		info, err := InfoFromRecord(rec)
		if err != nil {
			t.Fatal(err)
		}
		if info.Name != name || info.Kind != want.Kind || info.URL != want.URL || info.Origin != want.Origin || info.PublicKey == nil {
			t.Errorf("%s: %+v", name, info)
		}
		if name == "argon2027h1" {
			rec.Kind = "" // pinned before A6
			if info, err := InfoFromRecord(rec); err != nil || info.Kind != loglist.KindRFC6962 {
				t.Errorf("a record without kind: %+v, %v", info, err)
			}
			continue
		}
		rec.Origin = "elsewhere.example"
		if _, err := InfoFromRecord(rec); err == nil {
			t.Errorf("%s: a wrong origin was accepted", name)
		}
	}
}
