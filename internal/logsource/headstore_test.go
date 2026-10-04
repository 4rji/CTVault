package logsource_test

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
)

func info(t *testing.T, l *ctlogtest.Log) logsource.LogInfo {
	t.Helper()
	pub, err := x509.ParsePKIXPublicKey(l.PublicKeyDER)
	if err != nil {
		t.Fatal(err)
	}
	return logsource.LogInfo{Name: "fakelog", LogID: l.LogID, PublicKey: pub, URL: l.URL}
}

func TestHeadStore(t *testing.T) {
	l := ctlogtest.New(t, 10, ctlogtest.Options{})
	in := info(t, l)
	state := t.TempDir()
	if h, err := logsource.LoadHead(state, "fakelog", in); err != nil || h != nil {
		t.Fatalf("no stored head yet: %v %v", h, err)
	}
	h, err := rfc6962.NewSource(in, nil, logsource.NewChainCache(1<<20), nil).Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := logsource.SaveHead(state, "fakelog", h, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	got, err := logsource.LoadHead(state, "fakelog", in)
	if err != nil || got.TreeSize != 10 || got.RootHash != h.RootHash || string(got.Raw) != string(h.Raw) {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	other := info(t, ctlogtest.New(t, 1, ctlogtest.Options{}))
	if _, err := logsource.LoadHead(state, "fakelog", other); !errors.Is(err, logsource.ErrBadHeadFile) {
		t.Fatalf("a head that does not verify with the pinned key is refused: %v", err)
	}
	os.WriteFile(filepath.Join(state, logsource.HeadsDir, "fakelog.json"), []byte("{"), 0o644)
	if _, err := logsource.LoadHead(state, "fakelog", in); !errors.Is(err, logsource.ErrBadHeadFile) {
		t.Fatalf("an unreadable head file is refused: %v", err)
	}
}
