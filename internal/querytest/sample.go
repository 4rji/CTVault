package querytest

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/ingest"
	"github.com/4rji/ctvault/internal/logreg"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/sample"
)

// FromSample ingests a captured sample's entries [0, n) in batches of size
// into a new vault, replayed over loopback through the production client
// and writer, as the real-data tests do.
func FromSample(t testing.TB, s *sample.Sample, n, size uint64) *Vault {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	for _, d := range []string{"state/intent", "state/incidents", "state/logs", "vault/segments", "vault/dict", "dataset", "tmp/stage", "tmp/rebuild"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	v := &Vault{Root: root, Dirs: []string{filepath.Join(root, "vault")}}
	url, stop, err := sample.Serve(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if err := logreg.Add(root, logreg.Record{Name: s.Manifest.Log.Name, URL: url, LogID: s.Manifest.Log.LogID, Key: s.Manifest.Log.Key,
		State: "usable"}); err != nil {
		t.Fatal(err)
	}
	chains := logsource.NewChainCache(logsource.DefaultChainCacheBytes)
	src := rfc6962.NewSource(s.LogInfo(url), nil, chains, nil)
	head, err := src.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	w, err := ingest.Open(ingest.Options{Root: root, VaultDirs: v.Dirs, Config: config.Default(), Guard: Guard, Version: "test", Out: io.Discard,
		Fetch: fetch.Options{MaxRPS: 1000, PageSize: s.Manifest.PageSize, MinBackoff: time.Millisecond, MaxBackoff: 10 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for first := uint64(0); first < n; first += size {
		if _, err := w.Batch(ctx, src, head, first, min(first+size, n)); err != nil {
			t.Fatalf("batch at %d: %v", first, err)
		}
		chains.Reset()
	}
	return v
}
