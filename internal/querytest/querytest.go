// Package querytest builds small vaults with the production writer, for the
// read path's tests (query and explore). It is test infrastructure:
// production binaries never import it.
package querytest

import (
	"context"
	"crypto/x509"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/ingest"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
)

// Vault is a vault written by the production writer from a fake log.
type Vault struct {
	Root    string
	Dirs    []string
	Gen     *ctlogtest.Generator
	Entries []ctlogtest.Entry
}

// FreeDisk reports a disk with plenty of room.
func FreeDisk(string) (diskguard.Usage, error) {
	return diskguard.Usage{Total: 1 << 40, Avail: 1 << 39, Dev: 1}, nil
}

// Guard is a disk guard over FreeDisk.
var Guard = diskguard.Guard{Cap: 0.85, Stat: FreeDisk}

// HostName is the name of the i-th issuance's certificates.
func HostName(i int) string { return "host" + strconv.Itoa(i) + ".example.test" }

// Pairs makes n entries: precert and final pairs issued directly by the CA,
// and every third pair's precert issued by the Precertificate Signing
// Certificate, so two issuers appear.
func Pairs(t testing.TB, n int) (*ctlogtest.Generator, []ctlogtest.Entry) {
	t.Helper()
	g, err := ctlogtest.NewGenerator()
	if err != nil {
		t.Fatal(err)
	}
	var es []ctlogtest.Entry
	for i := 0; len(es) < n; i++ {
		pair := g.Pair
		if i%3 == 2 {
			pair = g.PairViaSigner
		}
		pre, fin, err := pair(HostName(i), 1790000000000+uint64(i)*2000)
		if err != nil {
			t.Fatal(err)
		}
		es = append(es, pre)
		if len(es) < n {
			es = append(es, fin)
		}
	}
	return g, es
}

// New ingests es in batches of size into a new vault, with a delta cache
// of lru entries.
func New(t testing.TB, g *ctlogtest.Generator, es []ctlogtest.Entry, size uint64, lru int) *Vault {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	for _, d := range []string{"state/intent", "state/incidents", "state/logs", "vault/segments", "vault/dict", "dataset", "tmp/stage", "tmp/rebuild"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	v := &Vault{Root: root, Dirs: []string{filepath.Join(root, "vault")}, Gen: g, Entries: es}
	l := ctlogtest.NewWithEntries(t, es, ctlogtest.Options{})
	pub, err := x509.ParsePKIXPublicKey(l.PublicKeyDER)
	if err != nil {
		t.Fatal(err)
	}
	chains := logsource.NewChainCache(logsource.DefaultChainCacheBytes)
	src := rfc6962.NewSource(logsource.LogInfo{Name: "fakelog", LogID: l.LogID, PublicKey: pub, URL: l.URL}, nil, chains, nil)
	cfg := config.Default()
	cfg.Ingest.DeltaLRUEntries = lru
	cfg.Vault.SegmentSize = 64 << 10
	w, err := ingest.Open(ingest.Options{Root: root, VaultDirs: v.Dirs, Config: cfg, Guard: Guard,
		Version: "test", Out: io.Discard, DictSamples: 1 << 30, CanarySamples: 16,
		Fetch: fetch.Options{MaxRPS: 1000, MinBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond},
		Now:   func() time.Time { return time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	sth, err := src.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for first := uint64(0); first < uint64(len(es)); first += size {
		if _, err := w.Batch(ctx, src, sth, first, min(first+size, uint64(len(es)))); err != nil {
			t.Fatal(err)
		}
		chains.Reset()
	}
	return v
}
