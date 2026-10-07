// Package querytest builds small vaults with the production writer, for the
// read path's tests (query and explore). It is test infrastructure:
// production binaries never import it.
package querytest

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/ingest"
	"github.com/4rji/ctvault/internal/logreg"
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
	v, _ := NewPublished(t, g, es, len(es), size, lru)
	return v
}

// NewPublished is New with the fake log publishing only its first n
// entries, which are ingested; the log is returned so that a test can
// publish more and Ingest them.
func NewPublished(t testing.TB, g *ctlogtest.Generator, es []ctlogtest.Entry, n int, size uint64, lru int) (*Vault, *ctlogtest.Log) {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"state/intent", "state/incidents", "state/logs", "vault/segments", "vault/dict", "dataset", "tmp/stage", "tmp/rebuild"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	v := &Vault{Root: root, Dirs: []string{filepath.Join(root, "vault")}, Gen: g, Entries: es}
	l := ctlogtest.NewWithEntries(t, es, ctlogtest.Options{})
	l.Publish(uint64(n))
	// Pinned as `logs add` pins a log, so verify can check signed heads.
	if err := logreg.Add(root, logreg.Record{Name: "fakelog", URL: l.URL, LogID: base64.StdEncoding.EncodeToString(l.LogID[:]),
		Key: base64.StdEncoding.EncodeToString(l.PublicKeyDER), State: "usable"}); err != nil {
		t.Fatal(err)
	}
	Ingest(t, v, l, size, lru, nil)
	return v, l
}

// Ingest commits the log's published entries past the vault's end in
// batches of size, as update does, calling each after every batch.
func Ingest(t testing.TB, v *Vault, l *ctlogtest.Log, size uint64, lru int, each func(commit.Manifest)) {
	t.Helper()
	ctx := context.Background()
	pub, err := x509.ParsePKIXPublicKey(l.PublicKeyDER)
	if err != nil {
		t.Fatal(err)
	}
	chains := logsource.NewChainCache(logsource.DefaultChainCacheBytes)
	src := rfc6962.NewSource(logsource.LogInfo{Name: "fakelog", LogID: l.LogID, PublicKey: pub, URL: l.URL}, nil, chains, nil)
	w := Open(t, v, lru)
	defer w.Close()
	sth, err := src.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for first := w.Next("fakelog"); first < sth.TreeSize; first += size {
		m, err := w.Batch(ctx, src, sth, first, min(first+size, sth.TreeSize))
		if err != nil {
			t.Fatal(err)
		}
		chains.Reset()
		if each != nil {
			each(m)
		}
	}
}

// Options are the writer options of every test vault, with a delta cache
// of lru entries.
func Options(v *Vault, lru int) ingest.Options {
	cfg := config.Default()
	cfg.Ingest.DeltaLRUEntries = lru
	cfg.Vault.SegmentSize = 64 << 10
	return ingest.Options{Root: v.Root, VaultDirs: v.Dirs, Config: cfg, Guard: Guard,
		Version: "test", Out: io.Discard, DictSamples: 1 << 30, CanarySamples: 16,
		Fetch: fetch.Options{MaxRPS: 1000, MinBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond},
		Now:   func() time.Time { return time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC) }}
}

// Open opens the vault's writer, as update and rebuild do: recovery runs.
// The caller closes it.
func Open(t testing.TB, v *Vault, lru int) *ingest.Writer {
	t.Helper()
	w, err := ingest.Open(Options(v, lru))
	if err != nil {
		t.Fatal(err)
	}
	return w
}
