package powerloss

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/derivetest"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/ingest"
	"github.com/4rji/ctvault/internal/logreg"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/vault"
)

// The workload's sizes (amendment A5 §14): small on purpose, so a few
// hundred flush points fit in about a MiB of writes.
const (
	ingestEntries  = 480
	upgradeEntries = 80
	batchSize      = 40
)

// vaultUUID is the workload vault's identity in its segment headers.
var vaultUUID = [16]byte{0x70, 0x6c, 0x6f, 0x73, 0x73}

// WriterOptions are the workload's writer options for a vault at root:
// 16 KiB segments and a small dictionary sample, so it trains and rolls
// over; free disk, so the small filesystem never trips the guard.
func WriterOptions(root string) ingest.Options {
	cfg := config.Default()
	cfg.Ingest.DeltaLRUEntries = 1000
	cfg.Vault.SegmentSize = 16 << 10
	free := func(string) (diskguard.Usage, error) {
		return diskguard.Usage{Total: 1 << 40, Avail: 1 << 39, Dev: 1}, nil
	}
	return ingest.Options{Root: root, VaultDirs: []string{filepath.Join(root, "vault")}, VaultUUID: vaultUUID, Config: cfg,
		Guard: diskguard.Guard{Cap: 0.85, Stat: free}, Version: "powerloss", Out: io.Discard,
		DictSamples: 60, CanarySamples: 16,
		Fetch: fetch.Options{MaxRPS: 1000, MinBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond}}
}

// Result is what the workload committed.
type Result struct {
	Batches   int
	Committed []string // batch IDs, sorted
}

// Workload runs amendment A5 §14's phases on a fresh vault at root, calling
// mark before each ("setup", "ingest", "upgrade", "gc", "reindex") and at
// the end ("end"): ingest from an in-process fake log; an upgrade to the test certs
// v2, with two batches built both ways and turns until the switch; gc;
// repair --reindex. It drives the writer in-process.
func Workload(t testing.TB, root string, mark func(phase string) error) (*Result, error) {
	ctx := context.Background()
	// Setup is init's work, not the commit protocol: its points are not
	// checked (amendment A5 §14), and it ends with the folders durable.
	if err := mark("setup"); err != nil {
		return nil, err
	}
	for _, d := range []string{"state/intent", "state/incidents", "state/logs", "vault/segments", "vault/dict", "dataset", "tmp/stage", "tmp/rebuild"} {
		if err := fsutil.MkdirAllSync(filepath.Join(root, d), 0o755); err != nil {
			return nil, err
		}
	}
	l := ctlogtest.New(t, ingestEntries+upgradeEntries, ctlogtest.Options{})
	pub, err := x509.ParsePKIXPublicKey(l.PublicKeyDER)
	if err != nil {
		return nil, err
	}
	// Pinned as `logs add` pins a log, so verify can check signed heads.
	if err := logreg.Add(root, logreg.Record{Name: "fakelog", URL: l.URL, LogID: base64.StdEncoding.EncodeToString(l.LogID[:]),
		Key: base64.StdEncoding.EncodeToString(l.PublicKeyDER), State: "usable"}); err != nil {
		return nil, err
	}
	if err := fsutil.SyncDir(filepath.Join(root, "state", "logs")); err != nil {
		return nil, err
	}
	chains := logsource.NewChainCache(logsource.DefaultChainCacheBytes)
	src := rfc6962.NewSource(logsource.LogInfo{Name: "fakelog", LogID: sha256.Sum256(l.PublicKeyDER), PublicKey: pub, URL: l.URL}, nil, chains, nil)
	o := WriterOptions(root)
	ingestTo := func(w *ingest.Writer, to uint64, turns bool) error {
		l.Publish(to)
		sth, err := src.Head(ctx)
		if err != nil {
			return err
		}
		for first := w.Next("fakelog"); first < to; first += batchSize {
			if _, err := w.Batch(ctx, src, sth, first, min(first+batchSize, to)); err != nil {
				return fmt.Errorf("batch at %d: %w", first, err)
			}
			chains.Reset()
			if turns { // as update does during a transition (amendment A5 §8)
				if _, _, err := w.RebuildTurn(ctx, 1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	phase := func(name string, fn func() error) error {
		if err := mark(name); err != nil {
			return err
		}
		if err := fn(); err != nil {
			return fmt.Errorf("phase %s: %w", name, err)
		}
		return nil
	}
	withWriter := func(fn func(w *ingest.Writer) error) error {
		w, err := ingest.Open(o)
		if err != nil {
			return err
		}
		if err := fn(w); err != nil {
			w.Close()
			return err
		}
		return w.Close()
	}

	err = phase("ingest", func() error {
		return withWriter(func(w *ingest.Writer) error { return ingestTo(w, ingestEntries, false) })
	})
	if err == nil {
		err = phase("upgrade", func() error {
			derivetest.Use(t, "v2")
			return withWriter(func(w *ingest.Writer) error {
				if err := ingestTo(w, ingestEntries+upgradeEntries, true); err != nil {
					return err
				}
				_, err := w.Rebuild(ctx)
				return err
			})
		})
	}
	if err == nil {
		err = phase("gc", func() error {
			return withWriter(func(w *ingest.Writer) error {
				_, err := w.RetireOld(true)
				return err
			})
		})
	}
	if err == nil {
		err = phase("reindex", func() error { return reindex(o) })
	}
	if err == nil {
		err = mark("end")
	}
	if err != nil {
		return nil, err
	}
	ms, err := commit.ListCommitted(root)
	if err != nil {
		return nil, err
	}
	res := &Result{Batches: len(ms)}
	for _, m := range ms {
		res.Committed = append(res.Committed, m.BatchID)
	}
	return res, nil
}

// reindex is repair --reindex, as the CLI runs it: no recovery, the
// writer's spill folder for the stager.
func reindex(o ingest.Options) error {
	codec, err := vault.NewCodec()
	if err != nil {
		return err
	}
	defer codec.Close()
	dicts, err := vault.LoadDicts(o.VaultDirs)
	if err != nil {
		return err
	}
	for _, d := range dicts {
		if err := codec.AddDict(d.Manifest.ID, d.Content); err != nil {
			return err
		}
	}
	spill := filepath.Join(o.Root, "tmp", ingest.WriterSpillDir)
	stager, err := dataset.NewStager(dataset.Options{TempDir: spill, MaxTempBytes: 1 << 30})
	if err != nil {
		return err
	}
	defer func() {
		stager.Close()
		os.RemoveAll(spill)
	}()
	_, err = commit.Reindex(commit.ReindexOptions{Paths: commit.Paths{Root: o.Root}, VaultDirs: o.VaultDirs, Codec: codec, ChainIDs: stager.ChainIDs})
	return err
}
