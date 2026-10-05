package ingest

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/vault"
)

// TestEngineHookOrder: a clean batch passes every named commit boundary of
// spec §13.5 in protocol order.
func TestEngineHookOrder(t *testing.T) {
	h := newHarness(t, entries(t, 40), ctlogtest.Options{})
	var points []string
	h.opts.Hook = func(p string) {
		if strings.HasPrefix(p, "commit.") {
			points = append(points, p)
		}
	}
	h.ingest(h.open(), h.head(), 0, 40, 40)
	want := []string{commit.HookAfterIntent, HookAfterVaultSync, HookDuringCanary, commit.HookAfterManifest,
		commit.HookBeforeRename, commit.HookAfterRename, HookBeforePebble, HookAfterPebble, commit.HookBeforeIntentDelete}
	if !slices.Equal(points, want) {
		t.Fatalf("hooks %v\nwant %v", points, want)
	}
}

// TestAbandonFailureStopsTheWriter: when an attempt cannot be cleaned up in
// process, the writer refuses every further batch instead of writing over
// a vault in an unknown state; the next start recovers.
func TestAbandonFailureStopsTheWriter(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	h := newHarness(t, entries(t, 40), ctlogtest.Options{})
	intents := filepath.Join(h.root, "state", "intent")
	bctx, cancel := context.WithCancel(ctx)
	h.opts.Hook = func(p string) {
		if p == HookAfterVaultSync {
			os.Chmod(intents, 0o555) // the abandon cannot mark its intent
			cancel()                 // and the batch fails: a second Ctrl-C
		}
	}
	t.Cleanup(func() { os.Chmod(intents, 0o755) })
	w := h.open()
	sth := h.head()
	if _, err := w.Batch(bctx, h.src, sth, 0, 20); !errors.Is(err, ErrAbandonFailed) || !errors.Is(err, context.Canceled) {
		t.Fatalf("the batch error and the failed abandon: %v", err)
	}
	os.Chmod(intents, 0o755)
	requests := h.log.Requests("get-entries")
	if _, err := w.Batch(ctx, h.src, sth, 0, 20); !errors.Is(err, ErrAbandonFailed) {
		t.Fatalf("a writer whose abandon failed must refuse more batches: %v", err)
	}
	if h.log.Requests("get-entries") != requests {
		t.Fatal("the refused batch must not fetch anything")
	}
	w.Close()
	h.opts.Hook = nil
	h.ingest(h.open(), sth, 0, 40, 20)
}

// TestAbandonAfterHardStopSkipsTheWarmUp: an attempt abandoned because the
// process is stopping does not re-read the vault to warm the delta cache;
// the cache is emptied, and warmed again only if another batch runs.
func TestAbandonAfterHardStopSkipsTheWarmUp(t *testing.T) {
	h := newHarness(t, entries(t, 100), ctlogtest.Options{})
	sth := h.head()
	w := h.open()
	h.ingest(w, sth, 0, 51, 51) // ends with the precert of pair 25
	bctx, cancel := context.WithCancel(ctx)
	h.opts.Hook = func(p string) {
		if p == HookAfterVaultSync {
			cancel()
		}
	}
	w.o.Hook = h.opts.Hook
	if _, err := w.Batch(bctx, h.src, sth, 51, 100); !errors.Is(err, context.Canceled) {
		t.Fatalf("the stopped batch: %v", err)
	}
	if !w.cold || w.delta.Len() != 0 {
		t.Fatalf("after a stop the cache is emptied and left cold: cold %v, %d entries", w.cold, w.delta.Len())
	}
	w.o.Hook = nil
	ms := h.ingest(w, sth, 51, 100, 49)
	if ms[0].Counts.DeltaRecords != 25 || w.cold {
		t.Fatalf("the next batch warms the cache first: %d deltas, want 25 (cold %v)", ms[0].Counts.DeltaRecords, w.cold)
	}
}

// TestWriterSpillFolderIsItsOwn: the writer's DuckDB spill folder is
// tmp/duckdb-writer. A killed writer's leftover is emptied at the next
// start (the lock makes it ours), and Close removes it; readers' spill
// folders and other files in tmp/ are never touched (amendment A1 §7).
func TestWriterSpillFolderIsItsOwn(t *testing.T) {
	h := newHarness(t, entries(t, 20), ctlogtest.Options{})
	tmp := filepath.Join(h.root, "tmp")
	for _, f := range []string{"duckdb-writer/leftover.tmp", "duckdb-4242/reader.tmp", "mine.txt"} {
		os.MkdirAll(filepath.Dir(filepath.Join(tmp, f)), 0o755)
		os.WriteFile(filepath.Join(tmp, f), []byte("x"), 0o644)
	}
	w := h.open()
	if _, err := os.Stat(filepath.Join(tmp, "duckdb-writer", "leftover.tmp")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the killed writer's spill file must go: %v", err)
	}
	h.ingest(w, h.head(), 0, 20, 20)
	w.Close()
	var left []string
	filepath.WalkDir(tmp, func(p string, d os.DirEntry, err error) error {
		if err == nil && p != tmp {
			rel, _ := filepath.Rel(tmp, p)
			left = append(left, rel)
		}
		return nil
	})
	want := []string{"duckdb-4242", "duckdb-4242/reader.tmp", "mine.txt", "rebuild", "stage"}
	if !slices.Equal(left, want) {
		t.Fatalf("tmp/ after Close: %v, want %v", left, want)
	}
}

// TestRefetchAfterAFailedCanaryCommits: spec §8.3 P6 retries a batch once.
// The retry must verify: the failed attempt must not have touched the
// committed Merkle tip it started from.
func TestRefetchAfterAFailedCanaryCommits(t *testing.T) {
	h := newHarness(t, entries(t, 80), ctlogtest.Options{})
	sth := h.head()
	w := h.open()
	h.ingest(w, sth, 0, 40, 40)
	start := w.vw.Tail()
	segs, _ := vault.FindSegments(h.vaultDirs())
	fired := false
	h.opts.Hook = func(p string) {
		if p == HookDuringCanary && !fired {
			fired = true // damage every record of this attempt once
			f, _ := os.OpenFile(segs[start.Segment], os.O_RDWR, 0)
			fi, _ := f.Stat()
			f.WriteAt(bytes.Repeat([]byte{0xff}, int(fi.Size())-int(start.Offset)), int64(start.Offset))
			f.Close()
		}
	}
	w.o.Hook = h.opts.Hook
	m, err := w.Batch(ctx, h.src, sth, 40, 80)
	if err != nil || !fired || w.Next("fakelog") != 80 {
		t.Fatalf("the refetched batch must commit: %v (canary failed once: %v)", err, fired)
	}
	if root, _ := m.MerkleAfter.Root(); root != sth.RootHash {
		t.Fatal("the committed batch must verify to the signed root")
	}
}
