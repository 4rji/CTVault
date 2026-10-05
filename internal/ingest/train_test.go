package ingest

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/vault"
)

// TestTrainingWaitsForThePreflight: a batch the disk guard refuses must
// not first spend minutes training, nor write dictionary files.
func TestTrainingWaitsForThePreflight(t *testing.T) {
	h := newHarness(t, entries(t, 100), ctlogtest.Options{})
	h.opts.DictSamples = 20
	calls := 0
	h.opts.Train = func(s [][]byte, id uint64) ([]byte, error) { calls++; return vault.Train(s, id) }
	w := h.open()
	sth := h.head()
	h.ingest(w, sth, 0, 50, 50)
	h.opts.Guard.Stat = func(string) (diskguard.Usage, error) {
		return diskguard.Usage{Total: 100 << 30, Avail: 10 << 30, Dev: 1}, nil // 90% used
	}
	w.o.Guard = h.opts.Guard
	if _, err := w.Batch(ctx, h.src, sth, 50, 100); !errors.Is(err, diskguard.ErrCap) {
		t.Fatalf("the full disk refuses the batch: %v", err)
	}
	if ds, _ := vault.LoadDicts(h.vaultDirs()); calls != 0 || len(ds) != 0 {
		t.Fatalf("a refused batch trained %d times and left %d dictionaries", calls, len(ds))
	}
}

// TestTrainingStopsOnHardStop: training takes minutes; a second Ctrl-C
// must not wait for it. Nothing is written, and a later run trains again.
func TestTrainingStopsOnHardStop(t *testing.T) {
	h := newHarness(t, entries(t, 100), ctlogtest.Options{})
	h.opts.DictSamples = 20
	release := make(chan struct{})
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	var calls atomic.Int32 // trainings run on their own goroutines
	h.opts.Train = func(s [][]byte, id uint64) ([]byte, error) {
		if calls.Add(1) == 1 {
			<-release // a training that would run for minutes
		}
		return vault.Train(s, id)
	}
	w := h.open()
	t.Cleanup(free) // runs before the writer closes
	sth := h.head()
	h.ingest(w, sth, 0, 50, 50)
	bctx, cancel := context.WithCancel(ctx)
	time.AfterFunc(100*time.Millisecond, cancel)
	done := make(chan error, 1)
	go func() {
		_, err := w.Batch(bctx, h.src, sth, 50, 100)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("a hard stop during training: %v", err)
		}
	case <-time.After(10 * time.Second):
		free()
		<-done
		t.Fatal("a hard stop waited for the training to finish")
	}
	free()
	if in, _ := commit.ReadIntents(commit.Paths{Root: h.root}); len(in) != 0 {
		t.Fatal("training comes before the intent: nothing to abandon")
	}
	m, err := w.Batch(ctx, h.src, sth, 50, 100)
	if err != nil || m.Dictionary.ID != 1 || calls.Load() != 2 {
		t.Fatalf("the next batch trains again: %v, dictionary %d, %d calls", err, m.Dictionary.ID, calls.Load())
	}
}

// TestCanarySamplesTheWholeBatch: the vault records the canary reads are a
// uniform sample of the batch, not its first few thousand.
func TestCanarySamplesTheWholeBatch(t *testing.T) {
	r := newReservoir(100, 1, 2)
	for i := range 10000 {
		r.add(sample{loc: vault.Loc{Offset: uint64(i)}})
	}
	late := 0
	for _, s := range r.items {
		if s.loc.Offset >= 5000 {
			late++
		}
	}
	if len(r.items) != 100 || late < 30 || late > 70 {
		t.Fatalf("%d samples, %d from the batch's second half; want 100 and about 50", len(r.items), late)
	}
}

// TestViewsAreRewrittenAfterTheFirstCommit: views.sql changes from the
// empty form to the committed one as soon as a batch commits.
func TestViewsAreRewrittenAfterTheFirstCommit(t *testing.T) {
	h := newHarness(t, entries(t, 20), ctlogtest.Options{})
	w := h.open()
	read := func() string {
		b, _ := os.ReadFile(filepath.Join(h.root, dataset.ViewsFile))
		return string(b)
	}
	if !strings.Contains(read(), "WHERE false") {
		t.Fatal("a new vault has the empty views")
	}
	h.ingest(w, h.head(), 0, 20, 20)
	if !strings.Contains(read(), "read_parquet") {
		t.Fatalf("after the first commit views.sql reads the batches:\n%s", read())
	}
}
