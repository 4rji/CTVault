package fetch

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
)

func source(t *testing.T, l *ctlogtest.Log) logsource.LogSource {
	t.Helper()
	pub, err := x509.ParsePKIXPublicKey(l.PublicKeyDER)
	if err != nil {
		t.Fatal(err)
	}
	info := logsource.LogInfo{Name: "fake", LogID: l.LogID, PublicKey: pub, URL: l.URL}
	return rfc6962.NewSource(info, nil, logsource.NewChainCache(logsource.DefaultChainCacheBytes), nil)
}

// fast options for tests: no real waiting between retries.
func fast(o Options) Options {
	o.MaxRPS = 1000
	o.MinBackoff, o.MaxBackoff = time.Millisecond, 5*time.Millisecond
	return o
}

// collect runs a fetch and checks that every entry of [start, end) arrives
// once, in order, with exactly the bytes the log holds.
func collect(t *testing.T, l *ctlogtest.Log, start, end uint64, o Options) Stats {
	t.Helper()
	next := start
	st, err := Run(context.Background(), source(t, l), start, end, o, func(e logsource.RawEntry) error {
		if e.Index != next {
			return fmt.Errorf("got index %d, want %d", e.Index, next)
		}
		if !bytes.Equal(e.LeafInput, l.Entries[e.Index].LeafInput) || !bytes.Equal(e.ExtraData, l.Entries[e.Index].ExtraData) {
			return fmt.Errorf("entry %d: bytes differ from the log", e.Index)
		}
		next++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if next != end || st.Entries != end-start {
		t.Fatalf("released up to %d (%d entries), want %d", next, st.Entries, end)
	}
	return st
}

func TestRunInOrderDespiteOutOfOrderCompletion(t *testing.T) {
	l := ctlogtest.New(t, 300, ctlogtest.Options{PageSize: 8, EntriesDelay: func(start uint64) time.Duration {
		return time.Duration(5-(start/8)%5) * 3 * time.Millisecond // earlier pages finish later
	}})
	st := collect(t, l, 0, 300, fast(Options{Workers: 6, PageSize: 8}))
	if st.Requests != 38 || st.LargestResponse != 8 {
		t.Fatalf("300 entries in pages of 8 take 38 requests of at most 8: %+v", st)
	}
}

func TestRunAlignsRequestsAndRequeuesShortReads(t *testing.T) {
	l := ctlogtest.New(t, 64, ctlogtest.Options{PageSize: 8, ShortReadEvery: 1})
	st := collect(t, l, 5, 40, fast(Options{Workers: 3, PageSize: 8}))
	if st.ShortReads == 0 || st.Requests <= 5 {
		t.Fatalf("every response is halved, so remainders must be refetched: %+v", st)
	}
}

func TestRunRetriesThrottlingAndFraming(t *testing.T) {
	l := ctlogtest.New(t, 200, ctlogtest.Options{PageSize: 8, RateLimitEvery: 3, NoRetryAfter: true,
		ServerErrorEvery: 5, CorruptJSONEvery: 4, InvalidBase64Every: 7})
	st := collect(t, l, 0, 200, fast(Options{Workers: 4, PageSize: 8}))
	if st.RateLimited == 0 || st.ServerErrors == 0 || st.FramingErrors == 0 {
		t.Fatalf("every fault class must have been hit and retried: %+v", st)
	}
	if st.FinalRPS >= 1000 {
		t.Fatalf("throttling must lower the rate: %v", st.FinalRPS)
	}
}

// TestRunRetriesTruncatedBodies: one dropped connection must not end a
// capture or a batch; the request is fetched again.
func TestRunRetriesTruncatedBodies(t *testing.T) {
	l := ctlogtest.New(t, 64, ctlogtest.Options{PageSize: 8, TruncateBodyEvery: 3})
	st := collect(t, l, 0, 64, fast(Options{Workers: 2, PageSize: 8}))
	if st.FramingErrors == 0 {
		t.Fatalf("truncated bodies must have been hit and retried: %+v", st)
	}
	_, err := rfc6962.New(ctlogtest.New(t, 8, ctlogtest.Options{TruncateBodyEvery: 1}).URL, nil).GetEntries(context.Background(), 0, 7)
	if err == nil || !Transient(err) {
		t.Fatalf("Retry must treat a truncated body as transient: %v", err)
	}
}

func TestRetryAfterPausesTheRun(t *testing.T) {
	l := ctlogtest.New(t, 24, ctlogtest.Options{PageSize: 8, RateLimitEvery: 2})
	t0 := time.Now()
	st := collect(t, l, 0, 24, fast(Options{Workers: 3, PageSize: 8}))
	if st.RetryAfterWaits == 0 || time.Since(t0) < time.Second {
		t.Fatalf("Retry-After: 1 must pause the run for a second: %v, %+v", time.Since(t0), st)
	}
}

// TestReorderBufferBounds: with a slow head of line and many workers, the
// buffer stays within its limits and the run still completes.
func TestReorderBufferBounds(t *testing.T) {
	l := ctlogtest.New(t, 256, ctlogtest.Options{PageSize: 4, EntriesDelay: func(start uint64) time.Duration {
		if start%32 == 0 {
			return 20 * time.Millisecond
		}
		return 0
	}})
	entryBytes := len(l.Entries[0].LeafInput) + len(l.Entries[0].ExtraData)
	for name, o := range map[string]Options{
		"entry bound":                   {Workers: 8, PageSize: 4, MaxBufferedEntries: 16},
		"byte bound":                    {Workers: 8, PageSize: 4, MaxBufferedBytes: 10 * entryBytes},
		"byte bound below one response": {Workers: 8, PageSize: 4, MaxBufferedBytes: 1},
	} {
		st := collect(t, l, 0, 256, fast(o))
		o = o.withDefaults()
		maxResponse := 4 * (entryBytes + 64)
		if st.PeakBufEntries > o.MaxBufferedEntries+o.PageSize {
			t.Errorf("%s: %d entries buffered, bound %d + one page", name, st.PeakBufEntries, o.MaxBufferedEntries)
		}
		if st.PeakBufBytes > o.MaxBufferedBytes+o.Workers*maxResponse {
			t.Errorf("%s: %d bytes buffered, bound %d + one response per worker", name, st.PeakBufBytes, o.MaxBufferedBytes)
		}
	}
}

// stub is a LogSource whose Fetch the test controls.
type stub struct {
	logsource.LogSource
	fetch func(ctx context.Context, start, end uint64) ([]logsource.RawEntry, error)
	calls atomic.Int64
}

func (s *stub) Fetch(ctx context.Context, start, end uint64) ([]logsource.RawEntry, error) {
	s.calls.Add(1)
	return s.fetch(ctx, start, end)
}

func entries(start, n uint64) []logsource.RawEntry {
	out := make([]logsource.RawEntry, n)
	for i := range out {
		out[i] = logsource.RawEntry{Index: start + uint64(i), LeafInput: []byte{1}}
	}
	return out
}

func TestStallRule(t *testing.T) {
	s := &stub{fetch: func(ctx context.Context, _, _ uint64) ([]logsource.RawEntry, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	t0 := time.Now()
	_, err := Run(context.Background(), s, 0, 10, fast(Options{StallTimeout: 200 * time.Millisecond}), func(logsource.RawEntry) error { return nil })
	if !errors.Is(err, ErrStalled) || time.Since(t0) > 2*time.Second {
		t.Fatalf("a run with no progress must stall out: %v after %v", err, time.Since(t0))
	}
}

func TestPermanentErrors(t *testing.T) {
	notFound := &stub{fetch: func(context.Context, uint64, uint64) ([]logsource.RawEntry, error) {
		return nil, &rfc6962.HTTPError{Status: 404}
	}}
	if _, err := Run(context.Background(), notFound, 0, 4, fast(Options{Workers: 1}), nil); err == nil || notFound.calls.Load() != maxOtherRetries+1 {
		t.Fatalf("an unexpected status is retried %d times, then fails: %v after %d calls", maxOtherRetries, err, notFound.calls.Load())
	}
	full := &stub{fetch: func(context.Context, uint64, uint64) ([]logsource.RawEntry, error) {
		return nil, logsource.ErrChainCacheFull
	}}
	if _, err := Run(context.Background(), full, 0, 4, fast(Options{Workers: 1}), nil); !errors.Is(err, logsource.ErrChainCacheFull) || full.calls.Load() != 1 {
		t.Fatalf("a local failure is not retried: %v", err)
	}
	ok := &stub{fetch: func(_ context.Context, start, end uint64) ([]logsource.RawEntry, error) {
		return entries(start, end-start), nil
	}}
	boom := errors.New("vault write failed")
	if _, err := Run(context.Background(), ok, 0, 100, fast(Options{}), func(logsource.RawEntry) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("an emit error ends the run: %v", err)
	}
}

// TestMisbehavingSourceIsRetried: wrong indexes or too many entries are
// framing errors; the request is retried and nothing wrong is released.
func TestMisbehavingSourceIsRetried(t *testing.T) {
	var n atomic.Int64
	s := &stub{fetch: func(_ context.Context, start, end uint64) ([]logsource.RawEntry, error) {
		switch n.Add(1) {
		case 1:
			return entries(start+1, end-start), nil // shifted indexes
		case 2:
			return entries(start, end-start+1), nil // one too many
		}
		return entries(start, end-start), nil
	}}
	var got []uint64
	st, err := Run(context.Background(), s, 0, 4, fast(Options{Workers: 1, PageSize: 4}), func(e logsource.RawEntry) error {
		got = append(got, e.Index)
		return nil
	})
	if err != nil || fmt.Sprint(got) != "[0 1 2 3]" || st.FramingErrors != 2 {
		t.Fatalf("got %v, %v, %+v", got, err, st)
	}
}

func TestContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &stub{fetch: func(ctx context.Context, start, end uint64) ([]logsource.RawEntry, error) {
		cancel()
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	if _, err := Run(ctx, s, 0, 8, fast(Options{}), nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation ends the run: %v", err)
	}
}

// fakeClock is a manually advanced clock for the rate controller.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }
func testRun(c *fakeClock, maxRPS float64) *run {
	return &run{opts: Options{MaxRPS: maxRPS}.withDefaults(), rps: maxRPS, now: c.now, lim: newTestLimiter(maxRPS)}
}

func TestRateHalvingAndIncrease(t *testing.T) {
	c := &fakeClock{t: time.Unix(1e9, 0)}
	r := testRun(c, 20)
	r.throttled(0)
	r.throttled(0) // same burst: counts once
	if r.rps != 10 {
		t.Fatalf("a burst of failures halves once: %v", r.rps)
	}
	c.add(decreaseCooldown)
	r.throttled(0)
	if r.rps != 5 {
		t.Fatalf("after the cooldown the next failure halves again: %v", r.rps)
	}
	c.add(time.Second)
	r.success()
	if r.rps != 5 {
		t.Fatalf("no increase within the cooldown: %v", r.rps)
	}
	for range 3 { // 2 s, 3 s and 4 s after the halving
		c.add(time.Second)
		r.success()
		r.success() // a second success in the same second adds nothing
	}
	if r.rps != 8 {
		t.Fatalf("one step per second once the cooldown has passed: %v, want 5+3", r.rps)
	}
	for range 40 {
		c.add(decreaseCooldown)
		r.throttled(0)
	}
	if r.rps != minRPS {
		t.Fatalf("the rate never drops below %v: %v", minRPS, r.rps)
	}
	for range 100 {
		c.add(time.Second)
		r.success()
	}
	if r.rps != 20 {
		t.Fatalf("the rate never exceeds MaxRPS: %v", r.rps)
	}
}

// TestRateSurvivesSparseFailures: requests at the current rate for 10
// minutes, every 50th failing regardless of rate (2%). The rate must stay
// high; halving on every failure would sink to the floor.
func TestRateSurvivesSparseFailures(t *testing.T) {
	c := &fakeClock{t: time.Unix(1e9, 0)}
	r := testRun(c, 20)
	n := 0
	for end := c.t.Add(10 * time.Minute); c.t.Before(end); {
		c.add(time.Duration(float64(time.Second) / r.rps))
		if n++; n%50 == 0 {
			r.throttled(0)
		} else {
			r.success()
		}
	}
	if r.rps < 8 {
		t.Fatalf("2%% independent failures must not collapse the rate: %v requests/s", r.rps)
	}
}

func TestBackoff(t *testing.T) {
	r := testRun(&fakeClock{}, 20)
	for attempt, want := range map[int]time.Duration{1: time.Second, 3: 4 * time.Second, 7: 60 * time.Second, 40: 60 * time.Second} {
		for range 50 {
			if d := r.backoff(attempt); d < want/2 || d > want {
				t.Fatalf("attempt %d: backoff %v outside [%v, %v]", attempt, d, want/2, want)
			}
		}
	}
}
