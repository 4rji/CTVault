// Package fetch reads an index range from a LogSource with a pool of workers
// and hands the entries to the caller strictly in index order (spec §5.3,
// amendment A1 §4).
//
//   - Requests are aligned to the log's page size. A short response answers
//     only its own request; the rest of that request is queued again.
//   - One token bucket, capped at MaxRPS, paces every request. A 429 or 5xx
//     halves the rate, at most once per 2 s so that one burst of failures
//     from parallel workers counts once; Retry-After pauses all workers.
//     Sustained success (2 s without a halving) raises the rate by 1 request
//     per second, every second. Halving on every failure instead collapses to
//     the floor when even 2% of requests fail independently of the rate.
//   - A failed request retries with exponential backoff and jitter, from
//     MinBackoff up to MaxBackoff. Transport and framing errors retry too:
//     nothing advances until the exact bytes are known.
//   - The reorder buffer is bounded by entry count and by bytes. Workers pause
//     when either limit is reached, except for the request that fills the gap
//     at the head of the line, which is always admitted, so the buffer can
//     never deadlock. Responses already in flight still land, so the byte
//     bound can be exceeded by at most one response per worker.
//   - If no entry is released for StallTimeout, the run fails with ErrStalled.
package fetch

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
)

// ErrStalled means no entry was released for Options.StallTimeout.
var ErrStalled = errors.New("fetch: no progress within the stall timeout")

// Options tunes a run. Zero values take the defaults noted.
type Options struct {
	Workers            int           // default 4 (ingest.workers)
	MaxRPS             float64       // default 20 (ingest.max_rps)
	PageSize           int           // default 32, Argon's get-entries page
	MaxBufferedEntries int           // default 65,536 (fetch.max_buffered_entries)
	MaxBufferedBytes   int           // default 256 MiB (fetch.max_buffered_bytes)
	StallTimeout       time.Duration // default 15m (ingest.stall_timeout)
	MinBackoff         time.Duration // default 1s
	MaxBackoff         time.Duration // default 60s
}

func (o Options) withDefaults() Options {
	def := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&o.Workers, 4)
	def(&o.PageSize, 32)
	def(&o.MaxBufferedEntries, 65536)
	def(&o.MaxBufferedBytes, 256<<20)
	if o.MaxRPS <= 0 {
		o.MaxRPS = 20
	}
	if o.StallTimeout <= 0 {
		o.StallTimeout = 15 * time.Minute
	}
	if o.MinBackoff <= 0 {
		o.MinBackoff = time.Second
	}
	if o.MaxBackoff < o.MinBackoff {
		o.MaxBackoff = max(60*time.Second, o.MinBackoff)
	}
	return o
}

// Stats describes a run. The high-water marks show the buffer bounds held.
type Stats struct {
	Requests        int64   // get-entries requests sent
	Entries         uint64  // entries released in order
	ShortReads      int64   // responses with fewer entries than requested
	RateLimited     int64   // HTTP 429
	ServerErrors    int64   // HTTP 5xx
	FramingErrors   int64   // malformed responses (spec §5.4), retried
	NetworkErrors   int64   // timeouts, resets and the like, retried
	OtherErrors     int64   // other HTTP statuses, retried a few times
	FinalRPS        float64 // the token bucket's rate at the end
	PeakBufEntries  int     // most entries held in the reorder buffer at once
	PeakBufBytes    int     // most bytes held in the reorder buffer at once
	RetryAfterWaits int64   // pauses imposed by Retry-After
	LargestResponse int     // most entries one get-entries response carried: the log's page size
}

// maxOtherRetries bounds retries of unexpected HTTP statuses (400, 404, ...),
// which a correct request below the pinned head should never get.
const maxOtherRetries = 3

// Rate control: halve on throttling at most once per decreaseCooldown; once
// that long has passed since the last halving, add increaseStep every
// increaseEvery; never go below minRPS.
const (
	decreaseCooldown = 2 * time.Second
	increaseEvery    = time.Second
	increaseStep     = 1.0
	minRPS           = 0.25
)

type task struct {
	start, end uint64
	attempt    int
}

type run struct {
	src  logsource.LogSource
	opts Options
	end  uint64

	mu       sync.Mutex
	cond     *sync.Cond
	pending  []task // sorted by start
	buf      map[uint64][]logsource.RawEntry
	bufN     int
	bufBytes int
	next     uint64
	err      error
	progress time.Time

	now          func() time.Time
	lim          *rate.Limiter
	rps          float64
	lastDecrease time.Time
	lastIncrease time.Time
	pauseUntil   time.Time

	stats Stats
}

// Run fetches [start, end) and calls emit for every entry in index order, in
// the calling goroutine. It returns when the range is done, emit fails, the
// context ends, a request fails permanently, or the run stalls.
func Run(ctx context.Context, src logsource.LogSource, start, end uint64, opts Options, emit func(logsource.RawEntry) error) (Stats, error) {
	opts = opts.withDefaults()
	r := &run{src: src, opts: opts, end: end, buf: map[uint64][]logsource.RawEntry{}, next: start,
		progress: time.Now(), now: time.Now, rps: opts.MaxRPS, lim: rate.NewLimiter(rate.Limit(opts.MaxRPS), 1)}
	r.cond = sync.NewCond(&r.mu)
	page := uint64(opts.PageSize)
	for a := start; a < end; {
		b := min(end, (a/page+1)*page) // align to absolute page boundaries
		r.pending = append(r.pending, task{start: a, end: b})
		a = b
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // wake everyone on cancellation, and enforce the stall rule
		defer wg.Done()
		tick := time.NewTicker(min(time.Second, opts.StallTimeout/4))
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				r.fail(ctx.Err())
				return
			case <-tick.C:
				r.mu.Lock()
				stalled := time.Since(r.progress) > opts.StallTimeout
				r.mu.Unlock()
				if stalled {
					r.fail(fmt.Errorf("%w (%v; next index %d)", ErrStalled, opts.StallTimeout, r.nextIndex()))
				}
			}
		}
	}()
	for range opts.Workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.worker(ctx)
		}()
	}

	err := r.consume(emit)
	cancel()
	wg.Wait()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stats.FinalRPS = r.rps
	return r.stats, err
}

func (r *run) nextIndex() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.next
}

// fail records the first fatal error and wakes every waiter.
func (r *run) fail(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err == nil {
		r.err = err
	}
	r.cond.Broadcast()
}

// consume releases entries in index order.
func (r *run) consume(emit func(logsource.RawEntry) error) error {
	for {
		r.mu.Lock()
		for r.err == nil && r.next < r.end && r.buf[r.next] == nil {
			r.cond.Wait()
		}
		if r.err != nil {
			err := r.err
			r.mu.Unlock()
			return err
		}
		if r.next >= r.end {
			r.mu.Unlock()
			return nil
		}
		chunk := r.buf[r.next]
		delete(r.buf, r.next)
		r.bufN -= len(chunk)
		for i := range chunk {
			r.bufBytes -= chunk[i].Size()
		}
		r.next += uint64(len(chunk))
		r.progress = time.Now()
		r.stats.Entries += uint64(len(chunk))
		r.cond.Broadcast()
		r.mu.Unlock()
		for _, e := range chunk {
			if err := emit(e); err != nil {
				r.fail(err)
				return err
			}
		}
	}
}

// take waits for the lowest pending task that the buffer bounds admit.
func (r *run) take() (task, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for {
		if r.err != nil {
			return task{}, false
		}
		if len(r.pending) > 0 {
			t := r.pending[0]
			headOfLine := t.start == r.next
			fits := t.start-r.next < uint64(r.opts.MaxBufferedEntries) && r.bufBytes < r.opts.MaxBufferedBytes
			if headOfLine || fits {
				r.pending = r.pending[1:]
				return t, true
			}
		} else if r.next >= r.end {
			return task{}, false
		}
		r.cond.Wait()
	}
}

func (r *run) requeue(t task) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := sort.Search(len(r.pending), func(i int) bool { return r.pending[i].start >= t.start })
	r.pending = append(r.pending, task{})
	copy(r.pending[i+1:], r.pending[i:])
	r.pending[i] = t
	r.cond.Broadcast()
}

func (r *run) worker(ctx context.Context) {
	for {
		t, ok := r.take()
		if !ok {
			return
		}
		if err := r.pace(ctx); err != nil {
			r.fail(err)
			return
		}
		atomic.AddInt64(&r.stats.Requests, 1)
		entries, err := r.src.Fetch(ctx, t.start, t.end)
		if err == nil {
			err = r.deliver(t, entries)
		}
		if err == nil {
			continue
		}
		if ctx.Err() != nil {
			r.fail(ctx.Err())
			return
		}
		if !r.retryable(err, t) {
			r.fail(fmt.Errorf("fetch [%d, %d): %w", t.start, t.end, err))
			return
		}
		t.attempt++
		if err := sleep(ctx, r.backoff(t.attempt)); err != nil {
			r.fail(err)
			return
		}
		r.requeue(t)
	}
}

// deliver buffers a response and queues the unanswered rest of the request.
func (r *run) deliver(t task, entries []logsource.RawEntry) error {
	n := uint64(len(entries))
	if n == 0 || n > t.end-t.start {
		return fmt.Errorf("%w: %d entries for a request of %d", rfc6962.ErrMalformed, n, t.end-t.start)
	}
	for i := range entries {
		if entries[i].Index != t.start+uint64(i) {
			return fmt.Errorf("%w: entry %d carries index %d", rfc6962.ErrMalformed, t.start+uint64(i), entries[i].Index)
		}
	}
	r.success()
	r.mu.Lock()
	r.buf[t.start] = entries
	r.bufN += len(entries)
	for i := range entries {
		r.bufBytes += entries[i].Size()
	}
	r.stats.PeakBufEntries = max(r.stats.PeakBufEntries, r.bufN)
	r.stats.PeakBufBytes = max(r.stats.PeakBufBytes, r.bufBytes)
	r.stats.LargestResponse = max(r.stats.LargestResponse, len(entries))
	r.cond.Broadcast()
	r.mu.Unlock()
	if t.start+n < t.end {
		atomic.AddInt64(&r.stats.ShortReads, 1)
		r.requeue(task{start: t.start + n, end: t.end})
	}
	return nil
}

// retryable classifies an error and adjusts the rate. Context errors and
// local failures (a full chain cache) are permanent.
func (r *run) retryable(err error, t task) bool {
	var he *rfc6962.HTTPError
	var ne net.Error
	switch {
	case errors.As(err, &he) && (he.Status == 429 || he.Status >= 500):
		if he.Status == 429 {
			atomic.AddInt64(&r.stats.RateLimited, 1)
		} else {
			atomic.AddInt64(&r.stats.ServerErrors, 1)
		}
		r.throttled(he.RetryAfter)
		return true
	case errors.As(err, &he):
		atomic.AddInt64(&r.stats.OtherErrors, 1)
		return t.attempt < maxOtherRetries
	case errors.Is(err, rfc6962.ErrMalformed):
		atomic.AddInt64(&r.stats.FramingErrors, 1)
		return true
	case errors.As(err, &ne):
		atomic.AddInt64(&r.stats.NetworkErrors, 1)
		return true
	}
	return false
}

// pace waits for any Retry-After pause, then for a token.
func (r *run) pace(ctx context.Context) error {
	r.mu.Lock()
	wait := time.Until(r.pauseUntil)
	r.mu.Unlock()
	if wait > 0 {
		if err := sleep(ctx, wait); err != nil {
			return err
		}
	}
	return r.lim.Wait(ctx)
}

func (r *run) success() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if r.rps < r.opts.MaxRPS && now.Sub(r.lastDecrease) >= decreaseCooldown && now.Sub(r.lastIncrease) >= increaseEvery {
		r.rps = min(r.opts.MaxRPS, r.rps+increaseStep)
		r.lim.SetLimit(rate.Limit(r.rps))
		r.lastIncrease = now
	}
}

func (r *run) throttled(retryAfter time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if now.Sub(r.lastDecrease) >= decreaseCooldown {
		r.rps = max(minRPS, r.rps/2)
		r.lim.SetLimit(rate.Limit(r.rps))
		r.lastDecrease = now
	}
	if retryAfter > 0 {
		r.stats.RetryAfterWaits++
		if until := now.Add(retryAfter); until.After(r.pauseUntil) {
			r.pauseUntil = until
		}
	}
}

// backoff is MinBackoff × 2^(attempt−1), capped at MaxBackoff, with jitter
// drawn from the upper half of the interval.
func (r *run) backoff(attempt int) time.Duration {
	d := r.opts.MinBackoff << min(attempt-1, 30)
	if d <= 0 || d > r.opts.MaxBackoff {
		d = r.opts.MaxBackoff
	}
	return d/2 + rand.N(d/2+1)
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
