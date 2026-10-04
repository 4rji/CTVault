package fetch

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"time"

	"github.com/4rji/ctvault/internal/logsource/rfc6962"
)

// Transient reports whether err is worth retrying: HTTP 429 or 5xx, a
// malformed response, or a network error.
func Transient(err error) bool {
	var he *rfc6962.HTTPError
	var ne net.Error
	switch {
	case errors.As(err, &he):
		return he.Status == 429 || he.Status >= 500
	case errors.Is(err, rfc6962.ErrMalformed), errors.As(err, &ne):
		return true
	}
	return false
}

// Retry runs fn until it succeeds, with the fetcher's backoff, for single
// requests such as proofs. Transient errors are retried until StallTimeout
// has passed since the first attempt; other HTTP statuses are retried
// maxOtherRetries times; anything else is returned at once. A Retry-After
// longer than the backoff is honoured.
func Retry(ctx context.Context, o Options, fn func(context.Context) error) error {
	o = o.withDefaults()
	deadline := time.Now().Add(o.StallTimeout)
	for attempt := 1; ; attempt++ {
		err := fn(ctx)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var he *rfc6962.HTTPError
		other := errors.As(err, &he) && !Transient(err)
		if (!Transient(err) && !other) || (other && attempt > maxOtherRetries) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%w: %v", ErrStalled, err)
		}
		d := min(o.MinBackoff<<min(attempt-1, 30), o.MaxBackoff)
		if d <= 0 {
			d = o.MaxBackoff
		}
		d = d/2 + rand.N(d/2+1)
		if he != nil && he.RetryAfter > d {
			d = he.RetryAfter
		}
		if err := sleep(ctx, d); err != nil {
			return err
		}
	}
}
