package fetch

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/logsource/rfc6962"
)

func TestRetry(t *testing.T) {
	o := fast(Options{StallTimeout: time.Second})
	n := 0
	err := Retry(context.Background(), o, func(context.Context) error {
		if n++; n < 4 {
			return []error{&rfc6962.HTTPError{Status: 429}, &rfc6962.HTTPError{Status: 503}, rfc6962.ErrMalformed}[n-1]
		}
		return nil
	})
	if err != nil || n != 4 {
		t.Fatalf("transient errors are retried: %v after %d calls", err, n)
	}
	n = 0
	err = Retry(context.Background(), o, func(context.Context) error { n++; return &rfc6962.HTTPError{Status: 400} })
	if err == nil || n != maxOtherRetries+1 {
		t.Fatalf("other statuses get %d retries: %v after %d calls", maxOtherRetries, err, n)
	}
	boom := errors.New("local failure")
	n = 0
	if err := Retry(context.Background(), o, func(context.Context) error { n++; return boom }); !errors.Is(err, boom) || n != 1 {
		t.Fatalf("local errors are not retried: %v", err)
	}
	short := fast(Options{StallTimeout: 50 * time.Millisecond})
	if err := Retry(context.Background(), short, func(context.Context) error { return &rfc6962.HTTPError{Status: 503} }); !errors.Is(err, ErrStalled) {
		t.Fatalf("endless transient errors stall out: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Retry(ctx, o, func(context.Context) error { return &rfc6962.HTTPError{Status: 503} }); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation ends retries: %v", err)
	}
}

func TestRetryHonoursRetryAfter(t *testing.T) {
	n := 0
	t0 := time.Now()
	err := Retry(context.Background(), fast(Options{}), func(context.Context) error {
		if n++; n == 1 {
			return &rfc6962.HTTPError{Status: 429, RetryAfter: 300 * time.Millisecond}
		}
		return nil
	})
	if err != nil || time.Since(t0) < 300*time.Millisecond {
		t.Fatalf("Retry-After must be waited out: %v after %v", err, time.Since(t0))
	}
}
