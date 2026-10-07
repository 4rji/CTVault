package logsource

import (
	"errors"
	"fmt"
	"net/http"
	"time"
)

// The HTTP errors of every LogSource, so the fetcher classifies RFC 6962
// and tiled requests alike (amendment A6 §2.1). The rfc6962 package keeps
// its names for them as aliases.

// ErrRateLimited is matched by an *HTTPError with status 429.
var ErrRateLimited = errors.New("rate limited by log (HTTP 429)")

// ErrMalformed means the log answered 200 with an unusable body.
var ErrMalformed = errors.New("malformed log response")

// HTTPError is a non-200 answer from the log.
type HTTPError struct {
	URL        string
	Status     int
	Body       string
	RetryAfter time.Duration
}

// Error quotes the body, so control characters a server sends (ANSI escapes,
// for example) are shown escaped instead of acting on the terminal (Plan 1
// review, minor 12).
func (e *HTTPError) Error() string {
	return fmt.Sprintf("%s: HTTP %d: %q", e.URL, e.Status, e.Body)
}

func (e *HTTPError) Is(target error) bool {
	return target == ErrRateLimited && e.Status == http.StatusTooManyRequests
}
