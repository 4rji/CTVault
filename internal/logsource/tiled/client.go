package tiled

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/4rji/ctvault/internal/logsource"
)

// Body limits (amendment A6 §2.1). A data tile measured 471 KB.
const (
	maxTileBytes  = Width * 32
	maxDataBytes  = 64 << 20
	maxIssuerSize = 1 << 20
)

// Client fetches one tiled log's files under its monitoring prefix.
type Client struct {
	BaseURL   string // the monitoring prefix, ending in "/"
	HTTP      *http.Client
	UserAgent string
}

// NewClient returns a client that never follows redirects: tlog-tiles
// forbids them, so a 3xx is reported like any unexpected status.
func NewClient(baseURL string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	c := *hc
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	return &Client{BaseURL: baseURL, HTTP: &c, UserAgent: "ctvault"}
}

// errNotFound marks a 404, which callers of partial tiles handle.
func notFound(err error) bool {
	var he *logsource.HTTPError
	return errors.As(err, &he) && he.Status == http.StatusNotFound
}

// Get fetches path and returns its body, at most max bytes. A non-200 answer
// is a *logsource.HTTPError; a body cut short or too long is
// logsource.ErrMalformed (spec §5.4: retried, never fatal).
func (c *Client) Get(ctx context.Context, path string, max int) ([]byte, error) {
	u := c.BaseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		he := &logsource.HTTPError{URL: u, Status: resp.StatusCode, Body: strings.TrimSpace(string(snippet))}
		if loc := resp.Header.Get("Location"); loc != "" {
			he.Body = "redirect to " + loc + " (tiled logs must not redirect)"
		}
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s >= 0 {
			he.RetryAfter = time.Duration(s) * time.Second
		}
		return nil, he
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(max)+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: reading body: %w", logsource.ErrMalformed, u, err)
	}
	if len(body) > max {
		return nil, fmt.Errorf("%w: %s: body exceeds %d bytes", logsource.ErrMalformed, u, max)
	}
	return body, nil
}
