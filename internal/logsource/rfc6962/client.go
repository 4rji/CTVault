// Package rfc6962 is CTVault's HTTP client for RFC 6962 logs. Plan 1 covers
// get-sth and get-sth-consistency; get-entries and the LogSource adapter
// arrive in Plan 2.
package rfc6962

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/4rji/ctvault/internal/merkle"
)

// maxBody bounds response bodies; a full get-entries page is well under this.
const maxBody = 16 << 20

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

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%s: HTTP %d: %s", e.URL, e.Status, e.Body)
}

func (e *HTTPError) Is(target error) bool {
	return target == ErrRateLimited && e.Status == http.StatusTooManyRequests
}

// Client talks to one log.
type Client struct {
	BaseURL   string // log URL from the log list, ending in "/"
	HTTP      *http.Client
	UserAgent string
}

// New returns a client with a sane default timeout.
func New(baseURL string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	return &Client{BaseURL: baseURL, HTTP: hc, UserAgent: "ctvault"}
}

func (c *Client) getJSON(ctx context.Context, path string, q url.Values, v any) error {
	u := c.BaseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("%s: reading body: %w", u, err)
	}
	if resp.StatusCode != http.StatusOK {
		he := &HTTPError{URL: u, Status: resp.StatusCode, Body: strings.TrimSpace(string(body[:min(len(body), 200)]))}
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s >= 0 {
			he.RetryAfter = time.Duration(s) * time.Second
		}
		return he
	}
	if len(body) > maxBody {
		return fmt.Errorf("%w: %s: body exceeds %d bytes", ErrMalformed, u, maxBody)
	}
	if err := json.Unmarshal(body, v); err != nil {
		// Quote the start of the body: a captive portal or proxy page is then
		// recognisable instead of a bare JSON syntax error.
		snippet := bytes.TrimSpace(body[:min(len(body), 60)])
		return fmt.Errorf("%w: %s: %v (response starts with %q)", ErrMalformed, u, err, snippet)
	}
	return nil
}

func decode32(field, s string) ([32]byte, error) {
	var out [32]byte
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return out, fmt.Errorf("%w: %s is not a base64 32-byte hash", ErrMalformed, field)
	}
	copy(out[:], b)
	return out, nil
}

// GetSTH fetches the current signed tree head. It does not verify the
// signature; callers verify with the pinned key via merkle.VerifySTH.
func (c *Client) GetSTH(ctx context.Context) (merkle.SignedTreeHead, error) {
	var j struct {
		TreeSize  *uint64 `json:"tree_size"`
		Timestamp uint64  `json:"timestamp"`
		Root      string  `json:"sha256_root_hash"`
		Sig       string  `json:"tree_head_signature"`
	}
	if err := c.getJSON(ctx, "ct/v1/get-sth", nil, &j); err != nil {
		return merkle.SignedTreeHead{}, err
	}
	if j.TreeSize == nil {
		return merkle.SignedTreeHead{}, fmt.Errorf("%w: get-sth has no tree_size", ErrMalformed)
	}
	root, err := decode32("sha256_root_hash", j.Root)
	if err != nil {
		return merkle.SignedTreeHead{}, err
	}
	sig, err := base64.StdEncoding.DecodeString(j.Sig)
	if err != nil || len(sig) == 0 {
		return merkle.SignedTreeHead{}, fmt.Errorf("%w: tree_head_signature is not base64", ErrMalformed)
	}
	return merkle.SignedTreeHead{TreeSize: *j.TreeSize, Timestamp: j.Timestamp, RootHash: root, Signature: sig}, nil
}

// GetSTHConsistency fetches the proof that the tree of size first is a prefix
// of the tree of size second.
func (c *Client) GetSTHConsistency(ctx context.Context, first, second uint64) ([][32]byte, error) {
	q := url.Values{"first": {strconv.FormatUint(first, 10)}, "second": {strconv.FormatUint(second, 10)}}
	var j struct {
		Consistency []string `json:"consistency"`
	}
	if err := c.getJSON(ctx, "ct/v1/get-sth-consistency", q, &j); err != nil {
		return nil, err
	}
	out := make([][32]byte, len(j.Consistency))
	for i, n := range j.Consistency {
		h, err := decode32(fmt.Sprintf("consistency[%d]", i), n)
		if err != nil {
			return nil, err
		}
		out[i] = h
	}
	return out, nil
}
