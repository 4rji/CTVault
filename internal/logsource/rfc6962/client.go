// Package rfc6962 is CTVault's HTTP client for RFC 6962 logs (get-sth,
// get-sth-consistency, get-entries, get-proof-by-hash) and the LogSource
// adapter built on it.
package rfc6962

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/merkle"
)

// maxBody bounds response bodies; a full get-entries page is well under this.
const maxBody = 16 << 20

// The HTTP errors are logsource's, shared with the tiled source (amendment
// A6 §2.1); these names stay for existing callers.
var (
	ErrRateLimited = logsource.ErrRateLimited
	ErrMalformed   = logsource.ErrMalformed
)

// HTTPError is a non-200 answer from the log.
type HTTPError = logsource.HTTPError

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

// getJSON fetches path and decodes it into v. It returns the body exactly as
// received.
func (c *Client) getJSON(ctx context.Context, path string, q url.Values, v any) ([]byte, error) {
	u := c.BaseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		// A body cut short (dropped connection, HTTP/2 stream reset) is
		// transport corruption (spec §5.4): retried, never fatal.
		return nil, fmt.Errorf("%w: %s: reading body: %w", ErrMalformed, u, err)
	}
	if resp.StatusCode != http.StatusOK {
		he := &HTTPError{URL: u, Status: resp.StatusCode, Body: strings.TrimSpace(string(body[:min(len(body), 200)]))}
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s >= 0 {
			he.RetryAfter = time.Duration(s) * time.Second
		}
		return nil, he
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("%w: %s: body exceeds %d bytes", ErrMalformed, u, maxBody)
	}
	if err := json.Unmarshal(body, v); err != nil {
		// Quote the start of the body: a captive portal or proxy page is then
		// recognisable instead of a bare JSON syntax error.
		snippet := bytes.TrimSpace(body[:min(len(body), 60)])
		return nil, fmt.Errorf("%w: %s: %v (response starts with %q)", ErrMalformed, u, err, snippet)
	}
	return body, nil
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
	sth, _, err := c.GetSTHRaw(ctx)
	return sth, err
}

// GetSTHRaw is GetSTH that also returns the response body exactly as
// received, for sample manifests and incident evidence.
func (c *Client) GetSTHRaw(ctx context.Context) (merkle.SignedTreeHead, []byte, error) {
	var j struct {
		TreeSize  *uint64 `json:"tree_size"`
		Timestamp uint64  `json:"timestamp"`
		Root      string  `json:"sha256_root_hash"`
		Sig       string  `json:"tree_head_signature"`
	}
	raw, err := c.getJSON(ctx, "ct/v1/get-sth", nil, &j)
	if err != nil {
		return merkle.SignedTreeHead{}, nil, err
	}
	if j.TreeSize == nil {
		return merkle.SignedTreeHead{}, nil, fmt.Errorf("%w: get-sth has no tree_size", ErrMalformed)
	}
	root, err := decode32("sha256_root_hash", j.Root)
	if err != nil {
		return merkle.SignedTreeHead{}, nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(j.Sig)
	if err != nil || len(sig) == 0 {
		return merkle.SignedTreeHead{}, nil, fmt.Errorf("%w: tree_head_signature is not base64", ErrMalformed)
	}
	return merkle.SignedTreeHead{TreeSize: *j.TreeSize, Timestamp: j.Timestamp, RootHash: root, Signature: sig}, raw, nil
}

// GetSTHConsistency fetches the proof that the tree of size first is a prefix
// of the tree of size second.
func (c *Client) GetSTHConsistency(ctx context.Context, first, second uint64) ([][32]byte, error) {
	q := url.Values{"first": {strconv.FormatUint(first, 10)}, "second": {strconv.FormatUint(second, 10)}}
	var j struct {
		Consistency []string `json:"consistency"`
	}
	if _, err := c.getJSON(ctx, "ct/v1/get-sth-consistency", q, &j); err != nil {
		return nil, err
	}
	return decodeNodes("consistency", j.Consistency)
}

func decodeNodes(field string, nodes []string) ([][32]byte, error) {
	out := make([][32]byte, len(nodes))
	for i, n := range nodes {
		h, err := decode32(fmt.Sprintf("%s[%d]", field, i), n)
		if err != nil {
			return nil, err
		}
		out[i] = h
	}
	return out, nil
}

// WireEntry is one get-entries element after base64 decoding: the exact
// bytes the log served.
type WireEntry struct {
	LeafInput []byte
	ExtraData []byte
}

// GetEntries fetches entries [start, end], inclusive as in RFC 6962 §4.6.
// The log may return fewer; it may not return none or more than asked.
// Anything that keeps the exact bytes from being established is ErrMalformed
// (spec §5.4: transport or framing corruption), so nothing advances.
func (c *Client) GetEntries(ctx context.Context, start, end uint64) ([]WireEntry, error) {
	if end < start {
		return nil, fmt.Errorf("get-entries: end %d before start %d", end, start)
	}
	q := url.Values{"start": {strconv.FormatUint(start, 10)}, "end": {strconv.FormatUint(end, 10)}}
	var j struct {
		Entries []struct {
			LeafInput *string `json:"leaf_input"`
			ExtraData *string `json:"extra_data"`
		} `json:"entries"`
	}
	if _, err := c.getJSON(ctx, "ct/v1/get-entries", q, &j); err != nil {
		return nil, err
	}
	if len(j.Entries) == 0 {
		return nil, fmt.Errorf("%w: get-entries %d-%d returned no entries", ErrMalformed, start, end)
	}
	if uint64(len(j.Entries)) > end-start+1 {
		return nil, fmt.Errorf("%w: get-entries %d-%d returned %d entries", ErrMalformed, start, end, len(j.Entries))
	}
	out := make([]WireEntry, len(j.Entries))
	for i, e := range j.Entries {
		if e.LeafInput == nil || e.ExtraData == nil {
			return nil, fmt.Errorf("%w: get-entries entry %d lacks leaf_input or extra_data", ErrMalformed, start+uint64(i))
		}
		li, err1 := base64.StdEncoding.DecodeString(*e.LeafInput)
		ed, err2 := base64.StdEncoding.DecodeString(*e.ExtraData)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("%w: get-entries entry %d is not valid base64", ErrMalformed, start+uint64(i))
		}
		out[i] = WireEntry{LeafInput: li, ExtraData: ed}
	}
	return out, nil
}

// GetProofByHash fetches the inclusion proof of the leaf with hash leafHash
// in the tree of size treeSize (RFC 6962 §4.5).
func (c *Client) GetProofByHash(ctx context.Context, leafHash [32]byte, treeSize uint64) (uint64, [][32]byte, error) {
	q := url.Values{"hash": {base64.StdEncoding.EncodeToString(leafHash[:])}, "tree_size": {strconv.FormatUint(treeSize, 10)}}
	var j struct {
		LeafIndex *uint64  `json:"leaf_index"`
		AuditPath []string `json:"audit_path"`
	}
	if _, err := c.getJSON(ctx, "ct/v1/get-proof-by-hash", q, &j); err != nil {
		return 0, nil, err
	}
	if j.LeafIndex == nil {
		return 0, nil, fmt.Errorf("%w: get-proof-by-hash has no leaf_index", ErrMalformed)
	}
	path, err := decodeNodes("audit_path", j.AuditPath)
	return *j.LeafIndex, path, err
}
