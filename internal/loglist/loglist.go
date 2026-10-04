// Package loglist reads Chrome's CT log list v3 and resolves CTVault log
// names to RFC 6962 logs with validated public keys.
package loglist

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
)

// DefaultURL is Chrome's published log list.
const DefaultURL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

const maxListSize = 16 << 20

var (
	ErrNotFound         = errors.New("log not found in log list")
	ErrAmbiguous        = errors.New("log name is ambiguous")
	ErrTiledUnsupported = errors.New("static-ct-api (tiled) logs are not supported in v1")
	ErrBadKey           = errors.New("log key does not match log_id")
)

// List is the subset of the v3 schema CTVault uses.
type List struct {
	Version   string     `json:"version"`
	Timestamp string     `json:"log_list_timestamp"`
	Operators []Operator `json:"operators"`
}

type Operator struct {
	Name      string     `json:"name"`
	Logs      []Log      `json:"logs"`
	TiledLogs []TiledLog `json:"tiled_logs"`
}

type State map[string]struct {
	Timestamp time.Time `json:"timestamp"`
}

type Interval struct {
	StartInclusive time.Time `json:"start_inclusive"`
	EndExclusive   time.Time `json:"end_exclusive"`
}

type Log struct {
	Description      string    `json:"description"`
	LogID            string    `json:"log_id"`
	Key              string    `json:"key"`
	URL              string    `json:"url"`
	MMD              int       `json:"mmd"`
	State            State     `json:"state"`
	TemporalInterval *Interval `json:"temporal_interval"`
}

type TiledLog struct {
	Description   string `json:"description"`
	SubmissionURL string `json:"submission_url"`
	MonitoringURL string `json:"monitoring_url"`
}

// Parse decodes a log list and rejects anything that is not one (for example
// an HTML error page from a captive portal).
func Parse(b []byte) (*List, error) {
	var l List
	if err := json.Unmarshal(b, &l); err != nil {
		snippet := string(bytes.TrimSpace(b[:min(len(b), 60)]))
		return nil, fmt.Errorf("log list is not valid JSON (starts with %q): %w", snippet, err)
	}
	if l.Version == "" || len(l.Operators) == 0 {
		return nil, errors.New("not a CT log list v3: missing version or operators")
	}
	return &l, nil
}

// Fetch loads a log list from an http(s) URL or a local file path.
func Fetch(ctx context.Context, hc *http.Client, src string) (*List, error) {
	var body []byte
	if u, err := url.Parse(src); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
		if err != nil {
			return nil, err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetching log list: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetching log list %s: HTTP %d", src, resp.StatusCode)
		}
		if body, err = io.ReadAll(io.LimitReader(resp.Body, maxListSize)); err != nil {
			return nil, err
		}
	} else if body, err = os.ReadFile(src); err != nil {
		return nil, err
	}
	return Parse(body)
}

var (
	// quotedName is the conventional log name operators put in single quotes
	// in the description ("DigiCert 'Wyvern2027h1'").
	quotedName = regexp.MustCompile(`'([A-Za-z0-9][A-Za-z0-9._-]{0,63})'`)
	// nameLike is a URL path segment or host label that looks like a log
	// name: starts with a letter and contains a digit ("tuscolo2028h1").
	nameLike = regexp.MustCompile(`^[a-z][a-z0-9_-]*[0-9][a-z0-9_-]*$`)
	nonName  = regexp.MustCompile(`[^a-z0-9]+`)
)

// LogName is CTVault's permanent name for a log; Plan 2 writes it into
// partition paths and batch IDs, so it must be unique across the log list.
// It is, in order of preference:
//  1. the single-quoted name in the description, lowercased
//     ("DigiCert 'Wyvern2027h1'" → "wyvern2027h1");
//  2. the last URL path segment, or else the first host label, that looks
//     like a log name ("https://tuscolo2028h1.sunlight.geomys.org/" → "tuscolo2028h1");
//  3. the URL's host and path with separators turned into '-'
//     ("https://ct.example.com/bogus/" → "ct-example-com-bogus").
func LogName(description, logURL string) string {
	if m := quotedName.FindStringSubmatch(description); m != nil {
		return strings.ToLower(m[1])
	}
	u, err := url.Parse(logURL)
	if err != nil {
		return strings.Trim(nonName.ReplaceAllString(strings.ToLower(logURL), "-"), "-")
	}
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	for i := len(segs) - 1; i >= 0; i-- {
		if s := strings.ToLower(segs[i]); nameLike.MatchString(s) {
			return s
		}
	}
	if label := strings.ToLower(strings.Split(u.Hostname(), ".")[0]); nameLike.MatchString(label) {
		return label
	}
	name := strings.Trim(nonName.ReplaceAllString(strings.ToLower(u.Hostname()+"/"+u.Path), "-"), "-")
	return name[:min(len(name), 64)]
}

// Name is the RFC 6962 log's CTVault name.
func (lg Log) Name() string { return LogName(lg.Description, lg.URL) }

// Name is the tiled log's CTVault name.
func (tl TiledLog) Name() string { return LogName(tl.Description, tl.SubmissionURL) }

// Resolved is one named RFC 6962 log.
type Resolved struct {
	Name     string
	Operator string
	Log      Log
}

// Find resolves a CTVault log name. RFC 6962 logs are matched first; a name
// that only matches a tiled log reports ErrTiledUnsupported.
func (l *List) Find(name string) (Resolved, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	var found []Resolved
	for _, op := range l.Operators {
		for _, lg := range op.Logs {
			if lg.Name() == name {
				found = append(found, Resolved{Name: name, Operator: op.Name, Log: lg})
			}
		}
	}
	switch len(found) {
	case 0:
		for _, op := range l.Operators {
			for _, tl := range op.TiledLogs {
				if tl.Name() == name {
					return Resolved{}, fmt.Errorf("%w: %s (%s)", ErrTiledUnsupported, name, tl.Description)
				}
			}
		}
		return Resolved{}, fmt.Errorf("%w: %q", ErrNotFound, name)
	case 1:
		return found[0], nil
	default:
		urls := make([]string, len(found))
		for i, f := range found {
			urls[i] = f.Log.URL
		}
		return Resolved{}, fmt.Errorf("%w: %q matches %s", ErrAmbiguous, name, strings.Join(urls, ", "))
	}
}

// RFC6962Logs lists every RFC 6962 log, sorted by name.
func (l *List) RFC6962Logs() []Resolved {
	var out []Resolved
	for _, op := range l.Operators {
		for _, lg := range op.Logs {
			out = append(out, Resolved{Name: lg.Name(), Operator: op.Name, Log: lg})
		}
	}
	slices.SortFunc(out, func(a, b Resolved) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// CurrentState returns the log's state name ("usable", "readonly", ...).
func (lg Log) CurrentState() string {
	names := make([]string, 0, len(lg.State))
	for k := range lg.State {
		names = append(names, k)
	}
	slices.Sort(names)
	return strings.Join(names, ",")
}

// ParseKey decodes a base64 SPKI and checks that logIDB64 is its SHA-256
// (RFC 6962 §3.2 defines the log ID that way).
func ParseKey(keyB64, logIDB64 string) (crypto.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("log key is not base64: %w", err)
	}
	id := sha256.Sum256(der)
	if base64.StdEncoding.EncodeToString(id[:]) != logIDB64 {
		return nil, ErrBadKey
	}
	return x509.ParsePKIXPublicKey(der)
}
