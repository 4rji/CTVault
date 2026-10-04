package ctlogtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
)

// Options configures page size and fault injection. Every "Every" counter
// fires on its Nth matching request (1 = every request, 0 = never).
type Options struct {
	PageSize           int  // max entries per get-entries response; default 32
	RateLimitEvery     int  // any endpoint answers 429 with Retry-After: 1
	NoRetryAfter       bool // 429 answers omit Retry-After
	ServerErrorEvery   int  // any endpoint answers 503 (no Retry-After)
	ShortReadEvery     int  // get-entries returns half of what it would have
	CorruptJSONEvery   int  // get-entries returns truncated JSON
	TruncateBodyEvery  int  // get-entries promises a full body, sends half, then drops the connection
	InvalidBase64Every int  // get-entries returns an invalid base64 leaf_input
	BadSTHSignature    bool
	AlterEntries       []uint64 // these indices are served with a modified leaf_input
	// EntriesDelay, if set, delays each get-entries response by the returned
	// duration before any lock is taken, so concurrent requests can complete
	// out of order. It receives the requested start index.
	EntriesDelay func(start uint64) time.Duration
}

// Log is a running fake log.
type Log struct {
	URL          string // base URL ending in "/"
	PublicKeyDER []byte // SPKI, as the log list publishes it
	LogID        [32]byte
	Entries      []Entry

	t    testing.TB
	key  *ecdsa.PrivateKey
	opts Options
	srv  *httptest.Server

	mu        sync.Mutex
	tree      *testonly.Tree // tree used for STHs and proofs
	honest    *testonly.Tree
	published uint64
	counts    map[string]int
	altered   map[uint64]bool
	byHash    map[[32]byte]uint64 // leaf hash → first index, for get-proof-by-hash
}

// New starts a fake log holding n generated entries, all published.
func New(t testing.TB, n int, opts Options) *Log {
	t.Helper()
	g, err := NewGenerator()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := g.Entries(n)
	if err != nil {
		t.Fatal(err)
	}
	return NewWithEntries(t, entries, opts)
}

// NewWithEntries starts a fake log serving the given entries.
func NewWithEntries(t testing.TB, entries []Entry, opts Options) *Log {
	t.Helper()
	if opts.PageSize == 0 {
		opts.PageSize = 32
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	l := &Log{PublicKeyDER: spki, LogID: sha256.Sum256(spki), Entries: entries, t: t, key: key, opts: opts,
		honest: testonly.New(rfc6962.DefaultHasher), published: uint64(len(entries)),
		counts: map[string]int{}, altered: map[uint64]bool{}, byHash: map[[32]byte]uint64{}}
	for i, e := range entries {
		l.honest.AppendData(e.LeafInput)
		var h [32]byte
		copy(h[:], rfc6962.DefaultHasher.HashLeaf(e.LeafInput))
		if _, dup := l.byHash[h]; !dup {
			l.byHash[h] = uint64(i)
		}
	}
	l.tree = l.honest
	for _, i := range opts.AlterEntries {
		l.altered[i] = true
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ct/v1/get-sth", l.getSTH)
	mux.HandleFunc("GET /ct/v1/get-sth-consistency", l.getConsistency)
	mux.HandleFunc("GET /ct/v1/get-entries", l.getEntries)
	mux.HandleFunc("GET /ct/v1/get-proof-by-hash", l.getProofByHash)
	l.srv = httptest.NewServer(mux)
	t.Cleanup(l.srv.Close)
	l.URL = l.srv.URL + "/"
	return l
}

// Publish sets the tree size reported by get-sth. It may shrink, which a
// correct client must treat as log misbehaviour.
func (l *Log) Publish(size uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if size > uint64(len(l.Entries)) {
		size = uint64(len(l.Entries))
	}
	l.published = size
}

// Fork makes STHs and proofs come from a tree whose leaf at index differs:
// a split view that consistency checks must detect. An index outside the log
// fails the test instead of silently forking nothing.
func (l *Log) Fork(index uint64) {
	if index >= uint64(len(l.Entries)) {
		l.t.Fatalf("ctlogtest: Fork(%d) is outside a log of %d entries", index, len(l.Entries))
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fork := testonly.New(rfc6962.DefaultHasher)
	for i, e := range l.Entries {
		leaf := e.LeafInput
		if uint64(i) == index {
			leaf = flip(leaf)
		}
		fork.AppendData(leaf)
	}
	l.tree = fork
}

// Requests returns how many requests an endpoint ("get-sth", ...) received.
func (l *Log) Requests(endpoint string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.counts[endpoint]
}

// flip changes one certificate byte while keeping the leaf structurally valid
// (the final two bytes are the CtExtensions length).
func flip(leaf []byte) []byte {
	out := append([]byte(nil), leaf...)
	out[len(out)-3] ^= 0xff
	return out
}

func every(n, count int) bool { return n > 0 && count%n == 0 }

// begin counts the request and applies rate limiting; it reports whether the
// handler should continue.
func (l *Log) begin(w http.ResponseWriter, endpoint string) (int, bool) {
	l.counts[endpoint]++
	l.counts["all"]++
	if every(l.opts.RateLimitEvery, l.counts["all"]) {
		if !l.opts.NoRetryAfter {
			w.Header().Set("Retry-After", "1")
		}
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return 0, false
	}
	if every(l.opts.ServerErrorEvery, l.counts["all"]) {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return 0, false
	}
	return l.counts[endpoint], true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (l *Log) rootAt(size uint64) []byte {
	if size == 0 {
		return rfc6962.DefaultHasher.EmptyRoot()
	}
	return l.tree.HashAt(size)
}

func (l *Log) getSTH(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.begin(w, "get-sth"); !ok {
		return
	}
	size := l.published
	ts := uint64(1790000000000) + size
	root := l.rootAt(size)
	in := []byte{0, 1}
	in = binary.BigEndian.AppendUint64(in, ts)
	in = binary.BigEndian.AppendUint64(in, size)
	in = append(in, root...)
	digest := sha256.Sum256(in)
	sig, err := ecdsa.SignASN1(rand.Reader, l.key, digest[:])
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if l.opts.BadSTHSignature {
		sig[len(sig)-1] ^= 0xff
	}
	ds := []byte{4, 3}
	ds = binary.BigEndian.AppendUint16(ds, uint16(len(sig)))
	ds = append(ds, sig...)
	writeJSON(w, map[string]any{
		"tree_size": size, "timestamp": ts,
		"sha256_root_hash":    base64.StdEncoding.EncodeToString(root),
		"tree_head_signature": base64.StdEncoding.EncodeToString(ds),
	})
}

func parseRange(r *http.Request, a, b string) (uint64, uint64, error) {
	x, err1 := strconv.ParseUint(r.URL.Query().Get(a), 10, 64)
	y, err2 := strconv.ParseUint(r.URL.Query().Get(b), 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, fmt.Errorf("bad %s/%s", a, b)
	}
	return x, y, nil
}

func (l *Log) getConsistency(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.begin(w, "get-sth-consistency"); !ok {
		return
	}
	first, second, err := parseRange(r, "first", "second")
	if err != nil || first == 0 || first > second || second > l.tree.Size() {
		http.Error(w, "bad range", http.StatusBadRequest)
		return
	}
	proof, err := l.tree.ConsistencyProof(first, second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	nodes := make([]string, len(proof))
	for i, p := range proof {
		nodes[i] = base64.StdEncoding.EncodeToString(p)
	}
	writeJSON(w, map[string]any{"consistency": nodes})
}

func (l *Log) getEntries(w http.ResponseWriter, r *http.Request) {
	if l.opts.EntriesDelay != nil {
		if start, _, err := parseRange(r, "start", "end"); err == nil {
			select {
			case <-time.After(l.opts.EntriesDelay(start)):
			case <-r.Context().Done():
				return
			}
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	n, ok := l.begin(w, "get-entries")
	if !ok {
		return
	}
	start, end, err := parseRange(r, "start", "end")
	if err != nil || start > end || start >= l.published {
		http.Error(w, "bad range", http.StatusBadRequest)
		return
	}
	end = min(end, l.published-1, start+uint64(l.opts.PageSize)-1)
	if every(l.opts.ShortReadEvery, n) && end > start {
		end = start + (end-start)/2
	}
	type wireEntry struct {
		LeafInput string `json:"leaf_input"`
		ExtraData string `json:"extra_data"`
	}
	out := make([]wireEntry, 0, end-start+1)
	for i := start; i <= end; i++ {
		e := l.Entries[i]
		leaf := e.LeafInput
		if l.altered[i] {
			leaf = flip(leaf)
		}
		out = append(out, wireEntry{base64.StdEncoding.EncodeToString(leaf), base64.StdEncoding.EncodeToString(e.ExtraData)})
	}
	if every(l.opts.InvalidBase64Every, n) {
		out[0].LeafInput = "!!not-base64!!"
	}
	if every(l.opts.TruncateBodyEvery, n) {
		b, _ := json.Marshal(map[string]any{"entries": out})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.WriteHeader(http.StatusOK)
		w.Write(b[:len(b)/2])
		w.(http.Flusher).Flush()
		if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
			conn.Close()
		}
		return
	}
	if every(l.opts.CorruptJSONEvery, n) {
		b, _ := json.Marshal(map[string]any{"entries": out})
		w.Header().Set("Content-Type", "application/json")
		w.Write(b[:len(b)/2])
		return
	}
	writeJSON(w, map[string]any{"entries": out})
}

func (l *Log) getProofByHash(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.begin(w, "get-proof-by-hash"); !ok {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(r.URL.Query().Get("hash"))
	size, err2 := strconv.ParseUint(r.URL.Query().Get("tree_size"), 10, 64)
	if err != nil || err2 != nil || len(raw) != 32 || size == 0 || size > l.tree.Size() {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var h [32]byte
	copy(h[:], raw)
	idx, ok := l.byHash[h]
	if !ok || idx >= size {
		http.Error(w, "leaf not found", http.StatusNotFound)
		return
	}
	proof, err := l.tree.InclusionProof(idx, size)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	path := make([]string, len(proof))
	for i, p := range proof {
		path[i] = base64.StdEncoding.EncodeToString(p)
	}
	writeJSON(w, map[string]any{"leaf_index": idx, "audit_path": path})
}
