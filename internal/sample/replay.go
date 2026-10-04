package sample

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Replay serves a verified sample as an RFC 6962 log on loopback, so the real
// client and fetcher run unchanged (amendment A1 §2.5): get-sth returns the
// captured head byte for byte, get-entries serves at the captured page size,
// and the stored proofs answer get-sth-consistency and get-proof-by-hash.
type Replay struct {
	s *Sample

	mu    sync.Mutex
	cache map[int][]Entry // decoded frames, at most two
	order []int
}

// NewReplay returns the handler for s.
func NewReplay(s *Sample) *Replay { return &Replay{s: s, cache: map[int][]Entry{}} }

func (rp *Replay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/ct/v1/get-sth":
		w.Header().Set("Content-Type", "application/json")
		w.Write(rp.s.Manifest.HeadRaw)
	case "/ct/v1/get-entries":
		rp.entries(w, r)
	case "/ct/v1/get-sth-consistency":
		first, err1 := strconv.ParseUint(r.URL.Query().Get("first"), 10, 64)
		second, err2 := strconv.ParseUint(r.URL.Query().Get("second"), 10, 64)
		c, ok := rp.s.Proofs.find(first, second)
		if err1 != nil || err2 != nil || !ok {
			http.Error(w, "no stored proof for this range", http.StatusBadRequest)
			return
		}
		reply(w, map[string]any{"consistency": c.Nodes})
	case "/ct/v1/get-proof-by-hash":
		inc := rp.s.Proofs.Inclusion
		h, _ := base64.StdEncoding.DecodeString(r.URL.Query().Get("hash"))
		size, _ := strconv.ParseUint(r.URL.Query().Get("tree_size"), 10, 64)
		if inc == nil || string(h) != string(inc.LeafHash[:]) || size != inc.TreeSize {
			http.Error(w, "no stored proof for this leaf", http.StatusNotFound)
			return
		}
		reply(w, map[string]any{"leaf_index": inc.LeafIndex, "audit_path": inc.AuditPath})
	default:
		http.NotFound(w, r)
	}
}

func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (rp *Replay) entries(w http.ResponseWriter, r *http.Request) {
	m := rp.s.Manifest
	start, err1 := strconv.ParseUint(r.URL.Query().Get("start"), 10, 64)
	end, err2 := strconv.ParseUint(r.URL.Query().Get("end"), 10, 64)
	if err1 != nil || err2 != nil || end < start || start < m.Start || start >= m.Start+m.Count {
		http.Error(w, "range outside the sample", http.StatusBadRequest)
		return
	}
	end = min(end, start+uint64(max(m.PageSize, 1))-1, m.Start+m.Count-1)
	type wire struct {
		LeafInput []byte `json:"leaf_input"`
		ExtraData []byte `json:"extra_data"`
	}
	out := make([]wire, 0, end-start+1)
	for i := start; i <= end; i++ {
		e, err := rp.entry(i)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out = append(out, wire{e.LeafInput, e.ExtraData})
	}
	reply(w, map[string]any{"entries": out})
}

// entry returns entry i, decoding its frame if it is not one of the two most
// recently used.
func (rp *Replay) entry(i uint64) (Entry, error) {
	m := rp.s.Manifest
	k := int((i - m.Start) / m.Boundary)
	rp.mu.Lock()
	defer rp.mu.Unlock()
	frame, ok := rp.cache[k]
	if !ok {
		var err error
		if frame, err = rp.s.Frame(k); err != nil {
			return Entry{}, err
		}
		rp.cache[k] = frame
		rp.order = append(rp.order, k)
		if len(rp.order) > 2 {
			delete(rp.cache, rp.order[0])
			rp.order = rp.order[1:]
		}
	}
	return frame[(i-m.Start)%m.Boundary], nil
}

// Serve listens on 127.0.0.1 and serves the sample until ctx ends. It
// returns the log URL (ending in "/") and a function that stops the server.
func Serve(ctx context.Context, s *Sample) (string, func(), error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	srv := &http.Server{Handler: NewReplay(s), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			ln.Close()
		}
	}()
	stop := func() { srv.Close() }
	context.AfterFunc(ctx, stop)
	return "http://" + ln.Addr().String() + "/", stop, nil
}
