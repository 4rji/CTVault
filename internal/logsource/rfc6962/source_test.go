package rfc6962

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/merkle"
)

func fakeSource(t *testing.T, l *ctlogtest.Log) *Source {
	t.Helper()
	pub, err := x509.ParsePKIXPublicKey(l.PublicKeyDER)
	if err != nil {
		t.Fatal(err)
	}
	info := logsource.LogInfo{Name: "fake", LogID: l.LogID, PublicKey: pub, URL: l.URL}
	return NewSource(info, nil, logsource.NewChainCache(logsource.DefaultChainCacheBytes), nil)
}

func TestSourceHeadChecks(t *testing.T) {
	l := ctlogtest.New(t, 30, ctlogtest.Options{})
	s := fakeSource(t, l)
	l.Publish(10)
	h10, err := s.Head(ctx)
	if err != nil || h10.TreeSize != 10 || len(h10.Raw) == 0 {
		t.Fatalf("first head: %+v %v", h10, err)
	}
	l.Publish(20)
	if h, err := s.Head(ctx); err != nil || h.TreeSize != 20 {
		t.Fatalf("growth is accepted: %v", err)
	}
	l.Publish(15)
	var ie *logsource.IncidentError
	if _, err := s.Head(ctx); !errors.As(err, &ie) || ie.Kind != logsource.TreeShrank || ie.Last.TreeSize != 20 {
		t.Fatalf("a smaller tree is an incident: %v", err)
	}
	l.Publish(20)
	if _, err := s.Head(ctx); err != nil {
		t.Fatalf("the refused head must not replace the last accepted one: %v", err)
	}
	l.Fork(3)
	if _, err := s.Head(ctx); !errors.As(err, &ie) || ie.Kind != logsource.RootChanged {
		t.Fatalf("same size, different root is an incident: %v", err)
	}

	bad := ctlogtest.New(t, 4, ctlogtest.Options{BadSTHSignature: true})
	if _, err := fakeSource(t, bad).Head(ctx); !errors.Is(err, merkle.ErrBadSignature) || errors.Is(err, logsource.ErrIncident) {
		t.Fatalf("a bad signature is reported as such: %v", err)
	}
}

func TestCheckHeadTimestamps(t *testing.T) {
	last := &logsource.SignedHead{SignedTreeHead: merkle.SignedTreeHead{TreeSize: 5, Timestamp: 1000, RootHash: [32]byte{1}}}
	older := logsource.SignedHead{SignedTreeHead: merkle.SignedTreeHead{TreeSize: 5, Timestamp: 999, RootHash: [32]byte{1}}}
	var ie *logsource.IncidentError
	if err := logsource.CheckHead(last, older); !errors.As(err, &ie) || ie.Kind != logsource.TimestampBackwards {
		t.Fatalf("an older timestamp is an incident: %v", err)
	}
	resigned := logsource.SignedHead{SignedTreeHead: merkle.SignedTreeHead{TreeSize: 5, Timestamp: 2000, RootHash: [32]byte{1}}}
	if err := logsource.CheckHead(last, resigned); err != nil {
		t.Fatalf("the same tree signed later is fine: %v", err)
	}
	if err := logsource.CheckHead(nil, older); err != nil {
		t.Fatalf("with no last head anything signed is accepted: %v", err)
	}
}

func TestSourceFetch(t *testing.T) {
	l := ctlogtest.New(t, 10, ctlogtest.Options{PageSize: 4})
	s := fakeSource(t, l)
	got, err := s.Fetch(ctx, 2, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("one page of 4, got %d", len(got))
	}
	caFP := sha256.Sum256(leaf.Decode(l.Entries[0].LeafInput, l.Entries[0].ExtraData).Chain[0])
	for i, e := range got {
		want := l.Entries[2+i]
		if e.Index != uint64(2+i) || !bytes.Equal(e.LeafInput, want.LeafInput) || e.Leaf.Code != leaf.OK {
			t.Fatalf("entry %d: index %d code %q", 2+i, e.Index, e.Leaf.Code)
		}
		if len(e.Chain) != 1 || e.Chain[0] != caFP {
			t.Fatalf("entry %d: chain must be fingerprinted", 2+i)
		}
		if e.Size() != len(want.LeafInput)+len(want.ExtraData) {
			t.Fatal("Size counts the exact bytes")
		}
	}
	der, err := s.Issuer(ctx, caFP)
	if err != nil || sha256.Sum256(der) != caFP {
		t.Fatalf("Issuer must serve the cached chain certificate: %v", err)
	}
	if _, err := s.Issuer(ctx, [32]byte{9}); !errors.Is(err, logsource.ErrIssuerUnknown) {
		t.Fatalf("unknown fingerprint: %v", err)
	}
	if _, err := s.Fetch(ctx, 5, 5); err == nil {
		t.Fatal("an empty range is refused")
	}
}

func TestSourceConsistencyProofNeedsNoRequestForTrivialSizes(t *testing.T) {
	l := ctlogtest.New(t, 8, ctlogtest.Options{})
	s := fakeSource(t, l)
	for _, sz := range [][2]uint64{{0, 8}, {8, 8}} {
		p, err := s.ConsistencyProof(ctx, sz[0], sz[1])
		if err != nil || p != nil {
			t.Fatalf("%v: %v %v", sz, p, err)
		}
	}
	if l.Requests("get-sth-consistency") != 0 {
		t.Fatal("trivial proofs must not hit the log")
	}
	if p, err := s.ConsistencyProof(ctx, 3, 8); err != nil || len(p) == 0 {
		t.Fatalf("real proof: %v %v", p, err)
	}
}

func TestChainCache(t *testing.T) {
	c := logsource.NewChainCache(10)
	a, b := [32]byte{1}, [32]byte{2}
	if err := c.Put(a, []byte("123456")); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(a, []byte("123456")); err != nil || c.Bytes() != 6 {
		t.Fatalf("a known certificate is free: %v, %d bytes", err, c.Bytes())
	}
	if err := c.Put(b, []byte("12345")); !errors.Is(err, logsource.ErrChainCacheFull) {
		t.Fatalf("11 bytes exceed the 10-byte bound: %v", err)
	}
	src := []byte("abc")
	c.Put(b, src)
	src[0] = 'X'
	if got, _ := c.Get(b); string(got) != "abc" {
		t.Fatal("Put must copy, so the caller's buffer can be reused")
	}
	c.Reset()
	if c.Len() != 0 || c.Bytes() != 0 {
		t.Fatal("Reset empties the cache")
	}
}

// TestSourceFetchRealPage serves the real argon2027h1 fixture page through
// get-entries and decodes it with the production Source.
func TestSourceFetchRealPage(t *testing.T) {
	page, err := os.ReadFile("../../testdata/argon2027h1_entries_380000000.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("start") != "380000000" || r.URL.Query().Get("end") != "380000031" {
			http.Error(w, "unexpected range", http.StatusBadRequest)
			return
		}
		w.Write(page)
	}))
	defer srv.Close()
	info := logsource.LogInfo{Name: "argon2027h1", URL: srv.URL}
	cache := logsource.NewChainCache(logsource.DefaultChainCacheBytes)
	got, err := NewSource(info, nil, cache, nil).Fetch(ctx, 380000000, 380000032)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 32 || got[31].Index != 380000031 {
		t.Fatalf("got %d entries", len(got))
	}
	for _, e := range got {
		if e.Leaf.Code != leaf.OK || len(e.Chain) == 0 {
			t.Fatalf("entry %d: code %q, chain %d", e.Index, e.Leaf.Code, len(e.Chain))
		}
		for _, fp := range e.Chain {
			if der, ok := cache.Get(fp); !ok || sha256.Sum256(der) != fp {
				t.Fatalf("entry %d: chain certificate not cached under its SHA-256", e.Index)
			}
		}
	}
	if cache.Len() != 25 {
		t.Fatalf("the fixture's 32 entries reference 25 distinct chain certificates, got %d", cache.Len())
	}
}
