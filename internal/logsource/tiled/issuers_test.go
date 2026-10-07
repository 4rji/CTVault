package tiled

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// issuerPeak resolves n distinct issuers against a server that holds each
// request briefly, and returns the most it saw at once.
func issuerPeak(t *testing.T, n int) int {
	t.Helper()
	ders := map[string][]byte{}
	fps := map[[32]byte]bool{}
	for i := 0; i < n; i++ {
		der := []byte(fmt.Sprintf("issuer %d", i))
		fp := sha256.Sum256(der)
		ders[hex.EncodeToString(fp[:])] = der
		fps[fp] = true
	}
	var mu sync.Mutex
	cur, peak := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cur++
		peak = max(peak, cur)
		mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		mu.Lock()
		cur--
		mu.Unlock()
		w.Write(ders[strings.TrimPrefix(r.URL.Path, "/issuer/")])
	}))
	defer srv.Close()
	is := newIssuers(NewClient(srv.URL, nil), 1<<20)
	got, err := is.resolve(ctx, fps)
	if err != nil || len(got) != n || is.fetched.Load() != int64(n) {
		t.Fatalf("resolved %d of %d (%d fetched): %v", len(got), n, is.fetched.Load(), err)
	}
	return peak
}
