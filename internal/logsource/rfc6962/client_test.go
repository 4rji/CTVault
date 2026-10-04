package rfc6962

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/merkle"
)

var ctx = context.Background()

func TestGetSTHAndConsistencyAgainstFakeLog(t *testing.T) {
	l := ctlogtest.New(t, 40, ctlogtest.Options{})
	pub, err := x509.ParsePKIXPublicKey(l.PublicKeyDER)
	if err != nil {
		t.Fatal(err)
	}
	c := New(l.URL, nil)

	l.Publish(17)
	old, err := c.GetSTH(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if old.TreeSize != 17 || merkle.VerifySTH(pub, old) != nil {
		t.Fatalf("STH at 17 should verify: %+v", old)
	}
	l.Publish(40)
	cur, err := c.GetSTH(ctx)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := c.GetSTHConsistency(ctx, old.TreeSize, cur.TreeSize)
	if err != nil {
		t.Fatal(err)
	}
	if err := merkle.VerifyConsistency(old.TreeSize, cur.TreeSize, old.RootHash, cur.RootHash, proof); err != nil {
		t.Fatalf("honest log must be consistent: %v", err)
	}
}

func TestDetectsForkAndBadSignature(t *testing.T) {
	l := ctlogtest.New(t, 40, ctlogtest.Options{})
	c := New(l.URL, nil)
	l.Publish(20)
	old, _ := c.GetSTH(ctx)
	l.Publish(40)
	l.Fork(5) // the log now presents a history in which leaf 5 differs
	cur, _ := c.GetSTH(ctx)
	proof, err := c.GetSTHConsistency(ctx, old.TreeSize, cur.TreeSize)
	if err != nil {
		t.Fatal(err)
	}
	if err := merkle.VerifyConsistency(old.TreeSize, cur.TreeSize, old.RootHash, cur.RootHash, proof); !errors.Is(err, merkle.ErrInconsistent) {
		t.Fatalf("fork must be detected, got %v", err)
	}

	bad := ctlogtest.New(t, 4, ctlogtest.Options{BadSTHSignature: true})
	pub, _ := x509.ParsePKIXPublicKey(bad.PublicKeyDER)
	sth, err := New(bad.URL, nil).GetSTH(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := merkle.VerifySTH(pub, sth); !errors.Is(err, merkle.ErrBadSignature) {
		t.Fatalf("bad signature must be detected, got %v", err)
	}
}

func TestRateLimitIsReported(t *testing.T) {
	l := ctlogtest.New(t, 4, ctlogtest.Options{RateLimitEvery: 1})
	_, err := New(l.URL, nil).GetSTH(ctx)
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("want ErrRateLimited, got %v", err)
	}
	var he *HTTPError
	if !errors.As(err, &he) || he.RetryAfter != time.Second {
		t.Fatalf("Retry-After not parsed: %+v", he)
	}
}

func TestMalformedResponses(t *testing.T) {
	for name, body := range map[string]string{
		"html captive portal": "<html>please log in</html>",
		"missing tree_size":   `{"timestamp":1,"sha256_root_hash":"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `","tree_head_signature":"BAMAAQA="}`,
		"short root":          `{"tree_size":1,"timestamp":1,"sha256_root_hash":"AAAA","tree_head_signature":"BAMAAQA="}`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		_, err := New(srv.URL, nil).GetSTH(ctx)
		srv.Close()
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: want ErrMalformed, got %v", name, err)
		}
	}
}

// TestRealArgonResponses replays responses captured from argon2027h1 on
// 2026-10-04 and verifies them with the key pinned from Chrome's log list.
func TestRealArgonResponses(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile("../../testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	// The log's answers change over time, so replay them in order.
	sthReplies := [][]byte{read("argon2027h1_sth1.json"), read("argon2027h1_sth2.json")}
	mux := http.NewServeMux()
	mux.HandleFunc("/logs/us1/argon2027h1/ct/v1/get-sth", func(w http.ResponseWriter, r *http.Request) {
		w.Write(sthReplies[0])
		sthReplies = sthReplies[1:]
	})
	mux.HandleFunc("/logs/us1/argon2027h1/ct/v1/get-sth-consistency", func(w http.ResponseWriter, r *http.Request) {
		w.Write(read("argon2027h1_consistency.json"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var ll struct {
		Operators []struct {
			Logs []struct{ URL, Key string } `json:"logs"`
		} `json:"operators"`
	}
	raw, _ := os.ReadFile("../../testdata/log_list_google.json")
	json.Unmarshal(raw, &ll)
	var keyB64 string
	for _, lg := range ll.Operators[0].Logs {
		if lg.URL == "https://ct.googleapis.com/logs/us1/argon2027h1/" {
			keyB64 = lg.Key
		}
	}
	der, _ := base64.StdEncoding.DecodeString(keyB64)
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}

	c := New(srv.URL+"/logs/us1/argon2027h1/", nil)
	sth1, err := c.GetSTH(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sth2, err := c.GetSTH(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []merkle.SignedTreeHead{sth1, sth2} {
		if err := merkle.VerifySTH(pub, s); err != nil {
			t.Fatalf("captured STH at %d must verify: %v", s.TreeSize, err)
		}
	}
	proof, err := c.GetSTHConsistency(ctx, sth1.TreeSize, sth2.TreeSize)
	if err != nil {
		t.Fatal(err)
	}
	if err := merkle.VerifyConsistency(sth1.TreeSize, sth2.TreeSize, sth1.RootHash, sth2.RootHash, proof); err != nil {
		t.Fatalf("captured 23-node proof must verify: %v", err)
	}
}
