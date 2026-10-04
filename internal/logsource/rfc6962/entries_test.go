package rfc6962

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"

	"github.com/4rji/ctvault/internal/ctlogtest"
)

func TestGetEntriesAgainstFakeLog(t *testing.T) {
	l := ctlogtest.New(t, 10, ctlogtest.Options{PageSize: 4})
	got, err := New(l.URL, nil).GetEntries(ctx, 3, 9)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("page size 4: got %d entries", len(got))
	}
	for i, w := range got {
		if !bytes.Equal(w.LeafInput, l.Entries[3+i].LeafInput) || !bytes.Equal(w.ExtraData, l.Entries[3+i].ExtraData) {
			t.Fatalf("entry %d: bytes must be exactly as served", 3+i)
		}
	}
	if _, err := New(l.URL, nil).GetEntries(ctx, 5, 4); err == nil {
		t.Fatal("end before start must be refused before any request")
	}
}

// TestGetEntriesFramingErrors: anything that keeps the exact bytes from being
// established is ErrMalformed, so the fetcher retries and nothing advances.
func TestGetEntriesFramingErrors(t *testing.T) {
	ok := `{"leaf_input":"AAA=","extra_data":"AAAA"}`
	for name, body := range map[string]string{
		"truncated JSON":     `{"entries":[` + ok,
		"invalid base64":     `{"entries":[{"leaf_input":"!!","extra_data":"AAAA"}]}`,
		"missing leaf":       `{"entries":[{"extra_data":"AAAA"}]}`,
		"missing extra":      `{"entries":[{"leaf_input":"AAA="}]}`,
		"no entries":         `{"entries":[]}`,
		"no entries field":   `{}`,
		"more than asked":    `{"entries":[` + ok + `,` + ok + `,` + ok + `]}`,
		"html error page":    `<html>502 Bad Gateway</html>`,
		"null leaf_input":    `{"entries":[{"leaf_input":null,"extra_data":"AAAA"}]}`,
		"extra not a string": `{"entries":[{"leaf_input":"AAA=","extra_data":5}]}`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		_, err := New(srv.URL, nil).GetEntries(ctx, 0, 1)
		srv.Close()
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: want ErrMalformed, got %v", name, err)
		}
	}
}

func TestGetProofByHash(t *testing.T) {
	l := ctlogtest.New(t, 21, ctlogtest.Options{})
	c := New(l.URL, nil)
	sth, err := c.GetSTH(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lh := sha256.Sum256(append([]byte{0}, l.Entries[13].LeafInput...))
	idx, path, err := c.GetProofByHash(ctx, lh, sth.TreeSize)
	if err != nil {
		t.Fatal(err)
	}
	nodes := make([][]byte, len(path))
	for i := range path {
		nodes[i] = path[i][:]
	}
	if idx != 13 || proof.VerifyInclusion(rfc6962.DefaultHasher, idx, sth.TreeSize, lh[:], nodes, sth.RootHash[:]) != nil {
		t.Fatalf("leaf 13: index %d; proof must verify", idx)
	}
	var he *HTTPError
	if _, _, err := c.GetProofByHash(ctx, [32]byte{1}, sth.TreeSize); !errors.As(err, &he) || he.Status != 404 {
		t.Fatalf("unknown leaf: want HTTP 404, got %v", err)
	}
}

// TestHTTPErrorBodyIsQuoted covers Plan 1 review minor 12: a server's error
// body is shown quoted, so escape sequences cannot act on the terminal.
func TestHTTPErrorBodyIsQuoted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "\x1b[2J\x1b[31mgotcha", http.StatusInternalServerError)
	}))
	defer srv.Close()
	_, err := New(srv.URL, nil).GetSTH(ctx)
	if err == nil || strings.Contains(err.Error(), "\x1b") || !strings.Contains(err.Error(), `\x1b[2J`) {
		t.Fatalf("error must show the escape sequence quoted: %q", err)
	}
}
