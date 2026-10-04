package ctlogtest

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
)

type wireEntries struct {
	Entries []struct {
		LeafInput string `json:"leaf_input"`
		ExtraData string `json:"extra_data"`
	} `json:"entries"`
}

func get(t *testing.T, url string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	return resp, buf.Bytes()
}

func TestPairIsRFC6962Consistent(t *testing.T) {
	g, err := NewGenerator()
	if err != nil {
		t.Fatal(err)
	}
	pre, fin, err := g.Pair("a.example.test", 1)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := x509.ParseCertificate(pre.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	fc, err := x509.ParseCertificate(fin.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	if pc.SerialNumber.Cmp(fc.SerialNumber) != 0 || len(pc.Extensions) != len(fc.Extensions) {
		t.Fatal("precert and final cert must describe the same issuance")
	}
	if bytes.Equal(pre.CertDER, fin.CertDER) || len(pre.PrecertTBS) == 0 {
		t.Fatal("precert and final cert must differ")
	}
	if pre.LeafInput[11] != byte(PrecertEntry) || fin.LeafInput[11] != byte(X509Entry) {
		t.Fatal("entry types are encoded at offset 10-11")
	}
}

func TestServesEntriesInPages(t *testing.T) {
	l := New(t, 10, Options{PageSize: 4})
	resp, body := get(t, l.URL+"ct/v1/get-entries?start=2&end=9")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var we wireEntries
	if err := json.Unmarshal(body, &we); err != nil {
		t.Fatal(err)
	}
	if len(we.Entries) != 4 {
		t.Fatalf("page size 4: got %d entries", len(we.Entries))
	}
	leaf, _ := base64.StdEncoding.DecodeString(we.Entries[0].LeafInput)
	if !bytes.Equal(leaf, l.Entries[2].LeafInput) {
		t.Fatal("first entry must be index 2")
	}
	if resp, _ := get(t, l.URL+"ct/v1/get-entries?start=10&end=12"); resp.StatusCode != 400 {
		t.Fatalf("start beyond the tree must be 400, got %d", resp.StatusCode)
	}
}

func TestFaultInjection(t *testing.T) {
	l := New(t, 8, Options{RateLimitEvery: 2, ShortReadEvery: 1, InvalidBase64Every: 1})
	resp, _ := get(t, l.URL+"ct/v1/get-entries?start=0&end=7") // request 1: served
	if resp.StatusCode != 200 {
		t.Fatalf("first request: %d", resp.StatusCode)
	}
	resp, _ = get(t, l.URL+"ct/v1/get-sth") // request 2: rate limited
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") != "1" {
		t.Fatalf("want 429 with Retry-After, got %d", resp.StatusCode)
	}
	_, body := get(t, l.URL+"ct/v1/get-entries?start=0&end=7") // request 3
	var we wireEntries
	json.Unmarshal(body, &we)
	if len(we.Entries) != 4 {
		t.Fatalf("short read should halve 8 entries to 4, got %d", len(we.Entries))
	}
	if we.Entries[0].LeafInput != "!!not-base64!!" {
		t.Fatal("invalid base64 not injected")
	}

	c := New(t, 4, Options{CorruptJSONEvery: 1})
	_, body = get(t, c.URL+"ct/v1/get-entries?start=0&end=3")
	if json.Valid(body) {
		t.Fatal("corrupt JSON not injected")
	}
}

func TestPublishAndAlter(t *testing.T) {
	l := New(t, 6, Options{AlterEntries: []uint64{1}})
	l.Publish(3)
	_, body := get(t, l.URL+"ct/v1/get-sth")
	if !bytes.Contains(body, []byte(`"tree_size":3`)) {
		t.Fatalf("published size not honoured: %s", body)
	}
	_, body = get(t, l.URL+"ct/v1/get-entries?start=0&end=5")
	var we wireEntries
	json.Unmarshal(body, &we)
	if len(we.Entries) != 3 {
		t.Fatalf("entries beyond the published size must not be served, got %d", len(we.Entries))
	}
	leaf, _ := base64.StdEncoding.DecodeString(we.Entries[1].LeafInput)
	if bytes.Equal(leaf, l.Entries[1].LeafInput) {
		t.Fatal("entry 1 should be served altered")
	}
	if l.Requests("get-entries") != 1 {
		t.Fatal("request counting is wrong")
	}
}
