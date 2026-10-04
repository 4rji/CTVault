package ctlogtest

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

func TestServerErrorEvery(t *testing.T) {
	l := New(t, 4, Options{ServerErrorEvery: 2})
	if resp, _ := get(t, l.URL+"ct/v1/get-sth"); resp.StatusCode != 200 {
		t.Fatalf("request 1: %d", resp.StatusCode)
	}
	resp, _ := get(t, l.URL+"ct/v1/get-entries?start=0&end=3")
	if resp.StatusCode != 503 || resp.Header.Get("Retry-After") != "" {
		t.Fatalf("request 2 must be a bare 503, got %d (Retry-After %q)", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
}

func TestNoRetryAfter(t *testing.T) {
	l := New(t, 4, Options{RateLimitEvery: 1, NoRetryAfter: true})
	resp, _ := get(t, l.URL+"ct/v1/get-sth")
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") != "" {
		t.Fatalf("want a 429 without Retry-After, got %d %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
}

// TestTruncateBodyEvery: the response promises more bytes than arrive, as
// when a connection drops mid-body.
func TestTruncateBodyEvery(t *testing.T) {
	l := New(t, 8, Options{TruncateBodyEvery: 1})
	resp, err := http.Get(l.URL + "ct/v1/get-entries?start=0&end=7")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("reading a cut body: %v, want unexpected EOF", err)
	}
}

// TestEntriesDelayCompletesOutOfOrder: with a delay on start=0 only, a later
// request for start=4 must finish first, as a real log under load can.
func TestEntriesDelayCompletesOutOfOrder(t *testing.T) {
	l := New(t, 8, Options{PageSize: 4, EntriesDelay: func(start uint64) time.Duration {
		if start == 0 {
			return 300 * time.Millisecond
		}
		return 0
	}})
	var mu sync.Mutex
	var order []string
	var wg sync.WaitGroup
	for _, start := range []string{"0", "4"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := l.srv.Client().Get(l.URL + "ct/v1/get-entries?start=" + start + "&end=7")
			if err != nil {
				t.Error(err)
				return
			}
			resp.Body.Close()
			mu.Lock()
			order = append(order, start)
			mu.Unlock()
		}()
		time.Sleep(20 * time.Millisecond) // start=0 is sent first
	}
	wg.Wait()
	if fmt.Sprint(order) != "[4 0]" {
		t.Fatalf("completion order %v, want [4 0]", order)
	}
}

func TestGetProofByHash(t *testing.T) {
	l := New(t, 13, Options{})
	sth := struct {
		Root string `json:"sha256_root_hash"`
	}{}
	_, body := get(t, l.URL+"ct/v1/get-sth")
	if err := json.Unmarshal(body, &sth); err != nil {
		t.Fatal(err)
	}
	root, _ := base64.StdEncoding.DecodeString(sth.Root)
	for _, idx := range []uint64{0, 6, 12} {
		lh := rfc6962.DefaultHasher.HashLeaf(l.Entries[idx].LeafInput)
		q := url.Values{"hash": {base64.StdEncoding.EncodeToString(lh)}, "tree_size": {"13"}}
		resp, body := get(t, l.URL+"ct/v1/get-proof-by-hash?"+q.Encode())
		if resp.StatusCode != 200 {
			t.Fatalf("leaf %d: status %d", idx, resp.StatusCode)
		}
		var p struct {
			LeafIndex uint64   `json:"leaf_index"`
			AuditPath []string `json:"audit_path"`
		}
		if err := json.Unmarshal(body, &p); err != nil {
			t.Fatal(err)
		}
		nodes := make([][]byte, len(p.AuditPath))
		for i, n := range p.AuditPath {
			nodes[i], _ = base64.StdEncoding.DecodeString(n)
		}
		if p.LeafIndex != idx {
			t.Fatalf("leaf_index %d, want %d", p.LeafIndex, idx)
		}
		if err := proof.VerifyInclusion(rfc6962.DefaultHasher, idx, 13, lh, nodes, root); err != nil {
			t.Fatalf("leaf %d: inclusion proof does not verify: %v", idx, err)
		}
	}
	lh := rfc6962.DefaultHasher.HashLeaf(l.Entries[9].LeafInput)
	q := url.Values{"hash": {base64.StdEncoding.EncodeToString(lh)}, "tree_size": {"5"}}
	if resp, _ := get(t, l.URL+"ct/v1/get-proof-by-hash?"+q.Encode()); resp.StatusCode != 404 {
		t.Fatalf("a leaf beyond tree_size must be 404, got %d", resp.StatusCode)
	}
}

// fatalRecorder stands in for testing.TB to observe Fatalf.
type fatalRecorder struct {
	testing.TB
	msg string
}

func (f *fatalRecorder) Fatalf(format string, args ...any) {
	f.msg = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

func TestForkOutsideLogFails(t *testing.T) {
	l := New(t, 4, Options{})
	rec := &fatalRecorder{TB: t}
	l.t = rec
	done := make(chan struct{})
	go func() {
		defer close(done)
		l.Fork(4)
	}()
	<-done
	if rec.msg == "" {
		t.Fatal("Fork(4) on a 4-entry log must fail the test")
	}
}

// withoutExtension re-encodes a TBSCertificate without the extension oid,
// keeping every other byte. It is the RFC 6962 §3.2 rule in its simplest form.
func withoutExtension(t *testing.T, tbs []byte, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(tbs, &seq); err != nil {
		t.Fatal(err)
	}
	var body []byte
	for rest := seq.Bytes; len(rest) > 0; {
		var el asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &el); err != nil {
			t.Fatal(err)
		}
		if el.Class != asn1.ClassContextSpecific || el.Tag != 3 {
			body = append(body, el.FullBytes...)
			continue
		}
		var exts asn1.RawValue
		if _, err := asn1.Unmarshal(el.Bytes, &exts); err != nil {
			t.Fatal(err)
		}
		var kept []byte
		for r := exts.Bytes; len(r) > 0; {
			var ext asn1.RawValue
			if r, err = asn1.Unmarshal(r, &ext); err != nil {
				t.Fatal(err)
			}
			var id asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(ext.Bytes, &id); err != nil {
				t.Fatal(err)
			}
			if !id.Equal(oid) {
				kept = append(kept, ext.FullBytes...)
			}
		}
		inner, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: kept})
		wrapped, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 3, IsCompound: true, Bytes: inner})
		body = append(body, wrapped...)
	}
	out, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
	return out
}

// TestPairTBSInvariant covers Plan 1 review minor 15: the generator must obey
// RFC 6962 §3.2 byte for byte, because the leaf decoder's precert checks are
// tested against it.
func TestPairTBSInvariant(t *testing.T) {
	g, err := NewGenerator()
	if err != nil {
		t.Fatal(err)
	}
	for name, viaSigner := range map[string]bool{"CA-issued": false, "signer-issued": true} {
		pre, fin, err := g.pair("inv.example.test", 5, viaSigner)
		if err != nil {
			t.Fatal(err)
		}
		pc, _ := x509.ParseCertificate(pre.CertDER)
		fc, _ := x509.ParseCertificate(fin.CertDER)
		if got := withoutExtension(t, fc.RawTBSCertificate, sctListOID); !bytes.Equal(got, pre.PrecertTBS) {
			t.Errorf("%s: final TBS without the SCT list must equal the log's TBS", name)
		}
		if pre.IssuerKeyHash != sha256.Sum256(g.ca.RawSubjectPublicKeyInfo) {
			t.Errorf("%s: issuer_key_hash must hash the final issuer's SPKI", name)
		}
		stripped := withoutExtension(t, pc.RawTBSCertificate, poisonOID)
		if viaSigner {
			if err := pc.CheckSignatureFrom(g.signer); err != nil {
				t.Errorf("%s: precert must be signed by the precert signer: %v", name, err)
			}
			if bytes.Equal(stripped, pre.PrecertTBS) {
				t.Errorf("%s: issuer and AKI must differ before the §3.2 rewrite", name)
			}
			continue
		}
		if !bytes.Equal(stripped, pre.PrecertTBS) {
			t.Errorf("%s: precert TBS without poison must equal the log's TBS", name)
		}
	}
	if err := g.signer.CheckSignatureFrom(g.ca); err != nil {
		t.Fatalf("signer must be certified by the CA: %v", err)
	}
	if len(g.signer.UnknownExtKeyUsage) != 1 || !g.signer.UnknownExtKeyUsage[0].Equal(precertSigningEKU) {
		t.Fatalf("signer EKU = %v, want the CT precert-signing EKU", g.signer.UnknownExtKeyUsage)
	}
}

func TestMalformedEntryIsServedAndHashed(t *testing.T) {
	g, err := NewGenerator()
	if err != nil {
		t.Fatal(err)
	}
	good, err := g.Entries(2)
	if err != nil {
		t.Fatal(err)
	}
	bad := MalformedEntry(7)
	l := NewWithEntries(t, append(good, bad), Options{})
	_, body := get(t, l.URL+"ct/v1/get-entries?start=2&end=2")
	var we wireEntries
	if err := json.Unmarshal(body, &we); err != nil || len(we.Entries) != 1 {
		t.Fatalf("entries: %v %s", err, body)
	}
	leaf, _ := base64.StdEncoding.DecodeString(we.Entries[0].LeafInput)
	if !bytes.Equal(leaf, bad.LeafInput) || leaf[0] != 1 {
		t.Fatal("the malformed leaf must be served byte for byte")
	}
	want := rfc6962.DefaultHasher.HashLeaf(bad.LeafInput)
	if got := l.honest.LeafHash(2); !bytes.Equal(got, want) {
		t.Fatal("the malformed leaf must be part of the Merkle tree")
	}
}
