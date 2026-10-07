package tiled

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/loglist"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/merkle"
)

var ctx = context.Background()

func info(t *testing.T, l *ctlogtest.Log) logsource.LogInfo {
	t.Helper()
	pub, err := x509.ParsePKIXPublicKey(l.PublicKeyDER)
	if err != nil {
		t.Fatal(err)
	}
	return logsource.LogInfo{Name: "fakelog", Kind: loglist.KindTiled, LogID: l.LogID, PublicKey: pub, URL: l.URL, Origin: l.Origin}
}

func tiledLog(t *testing.T, n int, o ctlogtest.Options) (*ctlogtest.Log, *Source) {
	t.Helper()
	o.Tiled = true
	l := ctlogtest.New(t, n, o)
	return l, NewSource(info(t, l), nil, nil)
}

// TestSameEntriesAsRFC6962: the fake serves one tree both ways; every entry
// read from tiles equals the RFC 6962 source's, field by field, and the
// proofs from tiles equal get-sth-consistency's (amendment A6 §3, §4.1).
func TestSameEntriesAsRFC6962(t *testing.T) {
	l, src := tiledLog(t, 600, ctlogtest.Options{})
	ref := rfc6962.NewSource(info(t, l), nil, logsource.NewChainCache(1<<20), nil)
	l.Publish(517) // two full tiles and a partial of width 5
	h, err := src.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rh, err := ref.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if h.TreeSize != 517 || h.RootHash != rh.RootHash || h.Timestamp != rh.Timestamp {
		t.Fatalf("checkpoint %+v, get-sth %+v", h.SignedTreeHead, rh.SignedTreeHead)
	}
	if !bytes.HasPrefix(h.Raw, []byte(l.Origin+"\n517\n")) {
		t.Fatalf("Raw is not the checkpoint: %q", h.Raw)
	}
	var got []logsource.RawEntry
	for next := uint64(0); next < 517; {
		es, err := src.Fetch(ctx, next, 517)
		if err != nil {
			t.Fatal(err)
		}
		if len(es) == 0 || len(es) > Width {
			t.Fatalf("Fetch(%d) returned %d entries", next, len(es))
		}
		got = append(got, es...)
		next += uint64(len(es))
	}
	for i, e := range got {
		r, err := ref.Fetch(ctx, uint64(i), uint64(i)+1)
		if err != nil {
			t.Fatal(err)
		}
		w := r[0]
		if e.Index != uint64(i) || !bytes.Equal(e.LeafInput, w.LeafInput) || !bytes.Equal(e.ExtraData, w.ExtraData) ||
			e.Leaf.LeafHash != w.Leaf.LeafHash || e.Leaf.Code != leaf.OK || w.Leaf.Code != leaf.OK || len(e.Chain) != len(w.Chain) {
			t.Fatalf("entry %d differs: tiled %+v, rfc6962 %+v", i, e.Leaf, w.Leaf)
		}
		for k := range e.Chain {
			if e.Chain[k] != w.Chain[k] {
				t.Fatalf("entry %d chain %d differs", i, k)
			}
		}
		if len(e.TileLeaf) == 0 || e.Size() != len(e.LeafInput)+len(e.ExtraData)+len(e.TileLeaf) {
			t.Fatalf("entry %d: TileLeaf %d bytes, Size %d", i, len(e.TileLeaf), e.Size())
		}
	}
	for _, p := range [][2]uint64{{1, 517}, {255, 517}, {256, 517}, {300, 517}, {516, 517}} {
		a, err := src.ConsistencyProof(ctx, p[0], p[1])
		if err != nil {
			t.Fatal(err)
		}
		b, err := ref.ConsistencyProof(ctx, p[0], p[1])
		if err != nil {
			t.Fatal(err)
		}
		if len(a) != len(b) {
			t.Fatalf("proof %v: %d nodes, get-sth-consistency %d", p, len(a), len(b))
		}
		for i := range a {
			if a[i] != b[i] {
				t.Fatalf("proof %v: node %d differs", p, i)
			}
		}
	}
	// Two issuers in the fake (the CA and the precert signer is unused
	// here): each fetched once, however many entries name it.
	if c := src.Counters(); c.IssuersFetched != int64(l.Requests("issuer")) || c.IssuersFetched < 1 || c.IssuersFetched > 2 {
		t.Fatalf("counters %+v, issuer requests %d", c, l.Requests("issuer"))
	}
}

// TestPartialFallback: a partial tile the log has deleted is read from the
// full tile (amendment A6 §4.2), for data and for proofs.
func TestPartialFallback(t *testing.T) {
	l, src := tiledLog(t, 600, ctlogtest.Options{})
	l.Publish(300)
	if _, err := src.Head(ctx); err != nil {
		t.Fatal(err)
	}
	l.Publish(600) // tile 1 is now full; its partial of width 44 is gone
	es, err := src.Fetch(ctx, 256, 300)
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 44 || es[0].Index != 256 {
		t.Fatalf("%d entries from %d", len(es), es[0].Index)
	}
	if _, err := src.ConsistencyProof(ctx, 100, 300); err != nil {
		t.Fatal(err)
	}
	if c := src.Counters(); c.PartialFallbacks < 2 {
		t.Fatalf("counters %+v: the data tile and a hash tile fell back", c)
	}
}

// TestHeadFaults: checkpoint faults map to the classes of amendment A6 §2.
func TestHeadFaults(t *testing.T) {
	for fault, want := range map[string]error{
		ctlogtest.WrongOrigin:   merkle.ErrBadSignature,
		ctlogtest.NoKeyLine:     merkle.ErrBadSignature,
		ctlogtest.TwoKeyLines:   merkle.ErrBadSignature,
		ctlogtest.ExtensionLine: logsource.ErrMalformed,
	} {
		_, src := tiledLog(t, 10, ctlogtest.Options{CheckpointFault: fault})
		h, err := src.Head(ctx)
		if !errors.Is(err, want) {
			t.Errorf("%s: got %v, want %v", fault, err, want)
		}
		if len(h.Raw) == 0 {
			t.Errorf("%s: the raw checkpoint is kept for incident evidence", fault)
		}
	}
	_, src := tiledLog(t, 10, ctlogtest.Options{BadSTHSignature: true})
	if _, err := src.Head(ctx); !errors.Is(err, merkle.ErrBadSignature) {
		t.Errorf("a bad signature: got %v", err)
	}
	l, src := tiledLog(t, 10, ctlogtest.Options{})
	if _, err := src.Head(ctx); err != nil {
		t.Fatal(err)
	}
	l.Publish(5)
	if _, err := src.Head(ctx); !errors.Is(err, logsource.ErrIncident) {
		t.Errorf("a shrinking tree: got %v", err)
	}
}

// TestFetchFaults: tile and issuer faults and their classes (A6 §3.3, §2.1).
func TestFetchFaults(t *testing.T) {
	isStatus := func(code int) func(error) bool {
		return func(err error) bool {
			var he *logsource.HTTPError
			return errors.As(err, &he) && he.Status == code
		}
	}
	isMalformed := func(err error) bool { return errors.Is(err, logsource.ErrMalformed) }
	cases := map[string]struct {
		o    ctlogtest.Options
		want func(error) bool
	}{
		"cut data tile":         {ctlogtest.Options{CutDataTileEvery: 1}, isMalformed},
		"issuer wrong bytes":    {ctlogtest.Options{IssuerWrongBytes: true}, isMalformed},
		"issuer missing":        {ctlogtest.Options{Missing: func(p string) bool { return strings.HasPrefix(p, "/issuer/") }}, isStatus(404)},
		"tile and partial gone": {ctlogtest.Options{Missing: func(p string) bool { return strings.HasPrefix(p, "/tile/data/") }}, isStatus(404)},
		"redirect":              {ctlogtest.Options{RedirectTiles: true}, isStatus(http.StatusFound)},
		"rate limited":          {ctlogtest.Options{RateLimitEvery: 2}, func(err error) bool { return errors.Is(err, logsource.ErrRateLimited) }},
	}
	for name, c := range cases {
		_, src := tiledLog(t, 20, c.o)
		var err error
		for k := 0; k < 3 && err == nil; k++ { // RateLimitEvery: 2 lets the checkpoint through
			if _, err = src.Head(ctx); err == nil {
				_, err = src.Fetch(ctx, 0, 20)
			}
		}
		if err == nil || !c.want(err) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	_, src := tiledLog(t, 20, ctlogtest.Options{GzipData: true})
	if _, err := src.Head(ctx); err != nil {
		t.Fatal(err)
	}
	if es, err := src.Fetch(ctx, 0, 20); err != nil || len(es) != 20 {
		t.Fatalf("gzip data tile: %d entries, %v", len(es), err)
	}
	l, src := tiledLog(t, 300, ctlogtest.Options{BadHashTile: true})
	h, err := src.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ref := rfc6962.NewSource(info(t, l), nil, logsource.NewChainCache(1<<20), nil)
	es, _ := ref.Fetch(ctx, 0, 32)
	st := merkle.NewState()
	for _, e := range es {
		st.Append(e.Leaf.LeafHash)
	}
	root, _ := st.Root()
	p, err := src.ConsistencyProof(ctx, 32, h.TreeSize)
	if err == nil {
		err = merkle.VerifyConsistency(32, h.TreeSize, root, h.RootHash, p)
	}
	if err == nil {
		t.Fatal("a wrong hash tile gave a proof that verifies")
	}
}

// TestLeafIndex: a missing or wrong leaf_index is leaf_index_mismatch, and
// the certificate is kept (amendment A6 §3.2).
func TestLeafIndex(t *testing.T) {
	_, src := tiledLog(t, 6, ctlogtest.Options{BadLeafIndex: []uint64{2}, NoLeafIndex: []uint64{4}})
	if _, err := src.Head(ctx); err != nil {
		t.Fatal(err)
	}
	es, err := src.Fetch(ctx, 0, 6)
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range es {
		want := leaf.OK
		if i == 2 || i == 4 {
			want = leaf.LeafIndexMismatch
		}
		if e.Leaf.Code != want || e.Leaf.CertDER == nil {
			t.Errorf("entry %d: code %q, certificate kept %v", i, e.Leaf.Code, e.Leaf.CertDER != nil)
		}
	}
}

// TestIssuerConcurrency: at most IssuerConcurrency issuer requests run at
// once, and each fingerprint is fetched once however many ask for it.
func TestIssuerConcurrency(t *testing.T) {
	l, src := tiledLog(t, 4, ctlogtest.Options{})
	if _, err := src.Head(ctx); err != nil {
		t.Fatal(err)
	}
	es, err := src.Fetch(ctx, 0, 4)
	if err != nil {
		t.Fatal(err)
	}
	before := l.Requests("issuer")
	for i := 0; i < 8; i++ {
		if _, err := src.Issuer(ctx, es[0].Chain[0]); err != nil {
			t.Fatal(err)
		}
	}
	if l.Requests("issuer") != before {
		t.Fatalf("a cached issuer was fetched again")
	}
	// The bound itself: resolve many distinct fingerprints against a server
	// that counts concurrent requests.
	peak := issuerPeak(t, 40)
	if peak > IssuerConcurrency || peak < 2 {
		t.Fatalf("peak %d concurrent issuer requests, bound %d", peak, IssuerConcurrency)
	}
}
