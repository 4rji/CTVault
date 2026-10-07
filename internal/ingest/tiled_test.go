package ingest

import (
	"bytes"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/loglist"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/logsource/tiled"
	"github.com/4rji/ctvault/internal/vaulttest"
)

// TestTiledEquivalence is amendment A6 §7.3's test: one fake log, serving one
// tree through both protocols, ingested into two vaults, once through RFC
// 6962 and once through tiles. The Parquet files, the vault segments, the
// index and the proofs recorded in the manifests are byte-identical.
func TestTiledEquivalence(t *testing.T) {
	es := entries(t, 1100)
	l := ctlogtest.NewWithEntries(t, es, ctlogtest.Options{Tiled: true})
	pub, _ := x509.ParsePKIXPublicKey(l.PublicKeyDER)
	info := logsource.LogInfo{Name: "fakelog", LogID: l.LogID, PublicKey: pub, URL: l.URL, Origin: l.Origin}

	vault := func(src logsource.LogSource, chains *logsource.ChainCache) *harness {
		h := newHarness(t, es[:1], ctlogtest.Options{}) // its own fake log is unused
		h.opts.VaultUUID = [16]byte{0xa6}
		h.opts.DictSamples = 300 // a dictionary trains, so it is compared too
		w := h.open()
		l.Publish(1000)
		sth, err := src.Head(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for first := uint64(0); first < 1000; first += 300 { // boundaries inside tiles
			if _, err := w.Batch(ctx, src, sth, first, min(first+300, 1000)); err != nil {
				t.Fatal(err)
			}
			chains.Reset()
		}
		return h
	}
	rc := logsource.NewChainCache(logsource.DefaultChainCacheBytes)
	rinfo := info
	rinfo.Kind = loglist.KindRFC6962
	rv := vault(rfc6962.NewSource(rinfo, nil, rc, nil), rc)
	tinfo := info
	tinfo.Kind = loglist.KindTiled
	tc := logsource.NewChainCache(logsource.DefaultChainCacheBytes)
	tsrc := tiled.NewSource(tinfo, nil, nil)
	tv := vault(tsrc, tc)

	rms, _ := commit.ListCommitted(rv.root)
	tms, _ := commit.ListCommitted(tv.root)
	if len(rms) != 4 || len(tms) != 4 {
		t.Fatalf("%d and %d batches", len(rms), len(tms))
	}
	for i := range rms {
		r, w := rms[i], tms[i]
		if len(r.Files) != len(w.Files) {
			t.Fatalf("batch %d: %d and %d files", i, len(r.Files), len(w.Files))
		}
		for name, f := range r.Files {
			if w.Files[name].SHA256 != f.SHA256 {
				t.Errorf("batch %d: %s differs", i, name)
			}
		}
		if r.Verified.Method != w.Verified.Method || len(r.Verified.Proof) != len(w.Verified.Proof) {
			t.Fatalf("batch %d: verified %+v and %+v", i, r.Verified, w.Verified)
		}
		for k := range r.Verified.Proof {
			if r.Verified.Proof[k] != w.Verified.Proof[k] {
				t.Errorf("batch %d: proof node %d differs", i, k)
			}
		}
	}
	// The vault: segments and dictionaries, byte for byte.
	for _, dir := range []string{"segments", "dict"} {
		names, _ := filepath.Glob(filepath.Join(rv.root, "vault", dir, "*"))
		if len(names) == 0 {
			t.Fatalf("no vault %s", dir)
		}
		for _, p := range names {
			a, _ := os.ReadFile(p)
			b, err := os.ReadFile(filepath.Join(tv.root, "vault", dir, filepath.Base(p)))
			if err != nil || !bytes.Equal(a, b) {
				t.Errorf("vault/%s/%s differs", dir, filepath.Base(p))
			}
		}
	}
	// The index and everything else a reader sees.
	rd := vaulttest.Vault{Root: rv.root, Dirs: rv.vaultDirs(), UUID: rv.opts.VaultUUID}.Dump(t)
	td := vaulttest.Vault{Root: tv.root, Dirs: tv.vaultDirs(), UUID: tv.opts.VaultUUID}.Dump(t)
	if d := vaulttest.Diff(td, rd); d != "" {
		t.Fatalf("the tiled vault differs: %s", d)
	}
	if c := tsrc.Counters(); c.IssuersFetched < 1 {
		t.Fatalf("counters %+v", c)
	}
}

// TestTiledQuarantineKeepsTheTileLeaf: a tiled entry with a leaf error is
// quarantined with its exact tile bytes (amendment A6 §3), and a
// leaf_index_mismatch still keeps its certificate (§3.2).
func TestTiledQuarantineKeepsTheTileLeaf(t *testing.T) {
	l := ctlogtest.NewWithEntries(t, entries(t, 20), ctlogtest.Options{Tiled: true, BadLeafIndex: []uint64{5}})
	pub, _ := x509.ParsePKIXPublicKey(l.PublicKeyDER)
	src := tiled.NewSource(logsource.LogInfo{Name: "fakelog", Kind: loglist.KindTiled, LogID: l.LogID, PublicKey: pub, URL: l.URL, Origin: l.Origin}, nil, nil)
	h := newHarness(t, entries(t, 1), ctlogtest.Options{}) // its own fake log is unused
	w := h.open()
	sth, err := src.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	m, err := w.Batch(ctx, src, sth, 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	if m.Counts.LeafErrors != 1 || m.Counts.NewCerts != 21 { // 20 entries and the CA
		t.Fatalf("counts %+v", m.Counts)
	}
	q, _ := os.ReadFile(filepath.Join(h.root, "dataset", "log=fakelog", "batch=000000000000-000000000019", commit.QuarantineFile))
	for _, want := range []string{`"idx":5`, `"leaf_error":"leaf_index_mismatch"`, `"tile_leaf":"`} {
		if !bytes.Contains(q, []byte(want)) {
			t.Fatalf("quarantine lacks %s: %s", want, q)
		}
	}
}
