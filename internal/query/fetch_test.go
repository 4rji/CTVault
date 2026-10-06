package query_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	. "github.com/4rji/ctvault/internal/query"
	"os"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/vault"
)

// fetchVault is 60 entries, plus the first final certificate logged again
// with a second chain (signer, CA).
func fetchVault(t *testing.T) (*testVault, []byte) {
	t.Helper()
	g, es := entriesWithSigner(t, 60)
	final := es[1].CertDER
	again := ctlogtest.Entry{Type: ctlogtest.X509Entry, Timestamp: 1790000999000, CertDER: final}
	again.LeafInput = ctlogtest.MerkleTreeLeaf(again.Timestamp, ctlogtest.X509Entry, final, [32]byte{})
	again.ExtraData = ctlogtest.Chain(g.SignerDER(), g.CADER())
	es = append(es, again)
	return newTestVault(t, g, es, 20), final
}

func newFetcher(t *testing.T, v *testVault) *Fetcher {
	t.Helper()
	s, err := Open(v.root, 0)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := NewSession(v.root, diskguard.Guard{Cap: 0.85, Stat: freeDisk})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sess.Close() })
	f, err := NewFetcher(s, sess, v.dirs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Close)
	return f
}

// TestFetch: a certificate is fetched by SHA-256 and by cert_id, byte-exact,
// with its certs row; an absent one is ErrNotFound (amendment A3 §4.1).
func TestFetch(t *testing.T) {
	v, final := fetchVault(t)
	f := newFetcher(t, v)
	sha := sha256.Sum256(final)
	c, err := f.BySHA256(ctx, sha)
	if err != nil || !bytes.Equal(c.DER, final) || c.Row["kind"] != "final" || c.CertID == 0 {
		t.Fatalf("by SHA-256: %+v %v", c, err)
	}
	byID, err := f.ByCertID(ctx, c.CertID)
	if err != nil || !bytes.Equal(byID.DER, final) || byID.SHA256 != sha {
		t.Fatalf("by cert_id %d: %v", c.CertID, err)
	}
	if _, err := f.BySHA256(ctx, sha256.Sum256([]byte("absent"))); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an absent certificate: %v", err)
	}
	if _, err := f.ByCertID(ctx, 1<<40); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an absent cert_id: %v", err)
	}
	names, err := f.Names(ctx, c)
	if err != nil || len(names) != 2 || names[0]["name"] != "host0.example.test" {
		t.Fatalf("names: %v %v", names, err)
	}
	dump := Dump(c)
	for _, s := range []string{"sha256:", "kind:       final", "parse:      ok", "dns names:  host0.example.test, www.host0.example.test", "CTVault Test CA"} {
		if !strings.Contains(dump, s) {
			t.Errorf("the text dump lacks %q:\n%s", s, dump)
		}
	}
}

// TestFetchChainsAndEntries: --with-chain gives every distinct chain the log
// served with the certificate, in order of first appearance;
// --with-entries lists the entries that reference it (amendment A3 §4.3).
func TestFetchChainsAndEntries(t *testing.T) {
	v, final := fetchVault(t)
	f := newFetcher(t, v)
	c, err := f.BySHA256(ctx, sha256.Sum256(final))
	if err != nil {
		t.Fatal(err)
	}
	chains, err := f.Chains(ctx, c.CertID)
	if err != nil || len(chains) != 2 || len(chains[0]) != 1 || len(chains[1]) != 2 {
		t.Fatalf("chains %v, %v", chains, err)
	}
	ca, err := f.ByCertID(ctx, chains[0][0])
	if err != nil || !bytes.Equal(ca.DER, v.gen.CADER()) || ca.Row["kind"] != "chain" {
		t.Fatalf("the chain's CA: %v", err)
	}
	signer, _ := f.ByCertID(ctx, chains[1][0])
	if !bytes.Equal(signer.DER, v.gen.SignerDER()) || chains[1][1] != chains[0][0] {
		t.Fatalf("the second chain is not signer, CA: %v", chains[1])
	}
	es, err := f.Entries(ctx, c.CertID)
	if err != nil || len(es) != 2 || es[0].Log != "fakelog" || es[0].Idx != 1 || es[1].Idx != 60 || es[0].EntryType != "x509" {
		t.Fatalf("entries %+v, %v", es, err)
	}
	if chains, _ := f.Chains(ctx, ca.CertID); len(chains) != 0 {
		t.Fatalf("a chain certificate has no chain of its own: %v", chains)
	}
}

// TestFetchVerifies: a vault record that no longer decodes to its SHA-256
// is corruption, never returned (amendment A3 §4.1).
func TestFetchVerifies(t *testing.T) {
	v, final := fetchVault(t)
	f := newFetcher(t, v)
	c, err := f.BySHA256(ctx, sha256.Sum256(final))
	if err != nil {
		t.Fatal(err)
	}
	segs, _ := vault.FindSegments(v.dirs)
	fh, _ := os.OpenFile(segs[c.Loc.Segment], os.O_RDWR, 0)
	b := make([]byte, 1)
	at := int64(c.Loc.Offset) + int64(c.Loc.Len) - 6
	fh.ReadAt(b, at)
	b[0] ^= 0xff
	fh.WriteAt(b, at)
	fh.Close()
	if _, err := newFetcher(t, v).BySHA256(ctx, sha256.Sum256(final)); !errors.Is(err, vault.ErrCorrupt) {
		t.Fatalf("a corrupted record: %v", err)
	}
}

// TestFetchNeedsCompleteTables: a vault still building certs refuses fetch.
func TestFetchNeedsCompleteTables(t *testing.T) {
	v, _ := fetchVault(t)
	derive.WriteActive(v.root, derive.Upgrading())
	s, _ := Open(v.root, 0)
	sess, _ := NewSession(v.root, diskguard.Guard{Cap: 0.85, Stat: freeDisk})
	defer sess.Close()
	if _, err := NewFetcher(s, sess, v.dirs); !errors.Is(err, ErrBuilding) {
		t.Fatalf("fetch while certs is building: %v", err)
	}
}

// TestLocate: Locate finds the certs row fetch would read, without the
// vault.
func TestLocate(t *testing.T) {
	v, final := fetchVault(t)
	f := newFetcher(t, v)
	sha := sha256.Sum256(final)
	row, err := f.Locate(ctx, sha)
	c, _ := f.BySHA256(ctx, sha)
	if err != nil || row["cert_id"] != c.CertID {
		t.Fatalf("Locate: %v %v", row, err)
	}
	if _, err := f.Locate(ctx, sha256.Sum256([]byte("absent"))); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absent: %v", err)
	}
}
