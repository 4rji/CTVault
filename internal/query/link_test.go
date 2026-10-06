package query_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/diskguard"
	. "github.com/4rji/ctvault/internal/query"
)

// TestLinked: a final leads to its precert and a precert to its final,
// through delta_base_cert_id when the final is a leaf-delta and through the
// issuance key otherwise (amendment A4 §3).
func TestLinked(t *testing.T) {
	g, es := entriesWithSigner(t, 40)
	// All precerts first, then all finals, with a one-entry delta cache:
	// most finals are stored in full, so the issuance-key path is used.
	var pre, fin []ctlogtest.Entry
	for i, e := range es {
		if i%2 == 0 {
			pre = append(pre, e)
		} else {
			fin = append(fin, e)
		}
	}
	for _, c := range []struct {
		name string
		es   []ctlogtest.Entry
		lru  int
	}{{"leaf-delta", es, 1000}, {"issuance key", append(append([]ctlogtest.Entry(nil), pre...), fin...), 1}} {
		v := newTestVaultLRU(t, g, c.es, 20, c.lru)
		s, _ := Open(v.root, 0)
		sess, _ := NewSession(v.root, diskguard.Guard{Cap: 0.85, Stat: freeDisk})
		f, err := NewFetcher(s, sess, v.dirs)
		if err != nil {
			t.Fatal(err)
		}
		deltas := 0
		for i := 0; i < len(pre); i++ {
			p, err := f.BySHA256(ctx, sha256.Sum256(pre[i].CertDER))
			if err != nil {
				t.Fatal(err)
			}
			fc, err := f.BySHA256(ctx, sha256.Sum256(fin[i].CertDER))
			if err != nil {
				t.Fatal(err)
			}
			if fc.Row["delta_base_cert_id"] != nil {
				deltas++
			}
			if got, err := f.Linked(ctx, fc); err != nil || got == nil || !bytes.Equal(got.DER, p.DER) {
				t.Fatalf("%s: final %d → %v (%v), want its precert", c.name, i, got, err)
			}
			if got, err := f.Linked(ctx, p); err != nil || got == nil || !bytes.Equal(got.DER, fc.DER) {
				t.Fatalf("%s: precert %d → %v (%v), want its final", c.name, i, got, err)
			}
		}
		if c.name == "issuance key" && deltas > 2 || c.name == "leaf-delta" && deltas == 0 {
			t.Fatalf("%s: %d of %d finals are leaf-deltas", c.name, deltas, len(fin))
		}
		ca, _ := f.BySHA256(ctx, sha256.Sum256(g.CADER()))
		if got, err := f.Linked(ctx, ca); err != nil || got != nil {
			t.Fatalf("a chain certificate has no link: %v %v", got, err)
		}
		f.Close()
		sess.Close()
	}
}
