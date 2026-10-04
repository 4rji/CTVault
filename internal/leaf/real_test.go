package leaf_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/4rji/ctvault/internal/leaf"
)

// TestRealArgonPage decodes 32 real argon2027h1 entries (indexes 380,000,000
// to 380,000,031, captured 2026-10-04). Every precert must pass issuer
// identification and both RFC 6962 cross-checks.
func TestRealArgonPage(t *testing.T) {
	b, err := os.ReadFile("../testdata/argon2027h1_entries_380000000.json")
	if err != nil {
		t.Fatal(err)
	}
	var page struct {
		Entries []struct {
			LeafInput string `json:"leaf_input"`
			ExtraData string `json:"extra_data"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(b, &page); err != nil {
		t.Fatal(err)
	}
	counts := map[leaf.Type]int{}
	for i, w := range page.Entries {
		li, err1 := base64.StdEncoding.DecodeString(w.LeafInput)
		ed, err2 := base64.StdEncoding.DecodeString(w.ExtraData)
		if err1 != nil || err2 != nil {
			t.Fatalf("entry %d: bad base64", i)
		}
		e := leaf.Decode(li, ed)
		if e.Code != leaf.OK {
			t.Errorf("entry %d (%s): code %q", 380000000+i, e.Type, e.Code)
		}
		if !e.HasIssuanceDigest || len(e.Chain) == 0 || e.CertDER == nil {
			t.Errorf("entry %d: missing digest, chain or certificate", 380000000+i)
		}
		counts[e.Type]++
	}
	if len(page.Entries) != 32 || counts[leaf.TypeX509] != 11 || counts[leaf.TypePrecert] != 21 {
		t.Fatalf("fixture has %d entries: %v; want 32 = 11 x509 + 21 precert", len(page.Entries), counts)
	}
}
