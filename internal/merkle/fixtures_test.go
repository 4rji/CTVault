package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

// The real fixtures in internal/testdata were captured from Chrome's log list
// and argon2027h1 on 2026-10-04. They are immutable: tests must never depend
// on the live log, whose answers change every few seconds. This guard fails if
// any fixture's bytes change; a deliberate new capture goes in a new file with
// its hash added here in the same commit (see internal/testdata/README.md).
var fixtureSHA256 = map[string]string{
	"log_list_google.json":               "852484a68c18c2eed06211af22148bbb6ca3cb6cfed142dccc31839943e40d19",
	"log_list_v93.3_full.json":           "d23ab4cd867239b3ff227d52eb9d60210fbd5eb0c66ab2b6d2bded8e6852d406",
	"argon2027h1_sth1.json":              "32b707ce8a1287e2d4c4b5fe51f531521d27c23fc578b8c9c4c67c8421cdbf65",
	"argon2027h1_sth2.json":              "6d8d1a6c4ead1dd4053bf0b35c8a8ee05240f97af58982147ef79500827c3db0",
	"argon2027h1_consistency.json":       "182aae03ee72d97002c78250f8830e65bfae66e059d5effc1c26e386b6c0740a",
	"argon2027h1_entries_380000000.json": "708399c3400262347d1dd0831e44a8575444073d7ef72df0d4f03c1abb2cc5f4",
}

func TestFixturesAreUnchanged(t *testing.T) {
	for name, want := range fixtureSHA256 {
		b, err := os.ReadFile("../testdata/" + name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s changed: sha256 %s, want %s; fixtures are immutable (internal/testdata/README.md)", name, got, want)
		}
	}
}
