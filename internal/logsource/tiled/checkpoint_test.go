package tiled

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/merkle"
)

const testOrigin = "ct.example.test/log"

type testKey struct {
	key   *ecdsa.PrivateKey
	logID [32]byte
}

func newTestKey(t *testing.T) testKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return testKey{k, sha256.Sum256(spki)}
}

// sigLine is the pinned key's signature line for size and root.
func (k testKey) sigLine(t *testing.T, origin string, size uint64, root [32]byte) string {
	ts := uint64(1791346973252)
	in := binary.BigEndian.AppendUint64([]byte{0, 1}, ts)
	in = binary.BigEndian.AppendUint64(in, size)
	in = append(in, root[:]...)
	d := sha256.Sum256(in)
	sig, err := ecdsa.SignASN1(rand.Reader, k.key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	id := KeyID(origin, k.logID)
	body := binary.BigEndian.AppendUint64(id[:], ts)
	body = append(body, 4, 3)
	body = binary.BigEndian.AppendUint16(body, uint16(len(sig)))
	body = append(body, sig...)
	return "— " + origin + " " + base64.StdEncoding.EncodeToString(body) + "\n"
}

func otherLine(name string, n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return "— " + name + " " + base64.StdEncoding.EncodeToString(b) + "\n"
}

// TestParseCheckpoint: every rule of amendment A6 §2, as a table. A
// readable note without one signature line from the pinned key is a bad
// signature; anything unreadable is malformed.
func TestParseCheckpoint(t *testing.T) {
	k := newTestKey(t)
	root := sha256.Sum256([]byte("root"))
	rootB64 := base64.StdEncoding.EncodeToString(root[:])
	text := fmt.Sprintf("%s\n1234\n%s\n", testOrigin, rootB64)
	key := k.sigLine(t, testOrigin, 1234, root)
	good := text + "\n" + key + otherLine(testOrigin, 68) + otherLine("witness.example/w", 76)

	sth, err := ParseCheckpoint([]byte(good), testOrigin, k.logID)
	if err != nil {
		t.Fatal(err)
	}
	if sth.TreeSize != 1234 || sth.RootHash != root || sth.Timestamp != 1791346973252 {
		t.Fatalf("parsed %+v", sth)
	}
	if err := merkle.VerifySTH(&k.key.PublicKey, sth); err != nil {
		t.Fatalf("the signature body must be the DigitallySigned VerifySTH checks: %v", err)
	}
	if _, err := ParseCheckpoint([]byte(text+"\n"+otherLine("witness.example/w", 76)+key), testOrigin, k.logID); err != nil {
		t.Fatalf("the pinned key's line may come anywhere: %v", err)
	}

	// The same name with another key ID is another key: ignored.
	wrongIDBytes, _ := base64.StdEncoding.DecodeString(strings.Fields(key)[2])
	wrongIDBytes[0] ^= 1
	wrongID := "— " + testOrigin + " " + base64.StdEncoding.EncodeToString(wrongIDBytes) + "\n"
	nonCanonical := strings.Replace(key, "=\n", "\n", 1)
	if nonCanonical == key { // no padding to drop: break canonicity another way
		nonCanonical = strings.TrimSuffix(key, "\n") + "=\n"
	}
	many := ""
	for i := 0; i < MaxSignatureLines; i++ {
		many += otherLine("witness.example/w", 76)
	}
	id := KeyID(testOrigin, k.logID)
	short := "— " + testOrigin + " " + base64.StdEncoding.EncodeToString(append(id[:], 1, 2, 3)) + "\n"
	keyBytes, _ := base64.StdEncoding.DecodeString(strings.Fields(key)[2])
	trailing := "— " + testOrigin + " " + base64.StdEncoding.EncodeToString(append(keyBytes, 0)) + "\n"
	cases := map[string]struct {
		note string
		want error
	}{
		"not UTF-8":                 {text + "\n" + key + "\xff\n", logsource.ErrMalformed},
		"control character":         {strings.Replace(good, "1234", "12\t34", 1), logsource.ErrMalformed},
		"no final newline":          {strings.TrimSuffix(good, "\n"), logsource.ErrMalformed},
		"no blank line":             {text + key, logsource.ErrMalformed},
		"no signature lines":        {text + "\n", logsource.ErrMalformed},
		"bad signature line":        {text + "\n" + key + "-- " + testOrigin + " AAAA\n", logsource.ErrMalformed},
		"non-canonical base64":      {text + "\n" + nonCanonical, logsource.ErrMalformed},
		"too many signatures":       {text + "\n" + key + many, logsource.ErrMalformed},
		"two text lines":            {testOrigin + "\n1234\n\n" + key, logsource.ErrMalformed},
		"an extension line":         {text + "ext\n\n" + key, logsource.ErrMalformed},
		"leading zero":              {strings.Replace(good, "\n1234\n", "\n01234\n", 1), logsource.ErrMalformed},
		"short root":                {strings.Replace(good, rootB64, "AAAA", 1), logsource.ErrMalformed},
		"body too short":            {text + "\n" + short, logsource.ErrMalformed},
		"bytes after the signature": {text + "\n" + trailing, logsource.ErrMalformed},
		"another origin":            {strings.Replace(good, testOrigin+"\n1234", "ct.example.test/other\n1234", 1), merkle.ErrBadSignature},
		"no line from the key":      {text + "\n" + otherLine(testOrigin, 68) + wrongID, merkle.ErrBadSignature},
		"two lines from the key":    {text + "\n" + key + key, merkle.ErrBadSignature},
	}
	for name, c := range cases {
		_, err := ParseCheckpoint([]byte(c.note), testOrigin, k.logID)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
	// The size of a 0 tree is "0".
	zero := fmt.Sprintf("%s\n0\n%s\n\n", testOrigin, rootB64) + k.sigLine(t, testOrigin, 0, root)
	if sth, err := ParseCheckpoint([]byte(zero), testOrigin, k.logID); err != nil || sth.TreeSize != 0 {
		t.Errorf("an empty tree: %+v, %v", sth, err)
	}
}
