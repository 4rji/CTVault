package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/exitcode"
)

// TestFetchCommand: fetch by SHA-256 or cert_id in every format, with the
// chain and the entries; usage errors exit 2 and absent certificates exit 1
// (amendment A3 §4).
func TestFetchCommand(t *testing.T) {
	e, l := updateEnv(t, 80, ctlogtest.Options{})
	e.mustRun("--root", e.root, "update")
	final := l.Entries[1].CertDER
	sha := sha256.Sum256(final)
	hexsha := hex.EncodeToString(sha[:])

	out := e.mustRun("--root", e.root, "fetch", hexsha)
	if blk, _ := pem.Decode([]byte(out)); blk == nil || blk.Type != "CERTIFICATE" || !bytes.Equal(blk.Bytes, final) {
		t.Fatalf("pem: %q", out)
	}
	if out := e.mustRun("--root", e.root, "fetch", hexsha, "--format", "der"); out != string(final) {
		t.Fatal("der: not the exact bytes")
	}
	var j struct {
		CertID  uint64              `json:"cert_id"`
		SHA256  string              `json:"sha256"`
		Kind    string              `json:"kind"`
		Names   []map[string]any    `json:"names"`
		Chains  [][]json.RawMessage `json:"chains"`
		Entries []struct {
			Log string `json:"log"`
			Idx uint64 `json:"idx"`
		} `json:"entries"`
	}
	raw := e.mustRun("--root", e.root, "fetch", hexsha, "--format", "json", "--with-chain", "--with-entries")
	if err := json.Unmarshal([]byte(raw), &j); err != nil {
		t.Fatalf("json: %v\n%s", err, raw)
	}
	if j.SHA256 != hexsha || j.Kind != "final" || len(j.Names) != 2 || len(j.Chains) != 1 || len(j.Chains[0]) != 1 ||
		len(j.Entries) != 1 || j.Entries[0].Idx != 1 {
		t.Fatalf("json: %s", raw)
	}
	if out := e.mustRun("--root", e.root, "fetch", strconv.FormatUint(j.CertID, 10), "--format", "text"); !strings.Contains(out, hexsha) {
		t.Fatalf("text by cert_id: %s", out)
	}
	if out := e.mustRun("--root", e.root, "fetch", hexsha, "--with-chain"); strings.Count(out, "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("pem with its chain: %s", out)
	}
	dst := filepath.Join(t.TempDir(), "c.der")
	e.mustRun("--root", e.root, "fetch", hexsha, "--format", "der", "--output", dst)
	if b, err := os.ReadFile(dst); err != nil || !bytes.Equal(b, final) {
		t.Fatalf("--output: %v", err)
	}
	for _, c := range []struct {
		args []string
		code int
	}{
		{[]string{"fetch", hexsha, "--output", dst}, exitcode.Error}, // exists, no --force
		{[]string{"fetch", "nothex"}, exitcode.Usage},
		{[]string{"fetch", hexsha, "--format", "der", "--with-chain"}, exitcode.Usage},
		{[]string{"fetch", hexsha, "--format", "xml"}, exitcode.Usage},
		{[]string{"fetch", hexsha, "--format", "em"}, exitcode.Usage},
		{[]string{"fetch", strings.Repeat("ab", 32)}, exitcode.Error},
		{[]string{"fetch", "99999999"}, exitcode.Error},
	} {
		if code := e.run(append([]string{"--root", e.root}, c.args...)...); code != c.code {
			t.Errorf("%v: exit %d, want %d (%s)", c.args, code, c.code, e.stderr)
		}
	}
}
