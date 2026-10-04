//go:build ctvault_dev

package cli

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/sample"
)

// sampleEnv points the dev CLI at a fake log named "fakelog" through a log
// list naming it, with sample limits small enough for a 120-entry log.
func sampleEnv(t *testing.T, used float64) (*env, *ctlogtest.Log) {
	t.Helper()
	l := ctlogtest.New(t, 120, ctlogtest.Options{PageSize: 4})
	list := map[string]any{"version": "test", "log_list_timestamp": "2026-10-04T00:00:00Z",
		"operators": []any{map[string]any{"name": "Test", "logs": []any{map[string]any{
			"description": "Test 'fakelog' log", "log_id": base64.StdEncoding.EncodeToString(l.LogID[:]),
			"key": base64.StdEncoding.EncodeToString(l.PublicKeyDER), "url": l.URL, "mmd": 86400,
			"state": map[string]any{"usable": map[string]any{"timestamp": "2026-01-01T00:00:00Z"}}}}}}}
	b, _ := json.Marshal(list)
	listPath := filepath.Join(t.TempDir(), "log_list.json")
	os.WriteFile(listPath, b, 0o644)

	e := newEnv(t, nil)
	e.deps.HTTP = &http.Client{}
	e.deps.LogListSource = listPath
	e.deps.DevBase = t.TempDir()
	t.Cleanup(func() {
		filepath.WalkDir(e.deps.DevBase, func(p string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				os.Chmod(p, 0o755)
			}
			return nil
		})
	})
	const total = 1 << 40
	e.deps.Statfs = func(string) (diskguard.Usage, error) {
		return diskguard.Usage{Total: total, Avail: uint64((1 - used) * total), Dev: 1}, nil
	}
	old := sampleLimits
	sampleLimits = sample.Limits{Boundary: 8, Min: 16, Max: 96}
	t.Cleanup(func() { sampleLimits = old })
	return e, l
}

func TestSampleCaptureAndVerify(t *testing.T) {
	e, _ := sampleEnv(t, 0.5)
	out := e.mustRun("sample", "capture", "--log", "fakelog", "--entries", "48")
	dir := filepath.Join(e.deps.DevBase, "samples", "fakelog", "000000000000-000000000047")
	if !strings.Contains(out, "captured and verified canonical sample fakelog/000000000000-000000000047") || !strings.Contains(out, dir) {
		t.Fatalf("capture output: %s", out)
	}
	if !strings.Contains(e.stderr.String(), "fetched 48 / 48 entries") {
		t.Fatalf("progress: %s", e.stderr)
	}
	if out := e.mustRun("sample", "verify", dir); !strings.Contains(out, "verified canonical sample") {
		t.Fatalf("verify output: %s", out)
	}
	if code := e.run("sample", "capture", "--log", "fakelog", "--entries", "48"); code != exitcode.Error || !strings.Contains(e.stderr.String(), "already exists") {
		t.Fatalf("an existing sample: exit %d, %s", code, e.stderr)
	}
	out = e.mustRun("sample", "capture", "--log", "fakelog", "--entries", "32", "--start", "head")
	if !strings.Contains(out, "representative sample fakelog/000000000088-000000000119") {
		t.Fatalf("--start head: %s", out)
	}
}

// TestSampleCaptureCreatesTheDevBase: on a fresh machine ~/.cache/ctvault-dev
// does not exist yet. The first capture must create it rather than fail its
// disk check, which stats the folder.
func TestSampleCaptureCreatesTheDevBase(t *testing.T) {
	e, _ := sampleEnv(t, 0.5)
	fake := e.deps.Statfs
	home := t.TempDir()
	t.Cleanup(func() { // runs before home's removal: published samples are read-only
		filepath.WalkDir(home, func(p string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				os.Chmod(p, 0o755)
			}
			return nil
		})
	})
	e.deps.DevBase = filepath.Join(home, ".cache", "ctvault-dev")
	e.deps.Statfs = func(p string) (diskguard.Usage, error) { // like statfs(2): a missing path fails
		if _, err := os.Stat(p); err != nil {
			return diskguard.Usage{}, err
		}
		return fake(p)
	}
	e.mustRun("sample", "capture", "--log", "fakelog", "--entries", "16")
	if _, err := os.Stat(filepath.Join(e.deps.DevBase, "samples", "fakelog", "000000000000-000000000015", sample.ManifestFile)); err != nil {
		t.Fatalf("the sample must be published under the new dev base: %v", err)
	}
}

func TestSampleCaptureRefusals(t *testing.T) {
	e, l := sampleEnv(t, 0.5)
	for _, tc := range []struct {
		args []string
		code int
	}{
		{[]string{"--log", "fakelog", "--entries", "20"}, exitcode.Usage},
		{[]string{"--log", "fakelog", "--entries", "16", "--start", "abc"}, exitcode.Usage},
		{[]string{"--entries", "16"}, exitcode.Usage},
		{[]string{"--log", "nosuchlog", "--entries", "16"}, exitcode.Error},
	} {
		if code := e.run(append([]string{"sample", "capture"}, tc.args...)...); code != tc.code {
			t.Errorf("%v: exit %d, want %d (%s)", tc.args, code, tc.code, e.stderr)
		}
	}
	if l.Requests("all") != 0 {
		t.Fatal("refused captures must not contact the log")
	}
}

func TestSampleCaptureRespectsTheDiskCap(t *testing.T) {
	e, l := sampleEnv(t, 0.86) // the normal disk is already above the 85% cap
	if code := e.run("sample", "capture", "--log", "fakelog", "--entries", "16"); code != exitcode.DiskCap || !strings.Contains(e.stderr.String(), "disk cap") {
		t.Fatalf("exit %d, want %d: %s", code, exitcode.DiskCap, e.stderr)
	}
	if l.Requests("get-entries") != 0 {
		t.Fatal("nothing is fetched after a refused preflight")
	}
	if names, _ := filepath.Glob(filepath.Join(e.deps.DevBase, "samples", "fakelog", "*")); len(names) != 0 {
		t.Fatalf("nothing may be left behind: %v", names)
	}
}

func TestSampleVerifyRefusesDamage(t *testing.T) {
	e, _ := sampleEnv(t, 0.5)
	e.mustRun("sample", "capture", "--log", "fakelog", "--entries", "16")
	dir := filepath.Join(e.deps.DevBase, "samples", "fakelog", "000000000000-000000000015")
	os.Chmod(dir, 0o755)
	p := filepath.Join(dir, sample.EntriesFile)
	os.Chmod(p, 0o644)
	b, _ := os.ReadFile(p)
	b[len(b)/2] ^= 1
	os.WriteFile(p, b, 0o644)
	if code := e.run("sample", "verify", dir); code != exitcode.Verification {
		t.Fatalf("a damaged sample: exit %d, want %d: %s", code, exitcode.Verification, e.stderr)
	}
}

func TestSampleVerifyRefusesAPartialCopy(t *testing.T) {
	e, _ := sampleEnv(t, 0.5)
	e.mustRun("sample", "capture", "--log", "fakelog", "--entries", "16")
	dir := filepath.Join(e.deps.DevBase, "samples", "fakelog", "000000000000-000000000015")
	os.Chmod(dir, 0o755)
	os.Remove(filepath.Join(dir, sample.ProofsFile))
	if code := e.run("sample", "verify", dir); code != exitcode.Verification {
		t.Fatalf("a sample missing %s: exit %d, want %d: %s", sample.ProofsFile, code, exitcode.Verification, e.stderr)
	}
}
