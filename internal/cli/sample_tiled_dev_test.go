//go:build ctvault_dev

package cli

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/loglist"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/sample"
)

var tiledTestLimits = sample.Limits{Boundary: 256, Min: 256, Max: 1 << 20}

// TestTiledSampleCaptureVerifyMeasure: the dev CLI captures a tiled log
// named in the log list as a tiled sample, verifies it and measures it
// (amendment A6 §5).
func TestTiledSampleCaptureVerifyMeasure(t *testing.T) {
	l := ctlogtest.New(t, 1100, ctlogtest.Options{Tiled: true})
	l.Publish(1000)
	list := map[string]any{"version": "test", "log_list_timestamp": "2026-10-06T00:00:00Z",
		"operators": []any{map[string]any{"name": "Test", "tiled_logs": []any{map[string]any{
			"description": "Test 'fakelog' log", "log_id": base64.StdEncoding.EncodeToString(l.LogID[:]),
			"key": base64.StdEncoding.EncodeToString(l.PublicKeyDER), "submission_url": "https://" + l.Origin + "/",
			"monitoring_url": l.URL, "mmd": 60,
			"state": map[string]any{"usable": map[string]any{"timestamp": "2026-01-01T00:00:00Z"}}}}}}}
	b, _ := json.Marshal(list)
	listPath := filepath.Join(t.TempDir(), "log_list.json")
	os.WriteFile(listPath, b, 0o644)
	e := newEnv(t, nil)
	e.deps.HTTP = &http.Client{}
	e.deps.LogListSource = listPath
	e.deps.DevBase = t.TempDir()
	t.Cleanup(func() { makeTreeWritable(e.deps.DevBase) })
	e.deps.Statfs = func(string) (diskguard.Usage, error) {
		return diskguard.Usage{Total: 1 << 40, Avail: 1 << 39, Dev: 1}, nil
	}
	old := sampleTiledLimits
	sampleTiledLimits = tiledTestLimits
	t.Cleanup(func() { sampleTiledLimits = old })

	if code := e.run("sample", "capture", "--log", "fakelog", "--entries", "700"); code != exitcode.Usage || !strings.Contains(e.stderr.String(), "multiple of 256") {
		t.Fatalf("a count that is not whole tiles: exit %d, %s", code, e.stderr)
	}
	out := e.mustRun("sample", "capture", "--log", "fakelog", "--entries", "768")
	dir := filepath.Join(e.deps.DevBase, "samples", "fakelog", "000000000000-000000000767")
	if !strings.Contains(out, "captured and verified canonical sample fakelog/000000000000-000000000767") ||
		!strings.Contains(out, "files      3 data tiles, 5 hash tiles, 1 issuers") || strings.Contains(out, "(0 B per entry") {
		t.Fatalf("capture output: %s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "tile", "data", "002")); err != nil {
		t.Fatalf("the sample does not mirror the data tiles: %v", err)
	}
	if out := e.mustRun("sample", "verify", dir); !strings.Contains(out, "verified canonical sample") {
		t.Fatalf("verify output: %s", out)
	}
	out = e.mustRun("sample", "measure", dir, "--batch-size", "256")
	if !strings.Contains(out, "report") {
		t.Fatalf("measure output: %s", out)
	}
}

func makeTreeWritable(dir string) {
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			os.Chmod(p, 0o755)
		}
		return nil
	})
}

// TestTiledReplay: update --replay ingests a tiled sample through the tiled
// source from the mirror alone, with any batch size (amendment A6 §5).
func TestTiledReplay(t *testing.T) {
	l := ctlogtest.New(t, 1100, ctlogtest.Options{Tiled: true})
	l.Publish(1000)
	pub, _ := x509.ParsePKIXPublicKey(l.PublicKeyDER)
	info := logsource.LogInfo{Name: "fakelog", Kind: loglist.KindTiled, LogID: l.LogID, PublicKey: pub, URL: l.URL, Origin: l.Origin}
	dir := t.TempDir()
	t.Cleanup(func() { makeTreeWritable(dir) })
	s, err := sample.CaptureTiled(context.Background(), dir, info, nil, sample.CaptureOptions{Kind: sample.Canonical, Count: 768,
		Limits: tiledTestLimits, Key: base64.StdEncoding.EncodeToString(l.PublicKeyDER), Version: "test",
		Fetch: fetch.Options{MaxRPS: 1000, MinBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	e := devVaultTiled(t, l, 300) // batch ends inside tiles
	before := l.Requests("all")
	e.mustRun("--root", e.root, "update", "--replay", s.Dir)
	if ms := committed(t, e.root); len(ms) != 3 || ms[2].Last != 767 {
		t.Fatalf("768 entries in batches of 300: %d batches", len(ms))
	}
	if l.Requests("all") != before {
		t.Fatalf("the replay reached the live fake: %d requests", l.Requests("all")-before)
	}
	e.mustRun("--root", e.root, "verify", "--full")

	r := devVault(t, l, 300) // pinned as RFC 6962
	if code := r.run("--root", r.root, "update", "--replay", s.Dir); code != exitcode.Usage || !strings.Contains(r.stderr.String(), "tiled") {
		t.Fatalf("a tiled sample into an RFC 6962 pin: exit %d, %s", code, r.stderr)
	}
}

// devVaultTiled is devVault with the fake pinned as a tiled log.
func devVaultTiled(t *testing.T, l *ctlogtest.Log, batchSize int) *env {
	t.Helper()
	e := devVault(t, l, batchSize)
	os.Remove(filepath.Join(e.root, "state", "logs", "fakelog.json"))
	pinFakeTiled(t, e.root, l)
	return e
}
