//go:build ctvault_dev

package cli

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/sample"
	"github.com/4rji/ctvault/internal/volume"
	"github.com/4rji/ctvault/internal/volume/volumetest"
)

var sampleTestLimits = sample.Limits{Boundary: 8, Min: 16, Max: 96}

// captureFake captures a sample of the fake log with frames of 8 entries.
func captureFake(t *testing.T, l *ctlogtest.Log, kind sample.Kind, start, count uint64) *sample.Sample {
	t.Helper()
	pub, _ := x509.ParsePKIXPublicKey(l.PublicKeyDER)
	info := logsource.LogInfo{Name: "fakelog", LogID: l.LogID, PublicKey: pub, URL: l.URL}
	src := rfc6962.NewSource(info, nil, logsource.NewChainCache(logsource.DefaultChainCacheBytes), nil)
	dir := t.TempDir()
	t.Cleanup(func() {
		filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				os.Chmod(p, 0o755)
			}
			return nil
		})
	})
	s, err := sample.Capture(context.Background(), dir, src, sample.CaptureOptions{Kind: kind, Start: start, Count: count,
		Limits: sampleTestLimits, Key: base64.StdEncoding.EncodeToString(l.PublicKeyDER), LogListVersion: "test", Version: "test",
		Fetch: fetch.Options{MaxRPS: 1000, MinBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// devVault creates a dev vault on a fake ext4 mount, with batch_size set.
func devVault(t *testing.T, l *ctlogtest.Log, batchSize int) *env {
	t.Helper()
	e := newEnv(t, nil)
	p := volumetest.New()
	base := p.Mount(t, t.TempDir(), "ext4", "8:33", "dev-uuid")
	e.deps.Volumes = volume.DevProbe{Base: base, Probe: p, Now: e.deps.Now}
	e.deps.HTTP = &http.Client{}
	e.deps.Statfs = freeDisk
	e.root = filepath.Join(base, "vaults", "v1")
	e.mustRun("init", e.root)
	if b, _ := os.ReadFile(filepath.Join(e.root, config.FileName)); !strings.Contains(string(b), "batch_size = 10000") {
		t.Fatalf("a dev vault starts with 10,000-entry batches (amendment A1 §2.5): %s", b)
	}
	cfg := "[ingest]\nbatch_size = " + itoa(batchSize) + "\ndelta_lru_entries = 1000\n[vault]\nsegment_size = \"1MiB\"\n"
	os.WriteFile(filepath.Join(e.root, config.FileName), []byte(cfg), 0o644)
	pinFake(t, e.root, l)
	return e
}

func itoa(n int) string {
	b := []byte{}
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func TestReplayIngestsACanonicalSample(t *testing.T) {
	l := ctlogtest.New(t, 120, ctlogtest.Options{PageSize: 4})
	s := captureFake(t, l, sample.Canonical, 0, 48)
	e := devVault(t, l, 16)
	before := l.Requests("get-entries")
	out := e.mustRun("--root", e.root, "update", "--replay", s.Dir)
	ms := committed(t, e.root)
	if len(ms) != 3 || ms[2].Last != 47 || ms[2].Verified.Method != "consistency_proof" {
		t.Fatalf("48 sampled entries in 3 verified batches: %d batches; %s", len(ms), out)
	}
	if l.Requests("get-entries") != before {
		t.Fatal("replay must not contact the live log")
	}
	if out := e.mustRun("--root", e.root, "update", "--replay", s.Dir); !strings.Contains(out, "up to date at index 48") {
		t.Fatalf("the replay ends at the sample's end: %s", out)
	}
}

func TestReplayRefusals(t *testing.T) {
	l := ctlogtest.New(t, 120, ctlogtest.Options{PageSize: 4})
	canonical := captureFake(t, l, sample.Canonical, 0, 48)
	representative := captureFake(t, l, sample.Representative, 16, 32)
	other := ctlogtest.New(t, 10, ctlogtest.Options{})
	for name, tc := range map[string]struct {
		batch  int
		pinned *ctlogtest.Log
		args   []string
	}{
		"representative sample": {16, l, []string{"--replay", representative.Dir}},
		"batch size off grid":   {20, l, []string{"--replay", canonical.Dir}},
		"until past the sample": {16, l, []string{"--replay", canonical.Dir, "--until", "56"}},
		"until off grid":        {16, l, []string{"--replay", canonical.Dir, "--until", "20"}},
		"another log's sample":  {16, other, []string{"--replay", canonical.Dir}},
	} {
		e := devVault(t, tc.pinned, tc.batch)
		if code := e.run(append([]string{"--root", e.root, "update"}, tc.args...)...); code != exitcode.Usage {
			t.Errorf("%s: exit %d, want 2: %s", name, code, e.stderr)
		}
		if len(committed(t, e.root)) != 0 {
			t.Errorf("%s: nothing may be committed", name)
		}
	}
}
