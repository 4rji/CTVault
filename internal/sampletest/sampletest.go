// Package sampletest gives tests the real-data samples cached by
// "ctvault-dev sample capture" (amendment A1 §2.5). It is test
// infrastructure: production binaries never import it.
package sampletest

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/logsource/sources"
	"github.com/4rji/ctvault/internal/sample"
)

// Base is <home>/.cache/ctvault-dev/samples, where the dev build captures
// samples (the same home lookup as volume.DefaultDevBase: the OS user
// database, not $HOME).
func Base(t testing.TB) string {
	t.Helper()
	u, err := user.Current()
	if err != nil || u.HomeDir == "" {
		t.Skipf("no home directory to look for samples in: %v", err)
	}
	return filepath.Join(u.HomeDir, ".cache", "ctvault-dev", "samples")
}

func dirs(t testing.TB, log string) []string {
	t.Helper()
	names, _ := filepath.Glob(filepath.Join(Base(t), log, "*"))
	var out []string
	for _, n := range names {
		if fi, err := os.Stat(n); err == nil && fi.IsDir() && !strings.HasPrefix(filepath.Base(n), ".") {
			out = append(out, n)
		}
	}
	return out
}

// Canonical opens, and so fully verifies, the canonical sample of log. The
// test is skipped with instructions when none is cached; a cached sample
// that fails verification fails the test.
func Canonical(t testing.TB, log string) *sample.Sample {
	t.Helper()
	for _, d := range dirs(t, log) {
		if !strings.HasPrefix(filepath.Base(d), "000000000000-") {
			continue
		}
		s, err := sample.Open(d)
		if err != nil {
			t.Fatalf("cached sample %s: %v", d, err)
		}
		return s
	}
	t.Skipf("no canonical sample of %s in %s; capture one with:\n  ctvault-dev sample capture --log %s --entries 100000", log, Base(t), log)
	return nil
}

// Representatives opens every cached representative sample of log.
func Representatives(t testing.TB, log string) []*sample.Sample {
	t.Helper()
	var out []*sample.Sample
	for _, d := range dirs(t, log) {
		if strings.HasPrefix(filepath.Base(d), "000000000000-") {
			continue
		}
		s, err := sample.Open(d)
		if err != nil {
			t.Fatalf("cached sample %s: %v", d, err)
		}
		out = append(out, s)
	}
	return out
}

// Serve replays s on loopback for the rest of the test and returns the
// production RFC 6962 Source reading it, keyed with the sample's pinned key.
func Serve(t testing.TB, s *sample.Sample) *rfc6962.Source {
	t.Helper()
	url, stop, err := sample.Serve(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	der, _ := base64.StdEncoding.DecodeString(s.Manifest.Log.Key)
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	info := logsource.LogInfo{Name: s.Manifest.Log.Name, LogID: s.LogIDBytes(), PublicKey: pub, URL: url}
	return rfc6962.NewSource(info, nil, logsource.NewChainCache(logsource.DefaultChainCacheBytes), nil)
}

// Source replays s on loopback for the rest of the test and returns the
// production source reading it, by the sample's protocol: RFC 6962, or tiled
// (amendment A6 §5). Its last accepted head is the sample's own.
func Source(t testing.TB, s *sample.Sample) logsource.LogSource {
	t.Helper()
	url, stop, err := sample.Serve(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	head := s.SignedHead()
	src, err := sources.Open(s.LogInfo(url), nil, logsource.NewChainCache(logsource.DefaultChainCacheBytes), &head)
	if err != nil {
		t.Fatal(err)
	}
	return src
}
