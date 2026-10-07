package cli

import (
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/loglist"
	"github.com/4rji/ctvault/internal/logreg"
)

// pinFakeTiled pins a fake log in tiled mode as "fakelog", as logs add pins
// a tiled log: kind, monitoring prefix, submission URL and origin.
func pinFakeTiled(t *testing.T, root string, l *ctlogtest.Log) {
	t.Helper()
	r := logreg.Record{Name: "fakelog", Kind: loglist.KindTiled, URL: l.URL, SubmissionURL: "https://" + l.Origin + "/", Origin: l.Origin,
		LogID: base64.StdEncoding.EncodeToString(l.LogID[:]), Key: base64.StdEncoding.EncodeToString(l.PublicKeyDER),
		State: "usable", PinnedAt: time.Unix(0, 0).UTC()}
	if err := logreg.Add(root, r); err != nil {
		t.Fatal(err)
	}
}

// tiledEnv is updateEnv for a fake log read through tiles.
func tiledEnv(t *testing.T, n int, lo ctlogtest.Options) (*env, *ctlogtest.Log) {
	t.Helper()
	lo.Tiled = true
	e := newEnv(t, nil)
	l := ctlogtest.New(t, n, lo)
	e.deps.HTTP = &http.Client{}
	e.deps.Statfs = freeDisk
	e.mustRun("init", e.root)
	cfg := "[ingest]\nbatch_size = 100\nfollow_interval = \"1s\"\ndelta_lru_entries = 1000\n[vault]\nsegment_size = \"1MiB\"\n"
	if err := os.WriteFile(filepath.Join(e.root, config.FileName), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	pinFakeTiled(t, e.root, l)
	old := headRetryDelay
	headRetryDelay = 10 * time.Millisecond
	t.Cleanup(func() { headRetryDelay = old })
	return e, l
}

// TestTiledUpdate: a tiled log is ingested, followed past a partial tile and
// verified like an RFC 6962 one; the cycle line counts issuers and partial
// tiles read from full ones (amendment A6 §6).
func TestTiledUpdate(t *testing.T) {
	e, l := tiledEnv(t, 600, ctlogtest.Options{})
	l.Publish(300)
	out := e.mustRun("--root", e.root, "update")
	if ms := committed(t, e.root); len(ms) != 3 || ms[2].Last != 299 {
		t.Fatalf("300 entries in batches of 100: %d batches", len(ms))
	}
	if !strings.Contains(out, "signed tree size 300 verified") || !strings.Contains(out, "fakelog: 1 issuers fetched, 0 partial tiles read from full tiles") {
		t.Fatalf("output: %s", out)
	}
	if l.Requests("get-entries") != 0 || l.Requests("get-sth") != 0 {
		t.Fatal("a tiled log is read through tiles only")
	}
	if n := l.Requests("data"); n != 4 { // tile 0 for [0,100) [100,200) [200,256), tile 1 for [256,300)
		t.Fatalf("%d data tile requests, want 4 (one per tile and batch)", n)
	}
	l.Publish(600)
	out = e.mustRun("--root", e.root, "update")
	if ms := committed(t, e.root); ms[len(ms)-1].Last != 599 || !strings.Contains(out, "signed tree size 600 verified") {
		t.Fatalf("the follow-up run: %s", out)
	}
	if out := e.mustRun("--root", e.root, "verify", "--full"); !strings.Contains(out, "sth signatures") {
		t.Fatalf("verify --full: %s", out)
	}
	if out := e.mustRun("--root", e.root, "stats"); !strings.Contains(out, "log fakelog (tiled, usable") {
		t.Fatalf("stats: %s", out)
	}
	out = e.mustRun("--root", e.root, "logs", "info", "fakelog")
	if !strings.Contains(out, "tree_size  600") || !strings.Contains(out, "signature  verified with pinned key") {
		t.Fatalf("logs info: %s", out)
	}
}

// TestTiledIncidents: a checkpoint that is not the pinned log's is an
// incident, with the raw checkpoint as evidence (amendment A6 §2).
func TestTiledIncidents(t *testing.T) {
	for _, o := range []ctlogtest.Options{{BadSTHSignature: true}, {CheckpointFault: ctlogtest.WrongOrigin}, {CheckpointFault: ctlogtest.NoKeyLine}} {
		e, _ := tiledEnv(t, 100, o)
		if code := e.run("--root", e.root, "update"); code != exitcode.Verification {
			t.Fatalf("%+v: exit %d, want 5: %s", o, code, e.stderr)
		}
		inc, _ := os.ReadDir(filepath.Join(e.root, "state", "incidents"))
		if len(inc) != 1 {
			t.Fatalf("%+v: incidents %v", o, inc)
		}
		b, _ := os.ReadFile(filepath.Join(e.root, "state", "incidents", inc[0].Name(), "incident.json"))
		if !strings.Contains(string(b), `"got_raw"`) {
			t.Fatalf("%+v: the incident lacks the raw checkpoint: %s", o, b)
		}
		if code := e.run("--root", e.root, "logs", "info", "fakelog"); code != exitcode.Verification {
			t.Fatalf("%+v: logs info exit %d, want 5", o, code)
		}
	}
	// A wrong hash tile gives a proof that fails against the signed head:
	// the batch is not committed, and the run stops with exit 5.
	e, l := tiledEnv(t, 300, ctlogtest.Options{BadHashTile: true})
	if code := e.run("--root", e.root, "update"); code != exitcode.Verification {
		t.Fatalf("a wrong hash tile: exit %d, want 5: %s", code, e.stderr)
	}
	if ms := committed(t, e.root); len(ms) != 0 || l.Requests("tile") == 0 {
		t.Fatalf("%d batches committed, %d hash tile requests", len(ms), l.Requests("tile"))
	}
}

// TestTiledFollowKeepsItsIssuers: under --follow, a tiled log's issuer cache
// lasts the whole run, not one cycle (amendment A6 §3.1): the fake's one
// issuer is fetched once over two cycles that both read tiles, and each
// cycle's line counts only its own fetches.
func TestTiledFollowKeepsItsIssuers(t *testing.T) {
	e, l := tiledEnv(t, 600, ctlogtest.Options{})
	l.Publish(300)
	done := make(chan int, 1)
	go func() { done <- e.run("--root", e.root, "update", "--follow") }()
	wait := func(last uint64) {
		for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			if ms, _ := commit.ListCommitted(e.root); len(ms) > 0 && ms[len(ms)-1].Last >= last {
				return
			}
		}
		t.Fatalf("timed out waiting for entry %d", last)
	}
	wait(299)
	l.Publish(600)
	wait(599)
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d: %s", code, e.stderr)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("update --follow did not stop")
	}
	if n := l.Requests("issuer"); n != 1 {
		t.Fatalf("the issuer was fetched %d times in one run", n)
	}
	out := e.stdout.String()
	if !strings.Contains(out, "fakelog: 1 issuers fetched") || !strings.Contains(out, "fakelog: 0 issuers fetched") {
		t.Fatalf("per-cycle counters:\n%s", out)
	}
}
