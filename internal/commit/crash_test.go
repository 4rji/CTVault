package commit_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/ingest"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/vault"
	"github.com/4rji/ctvault/internal/vaulttest"
)

// The crash suite (spec §13.5) runs the real writer in a subprocess, the
// test binary itself running TestCrashChild, and kills it with SIGKILL: at
// a named boundary, through the hook, or at a random moment. After every
// kill the parent checks what readers would see, recovers the vault the way
// the next start does, and checks the invariants again.

// childEnv names the file that tells TestCrashChild what to do. Only the
// crash tests set it, in the subprocesses they start.
const childEnv = "CTVAULT_CRASH_CHILD"

var crashUUID = [16]byte{0xc7, 0x5a, 0x01}

// crashConfig is what a crash child needs.
type crashConfig struct {
	Root      string
	LogURL    string
	PublicKey []byte // SPKI
	End       uint64
	BatchSize uint64
	KillAt    string // a hook point; "" runs to the end
	KillNth   int    // die the nth time KillAt fires
	Mode      string // "" ingests; "rebuild" or "reindex" runs that instead
	NoDerived bool   // ingest without derived files, as Plan 2 did
}

// options is the writer configuration of every crash test: small segments
// so batches roll over, and a small dictionary sample so a run trains.
func options(root string, hook func(string)) ingest.Options {
	cfg := config.Default()
	cfg.Ingest.DeltaLRUEntries = 1000
	cfg.Vault.SegmentSize = 16 << 10
	free := func(string) (diskguard.Usage, error) {
		return diskguard.Usage{Total: 1 << 40, Avail: 1 << 39, Dev: 1}, nil
	}
	return ingest.Options{Root: root, VaultDirs: []string{filepath.Join(root, "vault")}, VaultUUID: crashUUID, Config: cfg,
		Guard: diskguard.Guard{Cap: 0.85, Stat: free}, Version: "crash-test", Out: io.Discard, Hook: hook,
		DictSamples: 60, CanarySamples: 16,
		Fetch: fetch.Options{MaxRPS: 1000, MinBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond}}
}

// TestCrashChild is not a test of its own: in a subprocess it ingests the
// fake log into the vault, and kills itself at the configured point.
func TestCrashChild(t *testing.T) {
	p := os.Getenv(childEnv)
	if p == "" {
		t.Skip("run by the crash tests in a subprocess")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var c crashConfig
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	fired := 0
	hook := func(point string) {
		if point == c.KillAt {
			if fired++; fired == c.KillNth {
				syscall.Kill(os.Getpid(), syscall.SIGKILL)
				time.Sleep(time.Hour)
			}
		}
	}
	if c.Mode == "reindex" {
		reindexChild(t, c.Root, hook)
		return
	}
	o := options(c.Root, hook)
	o.NoDerived = c.NoDerived
	w, err := ingest.Open(o)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if c.Mode == "rebuild" {
		if _, err := w.Rebuild(context.Background()); err != nil {
			t.Fatal(err)
		}
		return
	}
	pub, err := x509.ParsePKIXPublicKey(c.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	chains := logsource.NewChainCache(logsource.DefaultChainCacheBytes)
	src := rfc6962.NewSource(logsource.LogInfo{Name: "fakelog", LogID: sha256.Sum256(c.PublicKey), PublicKey: pub, URL: c.LogURL}, nil, chains, nil)
	ctx := context.Background()
	sth, err := src.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for first := w.Next("fakelog"); first < c.End; {
		end := min(first+c.BatchSize, c.End)
		if _, err := w.Batch(ctx, src, sth, first, end); err != nil {
			t.Fatal(err)
		}
		chains.Reset()
		first = end
	}
}

// crashRun is one vault under the crash suite.
type crashRun struct {
	t       *testing.T
	v       vaulttest.Vault
	cfg     crashConfig
	ids     map[uint64][32]byte // every cert_id assignment seen, over all attempts
	dropped map[uint64]bool     // cert_ids of records recovery truncated
	seen    map[string][]byte   // every committed batch's _COMMIT.json
}

func newCrashRun(t *testing.T, l *ctlogtest.Log, end, batch uint64) *crashRun {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"state/intent", "state/incidents", "state/logs", "vault/segments", "vault/dict", "dataset", "tmp/stage", "tmp/rebuild"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return &crashRun{t: t, v: vaulttest.Vault{Root: root, Dirs: []string{filepath.Join(root, "vault")}, UUID: crashUUID},
		cfg: crashConfig{Root: root, LogURL: l.URL, PublicKey: l.PublicKeyDER, End: end, BatchSize: batch},
		ids: map[uint64][32]byte{}, dropped: map[uint64]bool{}, seen: map[string][]byte{}}
}

// child runs a crash child. With killAt set it must die there; with after
// set it is killed after that long unless it finishes first. It reports
// whether the child was killed.
func (r *crashRun) child(killAt string, nth int, after time.Duration) bool {
	r.t.Helper()
	cfg := r.cfg
	cfg.KillAt, cfg.KillNth = killAt, nth
	b, _ := json.Marshal(cfg)
	p := filepath.Join(r.t.TempDir(), "child.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		r.t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), childEnv+"="+p)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		r.t.Fatal(err)
	}
	if after > 0 {
		timer := time.AfterFunc(after, func() { cmd.Process.Signal(syscall.SIGKILL) })
		defer timer.Stop()
	}
	err := cmd.Wait()
	var ee *exec.ExitError
	if err == nil {
		return false
	}
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() && ws.Signal() == syscall.SIGKILL {
			return true
		}
	}
	r.t.Fatalf("the crash child failed: %v\n%s", err, out.String())
	return false
}

// restart checks the vault as a kill left it (no partial batch visible,
// nothing committed lost, no cert_id reused), recovers it as the next start
// does, and checks spec §13.5's invariants on the result.
func (r *crashRun) restart() {
	t := r.t
	t.Helper()
	committed := r.v.Committed(t)
	for dir, b := range r.seen {
		if !bytes.Equal(committed[dir], b) {
			t.Fatalf("committed batch %s was lost or changed", dir)
		}
	}
	r.seen = committed
	beyond := r.v.BeyondTail(t)
	for id, sha := range r.v.Assignments(t) {
		if prev, ok := r.ids[id]; ok && prev != sha {
			t.Fatalf("cert_id %d was reused for a different certificate", id)
		}
		if _, now := beyond[id]; !now && r.dropped[id] {
			t.Fatalf("cert_id %d belonged to a record recovery truncated, and was committed later (spec §8.6: IDs are never reused)", id)
		}
		r.ids[id] = sha
	}
	for id := range beyond {
		r.dropped[id] = true
	}
	w, err := ingest.Open(options(r.v.Root, nil))
	if err != nil {
		t.Fatalf("recovery: %v", err)
	}
	w.Close()
	r.v.CheckRecovered(t)
}

// clean ingests the whole log in a child that is never killed and returns
// its content and how long the child took. The content holds derived rows
// for every certificate an entry references (amendment A2 §4), so the
// comparisons below cover the derived files too.
func clean(t *testing.T, l *ctlogtest.Log, end, batch uint64) (vaulttest.Content, time.Duration) {
	t.Helper()
	r := newCrashRun(t, l, end, batch)
	start := time.Now()
	if r.child("", 0, 0) {
		t.Fatal("the clean child was killed")
	}
	took := time.Since(start)
	r.restart()
	c := r.v.Dump(t)
	for _, es := range c.Entries {
		for _, e := range es {
			if _, ok := c.Certs[e.Cert]; e.Cert != "" && !ok {
				t.Fatalf("entry %d: certificate %s has no derived rows", e.Idx, e.Cert)
			}
		}
	}
	return c, took
}

const (
	crashEntries = 240
	crashBatch   = 40
)

// TestCrashAtEveryBoundary kills the writer at each named boundary of spec
// §13.5, mostly in the second batch, then lets a new run finish: the result
// must equal a clean ingest except for cert_id and chain_id (amendment A1
// §7). The ACTIVE.json and rebuild boundaries arrive with Plans 3 and 6.
func TestCrashAtEveryBoundary(t *testing.T) {
	if testing.Short() {
		t.Skip("starts about 40 subprocesses")
	}
	l := ctlogtest.New(t, crashEntries, ctlogtest.Options{})
	want, _ := clean(t, l, crashEntries, crashBatch)
	for _, b := range []struct {
		point string
		nth   int
	}{
		{commit.HookAfterIntent, 2},
		{vault.HookAppendMidRecord, 60},
		{vault.HookRolloverBeforeHeader, 3},
		{vault.HookRolloverAfterHeader, 3},
		{vault.HookRolloverBeforeDirSync, 3},
		{commit.HookIDFloorBeforeAdvance, 1},
		{commit.HookIDFloorAfterAdvance, 1},
		{ingest.HookAfterVaultSync, 2},
		{ingest.HookDuringCanary, 2},
		{commit.HookAfterManifest, 2},
		{commit.HookBeforeRename, 2},
		{commit.HookAfterRename, 2},
		{ingest.HookBeforePebble, 2},
		{ingest.HookAfterPebble, 2},
		{commit.HookBeforeIntentDelete, 2},
		{ingest.HookDuringAudit, 2}, // P11: the batch stays committed
	} {
		t.Run(b.point, func(t *testing.T) {
			r := newCrashRun(t, l, crashEntries, crashBatch)
			if !r.child(b.point, b.nth, 0) {
				t.Fatalf("the child finished without reaching %s #%d", b.point, b.nth)
			}
			r.restart()
			if r.child("", 0, 0) {
				t.Fatal("the second run was killed")
			}
			r.restart()
			if d := vaulttest.Diff(r.v.Dump(t), want); d != "" {
				t.Fatalf("the recovered ingest differs from a clean one: %s", d)
			}
		})
	}
}

// TestRandomKillLoop kills the writer at random moments, killLoopRuns times
// (25 by default, 200 with -tags nightly). Each kill is followed by the
// recovery checks; every ingest that runs to the end must equal a clean one.
func TestRandomKillLoop(t *testing.T) {
	if testing.Short() {
		t.Skip("starts many subprocesses")
	}
	l := ctlogtest.New(t, crashEntries, ctlogtest.Options{})
	want, took := clean(t, l, crashEntries, crashBatch)
	seed := uint64(time.Now().UnixNano())
	t.Logf("seed %d; a clean ingest takes %v", seed, took)
	rnd := rand.New(rand.NewPCG(seed, 1))
	r := newCrashRun(t, l, crashEntries, crashBatch)
	kills, complete := 0, 0
	for range killLoopRuns {
		if r.child("", 0, time.Duration(rnd.Int64N(int64(took)))+time.Millisecond) {
			kills++
			r.restart()
			continue
		}
		r.restart()
		if d := vaulttest.Diff(r.v.Dump(t), want); d != "" {
			t.Fatalf("seed %d: an ingest that survived %d kills differs from a clean one: %s", seed, kills, d)
		}
		complete++
		r = newCrashRun(t, l, crashEntries, crashBatch)
	}
	for r.child("", 0, 0) {
	}
	r.restart()
	if d := vaulttest.Diff(r.v.Dump(t), want); d != "" {
		t.Fatalf("seed %d: the last ingest differs from a clean one: %s", seed, d)
	}
	t.Logf("%d runs: %d kills, %d ingests completed and compared", killLoopRuns, kills, complete+1)
}
