package cli

import (
	"encoding/base64"
	"fmt"
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
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/lock"
	"github.com/4rji/ctvault/internal/logreg"
	"github.com/4rji/ctvault/internal/volume"
)

func freeDisk(string) (diskguard.Usage, error) {
	return diskguard.Usage{Total: 1 << 40, Avail: 1 << 39, Dev: 1}, nil
}

// pinFake pins a fake log as "fakelog" without going through a log list.
func pinFake(t *testing.T, root string, l *ctlogtest.Log) {
	t.Helper()
	r := logreg.Record{Name: "fakelog", URL: l.URL, LogID: base64.StdEncoding.EncodeToString(l.LogID[:]),
		Key: base64.StdEncoding.EncodeToString(l.PublicKeyDER), State: "usable", PinnedAt: time.Unix(0, 0).UTC()}
	if err := logreg.Add(root, r); err != nil {
		t.Fatal(err)
	}
}

// updateEnv is a production vault on a fake SSD with a fake log pinned and
// 40-entry batches.
func updateEnv(t *testing.T, n int, lo ctlogtest.Options) (*env, *ctlogtest.Log) {
	t.Helper()
	e := newEnv(t, nil)
	l := ctlogtest.New(t, n, lo)
	e.deps.HTTP = &http.Client{}
	e.deps.Statfs = freeDisk
	e.mustRun("init", e.root)
	cfg := "[ingest]\nbatch_size = 40\nfollow_interval = \"1s\"\ndelta_lru_entries = 1000\n[vault]\nsegment_size = \"1MiB\"\n"
	if err := os.WriteFile(filepath.Join(e.root, config.FileName), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	pinFake(t, e.root, l)
	old := headRetryDelay
	headRetryDelay = 10 * time.Millisecond
	t.Cleanup(func() { headRetryDelay = old })
	return e, l
}

func committed(t *testing.T, root string) []commit.Manifest {
	t.Helper()
	ms, err := commit.ListCommitted(root)
	if err != nil {
		t.Fatal(err)
	}
	return ms
}

func TestUpdateIngestsToTheHead(t *testing.T) {
	e, _ := updateEnv(t, 120, ctlogtest.Options{})
	out := e.mustRun("--root", e.root, "update")
	if ms := committed(t, e.root); len(ms) != 3 || ms[2].Last != 119 {
		t.Fatalf("120 entries in batches of 40: %d batches", len(ms))
	}
	if !strings.Contains(out, "batch fakelog/000000000000-000000000039") || !strings.Contains(out, "signed tree size 120 verified") {
		t.Fatalf("output: %s", out)
	}
	if _, err := os.Stat(filepath.Join(e.root, "state", "heads", "fakelog.json")); err != nil {
		t.Fatalf("the accepted head is stored: %v", err)
	}
	if out := e.mustRun("--root", e.root, "ingest"); !strings.Contains(out, "up to date at index 120") {
		t.Fatalf("a second run (through the ingest alias) has nothing to do: %s", out)
	}
}

func TestUpdateUntil(t *testing.T) {
	e, l := updateEnv(t, 120, ctlogtest.Options{})
	e.mustRun("--root", e.root, "update", "--until", "50")
	ms := committed(t, e.root)
	if len(ms) != 2 || ms[1].First != 40 || ms[1].Last != 49 {
		t.Fatalf("--until 50 commits [0,40) and a partial [40,50): %+v", ms)
	}
	heads := l.Requests("get-sth")
	if out := e.mustRun("--root", e.root, "update", "--until", "50"); !strings.Contains(out, "already at index 50") {
		t.Fatalf("output: %s", out)
	}
	if l.Requests("get-sth") != heads {
		t.Fatal("with the checkpoint at --until, not even a signed head is fetched (amendment A1 §3)")
	}
	if code := e.run("--root", e.root, "update", "--until", "500"); code != exitcode.Error || !strings.Contains(e.stderr.String(), "only 120 entries") {
		t.Fatalf("--until beyond the log: exit %d, %s", code, e.stderr)
	}
	e.mustRun("--root", e.root, "update")
	if ms := committed(t, e.root); ms[len(ms)-1].Last != 119 {
		t.Fatal("--until never makes a later update think the log ends there")
	}
}

func TestUpdateIncidents(t *testing.T) {
	e, l := updateEnv(t, 120, ctlogtest.Options{})
	e.mustRun("--root", e.root, "update")
	l.Publish(100) // the log now claims a smaller tree
	if code := e.run("--root", e.root, "update"); code != exitcode.Verification {
		t.Fatalf("a shrinking log: exit %d, want 5: %s", code, e.stderr)
	}
	inc, _ := os.ReadDir(filepath.Join(e.root, "state", "incidents"))
	if len(inc) != 1 || !strings.HasSuffix(inc[0].Name(), "_fakelog_head") {
		t.Fatalf("a head incident is written: %v", inc)
	}

	f, fl := updateEnv(t, 120, ctlogtest.Options{})
	fl.Fork(30)
	if code := f.run("--root", f.root, "update"); code != exitcode.Verification || len(committed(t, f.root)) != 0 {
		t.Fatalf("a forked log: exit %d, want 5, nothing committed: %s", code, f.stderr)
	}
}

func TestUpdateDiskCapAndLock(t *testing.T) {
	e, _ := updateEnv(t, 40, ctlogtest.Options{})
	e.deps.Statfs = func(string) (diskguard.Usage, error) {
		return diskguard.Usage{Total: 100 << 30, Avail: 10 << 30, Dev: 1}, nil
	}
	if code := e.run("--root", e.root, "update"); code != exitcode.DiskCap {
		t.Fatalf("a full disk: exit %d, want 3: %s", code, e.stderr)
	}
	e.deps.Statfs = freeDisk
	lk, err := lock.Acquire(filepath.Join(e.root, "state", "LOCK"))
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Release()
	if code := e.run("--root", e.root, "update"); code != exitcode.Error || !strings.Contains(e.stderr.String(), "held by PID") {
		t.Fatalf("a held writer lock: exit %d, %s", code, e.stderr)
	}
}

// TestUpdateFollowStopsOnFirstSignal: --follow ingests each new head; the
// first SIGINT stops it between cycles with exit 0.
func TestUpdateFollowStopsOnFirstSignal(t *testing.T) {
	e, l := updateEnv(t, 80, ctlogtest.Options{})
	l.Publish(40)
	done := make(chan int, 1)
	go func() { done <- e.run("--root", e.root, "update", "--follow") }()
	wait := func(n int) {
		for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			if ms, _ := commit.ListCommitted(e.root); len(ms) >= n {
				return
			}
		}
		t.Fatalf("timed out waiting for %d batches", n)
	}
	wait(1)
	l.Publish(80)
	wait(2)
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 0 || !strings.Contains(e.stdout.String(), "stopped") {
			t.Fatalf("exit %d: %s %s", code, e.stdout, e.stderr)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("update --follow did not stop")
	}
}

// vanishingVolumes passes the first n volume checks, then reports the
// volume gone.
type vanishingVolumes struct {
	Volumes
	n int
}

func (v *vanishingVolumes) Check(root string) (volume.VaultID, error) {
	if v.n--; v.n < 0 {
		return volume.VaultID{}, fmt.Errorf("%w: %s is no longer the vault's SSD", volume.ErrVolume, root)
	}
	return v.Volumes.Check(root)
}

func TestUpdateStopsWhenTheVolumeDisappears(t *testing.T) {
	e, _ := updateEnv(t, 120, ctlogtest.Options{})
	e.deps.Volumes = &vanishingVolumes{Volumes: e.deps.Volumes, n: 2} // the command start and batch 1
	if code := e.run("--root", e.root, "update"); code != exitcode.Volume {
		t.Fatalf("a vanished volume: exit %d, want 4: %s", code, e.stderr)
	}
	if ms := committed(t, e.root); len(ms) != 1 {
		t.Fatalf("only the first batch commits: %d", len(ms))
	}
}
