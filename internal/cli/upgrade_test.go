package cli

import (
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/derivetest"
	"github.com/4rji/ctvault/internal/diskguard"
)

// TestUpgradeThroughUpdate: with a newer binary, update alone carries a
// table from v1 to v2 (amendment A5 §8): its first run starts the upgrade;
// each committed batch builds both versions and is followed by one old
// batch rebuilt; the last turn switches. search gives the same rows before,
// during and after, and verify --full passes at every step.
func TestUpgradeThroughUpdate(t *testing.T) {
	e, _ := updateEnv(t, 240, ctlogtest.Options{})
	e.mustRun("--root", e.root, "update", "--until", "120") // 3 batches at v1
	certs := func() string {
		return e.mustRun("--root", e.root, "search", "example.test", "--group", "certs", "--format", "csv", "--fields", "sha256,cert_id,kind")
	}
	before := certs()

	derivetest.Use(t, "v2")
	out := e.mustRun("--root", e.root, "update", "--until", "160")
	if !strings.Contains(out, "starting the upgrade of certs from v1 to v2") || !strings.Contains(out, "rebuilt batch fakelog/000000000000-000000000039") {
		t.Fatalf("the first update with v2:\n%s", out)
	}
	a, _, _ := derive.ReadActive(e.root)
	if s := a.Tables["certs"]; *s.Active != 1 || *s.Building != 2 {
		t.Fatalf("during the upgrade: %+v", s)
	}
	if during := certs(); !holds(during, before) {
		t.Fatalf("search during the upgrade:\n%s\nbefore:\n%s", during, before)
	}
	e.mustRun("--root", e.root, "verify", "--full")

	out = e.mustRun("--root", e.root, "update", "--until", "240")
	if !strings.Contains(out, "switched certs to v2") {
		t.Fatalf("the update that finishes the upgrade:\n%s", out)
	}
	a, _, _ = derive.ReadActive(e.root)
	if s := a.Tables["certs"]; *s.Active != 2 || s.Building != nil || *s.Retiring != 1 {
		t.Fatalf("after the switch: %+v", s)
	}
	if after := certs(); !holds(after, before) || strings.Count(after, "\n") != 2*strings.Count(before, "\n")-1 {
		t.Fatalf("search after the switch:\n%s\nbefore:\n%s", after, before)
	}
	if out := e.mustRun("--root", e.root, "verify", "--full"); !strings.Contains(out, "certs v2 complete, v1 retiring") {
		t.Fatalf("verify after the switch:\n%s", out)
	}
}

// holds reports whether every line of b is a line of a: the rows found
// before are still found, beside those of batches ingested since.
func holds(a, b string) bool {
	lines := map[string]bool{}
	for _, l := range strings.Split(a, "\n") {
		lines[l] = true
	}
	for _, l := range strings.Split(b, "\n") {
		if !lines[l] {
			return false
		}
	}
	return true
}

// TestUpgradeInFollowIdleTime: with nothing to ingest, update --follow
// rebuilds the old batches while it waits for the next cycle, then
// switches; a SIGINT still stops it between turns (amendment A5 §8).
func TestUpgradeInFollowIdleTime(t *testing.T) {
	e, _ := updateEnv(t, 160, ctlogtest.Options{})
	e.mustRun("--root", e.root, "update") // 4 batches at v1, up to date
	derivetest.Use(t, "v2")
	done := make(chan int, 1)
	go func() { done <- e.run("--root", e.root, "update", "--follow") }()
	for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if a, _, _ := derive.ReadActive(e.root); a.Tables["certs"].Active != nil && *a.Tables["certs"].Active == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the idle time did not finish the upgrade")
		}
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 0 || !strings.Contains(e.stdout.String(), "switched certs to v2") || strings.Count(e.stdout.String(), "rebuilt batch") != 4 {
			t.Fatalf("exit %d:\n%s\n%s", code, e.stdout, e.stderr)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("update --follow did not stop")
	}
}

// TestGCCommand: gc retires a replaced version's files at once; update
// does it by itself once 24 hours have passed since the switch; verify
// passes after both (amendment A5 §9).
func TestGCCommand(t *testing.T) {
	for _, way := range []string{"gc", "update after 24 hours"} {
		t.Run(way, func(t *testing.T) {
			e, _ := updateEnv(t, 120, ctlogtest.Options{})
			at := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
			e.deps.Now = func() time.Time { return at }
			e.mustRun("--root", e.root, "update")
			derivetest.Use(t, "v2")
			e.mustRun("--root", e.root, "rebuild")
			var out string
			if way == "gc" {
				out = e.mustRun("--root", e.root, "gc")
			} else {
				if out = e.mustRun("--root", e.root, "update"); strings.Contains(out, "retired") {
					t.Fatalf("update retired before 24 hours:\n%s", out)
				}
				at = at.Add(25 * time.Hour)
				out = e.mustRun("--root", e.root, "update")
			}
			if !strings.Contains(out, "retired 3 files (certs v1)") {
				t.Fatalf("%s:\n%s", way, out)
			}
			if out := e.mustRun("--root", e.root, "verify", "--full"); !strings.Contains(out, "certs v2 complete, names v1 complete; views.sql current") {
				t.Fatalf("verify after the retirement:\n%s", out)
			}
			if out := e.mustRun("--root", e.root, "gc"); !strings.Contains(out, "nothing to retire") {
				t.Fatalf("gc with nothing left:\n%s", out)
			}
		})
	}
}

// TestRebuildInPlace: without room for a side-by-side copy, update warns and
// stays at v1; rebuild --in-place converts every batch, after which no v1
// file remains and verify passes (amendment A5 §8, §10).
func TestRebuildInPlace(t *testing.T) {
	e, _ := updateEnv(t, 120, ctlogtest.Options{})
	e.mustRun("--root", e.root, "update")
	derivetest.Use(t, "v2")
	e.deps.Statfs = func(string) (diskguard.Usage, error) {
		return diskguard.Usage{Total: 100 << 20, Avail: 15 << 20, Dev: 1}, nil // at the cap
	}
	e.mustRun("--root", e.root, "update")
	if !strings.Contains(e.stderr.String(), "certs v2 needs") || !strings.Contains(e.stderr.String(), "rebuild --in-place") {
		t.Fatalf("update without room: %s", e.stderr)
	}
	if out := e.mustRun("--root", e.root, "rebuild"); !strings.Contains(e.stderr.String(), "rebuild --in-place") || !strings.Contains(out, "nothing to rebuild") {
		t.Fatalf("rebuild without room:\n%s\n%s", out, e.stderr)
	}
	out := e.mustRun("--root", e.root, "rebuild", "--in-place")
	if !strings.Contains(out, "converting certs from v1 to v2 in place") || !strings.Contains(out, "rebuilt 3 batches; certs is complete") {
		t.Fatalf("rebuild --in-place:\n%s", out)
	}
	a, _, _ := derive.ReadActive(e.root)
	if s := a.Tables["certs"]; *s.Active != 2 || s.Status != derive.StatusComplete || s.Retiring != nil {
		t.Fatalf("after the conversion: %+v", s)
	}
	e.deps.Statfs = freeDisk
	e.mustRun("--root", e.root, "verify", "--full")
}

// TestMixedReadFlags: search, fetch and explore refuse a mixed table with
// exit 2 and name the flags; --allow-mixed and --parser-version read it and
// say how (amendment A5 §10).
func TestMixedReadFlags(t *testing.T) {
	e, _ := updateEnv(t, 80, ctlogtest.Options{})
	e.mustRun("--root", e.root, "update")
	derivetest.Use(t, "v2")
	e.mustRun("--root", e.root, "rebuild", "--in-place")
	// Mixed at rest: as if the conversion had stopped with every batch at v2.
	a, _, _ := derive.ReadActive(e.root)
	one, two := 1, 2
	a.Tables["certs"] = derive.TableState{Active: &one, Building: &two, Status: derive.StatusMixed}
	a.Seq++
	if err := derive.WriteActive(e.root, a); err != nil {
		t.Fatal(err)
	}
	if code := e.run("--root", e.root, "search", "example.test"); code != 2 || !strings.Contains(e.stderr.String(), "--allow-mixed") {
		t.Fatalf("search of a mixed table: exit %d, %s", code, e.stderr)
	}
	e.mustRun("--root", e.root, "search", "example.test", "--allow-mixed")
	if !strings.Contains(e.stderr.String(), "certs is mixed: reading v2 in 2 batches") {
		t.Fatalf("--allow-mixed: %s", e.stderr)
	}
	e.mustRun("--root", e.root, "search", "example.test", "--parser-version", "2")
	if !strings.Contains(e.stderr.String(), "reading only the 2 of 2 batches at v2 (a partial result)") {
		t.Fatalf("--parser-version: %s", e.stderr)
	}
	if code := e.run("--root", e.root, "search", "example.test", "--parser-version", "2", "--allow-mixed"); code != 2 {
		t.Fatalf("both flags: exit %d", code)
	}
	if code := e.run("--root", e.root, "fetch", "1"); code != 2 {
		t.Fatalf("fetch of a mixed table: exit %d", code)
	}
	e.mustRun("--root", e.root, "fetch", "1", "--allow-mixed")
}
