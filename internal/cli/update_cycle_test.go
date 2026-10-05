package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/ingest"
	"github.com/4rji/ctvault/internal/vault"
	"github.com/4rji/ctvault/internal/volume"
)

// TestAfterCycle: what update does with a cycle's error. --follow waits out
// a full disk or a stall, but never a writer whose abandon failed; after a
// second interrupt an error keeps its own exit code (corruption stays 5).
func TestAfterCycle(t *testing.T) {
	broken := errors.Join(diskguard.ErrCap, ingest.ErrAbandonFailed)
	for _, c := range []struct {
		name         string
		err          error
		follow, hard bool
		warn         bool
		code         int // -1: go on
	}{
		{"ok", nil, true, false, false, -1},
		{"full disk under --follow", diskguard.ErrCap, true, false, true, -1},
		{"stall under --follow", fetch.ErrStalled, true, false, true, -1},
		{"full disk once", diskguard.ErrCap, false, false, false, exitcode.DiskCap},
		{"abandon failed under --follow", broken, true, false, false, exitcode.DiskCap},
		{"stalled abandon failed", errors.Join(fetch.ErrStalled, ingest.ErrAbandonFailed), true, false, false, exitcode.Error},
		{"second interrupt", context.Canceled, true, true, false, exitcode.Error},
		{"corruption with a second interrupt", errors.Join(context.Canceled, vault.ErrCorrupt), false, true, false, exitcode.Verification},
		{"volume gone with a second interrupt", volume.ErrVolume, true, true, false, exitcode.Volume},
	} {
		warn, stop := afterCycle(c.err, c.follow, c.hard)
		got := -1
		if stop != nil {
			got = exitcode.Of(stop)
		}
		if got != c.code || (warn != "") != c.warn {
			t.Errorf("%s: exit %d, warning %q; want exit %d, warning %v", c.name, got, warn, c.code, c.warn)
		}
	}
}

// TestUpdateChecksTheHeadAgainstTheCommittedTip: without a stored head (a
// deleted state/heads file, a restored vault) a signed head that is smaller
// than, or forks from, what is committed is an incident, also when there is
// nothing to ingest.
func TestUpdateChecksTheHeadAgainstTheCommittedTip(t *testing.T) {
	for name, misbehave := range map[string]func(*ctlogtest.Log){
		"shrunk": func(l *ctlogtest.Log) { l.Publish(100) },
		"forked": func(l *ctlogtest.Log) { l.Fork(30) },
	} {
		t.Run(name, func(t *testing.T) {
			e, l := updateEnv(t, 120, ctlogtest.Options{})
			e.mustRun("--root", e.root, "update")
			os.Remove(filepath.Join(e.root, "state", "heads", "fakelog.json"))
			misbehave(l)
			if code := e.run("--root", e.root, "update"); code != exitcode.Verification {
				t.Fatalf("exit %d, want 5: %s%s", code, e.stdout, e.stderr)
			}
			if _, err := os.Stat(filepath.Join(e.root, "state", "heads", "fakelog.json")); err == nil {
				t.Fatal("a contradicting head must not be stored as accepted")
			}
			inc, _ := filepath.Glob(filepath.Join(e.root, "state", "incidents", "*_fakelog_head", "incident.json"))
			if len(inc) != 1 {
				t.Fatalf("one head incident: %v", inc)
			}
			if b, _ := os.ReadFile(inc[0]); !strings.Contains(string(b), `"committed_size": 120`) {
				t.Fatalf("the incident records the committed tip:\n%s", b)
			}
		})
	}
	e, l := updateEnv(t, 120, ctlogtest.Options{})
	e.mustRun("--root", e.root, "update", "--until", "80")
	os.Remove(filepath.Join(e.root, "state", "heads", "fakelog.json"))
	proofs := l.Requests("get-sth-consistency")
	if out := e.mustRun("--root", e.root, "update", "--until", "120"); !strings.Contains(out, "ingesting [80, 120)") {
		t.Fatalf("an honest larger head is accepted: %s", out)
	}
	if l.Requests("get-sth-consistency") == proofs {
		t.Fatal("the larger head is proven to extend the committed tree")
	}
}

// TestHeadIncidentWriteFailureIsReported: when the incident evidence cannot
// be written, the exit stays 5 and the message says so instead of naming a
// folder that does not exist.
func TestHeadIncidentWriteFailureIsReported(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	e, l := updateEnv(t, 120, ctlogtest.Options{})
	e.mustRun("--root", e.root, "update")
	l.Publish(100)
	inc := filepath.Join(e.root, "state", "incidents")
	os.Chmod(inc, 0o555)
	t.Cleanup(func() { os.Chmod(inc, 0o755) })
	if code := e.run("--root", e.root, "update"); code != exitcode.Verification {
		t.Fatalf("exit %d, want 5", code)
	}
	if msg := e.stderr.String(); !strings.Contains(msg, "could not be written") || strings.Contains(msg, "incident written to") {
		t.Fatalf("message: %s", msg)
	}
}
