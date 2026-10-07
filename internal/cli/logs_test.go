package cli

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/lock"
)

func TestLogsAddListInfo(t *testing.T) {
	e := newEnv(t, realSTH(t))
	e.mustRun("init", e.root)
	out := e.mustRun("--root", e.root, "logs", "add", "argon2027h1")
	if !strings.Contains(out, "Pinned argon2027h1") || !strings.Contains(out, "2027-01-01 to 2027-07-01") {
		t.Fatalf("logs add output: %s", out)
	}
	out = e.mustRun("--root", e.root, "logs", "list")
	if !strings.Contains(out, "argon2027h1") || !strings.Contains(out, "usable") {
		t.Fatalf("logs list output: %s", out)
	}
	out = e.mustRun("--root", e.root, "logs", "list", "--available")
	if !strings.Contains(out, "xenon2027h1") || !strings.Contains(out, "yes") {
		t.Fatalf("logs list --available output: %s", out)
	}
	// Both kinds are listed, with a KIND column (amendment A6 §1).
	if !regexp.MustCompile(`(?m)^parcelyard2027h1\s+tiled\s+usable\s+Google\s+https://storage\.googleapis\.com/parcelyard2027h1`).MatchString(out) ||
		!regexp.MustCompile(`(?m)^argon2027h1\s+rfc6962\s+usable\s+Google\s+yes\s+https://ct\.googleapis\.com/`).MatchString(out) ||
		!strings.HasPrefix(out, "NAME") || !strings.Contains(strings.SplitN(out, "\n", 2)[0], "KIND") {
		t.Fatalf("logs list --available must show both kinds:\n%s", out)
	}
	out = e.mustRun("--root", e.root, "logs", "info", "argon2027h1")
	if !strings.Contains(out, "tree_size  384065451") || !strings.Contains(out, "verified with pinned key") {
		t.Fatalf("logs info output: %s", out)
	}
	out = e.mustRun("--root", e.root, "logs", "info", "--offline", "argon2027h1")
	if strings.Contains(out, "tree_size") {
		t.Fatal("--offline must not contact the log")
	}
}

func TestLogsRootFromEnvironment(t *testing.T) {
	e := newEnv(t, realSTH(t))
	if got := e.run("logs", "list"); got != exitcode.Usage {
		t.Fatalf("no root anywhere: exit %d, want %d", got, exitcode.Usage)
	}
	if got := e.run("--root", e.root, "logs", "list"); got != exitcode.Volume {
		t.Fatalf("uninitialized root: exit %d, want %d", got, exitcode.Volume)
	}
	e.mustRun("init", e.root)
	e.deps.Getenv = func(k string) string {
		if k == "CTVAULT_ROOT" {
			return e.root
		}
		return ""
	}
	e.mustRun("logs", "list")
}

func TestLogsInfoRejectsForgedHead(t *testing.T) {
	forged := bytes.Replace(realSTH(t), []byte("384065451"), []byte("384065452"), 1)
	e := newEnv(t, forged)
	e.mustRun("init", e.root)
	e.mustRun("--root", e.root, "logs", "add", "argon2027h1")
	if got := e.run("--root", e.root, "logs", "info", "argon2027h1"); got != exitcode.Verification {
		t.Fatalf("forged STH: exit %d, want %d (stderr %s)", got, exitcode.Verification, e.stderr)
	}
	if !strings.Contains(e.stderr.String(), "does not verify with the pinned key") {
		t.Fatalf("stderr: %s", e.stderr)
	}
}

// TestLogsAddTiled: a tiled log is pinned with its kind, monitoring prefix
// and origin, and shown by list and info (amendment A6 §1).
func TestLogsAddTiled(t *testing.T) {
	e := newEnv(t, realSTH(t))
	e.mustRun("init", e.root)
	out := e.mustRun("--root", e.root, "logs", "add", "parcelyard2027h1")
	for _, want := range []string{"Pinned parcelyard2027h1", "kind    tiled (static-ct-api)",
		"url     https://storage.googleapis.com/parcelyard2027h1.prod.certificate.transparency.goog/ (monitoring)",
		"origin  parcelyard2027h1.prod.certificate.transparency.goog"} {
		if !strings.Contains(out, want) {
			t.Fatalf("logs add output lacks %q:\n%s", want, out)
		}
	}
	out = e.mustRun("--root", e.root, "logs", "list")
	if !strings.Contains(strings.SplitN(out, "\n", 2)[0], "KIND") || !regexp.MustCompile(`(?m)^parcelyard2027h1\s+tiled\s+usable`).MatchString(out) {
		t.Fatalf("logs list output:\n%s", out)
	}
	out = e.mustRun("--root", e.root, "logs", "info", "--offline", "parcelyard2027h1")
	for _, want := range []string{"kind       tiled", "origin     parcelyard2027h1.prod.certificate.transparency.goog",
		"submission https://parcelyard2027h1.prod.certificate.transparency.goog/"} {
		if !strings.Contains(out, want) {
			t.Fatalf("logs info output lacks %q:\n%s", want, out)
		}
	}
}

func TestLogsAddFailures(t *testing.T) {
	e := newEnv(t, realSTH(t))
	e.mustRun("init", e.root)
	held, err := lock.Acquire(filepath.Join(e.root, "state", "LOCK"))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	if got := e.run("--root", e.root, "logs", "add", "argon2027h1"); got != exitcode.Error ||
		!strings.Contains(e.stderr.String(), "writer lock is held by PID") {
		t.Fatalf("held lock: exit %d stderr %s", got, e.stderr)
	}
}
