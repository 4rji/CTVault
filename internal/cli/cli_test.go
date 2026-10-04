package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/volume/volumetest"
)

const logList = "../testdata/log_list_google.json"

// rewrite sends every request to the test server, keeping the path, so the
// pinned https://ct.googleapis.com/... URL can be answered locally.
type rewrite struct{ target *url.URL }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme, req.URL.Host = r.target.Scheme, r.target.Host
	return http.DefaultTransport.RoundTrip(req)
}

type env struct {
	t      *testing.T
	probe  *volumetest.Probe
	root   string
	deps   Deps
	stdout *bytes.Buffer
	stderr *bytes.Buffer
}

// newEnv presents a temp dir as an ext4 SSD and answers the Argon get-sth
// endpoint with sthBody.
func newEnv(t *testing.T, sthBody []byte) *env {
	t.Helper()
	p := volumetest.New()
	root := p.Mount(t, t.TempDir(), "ext4", "8:17", "ssd-uuid")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/logs/us1/argon2027h1/ct/v1/get-sth" {
			w.Write(sthBody)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	target, _ := url.Parse(srv.URL)
	e := &env{t: t, probe: p, root: root, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	e.deps = Deps{
		Probe: p, HTTP: &http.Client{Transport: rewrite{target}}, Getenv: func(string) string { return "" },
		Now:    func() time.Time { return time.Date(2026, 10, 4, 7, 0, 0, 0, time.UTC) },
		Stdout: e.stdout, Stderr: e.stderr, LogListSource: logList, Version: "test",
	}
	return e
}

func (e *env) run(args ...string) int {
	e.stdout.Reset()
	e.stderr.Reset()
	return Main(args, e.deps)
}

func (e *env) mustRun(args ...string) string {
	e.t.Helper()
	if code := e.run(args...); code != 0 {
		e.t.Fatalf("ctvault %v: exit %d\nstderr: %s", args, code, e.stderr)
	}
	return e.stdout.String()
}

func realSTH(t *testing.T) []byte {
	b, err := os.ReadFile("../testdata/argon2027h1_sth1.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestInitWritesVault(t *testing.T) {
	e := newEnv(t, realSTH(t))
	out := e.mustRun("init", e.root)
	if !strings.Contains(out, "Initialized CTVault") || !strings.Contains(out, "durability tested") ||
		!strings.Contains(out, "logs add argon2027h1") {
		t.Fatalf("init output: %s", out)
	}
	for _, f := range []string{"VAULT_ID", "ctvault.toml", "vault/DIR_ID", "state/logs"} {
		if _, err := os.Stat(filepath.Join(e.root, f)); err != nil {
			t.Errorf("init must create %s: %v", f, err)
		}
	}
}

func TestExitCodes(t *testing.T) {
	e := newEnv(t, realSTH(t))
	cases := []struct {
		args []string
		want int
	}{
		{[]string{"frobnicate"}, exitcode.Usage},
		{[]string{"init"}, exitcode.Usage},
		{[]string{"init", e.root, "--bogus-flag"}, exitcode.Usage},
		{[]string{"vault", "add-dir", "/x"}, exitcode.Usage},                    // no --root, no CTVAULT_ROOT
		{[]string{"--root", e.root, "vault", "add-dir", "/x"}, exitcode.Volume}, // not initialized
		{[]string{"init", filepath.Join(t.TempDir(), "x")}, exitcode.Volume},    // missing root: usually an unmounted SSD
		{[]string{"init", t.TempDir()}, exitcode.Volume},                        // a plain directory on the system disk
	}
	for _, c := range cases {
		if got := e.run(c.args...); got != c.want {
			t.Errorf("ctvault %v: exit %d, want %d (stderr %s)", c.args, got, c.want, e.stderr)
		}
	}
	if got := e.run("version"); got != 0 || !strings.Contains(e.stdout.String(), "ctvault test") {
		t.Errorf("version: exit %d output %q", got, e.stdout)
	}
}

func TestVaultAddDirAndSwappedDisk(t *testing.T) {
	e := newEnv(t, realSTH(t))
	e.mustRun("init", e.root)
	disk2 := e.probe.Mount(t, t.TempDir(), "ext4", "8:33", "disk2-uuid")
	out := e.mustRun("--root", e.root, "vault", "add-dir", filepath.Join(disk2, "vault"))
	if !strings.Contains(out, "disk2-uuid") {
		t.Fatalf("add-dir output: %s", out)
	}
	e.probe.UUIDs["8:33"] = "a-different-disk"
	disk3 := e.probe.Mount(t, t.TempDir(), "ext4", "8:49", "disk3-uuid")
	if got := e.run("--root", e.root, "vault", "add-dir", disk3); got != exitcode.Volume {
		t.Fatalf("swapped second disk must fail the vault check: exit %d, want %d", got, exitcode.Volume)
	}
}
