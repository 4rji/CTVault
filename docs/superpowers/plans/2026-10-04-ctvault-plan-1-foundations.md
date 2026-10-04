# CTVault Plan 1 (Foundations) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the tested foundation that every later CTVault plan depends on. When this plan is done, `ctvault init` creates a vault only on a verified, dedicated ext4 volume, `ctvault logs add argon2027h1` pins a log and its key from Chrome's log list, and `ctvault logs info argon2027h1` fetches the live signed tree head and verifies it cryptographically.

**Architecture:** One Go module with small `internal/` packages, each with a single job:
- `volume`: volume identity and filesystem policy
- `diskguard`: the disk cap
- `merkle`: RFC 6962 hashing, compact ranges, consistency proofs and signed-tree-head signatures
- `logsource/rfc6962`: the HTTP client
- `loglist` and `logreg`: Chrome's log list and the pinned logs
- `cli`: the cobra command line

Host access (mount table, network, clock, output) is injected so that every command is tested end to end without root privileges or network access. A fake CT log (`ctlogtest`) backed by a real Merkle tree supports this plan's tests and Plan 2's ingest tests.

**Tech Stack:**
- Go 1.26.8
- `github.com/transparency-dev/merkle` v0.0.2 (compact ranges, proofs, test tree)
- `github.com/spf13/cobra` v1.10.2
- `github.com/BurntSushi/toml` v1.6.0
- `golang.org/x/sys` v0.48.0

**Spec:** `docs/superpowers/specs/2026-10-04-ctvault-design.md` (approved 2026-10-04). This plan implements phase 1 of spec §16: §4.2–4.3 (layout), §5.2 STH and consistency parts, §5.5, §9, §10.1 guard primitives, §11.1–11.2 for `init`, `logs`, `vault add-dir` and `version`, and §13.1, §13.4 and §13.6 (fixtures) for these packages.

## Global Constraints

- **Platform:** Linux only ("v1 runs on Linux only", spec §9.3).
- **Module:** `github.com/4rji/ctvault`, with the `go 1.26.8` directive (`golang.org/x/sys` v0.48.0 requires Go ≥ 1.26.0). With `GOTOOLCHAIN=auto`, an older local `go` downloads 1.26.8 by itself.
- **Pinned dependencies:**
  - `github.com/transparency-dev/merkle@v0.0.2`
  - `github.com/spf13/cobra@v1.10.2`
  - `github.com/BurntSushi/toml@v1.6.0`
  - `golang.org/x/sys@v0.48.0`

  No other third-party dependencies in Plan 1.
- **Exit codes:** "0 OK, 1 error, 2 usage, 3 disk cap reached, 4 volume check failed, 5 verification or corruption failure" (spec §11.2).
- **Filesystems** (spec §9.3):
  - `ext4` is supported and tested.
  - `xfs`, `btrfs` and `f2fs` are "Rejected unless `init --allow-untested-fs` is given, which records `durability: "untested"`".
  - "`vfat`, `exfat`, `ntfs` / `ntfs3` / `fuseblk`, any FUSE filesystem, `nfs`, `cifs`/`smb`, `tmpfs`, `overlay`" are always rejected.
  - "`nobarrier` or `barrier=0` is rejected because it disables flushes."
- **Never the system disk:**
  - The root must be a mount point on a different device from `/`, with its filesystem UUID recorded in `VAULT_ID`.
  - Every vault directory carries a `DIR_ID` and a recorded filesystem UUID.
  - Checks run "on every command start (readers included)" (spec §9.1–9.2).
- **Durable writes:** a temp file, fsync, rename, then fsync of the directory. "`rename` within a directory is atomic. `fsync(file)` persists data and metadata. `fsync(dir)` persists directory entries." (spec §9.3)
- **Writer lock:** commands that write state take an exclusive `flock` on `state/LOCK`. "If the lock is held, the command exits 1 and names the PID holding it" (spec §8.1). In Plan 1 these are `logs add` and `vault add-dir`.
- **Disk cap:** "Usage per volume is `(f_blocks − f_bavail) / f_blocks`"; the default cap is 0.85. The seeds are "vault 840, Parquet 175 and Pebble 60 B per entry" (spec §10.1).
- **Logs:**
  - The log ID must equal SHA-256 of the pinned SPKI.
  - STH signatures use SHA-256 with ECDSA or RSA.
  - Tiled (static-ct-api) logs are rejected in v1.
- **On-disk layout:** as in spec §4.3. `init` creates `state/{intent,incidents,logs}`, `vault/{dict,segments}`, `dataset`, `tmp` and `logs`.
- **Quality gates:** for every task, `gofmt -l .` prints nothing, `go vet ./...` is clean, and `go test -race ./...` passes.

## Review Focus

Each of these inputs is something the spec implies but never spells out. Each is pinned by a test in the task that owns the code.

1. **The external SSD is mounted at a path containing spaces** (mountinfo writes `\040`).
   - Expected: the path is decoded, the mount is found and the checks pass.
   - Pinned by `TestParseMountInfo` and `TestMountFor` in Task 2.
2. **The user passes the root with a trailing slash or through a symlink.**
   - Expected: it's the same vault, and the checks pass.
   - Pinned by `TestCheckAcceptsTrailingSlashAndSymlink` in Task 3.
3. **The same SSD is later mounted at a different path.**
   - Expected: identity is the filesystem UUID plus the vault UUID, not the path, so the checks pass.
   - Pinned by `TestCheckAfterRemountAtNewPath` in Task 3.
4. **A host has no `/dev/disk/by-uuid` (containers, minimal systems), or a device has no UUID.**
   - Expected: the error says "cannot determine filesystem UUID", the exit code is 4, and nothing is written.
   - Pinned by `TestHostProbeMissingByUUID` and `TestInitRefusals/no filesystem UUID` in Task 3.
5. **The log-list URL or a log answers with an HTML page** (captive portal, proxy error).
   - Expected: a clear error that quotes the start of the page, no crash, and nothing pinned.
   - Pinned by `TestFetchOverHTTPAndHTMLPage` in Task 10 and `TestMalformedResponses` in Task 9.

## Plan Series

The spec is implemented in six sequential plans that follow spec §16. Each later plan is written after the previous one has been executed, so it builds on real interfaces and real measurements.

| Plan | Scope (spec §16 phase) |
|---|---|
| **1 (this plan)** | Foundations: volume and `init`, disk guard, log list and `logs`, `merkle`, the fake CT log |
| 2 | Source-layer ingest: LogSource with `get-entries`, fetcher, leaf classes, vault (dictionaries, `leaf-delta`; check V1), Pebble, `entries`/`chains` Parquet, commit protocol, recovery, `ID_FLOOR`, `update --follow`, crash suite |
| 3 | Derived layer: extractor, `certs`/`names` builders, version metadata, `ACTIVE.json`, `views.sql`, canary (check V2), `stats` |
| 4 | Read path: `query`, `search`, `fetch`, export; live smoke test M1–M4 |
| 5 | `explore` TUI |
| 6 | Rebuild, `gc`, `verify --full`, `repair --reindex`, `dm-log-writes` power-loss gate |

## Before You Start

- Work from the repository root. It already contains `ct_log_local_search_platform.md`, `.gitattributes` and `docs/`.
- You need Linux and network access to `proxy.golang.org` for module downloads. Tests need no other network access.
- Run tests exactly as shown. `go test` caches results, so use `-count=1` when you need a fresh run.

## File Structure

```text
go.mod, go.sum, .gitignore, README.md
cmd/ctvault/main.go                     entry point: cli.Main(os.Args[1:], cli.DefaultDeps(version))
internal/exitcode/exitcode.go           exit codes + CodedError
internal/fsutil/fsutil.go               durable writes: WriteFileAtomic, MkdirAllSync, SyncDir
internal/volume/mountinfo.go            /proc/self/mountinfo parser, MountFor
internal/volume/policy.go               filesystem policy (Classify)
internal/volume/probe.go                Probe interface + HostProbe (mountinfo, /dev/disk/by-uuid)
internal/volume/identity.go             VAULT_ID / DIR_ID types and I/O
internal/volume/volume.go               Checker: Inspect, Init, Check, AddDir
internal/volume/volumetest/volumetest.go  fake Probe for tests
internal/lock/lock.go                   writer flock on state/LOCK
internal/config/config.go               ctvault.toml defaults, load, validate
internal/diskguard/diskguard.go         statfs usage, cap check, peak estimate
internal/merkle/sth.go                  STH signature verification
internal/merkle/state.go                leaf hash, compact range State, consistency verification
internal/ctlogtest/entries.go           MerkleTreeLeaf encoding, certificate generator
internal/ctlogtest/log.go               fake RFC 6962 log server with fault injection
internal/logsource/rfc6962/client.go    get-sth, get-sth-consistency client
internal/loglist/loglist.go             Chrome log list v3: parse, fetch, Find, ParseKey
internal/logreg/logreg.go               pinned logs under state/logs/
internal/cli/cli.go                     Deps, Main, root command, helpers, version
internal/cli/vaultcmds.go               init, vault add-dir
internal/cli/logs.go                    logs list/add/info
internal/testdata/*.json                real fixtures captured 2026-10-04
```

---

### Task 1: Module scaffold, exit codes and durable file writes

**Files:**
- Create: `go.mod`, `.gitignore`
- Create: `internal/exitcode/exitcode.go`, `internal/exitcode/exitcode_test.go`
- Create: `internal/fsutil/fsutil.go`, `internal/fsutil/fsutil_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `exitcode`:
    - constants `OK=0, Error=1, Usage=2, DiskCap=3, Volume=4, Verification=5`
    - `type CodedError struct{ Code int; Err error }`
    - `func With(code int, err error) error` (nil stays nil)
    - `func Withf(code int, format string, args ...any) error`
    - `func Of(err error) int`
  - `fsutil`:
    - `func SyncDir(dir string) error`
    - `func WriteFileAtomic(path string, data []byte, perm fs.FileMode) error`
    - `func MkdirAllSync(dir string, perm fs.FileMode) error`

- [ ] **Step 1: Create the module and .gitignore**

```bash
go mod init github.com/4rji/ctvault
go get go@1.26.8 toolchain@none
```

Then create `.gitignore`:

```text
/ctvault
*.test
/coverage.out
```

- [ ] **Step 2: Write the failing exitcode test**

```go
package exitcode

import (
	"errors"
	"fmt"
	"testing"
)

func TestOf(t *testing.T) {
	base := errors.New("boom")
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, OK},
		{"plain", base, Error},
		{"coded", With(DiskCap, base), DiskCap},
		{"wrapped coded", fmt.Errorf("context: %w", With(Volume, base)), Volume},
		{"formatted", Withf(Verification, "bad %d", 1), Verification},
	}
	for _, c := range cases {
		if got := Of(c.err); got != c.want {
			t.Errorf("%s: Of() = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestWithNilStaysNil(t *testing.T) {
	if With(Usage, nil) != nil {
		t.Fatal("With(code, nil) must return nil")
	}
}

func TestCodedErrorUnwraps(t *testing.T) {
	base := errors.New("root cause")
	if !errors.Is(With(Error, base), base) {
		t.Fatal("errors.Is must see through CodedError")
	}
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `go test ./internal/exitcode/`
Expected: FAIL with `[build failed]` and `undefined: Of`.

- [ ] **Step 4: Implement exitcode**

```go
// Package exitcode defines CTVault's process exit codes (spec §11.2) and a way
// to attach one to an error as it travels up to main.
package exitcode

import (
	"errors"
	"fmt"
)

// Exit codes from spec §11.2.
const (
	OK           = 0
	Error        = 1
	Usage        = 2
	DiskCap      = 3
	Volume       = 4
	Verification = 5
)

// CodedError carries an exit code alongside the error.
type CodedError struct {
	Code int
	Err  error
}

func (e *CodedError) Error() string { return e.Err.Error() }
func (e *CodedError) Unwrap() error { return e.Err }

// With attaches code to err. A nil err stays nil.
func With(code int, err error) error {
	if err == nil {
		return nil
	}
	return &CodedError{Code: code, Err: err}
}

// Withf formats a new error carrying code.
func Withf(code int, format string, args ...any) error {
	return &CodedError{Code: code, Err: fmt.Errorf(format, args...)}
}

// Of returns the exit code for err: OK for nil, the outermost attached code,
// or Error when none is attached.
func Of(err error) int {
	if err == nil {
		return OK
	}
	var ce *CodedError
	if errors.As(err, &ce) {
		return ce.Code
	}
	return Error
}
```

- [ ] **Step 5: Run it to verify it passes**

Run: `go test ./internal/exitcode/ -v`
Expected: PASS (`TestOf`, `TestWithNilStaysNil`, `TestCodedErrorUnwraps`).

- [ ] **Step 6: Write the failing fsutil test**

```go
package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomicCreatesAndReplaces(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "VAULT_ID")
	if err := WriteFileAtomic(p, []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(p, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "second" {
		t.Fatalf("content = %q, want %q", got, "second")
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("perm = %v, want 0600", fi.Mode().Perm())
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("temp files left behind: %v", ents)
	}
}

func TestWriteFileAtomicMissingDirFailsCleanly(t *testing.T) {
	err := WriteFileAtomic(filepath.Join(t.TempDir(), "nope", "f"), []byte("x"), 0o644)
	if err == nil {
		t.Fatal("expected error for missing parent directory")
	}
}

func TestMkdirAllSync(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, "state", "intent")
	if err := MkdirAllSync(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
		t.Fatalf("directory not created: %v", err)
	}
	if err := MkdirAllSync(d, 0o755); err != nil {
		t.Fatalf("second call must be a no-op: %v", err)
	}
	f := filepath.Join(root, "file")
	os.WriteFile(f, nil, 0o644)
	if err := MkdirAllSync(f, 0o755); err == nil {
		t.Fatal("expected error when a file occupies the path")
	}
}
```

- [ ] **Step 7: Run it to verify it fails**

Run: `go test ./internal/fsutil/`
Expected: FAIL with `undefined: WriteFileAtomic`.

- [ ] **Step 8: Implement fsutil**

```go
// Package fsutil provides durable file operations. Every write is fsynced and
// every rename or create is followed by an fsync of the parent directory, as
// required by the durability assumptions in spec §9.3.
package fsutil

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// SyncDir fsyncs a directory so that entries created, renamed or removed in it
// are durable.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	return errors.Join(syncErr, closeErr)
}

// WriteFileAtomic replaces path with data: it writes a temp file in the same
// directory, fsyncs it, renames it over path and fsyncs the directory. Readers
// see either the old content or the new content, never a mix.
func WriteFileAtomic(path string, data []byte, perm fs.FileMode) (err error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	closed := false
	defer func() {
		if err != nil {
			if !closed {
				f.Close()
			}
			os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Chmod(perm); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	closed = true
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	return SyncDir(dir)
}

// MkdirAllSync creates dir and any missing parents, fsyncing each parent whose
// entries changed. An existing directory is left untouched.
func MkdirAllSync(dir string, perm fs.FileMode) error {
	dir = filepath.Clean(dir)
	if fi, err := os.Stat(dir); err == nil {
		if !fi.IsDir() {
			return fmt.Errorf("%s exists and is not a directory", dir)
		}
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(dir)
	if parent != dir {
		if err := MkdirAllSync(parent, perm); err != nil {
			return err
		}
	}
	if err := os.Mkdir(dir, perm); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	return SyncDir(parent)
}
```

- [ ] **Step 9: Run it to verify it passes**

Run: `go test ./internal/fsutil/ -v && gofmt -l . && go vet ./...`
Expected: PASS. `gofmt` prints nothing.

- [ ] **Step 10: Commit**

```bash
git add go.mod .gitignore internal/exitcode internal/fsutil
git commit -m "feat: module scaffold, exit codes and durable file writes"
```

---

### Task 2: Mount table parsing and filesystem policy

**Files:**
- Create: `internal/volume/mountinfo.go`, `internal/volume/mountinfo_test.go`
- Create: `internal/volume/policy.go`, `internal/volume/policy_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces (package `volume`):
  - `type MountEntry struct{ MountID int; MajorMinor, Root, MountPoint string; MountOptions []string; FSType, Source string; SuperOptions []string }`
  - `func ParseMountInfo(r io.Reader) ([]MountEntry, error)`
  - `func MountFor(entries []MountEntry, absPath string) (MountEntry, bool)`
  - `type Durability string`, with `DurabilityTested = "tested"` and `DurabilityUntested = "untested"`
  - `var ErrUnsupportedFS error`
  - `func Classify(m MountEntry) (Durability, error)`

- [ ] **Step 1: Write the failing mountinfo test**

This is Review Focus item 1. The sample includes a mount point with `\040` (a space) and a stacked mount at the same path.

```go
package volume

import (
	"strings"
	"testing"
)

const sampleMountInfo = `24 30 0:22 / /sys rw,nosuid,nodev,noexec,relatime shared:6 - sysfs sysfs rw
30 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro
88 30 8:17 / /mnt/ctvault rw,relatime shared:40 - ext4 /dev/sdb1 rw
89 30 8:33 / /mnt/my\040disk rw,relatime - ext4 /dev/sdc1 rw,nobarrier
90 88 8:49 / /mnt/ctvault/extra rw - xfs /dev/sdd1 rw
91 30 8:17 / /mnt/ctvault rw,relatime shared:41 - ext4 /dev/sdb1 rw
`

func TestParseMountInfo(t *testing.T) {
	ms, err := ParseMountInfo(strings.NewReader(sampleMountInfo))
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 6 {
		t.Fatalf("got %d entries, want 6", len(ms))
	}
	root := ms[1]
	if root.MountPoint != "/" || root.MajorMinor != "8:1" || root.FSType != "ext4" || root.Source != "/dev/sda1" {
		t.Fatalf("root entry parsed wrong: %+v", root)
	}
	if got := ms[3].MountPoint; got != "/mnt/my disk" {
		t.Fatalf("octal escape not decoded: %q", got)
	}
	if got := ms[3].SuperOptions; len(got) != 2 || got[1] != "nobarrier" {
		t.Fatalf("super options = %v", got)
	}
	if ms[0].MountOptions[0] != "rw" || ms[0].FSType != "sysfs" {
		t.Fatalf("optional fields handled wrong: %+v", ms[0])
	}
}

func TestParseMountInfoRejectsMalformed(t *testing.T) {
	if _, err := ParseMountInfo(strings.NewReader("24 30 0:22 / /sys rw\n")); err == nil {
		t.Fatal("expected error for a line without the '-' separator")
	}
}

func TestMountFor(t *testing.T) {
	ms, _ := ParseMountInfo(strings.NewReader(sampleMountInfo))
	cases := map[string]string{
		"/":                    "/",
		"/home/metro":          "/",
		"/mnt/ctvault":         "/mnt/ctvault",
		"/mnt/ctvault/vault":   "/mnt/ctvault",
		"/mnt/ctvault/extra/x": "/mnt/ctvault/extra",
		"/mnt/ctvaultX":        "/",
		"/mnt/my disk/ctvault": "/mnt/my disk",
	}
	for path, want := range cases {
		m, ok := MountFor(ms, path)
		if !ok || m.MountPoint != want {
			t.Errorf("MountFor(%q) = %q, want %q", path, m.MountPoint, want)
		}
	}
	m, _ := MountFor(ms, "/mnt/ctvault")
	if m.MountID != 91 {
		t.Errorf("stacked mount: got id %d, want the topmost (91)", m.MountID)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/volume/`
Expected: FAIL with `undefined: ParseMountInfo`.

- [ ] **Step 3: Implement the parser**

```go
package volume

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// MountEntry is one line of /proc/self/mountinfo, as documented in proc(5).
type MountEntry struct {
	MountID      int
	MajorMinor   string // "8:1"
	Root         string
	MountPoint   string // octal escapes decoded
	MountOptions []string
	FSType       string
	Source       string
	SuperOptions []string
}

// ParseMountInfo parses the mountinfo format.
func ParseMountInfo(r io.Reader) ([]MountEntry, error) {
	var out []MountEntry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		if strings.TrimSpace(text) == "" {
			continue
		}
		f := strings.Fields(text)
		sep := -1
		for i := 6; i < len(f); i++ {
			if f[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || len(f) < sep+4 {
			return nil, fmt.Errorf("mountinfo line %d: malformed: %q", line, text)
		}
		id, err := strconv.Atoi(f[0])
		if err != nil {
			return nil, fmt.Errorf("mountinfo line %d: bad mount id %q", line, f[0])
		}
		out = append(out, MountEntry{
			MountID:      id,
			MajorMinor:   f[2],
			Root:         unescape(f[3]),
			MountPoint:   unescape(f[4]),
			MountOptions: strings.Split(f[5], ","),
			FSType:       f[sep+1],
			Source:       unescape(f[sep+2]),
			SuperOptions: strings.Split(f[sep+3], ","),
		})
	}
	return out, sc.Err()
}

// unescape decodes the \NNN octal escapes the kernel writes for space, tab,
// newline and backslash in mountinfo paths.
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && isOctal(s[i+1]) && isOctal(s[i+2]) && isOctal(s[i+3]) {
			b.WriteByte((s[i+1]-'0')<<6 | (s[i+2]-'0')<<3 | (s[i+3] - '0'))
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOctal(c byte) bool { return c >= '0' && c <= '7' }

// MountFor returns the mount that contains absPath: the entry with the longest
// matching mount point, preferring the later (topmost) one on ties.
func MountFor(entries []MountEntry, absPath string) (MountEntry, bool) {
	best := -1
	for i, e := range entries {
		if !within(absPath, e.MountPoint) {
			continue
		}
		if best < 0 || len(e.MountPoint) >= len(entries[best].MountPoint) {
			best = i
		}
	}
	if best < 0 {
		return MountEntry{}, false
	}
	return entries[best], true
}

func within(path, mountPoint string) bool {
	if mountPoint == "/" {
		return strings.HasPrefix(path, "/")
	}
	return path == mountPoint || strings.HasPrefix(path, mountPoint+"/")
}
```

- [ ] **Step 4: Write the failing policy test**

```go
package volume

import (
	"errors"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		fstype string
		super  []string
		want   Durability
		reject bool
	}{
		{"ext4", []string{"rw"}, DurabilityTested, false},
		{"xfs", []string{"rw"}, DurabilityUntested, false},
		{"btrfs", []string{"rw"}, DurabilityUntested, false},
		{"f2fs", []string{"rw"}, DurabilityUntested, false},
		{"exfat", []string{"rw"}, "", true},
		{"vfat", []string{"rw"}, "", true},
		{"ntfs3", []string{"rw"}, "", true},
		{"fuseblk", []string{"rw"}, "", true},
		{"fuse.sshfs", []string{"rw"}, "", true},
		{"nfs4", []string{"rw"}, "", true},
		{"cifs", []string{"rw"}, "", true},
		{"tmpfs", []string{"rw"}, "", true},
		{"overlay", []string{"rw"}, "", true},
		{"ext4", []string{"rw", "nobarrier"}, "", true},
		{"ext4", []string{"rw", "barrier=0"}, "", true},
	}
	for _, c := range cases {
		got, err := Classify(MountEntry{MountPoint: "/mnt/x", FSType: c.fstype, MountOptions: []string{"rw"}, SuperOptions: c.super})
		if c.reject {
			if !errors.Is(err, ErrUnsupportedFS) {
				t.Errorf("%s %v: want ErrUnsupportedFS, got %v", c.fstype, c.super, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s: got (%q, %v), want %q", c.fstype, got, err, c.want)
		}
	}
}
```

- [ ] **Step 5: Run it to verify it fails**

Run: `go test ./internal/volume/`
Expected: FAIL with `undefined: Classify`.

- [ ] **Step 6: Implement the policy**

```go
package volume

import (
	"errors"
	"fmt"
)

// Durability records whether a vault's filesystems are tested (spec §9.3).
type Durability string

const (
	DurabilityTested   Durability = "tested"
	DurabilityUntested Durability = "untested"
)

// ErrUnsupportedFS means the filesystem can never hold a vault.
var ErrUnsupportedFS = errors.New("unsupported filesystem")

var (
	testedFS   = map[string]bool{"ext4": true}
	untestedFS = map[string]bool{"xfs": true, "btrfs": true, "f2fs": true}
)

// Classify applies the spec §9.3 policy: ext4 is tested; xfs, btrfs and f2fs
// are untested; everything else is rejected, as are mounts that disable
// cache flushes.
func Classify(m MountEntry) (Durability, error) {
	for _, opts := range [][]string{m.MountOptions, m.SuperOptions} {
		for _, o := range opts {
			if o == "nobarrier" || o == "barrier=0" {
				return "", fmt.Errorf("%w: %s is mounted with %q, which disables cache flushes", ErrUnsupportedFS, m.MountPoint, o)
			}
		}
	}
	switch {
	case testedFS[m.FSType]:
		return DurabilityTested, nil
	case untestedFS[m.FSType]:
		return DurabilityUntested, nil
	default:
		return "", fmt.Errorf("%w: %s is %s; CTVault requires ext4 (xfs, btrfs and f2fs only with --allow-untested-fs)", ErrUnsupportedFS, m.MountPoint, m.FSType)
	}
}
```

- [ ] **Step 7: Run it to verify it passes**

Run: `go test ./internal/volume/ -v`
Expected: PASS (`TestParseMountInfo`, `TestParseMountInfoRejectsMalformed`, `TestMountFor`, `TestClassify`).

- [ ] **Step 8: Commit**

```bash
git add internal/volume
git commit -m "feat(volume): mountinfo parser and filesystem policy"
```

---

### Task 3: Volume identity, init and check

**Files:**
- Create: `internal/volume/probe.go`, `internal/volume/probe_test.go`
- Create: `internal/volume/identity.go`, `internal/volume/volume.go`, `internal/volume/volume_test.go`
- Create: `internal/volume/volumetest/volumetest.go`

**Interfaces:**
- Consumes:
  - from Task 2: `MountEntry`, `MountFor`, `Classify`, `Durability`
  - from Task 1: `fsutil.WriteFileAtomic`, `fsutil.MkdirAllSync`
- Produces (package `volume`):
  - The probe:
    - `type Probe interface{ MountInfo() ([]MountEntry, error); FSUUID(m MountEntry) (string, error) }`
    - `var ErrNoUUID error`
    - `type HostProbe struct{ MountInfoPath, ByUUIDDir string }`
  - Identity markers:
    - constants `VaultIDFile = "VAULT_ID"`, `DirIDFile = "DIR_ID"`, `FormatVersion = 1`
    - `type Role string`, with `RoleRoot = "root"` and `RoleVaultDir = "vault_dir"`
    - `type Volume struct{ Role Role; Path, DirID, FSUUID, FSType string }`
    - `type VaultID struct{ Format int; VaultUUID string; CreatedAt time.Time; Durability Durability; Volumes []Volume }`
    - `type DirID struct{ Format int; VaultUUID, DirID, FSUUID string }`
    - `func NewUUID() (string, error)`
    - `func ReadVaultID(root string) (VaultID, error)`
    - `func ReadDirID(dir string) (DirID, error)`
  - The checker:
    - `var ErrVolume error` (the CLI maps it to exit 4)
    - `var LayoutDirs []string`
    - `type Checker struct{ Probe Probe; Now func() time.Time }`
    - `type Info struct{ Path string; Mount MountEntry; IsMountPoint, OnSystemRoot bool; FSUUID string; Durability Durability }`
    - `func (Checker) Inspect(path string) (Info, error)`
    - `type InitOptions struct{ AllowUntestedFS bool }`
    - `func (Checker) Init(root string, opts InitOptions) (VaultID, error)`
    - `func (Checker) Check(root string) (VaultID, error)`
    - `func (Checker) AddDir(root, dir string, opts InitOptions) (VaultID, error)`
- Produces (package `volumetest`):
  - `type Probe struct{ Mounts []volume.MountEntry; UUIDs map[string]string }`
  - `func New() *Probe` (its "/" is ext4 on device 8:1 with UUID `system-root`)
  - `func (*Probe) Mount(t testing.TB, dir, fstype, majorMinor, uuid string, superOpts ...string) string`

Volume paths in `VAULT_ID` are relative to the root for directories inside it (`"vault"`) and absolute otherwise. The root role is checked through the root path in use now, not the recorded one. That is what makes remounting at a new path work (Review Focus item 3).

- [ ] **Step 1: Add the x/sys dependency**

```bash
go get golang.org/x/sys@v0.48.0
```

- [ ] **Step 2: Write the failing tests and the fake probe**

`volume_test.go` is an external test package (`volume_test`), so it can import `volumetest`. That package in turn imports `volume`.

```go
// Package volumetest provides a fake volume.Probe so tests can present
// temporary directories as mounted filesystems without root privileges.
package volumetest

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/4rji/ctvault/internal/volume"
)

// Probe is an in-memory mount table plus a device → UUID map.
type Probe struct {
	Mounts []volume.MountEntry
	UUIDs  map[string]string // major:minor → filesystem UUID
}

// MountInfo returns the configured mount table.
func (p *Probe) MountInfo() ([]volume.MountEntry, error) { return p.Mounts, nil }

// FSUUID looks the mount's device up in UUIDs.
func (p *Probe) FSUUID(m volume.MountEntry) (string, error) {
	if u, ok := p.UUIDs[m.MajorMinor]; ok {
		return u, nil
	}
	return "", fmt.Errorf("%w: device %s", volume.ErrNoUUID, m.MajorMinor)
}

// New returns a probe whose "/" is ext4 on device 8:1 (UUID "system-root").
func New() *Probe {
	return &Probe{
		Mounts: []volume.MountEntry{{MountID: 1, MajorMinor: "8:1", Root: "/", MountPoint: "/", FSType: "ext4",
			Source: "/dev/sda1", MountOptions: []string{"rw"}, SuperOptions: []string{"rw"}}},
		UUIDs: map[string]string{"8:1": "system-root"},
	}
}

// Mount presents dir (resolved through symlinks) as a mount point of fstype on
// device majorMinor with filesystem UUID uuid. It returns the resolved path.
func (p *Probe) Mount(t testing.TB, dir, fstype, majorMinor, uuid string, superOpts ...string) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(superOpts) == 0 {
		superOpts = []string{"rw"}
	}
	p.Mounts = append(p.Mounts, volume.MountEntry{MountID: len(p.Mounts) + 1, MajorMinor: majorMinor, Root: "/",
		MountPoint: real, FSType: fstype, Source: "/dev/fake" + majorMinor, MountOptions: []string{"rw"}, SuperOptions: superOpts})
	if uuid != "" {
		p.UUIDs[majorMinor] = uuid
	}
	return real
}
```

```go
package volume

import (
	"errors"
	"os"
	"testing"
)

// TestHostProbeOnThisMachine reads the real mount table and resolves the UUID
// of the filesystem holding "/". It skips where /dev/disk/by-uuid is absent
// (some containers).
func TestHostProbeOnThisMachine(t *testing.T) {
	if _, err := os.Stat("/dev/disk/by-uuid"); err != nil {
		t.Skip("no /dev/disk/by-uuid on this host")
	}
	p := HostProbe{}
	ms, err := p.MountInfo()
	if err != nil {
		t.Fatal(err)
	}
	root, ok := MountFor(ms, "/")
	if !ok {
		t.Fatal("no mount for /")
	}
	uuid, err := p.FSUUID(root)
	if err != nil {
		t.Skipf("root filesystem has no by-uuid entry here: %v", err)
	}
	if len(uuid) < 8 {
		t.Fatalf("implausible UUID %q", uuid)
	}
}

func TestHostProbeMissingByUUID(t *testing.T) {
	p := HostProbe{ByUUIDDir: t.TempDir() + "/absent"}
	_, err := p.FSUUID(MountEntry{MountPoint: "/mnt/x", MajorMinor: "8:17", Source: "/dev/nonexistent"})
	if !errors.Is(err, ErrNoUUID) {
		t.Fatalf("want ErrNoUUID, got %v", err)
	}
}
```

```go
package volume_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/volume"
	"github.com/4rji/ctvault/internal/volume/volumetest"
)

var fixedNow = func() time.Time { return time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC) }

// newSSD returns a checker and a temp dir presented as an ext4 mount point
// on device 8:17 with UUID "ssd-uuid".
func newSSD(t *testing.T) (volume.Checker, *volumetest.Probe, string) {
	t.Helper()
	p := volumetest.New()
	root := p.Mount(t, t.TempDir(), "ext4", "8:17", "ssd-uuid")
	return volume.Checker{Probe: p, Now: fixedNow}, p, root
}

func wantVolumeErr(t *testing.T, err error, substr string) {
	t.Helper()
	if !errors.Is(err, volume.ErrVolume) {
		t.Fatalf("want ErrVolume, got %v", err)
	}
	if !strings.Contains(err.Error(), substr) {
		t.Fatalf("error %q does not mention %q", err, substr)
	}
}

func TestInitCreatesLayoutAndMarkers(t *testing.T) {
	c, _, root := newSSD(t)
	id, err := c.Init(root, volume.InitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if id.Durability != volume.DurabilityTested || len(id.Volumes) != 2 {
		t.Fatalf("unexpected VAULT_ID: %+v", id)
	}
	for _, d := range volume.LayoutDirs {
		if fi, err := os.Stat(filepath.Join(root, d)); err != nil || !fi.IsDir() {
			t.Errorf("layout dir %s missing", d)
		}
	}
	dir, err := volume.ReadDirID(filepath.Join(root, "vault"))
	if err != nil || dir.VaultUUID != id.VaultUUID || dir.FSUUID != "ssd-uuid" {
		t.Fatalf("DIR_ID = %+v, %v", dir, err)
	}
	got, err := c.Check(root)
	if err != nil {
		t.Fatalf("Check after Init: %v", err)
	}
	if got.VaultUUID != id.VaultUUID || !got.CreatedAt.Equal(fixedNow()) {
		t.Fatalf("Check returned %+v", got)
	}
}

func TestInitRefusals(t *testing.T) {
	t.Run("not a mount point", func(t *testing.T) {
		c, _, root := newSSD(t)
		sub := filepath.Join(root, "sub")
		os.Mkdir(sub, 0o755)
		_, err := c.Init(sub, volume.InitOptions{})
		wantVolumeErr(t, err, "not a mount point")
	})
	t.Run("system disk bind mount", func(t *testing.T) {
		p := volumetest.New()
		root := p.Mount(t, t.TempDir(), "ext4", "8:1", "system-root")
		_, err := volume.Checker{Probe: p}.Init(root, volume.InitOptions{})
		wantVolumeErr(t, err, "same device as /")
	})
	t.Run("untested filesystem", func(t *testing.T) {
		p := volumetest.New()
		root := p.Mount(t, t.TempDir(), "xfs", "8:17", "x")
		_, err := volume.Checker{Probe: p}.Init(root, volume.InitOptions{})
		wantVolumeErr(t, err, "--allow-untested-fs")
		id, err := volume.Checker{Probe: p}.Init(root, volume.InitOptions{AllowUntestedFS: true})
		if err != nil || id.Durability != volume.DurabilityUntested {
			t.Fatalf("with override: %+v, %v", id, err)
		}
	})
	t.Run("unsupported filesystem", func(t *testing.T) {
		p := volumetest.New()
		root := p.Mount(t, t.TempDir(), "exfat", "8:17", "x")
		_, err := volume.Checker{Probe: p}.Init(root, volume.InitOptions{AllowUntestedFS: true})
		wantVolumeErr(t, err, "exfat")
	})
	t.Run("nobarrier", func(t *testing.T) {
		p := volumetest.New()
		root := p.Mount(t, t.TempDir(), "ext4", "8:17", "x", "rw", "nobarrier")
		_, err := volume.Checker{Probe: p}.Init(root, volume.InitOptions{})
		wantVolumeErr(t, err, "nobarrier")
	})
	t.Run("no filesystem UUID", func(t *testing.T) {
		p := volumetest.New()
		root := p.Mount(t, t.TempDir(), "ext4", "8:17", "")
		_, err := volume.Checker{Probe: p}.Init(root, volume.InitOptions{})
		wantVolumeErr(t, err, "cannot determine filesystem UUID")
	})
	t.Run("not empty", func(t *testing.T) {
		c, _, root := newSSD(t)
		os.WriteFile(filepath.Join(root, "photos.zip"), nil, 0o644)
		_, err := c.Init(root, volume.InitOptions{})
		wantVolumeErr(t, err, "not empty")
	})
	t.Run("already initialized", func(t *testing.T) {
		c, _, root := newSSD(t)
		if _, err := c.Init(root, volume.InitOptions{}); err != nil {
			t.Fatal(err)
		}
		_, err := c.Init(root, volume.InitOptions{})
		wantVolumeErr(t, err, "already an initialized")
	})
}

func TestInitAllowsLostFoundAndRetry(t *testing.T) {
	c, _, root := newSSD(t)
	os.Mkdir(filepath.Join(root, "lost+found"), 0o700)
	os.MkdirAll(filepath.Join(root, "state", "intent"), 0o755) // interrupted earlier init
	if _, err := c.Init(root, volume.InitOptions{}); err != nil {
		t.Fatalf("Init should accept lost+found and partial layout: %v", err)
	}
}

func TestCheckDetectsDifferentFilesystem(t *testing.T) {
	c, p, root := newSSD(t)
	if _, err := c.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	p.UUIDs["8:17"] = "some-other-disk"
	_, err := c.Check(root)
	wantVolumeErr(t, err, "VAULT_ID records")
}

func TestCheckDetectsUnmountedDrive(t *testing.T) {
	c, p, root := newSSD(t)
	if _, err := c.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	p.Mounts = p.Mounts[:1] // only "/" remains: the path is now a plain directory on the system disk
	_, err := c.Check(root)
	wantVolumeErr(t, err, "not a mount point")
}

func TestCheckUninitialized(t *testing.T) {
	c, _, root := newSSD(t)
	_, err := c.Check(root)
	wantVolumeErr(t, err, "not an initialized CTVault root")
}

func TestCheckAcceptsTrailingSlashAndSymlink(t *testing.T) {
	c, _, root := newSSD(t)
	if _, err := c.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Check(root + "/"); err != nil {
		t.Fatalf("trailing slash: %v", err)
	}
	link := filepath.Join(t.TempDir(), "ctvault-link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Check(link); err != nil {
		t.Fatalf("symlink to root: %v", err)
	}
}

func TestCheckAfterRemountAtNewPath(t *testing.T) {
	c, _, oldRoot := newSSD(t)
	id, err := c.Init(oldRoot, volume.InitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// The same filesystem (same UUID) is mounted somewhere else next time.
	p2 := volumetest.New()
	newRoot := p2.Mount(t, t.TempDir(), "ext4", "8:65", "ssd-uuid")
	ents, _ := os.ReadDir(oldRoot)
	for _, e := range ents {
		if err := os.Rename(filepath.Join(oldRoot, e.Name()), filepath.Join(newRoot, e.Name())); err != nil {
			t.Fatal(err)
		}
	}
	got, err := volume.Checker{Probe: p2}.Check(newRoot)
	if err != nil {
		t.Fatalf("remounted vault should pass: %v", err)
	}
	if got.VaultUUID != id.VaultUUID {
		t.Fatal("vault identity changed")
	}
}

func TestAddDir(t *testing.T) {
	c, p, root := newSSD(t)
	if _, err := c.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	disk2 := p.Mount(t, t.TempDir(), "ext4", "8:33", "disk2-uuid")
	extra := filepath.Join(disk2, "ctvault-vault")
	id, err := c.AddDir(root, extra, volume.InitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(id.Volumes) != 3 || id.Volumes[2].FSUUID != "disk2-uuid" {
		t.Fatalf("volumes = %+v", id.Volumes)
	}
	if _, err := c.Check(root); err != nil {
		t.Fatalf("Check with added dir: %v", err)
	}
	p.UUIDs["8:33"] = "swapped-disk"
	_, err = c.Check(root)
	wantVolumeErr(t, err, "vault dir")
}

func TestAddDirRefusesSystemDiskAndNonEmpty(t *testing.T) {
	c, p, root := newSSD(t)
	if _, err := c.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	onSystem := filepath.Join(t.TempDir(), "v") // not mounted in the fake: lives on "/"
	_, err := c.AddDir(root, onSystem, volume.InitOptions{})
	wantVolumeErr(t, err, "same device as /")

	disk2 := p.Mount(t, t.TempDir(), "ext4", "8:33", "disk2-uuid")
	os.WriteFile(filepath.Join(disk2, "junk"), nil, 0o644)
	_, err = c.AddDir(root, disk2, volume.InitOptions{})
	wantVolumeErr(t, err, "not empty")
}
```

- [ ] **Step 3: Run them to verify they fail**

Run: `go test ./internal/volume/...`
Expected: FAIL with `undefined: volume.ErrNoUUID` (and similar undefined names).

- [ ] **Step 4: Implement the probe**

```go
package volume

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Probe reads the host's mount table and filesystem identities. Tests use
// volumetest.Probe; production uses HostProbe.
type Probe interface {
	MountInfo() ([]MountEntry, error)
	// FSUUID returns the filesystem UUID of the device backing the mount.
	FSUUID(m MountEntry) (string, error)
}

// ErrNoUUID means the filesystem UUID could not be determined.
var ErrNoUUID = errors.New("cannot determine filesystem UUID")

// HostProbe reads /proc/self/mountinfo and /dev/disk/by-uuid.
type HostProbe struct {
	MountInfoPath string // default /proc/self/mountinfo
	ByUUIDDir     string // default /dev/disk/by-uuid
}

// MountInfo parses the host mount table.
func (p HostProbe) MountInfo() ([]MountEntry, error) {
	path := p.MountInfoPath
	if path == "" {
		path = "/proc/self/mountinfo"
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseMountInfo(f)
}

// FSUUID finds the /dev/disk/by-uuid entry whose block device matches the
// mount's major:minor, or failing that, the device named as the mount source.
func (p HostProbe) FSUUID(m MountEntry) (string, error) {
	dir := p.ByUUIDDir
	if dir == "" {
		dir = "/dev/disk/by-uuid"
	}
	want := []string{m.MajorMinor}
	var st unix.Stat_t
	if unix.Stat(m.Source, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFBLK {
		want = append(want, devString(st.Rdev))
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("%w for %s: %v", ErrNoUUID, m.MountPoint, err)
	}
	for _, e := range ents {
		if unix.Stat(filepath.Join(dir, e.Name()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFBLK {
			continue
		}
		for _, w := range want {
			if devString(st.Rdev) == w {
				return e.Name(), nil
			}
		}
	}
	return "", fmt.Errorf("%w for %s (device %s): no match in %s", ErrNoUUID, m.MountPoint, m.MajorMinor, dir)
}

func devString(rdev uint64) string {
	return fmt.Sprintf("%d:%d", unix.Major(rdev), unix.Minor(rdev))
}
```

- [ ] **Step 5: Implement the identity markers**

```go
package volume

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/4rji/ctvault/internal/fsutil"
)

// Marker file names and format version (spec §9.1).
const (
	VaultIDFile   = "VAULT_ID"
	DirIDFile     = "DIR_ID"
	FormatVersion = 1
)

// Role is a volume's purpose within the vault.
type Role string

const (
	RoleRoot     Role = "root"
	RoleVaultDir Role = "vault_dir"
)

// Volume is one CTVault volume recorded in VAULT_ID. Path is relative to the
// root for directories inside it (so the drive can be remounted elsewhere)
// and absolute otherwise; for the root itself it records where init ran.
type Volume struct {
	Role   Role   `json:"role"`
	Path   string `json:"path"`
	DirID  string `json:"dir_id,omitempty"`
	FSUUID string `json:"fs_uuid"`
	FSType string `json:"fs_type"`
}

// VaultID is the content of <root>/VAULT_ID.
type VaultID struct {
	Format     int        `json:"format"`
	VaultUUID  string     `json:"vault_uuid"`
	CreatedAt  time.Time  `json:"created_at"`
	Durability Durability `json:"durability"`
	Volumes    []Volume   `json:"volumes"`
}

// DirID is the content of <vault dir>/DIR_ID.
type DirID struct {
	Format    int    `json:"format"`
	VaultUUID string `json:"vault_uuid"`
	DirID     string `json:"dir_id"`
	FSUUID    string `json:"fs_uuid"`
}

// NewUUID returns a random RFC 4122 version 4 UUID.
func NewUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, append(b, '\n'), 0o644)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// ReadVaultID reads <root>/VAULT_ID.
func ReadVaultID(root string) (VaultID, error) {
	var id VaultID
	if err := readJSON(filepath.Join(root, VaultIDFile), &id); err != nil {
		return id, err
	}
	if id.Format != FormatVersion || id.VaultUUID == "" {
		return id, fmt.Errorf("%s: unsupported format %d or missing vault_uuid", VaultIDFile, id.Format)
	}
	return id, nil
}

// ReadDirID reads <dir>/DIR_ID.
func ReadDirID(dir string) (DirID, error) {
	var d DirID
	err := readJSON(filepath.Join(dir, DirIDFile), &d)
	return d, err
}
```

- [ ] **Step 6: Implement the checker**

```go
// Package volume implements CTVault's volume-safety rules (spec §9): a vault
// lives on a dedicated, supported, identified filesystem, never on the system
// disk, and every command re-checks that identity before touching data.
package volume

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/4rji/ctvault/internal/fsutil"
)

// ErrVolume wraps every volume-check failure; the CLI maps it to exit code 4.
var ErrVolume = errors.New("volume check failed")

// LayoutDirs are created by Init (spec §4.3).
var LayoutDirs = []string{
	"state", "state/intent", "state/incidents", "state/logs",
	"vault", "vault/dict", "vault/segments",
	"dataset", "tmp", "logs",
}

// Checker performs volume checks through an injectable Probe.
type Checker struct {
	Probe Probe
	Now   func() time.Time
}

// Info describes the filesystem holding a path.
type Info struct {
	Path         string // absolute, symlinks resolved
	Mount        MountEntry
	IsMountPoint bool
	OnSystemRoot bool // same device as "/"
	FSUUID       string
	Durability   Durability
}

// Inspect resolves path and describes the filesystem that holds it.
func (c Checker) Inspect(path string) (Info, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Info{}, err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return Info{}, err
	}
	mounts, err := c.Probe.MountInfo()
	if err != nil {
		return Info{}, fmt.Errorf("reading mount table: %w", err)
	}
	m, ok := MountFor(mounts, real)
	if !ok {
		return Info{}, fmt.Errorf("%s is not on any mounted filesystem", real)
	}
	sys, ok := MountFor(mounts, "/")
	if !ok {
		return Info{}, errors.New("mount table has no entry for /")
	}
	info := Info{Path: real, Mount: m, IsMountPoint: m.MountPoint == real, OnSystemRoot: m.MajorMinor == sys.MajorMinor}
	if info.Durability, err = Classify(m); err != nil {
		return info, err
	}
	info.FSUUID, err = c.Probe.FSUUID(m)
	return info, err
}

func volErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrVolume, fmt.Sprintf(format, args...))
}

// InitOptions are the user's choices for Init and AddDir.
type InitOptions struct {
	AllowUntestedFS bool
}

func requireUsable(info Info, opts InitOptions, needMountPoint bool) error {
	switch {
	case needMountPoint && !info.IsMountPoint:
		return volErr("%s is not a mount point; mount the external SSD there first", info.Path)
	case info.OnSystemRoot:
		return volErr("%s is on the same device as /; CTVault refuses to write to the system disk", info.Path)
	case info.Durability == DurabilityUntested && !opts.AllowUntestedFS:
		return volErr("%s is %s, which is untested; pass --allow-untested-fs to accept weaker durability guarantees", info.Path, info.Mount.FSType)
	}
	return nil
}

// requireEmpty allows only lost+found and leftovers of an interrupted init.
func requireEmpty(dir string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	allowed := map[string]bool{"lost+found": true, "ctvault.toml": true}
	for _, d := range LayoutDirs {
		allowed[strings.SplitN(d, "/", 2)[0]] = true
	}
	for _, e := range ents {
		if e.Name() == VaultIDFile {
			return volErr("%s is already an initialized CTVault root", dir)
		}
		if !allowed[e.Name()] {
			return volErr("%s is not empty (found %q)", dir, e.Name())
		}
	}
	return nil
}

func (c Checker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Init prepares a new vault at root (spec §9.1). VAULT_ID is written last, so
// an interrupted Init can simply be run again.
func (c Checker) Init(root string, opts InitOptions) (VaultID, error) {
	info, err := c.Inspect(root)
	if err != nil {
		return VaultID{}, fmt.Errorf("%w: %v", ErrVolume, err)
	}
	if err := requireUsable(info, opts, true); err != nil {
		return VaultID{}, err
	}
	if err := requireEmpty(info.Path); err != nil {
		return VaultID{}, err
	}
	vaultUUID, err := NewUUID()
	if err != nil {
		return VaultID{}, err
	}
	dirUUID, err := NewUUID()
	if err != nil {
		return VaultID{}, err
	}
	for _, d := range LayoutDirs {
		if err := fsutil.MkdirAllSync(filepath.Join(info.Path, d), 0o755); err != nil {
			return VaultID{}, err
		}
	}
	dir := DirID{Format: FormatVersion, VaultUUID: vaultUUID, DirID: dirUUID, FSUUID: info.FSUUID}
	if err := writeJSON(filepath.Join(info.Path, "vault", DirIDFile), dir); err != nil {
		return VaultID{}, err
	}
	id := VaultID{
		Format: FormatVersion, VaultUUID: vaultUUID, CreatedAt: c.now().UTC(), Durability: info.Durability,
		Volumes: []Volume{
			{Role: RoleRoot, Path: info.Path, FSUUID: info.FSUUID, FSType: info.Mount.FSType},
			{Role: RoleVaultDir, Path: "vault", DirID: dirUUID, FSUUID: info.FSUUID, FSType: info.Mount.FSType},
		},
	}
	return id, writeJSON(filepath.Join(info.Path, VaultIDFile), id)
}

// Check verifies that root holds the vault its VAULT_ID describes and that
// every recorded volume is still the same filesystem (spec §9.2).
func (c Checker) Check(root string) (VaultID, error) {
	info, err := c.Inspect(root)
	if err != nil {
		return VaultID{}, fmt.Errorf("%w: %v", ErrVolume, err)
	}
	id, err := ReadVaultID(info.Path)
	if err != nil {
		return VaultID{}, volErr("%s is not an initialized CTVault root (%v)", info.Path, err)
	}
	for _, v := range id.Volumes {
		switch v.Role {
		case RoleRoot:
			if err := requireUsable(info, InitOptions{AllowUntestedFS: id.Durability == DurabilityUntested}, true); err != nil {
				return id, err
			}
			if v.FSUUID != info.FSUUID || v.FSType != info.Mount.FSType {
				return id, volErr("%s is filesystem %s (%s) but VAULT_ID records %s (%s)", info.Path, info.FSUUID, info.Mount.FSType, v.FSUUID, v.FSType)
			}
		case RoleVaultDir:
			if err := c.checkDir(info.Path, id, v); err != nil {
				return id, err
			}
		default:
			return id, volErr("VAULT_ID has unknown volume role %q", v.Role)
		}
	}
	return id, nil
}

func (c Checker) checkDir(root string, id VaultID, v Volume) error {
	p := v.Path
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, p)
	}
	vi, err := c.Inspect(p)
	if err != nil {
		return fmt.Errorf("%w: vault dir %s: %v", ErrVolume, p, err)
	}
	if err := requireUsable(vi, InitOptions{AllowUntestedFS: id.Durability == DurabilityUntested}, false); err != nil {
		return err
	}
	if vi.FSUUID != v.FSUUID {
		return volErr("vault dir %s is filesystem %s but VAULT_ID records %s", p, vi.FSUUID, v.FSUUID)
	}
	d, err := ReadDirID(vi.Path)
	if err != nil {
		return volErr("vault dir %s has no readable %s (%v)", p, DirIDFile, err)
	}
	if d.VaultUUID != id.VaultUUID || d.DirID != v.DirID {
		return volErr("vault dir %s belongs to vault %s dir %s, not %s dir %s", p, d.VaultUUID, d.DirID, id.VaultUUID, v.DirID)
	}
	return nil
}

// AddDir records an additional vault directory, usually on another disk
// (spec §9.1). The caller must hold the writer lock.
func (c Checker) AddDir(root, dir string, opts InitOptions) (VaultID, error) {
	id, err := c.Check(root)
	if err != nil {
		return id, err
	}
	if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
		return id, err
	}
	vi, err := c.Inspect(dir)
	if err != nil {
		return id, fmt.Errorf("%w: %v", ErrVolume, err)
	}
	if err := requireUsable(vi, opts, false); err != nil {
		return id, err
	}
	if ents, err := os.ReadDir(vi.Path); err != nil {
		return id, err
	} else if len(ents) > 0 {
		return id, volErr("%s is not empty", vi.Path)
	}
	if slices.ContainsFunc(id.Volumes, func(v Volume) bool { return v.Path == vi.Path }) {
		return id, volErr("%s is already a vault dir", vi.Path)
	}
	for _, sub := range []string{"dict", "segments"} {
		if err := fsutil.MkdirAllSync(filepath.Join(vi.Path, sub), 0o755); err != nil {
			return id, err
		}
	}
	dirUUID, err := NewUUID()
	if err != nil {
		return id, err
	}
	if err := writeJSON(filepath.Join(vi.Path, DirIDFile), DirID{Format: FormatVersion, VaultUUID: id.VaultUUID, DirID: dirUUID, FSUUID: vi.FSUUID}); err != nil {
		return id, err
	}
	id.Volumes = append(id.Volumes, Volume{Role: RoleVaultDir, Path: vi.Path, DirID: dirUUID, FSUUID: vi.FSUUID, FSType: vi.Mount.FSType})
	if vi.Durability == DurabilityUntested {
		id.Durability = DurabilityUntested
	}
	rootInfo, err := c.Inspect(root)
	if err != nil {
		return id, err
	}
	return id, writeJSON(filepath.Join(rootInfo.Path, VaultIDFile), id)
}
```

- [ ] **Step 7: Run them to verify they pass**

Run: `go test -count=1 ./internal/volume/... -v`
Expected: PASS. Covered:
- `TestInitCreatesLayoutAndMarkers`
- all eight `TestInitRefusals` subtests
- `TestInitAllowsLostFoundAndRetry`
- `TestCheckDetectsDifferentFilesystem`, `TestCheckDetectsUnmountedDrive`, `TestCheckUninitialized`
- `TestCheckAcceptsTrailingSlashAndSymlink`, `TestCheckAfterRemountAtNewPath`
- `TestAddDir`, `TestAddDirRefusesSystemDiskAndNonEmpty`
- `TestHostProbeMissingByUUID`, and `TestHostProbeOnThisMachine`, which passes, or skips where there is no `/dev/disk/by-uuid`

- [ ] **Step 8: Commit**

```bash
git add go.mod go.sum internal/volume
git commit -m "feat(volume): VAULT_ID/DIR_ID identity, init, check and add-dir"
```

---

### Task 4: Writer lock

**Files:**
- Create: `internal/lock/lock.go`, `internal/lock/lock_test.go`

**Interfaces:**
- Consumes: `golang.org/x/sys/unix` (from Task 3).
- Produces:
  - `var ErrHeld error`
  - `func Acquire(path string) (*Lock, error)`
  - `func (*Lock) Release() error`

  When the lock is held, the error reads `writer lock is held by PID <n> (<path>)`.

- [ ] **Step 1: Write the failing test**

```go
package lock

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestAcquireIsExclusiveAndNamesHolder(t *testing.T) {
	p := filepath.Join(t.TempDir(), "LOCK")
	a, err := Acquire(p)
	if err != nil {
		t.Fatal(err)
	}
	// flock locks belong to open file descriptions, so a second open in the
	// same process conflicts exactly like a second process would.
	_, err = Acquire(p)
	if !errors.Is(err, ErrHeld) {
		t.Fatalf("second Acquire: want ErrHeld, got %v", err)
	}
	if !strings.Contains(err.Error(), "PID "+strconv.Itoa(os.Getpid())) {
		t.Fatalf("error should name the holder PID: %v", err)
	}
	if err := a.Release(); err != nil {
		t.Fatal(err)
	}
	b, err := Acquire(p)
	if err != nil {
		t.Fatalf("Acquire after Release: %v", err)
	}
	b.Release()
}

func TestAcquireMissingDirectory(t *testing.T) {
	if _, err := Acquire(filepath.Join(t.TempDir(), "state", "LOCK")); err == nil {
		t.Fatal("expected error when state/ does not exist")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/lock/`
Expected: FAIL with `undefined: Acquire`.

- [ ] **Step 3: Implement the lock**

```go
// Package lock implements the single-writer lock on <root>/state/LOCK
// (spec §8.1). Readers never take it.
package lock

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// ErrHeld means another process holds the writer lock.
var ErrHeld = errors.New("writer lock is held")

// Lock is a held writer lock.
type Lock struct {
	f *os.File
}

// Acquire takes the exclusive writer lock without blocking and records this
// process's PID in the lock file so a second writer can name the holder.
func Acquire(path string) (*Lock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		holder := readPID(f)
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w by PID %s (%s)", ErrHeld, holder, path)
		}
		return nil, fmt.Errorf("locking %s: %w", path, err)
	}
	if err := writePID(f); err != nil {
		unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
		return nil, err
	}
	return &Lock{f: f}, nil
}

func writePID(f *os.File) error {
	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0); err != nil {
		return err
	}
	return f.Sync()
}

func readPID(f *os.File) string {
	b := make([]byte, 32)
	n, _ := f.ReadAt(b, 0)
	if s := strings.TrimSpace(string(b[:n])); s != "" {
		return s
	}
	return "unknown"
}

// Release drops the lock. The file stays behind with a stale PID, which is
// harmless: holding the flock, not the file content, is what counts.
func (l *Lock) Release() error {
	err := unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	return errors.Join(err, l.f.Close())
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `go test -count=1 ./internal/lock/ -v`
Expected: PASS (`TestAcquireIsExclusiveAndNamesHolder`, `TestAcquireMissingDirectory`).

- [ ] **Step 5: Commit**

```bash
git add internal/lock
git commit -m "feat(lock): single-writer flock that names the holder PID"
```

---

### Task 5: Configuration file

**Files:**
- Create: `internal/config/config.go`, `internal/config/config_test.go`

**Interfaces:**
- Consumes: `fsutil.WriteFileAtomic`.
- Produces:
  - `const FileName = "ctvault.toml"`
  - The types:
    - `type Config struct{ Ingest Ingest; Vault Vault; Disk Disk; Rebuild Rebuild }`
    - `Ingest{BatchSize, Workers int; MaxRPS float64; FollowInterval, StallTimeout Duration; DeltaLRUEntries int}`
    - `Vault{SegmentSize Size}`
    - `Disk{MaxUsedFraction, SafetyFactor float64}`
    - `Rebuild{Workers int}`
    - `type Duration struct{ time.Duration }`
    - `type Size uint64` (parses `1GiB`, `512MiB`, `64KiB` or bytes)
  - The functions:
    - `func Default() Config`
    - `const DefaultTOML`
    - `func Load(root string) (Config, error)` (a missing file gives defaults; unknown keys are errors)
    - `func (Config) Validate() error`
    - `func WriteDefault(root string) error` (never overwrites an existing file)

- [ ] **Step 1: Add the TOML dependency**

```bash
go get github.com/BurntSushi/toml@v1.6.0
```

- [ ] **Step 2: Write the failing test**

```go
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultTOMLMatchesDefault(t *testing.T) {
	root := t.TempDir()
	if err := WriteDefault(root); err != nil {
		t.Fatal(err)
	}
	got, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if got != Default() {
		t.Fatalf("DefaultTOML decodes to %+v, want %+v", got, Default())
	}
}

func TestLoadMissingFileGivesDefaults(t *testing.T) {
	got, err := Load(t.TempDir())
	if err != nil || got != Default() {
		t.Fatalf("Load without file = %+v, %v", got, err)
	}
}

func TestLoadOverridesAndUnits(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, FileName), []byte(`
[ingest]
batch_size = 1000
follow_interval = "30s"
[vault]
segment_size = "256MiB"
`), 0o644)
	got, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Ingest.BatchSize != 1000 || got.Ingest.FollowInterval.Duration != 30*time.Second || got.Vault.SegmentSize != 256<<20 {
		t.Fatalf("overrides not applied: %+v", got)
	}
	if got.Ingest.Workers != 4 {
		t.Fatal("unset keys must keep defaults")
	}
}

func TestLoadRejectsUnknownKeysAndBadValues(t *testing.T) {
	for name, body := range map[string]string{
		"typo":         "[ingest]\nbatchsize = 10\n",
		"cap too high": "[disk]\nmax_used_fraction = 0.99\n",
		"bad size":     "[vault]\nsegment_size = \"lots\"\n",
		"tiny segment": "[vault]\nsegment_size = \"4KiB\"\n",
		"zero workers": "[ingest]\nworkers = 0\n",
	} {
		root := t.TempDir()
		os.WriteFile(filepath.Join(root, FileName), []byte(body), 0o644)
		if _, err := Load(root); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestWriteDefaultKeepsExistingFile(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, FileName)
	os.WriteFile(p, []byte("[ingest]\nworkers = 8\n"), 0o644)
	if err := WriteDefault(root); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "workers = 8") {
		t.Fatal("WriteDefault overwrote an existing config")
	}
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `go test ./internal/config/`
Expected: FAIL with `undefined: WriteDefault`.

- [ ] **Step 4: Implement config**

The defaults are exactly spec §11.1. `max_rps` is written as `20.0`; integers such as `max_rps = 30` also load (verified during execution).

```go
// Package config loads <root>/ctvault.toml (spec §11.1). A missing file means
// defaults, so an interrupted init never leaves a vault unusable.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/4rji/ctvault/internal/fsutil"
)

// FileName is the config file inside the vault root.
const FileName = "ctvault.toml"

// Config mirrors the sections of ctvault.toml.
type Config struct {
	Ingest  Ingest  `toml:"ingest"`
	Vault   Vault   `toml:"vault"`
	Disk    Disk    `toml:"disk"`
	Rebuild Rebuild `toml:"rebuild"`
}

type Ingest struct {
	BatchSize       int      `toml:"batch_size"`
	Workers         int      `toml:"workers"`
	MaxRPS          float64  `toml:"max_rps"`
	FollowInterval  Duration `toml:"follow_interval"`
	StallTimeout    Duration `toml:"stall_timeout"`
	DeltaLRUEntries int      `toml:"delta_lru_entries"`
}

type Vault struct {
	SegmentSize Size `toml:"segment_size"`
}

type Disk struct {
	MaxUsedFraction float64 `toml:"max_used_fraction"`
	SafetyFactor    float64 `toml:"safety_factor"`
}

type Rebuild struct {
	Workers int `toml:"workers"`
}

// Duration is a time.Duration written as a Go duration string ("10m").
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	d.Duration = v
	return err
}

func (d Duration) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

// Size is a byte count written as "1GiB", "512MiB", "64KiB" or plain bytes.
type Size uint64

var sizeUnits = []struct {
	suffix string
	mult   uint64
}{{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"B", 1}}

func (s *Size) UnmarshalText(b []byte) error {
	str := strings.TrimSpace(string(b))
	for _, u := range sizeUnits {
		if num, ok := strings.CutSuffix(str, u.suffix); ok {
			n, err := strconv.ParseUint(strings.TrimSpace(num), 10, 64)
			if err != nil {
				return fmt.Errorf("invalid size %q", str)
			}
			*s = Size(n * u.mult)
			return nil
		}
	}
	n, err := strconv.ParseUint(str, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid size %q (use e.g. 1GiB)", str)
	}
	*s = Size(n)
	return nil
}

// Default returns the spec §11.1 defaults.
func Default() Config {
	return Config{
		Ingest: Ingest{BatchSize: 500000, Workers: 4, MaxRPS: 20,
			FollowInterval: Duration{10 * time.Minute}, StallTimeout: Duration{15 * time.Minute}, DeltaLRUEntries: 2000000},
		Vault:   Vault{SegmentSize: 1 << 30},
		Disk:    Disk{MaxUsedFraction: 0.85, SafetyFactor: 1.5},
		Rebuild: Rebuild{Workers: 2},
	}
}

// DefaultTOML is written by `ctvault init`.
const DefaultTOML = `# CTVault configuration (spec §11.1). Logs and volumes are managed with
# "ctvault logs add" and "ctvault vault add-dir", not in this file.

[ingest]
batch_size = 500000
workers = 4
max_rps = 20.0
follow_interval = "10m"
stall_timeout = "15m"
delta_lru_entries = 2000000

[vault]
segment_size = "1GiB"

[disk]
max_used_fraction = 0.85
safety_factor = 1.5

[rebuild]
workers = 2
`

// Load reads <root>/ctvault.toml over the defaults and validates the result.
// Unknown keys are errors so that typos do not silently fall back to defaults.
func Load(root string) (Config, error) {
	cfg := Default()
	b, err := os.ReadFile(filepath.Join(root, FileName))
	if errors.Is(err, fs.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	md, err := toml.Decode(string(b), &cfg)
	if err != nil {
		return cfg, fmt.Errorf("%s: %w", FileName, err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		return cfg, fmt.Errorf("%s: unknown keys: %s", FileName, strings.Join(keys, ", "))
	}
	return cfg, cfg.Validate()
}

// Validate rejects values that would make ingestion unsafe or meaningless.
func (c Config) Validate() error {
	var errs []error
	check := func(ok bool, format string, args ...any) {
		if !ok {
			errs = append(errs, fmt.Errorf(format, args...))
		}
	}
	check(c.Ingest.BatchSize >= 1, "ingest.batch_size must be >= 1")
	check(c.Ingest.Workers >= 1 && c.Ingest.Workers <= 64, "ingest.workers must be 1-64")
	check(c.Ingest.MaxRPS > 0, "ingest.max_rps must be > 0")
	check(c.Ingest.FollowInterval.Duration >= time.Second, "ingest.follow_interval must be >= 1s")
	check(c.Ingest.StallTimeout.Duration >= time.Second, "ingest.stall_timeout must be >= 1s")
	check(c.Ingest.DeltaLRUEntries >= 0, "ingest.delta_lru_entries must be >= 0")
	check(c.Vault.SegmentSize >= 1<<20, "vault.segment_size must be >= 1MiB")
	check(c.Disk.MaxUsedFraction > 0 && c.Disk.MaxUsedFraction <= 0.95, "disk.max_used_fraction must be in (0, 0.95]")
	check(c.Disk.SafetyFactor >= 1, "disk.safety_factor must be >= 1")
	check(c.Rebuild.Workers >= 1, "rebuild.workers must be >= 1")
	if len(errs) > 0 {
		return fmt.Errorf("%s: %w", FileName, errors.Join(errs...))
	}
	return nil
}

// WriteDefault writes DefaultTOML unless the file already exists.
func WriteDefault(root string) error {
	p := filepath.Join(root, FileName)
	if _, err := os.Stat(p); err == nil {
		return nil
	}
	return fsutil.WriteFileAtomic(p, []byte(DefaultTOML), 0o644)
}
```

- [ ] **Step 5: Run it to verify it passes**

Run: `go test -count=1 ./internal/config/ -v`
Expected: PASS (`TestDefaultTOMLMatchesDefault`, `TestLoadMissingFileGivesDefaults`, `TestLoadOverridesAndUnits`, `TestLoadRejectsUnknownKeysAndBadValues`, `TestWriteDefaultKeepsExistingFile`).

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/config
git commit -m "feat(config): ctvault.toml with spec defaults and strict validation"
```

---

### Task 6: Disk guard primitives

**Files:**
- Create: `internal/diskguard/diskguard.go`, `internal/diskguard/diskguard_test.go`

**Interfaces:**
- Consumes: `golang.org/x/sys/unix`.
- Produces:
  - Usage:
    - `type Usage struct{ Total, Avail uint64 }`, with `Used()` and `UsedFraction()` (a zero-sized filesystem counts as 1)
    - `type StatFunc func(path string) (Usage, error)`
    - `func Statfs(path string) (Usage, error)`
  - The cap check:
    - `var ErrCap error`
    - `type CapError struct{ Path string; Usage Usage; Need uint64; Cap float64 }` (matches `ErrCap`)
    - `type Guard struct{ Cap float64; Stat StatFunc }`
    - `func (Guard) Check(path string, need uint64) error`
  - The peak estimate:
    - constants `SeedVaultBytesPerEntry=840`, `SeedParquetBytesPerEntry=175`, `SeedPebbleBytesPerEntry=60`, `MinHistory=20`, `SegmentReserve=1<<30`, `MetadataOverhead=64<<20`, `MinPebbleCompactionReserve=2<<30`
    - `func P95(samples []float64, seed float64) float64`
    - `type PeakInput struct{ Entries uint64; VaultP95, ParquetP95, PebbleP95, Safety float64; PebbleSize, CanarySpill uint64; RebuildExtraPerEntry float64 }`
    - `type Peak struct{ Vault, Root uint64 }`
    - `func EstimatePeak(in PeakInput) Peak`

Plan 2 wires these into batch preflight. This task only builds and tests the primitives.

- [ ] **Step 1: Write the failing test**

```go
package diskguard

import (
	"errors"
	"strings"
	"testing"
)

const tb = 1_000_000_000_000

func fixed(u Usage) StatFunc { return func(string) (Usage, error) { return u, nil } }

func TestCheckUnderAndOverCap(t *testing.T) {
	g := Guard{Cap: 0.85, Stat: fixed(Usage{Total: 4 * tb, Avail: 2 * tb})} // 50% used
	if err := g.Check("/mnt/ctvault", tb); err != nil {
		t.Fatalf("75%% after write is under the cap: %v", err)
	}
	// The limit is rounded down (conservative), so ask for just under 85%.
	if err := g.Check("/mnt/ctvault", 1.399*tb); err != nil {
		t.Fatalf("84.98%% is allowed: %v", err)
	}
	err := g.Check("/mnt/ctvault", 1.5*tb)
	if !errors.Is(err, ErrCap) {
		t.Fatalf("87.5%% must be refused, got %v", err)
	}
	var ce *CapError
	if !errors.As(err, &ce) || ce.Need != 1.5*tb {
		t.Fatalf("CapError fields: %+v", ce)
	}
	if !strings.Contains(err.Error(), "cap 85%") {
		t.Fatalf("message should show the cap: %v", err)
	}
}

func TestCheckAlreadyOverCapAndHugeNeed(t *testing.T) {
	over := Guard{Cap: 0.85, Stat: fixed(Usage{Total: 100, Avail: 10})}
	if err := over.Check("/x", 0); !errors.Is(err, ErrCap) {
		t.Fatalf("volume already at 90%% must refuse even zero bytes: %v", err)
	}
	g := Guard{Cap: 0.85, Stat: fixed(Usage{Total: 100, Avail: 100})}
	if err := g.Check("/x", ^uint64(0)); !errors.Is(err, ErrCap) {
		t.Fatalf("overflowing need must refuse: %v", err)
	}
}

func TestCheckZeroSizedFilesystem(t *testing.T) {
	g := Guard{Cap: 0.85, Stat: fixed(Usage{})}
	if err := g.Check("/x", 0); !errors.Is(err, ErrCap) {
		t.Fatalf("zero-sized filesystem must refuse: %v", err)
	}
	if f := (Usage{}).UsedFraction(); f != 1 {
		t.Fatalf("UsedFraction of empty fs = %v, want 1", f)
	}
}

func TestStatfsOnTempDir(t *testing.T) {
	u, err := Statfs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if u.Total == 0 || u.Avail > u.Total {
		t.Fatalf("implausible usage %+v", u)
	}
}

func TestP95(t *testing.T) {
	if got := P95([]float64{1, 2, 3}, 840); got != 840 {
		t.Fatalf("short history must use the seed, got %v", got)
	}
	s := make([]float64, 20)
	for i := range s {
		s[i] = float64(20 - i) // 20..1, unsorted
	}
	if got := P95(s, 840); got != 19 {
		t.Fatalf("p95 of 1..20 = %v, want 19", got)
	}
}

func TestEstimatePeak(t *testing.T) {
	p := EstimatePeak(PeakInput{
		Entries: 500000, VaultP95: 840, ParquetP95: 175, PebbleP95: 60, Safety: 1.5,
		PebbleSize: 100 << 30, CanarySpill: 1 << 30,
	})
	wantVault := uint64(500000*840*1.5) + SegmentReserve
	wantRoot := uint64(500000*(175+60)*1.5) + 10<<30 + MetadataOverhead + 1<<30
	if p.Vault != wantVault || p.Root != wantRoot {
		t.Fatalf("peak = %+v, want vault %d root %d", p, wantVault, wantRoot)
	}
	small := EstimatePeak(PeakInput{Entries: 1, Safety: 1})
	if small.Root < MinPebbleCompactionReserve {
		t.Fatal("compaction reserve has a 2 GiB floor")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/diskguard/`
Expected: FAIL with `undefined: Usage`.

- [ ] **Step 3: Implement the guard**

The limit is `uint64(cap × total)`, so it rounds **down**. That is the conservative direction, and the test asks for "just under 85%" for that reason.

```go
// Package diskguard enforces the per-volume disk cap (spec §10.1): a batch may
// start only if its estimated peak fits under the cap, and nothing may ever
// push a volume past it.
package diskguard

import (
	"errors"
	"fmt"
	"math"
	"slices"

	"golang.org/x/sys/unix"
)

// Usage is a filesystem's size and the space available to unprivileged writers.
type Usage struct {
	Total uint64
	Avail uint64
}

// Used counts everything not available to us, including ext4's reserved blocks.
func (u Usage) Used() uint64 {
	if u.Avail > u.Total {
		return 0
	}
	return u.Total - u.Avail
}

// UsedFraction is Used/Total; a zero-sized filesystem counts as full.
func (u Usage) UsedFraction() float64 {
	if u.Total == 0 {
		return 1
	}
	return float64(u.Used()) / float64(u.Total)
}

// StatFunc reports usage for the filesystem holding path.
type StatFunc func(path string) (Usage, error)

// Statfs is the real StatFunc: (f_blocks − f_bavail) × fragment size.
func Statfs(path string) (Usage, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return Usage{}, err
	}
	bs := uint64(st.Frsize)
	if bs == 0 {
		bs = uint64(st.Bsize)
	}
	return Usage{Total: st.Blocks * bs, Avail: st.Bavail * bs}, nil
}

// ErrCap is matched by every *CapError.
var ErrCap = errors.New("disk cap would be exceeded")

// CapError reports the numbers behind a refusal.
type CapError struct {
	Path  string
	Usage Usage
	Need  uint64
	Cap   float64
}

func (e *CapError) Error() string {
	return fmt.Sprintf("%s: %v; %s used of %s (%.1f%%), need %s more, cap %.0f%% allows %s",
		e.Path, ErrCap, human(e.Usage.Used()), human(e.Usage.Total), 100*e.Usage.UsedFraction(),
		human(e.Need), 100*e.Cap, human(limit(e.Usage, e.Cap)))
}

func (e *CapError) Is(target error) bool { return target == ErrCap }

func limit(u Usage, capFrac float64) uint64 { return uint64(capFrac * float64(u.Total)) }

func human(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// Guard checks requests against a cap such as 0.85.
type Guard struct {
	Cap  float64
	Stat StatFunc
}

// Check returns a *CapError if adding need bytes to path's volume would take
// usage above Cap × Total.
func (g Guard) Check(path string, need uint64) error {
	u, err := g.Stat(path)
	if err != nil {
		return fmt.Errorf("statfs %s: %w", path, err)
	}
	lim, used := limit(u, g.Cap), u.Used()
	if u.Total == 0 || used > lim || need > lim-used {
		return &CapError{Path: path, Usage: u, Need: need, Cap: g.Cap}
	}
	return nil
}

// Seed bytes-per-entry figures used until MinHistory batches exist (spec §10.1).
const (
	SeedVaultBytesPerEntry   = 840
	SeedParquetBytesPerEntry = 175
	SeedPebbleBytesPerEntry  = 60
	MinHistory               = 20

	SegmentReserve             = 1 << 30
	MetadataOverhead           = 64 << 20
	MinPebbleCompactionReserve = 2 << 30
)

// P95 returns the 95th percentile of samples, or seed when there are fewer
// than MinHistory samples.
func P95(samples []float64, seed float64) float64 {
	if len(samples) < MinHistory {
		return seed
	}
	s := slices.Clone(samples)
	slices.Sort(s)
	return s[int(math.Ceil(0.95*float64(len(s))))-1]
}

// PeakInput holds the values the spec §10.1 formula needs.
type PeakInput struct {
	Entries              uint64
	VaultP95             float64 // bytes per entry
	ParquetP95           float64
	PebbleP95            float64
	Safety               float64
	PebbleSize           uint64
	CanarySpill          uint64
	RebuildExtraPerEntry float64 // derived bytes per entry for a dual-built version, 0 if none
}

// Peak is the space a batch may need on the vault volume and the root volume.
type Peak struct {
	Vault uint64
	Root  uint64
}

// EstimatePeak applies the spec §10.1 formula.
func EstimatePeak(in PeakInput) Peak {
	n := float64(in.Entries)
	compaction := max(uint64(MinPebbleCompactionReserve), in.PebbleSize/10)
	return Peak{
		Vault: uint64(math.Ceil(n*in.VaultP95*in.Safety)) + SegmentReserve,
		Root: uint64(math.Ceil(n*(in.ParquetP95+in.PebbleP95+in.RebuildExtraPerEntry)*in.Safety)) +
			compaction + MetadataOverhead + in.CanarySpill,
	}
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `go test -count=1 ./internal/diskguard/ -v`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/diskguard
git commit -m "feat(diskguard): per-volume cap check and spec §10.1 peak estimate"
```

---

### Task 7: Merkle verification with real Argon fixtures

**Files:**
- Create: the four real fixtures in `internal/testdata/`:
  - `log_list_google.json`
  - `argon2027h1_sth1.json`
  - `argon2027h1_sth2.json`
  - `argon2027h1_consistency.json`
- Create: `internal/merkle/sth.go`, `internal/merkle/state.go`, `internal/merkle/merkle_test.go`

**Interfaces:**
- Consumes: `github.com/transparency-dev/merkle` v0.0.2 (`compact`, `proof`, `rfc6962`, `testonly`).
- Produces:
  - Signed tree heads:
    - `type SignedTreeHead struct{ TreeSize, Timestamp uint64; RootHash [32]byte; Signature []byte }` (the signature is the raw TLS DigitallySigned bytes)
    - `var ErrBadSignature error`
    - `func VerifySTH(pub crypto.PublicKey, sth SignedTreeHead) error`
  - Hashing and the compact range:
    - `func LeafHash(leafInput []byte) [32]byte`
    - `type State`, with `NewState() *State` and the methods `Size() uint64`, `Append([32]byte) error`, `Root() ([32]byte, error)` and `Clone() *State`
    - `State` serializes to JSON as `{"size":N,"compact_range":[hex…]}`. That is the `merkle_after` format in spec §8.4.
  - Consistency:
    - `var ErrInconsistent error`
    - `func VerifyConsistency(size1, size2 uint64, root1, root2 [32]byte, p [][32]byte) error`

The fixtures are **real data** captured on 2026-10-04:
- a trimmed copy of Chrome's log list v93.3 (Google's operator only)
- two `argon2027h1` signed tree heads, at 384,065,451 and 384,071,894
- the 23-node consistency proof between them

Copy them byte for byte. The tests verify Google's real signatures and proof.

**Added during execution, at the user's request:** the fixtures are immutable test data.
- `internal/merkle/fixtures_test.go` (`TestFixturesAreUnchanged`) checks each file's SHA-256.
- `internal/testdata/README.md` records provenance and the never-refresh rule.
- `.gitattributes` adds `internal/testdata/** -text`, so line-ending conversion can never alter the bytes.

The guard test is written first and fails because the files are missing, and it passes once they are added.

- [ ] **Step 1: Add the fixtures**

`internal/testdata/log_list_google.json`:

```json
{
  "version": "93.3",
  "log_list_timestamp": "2026-10-03T13:35:24Z",
  "operators": [
    {
      "name": "Google",
      "email": [
        "google-ct-logs@googlegroups.com"
      ],
      "logs": [
        {
          "description": "Google 'Argon2026h2' log",
          "log_id": "1219ENGn9XfCx+lf1wC/+YLJM1pl4dCzAXMXwMjFaXc=",
          "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKjpni/66DIYrSlGK6Rf+e6F2c/28ZUvDJ79N81+gyimAESAyeNZ++TRgjHWg9TVQnKHTSU0T1TtqDupFnSQTIg==",
          "url": "https://ct.googleapis.com/logs/us1/argon2026h2/",
          "mmd": 86400,
          "state": {
            "usable": {
              "timestamp": "2024-09-30T22:19:27Z"
            }
          },
          "temporal_interval": {
            "start_inclusive": "2026-07-01T00:00:00Z",
            "end_exclusive": "2027-01-01T00:00:00Z"
          }
        },
        {
          "description": "Google 'Argon2027h1'",
          "log_id": "1tWNqdAXU/NqSqDHV0kCr+vH3CzTjNn3ZMgMiRkenwI=",
          "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKHRm0H/zUaFA6Idz5cGvGO3tCPQyfGMgJmVBOPyKAP6mGM1IiNXi4CLomOUyYj0YN74p+eGVApFMsM4h/jzCsA==",
          "url": "https://ct.googleapis.com/logs/us1/argon2027h1/",
          "mmd": 86400,
          "state": {
            "usable": {
              "timestamp": "2025-12-28T00:30:00Z"
            }
          },
          "temporal_interval": {
            "start_inclusive": "2027-01-01T00:00:00Z",
            "end_exclusive": "2027-07-01T00:00:00Z"
          }
        },
        {
          "description": "Google 'Xenon2026h2' log",
          "log_id": "2AlVO5RPev/IFhlvlE+Fq7D4/F6HVSYPFdEucrtFSxQ=",
          "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5Xd4lXEos5XJpcx6TOgyA5Z7/C4duaTbQ6C9aXL5Rbqaw+mW1XDnDX7JlRUninIwZYZDU9wRRBhJmCVopzwFvw==",
          "url": "https://ct.googleapis.com/logs/eu1/xenon2026h2/",
          "mmd": 86400,
          "state": {
            "usable": {
              "timestamp": "2024-09-30T22:19:27Z"
            }
          },
          "temporal_interval": {
            "start_inclusive": "2026-07-01T00:00:00Z",
            "end_exclusive": "2027-01-01T00:00:00Z"
          }
        },
        {
          "description": "Google 'Xenon2027h1'",
          "log_id": "RMK9DOkUDmSlyUoBkwpaobs1lw4A7hEWiWgqHETXtWY=",
          "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/6WcA4VRSljIfTdY48+pFRLLtLrmTb88cGDdl8Gv3E2LduG4jgJ3AK5iNMFGhpbRRLi5B3rPlBaXVywuR5IFDg==",
          "url": "https://ct.googleapis.com/logs/eu1/xenon2027h1/",
          "mmd": 86400,
          "state": {
            "usable": {
              "timestamp": "2025-12-28T00:30:00Z"
            }
          },
          "temporal_interval": {
            "start_inclusive": "2027-01-01T00:00:00Z",
            "end_exclusive": "2027-07-01T00:00:00Z"
          }
        }
      ],
      "tiled_logs": [
        {
          "description": "Google 'ParcelYard2027h1' log",
          "log_id": "HIl0B+YBCgEpO7Z439ejaM6xjMpSHcyk04bkoy5bXQQ=",
          "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEX7i7gYwmBxpiLXAlM/VLk4BFzspJRmZA86iReO7NVRlwGL1KWb/Dv5DRXJNBZd+9uREkNUTee5yBy2dRdRGa0w==",
          "submission_url": "https://parcelyard2027h1.prod.certificate.transparency.goog/",
          "monitoring_url": "https://storage.googleapis.com/parcelyard2027h1.prod.certificate.transparency.goog/",
          "mmd": 60,
          "state": {
            "usable": {
              "timestamp": "2026-08-31T13:50:00Z"
            }
          },
          "temporal_interval": {
            "start_inclusive": "2027-01-01T00:00:00Z",
            "end_exclusive": "2027-07-01T00:00:00Z"
          }
        },
        {
          "description": "Google 'PlumbersArms2027h1' log",
          "log_id": "X/nA+6QtrHjOZELrGazggaKb1OL7U68MYzB55QWCBMk=",
          "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAKYYdjIeQwDP0RIY9mhAVntX5s2ObMc2F6u8cELSbhvavljWD/OesJZHUtqQjBXE5Ekbpiq6nchmaVnEHHpJmw==",
          "submission_url": "https://plumbersarms2027h1.prod.certificate.transparency.goog/",
          "monitoring_url": "https://storage.googleapis.com/plumbersarms2027h1.prod.certificate.transparency.goog/",
          "mmd": 60,
          "state": {
            "usable": {
              "timestamp": "2026-08-31T13:50:00Z"
            }
          },
          "temporal_interval": {
            "start_inclusive": "2027-01-01T00:00:00Z",
            "end_exclusive": "2027-07-01T00:00:00Z"
          }
        }
      ]
    }
  ]
}
```

`internal/testdata/argon2027h1_sth1.json`:

```json
{"tree_size":384065451,"timestamp":1791095073447,"sha256_root_hash":"62+t2XxLmSqJnk7pxUna6EVA7+u+dotyl8q6wojifD8=","tree_head_signature":"BAMARzBFAiAOhTncRJL5E4FfPVNWRYhsEeGThRG21r4e5gOi1yK0WwIhAM/2qDFMO5uJhZ/mK17c1YcSK3vIjbE9qTTc/V5z4aTu"}
```

`internal/testdata/argon2027h1_sth2.json`:

```json
{"tree_size":384071894,"timestamp":1791095139948,"sha256_root_hash":"PRK7kHXyMbv9nTQAKoubWZ0KhDKtI6z/gPRWrnc+sGs=","tree_head_signature":"BAMARzBFAiBtlUTOF4jid3uymYHrCs9kWDFv2uA+Z1Lt+KBfeHQd4AIhAIK+tWh1lpR54bbmL0liu/vm9IM3kSFemUSEALEW/83N"}
```

`internal/testdata/argon2027h1_consistency.json`:

```json
{"consistency":["9u3YdOZDgbN2wSbaJP7U7/84pejnGTBu/NWZd3mmvO0=","qlplbDbJ35QNcAUu+Yjt5n20a9ZrFh7MCXzuIMDUy5Y=","GnKudDI2CNMwvgv951u8aHtf5LK0VsGn3QXjRcw104I=","Twu4yAFNF4jpxnrw6sxMJurSSgT1Vc67clwD/0TRSI0=","/3mVXmJqUx3i1WtQwn2ApkNCPLyv4PXzI0m0jNuNQ2Q=","E4tTksYQPO1mJmTHIPKbrasFDy5TmMAXFreOkUdsozU=","cdYdgfYY96e/3/r/njenmouHyhCAJuRgxTw0G0+SbPQ=","Z9x1/ZFk/cu7LKwf7aM/sxjK78pT/vECwOOHyOQiJgs=","HiSQC7Ym01GaiBr6nZ/7ya16vqWcCunLY5U9myxS/Fc=","GIZGmqlNtv7tam3IsJunxZMX5Q+tMcGp3s5q3IGufsk=","Foz0cJyd4oKFqUV3tNSk2ZPZlEvx80VOif3jiAWzgXk=","rYKbwB6vesfESl1Z6WS+j0+iyxYWbpwALp4/uo4K0u8=","7US3OehJNbJCURkhajomq6/fOBeaeRq5rixbAgDE6Hk=","p/TyuZ7+afBqLJBBTwHbhgDqVbBgkoqg7wo16aICLUs=","eUsJwf94b3sLzRjjVFHZ3Tipbbaa1p31VHZnKpbAJOc=","3JxaG+LYLt7/DBG9XpuieNRxM4Ik6yPBK3jJ069Px7c=","JfHQShc8Qdq0dHFJCLhQbyiRhN0MF5a0n6cbVyctrBo=","KjiTKgxN1O+q6jLLTQClBWdqRGWZi5HcK1uPJsG8jII=","JGjL9a4XEaexPPyc3nmSe9C/vDV74ILWLRRtfqSqpU0=","Fl7mMkWi4+OU6ANJ5lI+8WDd2y+3qKKfcf+FJhecZAs=","YQDbMi+MXqTmckWgwjaMvxvEcCSNq4k2umsobJ4xPJc=","NoHD/4b8CYUtVcDSafX+kjG4oR0MydtCmC9uUcc/y8I=","tEv0P40KfnW9PqT0m1YNG3dVZOg2q+V26CR2k20QJ/c="]}
```

- [ ] **Step 2: Add the Merkle dependency**

```bash
go get github.com/transparency-dev/merkle@v0.0.2
```

- [ ] **Step 3: Write the failing test**

```go
package merkle

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
)

// --- helpers -----------------------------------------------------------------

type sthJSON struct {
	TreeSize  uint64 `json:"tree_size"`
	Timestamp uint64 `json:"timestamp"`
	Root      string `json:"sha256_root_hash"`
	Sig       string `json:"tree_head_signature"`
}

func loadSTH(t *testing.T, name string) SignedTreeHead {
	t.Helper()
	raw, err := os.ReadFile("../testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var j sthJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		t.Fatal(err)
	}
	root, _ := base64.StdEncoding.DecodeString(j.Root)
	sig, _ := base64.StdEncoding.DecodeString(j.Sig)
	sth := SignedTreeHead{TreeSize: j.TreeSize, Timestamp: j.Timestamp, Signature: sig}
	copy(sth.RootHash[:], root)
	return sth
}

// argonKey reads the argon2027h1 public key from the real log list fixture.
func argonKey(t *testing.T) crypto.PublicKey {
	t.Helper()
	raw, err := os.ReadFile("../testdata/log_list_google.json")
	if err != nil {
		t.Fatal(err)
	}
	var ll struct {
		Operators []struct {
			Logs []struct{ URL, Key string } `json:"logs"`
		} `json:"operators"`
	}
	if err := json.Unmarshal(raw, &ll); err != nil {
		t.Fatal(err)
	}
	for _, l := range ll.Operators[0].Logs {
		if l.URL == "https://ct.googleapis.com/logs/us1/argon2027h1/" {
			der, _ := base64.StdEncoding.DecodeString(l.Key)
			pub, err := x509.ParsePKIXPublicKey(der)
			if err != nil {
				t.Fatal(err)
			}
			return pub
		}
	}
	t.Fatal("argon2027h1 missing from fixture")
	return nil
}

// sign builds a DigitallySigned blob over the STH with a test key.
func sign(t *testing.T, key crypto.Signer, sigAlg byte, sth SignedTreeHead) []byte {
	t.Helper()
	digest := sha256.Sum256(treeHeadSignatureInput(sth))
	sig, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	ds := []byte{hashAlgSHA256, sigAlg}
	ds = binary.BigEndian.AppendUint16(ds, uint16(len(sig)))
	return append(ds, sig...)
}

// --- STH signatures ----------------------------------------------------------

func TestVerifySTHRealArgon(t *testing.T) {
	pub := argonKey(t)
	for _, f := range []string{"argon2027h1_sth1.json", "argon2027h1_sth2.json"} {
		sth := loadSTH(t, f)
		if err := VerifySTH(pub, sth); err != nil {
			t.Fatalf("%s should verify: %v", f, err)
		}
		sth.TreeSize++
		if err := VerifySTH(pub, sth); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("%s with tampered size: got %v, want ErrBadSignature", f, err)
		}
	}
}

func TestVerifySTHTestKeys(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	sth := SignedTreeHead{TreeSize: 42, Timestamp: 1700000000000, RootHash: sha256.Sum256([]byte("root"))}

	ecSTH := sth
	ecSTH.Signature = sign(t, ec, sigAlgECDSA, sth)
	if err := VerifySTH(&ec.PublicKey, ecSTH); err != nil {
		t.Fatalf("ECDSA: %v", err)
	}
	rsaSTH := sth
	rsaSTH.Signature = sign(t, rk, sigAlgRSA, sth)
	if err := VerifySTH(&rk.PublicKey, rsaSTH); err != nil {
		t.Fatalf("RSA: %v", err)
	}

	bad := map[string]SignedTreeHead{
		"wrong key":           ecSTH,
		"truncated":           {TreeSize: 42, Signature: []byte{4, 3, 0}},
		"length mismatch":     {TreeSize: 42, Signature: append(append([]byte{}, ecSTH.Signature...), 0)},
		"sha1 hash algorithm": {TreeSize: 42, Signature: append([]byte{2}, ecSTH.Signature[1:]...)},
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, s := range bad {
		pub := crypto.PublicKey(&ec.PublicKey)
		if name == "wrong key" {
			pub = &other.PublicKey
		}
		if err := VerifySTH(pub, s); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: got %v, want ErrBadSignature", name, err)
		}
	}
	mislabeled := rsaSTH
	mislabeled.Signature = append([]byte{hashAlgSHA256, sigAlgECDSA}, rsaSTH.Signature[2:]...)
	if err := VerifySTH(&rk.PublicKey, mislabeled); !errors.Is(err, ErrBadSignature) {
		t.Errorf("RSA key with ECDSA label must fail, got %v", err)
	}
}

// --- compact range -----------------------------------------------------------

// TestStateMatchesRFC6962Vectors checks every tree size against the RFC 6962
// reference vectors shipped with transparency-dev/merkle: the root hash and
// the compact range we persist in _COMMIT.json (spec §8.4).
func TestStateMatchesRFC6962Vectors(t *testing.T) {
	leaves, roots, compacts := testonly.LeafInputs(), testonly.RootHashes(), testonly.CompactTrees()
	s := NewState()
	for size := 0; size <= len(leaves); size++ {
		if size > 0 {
			if err := s.Append(LeafHash(leaves[size-1])); err != nil {
				t.Fatal(err)
			}
		}
		root, err := s.Root()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(root[:], roots[size]) {
			t.Fatalf("size %d: root %x, want %x", size, root, roots[size])
		}
		b, _ := json.Marshal(s)
		var j struct {
			Hashes []string `json:"compact_range"`
		}
		json.Unmarshal(b, &j)
		if len(j.Hashes) != len(compacts[size]) {
			t.Fatalf("size %d: %d compact hashes, want %d", size, len(j.Hashes), len(compacts[size]))
		}
		for i, h := range compacts[size] {
			if j.Hashes[i] != fmt.Sprintf("%x", h) {
				t.Fatalf("size %d: compact hash %d differs", size, i)
			}
		}
	}
}

func TestStateMatchesReferenceTree(t *testing.T) {
	ref := testonly.New(rfc6962.DefaultHasher)
	s := NewState()
	empty, _ := s.Root()
	if string(empty[:]) != string(rfc6962.DefaultHasher.EmptyRoot()) {
		t.Fatal("empty state must have the RFC 6962 empty root")
	}
	for i := 0; i < 70; i++ {
		leaf := []byte(fmt.Sprintf("leaf-%d", i))
		ref.AppendData(leaf)
		if err := s.Append(LeafHash(leaf)); err != nil {
			t.Fatal(err)
		}
		got, err := s.Root()
		if err != nil {
			t.Fatal(err)
		}
		if string(got[:]) != string(ref.Hash()) || s.Size() != uint64(i+1) {
			t.Fatalf("size %d: root mismatch", i+1)
		}
	}
}

func TestStateJSONRoundTripAndClone(t *testing.T) {
	s := NewState()
	for i := 0; i < 13; i++ {
		s.Append(LeafHash([]byte{byte(i)}))
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var back State
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	r1, _ := s.Root()
	r2, _ := back.Root()
	if back.Size() != 13 || r1 != r2 {
		t.Fatalf("round trip changed state (size %d)", back.Size())
	}
	c := s.Clone()
	c.Append(LeafHash([]byte("more")))
	if s.Size() != 13 || c.Size() != 14 {
		t.Fatal("Clone must be independent")
	}
}

func TestStateUnmarshalRejectsGarbage(t *testing.T) {
	for _, in := range []string{
		`{"size": 13, "compact_range": ["zz"]}`,
		`{"size": 13, "compact_range": []}`,
		`{"size": 1, "compact_range": ["` + fmt.Sprintf("%064x", 1) + `", "` + fmt.Sprintf("%064x", 2) + `"]}`,
	} {
		var s State
		if err := json.Unmarshal([]byte(in), &s); err == nil {
			t.Errorf("accepted invalid state %s", in)
		}
	}
}

// --- consistency proofs ------------------------------------------------------

func TestVerifyConsistencyRealArgon(t *testing.T) {
	sth1, sth2 := loadSTH(t, "argon2027h1_sth1.json"), loadSTH(t, "argon2027h1_sth2.json")
	raw, err := os.ReadFile("../testdata/argon2027h1_consistency.json")
	if err != nil {
		t.Fatal(err)
	}
	var cj struct{ Consistency []string }
	json.Unmarshal(raw, &cj)
	p := make([][32]byte, len(cj.Consistency))
	for i, n := range cj.Consistency {
		d, _ := base64.StdEncoding.DecodeString(n)
		copy(p[i][:], d)
	}
	if err := VerifyConsistency(sth1.TreeSize, sth2.TreeSize, sth1.RootHash, sth2.RootHash, p); err != nil {
		t.Fatalf("real Argon proof should verify: %v", err)
	}
	p[0][0] ^= 1
	if err := VerifyConsistency(sth1.TreeSize, sth2.TreeSize, sth1.RootHash, sth2.RootHash, p); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("tampered proof: got %v", err)
	}
}

func TestVerifyConsistencyFromState(t *testing.T) {
	ref := testonly.New(rfc6962.DefaultHasher)
	s := NewState()
	for i := 0; i < 100; i++ {
		leaf := []byte(fmt.Sprintf("e%d", i))
		ref.AppendData(leaf)
		if i < 37 {
			s.Append(LeafHash(leaf))
		}
	}
	nodes, err := ref.ConsistencyProof(37, 100)
	if err != nil {
		t.Fatal(err)
	}
	p := make([][32]byte, len(nodes))
	for i, n := range nodes {
		copy(p[i][:], n)
	}
	var signedRoot [32]byte
	copy(signedRoot[:], ref.Hash())
	ours, _ := s.Root()
	if err := VerifyConsistency(37, 100, ours, signedRoot, p); err != nil {
		t.Fatalf("our prefix should be consistent: %v", err)
	}
	ours[5] ^= 1
	if err := VerifyConsistency(37, 100, ours, signedRoot, p); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("altered prefix must be inconsistent, got %v", err)
	}
}
```

- [ ] **Step 4: Run it to verify it fails**

Run: `go test ./internal/merkle/`
Expected: FAIL with `undefined: SignedTreeHead`.

- [ ] **Step 5: Implement STH verification**

The signed structure is RFC 6962 §3.5: `version(0) | signature_type(1 = tree_hash) | timestamp | tree_size | root_hash`.

```go
package merkle

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// SignedTreeHead is an RFC 6962 signed tree head with its raw DigitallySigned bytes.
type SignedTreeHead struct {
	TreeSize  uint64
	Timestamp uint64 // milliseconds since the Unix epoch
	RootHash  [32]byte
	Signature []byte // TLS DigitallySigned: hash alg (1) | sig alg (1) | uint16 len | sig
}

const (
	hashAlgSHA256 = 4
	sigAlgRSA     = 1
	sigAlgECDSA   = 3
)

// ErrBadSignature is returned when an STH signature does not verify.
var ErrBadSignature = errors.New("merkle: tree head signature does not verify")

// treeHeadSignatureInput builds the RFC 6962 §3.5 TreeHeadSignature structure.
func treeHeadSignatureInput(sth SignedTreeHead) []byte {
	b := make([]byte, 0, 2+8+8+32)
	b = append(b, 0 /* v1 */, 1 /* tree_hash */)
	b = binary.BigEndian.AppendUint64(b, sth.Timestamp)
	b = binary.BigEndian.AppendUint64(b, sth.TreeSize)
	return append(b, sth.RootHash[:]...)
}

// VerifySTH checks the STH signature with the log's public key (ECDSA P-256 or RSA, SHA-256).
func VerifySTH(pub crypto.PublicKey, sth SignedTreeHead) error {
	ds := sth.Signature
	if len(ds) < 4 {
		return fmt.Errorf("%w: DigitallySigned too short (%d bytes)", ErrBadSignature, len(ds))
	}
	hashAlg, sigAlg := ds[0], ds[1]
	n := int(binary.BigEndian.Uint16(ds[2:4]))
	if len(ds) != 4+n {
		return fmt.Errorf("%w: signature length %d does not match %d remaining bytes", ErrBadSignature, n, len(ds)-4)
	}
	if hashAlg != hashAlgSHA256 {
		return fmt.Errorf("%w: unsupported hash algorithm %d", ErrBadSignature, hashAlg)
	}
	sig := ds[4:]
	digest := sha256.Sum256(treeHeadSignatureInput(sth))
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if sigAlg != sigAlgECDSA || !ecdsa.VerifyASN1(k, digest[:], sig) {
			return ErrBadSignature
		}
	case *rsa.PublicKey:
		if sigAlg != sigAlgRSA || rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig) != nil {
			return ErrBadSignature
		}
	default:
		return fmt.Errorf("%w: unsupported key type %T", ErrBadSignature, pub)
	}
	return nil
}
```

- [ ] **Step 6: Implement the compact range and consistency verification**

`GetRootHash` returns nil for an empty range, so `Root()` returns the RFC 6962 empty root (SHA-256 of nothing) explicitly.

```go
package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

var factory = &compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}

// ErrInconsistent is returned when a consistency proof or root comparison fails.
var ErrInconsistent = errors.New("merkle: tree is inconsistent with signed head")

// LeafHash returns the RFC 6962 leaf hash SHA-256(0x00 || leafInput).
func LeafHash(leafInput []byte) [32]byte {
	var h [32]byte
	copy(h[:], rfc6962.DefaultHasher.HashLeaf(leafInput))
	return h
}

// State is the compact Merkle range for leaves [0, Size) of one log.
type State struct {
	r *compact.Range
}

// NewState returns the state of an empty log.
func NewState() *State { return &State{r: factory.NewEmptyRange(0)} }

// Size returns the number of leaves accumulated.
func (s *State) Size() uint64 { return s.r.End() }

// Append adds the next leaf hash. Callers must append in strict index order.
func (s *State) Append(leafHash [32]byte) error { return s.r.Append(leafHash[:], nil) }

// Root returns the RFC 6962 root hash of leaves [0, Size).
func (s *State) Root() ([32]byte, error) {
	var out [32]byte
	if s.r.End() == 0 {
		copy(out[:], rfc6962.DefaultHasher.EmptyRoot())
		return out, nil
	}
	h, err := s.r.GetRootHash(nil)
	if err != nil {
		return out, err
	}
	copy(out[:], h)
	return out, nil
}

// Clone returns an independent copy.
func (s *State) Clone() *State {
	c, err := factory.NewRange(0, s.r.End(), s.r.Hashes())
	if err != nil {
		panic(fmt.Sprintf("merkle: cloning a valid range failed: %v", err))
	}
	return &State{r: c}
}

type stateJSON struct {
	Size   uint64   `json:"size"`
	Hashes []string `json:"compact_range"`
}

// MarshalJSON encodes the state as {"size": N, "compact_range": [hex...]}.
func (s *State) MarshalJSON() ([]byte, error) {
	hs := s.r.Hashes()
	out := stateJSON{Size: s.r.End(), Hashes: make([]string, len(hs))}
	for i, h := range hs {
		out.Hashes[i] = hex.EncodeToString(h)
	}
	return json.Marshal(out)
}

// UnmarshalJSON decodes and validates the state.
func (s *State) UnmarshalJSON(b []byte) error {
	var in stateJSON
	if err := json.Unmarshal(b, &in); err != nil {
		return err
	}
	hs := make([][]byte, len(in.Hashes))
	for i, h := range in.Hashes {
		d, err := hex.DecodeString(h)
		if err != nil || len(d) != sha256.Size {
			return fmt.Errorf("merkle: compact_range[%d] is not a 32-byte hex hash", i)
		}
		hs[i] = d
	}
	r, err := factory.NewRange(0, in.Size, hs)
	if err != nil {
		return fmt.Errorf("merkle: invalid compact range for size %d: %w", in.Size, err)
	}
	s.r = r
	return nil
}

// VerifyConsistency checks that the tree of size1 with root1 is a prefix of the
// signed tree of size2 with root2.
func VerifyConsistency(size1, size2 uint64, root1, root2 [32]byte, p [][32]byte) error {
	nodes := make([][]byte, len(p))
	for i := range p {
		nodes[i] = p[i][:]
	}
	if err := proof.VerifyConsistency(rfc6962.DefaultHasher, size1, size2, nodes, root1[:], root2[:]); err != nil {
		return fmt.Errorf("%w: %v", ErrInconsistent, err)
	}
	return nil
}
```

- [ ] **Step 7: Run it to verify it passes**

Run: `go test -count=1 ./internal/merkle/ -v`
Expected: PASS. Covered:
- `TestVerifySTHRealArgon`, `TestVerifySTHTestKeys`
- `TestStateMatchesRFC6962Vectors`, which checks the RFC 6962 reference vectors, both roots and compact ranges
- `TestStateMatchesReferenceTree`, `TestStateJSONRoundTripAndClone`, `TestStateUnmarshalRejectsGarbage`
- `TestVerifyConsistencyRealArgon`, `TestVerifyConsistencyFromState`

- [ ] **Step 8: Commit**

```bash
git add go.mod go.sum internal/testdata internal/merkle
git commit -m "feat(merkle): STH signatures, compact range and consistency proofs (real Argon fixtures)"
```

---

### Task 8: Fake CT log for tests

**Files:**
- Create: `internal/ctlogtest/entries.go`, `internal/ctlogtest/log.go`, `internal/ctlogtest/log_test.go`

**Interfaces:**
- Consumes: `testonly.Tree` and `rfc6962.DefaultHasher` from transparency-dev/merkle.
- Produces (test infrastructure only; production code must never import it):
  - Entries:
    - `type EntryType uint16`, with `X509Entry=0` and `PrecertEntry=1`
    - `type Entry struct{ Type EntryType; Timestamp uint64; CertDER, PrecertTBS []byte; IssuerKeyHash [32]byte; LeafInput, ExtraData []byte }`
    - `func MerkleTreeLeaf(ts uint64, typ EntryType, certOrTBS []byte, issuerKeyHash [32]byte) []byte`
  - The certificate generator:
    - `type Generator`, with `NewGenerator() (*Generator, error)`
    - `(*Generator) CADER() []byte`
    - `(*Generator) Pair(name string, ts uint64) (pre, final Entry, err error)`
    - `(*Generator) Entries(n int) ([]Entry, error)`
  - The fake log:
    - `type Options struct{ PageSize, RateLimitEvery, ShortReadEvery, CorruptJSONEvery, InvalidBase64Every int; BadSTHSignature bool; AlterEntries []uint64 }`
    - `type Log struct{ URL string; PublicKeyDER []byte; LogID [32]byte; Entries []Entry; … }`
    - `func New(t testing.TB, n int, opts Options) *Log`
    - `func NewWithEntries(t testing.TB, entries []Entry, opts Options) *Log`
    - `(*Log) Publish(size uint64)`, `(*Log) Fork(index uint64)`, `(*Log) Requests(endpoint string) int`

The generator follows RFC 6962 §3.1 exactly. The precert TBS with the poison extension removed equals the final certificate's TBS without the SCT list. Plan 3's issuance-key tests rely on this.

- [ ] **Step 1: Write the failing test**

```go
package ctlogtest

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
)

type wireEntries struct {
	Entries []struct {
		LeafInput string `json:"leaf_input"`
		ExtraData string `json:"extra_data"`
	} `json:"entries"`
}

func get(t *testing.T, url string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	return resp, buf.Bytes()
}

func TestPairIsRFC6962Consistent(t *testing.T) {
	g, err := NewGenerator()
	if err != nil {
		t.Fatal(err)
	}
	pre, fin, err := g.Pair("a.example.test", 1)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := x509.ParseCertificate(pre.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	fc, err := x509.ParseCertificate(fin.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	if pc.SerialNumber.Cmp(fc.SerialNumber) != 0 || len(pc.Extensions) != len(fc.Extensions) {
		t.Fatal("precert and final cert must describe the same issuance")
	}
	if bytes.Equal(pre.CertDER, fin.CertDER) || len(pre.PrecertTBS) == 0 {
		t.Fatal("precert and final cert must differ")
	}
	if pre.LeafInput[11] != byte(PrecertEntry) || fin.LeafInput[11] != byte(X509Entry) {
		t.Fatal("entry types are encoded at offset 10-11")
	}
}

func TestServesEntriesInPages(t *testing.T) {
	l := New(t, 10, Options{PageSize: 4})
	resp, body := get(t, l.URL+"ct/v1/get-entries?start=2&end=9")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var we wireEntries
	if err := json.Unmarshal(body, &we); err != nil {
		t.Fatal(err)
	}
	if len(we.Entries) != 4 {
		t.Fatalf("page size 4: got %d entries", len(we.Entries))
	}
	leaf, _ := base64.StdEncoding.DecodeString(we.Entries[0].LeafInput)
	if !bytes.Equal(leaf, l.Entries[2].LeafInput) {
		t.Fatal("first entry must be index 2")
	}
	if resp, _ := get(t, l.URL+"ct/v1/get-entries?start=10&end=12"); resp.StatusCode != 400 {
		t.Fatalf("start beyond the tree must be 400, got %d", resp.StatusCode)
	}
}

func TestFaultInjection(t *testing.T) {
	l := New(t, 8, Options{RateLimitEvery: 2, ShortReadEvery: 1, InvalidBase64Every: 1})
	resp, _ := get(t, l.URL+"ct/v1/get-entries?start=0&end=7") // request 1: served
	if resp.StatusCode != 200 {
		t.Fatalf("first request: %d", resp.StatusCode)
	}
	resp, _ = get(t, l.URL+"ct/v1/get-sth") // request 2: rate limited
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") != "1" {
		t.Fatalf("want 429 with Retry-After, got %d", resp.StatusCode)
	}
	_, body := get(t, l.URL+"ct/v1/get-entries?start=0&end=7") // request 3
	var we wireEntries
	json.Unmarshal(body, &we)
	if len(we.Entries) != 4 {
		t.Fatalf("short read should halve 8 entries to 4, got %d", len(we.Entries))
	}
	if we.Entries[0].LeafInput != "!!not-base64!!" {
		t.Fatal("invalid base64 not injected")
	}

	c := New(t, 4, Options{CorruptJSONEvery: 1})
	_, body = get(t, c.URL+"ct/v1/get-entries?start=0&end=3")
	if json.Valid(body) {
		t.Fatal("corrupt JSON not injected")
	}
}

func TestPublishAndAlter(t *testing.T) {
	l := New(t, 6, Options{AlterEntries: []uint64{1}})
	l.Publish(3)
	_, body := get(t, l.URL+"ct/v1/get-sth")
	if !bytes.Contains(body, []byte(`"tree_size":3`)) {
		t.Fatalf("published size not honoured: %s", body)
	}
	_, body = get(t, l.URL+"ct/v1/get-entries?start=0&end=5")
	var we wireEntries
	json.Unmarshal(body, &we)
	if len(we.Entries) != 3 {
		t.Fatalf("entries beyond the published size must not be served, got %d", len(we.Entries))
	}
	leaf, _ := base64.StdEncoding.DecodeString(we.Entries[1].LeafInput)
	if bytes.Equal(leaf, l.Entries[1].LeafInput) {
		t.Fatal("entry 1 should be served altered")
	}
	if l.Requests("get-entries") != 1 {
		t.Fatal("request counting is wrong")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/ctlogtest/`
Expected: FAIL with `undefined: NewGenerator`.

- [ ] **Step 3: Implement entries and the certificate generator**

```go
// Package ctlogtest is an in-process fake RFC 6962 CT log backed by a real
// Merkle tree, with fault injection for tests (spec §13.4). It is test
// infrastructure only and must never be imported by production code.
package ctlogtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"
)

// EntryType is the RFC 6962 LogEntryType.
type EntryType uint16

const (
	X509Entry    EntryType = 0
	PrecertEntry EntryType = 1
)

// Entry is one log entry, with both the wire bytes and the parts tests check.
type Entry struct {
	Type          EntryType
	Timestamp     uint64 // ms
	CertDER       []byte // final certificate, or the precertificate for PrecertEntry
	PrecertTBS    []byte // PrecertEntry only: TBS with the poison extension removed
	IssuerKeyHash [32]byte
	LeafInput     []byte // MerkleTreeLeaf
	ExtraData     []byte
}

var (
	poisonOID  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	sctListOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

func appendU24(b, data []byte) []byte {
	n := len(data)
	return append(append(b, byte(n>>16), byte(n>>8), byte(n)), data...)
}

// MerkleTreeLeaf encodes an RFC 6962 §3.4 MerkleTreeLeaf: version v1,
// timestamped_entry, the signed entry, and empty CtExtensions.
func MerkleTreeLeaf(ts uint64, typ EntryType, certOrTBS []byte, issuerKeyHash [32]byte) []byte {
	b := []byte{0, 0}
	b = binary.BigEndian.AppendUint64(b, ts)
	b = binary.BigEndian.AppendUint16(b, uint16(typ))
	if typ == PrecertEntry {
		b = append(b, issuerKeyHash[:]...)
	}
	b = appendU24(b, certOrTBS)
	return binary.BigEndian.AppendUint16(b, 0)
}

// chain encodes a TLS vector<ASN.1Cert> with a 24-bit total length.
func chain(certs ...[]byte) []byte {
	var body []byte
	for _, c := range certs {
		body = appendU24(body, c)
	}
	return appendU24(nil, body)
}

// Generator issues certificates from a throwaway ECDSA CA.
type Generator struct {
	caKey  *ecdsa.PrivateKey
	ca     *x509.Certificate
	serial int64
	t0     time.Time
}

// NewGenerator creates a self-signed test CA.
func NewGenerator() (*Generator, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CTVault Test CA", Organization: []string{"CTVault Tests"}},
		NotBefore: t0.Add(-24 * time.Hour), NotAfter: t0.Add(5 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Generator{caKey: key, ca: ca, serial: 1, t0: t0}, nil
}

// CADER returns the CA certificate.
func (g *Generator) CADER() []byte { return g.ca.Raw }

// Pair issues one certificate as a precert entry and its final x509 entry,
// exactly as RFC 6962 §3.1 describes: the precert TBS with the poison
// extension removed equals the final cert TBS without the SCT list.
func (g *Generator) Pair(name string, ts uint64) (pre, final Entry, err error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return pre, final, err
	}
	g.serial++
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(g.serial), Subject: pkix.Name{CommonName: name},
		DNSNames:  []string{name, "www." + name},
		NotBefore: g.t0, NotAfter: g.t0.Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	issue := func(extra ...pkix.Extension) ([]byte, error) {
		t := tmpl
		t.ExtraExtensions = extra
		return x509.CreateCertificate(rand.Reader, &t, g.ca, &leafKey.PublicKey, g.caKey)
	}
	plainDER, err := issue()
	if err != nil {
		return pre, final, err
	}
	plain, err := x509.ParseCertificate(plainDER)
	if err != nil {
		return pre, final, err
	}
	preDER, err := issue(pkix.Extension{Id: poisonOID, Critical: true, Value: []byte{0x05, 0x00}})
	if err != nil {
		return pre, final, err
	}
	// An empty SignedCertificateTimestampList wrapped in an OCTET STRING.
	finDER, err := issue(pkix.Extension{Id: sctListOID, Value: []byte{0x04, 0x02, 0x00, 0x00}})
	if err != nil {
		return pre, final, err
	}
	ikh := sha256.Sum256(g.ca.RawSubjectPublicKeyInfo)
	pre = Entry{Type: PrecertEntry, Timestamp: ts, CertDER: preDER, PrecertTBS: plain.RawTBSCertificate, IssuerKeyHash: ikh}
	pre.LeafInput = MerkleTreeLeaf(ts, PrecertEntry, plain.RawTBSCertificate, ikh)
	pre.ExtraData = append(appendU24(nil, preDER), chain(g.ca.Raw)...)
	final = Entry{Type: X509Entry, Timestamp: ts + 1000, CertDER: finDER}
	final.LeafInput = MerkleTreeLeaf(ts+1000, X509Entry, finDER, [32]byte{})
	final.ExtraData = chain(g.ca.Raw)
	return pre, final, nil
}

// Entries issues n entries as alternating precert/final pairs (a trailing odd
// entry is a lone precert), named host<i>.example.test.
func (g *Generator) Entries(n int) ([]Entry, error) {
	out := make([]Entry, 0, n)
	for i := 0; len(out) < n; i++ {
		pre, fin, err := g.Pair(fmt.Sprintf("host%d.example.test", i), 1790000000000+uint64(i)*2000)
		if err != nil {
			return nil, err
		}
		out = append(out, pre)
		if len(out) < n {
			out = append(out, fin)
		}
	}
	return out, nil
}
```

- [ ] **Step 4: Implement the fake log server**

```go
package ctlogtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
)

// Options configures page size and fault injection. Every "Every" counter
// fires on its Nth matching request (1 = every request, 0 = never).
type Options struct {
	PageSize           int // max entries per get-entries response; default 32
	RateLimitEvery     int // any endpoint answers 429 with Retry-After: 1
	ShortReadEvery     int // get-entries returns half of what it would have
	CorruptJSONEvery   int // get-entries returns truncated JSON
	InvalidBase64Every int // get-entries returns an invalid base64 leaf_input
	BadSTHSignature    bool
	AlterEntries       []uint64 // these indices are served with a modified leaf_input
}

// Log is a running fake log.
type Log struct {
	URL          string // base URL ending in "/"
	PublicKeyDER []byte // SPKI, as the log list publishes it
	LogID        [32]byte
	Entries      []Entry

	key  *ecdsa.PrivateKey
	opts Options
	srv  *httptest.Server

	mu        sync.Mutex
	tree      *testonly.Tree // tree used for STHs and proofs
	honest    *testonly.Tree
	published uint64
	counts    map[string]int
	altered   map[uint64]bool
}

// New starts a fake log holding n generated entries, all published.
func New(t testing.TB, n int, opts Options) *Log {
	t.Helper()
	g, err := NewGenerator()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := g.Entries(n)
	if err != nil {
		t.Fatal(err)
	}
	return NewWithEntries(t, entries, opts)
}

// NewWithEntries starts a fake log serving the given entries.
func NewWithEntries(t testing.TB, entries []Entry, opts Options) *Log {
	t.Helper()
	if opts.PageSize == 0 {
		opts.PageSize = 32
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	l := &Log{PublicKeyDER: spki, LogID: sha256.Sum256(spki), Entries: entries, key: key, opts: opts,
		honest: testonly.New(rfc6962.DefaultHasher), published: uint64(len(entries)),
		counts: map[string]int{}, altered: map[uint64]bool{}}
	for _, e := range entries {
		l.honest.AppendData(e.LeafInput)
	}
	l.tree = l.honest
	for _, i := range opts.AlterEntries {
		l.altered[i] = true
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ct/v1/get-sth", l.getSTH)
	mux.HandleFunc("GET /ct/v1/get-sth-consistency", l.getConsistency)
	mux.HandleFunc("GET /ct/v1/get-entries", l.getEntries)
	l.srv = httptest.NewServer(mux)
	t.Cleanup(l.srv.Close)
	l.URL = l.srv.URL + "/"
	return l
}

// Publish sets the tree size reported by get-sth. It may shrink, which a
// correct client must treat as log misbehaviour.
func (l *Log) Publish(size uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if size > uint64(len(l.Entries)) {
		size = uint64(len(l.Entries))
	}
	l.published = size
}

// Fork makes STHs and proofs come from a tree whose leaf at index differs:
// a split view that consistency checks must detect.
func (l *Log) Fork(index uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fork := testonly.New(rfc6962.DefaultHasher)
	for i, e := range l.Entries {
		leaf := e.LeafInput
		if uint64(i) == index {
			leaf = flip(leaf)
		}
		fork.AppendData(leaf)
	}
	l.tree = fork
}

// Requests returns how many requests an endpoint ("get-sth", ...) received.
func (l *Log) Requests(endpoint string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.counts[endpoint]
}

// flip changes one certificate byte while keeping the leaf structurally valid
// (the final two bytes are the CtExtensions length).
func flip(leaf []byte) []byte {
	out := append([]byte(nil), leaf...)
	out[len(out)-3] ^= 0xff
	return out
}

func every(n, count int) bool { return n > 0 && count%n == 0 }

// begin counts the request and applies rate limiting; it reports whether the
// handler should continue.
func (l *Log) begin(w http.ResponseWriter, endpoint string) (int, bool) {
	l.counts[endpoint]++
	l.counts["all"]++
	if every(l.opts.RateLimitEvery, l.counts["all"]) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return 0, false
	}
	return l.counts[endpoint], true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (l *Log) rootAt(size uint64) []byte {
	if size == 0 {
		return rfc6962.DefaultHasher.EmptyRoot()
	}
	return l.tree.HashAt(size)
}

func (l *Log) getSTH(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.begin(w, "get-sth"); !ok {
		return
	}
	size := l.published
	ts := uint64(1790000000000) + size
	root := l.rootAt(size)
	in := []byte{0, 1}
	in = binary.BigEndian.AppendUint64(in, ts)
	in = binary.BigEndian.AppendUint64(in, size)
	in = append(in, root...)
	digest := sha256.Sum256(in)
	sig, err := ecdsa.SignASN1(rand.Reader, l.key, digest[:])
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if l.opts.BadSTHSignature {
		sig[len(sig)-1] ^= 0xff
	}
	ds := []byte{4, 3}
	ds = binary.BigEndian.AppendUint16(ds, uint16(len(sig)))
	ds = append(ds, sig...)
	writeJSON(w, map[string]any{
		"tree_size": size, "timestamp": ts,
		"sha256_root_hash":    base64.StdEncoding.EncodeToString(root),
		"tree_head_signature": base64.StdEncoding.EncodeToString(ds),
	})
}

func parseRange(r *http.Request, a, b string) (uint64, uint64, error) {
	x, err1 := strconv.ParseUint(r.URL.Query().Get(a), 10, 64)
	y, err2 := strconv.ParseUint(r.URL.Query().Get(b), 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, fmt.Errorf("bad %s/%s", a, b)
	}
	return x, y, nil
}

func (l *Log) getConsistency(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.begin(w, "get-sth-consistency"); !ok {
		return
	}
	first, second, err := parseRange(r, "first", "second")
	if err != nil || first == 0 || first > second || second > l.tree.Size() {
		http.Error(w, "bad range", http.StatusBadRequest)
		return
	}
	proof, err := l.tree.ConsistencyProof(first, second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	nodes := make([]string, len(proof))
	for i, p := range proof {
		nodes[i] = base64.StdEncoding.EncodeToString(p)
	}
	writeJSON(w, map[string]any{"consistency": nodes})
}

func (l *Log) getEntries(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n, ok := l.begin(w, "get-entries")
	if !ok {
		return
	}
	start, end, err := parseRange(r, "start", "end")
	if err != nil || start > end || start >= l.published {
		http.Error(w, "bad range", http.StatusBadRequest)
		return
	}
	end = min(end, l.published-1, start+uint64(l.opts.PageSize)-1)
	if every(l.opts.ShortReadEvery, n) && end > start {
		end = start + (end-start)/2
	}
	type wireEntry struct {
		LeafInput string `json:"leaf_input"`
		ExtraData string `json:"extra_data"`
	}
	out := make([]wireEntry, 0, end-start+1)
	for i := start; i <= end; i++ {
		e := l.Entries[i]
		leaf := e.LeafInput
		if l.altered[i] {
			leaf = flip(leaf)
		}
		out = append(out, wireEntry{base64.StdEncoding.EncodeToString(leaf), base64.StdEncoding.EncodeToString(e.ExtraData)})
	}
	if every(l.opts.InvalidBase64Every, n) {
		out[0].LeafInput = "!!not-base64!!"
	}
	if every(l.opts.CorruptJSONEvery, n) {
		b, _ := json.Marshal(map[string]any{"entries": out})
		w.Header().Set("Content-Type", "application/json")
		w.Write(b[:len(b)/2])
		return
	}
	writeJSON(w, map[string]any{"entries": out})
}
```

- [ ] **Step 5: Run it to verify it passes**

Run: `go test -count=1 -race ./internal/ctlogtest/ -v`
Expected: PASS (`TestPairIsRFC6962Consistent`, `TestServesEntriesInPages`, `TestFaultInjection`, `TestPublishAndAlter`).

- [ ] **Step 6: Commit**

```bash
git add internal/ctlogtest
git commit -m "test(ctlogtest): fake RFC 6962 log with real Merkle tree and fault injection"
```

---

### Task 9: RFC 6962 client (get-sth, get-sth-consistency)

**Files:**
- Create: `internal/logsource/rfc6962/client.go`, `internal/logsource/rfc6962/client_test.go`

**Interfaces:**
- Consumes:
  - `merkle.SignedTreeHead`, `merkle.VerifySTH`, `merkle.VerifyConsistency`
  - `ctlogtest.New`, `Options`, `(*Log).Publish`, `(*Log).Fork`
- Produces:
  - `type Client struct{ BaseURL string; HTTP *http.Client; UserAgent string }`
  - `func New(baseURL string, hc *http.Client) *Client` (nil `hc` means a 60 s timeout)
  - `func (*Client) GetSTH(ctx context.Context) (merkle.SignedTreeHead, error)`. It does **not** verify; the caller verifies with the pinned key.
  - `func (*Client) GetSTHConsistency(ctx context.Context, first, second uint64) ([][32]byte, error)`
  - `var ErrRateLimited, ErrMalformed error`
  - `type HTTPError struct{ URL string; Status int; Body string; RetryAfter time.Duration }` (matches `ErrRateLimited` on 429)

Plan 2 adds `get-entries` and the `LogSource` adapter to this package.

- [ ] **Step 1: Write the failing test**

`TestRealArgonResponses` replays Google's captured answers in order and verifies them with the key pinned from the log-list fixture.

```go
package rfc6962

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/merkle"
)

var ctx = context.Background()

func TestGetSTHAndConsistencyAgainstFakeLog(t *testing.T) {
	l := ctlogtest.New(t, 40, ctlogtest.Options{})
	pub, err := x509.ParsePKIXPublicKey(l.PublicKeyDER)
	if err != nil {
		t.Fatal(err)
	}
	c := New(l.URL, nil)

	l.Publish(17)
	old, err := c.GetSTH(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if old.TreeSize != 17 || merkle.VerifySTH(pub, old) != nil {
		t.Fatalf("STH at 17 should verify: %+v", old)
	}
	l.Publish(40)
	cur, err := c.GetSTH(ctx)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := c.GetSTHConsistency(ctx, old.TreeSize, cur.TreeSize)
	if err != nil {
		t.Fatal(err)
	}
	if err := merkle.VerifyConsistency(old.TreeSize, cur.TreeSize, old.RootHash, cur.RootHash, proof); err != nil {
		t.Fatalf("honest log must be consistent: %v", err)
	}
}

func TestDetectsForkAndBadSignature(t *testing.T) {
	l := ctlogtest.New(t, 40, ctlogtest.Options{})
	c := New(l.URL, nil)
	l.Publish(20)
	old, _ := c.GetSTH(ctx)
	l.Publish(40)
	l.Fork(5) // the log now presents a history in which leaf 5 differs
	cur, _ := c.GetSTH(ctx)
	proof, err := c.GetSTHConsistency(ctx, old.TreeSize, cur.TreeSize)
	if err != nil {
		t.Fatal(err)
	}
	if err := merkle.VerifyConsistency(old.TreeSize, cur.TreeSize, old.RootHash, cur.RootHash, proof); !errors.Is(err, merkle.ErrInconsistent) {
		t.Fatalf("fork must be detected, got %v", err)
	}

	bad := ctlogtest.New(t, 4, ctlogtest.Options{BadSTHSignature: true})
	pub, _ := x509.ParsePKIXPublicKey(bad.PublicKeyDER)
	sth, err := New(bad.URL, nil).GetSTH(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := merkle.VerifySTH(pub, sth); !errors.Is(err, merkle.ErrBadSignature) {
		t.Fatalf("bad signature must be detected, got %v", err)
	}
}

func TestRateLimitIsReported(t *testing.T) {
	l := ctlogtest.New(t, 4, ctlogtest.Options{RateLimitEvery: 1})
	_, err := New(l.URL, nil).GetSTH(ctx)
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("want ErrRateLimited, got %v", err)
	}
	var he *HTTPError
	if !errors.As(err, &he) || he.RetryAfter != time.Second {
		t.Fatalf("Retry-After not parsed: %+v", he)
	}
}

func TestMalformedResponses(t *testing.T) {
	for name, body := range map[string]string{
		"html captive portal": "<html>please log in</html>",
		"missing tree_size":   `{"timestamp":1,"sha256_root_hash":"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `","tree_head_signature":"BAMAAQA="}`,
		"short root":          `{"tree_size":1,"timestamp":1,"sha256_root_hash":"AAAA","tree_head_signature":"BAMAAQA="}`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		_, err := New(srv.URL, nil).GetSTH(ctx)
		srv.Close()
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: want ErrMalformed, got %v", name, err)
		}
	}
}

// TestRealArgonResponses replays responses captured from argon2027h1 on
// 2026-10-04 and verifies them with the key pinned from Chrome's log list.
func TestRealArgonResponses(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile("../../testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	// The log's answers change over time, so replay them in order.
	sthReplies := [][]byte{read("argon2027h1_sth1.json"), read("argon2027h1_sth2.json")}
	mux := http.NewServeMux()
	mux.HandleFunc("/logs/us1/argon2027h1/ct/v1/get-sth", func(w http.ResponseWriter, r *http.Request) {
		w.Write(sthReplies[0])
		sthReplies = sthReplies[1:]
	})
	mux.HandleFunc("/logs/us1/argon2027h1/ct/v1/get-sth-consistency", func(w http.ResponseWriter, r *http.Request) {
		w.Write(read("argon2027h1_consistency.json"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var ll struct {
		Operators []struct {
			Logs []struct{ URL, Key string } `json:"logs"`
		} `json:"operators"`
	}
	raw, _ := os.ReadFile("../../testdata/log_list_google.json")
	json.Unmarshal(raw, &ll)
	var keyB64 string
	for _, lg := range ll.Operators[0].Logs {
		if lg.URL == "https://ct.googleapis.com/logs/us1/argon2027h1/" {
			keyB64 = lg.Key
		}
	}
	der, _ := base64.StdEncoding.DecodeString(keyB64)
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}

	c := New(srv.URL+"/logs/us1/argon2027h1/", nil)
	sth1, err := c.GetSTH(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sth2, err := c.GetSTH(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []merkle.SignedTreeHead{sth1, sth2} {
		if err := merkle.VerifySTH(pub, s); err != nil {
			t.Fatalf("captured STH at %d must verify: %v", s.TreeSize, err)
		}
	}
	proof, err := c.GetSTHConsistency(ctx, sth1.TreeSize, sth2.TreeSize)
	if err != nil {
		t.Fatal(err)
	}
	if err := merkle.VerifyConsistency(sth1.TreeSize, sth2.TreeSize, sth1.RootHash, sth2.RootHash, proof); err != nil {
		t.Fatalf("captured 23-node proof must verify: %v", err)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/logsource/rfc6962/`
Expected: FAIL with `undefined: New`.

- [ ] **Step 3: Implement the client**

```go
// Package rfc6962 is CTVault's HTTP client for RFC 6962 logs. Plan 1 covers
// get-sth and get-sth-consistency; get-entries and the LogSource adapter
// arrive in Plan 2.
package rfc6962

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/4rji/ctvault/internal/merkle"
)

// maxBody bounds response bodies; a full get-entries page is well under this.
const maxBody = 16 << 20

// ErrRateLimited is matched by an *HTTPError with status 429.
var ErrRateLimited = errors.New("rate limited by log (HTTP 429)")

// ErrMalformed means the log answered 200 with an unusable body.
var ErrMalformed = errors.New("malformed log response")

// HTTPError is a non-200 answer from the log.
type HTTPError struct {
	URL        string
	Status     int
	Body       string
	RetryAfter time.Duration
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%s: HTTP %d: %s", e.URL, e.Status, e.Body)
}

func (e *HTTPError) Is(target error) bool {
	return target == ErrRateLimited && e.Status == http.StatusTooManyRequests
}

// Client talks to one log.
type Client struct {
	BaseURL   string // log URL from the log list, ending in "/"
	HTTP      *http.Client
	UserAgent string
}

// New returns a client with a sane default timeout.
func New(baseURL string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	return &Client{BaseURL: baseURL, HTTP: hc, UserAgent: "ctvault"}
}

func (c *Client) getJSON(ctx context.Context, path string, q url.Values, v any) error {
	u := c.BaseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("%s: reading body: %w", u, err)
	}
	if resp.StatusCode != http.StatusOK {
		he := &HTTPError{URL: u, Status: resp.StatusCode, Body: strings.TrimSpace(string(body[:min(len(body), 200)]))}
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s >= 0 {
			he.RetryAfter = time.Duration(s) * time.Second
		}
		return he
	}
	if len(body) > maxBody {
		return fmt.Errorf("%w: %s: body exceeds %d bytes", ErrMalformed, u, maxBody)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrMalformed, u, err)
	}
	return nil
}

func decode32(field, s string) ([32]byte, error) {
	var out [32]byte
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return out, fmt.Errorf("%w: %s is not a base64 32-byte hash", ErrMalformed, field)
	}
	copy(out[:], b)
	return out, nil
}

// GetSTH fetches the current signed tree head. It does not verify the
// signature; callers verify with the pinned key via merkle.VerifySTH.
func (c *Client) GetSTH(ctx context.Context) (merkle.SignedTreeHead, error) {
	var j struct {
		TreeSize  *uint64 `json:"tree_size"`
		Timestamp uint64  `json:"timestamp"`
		Root      string  `json:"sha256_root_hash"`
		Sig       string  `json:"tree_head_signature"`
	}
	if err := c.getJSON(ctx, "ct/v1/get-sth", nil, &j); err != nil {
		return merkle.SignedTreeHead{}, err
	}
	if j.TreeSize == nil {
		return merkle.SignedTreeHead{}, fmt.Errorf("%w: get-sth has no tree_size", ErrMalformed)
	}
	root, err := decode32("sha256_root_hash", j.Root)
	if err != nil {
		return merkle.SignedTreeHead{}, err
	}
	sig, err := base64.StdEncoding.DecodeString(j.Sig)
	if err != nil || len(sig) == 0 {
		return merkle.SignedTreeHead{}, fmt.Errorf("%w: tree_head_signature is not base64", ErrMalformed)
	}
	return merkle.SignedTreeHead{TreeSize: *j.TreeSize, Timestamp: j.Timestamp, RootHash: root, Signature: sig}, nil
}

// GetSTHConsistency fetches the proof that the tree of size first is a prefix
// of the tree of size second.
func (c *Client) GetSTHConsistency(ctx context.Context, first, second uint64) ([][32]byte, error) {
	q := url.Values{"first": {strconv.FormatUint(first, 10)}, "second": {strconv.FormatUint(second, 10)}}
	var j struct {
		Consistency []string `json:"consistency"`
	}
	if err := c.getJSON(ctx, "ct/v1/get-sth-consistency", q, &j); err != nil {
		return nil, err
	}
	out := make([][32]byte, len(j.Consistency))
	for i, n := range j.Consistency {
		h, err := decode32(fmt.Sprintf("consistency[%d]", i), n)
		if err != nil {
			return nil, err
		}
		out[i] = h
	}
	return out, nil
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `go test -count=1 -race ./internal/logsource/rfc6962/ -v`
Expected: PASS (`TestGetSTHAndConsistencyAgainstFakeLog`, `TestDetectsForkAndBadSignature`, `TestRateLimitIsReported`, `TestMalformedResponses`, `TestRealArgonResponses`).

- [ ] **Step 5: Commit**

```bash
git add internal/logsource
git commit -m "feat(rfc6962): get-sth and get-sth-consistency client"
```

---

### Task 10: Chrome log list

**Files:**
- Create: `internal/loglist/loglist.go`, `internal/loglist/loglist_test.go`

**Interfaces:**
- Consumes: the `internal/testdata/log_list_google.json` fixture (Task 7).
- Produces:
  - Constants and errors:
    - `const DefaultURL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"`
    - `var ErrNotFound, ErrAmbiguous, ErrTiledUnsupported, ErrBadKey error`
  - Types:
    - `type List struct{ Version, Timestamp string; Operators []Operator }`
    - `Operator{Name string; Logs []Log; TiledLogs []TiledLog}`
    - `Log{Description, LogID, Key, URL string; MMD int; State State; TemporalInterval *Interval}`
    - `TiledLog{Description, MonitoringURL string}`
    - `Interval{StartInclusive, EndExclusive time.Time}`
    - `type Resolved struct{ Name, Operator string; Log Log }`
  - Functions:
    - `func Parse(b []byte) (*List, error)`
    - `func Fetch(ctx context.Context, hc *http.Client, src string) (*List, error)` (an `http(s)` URL or a file path)
    - `func LogName(logURL string) string`
    - `func TiledName(monitoringURL string) string`
    - `func (*List) Find(name string) (Resolved, error)`
    - `func (*List) RFC6962Logs() []Resolved` (sorted by name)
    - `func (Log) CurrentState() string`
    - `func ParseKey(keyB64, logIDB64 string) (crypto.PublicKey, error)` (checks log_id == SHA-256(SPKI))

A log's CTVault name is the last segment of its URL path, so `https://ct.googleapis.com/logs/us1/argon2027h1/` becomes `argon2027h1`.

- [ ] **Step 1: Write the failing test**

This is Review Focus item 5: an HTML captive-portal page.

```go
package loglist

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

const fixture = "../testdata/log_list_google.json"

func load(t *testing.T) *List {
	t.Helper()
	l, err := Fetch(context.Background(), http.DefaultClient, fixture)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestFindArgon2027h1(t *testing.T) {
	r, err := load(t).Find("Argon2027h1")
	if err != nil {
		t.Fatal(err)
	}
	if r.Name != "argon2027h1" || r.Log.URL != "https://ct.googleapis.com/logs/us1/argon2027h1/" || r.Operator != "Google" {
		t.Fatalf("resolved %+v", r)
	}
	if r.Log.CurrentState() != "usable" || r.Log.TemporalInterval == nil {
		t.Fatalf("state %q interval %v", r.Log.CurrentState(), r.Log.TemporalInterval)
	}
	pub, err := ParseKey(r.Log.Key, r.Log.LogID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Fatalf("argon2027h1 uses ECDSA, got %T", pub)
	}
}

func TestFindErrors(t *testing.T) {
	l := load(t)
	if _, err := l.Find("parcelyard2027h1"); !errors.Is(err, ErrTiledUnsupported) {
		t.Fatalf("tiled log: got %v", err)
	}
	if _, err := l.Find("argon2099h1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown log: got %v", err)
	}
	dup := *l
	dup.Operators = append(dup.Operators, Operator{Name: "Copycat", Logs: []Log{{URL: "https://example.test/ct/argon2027h1/"}}})
	if _, err := dup.Find("argon2027h1"); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("duplicate name: got %v", err)
	}
}

func TestRFC6962LogsSorted(t *testing.T) {
	logs := load(t).RFC6962Logs()
	var names []string
	for _, r := range logs {
		names = append(names, r.Name)
	}
	if strings.Join(names, ",") != "argon2026h2,argon2027h1,xenon2026h2,xenon2027h1" {
		t.Fatalf("names = %v", names)
	}
}

func TestParseKeyRejectsMismatchedLogID(t *testing.T) {
	r, _ := load(t).Find("argon2027h1")
	other, _ := load(t).Find("xenon2027h1")
	if _, err := ParseKey(r.Log.Key, other.Log.LogID); !errors.Is(err, ErrBadKey) {
		t.Fatalf("want ErrBadKey, got %v", err)
	}
}

func TestFetchOverHTTPAndHTMLPage(t *testing.T) {
	good, _ := os.ReadFile(fixture)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/portal" {
			w.Write([]byte("<html><body>Hotel Wi-Fi login</body></html>"))
			return
		}
		w.Write(good)
	}))
	defer srv.Close()
	if _, err := Fetch(context.Background(), srv.Client(), srv.URL+"/log_list.json"); err != nil {
		t.Fatalf("HTTP fetch: %v", err)
	}
	_, err := Fetch(context.Background(), srv.Client(), srv.URL+"/portal")
	if err == nil || !strings.Contains(err.Error(), "not valid JSON") || !strings.Contains(err.Error(), "<html>") {
		t.Fatalf("HTML page must give a clear error, got %v", err)
	}
	if _, err := Parse([]byte(`{"version":"1"}`)); err == nil {
		t.Fatal("list without operators must be rejected")
	}
}

func TestTiledName(t *testing.T) {
	cases := map[string]string{
		"https://storage.googleapis.com/parcelyard2027h1.prod.certificate.transparency.goog/": "parcelyard2027h1",
		"https://sycamore2027h1.ct.example.org/":                                              "sycamore2027h1",
	}
	for in, want := range cases {
		if got := TiledName(in); got != want {
			t.Errorf("TiledName(%q) = %q, want %q", in, got, want)
		}
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/loglist/`
Expected: FAIL with `undefined: Fetch`.

- [ ] **Step 3: Implement the log list**

```go
// Package loglist reads Chrome's CT log list v3 and resolves CTVault log
// names to RFC 6962 logs with validated public keys.
package loglist

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
)

// DefaultURL is Chrome's published log list.
const DefaultURL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

const maxListSize = 16 << 20

var (
	ErrNotFound         = errors.New("log not found in log list")
	ErrAmbiguous        = errors.New("log name is ambiguous")
	ErrTiledUnsupported = errors.New("static-ct-api (tiled) logs are not supported in v1")
	ErrBadKey           = errors.New("log key does not match log_id")
)

// List is the subset of the v3 schema CTVault uses.
type List struct {
	Version   string     `json:"version"`
	Timestamp string     `json:"log_list_timestamp"`
	Operators []Operator `json:"operators"`
}

type Operator struct {
	Name      string     `json:"name"`
	Logs      []Log      `json:"logs"`
	TiledLogs []TiledLog `json:"tiled_logs"`
}

type State map[string]struct {
	Timestamp time.Time `json:"timestamp"`
}

type Interval struct {
	StartInclusive time.Time `json:"start_inclusive"`
	EndExclusive   time.Time `json:"end_exclusive"`
}

type Log struct {
	Description      string    `json:"description"`
	LogID            string    `json:"log_id"`
	Key              string    `json:"key"`
	URL              string    `json:"url"`
	MMD              int       `json:"mmd"`
	State            State     `json:"state"`
	TemporalInterval *Interval `json:"temporal_interval"`
}

type TiledLog struct {
	Description   string `json:"description"`
	MonitoringURL string `json:"monitoring_url"`
}

// Parse decodes a log list and rejects anything that is not one (for example
// an HTML error page from a captive portal).
func Parse(b []byte) (*List, error) {
	var l List
	if err := json.Unmarshal(b, &l); err != nil {
		snippet := string(bytes.TrimSpace(b[:min(len(b), 60)]))
		return nil, fmt.Errorf("log list is not valid JSON (starts with %q): %w", snippet, err)
	}
	if l.Version == "" || len(l.Operators) == 0 {
		return nil, errors.New("not a CT log list v3: missing version or operators")
	}
	return &l, nil
}

// Fetch loads a log list from an http(s) URL or a local file path.
func Fetch(ctx context.Context, hc *http.Client, src string) (*List, error) {
	var body []byte
	if u, err := url.Parse(src); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
		if err != nil {
			return nil, err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetching log list: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetching log list %s: HTTP %d", src, resp.StatusCode)
		}
		if body, err = io.ReadAll(io.LimitReader(resp.Body, maxListSize)); err != nil {
			return nil, err
		}
	} else if body, err = os.ReadFile(src); err != nil {
		return nil, err
	}
	return Parse(body)
}

// LogName is CTVault's name for an RFC 6962 log: the last URL path segment,
// lowercased ("https://ct.googleapis.com/logs/us1/argon2027h1/" → "argon2027h1").
func LogName(logURL string) string {
	segs := strings.Split(strings.Trim(logURL, "/"), "/")
	return strings.ToLower(segs[len(segs)-1])
}

// TiledName is the first DNS label of a tiled log's monitoring host
// ("https://storage.googleapis.com/parcelyard2027h1.prod.…/" → "parcelyard2027h1").
func TiledName(monitoringURL string) string {
	u, err := url.Parse(monitoringURL)
	if err != nil {
		return ""
	}
	host := u.Host
	if p := strings.Trim(u.Path, "/"); p != "" {
		host = strings.Split(p, "/")[0]
	}
	return strings.ToLower(strings.Split(host, ".")[0])
}

// Resolved is one named RFC 6962 log.
type Resolved struct {
	Name     string
	Operator string
	Log      Log
}

// Find resolves a CTVault log name.
func (l *List) Find(name string) (Resolved, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	var found []Resolved
	for _, op := range l.Operators {
		for _, tl := range op.TiledLogs {
			if TiledName(tl.MonitoringURL) == name {
				return Resolved{}, fmt.Errorf("%w: %s (%s)", ErrTiledUnsupported, name, tl.Description)
			}
		}
		for _, lg := range op.Logs {
			if LogName(lg.URL) == name {
				found = append(found, Resolved{Name: name, Operator: op.Name, Log: lg})
			}
		}
	}
	switch len(found) {
	case 0:
		return Resolved{}, fmt.Errorf("%w: %q", ErrNotFound, name)
	case 1:
		return found[0], nil
	default:
		urls := make([]string, len(found))
		for i, f := range found {
			urls[i] = f.Log.URL
		}
		return Resolved{}, fmt.Errorf("%w: %q matches %s", ErrAmbiguous, name, strings.Join(urls, ", "))
	}
}

// RFC6962Logs lists every RFC 6962 log, sorted by name.
func (l *List) RFC6962Logs() []Resolved {
	var out []Resolved
	for _, op := range l.Operators {
		for _, lg := range op.Logs {
			out = append(out, Resolved{Name: LogName(lg.URL), Operator: op.Name, Log: lg})
		}
	}
	slices.SortFunc(out, func(a, b Resolved) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// CurrentState returns the log's state name ("usable", "readonly", ...).
func (lg Log) CurrentState() string {
	names := make([]string, 0, len(lg.State))
	for k := range lg.State {
		names = append(names, k)
	}
	slices.Sort(names)
	return strings.Join(names, ",")
}

// ParseKey decodes a base64 SPKI and checks that logIDB64 is its SHA-256
// (RFC 6962 §3.2 defines the log ID that way).
func ParseKey(keyB64, logIDB64 string) (crypto.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("log key is not base64: %w", err)
	}
	id := sha256.Sum256(der)
	if base64.StdEncoding.EncodeToString(id[:]) != logIDB64 {
		return nil, ErrBadKey
	}
	return x509.ParsePKIXPublicKey(der)
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `go test -count=1 ./internal/loglist/ -v`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/loglist
git commit -m "feat(loglist): Chrome log list v3 parsing, name resolution and key checks"
```

---

### Task 11: Pinned log registry

**Files:**
- Create: `internal/logreg/logreg.go`, `internal/logreg/logreg_test.go`

**Interfaces:**
- Consumes:
  - `loglist.List`, `Resolved`, `Interval`, `ParseKey`, `Fetch`
  - `fsutil.WriteFileAtomic`
- Produces:
  - `type Record struct{ Name, Operator, Description, URL, LogID, Key string; MMD int; State string; TemporalInterval *loglist.Interval; LogListVersion, LogListTimestamp string; PinnedAt time.Time }`
  - `func FromList(l *loglist.List, r loglist.Resolved, now time.Time) Record`
  - `func (Record) PublicKey() (crypto.PublicKey, error)`
  - `func Dir(root string) string` (returns `<root>/state/logs`)
  - `func Add(root string, r Record) error` (the caller holds the writer lock)
  - `func Get(root, name string) (Record, error)`
  - `func List(root string) ([]Record, error)`
  - `var ErrExists, ErrUnknown error`

- [ ] **Step 1: Write the failing test**

```go
package logreg

import (
	"context"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/loglist"
)

func setup(t *testing.T) (string, *loglist.List) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(Dir(root), 0o755); err != nil {
		t.Fatal(err)
	}
	l, err := loglist.Fetch(context.Background(), http.DefaultClient, "../testdata/log_list_google.json")
	if err != nil {
		t.Fatal(err)
	}
	return root, l
}

func TestAddGetList(t *testing.T) {
	root, l := setup(t)
	now := time.Date(2026, 10, 4, 7, 0, 0, 0, time.UTC)
	for _, name := range []string{"xenon2027h1", "argon2027h1"} {
		r, err := l.Find(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := Add(root, FromList(l, r, now)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Get(root, "Argon2027h1")
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != "https://ct.googleapis.com/logs/us1/argon2027h1/" || got.LogListVersion != "93.3" || !got.PinnedAt.Equal(now) {
		t.Fatalf("record = %+v", got)
	}
	if _, err := got.PublicKey(); err != nil {
		t.Fatal(err)
	}
	all, err := List(root)
	if err != nil || len(all) != 2 || all[0].Name != "argon2027h1" {
		t.Fatalf("List = %v, %v", all, err)
	}
}

func TestAddRefusesDuplicatesAndBadKeys(t *testing.T) {
	root, l := setup(t)
	r, _ := l.Find("argon2027h1")
	rec := FromList(l, r, time.Now())
	if err := Add(root, rec); err != nil {
		t.Fatal(err)
	}
	if err := Add(root, rec); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate: got %v", err)
	}
	other, _ := l.Find("xenon2027h1")
	forged := FromList(l, other, time.Now())
	forged.LogID = rec.LogID // key no longer hashes to the log ID
	if err := Add(root, forged); !errors.Is(err, loglist.ErrBadKey) {
		t.Fatalf("forged record: got %v", err)
	}
}

func TestGetUnknownAndInvalidName(t *testing.T) {
	root, _ := setup(t)
	if _, err := Get(root, "argon2027h1"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("unknown: got %v", err)
	}
	if _, err := Get(root, "../../etc/passwd"); err == nil {
		t.Fatal("path traversal must be rejected")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/logreg/`
Expected: FAIL with `undefined: Dir`.

- [ ] **Step 3: Implement the registry**

```go
// Package logreg stores the logs a vault follows, pinned at the moment they
// were added, under <root>/state/logs/<name>.json. Later changes to Chrome's
// log list never silently change a pinned key.
package logreg

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/loglist"
)

var (
	ErrExists  = errors.New("log is already pinned")
	ErrUnknown = errors.New("log is not pinned in this vault")
)

var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Record is a pinned log.
type Record struct {
	Name             string            `json:"name"`
	Operator         string            `json:"operator"`
	Description      string            `json:"description"`
	URL              string            `json:"url"`
	LogID            string            `json:"log_id"`
	Key              string            `json:"key"`
	MMD              int               `json:"mmd"`
	State            string            `json:"state"`
	TemporalInterval *loglist.Interval `json:"temporal_interval,omitempty"`
	LogListVersion   string            `json:"log_list_version"`
	LogListTimestamp string            `json:"log_list_timestamp"`
	PinnedAt         time.Time         `json:"pinned_at"`
}

// FromList builds a record from a resolved log-list entry.
func FromList(l *loglist.List, r loglist.Resolved, now time.Time) Record {
	return Record{
		Name: r.Name, Operator: r.Operator, Description: r.Log.Description, URL: r.Log.URL,
		LogID: r.Log.LogID, Key: r.Log.Key, MMD: r.Log.MMD, State: r.Log.CurrentState(),
		TemporalInterval: r.Log.TemporalInterval, LogListVersion: l.Version, LogListTimestamp: l.Timestamp,
		PinnedAt: now.UTC(),
	}
}

// PublicKey returns the pinned key after re-checking it against the log ID.
func (r Record) PublicKey() (crypto.PublicKey, error) { return loglist.ParseKey(r.Key, r.LogID) }

// Dir is where records live.
func Dir(root string) string { return filepath.Join(root, "state", "logs") }

func path(root, name string) (string, error) {
	if !validName.MatchString(name) {
		return "", fmt.Errorf("invalid log name %q", name)
	}
	return filepath.Join(Dir(root), name+".json"), nil
}

// Add pins a log. The caller must hold the writer lock.
func Add(root string, r Record) error {
	if _, err := r.PublicKey(); err != nil {
		return fmt.Errorf("refusing to pin %s: %w", r.Name, err)
	}
	p, err := path(root, r.Name)
	if err != nil {
		return err
	}
	if _, err := os.Stat(p); err == nil {
		return fmt.Errorf("%w: %s", ErrExists, r.Name)
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(p, append(b, '\n'), 0o644)
}

// Get loads one pinned log.
func Get(root, name string) (Record, error) {
	var r Record
	p, err := path(root, strings.ToLower(name))
	if err != nil {
		return r, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return r, fmt.Errorf("%w: %s (run: ctvault logs add %s)", ErrUnknown, name, name)
	}
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, fmt.Errorf("%s: %w", p, err)
	}
	return r, nil
}

// List returns every pinned log, sorted by name.
func List(root string) ([]Record, error) {
	ents, err := os.ReadDir(Dir(root))
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, e := range ents {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || e.IsDir() {
			continue
		}
		r, err := Get(root, name)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b Record) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `go test -count=1 ./internal/logreg/ -v`
Expected: PASS (`TestAddGetList`, `TestAddRefusesDuplicatesAndBadKeys`, `TestGetUnknownAndInvalidName`).

- [ ] **Step 5: Commit**

```bash
git add internal/logreg
git commit -m "feat(logreg): pinned log records under state/logs"
```

---

### Task 12: CLI core, `init` and `vault add-dir`

**Files:**
- Create: `internal/cli/cli.go`, `internal/cli/vaultcmds.go`, `internal/cli/cli_test.go`
- Create: `cmd/ctvault/main.go`

**Interfaces:**
- Consumes:
  - `volume.Checker`, `InitOptions`, `ErrVolume`, `HostProbe`, `DurabilityUntested`
  - `volumetest.New`, `(*Probe).Mount`
  - `config.WriteDefault`
  - `lock.Acquire`
  - `loglist.DefaultURL`
  - `exitcode.*`
- Produces:
  - `type Deps struct{ Probe volume.Probe; HTTP *http.Client; Now func() time.Time; Stdout, Stderr io.Writer; Getenv func(string) string; LogListSource, Version string }`
  - `func DefaultDeps(version string) Deps`
  - `func Main(args []string, d Deps) int`
  - Unexported helpers used by Task 13:
    - `type app struct{ d Deps; root string }`
    - `usageArgs`
    - `groupCmd`
    - `(*app).checker()`
    - `volumeErr`
    - `(*app).openVault(c *cobra.Command) (string, volume.VaultID, error)`
    - `(*app).writerLock(root string) (*lock.Lock, error)`
  - Test helpers used by Task 13: `newEnv`, `(*env).run`, `(*env).mustRun`, `realSTH`, `rewrite`.

How exit codes are produced:
- Argument-count and flag errors map to exit 2 through `usageArgs` and `SetFlagErrorFunc`.
- Volume failures map to exit 4 through `volumeErr`.
- Everything else is exit 1, unless an error carries its own code.

- [ ] **Step 1: Add the cobra dependency**

```bash
go get github.com/spf13/cobra@v1.10.2
```

- [ ] **Step 2: Write the failing test**

```go
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
```

- [ ] **Step 3: Run it to verify it fails**

Run: `go test ./internal/cli/`
Expected: FAIL with `undefined: Deps`.

- [ ] **Step 4: Implement the CLI core**

The root command registers `version`, `init` and `vault` in this task. Task 13 adds `logs`.

```go
// Package cli implements the ctvault command line. Every dependency on the
// host (mount table, network, clock, output) comes in through Deps so the
// commands can be tested end to end without root privileges or network.
package cli

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/lock"
	"github.com/4rji/ctvault/internal/loglist"
	"github.com/4rji/ctvault/internal/volume"
)

// Deps are the host services the commands use.
type Deps struct {
	Probe         volume.Probe
	HTTP          *http.Client
	Now           func() time.Time
	Stdout        io.Writer
	Stderr        io.Writer
	Getenv        func(string) string
	LogListSource string
	Version       string
}

// DefaultDeps wires the real host.
func DefaultDeps(version string) Deps {
	return Deps{
		Probe: volume.HostProbe{}, HTTP: &http.Client{Timeout: 60 * time.Second}, Now: time.Now,
		Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv,
		LogListSource: loglist.DefaultURL, Version: version,
	}
}

// Main runs one command and returns its exit code (spec §11.2).
func Main(args []string, d Deps) int {
	a := &app{d: d}
	cmd := newRootCmd(a)
	cmd.SetArgs(args)
	cmd.SetOut(d.Stdout)
	cmd.SetErr(d.Stderr)
	err := cmd.Execute()
	if err == nil {
		return exitcode.OK
	}
	fmt.Fprintln(d.Stderr, "ctvault:", err)
	code := exitcode.Of(err)
	if code == exitcode.Usage {
		fmt.Fprintln(d.Stderr, "Run 'ctvault --help' for usage.")
	}
	return code
}

type app struct {
	d    Deps
	root string
}

func newRootCmd(a *app) *cobra.Command {
	root := &cobra.Command{
		Use:           "ctvault",
		Short:         "A local, cryptographically verified Certificate Transparency research archive",
		Args:          usageArgs(cobra.NoArgs),
		RunE:          func(c *cobra.Command, _ []string) error { return c.Help() },
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&a.root, "root", a.d.Getenv("CTVAULT_ROOT"), "vault root (default $CTVAULT_ROOT)")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return exitcode.With(exitcode.Usage, err) })
	root.AddCommand(newVersionCmd(a), newInitCmd(a), newVaultCmd(a))
	return root
}

// usageArgs marks argument-count errors as usage errors (exit code 2).
func usageArgs(v cobra.PositionalArgs) cobra.PositionalArgs {
	return func(c *cobra.Command, args []string) error { return exitcode.With(exitcode.Usage, v(c, args)) }
}

func groupCmd(use, short string, children ...*cobra.Command) *cobra.Command {
	c := &cobra.Command{Use: use, Short: short, Args: usageArgs(cobra.NoArgs),
		RunE: func(c *cobra.Command, _ []string) error { return c.Help() }}
	c.AddCommand(children...)
	return c
}

func (a *app) checker() volume.Checker { return volume.Checker{Probe: a.d.Probe, Now: a.d.Now} }

func volumeErr(err error) error {
	if errors.Is(err, volume.ErrVolume) {
		return exitcode.With(exitcode.Volume, err)
	}
	return err
}

// openVault runs the spec §9.2 checks that precede every command on a vault.
func (a *app) openVault(c *cobra.Command) (string, volume.VaultID, error) {
	if a.root == "" {
		return "", volume.VaultID{}, exitcode.Withf(exitcode.Usage, "no vault root: pass --root or set CTVAULT_ROOT")
	}
	id, err := a.checker().Check(a.root)
	if err != nil {
		return "", id, volumeErr(err)
	}
	if id.Durability == volume.DurabilityUntested {
		fmt.Fprintln(c.ErrOrStderr(), "warning: this vault uses an untested filesystem; durability guarantees are weaker (spec §9.3)")
	}
	return a.root, id, nil
}

func (a *app) writerLock(root string) (*lock.Lock, error) {
	return lock.Acquire(filepath.Join(root, "state", "LOCK"))
}

func newVersionCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use: "version", Short: "Print the ctvault version", Args: usageArgs(cobra.NoArgs),
		RunE: func(c *cobra.Command, _ []string) error {
			fmt.Fprintln(c.OutOrStdout(), "ctvault", a.d.Version)
			return nil
		},
	}
}
```

- [ ] **Step 5: Implement `init` and `vault add-dir`**

```go
package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/volume"
)

func newInitCmd(a *app) *cobra.Command {
	var allowUntested bool
	cmd := &cobra.Command{
		Use:   "init <root>",
		Short: "Create a vault on a dedicated, mounted ext4 volume",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(c *cobra.Command, args []string) error {
			id, err := a.checker().Init(args[0], volume.InitOptions{AllowUntestedFS: allowUntested})
			if err != nil {
				return volumeErr(err)
			}
			if err := config.WriteDefault(args[0]); err != nil {
				return err
			}
			r := id.Volumes[0]
			fmt.Fprintf(c.OutOrStdout(), "Initialized CTVault %s at %s (%s, filesystem %s, durability %s)\n",
				id.VaultUUID, r.Path, r.FSType, r.FSUUID, id.Durability)
			fmt.Fprintf(c.OutOrStdout(), "Next: ctvault --root %s logs add argon2027h1\n", r.Path)
			return nil
		},
	}
	cmd.Flags().BoolVar(&allowUntested, "allow-untested-fs", false, "accept xfs, btrfs or f2fs with weaker durability guarantees")
	return cmd
}

func newVaultCmd(a *app) *cobra.Command {
	var allowUntested bool
	addDir := &cobra.Command{
		Use:   "add-dir <path>",
		Short: "Add a vault directory on another disk",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(c *cobra.Command, args []string) error {
			root, _, err := a.openVault(c)
			if err != nil {
				return err
			}
			lk, err := a.writerLock(root)
			if err != nil {
				return err
			}
			defer lk.Release()
			id, err := a.checker().AddDir(root, args[0], volume.InitOptions{AllowUntestedFS: allowUntested})
			if err != nil {
				return volumeErr(err)
			}
			v := id.Volumes[len(id.Volumes)-1]
			fmt.Fprintf(c.OutOrStdout(), "Added vault dir %s (%s, filesystem %s)\n", v.Path, v.FSType, v.FSUUID)
			return nil
		},
	}
	addDir.Flags().BoolVar(&allowUntested, "allow-untested-fs", false, "accept xfs, btrfs or f2fs with weaker durability guarantees")
	return groupCmd("vault", "Manage vault volumes", addDir)
}
```

- [ ] **Step 6: Add the entry point**

```go
// Command ctvault is a local, cryptographically verified Certificate
// Transparency research archive. See docs/superpowers/specs/.
package main

import (
	"os"

	"github.com/4rji/ctvault/internal/cli"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(cli.Main(os.Args[1:], cli.DefaultDeps(version)))
}
```

- [ ] **Step 7: Run it to verify it passes**

Run:

```bash
go test -count=1 ./internal/cli/ -v
go build -o ctvault ./cmd/ctvault
mkdir -p not-a-mount && ./ctvault init ./not-a-mount; echo "exit=$?"; rmdir not-a-mount
```

Expected:
- PASS (`TestInitWritesVault`, `TestExitCodes`, `TestVaultAddDirAndSwappedDisk`)
- then `ctvault: volume check failed: …/not-a-mount is not a mount point; mount the external SSD there first` and `exit=4`. That is the real host probe refusing a plain directory inside your checkout. If your checkout is on an unsupported filesystem, the message names that filesystem instead, and the exit code is still 4.

- [ ] **Step 8: Commit**

```bash
git add go.mod go.sum internal/cli cmd/ctvault
git commit -m "feat(cli): ctvault init, vault add-dir and version with spec exit codes"
```

---

### Task 13: `logs` commands, README and final verification

**Files:**
- Create: `internal/cli/logs.go`, `internal/cli/logs_test.go`, `README.md`
- Modify: `internal/cli/cli.go`, in `newRootCmd`, the `root.AddCommand(...)` line

**Interfaces:**
- Consumes:
  - `logreg.FromList`, `Add`, `Get`, `List`
  - `loglist.Fetch`, `(*List).Find`, `RFC6962Logs`
  - `rfc6962.New`, `(*Client).GetSTH`
  - `merkle.VerifySTH`
  - the Task 12 helpers
- Produces:
  - `ctvault logs list [--available]`
  - `ctvault logs add <name>` (takes the writer lock)
  - `ctvault logs info <name> [--offline]`, which exits 5 when the live STH does not verify with the pinned key
  - the persistent flag `--log-list <url|file>` (default `loglist.DefaultURL`)

- [ ] **Step 1: Write the failing test**

```go
package cli

import (
	"bytes"
	"path/filepath"
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

func TestLogsAddFailures(t *testing.T) {
	e := newEnv(t, realSTH(t))
	e.mustRun("init", e.root)
	if got := e.run("--root", e.root, "logs", "add", "parcelyard2027h1"); got != exitcode.Error ||
		!strings.Contains(e.stderr.String(), "tiled") {
		t.Fatalf("tiled log: exit %d stderr %s", got, e.stderr)
	}
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
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/cli/`
Expected: FAIL. The test binary builds, but all four `TestLogs…` tests fail with `exit 2` and `unknown command "logs" for "ctvault"`.

- [ ] **Step 3: Implement the logs commands**

```go
package cli

import (
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/loglist"
	"github.com/4rji/ctvault/internal/logreg"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/merkle"
)

func newLogsCmd(a *app) *cobra.Command {
	src := new(string)
	cmd := groupCmd("logs", "Manage the CT logs this vault follows",
		logsListCmd(a, src), logsAddCmd(a, src), logsInfoCmd(a))
	cmd.PersistentFlags().StringVar(src, "log-list", a.d.LogListSource, "log list URL or file")
	return cmd
}

func logsListCmd(a *app, src *string) *cobra.Command {
	var available bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List pinned logs, or all RFC 6962 logs in the log list with --available",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(c *cobra.Command, _ []string) error {
			root, _, err := a.openVault(c)
			if err != nil {
				return err
			}
			pinned, err := logreg.List(root)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
			defer tw.Flush()
			if !available {
				fmt.Fprintln(tw, "NAME\tSTATE AT PIN\tPINNED AT\tURL")
				for _, r := range pinned {
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.Name, r.State, r.PinnedAt.Format(time.RFC3339), r.URL)
				}
				return nil
			}
			list, err := loglist.Fetch(c.Context(), a.d.HTTP, *src)
			if err != nil {
				return err
			}
			isPinned := map[string]bool{}
			for _, r := range pinned {
				isPinned[r.Name] = true
			}
			fmt.Fprintln(tw, "NAME\tSTATE\tOPERATOR\tPINNED\tURL")
			for _, r := range list.RFC6962Logs() {
				mark := ""
				if isPinned[r.Name] {
					mark = "yes"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.Name, r.Log.CurrentState(), r.Operator, mark, r.Log.URL)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&available, "available", false, "list every RFC 6962 log in the log list")
	return cmd
}

func logsAddCmd(a *app, src *string) *cobra.Command {
	return &cobra.Command{
		Use:   "add <name>",
		Short: "Pin a log from Chrome's log list (for example argon2027h1)",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(c *cobra.Command, args []string) error {
			root, _, err := a.openVault(c)
			if err != nil {
				return err
			}
			lk, err := a.writerLock(root)
			if err != nil {
				return err
			}
			defer lk.Release()
			list, err := loglist.Fetch(c.Context(), a.d.HTTP, *src)
			if err != nil {
				return err
			}
			r, err := list.Find(args[0])
			if err != nil {
				return err
			}
			rec := logreg.FromList(list, r, a.d.Now())
			if err := logreg.Add(root, rec); err != nil {
				return err
			}
			out := c.OutOrStdout()
			fmt.Fprintf(out, "Pinned %s: %s (%s, %s)\n", rec.Name, rec.Description, rec.Operator, rec.State)
			if ti := rec.TemporalInterval; ti != nil {
				fmt.Fprintf(out, "  accepts certificates expiring %s to %s\n", ti.StartInclusive.Format("2006-01-02"), ti.EndExclusive.Format("2006-01-02"))
			}
			fmt.Fprintf(out, "  url     %s\n  log_id  %s\n  from log list %s (%s)\n", rec.URL, rec.LogID, rec.LogListVersion, rec.LogListTimestamp)
			return nil
		},
	}
}

func logsInfoCmd(a *app) *cobra.Command {
	var offline bool
	cmd := &cobra.Command{
		Use:   "info <name>",
		Short: "Show a pinned log and verify its current signed tree head",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(c *cobra.Command, args []string) error {
			root, _, err := a.openVault(c)
			if err != nil {
				return err
			}
			rec, err := logreg.Get(root, args[0])
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			fmt.Fprintf(out, "name       %s\ndescription %s\noperator   %s\nurl        %s\nlog_id     %s\nstate      %s (at pin)\npinned_at  %s\n",
				rec.Name, rec.Description, rec.Operator, rec.URL, rec.LogID, rec.State, rec.PinnedAt.Format(time.RFC3339))
			if offline {
				return nil
			}
			pub, err := rec.PublicKey()
			if err != nil {
				return exitcode.With(exitcode.Verification, fmt.Errorf("pinned record for %s is corrupt: %w", rec.Name, err))
			}
			sth, err := rfc6962.New(rec.URL, a.d.HTTP).GetSTH(c.Context())
			if err != nil {
				return err
			}
			if err := merkle.VerifySTH(pub, sth); err != nil {
				return exitcode.With(exitcode.Verification, fmt.Errorf("signed tree head from %s does not verify with the pinned key: %w", rec.URL, err))
			}
			fmt.Fprintf(out, "tree_size  %d\nsth_time   %s\nroot_hash  %x\nsignature  verified with pinned key\n",
				sth.TreeSize, time.UnixMilli(int64(sth.Timestamp)).UTC().Format(time.RFC3339), sth.RootHash)
			return nil
		},
	}
	cmd.Flags().BoolVar(&offline, "offline", false, "show pinned metadata only; do not contact the log")
	return cmd
}
```

- [ ] **Step 4: Register `logs` on the root command**

In `internal/cli/cli.go`, replace:

```go
	root.AddCommand(newVersionCmd(a), newInitCmd(a), newVaultCmd(a))
```

with:

```go
	root.AddCommand(newVersionCmd(a), newInitCmd(a), newLogsCmd(a), newVaultCmd(a))
```

- [ ] **Step 5: Run the CLI tests to verify they pass**

Run: `go test -count=1 ./internal/cli/ -v`
Expected: PASS. Covered:
- `TestInitWritesVault`, `TestExitCodes`, `TestVaultAddDirAndSwappedDisk`
- `TestLogsAddListInfo`, which verifies Google's real STH at tree size 384,065,451 with the pinned key
- `TestLogsRootFromEnvironment`, `TestLogsInfoRejectsForgedHead`, `TestLogsAddFailures`

- [ ] **Step 6: Write the README**

````markdown
# CTVault

A local, cryptographically verified Certificate Transparency research archive.
Design: `docs/superpowers/specs/2026-10-04-ctvault-design.md`.

**Status:** Plan 1 (Foundations). You can create a vault on a dedicated ext4
volume, pin CT logs from Chrome's log list and verify a log's live signed tree
head. Ingestion arrives in Plan 2.

## Requirements

- Linux, with the vault on a dedicated, mounted **ext4** volume (an external
  SSD). xfs, btrfs and f2fs work only with `--allow-untested-fs`; exFAT, NTFS,
  FAT, FUSE, network filesystems and tmpfs are always rejected.
- Go 1.26.8 or newer. With the default `GOTOOLCHAIN=auto`, an older `go`
  downloads the right toolchain automatically.

## Build and test

```bash
go build -o ctvault ./cmd/ctvault
go test -race ./...
```

## Usage

```bash
# The SSD must be mounted at /mnt/ctvault and contain nothing but lost+found.
./ctvault init /mnt/ctvault
export CTVAULT_ROOT=/mnt/ctvault

./ctvault logs list --available        # RFC 6962 logs in Chrome's log list
./ctvault logs add argon2027h1          # pin the log and its public key
./ctvault logs info argon2027h1         # fetch and verify the live signed tree head
./ctvault vault add-dir /mnt/disk2/ctvault-vault   # optional extra vault disk
```

Exit codes: 0 OK, 1 error, 2 usage, 3 disk cap reached, 4 volume check failed,
5 verification or corruption failure.
````

- [ ] **Step 7: Run final verification**

Run:

```bash
go mod tidy
gofmt -l .
go vet ./...
go test -race -count=1 ./...
go build -o ctvault ./cmd/ctvault && ./ctvault --help
```

Expected:
- `go mod tidy` moves the four pinned modules from `// indirect` into the direct `require` block. `go get` marks a module indirect until code imports it.
- `gofmt` prints nothing and `go vet` is clean.
- All 12 packages print `ok`; `cmd/ctvault` and `internal/volume/volumetest` print `[no test files]`.
- `--help` lists `init`, `logs`, `vault` and `version`.
- `go.mod` matches:

```text
module github.com/4rji/ctvault

go 1.26.8

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/spf13/cobra v1.10.2
	github.com/transparency-dev/merkle v0.0.2
	golang.org/x/sys v0.48.0
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
)
```

- [ ] **Step 8 (optional, needs a real ext4 mount and network): live smoke test**

If a spare ext4 SSD is mounted at `/mnt/ctvault` and empty:

```bash
./ctvault init /mnt/ctvault
./ctvault --root /mnt/ctvault logs add argon2027h1
./ctvault --root /mnt/ctvault logs info argon2027h1
```

Expected: `signature  verified with pinned key`, and a `tree_size` larger than 384,071,894. Skip this step if no spare volume is available. The CI-safe tests already verify Google's real STH.

- [ ] **Step 9: Commit**

```bash
git add go.mod go.sum internal/cli README.md
git commit -m "feat(cli): logs list/add/info with live STH verification; README"
```

---

## Post-review fixes (applied after execution)

A fresh whole-branch review found 0 Critical and 5 Important issues. Each was fixed test-first: a failing test came first, then the full suite was run. The code now differs from the task text above in these places:

1. **`volume.AddDir`** checks the nearest existing ancestor of the target and refuses before creating anything. It then creates the directory with `MkdirAllSync`. Test: `TestAddDirRefusesSystemDiskAndNonEmpty`.
2. **`volume.requireEmpty`** accepts only `lost+found`, empty layout directories, `vault/DIR_ID` and the temp files of atomic writes. User files under layout folder names, a foreign `ctvault.toml` and old segments are refused. Tests: `TestInitRefusesUserDataUnderLayoutNames`, `TestInitAcceptsInterruptedInitLeftovers`.
3. **`Probe.BackingDevices`** (new) follows loop backing files and dm/md slaves through `/sys/dev/block`. `Inspect` refuses any mount whose data shares a device with `/`. Tests:
   - `TestInitRefusals`: loop image, and dm-crypt on a loop image
   - `TestInitAcceptsEncryptedExternalDisk`
   - `TestHostProbeBackingDevices`
4. **The `rfc6962` client** quotes the first 60 bytes of an unparseable response (Review Focus 5). Test: `TestHTMLPageIsQuoted`.
5. **`loglist.LogName(description, url)`** uses the single-quoted name in the description. Failing that, it uses a name-like URL segment or host label. Failing that, it uses the sanitized host and path. `Find` matches RFC 6962 logs before tiled ones, and a new immutable fixture `log_list_v93.3_full.json` proves every name in the real list is unique. Tests: `TestLogName`, `TestEveryLogInFullListHasAUniqueName`, `TestFindNonGoogleLogs`.

**Pending: Task 13 Step 8, the real-SSD smoke test, has not been run** (there was no access to the external drive on 2026-10-04). The README's "Pending verification" section has the commands and expected output.
