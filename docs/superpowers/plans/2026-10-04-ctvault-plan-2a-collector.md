# CTVault Plan 2A (Collector) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build CTVault's collector side and its real-data tooling. When this plan is done:
- the RFC 6962 client reads entries and proofs;
- every entry is decoded and classified with stable error codes, with precertificates cross-checked against RFC 6962;
- a rate-adaptive fetcher hands entries over strictly in index order, with a bounded buffer;
- the dev build (`-tags ctvault_dev`) captures, verifies and replays real `argon2027h1` samples on the normal disk.

Plan 2B then writes these entries into the vault.

**Architecture:** New packages, each with one job:
- `leaf`: MerkleTreeLeaf and `extra_data` decoding, plus the precertificate checks, built on `cryptobyte`.
- `logsource`: the `LogSource` interface, signed-head checks and the per-batch chain cache.
- `logsource/rfc6962`: the client, extended with `get-entries` and `get-proof-by-hash`, and the `Source` adapter.
- `fetch`: workers, token bucket, retries, and an ordered, bounded reorder buffer.
- `stop`: two-level signal contexts.
- `sample`: the dev-only sample format, capture, verify-on-load and loopback replay.
- `sampletest`: a test-only helper for cached samples.

`config`, `diskguard`, `merkle`, `volume`, `ctlogtest` and `cli` gain the amendment's hardening. Everything runs offline in tests, against the fake log or a loopback replay of a real sample.

**Tech Stack:**
- Go 1.26.8
- Unchanged from Plan 1: `transparency-dev/merkle` v0.0.2, `cobra` v1.10.2, `BurntSushi/toml` v1.6.0, `x/sys` v0.48.0
- New:
  - `golang.org/x/crypto` v0.57.0 (`cryptobyte`)
  - `golang.org/x/time` v0.16.0 (`rate`)
  - `github.com/klauspost/compress` v1.20.1 (`zstd`)

**Spec:**
- `docs/superpowers/specs/2026-10-04-ctvault-design.md` ("the spec")
- **Amendment A1:** `docs/superpowers/specs/2026-10-04-ctvault-plan2-amendment.md` (approved 2026-10-04)

This plan implements the amendment's tasks 1–6 and the capture and verify half of task 14. In detail:
- **Spec:** §5.1–5.4, plus §13.3–13.4 for these packages
- **Amendment:** §1, §2.1–2.5 (except `update --replay`), §4 (except the batch-commit parts), §6–7 (the guard primitives only), §8's provenance inputs, and §11 minors 6, 7, 9, 10, 11, 12, 15 and 16

## Global Constraints

- **Platform:** Linux only. Module `github.com/4rji/ctvault`, `go 1.26.8`.
- **Pinned dependencies:**
  - `golang.org/x/crypto@v0.57.0`
  - `golang.org/x/time@v0.16.0`
  - `github.com/klauspost/compress@v1.20.1`
  - Plan 1's four, unchanged

  No other third-party dependencies.
- **Production safety is unchanged** (amendment A1, preamble): "Nothing in this amendment lets a production build accept the normal disk, loosens any volume check, or adds a runtime flag or environment variable that affects safety."
  - Dev code lives only in files tagged `//go:build ctvault_dev`.
  - The only environment variable production reads is `CTVAULT_ROOT` (`TestOnlyRootEnvVarIsRead`).
- **Test-only and dev-only packages** never reach the production binary: `volumetest`, `ctlogtest`, `sampletest` and `sample` (`TestProductionBinaryExcludesDevCode`).
- **Exit codes:** "0 OK, 1 error, 2 usage, 3 disk cap reached, 4 volume check failed, 5 verification or corruption failure" (spec §11.2).
- **Never invent, skip or guess** (spec §5.2, §5.4, §12):
  - Indexes come from request position.
  - A transport or framing error advances nothing.
  - The leaf hash is "always RFC 6962's `SHA-256(0x00 ‖ leaf_input)` over the exact bytes, even when decoding fails".
  - Fields that cannot be decoded safely stay empty.
- **Stable error codes** (amendment A1 §4) are stored in Parquet later and must never change spelling: `leaf_bad_version`, `leaf_bad_leaf_type`, `leaf_unknown_entry_type`, `leaf_truncated`, `leaf_trailing_bytes`, `extra_truncated`, `extra_trailing_bytes`, `chain_cert_empty`, `chain_issuer_missing`, `chain_issuer_ambiguous`, `issuer_key_hash_mismatch`, `precert_tbs_mismatch`, `issuance_key_unavailable`.
- **Samples** (amendment A1 §2):
  - They live outside the repository, under `<home>/.cache/ctvault-dev/samples/`, with `<home>` taken from the OS user database.
  - "An existing sample is never overwritten."
  - "Any failure or interruption leaves no visible sample."
  - They are verified "on every load".
- **Disk cap:** the dev build keeps "the same 85% cap, protecting the normal disk".
- **Quality gates, for every task:**
  - `gofmt -l .` prints nothing
  - `go vet ./...` and `go vet -tags ctvault_dev ./...` are clean
  - `go test -race ./...` and `go test -race -tags ctvault_dev ./...` pass

## Review Focus

These failure modes are implied by the spec but untested by its own examples. They are the likeliest to bite someone running a multi-week catch-up or handling samples. Each is pinned by a test in the task that owns the code.

1. **Google throttles a share of requests whatever our rate** (load from other clients, shared quotas).
   - Expected: the fetcher slows down but never collapses to a crawl, and every entry still arrives once, in order.
   - Pinned by `TestRateSurvivesSparseFailures` and `TestRunRetriesThrottlingAndFraming` (Task A6).
2. **The log answers a request with fewer entries than asked, or with a page that ends early** (replica lag, page-size change).
   - Expected: the remainder is fetched again; nothing is skipped or duplicated.
   - Pinned by `TestRunAlignsRequestsAndRequeuesShortReads` and `TestMisbehavingSourceIsRetried` (Task A6).
3. **A capture is interrupted** by Ctrl-C, a network drop or a full disk.
   - Expected: no sample folder and no staging leftovers. A rerun works.
   - Pinned by `TestCaptureNeverOverwritesAndLeavesNothingOnFailure` and `TestDiskCheckAbortsCapture` (Task A7), and `TestSampleCaptureRespectsTheDiskCap` (Task A8).
4. **A cached sample is damaged later** (bit rot, a hand edit, a partial copy).
   - Expected: it is refused with exit 5 and never replayed. A consistent forgery that updates the checksums still fails the Merkle proofs.
   - Pinned by `TestOpenDetectsTampering` and `TestCommitRefusesEntriesThatDoNotMatchTheProofs` (Task A7), and `TestSampleVerifyRefusesDamage` (Task A8).
5. **A precertificate's chain is out of order, repeats a certificate, carries a same-name impostor, or goes through a precertificate signing certificate.**
   - Expected: the issuer is found by relationship; an ambiguity is flagged, never guessed.
   - Pinned by `TestPrecertIssuerByRelationship` (Task A4).

## Decisions This Plan Adds

These were settled while writing and testing this plan. They are **not** in the approved spec sections, so review them explicitly.

| # | Decision | Why |
|---|---|---|
| 1 | **Plan 2 is split into 2A (this plan, collector and samples), 2B (vault, Pebble, `ID_FLOOR`, staging, commit, recovery, `update` with `--follow`, `--until` and `--replay`) and 2C (crash and fault suite, `sample measure` and reports, real-data end-to-end and recovery equivalence).** Sample capture and verify move from amendment task 14 into 2A. | 16 tasks in one document is too large to review. Capturing samples first lets 2B test the vault against real certificates. |
| 2 | **Rate control halves at most once per 2 s, and adds 1 request/s each second once 2 s have passed since the last halving.** | Halving on *every* 429 and adding +1 per 50 successes collapses to the 0.25 request/s floor when even 2% of requests fail regardless of rate. In simulation the current design manages 1.1 OK requests/s, against 8.0 for this one (Evidence 3). This design keeps the spec's wording ("halves the rate", "fixed step"). A ×0.75 decrease plus a two-failure trigger did better still (12.6 at 2%), but it changes "halves". Say if you want it. |
| 3 | **Sample file details:** `entries.ndjson.zst` holds one zstd frame per 5,000 entries, with frame offsets in `sample.json`. The signed head is kept as base64 `head_raw` (authoritative) next to a readable `head` summary. `--start` must be a multiple of 5,000. Folders are named `<first>-<last>[_suffix]`, 12-digit and inclusive like batch IDs. Publishing uses `renameat2(RENAME_NOREPLACE)`. | Replay can then decode one 5,000-entry frame (about 22 MB) instead of a whole 440 MB sample, and the file is still one valid `.zst` stream. JSON re-encoding would change the head's bytes. No-replace makes "never overwritten" atomic. |
| 4 | **Dev vaults live under `~/.cache/ctvault-dev/vaults/`**, not anywhere under the dev base. | It keeps `samples/` and `reports/` from ever being mistaken for vaults. |
| 5 | **Leaf-decoding details:** the first problem found sets the code. An x509 entry keeps its certificate (taken from `leaf_input`) when `extra_data` is damaged. Chain candidates that share a key and signing role (cross-signed copies) count as one issuer. An unparseable precertificate gives `precert_tbs_mismatch`, and a zero-length certificate gives `leaf_truncated`. | It follows "nothing is guessed" without discarding authenticated data. All 32,768 + 1,184 real entries decode with no code (Evidence 1). |
| 6 | **Unexpected HTTP statuses** (400, 404, …) are retried 3 times, then the fetch fails. 429, 5xx, framing and network errors are retried until `ingest.stall_timeout`. | A request below the pinned head should never get them, so retrying forever would only hide a bug. |
| 7 | **The chain cache is bounded at 64 MiB.** Overflowing it fails the fetch (`ErrChainCacheFull`) instead of evicting. | 32,768 real entries need 184 KiB (167 certificates). Overflowing would mean a misbehaving log, and nothing may be dropped silently. |
| 8 | **A bad STH signature is reported as `merkle.ErrBadSignature`**, separately from the three incident kinds. | Spec §12 already handles it ("refetch once, then exit 5"); Plan 2B maps both to exit 5. |
| 9 | **`diskguard.Guard.Preflight` sums targets on the same filesystem** (grouped by `st_dev`). | The default `vault/` folder lives on the root volume, so checking the vault peak and the root peak separately could pass while their sum crosses the cap. |
| 10 | **The capture preflight assumes 7,409 B per entry.** | That is the spec's uncompressed figure; the measured size is 760–900 B. It stays conservative, as the amendment requires. |
| 11 | **`cli.Deps` gains `Statfs` (production) and `DevBase`** (empty in production). | They are needed to test the dev disk guard without touching the real disk. Neither is a flag or environment variable. |
| 12 | **`logsource.RawEntry` carries the decoded `leaf.Entry` in a `Leaf` field**, instead of repeating the spec §5.1 fields. `Leaf.Code` is the spec's `LeafErr`. `LogSource.Fetch` covers the half-open range `[start, end)`; the client's `GetEntries` keeps RFC 6962's inclusive `end`. | One decoded type serves the fetcher, the samples and Plan 2B's writer. Half-open ranges match the spec's batch arithmetic, `[start, min(start + batch_size, tree_size))`. |

## Evidence Behind This Plan (measured 2026-10-04)

1. **Leaf decoder on real data:**
   - 32,768 contiguous `argon2027h1` entries (index 380,000,000 onwards): 0 error codes. Every precert passes issuer identification, the `issuer_key_hash` check and the TBS reconstruction.
   - 2,555 final certificates link to their precert. The independent Python measurement in spec §3.3 also found 2,555.
   - The 1,184-entry spread sample: 0 error codes.
   - One million randomly mutated entries decode in 7.8 s, the slowest in 5 ms.
2. **Chain cache and buffer:**
   - The same 32,768 entries reference 167 distinct chain certificates, 184 KiB in total.
   - Decoded entries average 4,432 bytes, so a 256 MiB reorder buffer holds about 60k entries, matching the 65,536-entry default.
3. **Rate control, simulated at a 13 request/s server limit** (OK requests/s):

   | Design | 0% | 2% | 5% | 20% |
   |---|---|---|---|---|
   | Halve on every 429, +1 per 50 successes | 10.5 | 1.1 | 0.4 | 0.2 |
   | **This plan:** halve at most every 2 s, +1/s after the cooldown | 11.2 | 8.0 | 5.4 | 2.0 |
   | ×0.75, at most every 2 s, only after 2 failures (needs a spec change) | 13.0 | 12.6 | 10.6 | 4.3 |

   The column headings are the share of requests that fail regardless of rate.
4. **Sample size:**
   - 32,768 real entries take 900 B each in `entries.ndjson.zst` (the raw `get-entries` JSON is 5,947 B per entry).
   - A live capture at the head took 760 B per entry.
5. **Live end-to-end check**, written to a scratch folder, not `~/.cache`:
   - `sample.Capture` took a 10,000-entry representative window at the head of `argon2027h1` (tree size 388,132,431) in 23 s, which is 441 entries/s.
   - Page size 32; 0 leaf error codes.
   - The inclusion proof, the left-sibling range derived from it, and the closing consistency proof all verified. Re-verifying took 0.7 s.
6. **The real fixture page** re-fetched live is byte-identical to the stored copy (same SHA-256), so Task A4 can download it.

## Plan Series

Plan 2 from Plan 1's table is split into three plans, each written after the previous one runs:

| Plan | Scope |
|---|---|
| 1 (done) | Foundations |
| **2A (this plan)** | Collector: dev build, config and guard hardening, fake-log faults, leaf decoding, RFC 6962 source, fetcher, samples |
| 2B | Vault segments and records, dictionaries and `leaf-delta`, Pebble and `ID_FLOOR`, DuckDB staging, the commit protocol and recovery, `update` with `--follow`, `--until`, `--replay`, signals and incidents |
| 2C | Crash and fault suite and the kill loop, `sample measure` and reports, real-data end-to-end and recovery equivalence, docs |
| 3–6 | As in Plan 1's table |

**Carried to Plan 2B, already prepared here:**
- `update` calls `ChainCache.Reset` after each commit.
- `Guard.Preflight` is wired to the batch peak.
- The last accepted head is persisted and passed to `NewSource`.
- Incidents are written to `state/incidents/` and "refetch once" applies to head errors.
- `--replay` runs over `sample.Serve`.
- `stop.OnSignals` drives `update`.

## Before You Start

- Work from the repository root, which holds Plan 1's code.
- You need Linux and network access to `proxy.golang.org` for module downloads. Task A4 downloads one real fixture page from `ct.googleapis.com`; no test needs the network.
- Run tests exactly as shown; `-count=1` forces a fresh run.
- **`/tmp` may be tmpfs.** Dev vaults refuse tmpfs, so `TestDevProbeOnThisMachine` then skips itself. To exercise it on the real disk, run `TMPDIR=$HOME/.cache/ctvault-test go test -tags ctvault_dev -run TestDevProbeOnThisMachine ./internal/volume/`, creating the folder first and deleting it after.
- **Commits:** each task ends with a commit step. If your human partner has turned Git operations off for this execution, skip the `git` commands and record the checkpoint in the progress ledger instead.

## File Structure

```text
cmd/ctvault/main.go                       calls deps(version): production or dev wiring by build tag
cmd/ctvault/deps_prod.go | deps_dev.go    production policy | dev policy (DevProbe, DevBase)
cmd/ctvault/guard_test.go                 production binary has no dev code, reads only CTVAULT_ROOT
internal/volume/build_prod.go | build_dev.go   const devBuild; DevBuild()
internal/volume/devprobe.go               (dev only) DevProbe: vaults only under the dev base
internal/volume/{identity,policy,volume}.go    VAULT_ID mode, dev-unsafe durability, minors 6 and 7
internal/cli/cli.go                       Volumes interface, banner, extraCommands, Deps.Statfs and DevBase
internal/cli/sample_dev.go                (dev only) sample capture | verify
internal/config/config.go                 [fetch] and [delta], non-finite and range checks
internal/diskguard/diskguard.go           cap validation, saturating peak, Preflight by filesystem
internal/ctlogtest/{log,entries}.go       5xx, latency, proof-by-hash, Fork check, precert signer, malformed leaf
internal/leaf/{leaf,cert,precert}.go      MerkleTreeLeaf and extra_data decoding, codes, precert checks
internal/logsource/logsource.go           LogSource, RawEntry, SignedHead, CheckHead, incidents
internal/logsource/chaincache.go          per-batch chain cache
internal/logsource/rfc6962/client.go      + get-entries, get-proof-by-hash, raw STH, quoted errors
internal/logsource/rfc6962/source.go      the RFC 6962 LogSource
internal/fetch/fetch.go                   Run: workers, pacing, retries, ordered bounded buffer, stall rule
internal/fetch/retry.go                   Retry and Transient for single requests
internal/stop/stop.go                     SIGINT/SIGTERM → Soft, then Hard
internal/merkle/state.go                  zero-value State is safe; strict JSON (minor 16)
internal/merkle/inclusion.go              VerifyInclusion, StateFromInclusion
internal/sample/{manifest,writer,read,replay,capture}.go   the sample format and tools (dev only)
internal/sampletest/sampletest.go         (test only) cached samples for tests
internal/integration/{doc.go,realdata_test.go}   real-data tests (tag realdata)
internal/testdata/argon2027h1_entries_380000000.json   real fixture, 32 entries
```

---

### Task A1: Dev build and storage safety

Implements amendment A1 §1 and Plan 1 review minors 6 and 7.

**Files:**
- Create: `internal/volume/build_prod.go`, `internal/volume/build_dev.go`, `internal/volume/devprobe.go`
- Create tests: `internal/volume/mode_test.go`, `internal/volume/build_prod_test.go`, `internal/volume/devprobe_test.go`
- Modify: `internal/volume/identity.go`, `internal/volume/policy.go`, `internal/volume/volume.go`
- Modify: `internal/cli/cli.go`, `internal/cli/vaultcmds.go`, `internal/cli/cli_test.go`
- Create tests: `internal/cli/mode_test.go`, `internal/cli/build_prod_test.go`, `internal/cli/build_dev_test.go`
- Modify: `cmd/ctvault/main.go`
- Create: `cmd/ctvault/deps_prod.go`, `cmd/ctvault/deps_dev.go`, `cmd/ctvault/guard_test.go`

**Interfaces:**
- Consumes (Plan 1): `volume.Checker{Probe, Now}` with `Init`, `Check`, `AddDir`; `volume.MountFor`, `volume.ReadVaultID`, `fsutil.MkdirAllSync`.
- Produces:
  - `volume`:
    - `const ModeProduction = "production"`, `ModeDev = "dev"`
    - `VaultID.Mode string` (empty means production)
    - `DurabilityDevUnsafe Durability = "dev-unsafe"`
    - `func DevBuild() bool`
  - Dev build only:
    - `type DevProbe struct{ Base string; Probe Probe; Now func() time.Time }` with `Init`, `Check`, `AddDir` (always refused)
    - `func DefaultDevBase() (string, error)`
  - `cli`:
    - `type Volumes interface{ Init(root string, opts volume.InitOptions) (volume.VaultID, error); Check(root string) (volume.VaultID, error); AddDir(root, dir string, opts volume.InitOptions) (volume.VaultID, error) }`
    - `Deps.Volumes`, replacing `Deps.Probe`
    - `var extraCommands []func(*app) *cobra.Command`
  - `cmd/ctvault`: `func deps(version string) cli.Deps`, one per build tag.

- [ ] **Step 1: Write the failing production-volume tests**

Create `internal/volume/mode_test.go`:

```go
package volume_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/4rji/ctvault/internal/volume"
)

// rewriteVaultID lets a test edit VAULT_ID in place.
func rewriteVaultID(t *testing.T, root string, edit func(*volume.VaultID)) {
	t.Helper()
	id, err := volume.ReadVaultID(root)
	if err != nil {
		t.Fatal(err)
	}
	edit(&id)
	b, _ := json.Marshal(id)
	if err := os.WriteFile(filepath.Join(root, volume.VaultIDFile), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestInitRecordsProductionMode(t *testing.T) {
	c, _, root := newSSD(t)
	id, err := c.Init(root, volume.InitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if id.Mode != volume.ModeProduction {
		t.Fatalf("mode = %q, want %q", id.Mode, volume.ModeProduction)
	}
}

func TestProductionRefusesDevVault(t *testing.T) {
	c, _, root := newSSD(t)
	if _, err := c.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	rewriteVaultID(t, root, func(id *volume.VaultID) { id.Mode = volume.ModeDev })
	_, err := c.Check(root)
	wantVolumeErr(t, err, "dev vault created by a ctvault_dev build")
}

func TestUnknownModeRefusedAndMissingModeIsProduction(t *testing.T) {
	c, _, root := newSSD(t)
	if _, err := c.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	rewriteVaultID(t, root, func(id *volume.VaultID) { id.Mode = "" }) // a Plan 1 vault
	if _, err := c.Check(root); err != nil {
		t.Fatalf("a VAULT_ID without mode is a production vault: %v", err)
	}
	rewriteVaultID(t, root, func(id *volume.VaultID) { id.Mode = "staging" })
	_, err := c.Check(root)
	wantVolumeErr(t, err, "unknown vault mode")
}

// Plan 1 review, minor 6: the root checks run whatever VAULT_ID lists.
func TestCheckRequiresExactlyOneRoot(t *testing.T) {
	c, _, root := newSSD(t)
	if _, err := c.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	rewriteVaultID(t, root, func(id *volume.VaultID) { id.Volumes = nil })
	_, err := c.Check(root)
	wantVolumeErr(t, err, "exactly one root volume")

	rewriteVaultID(t, root, func(id *volume.VaultID) {
		id.Volumes = []volume.Volume{{Role: volume.RoleRoot}, {Role: volume.RoleRoot}}
	})
	_, err = c.Check(root)
	wantVolumeErr(t, err, "exactly one root volume")
}

func TestCheckEmptyVolumesInPlainDirStillRefused(t *testing.T) {
	c, p, root := newSSD(t)
	if _, err := c.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	rewriteVaultID(t, root, func(id *volume.VaultID) { id.Volumes = nil })
	p.Mounts = p.Mounts[:1] // now a plain directory on the system disk
	_, err := c.Check(root)
	wantVolumeErr(t, err, "not a mount point")
}

// Plan 1 review, minor 7: layout folders must stay on the vault's filesystem.
func TestCheckRefusesSymlinkedLayoutFolder(t *testing.T) {
	c, _, root := newSSD(t)
	if _, err := c.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir() // on the system disk in the fake mount table
	state := filepath.Join(root, "state")
	if err := os.RemoveAll(state); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, state); err != nil {
		t.Fatal(err)
	}
	_, err := c.Check(root)
	wantVolumeErr(t, err, "is a symlink")
}

func TestCheckRefusesLayoutFolderOnAnotherFilesystem(t *testing.T) {
	c, p, root := newSSD(t)
	if _, err := c.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	p.Mount(t, filepath.Join(root, "state"), "ext4", "8:65", "other-disk")
	_, err := c.Check(root)
	wantVolumeErr(t, err, "different filesystem")
}

func TestCheckRefusesMissingLayoutFolder(t *testing.T) {
	c, _, root := newSSD(t)
	if _, err := c.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(filepath.Join(root, "dataset"))
	_, err := c.Check(root)
	wantVolumeErr(t, err, "is missing")
}
```

Create `internal/volume/build_prod_test.go`:

```go
//go:build !ctvault_dev

package volume

import "testing"

func TestDevBuildIsOffInProductionBuilds(t *testing.T) {
	if DevBuild() {
		t.Fatal("DevBuild() must be false without -tags ctvault_dev")
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/volume/`
Expected: FAIL with `id.Mode undefined (type volume.VaultID has no field or method Mode)` and `undefined: DevBuild`.

- [ ] **Step 3: Implement modes, the build-tag constant and minors 6 and 7**

Replace `internal/volume/identity.go`:

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
	Mode       string     `json:"mode"` // ModeProduction or ModeDev; empty (Plan 1 vaults) means production
	CreatedAt  time.Time  `json:"created_at"`
	Durability Durability `json:"durability"`
	Volumes    []Volume   `json:"volumes"`
}

// Vault modes (amendment A1 §1). A production binary only opens production
// vaults; a ctvault_dev binary only opens dev vaults.
const (
	ModeProduction = "production"
	ModeDev        = "dev"
)

// requireMode refuses a vault whose mode is not want.
func requireMode(root string, id VaultID, want string) error {
	mode := id.Mode
	if mode == "" {
		mode = ModeProduction
	}
	switch {
	case mode == want:
		return nil
	case mode == ModeDev:
		return volErr("%s is a dev vault created by a ctvault_dev build; the production binary refuses it", root)
	case mode == ModeProduction:
		return volErr("%s is a production vault; the ctvault_dev build refuses it", root)
	default:
		return volErr("%s has unknown vault mode %q", root, id.Mode)
	}
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

Replace `internal/volume/policy.go`:

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
	// DurabilityDevUnsafe marks dev vaults on the normal disk (amendment A1 §1).
	DurabilityDevUnsafe Durability = "dev-unsafe"
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

Replace `internal/volume/volume.go`:

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
	OnSystemRoot bool     // shares a backing device with "/"
	Backing      []string // devices that really hold the data (loop/dm/md resolved)
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
	info := Info{Path: real, Mount: m, IsMountPoint: m.MountPoint == real}
	// A loop image or dm/md device stored on the system disk is the system
	// disk: compare the devices that really hold the data, not just major:minor.
	sysBacking, err := c.Probe.BackingDevices(sys)
	if err != nil {
		return info, fmt.Errorf("cannot determine the devices behind /: %w", err)
	}
	if info.Backing, err = c.Probe.BackingDevices(m); err != nil {
		return info, fmt.Errorf("cannot determine the devices behind %s: %w", m.MountPoint, err)
	}
	info.OnSystemRoot = m.MajorMinor == sys.MajorMinor ||
		slices.ContainsFunc(info.Backing, func(d string) bool { return slices.Contains(sysBacking, d) })
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
		return volErr("%s is on the same device as / (its data is stored on %s); CTVault refuses to write to the system disk",
			info.Path, strings.Join(info.Backing, ", "))
	case info.Durability == DurabilityUntested && !opts.AllowUntestedFS:
		return volErr("%s is %s, which is untested; pass --allow-untested-fs to accept weaker durability guarantees", info.Path, info.Mount.FSType)
	}
	return nil
}

// requireEmpty allows only lost+found and the leftovers of an interrupted
// init: empty layout directories, vault/DIR_ID and the temp files of the
// atomic writes. Anything else (user files, a foreign ctvault.toml, an old
// vault's segments) means the volume is not dedicated to this vault.
func requireEmpty(dir string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	layout := map[string]bool{}
	for _, d := range LayoutDirs {
		layout[d] = true
		layout[strings.SplitN(d, "/", 2)[0]] = true
	}
	for _, e := range ents {
		name := e.Name()
		switch {
		case name == VaultIDFile:
			return volErr("%s is already an initialized CTVault root", dir)
		case name == "lost+found" || strings.HasPrefix(name, "."+VaultIDFile+".tmp-"):
			continue
		case layout[name] && e.IsDir():
			if err := requireLeftover(dir, name, layout); err != nil {
				return err
			}
		default:
			return volErr("%s is not empty (found %q)", dir, name)
		}
	}
	return nil
}

// requireLeftover walks one top-level layout directory and fails on anything
// an interrupted init could not have created.
func requireLeftover(root, top string, layout map[string]bool) error {
	return filepath.WalkDir(filepath.Join(root, top), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		dirID := "vault/" + DirIDFile
		switch {
		case d.IsDir() && layout[rel]:
			return nil
		case d.Type().IsRegular() && (rel == dirID || strings.HasPrefix(rel, "vault/."+DirIDFile+".tmp-")):
			return nil
		default:
			return volErr("%s is not empty (found %q)", root, rel)
		}
	})
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
	return createVault(info, ModeProduction, info.Durability, c.now())
}

// createVault writes the layout, vault/DIR_ID and, last, VAULT_ID. The caller
// has already applied its mode's volume policy and checked that path is empty.
func createVault(info Info, mode string, durability Durability, now time.Time) (VaultID, error) {
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
		Format: FormatVersion, VaultUUID: vaultUUID, Mode: mode, CreatedAt: now.UTC(), Durability: durability,
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
	if err := requireMode(info.Path, id, ModeProduction); err != nil {
		return id, err
	}
	// The root checks run whatever VAULT_ID says (Plan 1 review, minor 6).
	if err := requireUsable(info, InitOptions{AllowUntestedFS: id.Durability == DurabilityUntested}, true); err != nil {
		return id, err
	}
	rootVol, dirs, err := splitVolumes(id)
	if err != nil {
		return id, err
	}
	if rootVol.FSUUID != info.FSUUID || rootVol.FSType != info.Mount.FSType {
		return id, volErr("%s is filesystem %s (%s) but VAULT_ID records %s (%s)", info.Path, info.FSUUID, info.Mount.FSType, rootVol.FSUUID, rootVol.FSType)
	}
	if err := checkLayout(c.Probe, info); err != nil {
		return id, err
	}
	for _, v := range dirs {
		if err := c.checkDir(info.Path, id, v); err != nil {
			return id, err
		}
	}
	return id, nil
}

// splitVolumes requires exactly one root volume and at least one vault dir.
func splitVolumes(id VaultID) (Volume, []Volume, error) {
	var roots, dirs []Volume
	for _, v := range id.Volumes {
		switch v.Role {
		case RoleRoot:
			roots = append(roots, v)
		case RoleVaultDir:
			dirs = append(dirs, v)
		default:
			return Volume{}, nil, volErr("VAULT_ID has unknown volume role %q", v.Role)
		}
	}
	if len(roots) != 1 {
		return Volume{}, nil, volErr("VAULT_ID must list exactly one root volume, found %d", len(roots))
	}
	if len(dirs) == 0 {
		return Volume{}, nil, volErr("VAULT_ID lists no vault directory")
	}
	return roots[0], dirs, nil
}

// checkLayout requires every layout folder to be a real directory on the
// root's own filesystem, so nothing inside the vault can lead off the volume
// (Plan 1 review, minor 7).
func checkLayout(p Probe, root Info) error {
	mounts, err := p.MountInfo()
	if err != nil {
		return fmt.Errorf("%w: reading mount table: %v", ErrVolume, err)
	}
	for _, d := range LayoutDirs {
		path := filepath.Join(root.Path, d)
		fi, err := os.Lstat(path)
		switch {
		case err != nil:
			return volErr("layout folder %s is missing (%v)", path, err)
		case fi.Mode()&fs.ModeSymlink != 0:
			return volErr("layout folder %s is a symlink; CTVault refuses folders that may lead off the vault volume", path)
		case !fi.IsDir():
			return volErr("layout folder %s is not a directory", path)
		}
		m, ok := MountFor(mounts, path)
		if !ok || m.MountPoint != root.Mount.MountPoint || m.MajorMinor != root.Mount.MajorMinor {
			return volErr("layout folder %s is on a different filesystem (%s) than the vault root", path, m.MountPoint)
		}
	}
	return nil
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
	return checkDirID(vi.Path, id, v)
}

// checkDirID requires dir's DIR_ID to belong to this vault and volume entry.
func checkDirID(dir string, id VaultID, v Volume) error {
	d, err := ReadDirID(dir)
	if err != nil {
		return volErr("vault dir %s has no readable %s (%v)", dir, DirIDFile, err)
	}
	if d.VaultUUID != id.VaultUUID || d.DirID != v.DirID {
		return volErr("vault dir %s belongs to vault %s dir %s, not %s dir %s", dir, d.VaultUUID, d.DirID, id.VaultUUID, v.DirID)
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
	abs, err := filepath.Abs(dir)
	if err != nil {
		return id, err
	}
	// Check the disk before writing anything (spec §9.1): the nearest existing
	// ancestor is on the filesystem the new directory will be created on.
	anc := abs
	for {
		if _, err := os.Lstat(anc); err == nil || filepath.Dir(anc) == anc {
			break
		}
		anc = filepath.Dir(anc)
	}
	ai, err := c.Inspect(anc)
	if err != nil {
		return id, fmt.Errorf("%w: %v", ErrVolume, err)
	}
	if err := requireUsable(ai, opts, false); err != nil {
		return id, err
	}
	if err := fsutil.MkdirAllSync(abs, 0o755); err != nil {
		return id, err
	}
	vi, err := c.Inspect(abs)
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

Create `internal/volume/build_prod.go`:

```go
//go:build !ctvault_dev

package volume

// devBuild is false in production builds, so every dev-only branch compiles
// away (amendment A1 §1).
const devBuild = false

// DevBuild reports whether this binary was built with -tags ctvault_dev.
func DevBuild() bool { return devBuild }
```

Create `internal/volume/build_dev.go`:

```go
//go:build ctvault_dev

package volume

// devBuild is true only in binaries built with -tags ctvault_dev.
const devBuild = true

// DevBuild reports whether this binary was built with -tags ctvault_dev.
func DevBuild() bool { return devBuild }
```

- [ ] **Step 4: Run them to verify they pass**

Run: `go test -count=1 ./internal/volume/... -v`
Expected: PASS, including:
- `TestInitRecordsProductionMode`, `TestProductionRefusesDevVault`, `TestUnknownModeRefusedAndMissingModeIsProduction`
- `TestCheckRequiresExactlyOneRoot`, `TestCheckEmptyVolumesInPlainDirStillRefused`
- `TestCheckRefusesSymlinkedLayoutFolder`, `TestCheckRefusesLayoutFolderOnAnotherFilesystem`, `TestCheckRefusesMissingLayoutFolder`
- `TestDevBuildIsOffInProductionBuilds`

- [ ] **Step 5: Write the failing dev-probe tests**

Create `internal/volume/devprobe_test.go`:

```go
//go:build ctvault_dev

package volume_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/4rji/ctvault/internal/volume"
	"github.com/4rji/ctvault/internal/volume/volumetest"
)

// newDev returns a dev probe whose base is a temp folder; the fake mount
// table places it on "/" (ext4, UUID "system-root"), like a laptop's disk.
func newDev(t *testing.T) (volume.DevProbe, *volumetest.Probe, string) {
	t.Helper()
	p := volumetest.New()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return volume.DevProbe{Base: base, Probe: p, Now: fixedNow}, p, base
}

func TestDevBuildIsOn(t *testing.T) {
	if !volume.DevBuild() {
		t.Fatal("DevBuild() must be true with -tags ctvault_dev")
	}
}

func TestDevInitAndCheck(t *testing.T) {
	d, _, base := newDev(t)
	root := filepath.Join(base, "vaults", "try1") // created by Init
	id, err := d.Init(root, volume.InitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if id.Mode != volume.ModeDev || id.Durability != volume.DurabilityDevUnsafe {
		t.Fatalf("dev VAULT_ID = %+v", id)
	}
	if id.Volumes[0].FSUUID != "system-root" {
		t.Fatalf("dev vault must record the normal disk's real UUID: %+v", id.Volumes[0])
	}
	if _, err := d.Check(root); err != nil {
		t.Fatalf("Check of a fresh dev vault: %v", err)
	}
}

func TestDevRefusesPathsOutsideTheBase(t *testing.T) {
	d, _, base := newDev(t)
	_, err := d.Init(t.TempDir(), volume.InitOptions{})
	wantVolumeErr(t, err, "outside the dev base")
	_, err = d.Init(base, volume.InitOptions{})
	wantVolumeErr(t, err, "outside the dev base")
	_, err = d.Init(filepath.Join(base, "..", "sneaky"), volume.InitOptions{})
	wantVolumeErr(t, err, "outside the dev base")
}

func TestDevRefusesSymlinkEscape(t *testing.T) {
	d, _, base := newDev(t)
	if err := os.MkdirAll(filepath.Join(base, "vaults"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "vaults", "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	_, err := d.Init(link, volume.InitOptions{})
	wantVolumeErr(t, err, "escapes the dev base")
}

func TestDevRefusesProductionVault(t *testing.T) {
	d, p, base := newDev(t)
	root := filepath.Join(base, "vaults", "prod")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	p.Mount(t, root, "ext4", "8:17", "ssd-uuid") // present it as a real SSD to create a production vault
	if _, err := (volume.Checker{Probe: p, Now: fixedNow}).Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	_, err := d.Check(root)
	wantVolumeErr(t, err, "production vault; the ctvault_dev build refuses it")
}

func TestDevRefusesNetworkFuseAndTmpfs(t *testing.T) {
	for _, fstype := range []string{"tmpfs", "nfs4", "fuse.sshfs", "fuseblk"} {
		d, p, base := newDev(t)
		p.Mounts[0].FSType = fstype // the base now sits on this filesystem
		_, err := d.Init(filepath.Join(base, "vaults", "v"), volume.InitOptions{})
		wantVolumeErr(t, err, "dev vaults need a local filesystem")
	}
}

func TestDevCheckDetectsDifferentFilesystem(t *testing.T) {
	d, p, base := newDev(t)
	root := filepath.Join(base, "vaults", "try1")
	if _, err := d.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	p.UUIDs["8:1"] = "another-disk"
	_, err := d.Check(root)
	wantVolumeErr(t, err, "VAULT_ID records")
}

// TestDevProbeOnThisMachine uses the real mount table and /dev/disk/by-uuid,
// with a temp folder as the dev base (never the user's ~/.cache).
func TestDevProbeOnThisMachine(t *testing.T) {
	if _, err := os.Stat("/dev/disk/by-uuid"); err != nil {
		t.Skip("no /dev/disk/by-uuid on this host")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d := volume.DevProbe{Base: base, Probe: volume.HostProbe{}, Now: fixedNow}
	root := filepath.Join(base, "vaults", "machine")
	id, err := d.Init(root, volume.InitOptions{})
	if err != nil {
		t.Skipf("temp folder is not usable for a dev vault on this host: %v", err)
	}
	if id.Volumes[0].FSUUID == "" {
		t.Fatal("dev vault recorded no filesystem UUID")
	}
	if _, err := d.Check(root); err != nil {
		t.Fatalf("Check on the real host: %v", err)
	}
}

func TestDevAddDirUnsupported(t *testing.T) {
	d, _, base := newDev(t)
	root := filepath.Join(base, "vaults", "try1")
	if _, err := d.Init(root, volume.InitOptions{}); err != nil {
		t.Fatal(err)
	}
	_, err := d.AddDir(root, filepath.Join(base, "x"), volume.InitOptions{})
	wantVolumeErr(t, err, "production-only")
}
```

Run: `go test -tags ctvault_dev ./internal/volume/`
Expected: FAIL with `undefined: volume.DevProbe`.

- [ ] **Step 6: Implement the dev probe**

Create `internal/volume/devprobe.go`:

```go
//go:build ctvault_dev

package volume

import (
	"errors"
	"fmt"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/4rji/ctvault/internal/fsutil"
)

// DevProbe is the volume policy of the ctvault_dev build (amendment A1 §1):
// vaults live only under Base, a folder on the normal disk, and are marked
// "dev" in VAULT_ID. It exists only in binaries built with -tags ctvault_dev;
// production binaries cannot construct it.
type DevProbe struct {
	Base  string // the dev base, normally DefaultDevBase(); tests use a temp folder
	Probe Probe  // mount table and filesystem UUIDs
	Now   func() time.Time
}

// DefaultDevBase is <home>/.cache/ctvault-dev, with <home> taken from the OS
// user database rather than $HOME.
func DefaultDevBase() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("looking up the current user: %w", err)
	}
	if u.HomeDir == "" {
		return "", errors.New("the current user has no home directory")
	}
	return filepath.Join(u.HomeDir, ".cache", "ctvault-dev"), nil
}

// resolve returns root's real path, requiring it to lie strictly inside the
// dev base both before and after symlinks are resolved. With create set, the
// folder (and the base) is created first.
func (p DevProbe) resolve(root string, create bool) (string, error) {
	base, err := filepath.Abs(p.Base)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	if !within(abs, base) || abs == base {
		return "", volErr("%s is outside the dev base %s; dev vaults may live only there", abs, base)
	}
	if create {
		if err := fsutil.MkdirAllSync(abs, 0o700); err != nil {
			return "", err
		}
	}
	realBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return "", volErr("dev base %s: %v", base, err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", volErr("%s: %v", abs, err)
	}
	if !within(real, realBase) || real == realBase {
		return "", volErr("%s escapes the dev base %s (resolves to %s)", abs, realBase, real)
	}
	return real, nil
}

// devFSRefused lists filesystems that cannot hold even a dev vault.
func devFSRefused(fstype string) bool {
	switch fstype {
	case "nfs", "nfs4", "cifs", "smb3", "smbfs", "9p", "tmpfs", "ramfs":
		return true
	}
	return fstype == "fuseblk" || fstype == "fuse" || strings.HasPrefix(fstype, "fuse.")
}

// inspect describes the filesystem holding a resolved dev path.
func (p DevProbe) inspect(real string) (Info, error) {
	mounts, err := p.Probe.MountInfo()
	if err != nil {
		return Info{}, fmt.Errorf("%w: reading mount table: %v", ErrVolume, err)
	}
	m, ok := MountFor(mounts, real)
	if !ok {
		return Info{}, volErr("%s is not on any mounted filesystem", real)
	}
	if devFSRefused(m.FSType) {
		return Info{}, volErr("%s is on %s (%s); dev vaults need a local filesystem", real, m.MountPoint, m.FSType)
	}
	uuid, err := p.Probe.FSUUID(m)
	if err != nil {
		return Info{}, fmt.Errorf("%w: %v", ErrVolume, err)
	}
	return Info{Path: real, Mount: m, IsMountPoint: m.MountPoint == real, FSUUID: uuid, Durability: DurabilityDevUnsafe}, nil
}

func (p DevProbe) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Init creates a dev vault at root, which must lie inside the dev base.
func (p DevProbe) Init(root string, _ InitOptions) (VaultID, error) {
	real, err := p.resolve(root, true)
	if err != nil {
		return VaultID{}, err
	}
	info, err := p.inspect(real)
	if err != nil {
		return VaultID{}, err
	}
	if err := requireEmpty(real); err != nil {
		return VaultID{}, err
	}
	return createVault(info, ModeDev, DurabilityDevUnsafe, p.now())
}

// Check verifies a dev vault: inside the dev base, marked dev, on the same
// filesystem as recorded, with an intact layout.
func (p DevProbe) Check(root string) (VaultID, error) {
	real, err := p.resolve(root, false)
	if err != nil {
		return VaultID{}, err
	}
	id, err := ReadVaultID(real)
	if err != nil {
		return VaultID{}, volErr("%s is not an initialized CTVault root (%v)", real, err)
	}
	if err := requireMode(real, id, ModeDev); err != nil {
		return id, err
	}
	info, err := p.inspect(real)
	if err != nil {
		return id, err
	}
	rootVol, dirs, err := splitVolumes(id)
	if err != nil {
		return id, err
	}
	if rootVol.FSUUID != info.FSUUID {
		return id, volErr("%s is filesystem %s but VAULT_ID records %s", real, info.FSUUID, rootVol.FSUUID)
	}
	if err := checkLayout(p.Probe, info); err != nil {
		return id, err
	}
	for _, v := range dirs {
		if filepath.IsAbs(v.Path) {
			return id, volErr("dev vaults keep their vault directory inside the root, not at %s", v.Path)
		}
		if err := checkDirID(filepath.Join(real, v.Path), id, v); err != nil {
			return id, err
		}
	}
	return id, nil
}

// AddDir is not supported for dev vaults: they keep one vault directory.
func (p DevProbe) AddDir(root, dir string, _ InitOptions) (VaultID, error) {
	return VaultID{}, volErr("dev vaults keep a single vault directory; vault add-dir is production-only")
}
```

Run: `go test -count=1 -tags ctvault_dev ./internal/volume/ -v -run Dev`
Expected: PASS, including:
- `TestDevBuildIsOn`, `TestDevInitAndCheck`
- `TestDevRefusesPathsOutsideTheBase`, `TestDevRefusesSymlinkEscape`, `TestDevRefusesProductionVault`, `TestDevRefusesNetworkFuseAndTmpfs`
- `TestDevCheckDetectsDifferentFilesystem`, `TestDevAddDirUnsupported`

`TestDevProbeOnThisMachine` passes, or skips on a tmpfs `/tmp` (see Before You Start).

- [ ] **Step 7: Write the failing CLI tests**

Replace `internal/cli/cli_test.go` (the harness now passes `Volumes` instead of `Probe`):

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
	"github.com/4rji/ctvault/internal/volume"
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
	now := func() time.Time { return time.Date(2026, 10, 4, 7, 0, 0, 0, time.UTC) }
	e.deps = Deps{
		Volumes: volume.Checker{Probe: p, Now: now},
		HTTP:    &http.Client{Transport: rewrite{target}}, Getenv: func(string) string { return "" },
		Now:    now,
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

Create `internal/cli/mode_test.go`:

```go
package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/volume"
)

func TestDevVaultRefusedWithExit4(t *testing.T) {
	e := newEnv(t, realSTH(t))
	e.mustRun("init", e.root)
	id, err := volume.ReadVaultID(e.root)
	if err != nil {
		t.Fatal(err)
	}
	id.Mode = volume.ModeDev
	b, _ := json.Marshal(id)
	os.WriteFile(filepath.Join(e.root, volume.VaultIDFile), b, 0o644)
	if got := e.run("--root", e.root, "logs", "list"); got != exitcode.Volume {
		t.Fatalf("dev vault in a production build: exit %d, want %d", got, exitcode.Volume)
	}
	if !strings.Contains(e.stderr.String(), "dev vault created by a ctvault_dev build") {
		t.Fatalf("stderr: %s", e.stderr)
	}
}
```

Create `internal/cli/build_prod_test.go`:

```go
//go:build !ctvault_dev

package cli

import (
	"strings"
	"testing"
)

func TestProductionBuildHasNoDevBanner(t *testing.T) {
	e := newEnv(t, realSTH(t))
	e.mustRun("version")
	if strings.Contains(e.stdout.String()+e.stderr.String(), "DEV BUILD") {
		t.Fatalf("production output mentions a dev build: %q %q", e.stdout, e.stderr)
	}
}
```

Create `internal/cli/build_dev_test.go`:

```go
//go:build ctvault_dev

package cli

import (
	"strings"
	"testing"
)

func TestDevBuildIsMarkedEverywhere(t *testing.T) {
	e := newEnv(t, realSTH(t))
	e.mustRun("version")
	if !strings.Contains(e.stdout.String(), "DEV BUILD — not for production") {
		t.Fatalf("version output: %q", e.stdout)
	}
	if !strings.Contains(e.stderr.String(), "WARNING: DEV BUILD") {
		t.Fatalf("every command must print the dev banner, stderr: %q", e.stderr)
	}
}
```

Run: `go test ./internal/cli/`
Expected: FAIL with `unknown field Volumes in struct literal of type Deps`.

- [ ] **Step 8: Wire the volume policy through the CLI**

Replace `internal/cli/cli.go`:

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

// Volumes is the volume policy the commands use: volume.Checker in production
// builds, volume.DevProbe in ctvault_dev builds (amendment A1 §1).
type Volumes interface {
	Init(root string, opts volume.InitOptions) (volume.VaultID, error)
	Check(root string) (volume.VaultID, error)
	AddDir(root, dir string, opts volume.InitOptions) (volume.VaultID, error)
}

// Deps are the host services the commands use.
type Deps struct {
	Volumes       Volumes
	HTTP          *http.Client
	Now           func() time.Time
	Stdout        io.Writer
	Stderr        io.Writer
	Getenv        func(string) string
	LogListSource string
	Version       string
}

// DefaultDeps wires the real host with the production volume policy.
func DefaultDeps(version string) Deps {
	return Deps{
		Volumes: volume.Checker{Probe: volume.HostProbe{}, Now: time.Now},
		HTTP:    &http.Client{Timeout: 60 * time.Second}, Now: time.Now,
		Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv,
		LogListSource: loglist.DefaultURL, Version: version,
	}
}

// devBanner is printed on stderr by every command of a ctvault_dev binary.
const devBanner = "WARNING: DEV BUILD (ctvault_dev) — not for production. Vaults live only under ~/.cache/ctvault-dev/."

// extraCommands lets build-tagged files add commands (the dev build's
// "sample" commands); production builds register none.
var extraCommands []func(*app) *cobra.Command

// Main runs one command and returns its exit code (spec §11.2).
func Main(args []string, d Deps) int {
	if volume.DevBuild() {
		fmt.Fprintln(d.Stderr, devBanner)
	}
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
	root.AddCommand(newVersionCmd(a), newInitCmd(a), newLogsCmd(a), newVaultCmd(a))
	for _, extra := range extraCommands {
		root.AddCommand(extra(a))
	}
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
	id, err := a.d.Volumes.Check(a.root)
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
			if volume.DevBuild() {
				fmt.Fprintln(c.OutOrStdout(), "ctvault", a.d.Version, "DEV BUILD — not for production")
				return nil
			}
			fmt.Fprintln(c.OutOrStdout(), "ctvault", a.d.Version)
			return nil
		},
	}
}
```

Replace `internal/cli/vaultcmds.go`:

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
			id, err := a.d.Volumes.Init(args[0], volume.InitOptions{AllowUntestedFS: allowUntested})
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
			id, err := a.d.Volumes.AddDir(root, args[0], volume.InitOptions{AllowUntestedFS: allowUntested})
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

Run: `go test -count=1 ./internal/cli/ && go test -count=1 -tags ctvault_dev ./internal/cli/`
Expected: PASS (`TestDevVaultRefusedWithExit4`, `TestProductionBuildHasNoDevBanner`, `TestDevBuildIsMarkedEverywhere`, and all Plan 1 CLI tests).

- [ ] **Step 9: Write the binary guard tests**

Create `cmd/ctvault/guard_test.go`:

```go
package main

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// goCmd runs the go tool with GOFLAGS cleared, so a developer's environment
// cannot sneak build tags into the production checks.
func goCmd(t *testing.T, args ...string) []byte {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not in PATH")
	}
	cmd := exec.Command(goBin, args...)
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("go %v: %v\n%s", args, err, ee.Stderr)
		}
		t.Fatalf("go %v: %v", args, err)
	}
	return out
}

// TestProductionBinaryExcludesDevCode proves amendment A1 §1: production
// builds contain no dev probe, no dev-only file and no test-only package.
func TestProductionBinaryExcludesDevCode(t *testing.T) {
	if testing.Short() {
		t.Skip("builds two binaries")
	}
	banned := []string{"/internal/volume/volumetest", "/internal/ctlogtest", "/internal/sampletest", "/internal/sample"}
	dec := json.NewDecoder(bytes.NewReader(goCmd(t, "list", "-deps", "-json", ".")))
	for dec.More() {
		var p struct {
			ImportPath string
			GoFiles    []string
		}
		if err := dec.Decode(&p); err != nil {
			t.Fatal(err)
		}
		for _, b := range banned {
			if strings.HasSuffix(p.ImportPath, b) {
				t.Errorf("production binary depends on test/dev-only package %s", p.ImportPath)
			}
		}
		for _, f := range p.GoFiles {
			if f == "devprobe.go" || strings.HasSuffix(f, "_dev.go") {
				t.Errorf("production build of %s compiles dev-only file %s", p.ImportPath, f)
			}
		}
	}

	dir := t.TempDir()
	prod, dev := filepath.Join(dir, "ctvault"), filepath.Join(dir, "ctvault-dev")
	goCmd(t, "build", "-o", prod, ".")
	goCmd(t, "build", "-tags", "ctvault_dev", "-o", dev, ".")
	if syms := goCmd(t, "tool", "nm", prod); bytes.Contains(syms, []byte("volume.DevProbe")) {
		t.Error("production binary contains the DevProbe symbol")
	}
	// Positive control: the same check finds DevProbe in a dev build, so the
	// assertion above can actually fail.
	if syms := goCmd(t, "tool", "nm", dev); !bytes.Contains(syms, []byte("volume.DevProbe")) {
		t.Error("dev binary lacks DevProbe; the symbol check is not meaningful")
	}
}

// productionFile reports whether a non-test Go file is compiled into
// production builds: its //go:build line, if any, must hold without ctvault_dev.
func productionFile(src []byte) bool {
	for _, line := range strings.Split(string(src), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package ") {
			return true
		}
		if constraint.IsGoBuild(line) {
			expr, err := constraint.Parse(line)
			if err != nil {
				return true
			}
			return expr.Eval(func(tag string) bool { return tag != "ctvault_dev" })
		}
	}
	return true
}

// TestOnlyRootEnvVarIsRead proves amendment A1 §1: no environment variable
// can change production behaviour except CTVAULT_ROOT, which selects a path.
// os.Getenv may be referenced only where it is injected (cli.DefaultDeps), and
// every Getenv call must name CTVAULT_ROOT literally.
func TestOnlyRootEnvVarIsRead(t *testing.T) {
	root := filepath.Join("..", "..")
	envFuncs := map[string]bool{"Getenv": true, "LookupEnv": true, "Environ": true, "ExpandEnv": true}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !productionFile(src) {
			return nil
		}
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if id, ok := x.X.(*ast.Ident); ok && (id.Name == "os" || id.Name == "syscall") && envFuncs[x.Sel.Name] {
					if rel != filepath.Join("internal", "cli", "cli.go") || x.Sel.Name != "Getenv" {
						t.Errorf("%s: %s.%s outside the single injection point", fset.Position(x.Pos()), id.Name, x.Sel.Name)
					}
				}
			case *ast.CallExpr:
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Getenv" || len(x.Args) != 1 {
					return true
				}
				lit, ok := x.Args[0].(*ast.BasicLit)
				if !ok || lit.Value != `"CTVAULT_ROOT"` {
					t.Errorf("%s: Getenv must read only \"CTVAULT_ROOT\"", fset.Position(x.Pos()))
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
```

Run: `go test -count=1 ./cmd/ctvault/`
Expected: FAIL with `dev binary lacks DevProbe; the symbol check is not meaningful`. `main.go` does not yet wire the dev probe, so the positive control fails.

- [ ] **Step 10: Select the wiring by build tag**

Replace `cmd/ctvault/main.go`:

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
	os.Exit(cli.Main(os.Args[1:], deps(version)))
}
```

Create `cmd/ctvault/deps_prod.go`:

```go
//go:build !ctvault_dev

package main

import "github.com/4rji/ctvault/internal/cli"

// deps wires the production volume policy (spec §9).
func deps(version string) cli.Deps { return cli.DefaultDeps(version) }
```

Create `cmd/ctvault/deps_dev.go`:

```go
//go:build ctvault_dev

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/4rji/ctvault/internal/cli"
	"github.com/4rji/ctvault/internal/volume"
)

// deps wires the dev volume policy: vaults only under ~/.cache/ctvault-dev/
// (amendment A1 §1).
func deps(version string) cli.Deps {
	d := cli.DefaultDeps(version)
	base, err := volume.DefaultDevBase()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ctvault-dev:", err)
		os.Exit(1)
	}
	d.Volumes = volume.DevProbe{Base: base, Probe: volume.HostProbe{}, Now: time.Now}
	return d
}
```

Run: `go test -count=1 ./cmd/ctvault/ -v`
Expected: PASS (`TestProductionBinaryExcludesDevCode`, `TestOnlyRootEnvVarIsRead`).

- [ ] **Step 11: Gate and commit**

Run the four gate commands from Global Constraints. All must pass.

```bash
git add internal/volume internal/cli cmd/ctvault
git commit -m "feat: ctvault_dev build with dev-only vaults; production refuses dev vaults (A1 §1, minors 6-7)"
```

---

### Task A2: Config and disk-guard hardening

Implements amendment A1 §4 (buffer limits), §5 (`delta.warm_batches`) and §7 (DuckDB spill), plus Plan 1 review minors 9, 10 and 11.

**Files:**
- Modify: `internal/config/config.go`
- Create test: `internal/config/hardening_test.go`
- Modify: `internal/diskguard/diskguard.go`, `internal/diskguard/diskguard_test.go`
- Create test: `internal/diskguard/preflight_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `config`:
    - `Config.Fetch{MaxBufferedEntries int; MaxBufferedBytes Size}`, defaults 65,536 and 256 MiB
    - `Config.Delta{WarmBatches int}`, default 4
    - `Validate` refuses non-finite and out-of-range values
    - `Size` parsing refuses overflow
  - `diskguard`:
    - `Usage.Dev uint64` (st_dev)
    - `var ErrBadCap`, `const MaxCap = 0.95`
    - `type Target struct{ Path string; Need uint64 }`
    - `func (Guard) Preflight([]Target) error`
    - `PeakInput.DuckDBSpill` (renamed from `CanarySpill`)
    - `EstimatePeak` saturates at `math.MaxUint64`

- [ ] **Step 1: Write the failing config tests**

Create `internal/config/hardening_test.go`:

```go
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultsForFetchAndDelta(t *testing.T) {
	d := Default()
	if d.Fetch.MaxBufferedEntries != 65536 || d.Fetch.MaxBufferedBytes != 256<<20 || d.Delta.WarmBatches != 4 {
		t.Fatalf("amendment A1 defaults: fetch %+v delta %+v", d.Fetch, d.Delta)
	}
}

// TestLoadRejectsNonFiniteAndAbsurdValues covers Plan 1 review minor 11: TOML
// accepts nan and inf, and a size suffix can overflow 64 bits.
func TestLoadRejectsNonFiniteAndAbsurdValues(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"nan rps":           {"[ingest]\nmax_rps = nan\n", "ingest.max_rps"},
		"inf rps":           {"[ingest]\nmax_rps = inf\n", "ingest.max_rps"},
		"nan cap":           {"[disk]\nmax_used_fraction = nan\n", "disk.max_used_fraction"},
		"inf safety":        {"[disk]\nsafety_factor = inf\n", "disk.safety_factor"},
		"huge safety":       {"[disk]\nsafety_factor = 1e9\n", "disk.safety_factor"},
		"huge batch":        {"[ingest]\nbatch_size = 1000000000\n", "ingest.batch_size"},
		"size overflow":     {"[vault]\nsegment_size = \"17179869184GiB\"\n", "overflows"},
		"huge segment":      {"[vault]\nsegment_size = \"1TiB\"\n", "vault.segment_size"},
		"tiny buffer":       {"[fetch]\nmax_buffered_entries = 10\n", "fetch.max_buffered_entries"},
		"tiny buffer bytes": {"[fetch]\nmax_buffered_bytes = \"1MiB\"\n", "fetch.max_buffered_bytes"},
		"negative warm":     {"[delta]\nwarm_batches = -1\n", "delta.warm_batches"},
		"day-long stall":    {"[ingest]\nstall_timeout = \"48h\"\n", "ingest.stall_timeout"},
	} {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, FileName), []byte(tc.body), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := Load(root)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to mention %q", name, err, tc.want)
		}
	}
}

func TestLoadFetchAndDeltaOverrides(t *testing.T) {
	root := t.TempDir()
	body := "[fetch]\nmax_buffered_entries = 4096\nmax_buffered_bytes = \"64MiB\"\n[delta]\nwarm_batches = 0\n"
	if err := os.WriteFile(filepath.Join(root, FileName), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Fetch.MaxBufferedEntries != 4096 || got.Fetch.MaxBufferedBytes != 64<<20 || got.Delta.WarmBatches != 0 {
		t.Fatalf("overrides not applied: fetch %+v delta %+v", got.Fetch, got.Delta)
	}
}
```

Run: `go test ./internal/config/`
Expected: FAIL with `d.Fetch undefined (type Config has no field or method Fetch)`.

- [ ] **Step 2: Implement the config changes**

Replace `internal/config/config.go`:

```go
// Package config loads <root>/ctvault.toml (spec §11.1). A missing file means
// defaults, so an interrupted init never leaves a vault unusable.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
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
	Fetch   Fetch   `toml:"fetch"`
	Delta   Delta   `toml:"delta"`
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

// Fetch bounds the fetcher's reorder buffer (amendment A1 §4): workers pause
// when either limit is reached.
type Fetch struct {
	MaxBufferedEntries int  `toml:"max_buffered_entries"`
	MaxBufferedBytes   Size `toml:"max_buffered_bytes"`
}

// Delta tunes the leaf-delta cache (amendment A1 §5).
type Delta struct {
	WarmBatches int `toml:"warm_batches"`
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
			if n > math.MaxUint64/u.mult {
				return fmt.Errorf("size %q overflows 64 bits", str)
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
		Fetch:   Fetch{MaxBufferedEntries: 65536, MaxBufferedBytes: 256 << 20},
		Delta:   Delta{WarmBatches: 4},
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

[fetch]
max_buffered_entries = 65536
max_buffered_bytes = "256MiB"

[delta]
warm_batches = 4

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

// Validate rejects values that would make ingestion unsafe or meaningless:
// non-finite numbers, values out of range, and sizes beyond what any real
// deployment uses (Plan 1 review, minor 11).
func (c Config) Validate() error {
	var errs []error
	check := func(ok bool, format string, args ...any) {
		if !ok {
			errs = append(errs, fmt.Errorf(format, args...))
		}
	}
	finite := func(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) }
	check(c.Ingest.BatchSize >= 1 && c.Ingest.BatchSize <= 10_000_000, "ingest.batch_size must be 1-10000000")
	check(c.Ingest.Workers >= 1 && c.Ingest.Workers <= 64, "ingest.workers must be 1-64")
	check(finite(c.Ingest.MaxRPS) && c.Ingest.MaxRPS > 0 && c.Ingest.MaxRPS <= 1000, "ingest.max_rps must be in (0, 1000]")
	check(c.Ingest.FollowInterval.Duration >= time.Second && c.Ingest.FollowInterval.Duration <= 24*time.Hour, "ingest.follow_interval must be 1s-24h")
	check(c.Ingest.StallTimeout.Duration >= time.Second && c.Ingest.StallTimeout.Duration <= 24*time.Hour, "ingest.stall_timeout must be 1s-24h")
	check(c.Ingest.DeltaLRUEntries >= 0 && c.Ingest.DeltaLRUEntries <= 100_000_000, "ingest.delta_lru_entries must be 0-100000000")
	check(c.Fetch.MaxBufferedEntries >= 1024 && c.Fetch.MaxBufferedEntries <= 16<<20, "fetch.max_buffered_entries must be 1024-16777216")
	check(c.Fetch.MaxBufferedBytes >= 16<<20 && c.Fetch.MaxBufferedBytes <= 64<<30, "fetch.max_buffered_bytes must be 16MiB-64GiB")
	check(c.Delta.WarmBatches >= 0 && c.Delta.WarmBatches <= 64, "delta.warm_batches must be 0-64")
	check(c.Vault.SegmentSize >= 1<<20 && c.Vault.SegmentSize <= 64<<30, "vault.segment_size must be 1MiB-64GiB")
	check(finite(c.Disk.MaxUsedFraction) && c.Disk.MaxUsedFraction > 0 && c.Disk.MaxUsedFraction <= 0.95, "disk.max_used_fraction must be in (0, 0.95]")
	check(finite(c.Disk.SafetyFactor) && c.Disk.SafetyFactor >= 1 && c.Disk.SafetyFactor <= 10, "disk.safety_factor must be 1-10")
	check(c.Rebuild.Workers >= 1 && c.Rebuild.Workers <= 64, "rebuild.workers must be 1-64")
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

Run: `go test -count=1 ./internal/config/ -v`
Expected: PASS:
- `TestDefaultsForFetchAndDelta`, `TestLoadRejectsNonFiniteAndAbsurdValues`, `TestLoadFetchAndDeltaOverrides`
- Plan 1's `TestDefaultTOMLMatchesDefault`, which proves `DefaultTOML` still matches `Default()`

- [ ] **Step 3: Write the failing guard tests**

Create `internal/diskguard/preflight_test.go`:

```go
package diskguard

import (
	"errors"
	"math"
	"strings"
	"testing"
)

// TestBadCapRefusesEverything covers Plan 1 review minor 9: a NaN, infinite,
// zero, negative or above-0.95 cap must refuse, never compare as "fits".
func TestBadCapRefusesEverything(t *testing.T) {
	u := fixed(Usage{Total: 100 * tb, Avail: 99 * tb})
	for _, c := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), 0, -0.5, 0.96, 1, 2} {
		g := Guard{Cap: c, Stat: u}
		if err := g.Check("/x", 0); !errors.Is(err, ErrBadCap) {
			t.Errorf("cap %v: Check = %v, want ErrBadCap", c, err)
		}
		if err := g.Preflight([]Target{{Path: "/x", Need: 0}}); !errors.Is(err, ErrBadCap) {
			t.Errorf("cap %v: Preflight = %v, want ErrBadCap", c, err)
		}
	}
	if err := (Guard{Cap: 0.95, Stat: u}).Check("/x", 1); err != nil {
		t.Fatalf("0.95 is the highest allowed cap: %v", err)
	}
}

// TestEstimatePeakSaturates covers Plan 1 review minor 10: the result never
// wraps around to a small number.
func TestEstimatePeakSaturates(t *testing.T) {
	for name, in := range map[string]PeakInput{
		"huge entries": {Entries: math.MaxUint64, VaultP95: 840, ParquetP95: 175, PebbleP95: 60, Safety: 1.5},
		"huge p95":     {Entries: 500000, VaultP95: 1e300, ParquetP95: 1e300, Safety: 1.5},
		"inf p95":      {Entries: 1, VaultP95: math.Inf(1), ParquetP95: math.Inf(1), Safety: 1},
		"nan p95":      {Entries: 1, VaultP95: math.NaN(), ParquetP95: math.NaN(), Safety: 1},
		"huge spill":   {Entries: 1, Safety: 1, VaultP95: math.MaxFloat64, DuckDBSpill: math.MaxUint64},
	} {
		p := EstimatePeak(in)
		if p.Vault != math.MaxUint64 || p.Root != math.MaxUint64 {
			t.Errorf("%s: peak %+v, want both saturated at MaxUint64", name, p)
		}
	}
}

// statByPath gives each path its own fake filesystem.
func statByPath(m map[string]Usage) StatFunc {
	return func(p string) (Usage, error) {
		u, ok := m[p]
		if !ok {
			return Usage{}, errors.New("no such path")
		}
		return u, nil
	}
}

// TestPreflightSumsTargetsOnOneFilesystem: the default vault/ folder lives on
// the root volume, so the vault peak and the root peak must fit together.
func TestPreflightSumsTargetsOnOneFilesystem(t *testing.T) {
	shared := Usage{Total: 100 * tb, Avail: 50 * tb, Dev: 7} // 50% used; 35 TB below the cap
	g := Guard{Cap: 0.85, Stat: statByPath(map[string]Usage{"/r": shared, "/r/vault": shared})}
	if err := g.Preflight([]Target{{"/r", 20 * tb}, {"/r/vault", 10 * tb}}); err != nil {
		t.Fatalf("30 TB in total fits under 35 TB: %v", err)
	}
	err := g.Preflight([]Target{{"/r", 20 * tb}, {"/r/vault", 20 * tb}})
	var ce *CapError
	if !errors.As(err, &ce) || ce.Need != 40*tb {
		t.Fatalf("each target fits alone but 40 TB together does not: %v", err)
	}
	if !strings.Contains(ce.Path, "/r + /r/vault") {
		t.Fatalf("the refusal must name every path on the filesystem: %q", ce.Path)
	}
}

func TestPreflightChecksSeparateFilesystemsSeparately(t *testing.T) {
	g := Guard{Cap: 0.85, Stat: statByPath(map[string]Usage{
		"/r":     {Total: 100 * tb, Avail: 50 * tb, Dev: 1},
		"/disk2": {Total: 100 * tb, Avail: 50 * tb, Dev: 2},
	})}
	if err := g.Preflight([]Target{{"/r", 30 * tb}, {"/disk2", 30 * tb}}); err != nil {
		t.Fatalf("30 TB on each of two volumes fits: %v", err)
	}
	if err := g.Preflight([]Target{{"/r", 30 * tb}, {"/disk2", 40 * tb}}); !errors.Is(err, ErrCap) {
		t.Fatalf("the second volume must refuse: %v", err)
	}
	if err := g.Preflight([]Target{{"/missing", 1}}); err == nil || errors.Is(err, ErrCap) {
		t.Fatalf("a statfs failure is an error, not a cap answer: %v", err)
	}
}

func TestPreflightSaturatesSummedNeed(t *testing.T) {
	u := Usage{Total: 100 * tb, Avail: 100 * tb, Dev: 1}
	g := Guard{Cap: 0.85, Stat: statByPath(map[string]Usage{"/a": u, "/b": u})}
	if err := g.Preflight([]Target{{"/a", math.MaxUint64}, {"/b", math.MaxUint64}}); !errors.Is(err, ErrCap) {
		t.Fatalf("an overflowing sum must refuse: %v", err)
	}
}

func TestStatfsReportsDevice(t *testing.T) {
	d := t.TempDir()
	a, err := Statfs(d)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Statfs(d + "/.")
	if err != nil {
		t.Fatal(err)
	}
	if a.Dev == 0 || a.Dev != b.Dev {
		t.Fatalf("Dev must identify the filesystem: %d vs %d", a.Dev, b.Dev)
	}
}
```

Replace `internal/diskguard/diskguard_test.go` (only `CanarySpill` becomes `DuckDBSpill` in `TestEstimatePeak`):

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
		PebbleSize: 100 << 30, DuckDBSpill: 1 << 30,
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

Run: `go test ./internal/diskguard/`
Expected: FAIL with `unknown field DuckDBSpill in struct literal of type PeakInput` and `undefined: ErrBadCap`.

- [ ] **Step 4: Implement the guard changes**

Replace `internal/diskguard/diskguard.go`:

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
	"strings"

	"golang.org/x/sys/unix"
)

// Usage is a filesystem's size and the space available to unprivileged
// writers. Dev identifies the filesystem (st_dev of the path), so targets that
// share one are checked together.
type Usage struct {
	Total uint64
	Avail uint64
	Dev   uint64
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

// Statfs is the real StatFunc: (f_blocks − f_bavail) × fragment size, with
// the filesystem identified by the path's st_dev.
func Statfs(path string) (Usage, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return Usage{}, err
	}
	var fi unix.Stat_t
	if err := unix.Stat(path, &fi); err != nil {
		return Usage{}, err
	}
	bs := uint64(st.Frsize)
	if bs == 0 {
		bs = uint64(st.Bsize)
	}
	return Usage{Total: st.Blocks * bs, Avail: st.Bavail * bs, Dev: uint64(fi.Dev)}, nil
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

// ErrBadCap means the guard was given a cap outside (0, MaxCap]; it refuses
// every request rather than guess (Plan 1 review, minor 9).
var ErrBadCap = errors.New("disk guard: cap must be a finite fraction in (0, 0.95]")

// MaxCap is the highest cap the guard accepts (config allows the same).
const MaxCap = 0.95

func (g Guard) validCap() error {
	if math.IsNaN(g.Cap) || math.IsInf(g.Cap, 0) || g.Cap <= 0 || g.Cap > MaxCap {
		return fmt.Errorf("%w (got %v)", ErrBadCap, g.Cap)
	}
	return nil
}

// Check returns a *CapError if adding need bytes to path's volume would take
// usage above Cap × Total.
func (g Guard) Check(path string, need uint64) error {
	if err := g.validCap(); err != nil {
		return err
	}
	u, err := g.Stat(path)
	if err != nil {
		return fmt.Errorf("statfs %s: %w", path, err)
	}
	return g.fits(path, u, need)
}

func (g Guard) fits(path string, u Usage, need uint64) error {
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
	DuckDBSpill          uint64  // DuckDB temp/spill limit (max_temp_directory_size), amendment A1 §7
	RebuildExtraPerEntry float64 // derived bytes per entry for a dual-built version, 0 if none
}

// Peak is the space a batch may need on the vault volume and the root volume.
type Peak struct {
	Vault uint64
	Root  uint64
}

// EstimatePeak applies the spec §10.1 formula. It computes in float64 and
// saturates at the largest uint64, so absurd inputs give a peak that can never
// fit instead of a wrapped small number (Plan 1 review, minor 10).
func EstimatePeak(in PeakInput) Peak {
	n := float64(in.Entries)
	compaction := max(uint64(MinPebbleCompactionReserve), in.PebbleSize/10)
	vault := toBytes(n*in.VaultP95*in.Safety) + SegmentReserve
	root := toBytes(n*(in.ParquetP95+in.PebbleP95+in.RebuildExtraPerEntry)*in.Safety) +
		float64(compaction) + MetadataOverhead + float64(in.DuckDBSpill)
	return Peak{Vault: saturate(vault), Root: saturate(root)}
}

// toBytes rounds a non-negative byte estimate up; NaN counts as unbounded.
func toBytes(f float64) float64 {
	if math.IsNaN(f) {
		return math.Inf(1)
	}
	return math.Ceil(max(f, 0))
}

// saturate converts to uint64, clamping anything at or beyond 2^64.
func saturate(f float64) uint64 {
	if f >= math.MaxUint64 {
		return math.MaxUint64
	}
	return uint64(f)
}

// Target is one place a batch writes and the bytes it may need there.
type Target struct {
	Path string
	Need uint64
}

// Preflight checks every target before a batch starts. Targets on the same
// filesystem (the default vault/ folder lives on the root volume, and a dev
// vault shares the normal disk) are summed and checked once, so two separate
// "fits" answers can never add up to a crossed cap.
func (g Guard) Preflight(targets []Target) error {
	if err := g.validCap(); err != nil {
		return err
	}
	type group struct {
		paths []string
		usage Usage
		need  uint64
	}
	var order []uint64
	groups := map[uint64]*group{}
	for _, t := range targets {
		u, err := g.Stat(t.Path)
		if err != nil {
			return fmt.Errorf("statfs %s: %w", t.Path, err)
		}
		gr, ok := groups[u.Dev]
		if !ok {
			gr = &group{usage: u}
			groups[u.Dev] = gr
			order = append(order, u.Dev)
		}
		gr.paths = append(gr.paths, t.Path)
		gr.need = addSat(gr.need, t.Need)
	}
	for _, dev := range order {
		gr := groups[dev]
		if err := g.fits(strings.Join(gr.paths, " + "), gr.usage, gr.need); err != nil {
			return err
		}
	}
	return nil
}

func addSat(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}
```

Run: `go test -count=1 ./internal/diskguard/ -v`
Expected: PASS:
- `TestBadCapRefusesEverything`, `TestEstimatePeakSaturates`
- `TestPreflightSumsTargetsOnOneFilesystem`, `TestPreflightChecksSeparateFilesystemsSeparately`, `TestPreflightSaturatesSummedNeed`
- `TestStatfsReportsDevice`, and the Plan 1 tests

- [ ] **Step 5: Gate and commit**

Run the four gate commands. All must pass.

```bash
git add internal/config internal/diskguard
git commit -m "feat: [fetch]/[delta] config, non-finite checks, guard cap validation, saturating peak, per-filesystem preflight (minors 9-11)"
```

---

### Task A3: Fake-log fault modes and certificate variants

Implements spec §13.4 and Plan 1 review minor 15. The leaf decoder (Task A4) and the fetcher (Task A6) are tested against these modes.

**Files:**
- Modify: `internal/ctlogtest/log.go`, `internal/ctlogtest/entries.go`
- Create test: `internal/ctlogtest/faults_test.go`

**Interfaces:**
- Consumes: Plan 1's `ctlogtest.New`, `NewWithEntries`, `Generator`, `Entry`, `MerkleTreeLeaf`.
- Produces:
  - `Options`:
    - `ServerErrorEvery int`: a bare 503
    - `NoRetryAfter bool`: 429s without `Retry-After`
    - `EntriesDelay func(start uint64) time.Duration`: lets requests complete out of order
  - Endpoint: `GET /ct/v1/get-proof-by-hash`
  - `Log.Fork(index)` fails the test for an index outside the log
  - `func Chain(certs ...[]byte) []byte`, `func PrecertExtraData(precert []byte, chain ...[]byte) []byte`
  - `func (*Generator) PairViaSigner(name string, ts uint64) (pre, final Entry, err error)`, `func (*Generator) SignerDER() []byte`
  - `func MalformedEntry(ts uint64) Entry`: a version-1 leaf that still belongs to the tree

- [ ] **Step 1: Write the failing tests**

Create `internal/ctlogtest/faults_test.go`:

```go
package ctlogtest

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

func TestServerErrorEvery(t *testing.T) {
	l := New(t, 4, Options{ServerErrorEvery: 2})
	if resp, _ := get(t, l.URL+"ct/v1/get-sth"); resp.StatusCode != 200 {
		t.Fatalf("request 1: %d", resp.StatusCode)
	}
	resp, _ := get(t, l.URL+"ct/v1/get-entries?start=0&end=3")
	if resp.StatusCode != 503 || resp.Header.Get("Retry-After") != "" {
		t.Fatalf("request 2 must be a bare 503, got %d (Retry-After %q)", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
}

func TestNoRetryAfter(t *testing.T) {
	l := New(t, 4, Options{RateLimitEvery: 1, NoRetryAfter: true})
	resp, _ := get(t, l.URL+"ct/v1/get-sth")
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") != "" {
		t.Fatalf("want a 429 without Retry-After, got %d %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
}

// TestEntriesDelayCompletesOutOfOrder: with a delay on start=0 only, a later
// request for start=4 must finish first, as a real log under load can.
func TestEntriesDelayCompletesOutOfOrder(t *testing.T) {
	l := New(t, 8, Options{PageSize: 4, EntriesDelay: func(start uint64) time.Duration {
		if start == 0 {
			return 300 * time.Millisecond
		}
		return 0
	}})
	var mu sync.Mutex
	var order []string
	var wg sync.WaitGroup
	for _, start := range []string{"0", "4"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := l.srv.Client().Get(l.URL + "ct/v1/get-entries?start=" + start + "&end=7")
			if err != nil {
				t.Error(err)
				return
			}
			resp.Body.Close()
			mu.Lock()
			order = append(order, start)
			mu.Unlock()
		}()
		time.Sleep(20 * time.Millisecond) // start=0 is sent first
	}
	wg.Wait()
	if fmt.Sprint(order) != "[4 0]" {
		t.Fatalf("completion order %v, want [4 0]", order)
	}
}

func TestGetProofByHash(t *testing.T) {
	l := New(t, 13, Options{})
	sth := struct {
		Root string `json:"sha256_root_hash"`
	}{}
	_, body := get(t, l.URL+"ct/v1/get-sth")
	if err := json.Unmarshal(body, &sth); err != nil {
		t.Fatal(err)
	}
	root, _ := base64.StdEncoding.DecodeString(sth.Root)
	for _, idx := range []uint64{0, 6, 12} {
		lh := rfc6962.DefaultHasher.HashLeaf(l.Entries[idx].LeafInput)
		q := url.Values{"hash": {base64.StdEncoding.EncodeToString(lh)}, "tree_size": {"13"}}
		resp, body := get(t, l.URL+"ct/v1/get-proof-by-hash?"+q.Encode())
		if resp.StatusCode != 200 {
			t.Fatalf("leaf %d: status %d", idx, resp.StatusCode)
		}
		var p struct {
			LeafIndex uint64   `json:"leaf_index"`
			AuditPath []string `json:"audit_path"`
		}
		if err := json.Unmarshal(body, &p); err != nil {
			t.Fatal(err)
		}
		nodes := make([][]byte, len(p.AuditPath))
		for i, n := range p.AuditPath {
			nodes[i], _ = base64.StdEncoding.DecodeString(n)
		}
		if p.LeafIndex != idx {
			t.Fatalf("leaf_index %d, want %d", p.LeafIndex, idx)
		}
		if err := proof.VerifyInclusion(rfc6962.DefaultHasher, idx, 13, lh, nodes, root); err != nil {
			t.Fatalf("leaf %d: inclusion proof does not verify: %v", idx, err)
		}
	}
	lh := rfc6962.DefaultHasher.HashLeaf(l.Entries[9].LeafInput)
	q := url.Values{"hash": {base64.StdEncoding.EncodeToString(lh)}, "tree_size": {"5"}}
	if resp, _ := get(t, l.URL+"ct/v1/get-proof-by-hash?"+q.Encode()); resp.StatusCode != 404 {
		t.Fatalf("a leaf beyond tree_size must be 404, got %d", resp.StatusCode)
	}
}

// fatalRecorder stands in for testing.TB to observe Fatalf.
type fatalRecorder struct {
	testing.TB
	msg string
}

func (f *fatalRecorder) Fatalf(format string, args ...any) {
	f.msg = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

func TestForkOutsideLogFails(t *testing.T) {
	l := New(t, 4, Options{})
	rec := &fatalRecorder{TB: t}
	l.t = rec
	done := make(chan struct{})
	go func() {
		defer close(done)
		l.Fork(4)
	}()
	<-done
	if rec.msg == "" {
		t.Fatal("Fork(4) on a 4-entry log must fail the test")
	}
}

// withoutExtension re-encodes a TBSCertificate without the extension oid,
// keeping every other byte. It is the RFC 6962 §3.2 rule in its simplest form.
func withoutExtension(t *testing.T, tbs []byte, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(tbs, &seq); err != nil {
		t.Fatal(err)
	}
	var body []byte
	for rest := seq.Bytes; len(rest) > 0; {
		var el asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &el); err != nil {
			t.Fatal(err)
		}
		if el.Class != asn1.ClassContextSpecific || el.Tag != 3 {
			body = append(body, el.FullBytes...)
			continue
		}
		var exts asn1.RawValue
		if _, err := asn1.Unmarshal(el.Bytes, &exts); err != nil {
			t.Fatal(err)
		}
		var kept []byte
		for r := exts.Bytes; len(r) > 0; {
			var ext asn1.RawValue
			if r, err = asn1.Unmarshal(r, &ext); err != nil {
				t.Fatal(err)
			}
			var id asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(ext.Bytes, &id); err != nil {
				t.Fatal(err)
			}
			if !id.Equal(oid) {
				kept = append(kept, ext.FullBytes...)
			}
		}
		inner, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: kept})
		wrapped, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 3, IsCompound: true, Bytes: inner})
		body = append(body, wrapped...)
	}
	out, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
	return out
}

// TestPairTBSInvariant covers Plan 1 review minor 15: the generator must obey
// RFC 6962 §3.2 byte for byte, because the leaf decoder's precert checks are
// tested against it.
func TestPairTBSInvariant(t *testing.T) {
	g, err := NewGenerator()
	if err != nil {
		t.Fatal(err)
	}
	for name, viaSigner := range map[string]bool{"CA-issued": false, "signer-issued": true} {
		pre, fin, err := g.pair("inv.example.test", 5, viaSigner)
		if err != nil {
			t.Fatal(err)
		}
		pc, _ := x509.ParseCertificate(pre.CertDER)
		fc, _ := x509.ParseCertificate(fin.CertDER)
		if got := withoutExtension(t, fc.RawTBSCertificate, sctListOID); !bytes.Equal(got, pre.PrecertTBS) {
			t.Errorf("%s: final TBS without the SCT list must equal the log's TBS", name)
		}
		if pre.IssuerKeyHash != sha256.Sum256(g.ca.RawSubjectPublicKeyInfo) {
			t.Errorf("%s: issuer_key_hash must hash the final issuer's SPKI", name)
		}
		stripped := withoutExtension(t, pc.RawTBSCertificate, poisonOID)
		if viaSigner {
			if err := pc.CheckSignatureFrom(g.signer); err != nil {
				t.Errorf("%s: precert must be signed by the precert signer: %v", name, err)
			}
			if bytes.Equal(stripped, pre.PrecertTBS) {
				t.Errorf("%s: issuer and AKI must differ before the §3.2 rewrite", name)
			}
			continue
		}
		if !bytes.Equal(stripped, pre.PrecertTBS) {
			t.Errorf("%s: precert TBS without poison must equal the log's TBS", name)
		}
	}
	if err := g.signer.CheckSignatureFrom(g.ca); err != nil {
		t.Fatalf("signer must be certified by the CA: %v", err)
	}
	if len(g.signer.UnknownExtKeyUsage) != 1 || !g.signer.UnknownExtKeyUsage[0].Equal(precertSigningEKU) {
		t.Fatalf("signer EKU = %v, want the CT precert-signing EKU", g.signer.UnknownExtKeyUsage)
	}
}

func TestMalformedEntryIsServedAndHashed(t *testing.T) {
	g, err := NewGenerator()
	if err != nil {
		t.Fatal(err)
	}
	good, err := g.Entries(2)
	if err != nil {
		t.Fatal(err)
	}
	bad := MalformedEntry(7)
	l := NewWithEntries(t, append(good, bad), Options{})
	_, body := get(t, l.URL+"ct/v1/get-entries?start=2&end=2")
	var we wireEntries
	if err := json.Unmarshal(body, &we); err != nil || len(we.Entries) != 1 {
		t.Fatalf("entries: %v %s", err, body)
	}
	leaf, _ := base64.StdEncoding.DecodeString(we.Entries[0].LeafInput)
	if !bytes.Equal(leaf, bad.LeafInput) || leaf[0] != 1 {
		t.Fatal("the malformed leaf must be served byte for byte")
	}
	want := rfc6962.DefaultHasher.HashLeaf(bad.LeafInput)
	if got := l.honest.LeafHash(2); !bytes.Equal(got, want) {
		t.Fatal("the malformed leaf must be part of the Merkle tree")
	}
}
```

Run: `go test ./internal/ctlogtest/`
Expected: FAIL with `unknown field ServerErrorEvery in struct literal of type Options`.

- [ ] **Step 2: Implement the fault modes**

Replace `internal/ctlogtest/log.go`:

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
	"time"

	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
)

// Options configures page size and fault injection. Every "Every" counter
// fires on its Nth matching request (1 = every request, 0 = never).
type Options struct {
	PageSize           int  // max entries per get-entries response; default 32
	RateLimitEvery     int  // any endpoint answers 429 with Retry-After: 1
	NoRetryAfter       bool // 429 answers omit Retry-After
	ServerErrorEvery   int  // any endpoint answers 503 (no Retry-After)
	ShortReadEvery     int  // get-entries returns half of what it would have
	CorruptJSONEvery   int  // get-entries returns truncated JSON
	InvalidBase64Every int  // get-entries returns an invalid base64 leaf_input
	BadSTHSignature    bool
	AlterEntries       []uint64 // these indices are served with a modified leaf_input
	// EntriesDelay, if set, delays each get-entries response by the returned
	// duration before any lock is taken, so concurrent requests can complete
	// out of order. It receives the requested start index.
	EntriesDelay func(start uint64) time.Duration
}

// Log is a running fake log.
type Log struct {
	URL          string // base URL ending in "/"
	PublicKeyDER []byte // SPKI, as the log list publishes it
	LogID        [32]byte
	Entries      []Entry

	t    testing.TB
	key  *ecdsa.PrivateKey
	opts Options
	srv  *httptest.Server

	mu        sync.Mutex
	tree      *testonly.Tree // tree used for STHs and proofs
	honest    *testonly.Tree
	published uint64
	counts    map[string]int
	altered   map[uint64]bool
	byHash    map[[32]byte]uint64 // leaf hash → first index, for get-proof-by-hash
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
	l := &Log{PublicKeyDER: spki, LogID: sha256.Sum256(spki), Entries: entries, t: t, key: key, opts: opts,
		honest: testonly.New(rfc6962.DefaultHasher), published: uint64(len(entries)),
		counts: map[string]int{}, altered: map[uint64]bool{}, byHash: map[[32]byte]uint64{}}
	for i, e := range entries {
		l.honest.AppendData(e.LeafInput)
		var h [32]byte
		copy(h[:], rfc6962.DefaultHasher.HashLeaf(e.LeafInput))
		if _, dup := l.byHash[h]; !dup {
			l.byHash[h] = uint64(i)
		}
	}
	l.tree = l.honest
	for _, i := range opts.AlterEntries {
		l.altered[i] = true
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ct/v1/get-sth", l.getSTH)
	mux.HandleFunc("GET /ct/v1/get-sth-consistency", l.getConsistency)
	mux.HandleFunc("GET /ct/v1/get-entries", l.getEntries)
	mux.HandleFunc("GET /ct/v1/get-proof-by-hash", l.getProofByHash)
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
// a split view that consistency checks must detect. An index outside the log
// fails the test instead of silently forking nothing.
func (l *Log) Fork(index uint64) {
	if index >= uint64(len(l.Entries)) {
		l.t.Fatalf("ctlogtest: Fork(%d) is outside a log of %d entries", index, len(l.Entries))
	}
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
		if !l.opts.NoRetryAfter {
			w.Header().Set("Retry-After", "1")
		}
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return 0, false
	}
	if every(l.opts.ServerErrorEvery, l.counts["all"]) {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
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
	if l.opts.EntriesDelay != nil {
		if start, _, err := parseRange(r, "start", "end"); err == nil {
			select {
			case <-time.After(l.opts.EntriesDelay(start)):
			case <-r.Context().Done():
				return
			}
		}
	}
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

func (l *Log) getProofByHash(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.begin(w, "get-proof-by-hash"); !ok {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(r.URL.Query().Get("hash"))
	size, err2 := strconv.ParseUint(r.URL.Query().Get("tree_size"), 10, 64)
	if err != nil || err2 != nil || len(raw) != 32 || size == 0 || size > l.tree.Size() {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var h [32]byte
	copy(h[:], raw)
	idx, ok := l.byHash[h]
	if !ok || idx >= size {
		http.Error(w, "leaf not found", http.StatusNotFound)
		return
	}
	proof, err := l.tree.InclusionProof(idx, size)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	path := make([]string, len(proof))
	for i, p := range proof {
		path[i] = base64.StdEncoding.EncodeToString(p)
	}
	writeJSON(w, map[string]any{"leaf_index": idx, "audit_path": path})
}
```

Replace `internal/ctlogtest/entries.go`:

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
	// precertSigningEKU marks an RFC 6962 §3.1 Precertificate Signing Certificate.
	precertSigningEKU = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 4}
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

// Chain encodes a TLS vector<ASN.1Cert> with a 24-bit total length: the
// extra_data of an x509_entry.
func Chain(certs ...[]byte) []byte {
	var body []byte
	for _, c := range certs {
		body = appendU24(body, c)
	}
	return appendU24(nil, body)
}

// PrecertExtraData encodes the extra_data of a precert_entry: the
// precertificate followed by its chain.
func PrecertExtraData(precert []byte, chain ...[]byte) []byte {
	return append(appendU24(nil, precert), Chain(chain...)...)
}

// Generator issues certificates from a throwaway ECDSA CA, and optionally
// through a Precertificate Signing Certificate that the CA certified.
type Generator struct {
	caKey     *ecdsa.PrivateKey
	ca        *x509.Certificate
	signerKey *ecdsa.PrivateKey
	signer    *x509.Certificate
	serial    int64
	t0        time.Time
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
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	stmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "CTVault Test Precert Signer", Organization: []string{"CTVault Tests"}},
		NotBefore: t0.Add(-24 * time.Hour), NotAfter: t0.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{precertSigningEKU},
	}
	sder, err := x509.CreateCertificate(rand.Reader, stmpl, ca, &signerKey.PublicKey, key)
	if err != nil {
		return nil, err
	}
	signer, err := x509.ParseCertificate(sder)
	if err != nil {
		return nil, err
	}
	return &Generator{caKey: key, ca: ca, signerKey: signerKey, signer: signer, serial: 2, t0: t0}, nil
}

// CADER returns the CA certificate.
func (g *Generator) CADER() []byte { return g.ca.Raw }

// SignerDER returns the Precertificate Signing Certificate.
func (g *Generator) SignerDER() []byte { return g.signer.Raw }

// Pair issues one certificate as a precert entry and its final x509 entry,
// exactly as RFC 6962 §3.1 describes: the precert TBS with the poison
// extension removed equals the final cert TBS without the SCT list.
func (g *Generator) Pair(name string, ts uint64) (pre, final Entry, err error) {
	return g.pair(name, ts, false)
}

// PairViaSigner is Pair with the precertificate issued by the Precertificate
// Signing Certificate (RFC 6962 §3.1). The log's TBS then carries the CA's
// issuer name and authority key ID, and the precert chain starts with the
// signer.
func (g *Generator) PairViaSigner(name string, ts uint64) (pre, final Entry, err error) {
	return g.pair(name, ts, true)
}

func (g *Generator) pair(name string, ts uint64, viaSigner bool) (pre, final Entry, err error) {
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
	issueBy := func(parent *x509.Certificate, parentKey *ecdsa.PrivateKey, extra ...pkix.Extension) ([]byte, error) {
		t := tmpl
		t.ExtraExtensions = extra
		return x509.CreateCertificate(rand.Reader, &t, parent, &leafKey.PublicKey, parentKey)
	}
	issue := func(extra ...pkix.Extension) ([]byte, error) { return issueBy(g.ca, g.caKey, extra...) }
	plainDER, err := issue()
	if err != nil {
		return pre, final, err
	}
	plain, err := x509.ParseCertificate(plainDER)
	if err != nil {
		return pre, final, err
	}
	preParent, preKey, preChain := g.ca, g.caKey, [][]byte{g.ca.Raw}
	if viaSigner {
		preParent, preKey, preChain = g.signer, g.signerKey, [][]byte{g.signer.Raw, g.ca.Raw}
	}
	preDER, err := issueBy(preParent, preKey, pkix.Extension{Id: poisonOID, Critical: true, Value: []byte{0x05, 0x00}})
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
	pre.ExtraData = PrecertExtraData(preDER, preChain...)
	final = Entry{Type: X509Entry, Timestamp: ts + 1000, CertDER: finDER}
	final.LeafInput = MerkleTreeLeaf(ts+1000, X509Entry, finDER, [32]byte{})
	final.ExtraData = Chain(g.ca.Raw)
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

// MalformedEntry returns an entry whose bytes are valid base64 but whose
// MerkleTreeLeaf cannot be interpreted (version 1 instead of v1 = 0). It is a
// semantic leaf error (spec §5.4): it belongs in the Merkle tree like any
// other leaf, so a log built with it still verifies.
func MalformedEntry(ts uint64) Entry {
	leaf := MerkleTreeLeaf(ts, X509Entry, []byte{0x30, 0x00}, [32]byte{})
	leaf[0] = 1
	return Entry{Type: X509Entry, Timestamp: ts, LeafInput: leaf, ExtraData: Chain()}
}
```

- [ ] **Step 3: Run the tests to verify they pass**

Run: `go test -race -count=1 ./internal/ctlogtest/ ./internal/logsource/... -v`
Expected: PASS:
- `TestServerErrorEvery`, `TestNoRetryAfter`, `TestEntriesDelayCompletesOutOfOrder`, `TestGetProofByHash`
- `TestForkOutsideLogFails`, `TestPairTBSInvariant`, `TestMalformedEntryIsServedAndHashed`
- The Plan 1 tests, including the `rfc6962` client's use of `Fork(5)`

- [ ] **Step 4: Gate and commit**

Run the four gate commands. All must pass.

```bash
git add internal/ctlogtest
git commit -m "test: fake log 5xx, latency, proof-by-hash, precert signer, malformed leaf; Fork bound; TBS invariant (minor 15)"
```

---

### Task A4: Leaf decoding

Implements spec §5.4, amendment A1 §4 (leaf decoding, precertificates) and spec §13.3 (fuzzing).

**Files:**
- Create: `internal/leaf/leaf.go`, `internal/leaf/cert.go`, `internal/leaf/precert.go`
- Create tests: `internal/leaf/leaf_test.go`, `internal/leaf/precert_test.go`, `internal/leaf/real_test.go`, `internal/leaf/fuzz_test.go`
- Create fixture: `internal/testdata/argon2027h1_entries_380000000.json`
- Modify: `internal/testdata/README.md`, `internal/merkle/fixtures_test.go`

**Interfaces:**
- Consumes:
  - `merkle.LeafHash(leafInput []byte) [32]byte`
  - From Task A3: `ctlogtest.Chain`, `PrecertExtraData`, `PairViaSigner`, `MalformedEntry`
- Produces (`leaf`):
  - Types:
    - `type Type uint8` (`TypeUnknown`, `TypeX509`, `TypePrecert`; `String()` gives `"unknown"`, `"x509"`, `"precert"`)
    - `type Code string`, the 13 constants named in Global Constraints, and `OK = ""`
    - `var Codes []Code`
    - `func (Code) LeafStructure() bool`
  - The entry:
    - `type Entry struct{ LeafHash [32]byte; Type Type; Timestamp uint64; CertDER, PrecertTBS []byte; IssuerKeyHash [32]byte; HasIssuerKeyHash bool; Chain [][]byte; IssuanceDigest [32]byte; HasIssuanceDigest bool; Code Code }`
    - `func (*Entry) IssuanceKey() ([16]byte, bool)`
  - `func Decode(leafInput, extraData []byte) Entry`

- [ ] **Step 1: Add the dependency and the real fixture**

```bash
go get golang.org/x/crypto@v0.57.0
curl -sS -o internal/testdata/argon2027h1_entries_380000000.json \
  "https://ct.googleapis.com/logs/us1/argon2027h1/ct/v1/get-entries?start=380000000&end=380000031"
sha256sum internal/testdata/argon2027h1_entries_380000000.json
```

Expected: `708399c3400262347d1dd0831e44a8575444073d7ef72df0d4f03c1abb2cc5f4`.
- If the log answers 429, wait a minute and repeat the `curl`.
- If the hash differs, stop and report it. Log entries are immutable, and a byte-identical re-fetch was verified on 2026-10-04.

Replace `internal/testdata/README.md`:

```markdown
# Test fixtures (immutable)

Real Certificate Transparency data captured on 2026-10-04. Tests use these
files instead of the live log, so results never depend on the network or on
the log's current state.

| File | Source | Content |
|---|---|---|
| `log_list_google.json` | `https://www.gstatic.com/ct/log_list/v3/log_list.json` v93.3 (2026-10-03T13:35:24Z) | Google operator only, trimmed to the 2026h2/2027h1 RFC 6962 logs and 2027h1 tiled logs |
| `log_list_v93.3_full.json` | same URL and version, untrimmed | every operator, RFC 6962 and tiled log (used to prove log names are unique) |
| `argon2027h1_sth1.json` | `https://ct.googleapis.com/logs/us1/argon2027h1/ct/v1/get-sth` | signed tree head, tree size 384,065,451 (06:25:33Z) |
| `argon2027h1_sth2.json` | same endpoint, a few minutes later | signed tree head, tree size 384,071,894 |
| `argon2027h1_consistency.json` | `get-sth-consistency?first=384065451&second=384071894` | 23-node consistency proof between the two heads |
| `argon2027h1_entries_380000000.json` | `get-entries?start=380000000&end=380000031` (05:38Z), saved exactly as served | 32 real entries: 11 x509, 21 precert |

Rules:

- Never edit or refresh these files. `TestFixturesAreUnchanged` in
  `internal/merkle` checks the SHA-256 of each one.
- A new capture goes in a new file with a new name, and its hash is added to
  that test in the same commit.
- `.gitattributes` marks this directory `-text`, so line-ending conversion can
  never alter the bytes.
```

Replace `internal/merkle/fixtures_test.go` (adds the new hash):

```go
package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

// The real fixtures in internal/testdata were captured from Chrome's log list
// and argon2027h1 on 2026-10-04. They are immutable: tests must never depend
// on the live log, whose answers change every few seconds. This guard fails if
// any fixture's bytes change; a deliberate new capture goes in a new file with
// its hash added here in the same commit (see internal/testdata/README.md).
var fixtureSHA256 = map[string]string{
	"log_list_google.json":               "852484a68c18c2eed06211af22148bbb6ca3cb6cfed142dccc31839943e40d19",
	"log_list_v93.3_full.json":           "d23ab4cd867239b3ff227d52eb9d60210fbd5eb0c66ab2b6d2bded8e6852d406",
	"argon2027h1_sth1.json":              "32b707ce8a1287e2d4c4b5fe51f531521d27c23fc578b8c9c4c67c8421cdbf65",
	"argon2027h1_sth2.json":              "6d8d1a6c4ead1dd4053bf0b35c8a8ee05240f97af58982147ef79500827c3db0",
	"argon2027h1_consistency.json":       "182aae03ee72d97002c78250f8830e65bfae66e059d5effc1c26e386b6c0740a",
	"argon2027h1_entries_380000000.json": "708399c3400262347d1dd0831e44a8575444073d7ef72df0d4f03c1abb2cc5f4",
}

func TestFixturesAreUnchanged(t *testing.T) {
	for name, want := range fixtureSHA256 {
		b, err := os.ReadFile("../testdata/" + name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s changed: sha256 %s, want %s; fixtures are immutable (internal/testdata/README.md)", name, got, want)
		}
	}
}
```

- [ ] **Step 2: Write the failing tests**

Create `internal/leaf/leaf_test.go`:

```go
package leaf_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/merkle"
)

func generator(t *testing.T) *ctlogtest.Generator {
	t.Helper()
	g, err := ctlogtest.NewGenerator()
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func pair(t *testing.T, g *ctlogtest.Generator, viaSigner bool) (pre, fin ctlogtest.Entry) {
	t.Helper()
	var err error
	if viaSigner {
		pre, fin, err = g.PairViaSigner("signer.example.test", 1790000000000)
	} else {
		pre, fin, err = g.Pair("a.example.test", 1790000000000)
	}
	if err != nil {
		t.Fatal(err)
	}
	return pre, fin
}

func TestCodesAreStable(t *testing.T) {
	want := []string{"leaf_bad_version", "leaf_bad_leaf_type", "leaf_unknown_entry_type", "leaf_truncated",
		"leaf_trailing_bytes", "extra_truncated", "extra_trailing_bytes", "chain_cert_empty",
		"chain_issuer_missing", "chain_issuer_ambiguous", "issuer_key_hash_mismatch",
		"precert_tbs_mismatch", "issuance_key_unavailable"}
	if len(leaf.Codes) != len(want) {
		t.Fatalf("%d codes, want %d", len(leaf.Codes), len(want))
	}
	for i, c := range leaf.Codes {
		if string(c) != want[i] {
			t.Errorf("code %d = %q, want %q (codes are stored in Parquet and must never change)", i, c, want[i])
		}
	}
	if leaf.TypeX509.String() != "x509" || leaf.TypePrecert.String() != "precert" || leaf.TypeUnknown.String() != "unknown" {
		t.Fatal("entry_type strings must be x509, precert and unknown")
	}
}

func TestDecodeGeneratedPair(t *testing.T) {
	g := generator(t)
	for name, viaSigner := range map[string]bool{"CA-issued": false, "via precert signer": true} {
		pre, fin := pair(t, g, viaSigner)
		p := leaf.Decode(pre.LeafInput, pre.ExtraData)
		f := leaf.Decode(fin.LeafInput, fin.ExtraData)
		if p.Code != leaf.OK || f.Code != leaf.OK {
			t.Fatalf("%s: codes %q / %q, want none", name, p.Code, f.Code)
		}
		if p.Type != leaf.TypePrecert || f.Type != leaf.TypeX509 || p.Timestamp != pre.Timestamp || f.Timestamp != fin.Timestamp {
			t.Fatalf("%s: types or timestamps wrong: %+v %+v", name, p, f)
		}
		if !bytes.Equal(p.CertDER, pre.CertDER) || !bytes.Equal(p.PrecertTBS, pre.PrecertTBS) || !bytes.Equal(f.CertDER, fin.CertDER) {
			t.Fatalf("%s: certificate bytes must be exactly as logged", name)
		}
		if !p.HasIssuerKeyHash || p.IssuerKeyHash != pre.IssuerKeyHash || f.HasIssuerKeyHash {
			t.Fatalf("%s: issuer_key_hash is set for precerts only", name)
		}
		if p.LeafHash != merkle.LeafHash(pre.LeafInput) || f.LeafHash != merkle.LeafHash(fin.LeafInput) {
			t.Fatalf("%s: leaf hash must be RFC 6962 over the exact bytes", name)
		}
		pk, ok1 := p.IssuanceKey()
		fk, ok2 := f.IssuanceKey()
		if !ok1 || !ok2 || pk != fk || p.IssuanceDigest != f.IssuanceDigest {
			t.Fatalf("%s: precert and final cert must share the issuance digest", name)
		}
		if p.IssuanceDigest != sha256.Sum256(pre.PrecertTBS) {
			t.Fatalf("%s: a precert's digest is SHA-256 of the log's TBS", name)
		}
		if !bytes.Equal(f.Chain[0], g.CADER()) {
			t.Fatalf("%s: chain must be decoded in order", name)
		}
	}
}

// leafBytes builds a MerkleTreeLeaf by hand so each structural fault can be
// placed exactly.
func leafBytes(version, leafType byte, entryType uint16, signed []byte, exts []byte) []byte {
	b := []byte{version, leafType}
	b = binary.BigEndian.AppendUint64(b, 1790000000000)
	b = binary.BigEndian.AppendUint16(b, entryType)
	if entryType == 1 {
		b = append(b, make([]byte, 32)...)
	}
	b = append(b, byte(len(signed)>>16), byte(len(signed)>>8), byte(len(signed)))
	b = append(b, signed...)
	return append(b, exts...)
}

func TestLeafStructureCodes(t *testing.T) {
	cert := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	noExt := []byte{0, 0}
	good := leafBytes(0, 0, 0, cert, noExt)
	for name, tc := range map[string]struct {
		leaf   []byte
		want   leaf.Code
		wantTS bool
	}{
		"empty":                  {nil, leaf.Truncated, false},
		"version 1":              {leafBytes(1, 0, 0, cert, noExt), leaf.BadVersion, false},
		"leaf type 1":            {leafBytes(0, 1, 0, cert, noExt), leaf.BadLeafType, false},
		"entry type 2":           {leafBytes(0, 0, 2, cert, noExt), leaf.UnknownEntryType, true},
		"cert cut short":         {good[:14], leaf.Truncated, true},
		"no extensions field":    {good[:len(good)-2], leaf.Truncated, true},
		"trailing byte":          {append(append([]byte(nil), good...), 0), leaf.TrailingBytes, true},
		"zero-length cert":       {leafBytes(0, 0, 0, nil, noExt), leaf.Truncated, true},
		"precert hash cut short": {leafBytes(0, 0, 1, cert, noExt)[:20], leaf.Truncated, true},
		"malformed from fakelog": {ctlogtest.MalformedEntry(1).LeafInput, leaf.BadVersion, false},
	} {
		e := leaf.Decode(tc.leaf, ctlogtest.Chain())
		if e.Code != tc.want || !e.Code.LeafStructure() {
			t.Errorf("%s: code %q, want %q", name, e.Code, tc.want)
		}
		if e.CertDER != nil || e.PrecertTBS != nil || e.Chain != nil || e.HasIssuanceDigest {
			t.Errorf("%s: no field may be kept from an uninterpretable leaf: %+v", name, e)
		}
		if e.LeafHash != merkle.LeafHash(tc.leaf) {
			t.Errorf("%s: the leaf hash is always computed from the exact bytes", name)
		}
		if (e.Timestamp != 0) != tc.wantTS {
			t.Errorf("%s: timestamp %d; it is kept only once version and leaf type are known", name, e.Timestamp)
		}
	}
	if e := leaf.Decode(good, ctlogtest.Chain()); e.Code.LeafStructure() {
		t.Fatalf("control: a well-formed leaf decodes, got %q", e.Code)
	}
}

func TestExtraDataCodes(t *testing.T) {
	g := generator(t)
	pre, fin := pair(t, g, false)
	trunc := func(b []byte) []byte { return b[:len(b)-1] }
	trailing := func(b []byte) []byte { return append(append([]byte(nil), b...), 0) }
	for name, tc := range map[string]struct {
		entry    ctlogtest.Entry
		extra    []byte
		want     leaf.Code
		keepCert bool // x509 certs come from leaf_input, so they survive
	}{
		"x509 chain cut short":    {fin, trunc(fin.ExtraData), leaf.ExtraTruncated, true},
		"x509 trailing byte":      {fin, trailing(fin.ExtraData), leaf.ExtraTrailingBytes, true},
		"x509 empty chain cert":   {fin, ctlogtest.Chain(g.CADER(), nil), leaf.ChainCertEmpty, true},
		"precert cut short":       {pre, trunc(pre.ExtraData), leaf.ExtraTruncated, false},
		"precert trailing byte":   {pre, trailing(pre.ExtraData), leaf.ExtraTrailingBytes, false},
		"precert empty precert":   {pre, ctlogtest.PrecertExtraData(nil, g.CADER()), leaf.ChainCertEmpty, false},
		"precert no chain vector": {pre, pre.ExtraData[:3+len(pre.CertDER)], leaf.ExtraTruncated, false},
	} {
		e := leaf.Decode(tc.entry.LeafInput, tc.extra)
		if e.Code != tc.want || e.Code.LeafStructure() {
			t.Errorf("%s: code %q, want %q", name, e.Code, tc.want)
		}
		if (e.CertDER != nil) != tc.keepCert || e.Chain != nil {
			t.Errorf("%s: cert kept %v (want %v), chain %v (want nil)", name, e.CertDER != nil, tc.keepCert, e.Chain)
		}
		if !e.HasIssuanceDigest {
			t.Errorf("%s: the issuance digest comes from leaf_input and survives extra_data faults", name)
		}
	}
	if e := leaf.Decode(fin.LeafInput, ctlogtest.Chain()); e.Code != leaf.OK || e.Chain == nil || len(e.Chain) != 0 {
		t.Fatalf("an empty chain is valid for x509 entries: %q %v", e.Code, e.Chain)
	}
}
```

Create `internal/leaf/precert_test.go`:

```go
package leaf_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/leaf"
)

// impostor returns a self-signed certificate with the given subject, a fresh
// key and no subject key ID: a chain certificate that matches by name only.
func impostor(t *testing.T, rawSubject []byte) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(99), RawSubject: rawSubject,
		NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<32, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestPrecertIssuerByRelationship(t *testing.T) {
	g := generator(t)
	pre, _ := pair(t, g, false)
	sPre, _ := pair(t, g, true)
	ca, _ := x509.ParseCertificate(g.CADER())
	other := generator(t) // an unrelated CA with the same name but another key ID
	for name, tc := range map[string]struct {
		entry ctlogtest.Entry
		chain [][]byte
		want  leaf.Code
	}{
		"issuer after an unrelated cert": {pre, [][]byte{other.CADER(), g.CADER()}, leaf.OK},
		"issuer listed twice":            {pre, [][]byte{g.CADER(), g.CADER()}, leaf.OK},
		"empty chain":                    {pre, nil, leaf.ChainIssuerMissing},
		"only a same-name other CA":      {pre, [][]byte{other.CADER()}, leaf.ChainIssuerMissing},
		"name-only impostor":             {pre, [][]byte{g.CADER(), impostor(t, ca.RawSubject)}, leaf.ChainIssuerAmbiguous},
		"signer, chain reversed":         {sPre, [][]byte{g.CADER(), g.SignerDER()}, leaf.OK},
		"signer without its CA":          {sPre, [][]byte{g.SignerDER()}, leaf.ChainIssuerMissing},
		"signer only CA":                 {sPre, [][]byte{g.CADER()}, leaf.ChainIssuerMissing},
	} {
		e := leaf.Decode(tc.entry.LeafInput, ctlogtest.PrecertExtraData(tc.entry.CertDER, tc.chain...))
		if e.Code != tc.want {
			t.Errorf("%s: code %q, want %q", name, e.Code, tc.want)
		}
		if e.CertDER == nil || !e.HasIssuanceDigest {
			t.Errorf("%s: issuer problems keep the precertificate and the issuance key", name)
		}
	}
}

func TestPrecertCrossChecks(t *testing.T) {
	g := generator(t)
	pre, _ := pair(t, g, false)
	pre2, _ := pair(t, g, false)
	sPre, _ := pair(t, g, true)

	wrongIKH := sha256.Sum256([]byte("not the issuer's key"))
	e := leaf.Decode(ctlogtest.MerkleTreeLeaf(pre.Timestamp, ctlogtest.PrecertEntry, pre.PrecertTBS, wrongIKH), pre.ExtraData)
	if e.Code != leaf.IssuerKeyHashMismatch || e.IssuerKeyHash != wrongIKH {
		t.Fatalf("wrong issuer_key_hash: code %q; the logged value must be kept", e.Code)
	}

	// The log's TBS belongs to another issuance than the precert in extra_data.
	e = leaf.Decode(ctlogtest.MerkleTreeLeaf(pre.Timestamp, ctlogtest.PrecertEntry, pre2.PrecertTBS, pre.IssuerKeyHash), pre.ExtraData)
	if e.Code != leaf.PrecertTBSMismatch {
		t.Fatalf("mismatched TBS: code %q", e.Code)
	}
	if e.IssuanceDigest != sha256.Sum256(pre2.PrecertTBS) {
		t.Fatal("the log's TBS is authoritative: the issuance digest must hash it, not a reconstruction")
	}

	// Via a signer, the log's TBS has the CA's name; a TBS that kept the
	// signer's name and key ID (no §3.2 rewrite) must not match.
	sc, _ := x509.ParseCertificate(sPre.CertDER)
	if e := leaf.Decode(ctlogtest.MerkleTreeLeaf(sPre.Timestamp, ctlogtest.PrecertEntry, sc.RawTBSCertificate, sPre.IssuerKeyHash), sPre.ExtraData); e.Code != leaf.PrecertTBSMismatch {
		t.Fatalf("un-rewritten signer TBS: code %q", e.Code)
	}

	garbage := ctlogtest.PrecertExtraData([]byte{0x30, 0x00}, g.CADER())
	if e := leaf.Decode(pre.LeafInput, garbage); e.Code != leaf.PrecertTBSMismatch || e.CertDER == nil {
		t.Fatalf("an unparseable precertificate is kept as served and flagged: %q", e.Code)
	}
}

func TestX509IssuanceDigest(t *testing.T) {
	g := generator(t)
	ca, _ := x509.ParseCertificate(g.CADER())
	plain := ctlogtest.MerkleTreeLeaf(1, ctlogtest.X509Entry, g.CADER(), [32]byte{})
	e := leaf.Decode(plain, ctlogtest.Chain())
	if e.Code != leaf.OK || e.IssuanceDigest != sha256.Sum256(ca.RawTBSCertificate) {
		t.Fatalf("a certificate without an SCT list hashes its TBS unchanged: %q", e.Code)
	}
	bad := ctlogtest.MerkleTreeLeaf(1, ctlogtest.X509Entry, []byte{0x30, 0x00}, [32]byte{})
	e = leaf.Decode(bad, ctlogtest.Chain())
	if e.Code != leaf.IssuanceKeyUnavailable || e.CertDER == nil || e.HasIssuanceDigest {
		t.Fatalf("unparseable final cert: code %q, cert kept %v, digest %v", e.Code, e.CertDER != nil, e.HasIssuanceDigest)
	}
	if _, ok := e.IssuanceKey(); ok {
		t.Fatal("no issuance key without a digest")
	}
}
```

Create `internal/leaf/real_test.go`:

```go
package leaf_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/4rji/ctvault/internal/leaf"
)

// TestRealArgonPage decodes 32 real argon2027h1 entries (indexes 380,000,000
// to 380,000,031, captured 2026-10-04). Every precert must pass issuer
// identification and both RFC 6962 cross-checks.
func TestRealArgonPage(t *testing.T) {
	b, err := os.ReadFile("../testdata/argon2027h1_entries_380000000.json")
	if err != nil {
		t.Fatal(err)
	}
	var page struct {
		Entries []struct {
			LeafInput string `json:"leaf_input"`
			ExtraData string `json:"extra_data"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(b, &page); err != nil {
		t.Fatal(err)
	}
	counts := map[leaf.Type]int{}
	for i, w := range page.Entries {
		li, err1 := base64.StdEncoding.DecodeString(w.LeafInput)
		ed, err2 := base64.StdEncoding.DecodeString(w.ExtraData)
		if err1 != nil || err2 != nil {
			t.Fatalf("entry %d: bad base64", i)
		}
		e := leaf.Decode(li, ed)
		if e.Code != leaf.OK {
			t.Errorf("entry %d (%s): code %q", 380000000+i, e.Type, e.Code)
		}
		if !e.HasIssuanceDigest || len(e.Chain) == 0 || e.CertDER == nil {
			t.Errorf("entry %d: missing digest, chain or certificate", 380000000+i)
		}
		counts[e.Type]++
	}
	if len(page.Entries) != 32 || counts[leaf.TypeX509] != 11 || counts[leaf.TypePrecert] != 21 {
		t.Fatalf("fixture has %d entries: %v; want 32 = 11 x509 + 21 precert", len(page.Entries), counts)
	}
}
```

Create `internal/leaf/fuzz_test.go`:

```go
package leaf_test

import (
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/merkle"
)

// FuzzDecode: the decoder must never panic (spec §13.3), and its invariants
// hold for any input.
func FuzzDecode(f *testing.F) {
	g, err := ctlogtest.NewGenerator()
	if err != nil {
		f.Fatal(err)
	}
	pre, fin, err := g.PairViaSigner("fuzz.example.test", 1)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(pre.LeafInput, pre.ExtraData)
	f.Add(fin.LeafInput, fin.ExtraData)
	f.Add(ctlogtest.MalformedEntry(1).LeafInput, []byte{})
	f.Fuzz(func(t *testing.T, li, ed []byte) {
		e := leaf.Decode(li, ed)
		if e.LeafHash != merkle.LeafHash(li) {
			t.Fatal("leaf hash must always be computed")
		}
		if e.Code.LeafStructure() && (e.CertDER != nil || e.Chain != nil) {
			t.Fatal("nothing may be kept from an uninterpretable leaf")
		}
		if e.Code == leaf.OK && e.Type == leaf.TypeUnknown {
			t.Fatal("an unknown entry type always carries a code")
		}
	})
}
```

Run: `go test ./internal/leaf/`
Expected: FAIL with `no non-test Go files in .../internal/leaf`.

- [ ] **Step 3: Implement the decoder**

Create `internal/leaf/leaf.go`:

```go
// Package leaf decodes RFC 6962 log entries: the MerkleTreeLeaf in leaf_input
// and the chain in extra_data (spec §5.4, amendment A1 §4). It never guesses:
// a field that cannot be decoded safely stays empty and the entry carries a
// stable error code. The leaf hash is always computed from the exact bytes.
package leaf

import (
	"crypto/sha256"

	"golang.org/x/crypto/cryptobyte"

	"github.com/4rji/ctvault/internal/merkle"
)

// Type is the RFC 6962 LogEntryType as CTVault records it.
type Type uint8

const (
	TypeUnknown Type = iota
	TypeX509
	TypePrecert
)

// String returns the entries.entry_type value: "x509", "precert" or "unknown".
func (t Type) String() string {
	switch t {
	case TypeX509:
		return "x509"
	case TypePrecert:
		return "precert"
	}
	return "unknown"
}

// Code is a stable error code stored in entries.leaf_error. The empty code
// means the entry decoded and every check passed.
type Code string

const (
	OK Code = ""

	// Leaf structure: leaf_input cannot be interpreted; no certificate is kept.
	BadVersion       Code = "leaf_bad_version"
	BadLeafType      Code = "leaf_bad_leaf_type"
	UnknownEntryType Code = "leaf_unknown_entry_type"
	Truncated        Code = "leaf_truncated"
	TrailingBytes    Code = "leaf_trailing_bytes"

	// extra_data structure.
	ExtraTruncated     Code = "extra_truncated"
	ExtraTrailingBytes Code = "extra_trailing_bytes"
	ChainCertEmpty     Code = "chain_cert_empty"

	// Issuer identification for precertificates.
	ChainIssuerMissing   Code = "chain_issuer_missing"
	ChainIssuerAmbiguous Code = "chain_issuer_ambiguous"

	// Precertificate cross-checks.
	IssuerKeyHashMismatch  Code = "issuer_key_hash_mismatch"
	PrecertTBSMismatch     Code = "precert_tbs_mismatch"
	IssuanceKeyUnavailable Code = "issuance_key_unavailable"
)

// Codes lists every code in a fixed order, for docs and explain-error.
var Codes = []Code{BadVersion, BadLeafType, UnknownEntryType, Truncated, TrailingBytes,
	ExtraTruncated, ExtraTrailingBytes, ChainCertEmpty, ChainIssuerMissing, ChainIssuerAmbiguous,
	IssuerKeyHashMismatch, PrecertTBSMismatch, IssuanceKeyUnavailable}

// LeafStructure reports whether c means leaf_input itself could not be
// interpreted. Such entries have no certificate (spec §5.4: null cert_id).
func (c Code) LeafStructure() bool {
	switch c {
	case BadVersion, BadLeafType, UnknownEntryType, Truncated, TrailingBytes:
		return true
	}
	return false
}

// Entry is one decoded log entry. Byte slices alias the inputs.
type Entry struct {
	LeafHash  [32]byte // RFC 6962 SHA-256(0x00 || leaf_input), always set
	Type      Type
	Timestamp uint64 // ms; 0 when the leaf version or leaf type is unknown

	// CertDER is the x509 entry's certificate or the precert entry's
	// precertificate (from extra_data). Nil when it cannot be decoded safely.
	CertDER []byte
	// PrecertTBS is the log's TBSCertificate from leaf_input, exactly as
	// logged. It is authoritative; nothing reconstructed ever replaces it.
	PrecertTBS []byte
	// IssuerKeyHash is the precert leaf's issuer_key_hash, as logged.
	IssuerKeyHash    [32]byte
	HasIssuerKeyHash bool
	// Chain holds the chain certificates in extra_data order. Nil when the
	// chain cannot be decoded.
	Chain [][]byte
	// IssuanceDigest is SHA-256 of the precert's log TBS, or of the final
	// certificate's TBS without the SCT-list extension. Equal digests link a
	// precert to its final certificate.
	IssuanceDigest    [32]byte
	HasIssuanceDigest bool

	Code Code // the first problem found, or OK
}

// IssuanceKey is the 16-byte entries.issuance_key: the digest's first half.
func (e *Entry) IssuanceKey() (k [16]byte, ok bool) {
	if !e.HasIssuanceDigest {
		return k, false
	}
	copy(k[:], e.IssuanceDigest[:16])
	return k, true
}

func (e *Entry) fail(c Code) {
	if e.Code == OK {
		e.Code = c
	}
}

// Decode interprets one entry exactly as served. It never fails: problems are
// reported in Entry.Code.
func Decode(leafInput, extraData []byte) Entry {
	e := Entry{LeafHash: merkle.LeafHash(leafInput)}
	if !e.decodeLeaf(leafInput) {
		return e
	}
	switch e.Type {
	case TypeX509:
		e.decodeX509Extra(extraData)
		e.x509IssuanceDigest()
	case TypePrecert:
		e.IssuanceDigest, e.HasIssuanceDigest = sha256.Sum256(e.PrecertTBS), true
		if e.decodePrecertExtra(extraData) {
			e.checkPrecert()
		}
	}
	return e
}

// decodeLeaf parses the MerkleTreeLeaf (RFC 6962 §3.4). It reports whether
// the leaf is fully usable.
func (e *Entry) decodeLeaf(b []byte) bool {
	s := cryptobyte.String(b)
	var version, leafType uint8
	if !s.ReadUint8(&version) {
		e.fail(Truncated)
		return false
	}
	if version != 0 {
		e.fail(BadVersion)
		return false
	}
	if !s.ReadUint8(&leafType) {
		e.fail(Truncated)
		return false
	}
	if leafType != 0 {
		e.fail(BadLeafType)
		return false
	}
	var ts uint64
	var entryType uint16
	if !s.ReadUint64(&ts) || !s.ReadUint16(&entryType) {
		e.fail(Truncated)
		return false
	}
	e.Timestamp = ts
	var signed []byte
	switch entryType {
	case 0:
		e.Type = TypeX509
		var cert cryptobyte.String
		if !s.ReadUint24LengthPrefixed(&cert) || len(cert) == 0 {
			e.fail(Truncated)
			return false
		}
		signed = cert
	case 1:
		e.Type = TypePrecert
		var ikh, tbs cryptobyte.String
		if !s.ReadBytes((*[]byte)(&ikh), 32) || !s.ReadUint24LengthPrefixed(&tbs) || len(tbs) == 0 {
			e.fail(Truncated)
			return false
		}
		copy(e.IssuerKeyHash[:], ikh)
		e.HasIssuerKeyHash = true
		signed = tbs
	default:
		e.fail(UnknownEntryType)
		return false
	}
	var exts cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&exts) {
		e.fail(Truncated)
		return false
	}
	if !s.Empty() {
		e.fail(TrailingBytes)
		return false
	}
	if e.Type == TypeX509 {
		e.CertDER = signed
	} else {
		e.PrecertTBS = signed
	}
	return true
}

// readChain reads a TLS vector<ASN.1Cert> with a 24-bit total length.
func readChain(s *cryptobyte.String) ([][]byte, Code) {
	var list cryptobyte.String
	if !s.ReadUint24LengthPrefixed(&list) {
		return nil, ExtraTruncated
	}
	var chain [][]byte
	for !list.Empty() {
		var c cryptobyte.String
		if !list.ReadUint24LengthPrefixed(&c) {
			return nil, ExtraTruncated
		}
		if len(c) == 0 {
			return nil, ChainCertEmpty
		}
		chain = append(chain, c)
	}
	if chain == nil {
		chain = [][]byte{}
	}
	return chain, OK
}

func (e *Entry) decodeX509Extra(b []byte) {
	s := cryptobyte.String(b)
	chain, code := readChain(&s)
	if code != OK {
		e.fail(code)
		return
	}
	if !s.Empty() {
		e.fail(ExtraTrailingBytes)
		return
	}
	e.Chain = chain
}

// decodePrecertExtra parses a PrecertChainEntry and reports whether the
// precertificate and its chain are usable for the cross-checks.
func (e *Entry) decodePrecertExtra(b []byte) bool {
	s := cryptobyte.String(b)
	var pre cryptobyte.String
	if !s.ReadUint24LengthPrefixed(&pre) {
		e.fail(ExtraTruncated)
		return false
	}
	if len(pre) == 0 {
		e.fail(ChainCertEmpty)
		return false
	}
	chain, code := readChain(&s)
	if code != OK {
		e.fail(code)
		return false
	}
	if !s.Empty() {
		e.fail(ExtraTrailingBytes)
		return false
	}
	e.CertDER, e.Chain = pre, chain
	return true
}

// x509IssuanceDigest hashes the final certificate's TBS without the SCT list.
func (e *Entry) x509IssuanceDigest() {
	c, err := parseCert(e.CertDER)
	if err != nil {
		e.fail(IssuanceKeyUnavailable)
		return
	}
	tbs, err := c.rebuildTBS(rewrite{drop: oidSCTList})
	if err != nil {
		e.fail(IssuanceKeyUnavailable)
		return
	}
	e.IssuanceDigest, e.HasIssuanceDigest = sha256.Sum256(tbs), true
}
```

Create `internal/leaf/cert.go`. CTVault parses only the raw pieces the checks need. Note that critical extensions must be read with `PeekASN1Tag` and then `ReadASN1Boolean`: cryptobyte's `ReadOptionalASN1Boolean` is for explicitly tagged booleans and rejects every real critical extension.

```go
package leaf

import (
	"bytes"
	"encoding/asn1"
	"errors"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidPoison         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	oidSCTList        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	oidPrecertSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 4}
	oidSKI            = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidAKI            = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidEKU            = asn1.ObjectIdentifier{2, 5, 29, 37}
)

var errCert = errors.New("leaf: malformed certificate")

var tagExtensions = cbasn1.Tag(3).Constructed().ContextSpecific()

// extension is one X.509 extension, with its exact encoding.
type extension struct {
	oid      asn1.ObjectIdentifier
	critical bool
	value    []byte // extnValue contents
	raw      []byte // the whole Extension element
}

// cert holds the raw pieces of a certificate that the precert checks need.
// It is deliberately minimal: the full field extractor arrives in Plan 3.
type cert struct {
	tbsParts  [][]byte // every TBSCertificate child element, in order
	issuerAt  int      // index of issuer in tbsParts
	extAt     int      // index of the [3] extensions element, or -1
	issuer    []byte   // full Name element
	subject   []byte   // full Name element
	spki      []byte   // full SubjectPublicKeyInfo element
	exts      []extension
	ski, akid []byte // subject key ID; authority key ID's keyIdentifier
	ctSigner  bool   // has the RFC 6962 precertificate-signing EKU
}

// parseCert reads a DER certificate.
func parseCert(der []byte) (*cert, error) {
	s := cryptobyte.String(der)
	var body, tbs cryptobyte.String
	if !s.ReadASN1(&body, cbasn1.SEQUENCE) || !s.Empty() || !body.ReadASN1Element(&tbs, cbasn1.SEQUENCE) {
		return nil, errCert
	}
	return parseTBS(tbs)
}

func parseTBS(full []byte) (*cert, error) {
	s := cryptobyte.String(full)
	var tbs cryptobyte.String
	if !s.ReadASN1(&tbs, cbasn1.SEQUENCE) || !s.Empty() {
		return nil, errCert
	}
	c := &cert{extAt: -1}
	var tags []cbasn1.Tag
	for !tbs.Empty() {
		var el cryptobyte.String
		var tag cbasn1.Tag
		if !tbs.ReadAnyASN1Element(&el, &tag) {
			return nil, errCert
		}
		c.tbsParts = append(c.tbsParts, el)
		tags = append(tags, tag)
	}
	i := 0
	if len(tags) > 0 && tags[0] == cbasn1.Tag(0).Constructed().ContextSpecific() {
		i = 1 // explicit version
	}
	// serial, signature, issuer, validity, subject, subjectPublicKeyInfo
	if len(tags) < i+6 || tags[i] != cbasn1.INTEGER || tags[i+2] != cbasn1.SEQUENCE ||
		tags[i+4] != cbasn1.SEQUENCE || tags[i+5] != cbasn1.SEQUENCE {
		return nil, errCert
	}
	c.issuerAt = i + 2
	c.issuer, c.subject, c.spki = c.tbsParts[i+2], c.tbsParts[i+4], c.tbsParts[i+5]
	for j := i + 6; j < len(tags); j++ {
		if tags[j] != tagExtensions {
			continue
		}
		if c.extAt >= 0 {
			return nil, errCert
		}
		c.extAt = j
		if err := c.parseExtensions(c.tbsParts[j]); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *cert) parseExtensions(el []byte) error {
	s := cryptobyte.String(el)
	var wrapped, list cryptobyte.String
	if !s.ReadASN1(&wrapped, tagExtensions) || !wrapped.ReadASN1(&list, cbasn1.SEQUENCE) || !wrapped.Empty() {
		return errCert
	}
	for !list.Empty() {
		var raw, ext cryptobyte.String
		if !list.ReadASN1Element(&raw, cbasn1.SEQUENCE) {
			return errCert
		}
		ext = raw
		var body cryptobyte.String
		var x extension
		var value cryptobyte.String
		if !ext.ReadASN1(&body, cbasn1.SEQUENCE) || !body.ReadASN1ObjectIdentifier(&x.oid) {
			return errCert
		}
		// critical is a plain BOOLEAN DEFAULT FALSE. (cryptobyte's
		// ReadOptionalASN1Boolean is for explicitly tagged booleans.)
		if body.PeekASN1Tag(cbasn1.BOOLEAN) && !body.ReadASN1Boolean(&x.critical) {
			return errCert
		}
		if !body.ReadASN1(&value, cbasn1.OCTET_STRING) || !body.Empty() {
			return errCert
		}
		x.value, x.raw = value, raw
		c.exts = append(c.exts, x)
		switch {
		case x.oid.Equal(oidSKI):
			v := cryptobyte.String(x.value)
			var id cryptobyte.String
			if v.ReadASN1(&id, cbasn1.OCTET_STRING) && v.Empty() {
				c.ski = id
			}
		case x.oid.Equal(oidAKI):
			v := cryptobyte.String(x.value)
			var seq, id cryptobyte.String
			var present bool
			if v.ReadASN1(&seq, cbasn1.SEQUENCE) &&
				seq.ReadOptionalASN1(&id, &present, cbasn1.Tag(0).ContextSpecific()) && present {
				c.akid = id
			}
		case x.oid.Equal(oidEKU):
			v := cryptobyte.String(x.value)
			var seq cryptobyte.String
			if v.ReadASN1(&seq, cbasn1.SEQUENCE) {
				for !seq.Empty() {
					var oid asn1.ObjectIdentifier
					if !seq.ReadASN1ObjectIdentifier(&oid) {
						break
					}
					if oid.Equal(oidPrecertSigning) {
						c.ctSigner = true
					}
				}
			}
		}
	}
	return nil
}

// rewrite describes an RFC 6962 §3.2 TBS transformation.
type rewrite struct {
	drop   asn1.ObjectIdentifier // extension to remove
	issuer []byte                // replacement issuer Name element, if non-nil
	akid   []byte                // replacement AKI keyIdentifier, if non-nil
}

// rebuildTBS re-encodes the TBSCertificate with rw applied. Every element it
// does not change is copied byte for byte. If no extension remains, the [3]
// element is omitted, as RFC 6962 implementations do.
func (c *cert) rebuildTBS(rw rewrite) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for j, part := range c.tbsParts {
			switch {
			case j == c.issuerAt && rw.issuer != nil:
				b.AddBytes(rw.issuer)
			case j == c.extAt:
				var kept []extension
				for _, x := range c.exts {
					if !x.oid.Equal(rw.drop) {
						kept = append(kept, x)
					}
				}
				if len(kept) == 0 {
					continue
				}
				b.AddASN1(tagExtensions, func(b *cryptobyte.Builder) {
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						for _, x := range kept {
							if rw.akid == nil || !x.oid.Equal(oidAKI) {
								b.AddBytes(x.raw)
								continue
							}
							addAKI(b, x.critical, rw.akid)
						}
					})
				})
			default:
				b.AddBytes(part)
			}
		}
	})
	return b.Bytes()
}

// addAKI encodes an AuthorityKeyIdentifier extension holding only keyid.
func addAKI(b *cryptobyte.Builder, critical bool, keyid []byte) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oidAKI)
		if critical {
			b.AddASN1Boolean(true)
		}
		b.AddASN1(cbasn1.OCTET_STRING, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) {
					b.AddBytes(keyid)
				})
			})
		})
	})
}

// hasExtension reports whether the certificate carries oid.
func (c *cert) hasExtension(oid asn1.ObjectIdentifier) bool {
	for _, x := range c.exts {
		if x.oid.Equal(oid) {
			return true
		}
	}
	return false
}

// issuedBy reports whether candidate can be c's issuer: its subject equals
// c's issuer name, and its subject key ID equals c's authority key ID when
// both are present.
func (c *cert) issuedBy(candidate *cert) bool {
	if !bytes.Equal(candidate.subject, c.issuer) {
		return false
	}
	return c.akid == nil || candidate.ski == nil || bytes.Equal(c.akid, candidate.ski)
}
```

Create `internal/leaf/precert.go`:

```go
package leaf

import (
	"bytes"
	"crypto/sha256"
)

// findIssuer picks c's issuer among chain by relationship, never by position.
// Candidates that share a key and signing role (a cross-signed copy of the
// same CA) count as one.
func findIssuer(c *cert, chain []*cert) (*cert, Code) {
	var found *cert
	for _, cand := range chain {
		if cand == nil || !c.issuedBy(cand) {
			continue
		}
		if found != nil && (!bytes.Equal(found.spki, cand.spki) || found.ctSigner != cand.ctSigner) {
			return nil, ChainIssuerAmbiguous
		}
		if found == nil {
			found = cand
		}
	}
	if found == nil {
		return nil, ChainIssuerMissing
	}
	return found, OK
}

// checkPrecert identifies the final issuer and cross-checks the log's
// issuer_key_hash and TBS against the precertificate (RFC 6962 §3.1-3.2).
// Failures are recorded; the decoded fields stay as logged.
func (e *Entry) checkPrecert() {
	pre, err := parseCert(e.CertDER)
	if err != nil {
		e.fail(PrecertTBSMismatch)
		return
	}
	chain := make([]*cert, len(e.Chain))
	for i, der := range e.Chain {
		chain[i], _ = parseCert(der) // unparseable chain certs are never candidates
	}
	issuer, code := findIssuer(pre, chain)
	if code != OK {
		e.fail(code)
		return
	}
	rw := rewrite{drop: oidPoison}
	final := issuer
	if issuer.ctSigner {
		// A Precertificate Signing Certificate: the real issuer is the CA that
		// certified it, and the log's TBS carries that CA's name and key ID.
		if final, code = findIssuer(issuer, chain); code != OK {
			e.fail(code)
			return
		}
		rw.issuer = issuer.issuer
		if pre.hasExtension(oidAKI) {
			if issuer.akid == nil {
				e.fail(PrecertTBSMismatch)
				return
			}
			rw.akid = issuer.akid
		}
	}
	if sha256.Sum256(final.spki) != e.IssuerKeyHash {
		e.fail(IssuerKeyHashMismatch)
		return
	}
	tbs, err := pre.rebuildTBS(rw)
	if err != nil || !bytes.Equal(tbs, e.PrecertTBS) {
		e.fail(PrecertTBSMismatch)
	}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go mod tidy && go test -race -count=1 ./internal/leaf/ ./internal/merkle/ -v`
Expected: PASS:
- `TestCodesAreStable`, `TestDecodeGeneratedPair`, `TestLeafStructureCodes`, `TestExtraDataCodes`
- `TestPrecertIssuerByRelationship`, `TestPrecertCrossChecks`, `TestX509IssuanceDigest`
- `TestRealArgonPage`, `TestFixturesAreUnchanged`, and `FuzzDecode` (its seed corpus)

- [ ] **Step 5: Fuzz the decoder**

Run: `go test -run '^$' -fuzz FuzzDecode -fuzztime 30s -fuzzminimizetime 2s ./internal/leaf/`
Expected: PASS. The `execs/sec` counter may show 0 while the fuzzer minimizes new inputs; that is normal. A failure writes a reproducer under `internal/leaf/testdata/fuzz/`. Fix the decoder, keep the reproducer, and rerun.

- [ ] **Step 6: Gate and commit**

Run the four gate commands. All must pass.

```bash
git add go.mod go.sum internal/leaf internal/testdata internal/merkle/fixtures_test.go
git commit -m "feat: leaf decoding with stable codes and RFC 6962 precert cross-checks; real fixture page"
```

---

### Task A5: RFC 6962 entries, proofs and the LogSource

Implements spec §5.1–5.2, amendment A1 §4 (head checks, chain cache) and Plan 1 review minor 12.

**Files:**
- Create: `internal/logsource/logsource.go`, `internal/logsource/chaincache.go`, `internal/logsource/rfc6962/source.go`
- Modify: `internal/logsource/rfc6962/client.go`
- Create tests: `internal/logsource/rfc6962/entries_test.go`, `internal/logsource/rfc6962/source_test.go`

**Interfaces:**
- Consumes:
  - From Task A4: `leaf.Decode`, `leaf.Entry`
  - Plan 1: `merkle.VerifySTH`, `merkle.SignedTreeHead`, `logreg.Record`, `loglist.ParseKey`
- Produces:
  - `rfc6962` client:
    - `func (*Client) GetSTHRaw(ctx) (merkle.SignedTreeHead, []byte, error)`
    - `type WireEntry struct{ LeafInput, ExtraData []byte }`
    - `func (*Client) GetEntries(ctx, start, end uint64) ([]WireEntry, error)`, with an **inclusive** `end` as in RFC 6962
    - `func (*Client) GetProofByHash(ctx, leafHash [32]byte, treeSize uint64) (uint64, [][32]byte, error)`
    - `HTTPError.Error` quotes the body
  - `logsource` types:
    - `type LogInfo struct{ Name string; LogID [32]byte; PublicKey crypto.PublicKey; URL string }`
    - `func InfoFromRecord(logreg.Record) (LogInfo, error)`
    - `type SignedHead struct{ merkle.SignedTreeHead; Raw []byte }`
    - `type RawEntry struct{ Index uint64; LeafInput, ExtraData []byte; Leaf leaf.Entry; Chain [][32]byte }`, with `Size() int`
    - `type LogSource interface{ Info() LogInfo; Head(ctx) (SignedHead, error); Fetch(ctx, start, end uint64) ([]RawEntry, error); ConsistencyProof(ctx, first, second uint64) ([][32]byte, error); Issuer(ctx, fp [32]byte) ([]byte, error) }`. `Fetch` covers the **half-open** range `[start, end)`.
  - `logsource` head checks:
    - `var ErrIncident`
    - `type IncidentError struct{ Kind string; Last, Got SignedHead }`, with kinds `TreeShrank`, `RootChanged` and `TimestampBackwards`
    - `func CheckHead(last *SignedHead, got SignedHead) error`
  - `logsource` chain cache:
    - `const DefaultChainCacheBytes = 64 << 20`
    - `var ErrChainCacheFull`, `ErrIssuerUnknown`
    - `type ChainCache` with `NewChainCache(maxBytes int)`, `Put`, `Get`, `Len`, `Bytes` and `Reset`
    - `func FingerprintChain(*ChainCache, [][]byte) ([][32]byte, error)`
  - `rfc6962` source:
    - `func NewSource(info logsource.LogInfo, hc *http.Client, chains *logsource.ChainCache, last *logsource.SignedHead) *Source`, implementing `LogSource`
    - `func (*Source) Client() *Client`

- [ ] **Step 1: Write the failing client tests**

Create `internal/logsource/rfc6962/entries_test.go`:

```go
package rfc6962

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"

	"github.com/4rji/ctvault/internal/ctlogtest"
)

func TestGetEntriesAgainstFakeLog(t *testing.T) {
	l := ctlogtest.New(t, 10, ctlogtest.Options{PageSize: 4})
	got, err := New(l.URL, nil).GetEntries(ctx, 3, 9)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("page size 4: got %d entries", len(got))
	}
	for i, w := range got {
		if !bytes.Equal(w.LeafInput, l.Entries[3+i].LeafInput) || !bytes.Equal(w.ExtraData, l.Entries[3+i].ExtraData) {
			t.Fatalf("entry %d: bytes must be exactly as served", 3+i)
		}
	}
	if _, err := New(l.URL, nil).GetEntries(ctx, 5, 4); err == nil {
		t.Fatal("end before start must be refused before any request")
	}
}

// TestGetEntriesFramingErrors: anything that keeps the exact bytes from being
// established is ErrMalformed, so the fetcher retries and nothing advances.
func TestGetEntriesFramingErrors(t *testing.T) {
	ok := `{"leaf_input":"AAA=","extra_data":"AAAA"}`
	for name, body := range map[string]string{
		"truncated JSON":     `{"entries":[` + ok,
		"invalid base64":     `{"entries":[{"leaf_input":"!!","extra_data":"AAAA"}]}`,
		"missing leaf":       `{"entries":[{"extra_data":"AAAA"}]}`,
		"missing extra":      `{"entries":[{"leaf_input":"AAA="}]}`,
		"no entries":         `{"entries":[]}`,
		"no entries field":   `{}`,
		"more than asked":    `{"entries":[` + ok + `,` + ok + `,` + ok + `]}`,
		"html error page":    `<html>502 Bad Gateway</html>`,
		"null leaf_input":    `{"entries":[{"leaf_input":null,"extra_data":"AAAA"}]}`,
		"extra not a string": `{"entries":[{"leaf_input":"AAA=","extra_data":5}]}`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		_, err := New(srv.URL, nil).GetEntries(ctx, 0, 1)
		srv.Close()
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: want ErrMalformed, got %v", name, err)
		}
	}
}

func TestGetProofByHash(t *testing.T) {
	l := ctlogtest.New(t, 21, ctlogtest.Options{})
	c := New(l.URL, nil)
	sth, err := c.GetSTH(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lh := sha256.Sum256(append([]byte{0}, l.Entries[13].LeafInput...))
	idx, path, err := c.GetProofByHash(ctx, lh, sth.TreeSize)
	if err != nil {
		t.Fatal(err)
	}
	nodes := make([][]byte, len(path))
	for i := range path {
		nodes[i] = path[i][:]
	}
	if idx != 13 || proof.VerifyInclusion(rfc6962.DefaultHasher, idx, sth.TreeSize, lh[:], nodes, sth.RootHash[:]) != nil {
		t.Fatalf("leaf 13: index %d; proof must verify", idx)
	}
	var he *HTTPError
	if _, _, err := c.GetProofByHash(ctx, [32]byte{1}, sth.TreeSize); !errors.As(err, &he) || he.Status != 404 {
		t.Fatalf("unknown leaf: want HTTP 404, got %v", err)
	}
}

// TestHTTPErrorBodyIsQuoted covers Plan 1 review minor 12: a server's error
// body is shown quoted, so escape sequences cannot act on the terminal.
func TestHTTPErrorBodyIsQuoted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "\x1b[2J\x1b[31mgotcha", http.StatusInternalServerError)
	}))
	defer srv.Close()
	_, err := New(srv.URL, nil).GetSTH(ctx)
	if err == nil || strings.Contains(err.Error(), "\x1b") || !strings.Contains(err.Error(), `\x1b[2J`) {
		t.Fatalf("error must show the escape sequence quoted: %q", err)
	}
}
```

Run: `go test ./internal/logsource/rfc6962/`
Expected: FAIL with `New(l.URL, nil).GetEntries undefined (type *Client has no field or method GetEntries)`.

- [ ] **Step 2: Extend the client**

Replace `internal/logsource/rfc6962/client.go`:

```go
// Package rfc6962 is CTVault's HTTP client for RFC 6962 logs (get-sth,
// get-sth-consistency, get-entries, get-proof-by-hash) and the LogSource
// adapter built on it.
package rfc6962

import (
	"bytes"
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

// Error quotes the body, so control characters a server sends (ANSI escapes,
// for example) are shown escaped instead of acting on the terminal (Plan 1
// review, minor 12).
func (e *HTTPError) Error() string {
	return fmt.Sprintf("%s: HTTP %d: %q", e.URL, e.Status, e.Body)
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

// getJSON fetches path and decodes it into v. It returns the body exactly as
// received.
func (c *Client) getJSON(ctx context.Context, path string, q url.Values, v any) ([]byte, error) {
	u := c.BaseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("%s: reading body: %w", u, err)
	}
	if resp.StatusCode != http.StatusOK {
		he := &HTTPError{URL: u, Status: resp.StatusCode, Body: strings.TrimSpace(string(body[:min(len(body), 200)]))}
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s >= 0 {
			he.RetryAfter = time.Duration(s) * time.Second
		}
		return nil, he
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("%w: %s: body exceeds %d bytes", ErrMalformed, u, maxBody)
	}
	if err := json.Unmarshal(body, v); err != nil {
		// Quote the start of the body: a captive portal or proxy page is then
		// recognisable instead of a bare JSON syntax error.
		snippet := bytes.TrimSpace(body[:min(len(body), 60)])
		return nil, fmt.Errorf("%w: %s: %v (response starts with %q)", ErrMalformed, u, err, snippet)
	}
	return body, nil
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
	sth, _, err := c.GetSTHRaw(ctx)
	return sth, err
}

// GetSTHRaw is GetSTH that also returns the response body exactly as
// received, for sample manifests and incident evidence.
func (c *Client) GetSTHRaw(ctx context.Context) (merkle.SignedTreeHead, []byte, error) {
	var j struct {
		TreeSize  *uint64 `json:"tree_size"`
		Timestamp uint64  `json:"timestamp"`
		Root      string  `json:"sha256_root_hash"`
		Sig       string  `json:"tree_head_signature"`
	}
	raw, err := c.getJSON(ctx, "ct/v1/get-sth", nil, &j)
	if err != nil {
		return merkle.SignedTreeHead{}, nil, err
	}
	if j.TreeSize == nil {
		return merkle.SignedTreeHead{}, nil, fmt.Errorf("%w: get-sth has no tree_size", ErrMalformed)
	}
	root, err := decode32("sha256_root_hash", j.Root)
	if err != nil {
		return merkle.SignedTreeHead{}, nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(j.Sig)
	if err != nil || len(sig) == 0 {
		return merkle.SignedTreeHead{}, nil, fmt.Errorf("%w: tree_head_signature is not base64", ErrMalformed)
	}
	return merkle.SignedTreeHead{TreeSize: *j.TreeSize, Timestamp: j.Timestamp, RootHash: root, Signature: sig}, raw, nil
}

// GetSTHConsistency fetches the proof that the tree of size first is a prefix
// of the tree of size second.
func (c *Client) GetSTHConsistency(ctx context.Context, first, second uint64) ([][32]byte, error) {
	q := url.Values{"first": {strconv.FormatUint(first, 10)}, "second": {strconv.FormatUint(second, 10)}}
	var j struct {
		Consistency []string `json:"consistency"`
	}
	if _, err := c.getJSON(ctx, "ct/v1/get-sth-consistency", q, &j); err != nil {
		return nil, err
	}
	return decodeNodes("consistency", j.Consistency)
}

func decodeNodes(field string, nodes []string) ([][32]byte, error) {
	out := make([][32]byte, len(nodes))
	for i, n := range nodes {
		h, err := decode32(fmt.Sprintf("%s[%d]", field, i), n)
		if err != nil {
			return nil, err
		}
		out[i] = h
	}
	return out, nil
}

// WireEntry is one get-entries element after base64 decoding: the exact
// bytes the log served.
type WireEntry struct {
	LeafInput []byte
	ExtraData []byte
}

// GetEntries fetches entries [start, end], inclusive as in RFC 6962 §4.6.
// The log may return fewer; it may not return none or more than asked.
// Anything that keeps the exact bytes from being established is ErrMalformed
// (spec §5.4: transport or framing corruption), so nothing advances.
func (c *Client) GetEntries(ctx context.Context, start, end uint64) ([]WireEntry, error) {
	if end < start {
		return nil, fmt.Errorf("get-entries: end %d before start %d", end, start)
	}
	q := url.Values{"start": {strconv.FormatUint(start, 10)}, "end": {strconv.FormatUint(end, 10)}}
	var j struct {
		Entries []struct {
			LeafInput *string `json:"leaf_input"`
			ExtraData *string `json:"extra_data"`
		} `json:"entries"`
	}
	if _, err := c.getJSON(ctx, "ct/v1/get-entries", q, &j); err != nil {
		return nil, err
	}
	if len(j.Entries) == 0 {
		return nil, fmt.Errorf("%w: get-entries %d-%d returned no entries", ErrMalformed, start, end)
	}
	if uint64(len(j.Entries)) > end-start+1 {
		return nil, fmt.Errorf("%w: get-entries %d-%d returned %d entries", ErrMalformed, start, end, len(j.Entries))
	}
	out := make([]WireEntry, len(j.Entries))
	for i, e := range j.Entries {
		if e.LeafInput == nil || e.ExtraData == nil {
			return nil, fmt.Errorf("%w: get-entries entry %d lacks leaf_input or extra_data", ErrMalformed, start+uint64(i))
		}
		li, err1 := base64.StdEncoding.DecodeString(*e.LeafInput)
		ed, err2 := base64.StdEncoding.DecodeString(*e.ExtraData)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("%w: get-entries entry %d is not valid base64", ErrMalformed, start+uint64(i))
		}
		out[i] = WireEntry{LeafInput: li, ExtraData: ed}
	}
	return out, nil
}

// GetProofByHash fetches the inclusion proof of the leaf with hash leafHash
// in the tree of size treeSize (RFC 6962 §4.5).
func (c *Client) GetProofByHash(ctx context.Context, leafHash [32]byte, treeSize uint64) (uint64, [][32]byte, error) {
	q := url.Values{"hash": {base64.StdEncoding.EncodeToString(leafHash[:])}, "tree_size": {strconv.FormatUint(treeSize, 10)}}
	var j struct {
		LeafIndex *uint64  `json:"leaf_index"`
		AuditPath []string `json:"audit_path"`
	}
	if _, err := c.getJSON(ctx, "ct/v1/get-proof-by-hash", q, &j); err != nil {
		return 0, nil, err
	}
	if j.LeafIndex == nil {
		return 0, nil, fmt.Errorf("%w: get-proof-by-hash has no leaf_index", ErrMalformed)
	}
	path, err := decodeNodes("audit_path", j.AuditPath)
	return *j.LeafIndex, path, err
}
```

Run: `go test -count=1 ./internal/logsource/rfc6962/ -v`
Expected: PASS: `TestGetEntriesAgainstFakeLog`, `TestGetEntriesFramingErrors`, `TestGetProofByHash`, `TestHTTPErrorBodyIsQuoted`, and the Plan 1 client tests.

- [ ] **Step 3: Write the failing source tests**

Create `internal/logsource/rfc6962/source_test.go`:

```go
package rfc6962

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/merkle"
)

func fakeSource(t *testing.T, l *ctlogtest.Log) *Source {
	t.Helper()
	pub, err := x509.ParsePKIXPublicKey(l.PublicKeyDER)
	if err != nil {
		t.Fatal(err)
	}
	info := logsource.LogInfo{Name: "fake", LogID: l.LogID, PublicKey: pub, URL: l.URL}
	return NewSource(info, nil, logsource.NewChainCache(logsource.DefaultChainCacheBytes), nil)
}

func TestSourceHeadChecks(t *testing.T) {
	l := ctlogtest.New(t, 30, ctlogtest.Options{})
	s := fakeSource(t, l)
	l.Publish(10)
	h10, err := s.Head(ctx)
	if err != nil || h10.TreeSize != 10 || len(h10.Raw) == 0 {
		t.Fatalf("first head: %+v %v", h10, err)
	}
	l.Publish(20)
	if h, err := s.Head(ctx); err != nil || h.TreeSize != 20 {
		t.Fatalf("growth is accepted: %v", err)
	}
	l.Publish(15)
	var ie *logsource.IncidentError
	if _, err := s.Head(ctx); !errors.As(err, &ie) || ie.Kind != logsource.TreeShrank || ie.Last.TreeSize != 20 {
		t.Fatalf("a smaller tree is an incident: %v", err)
	}
	l.Publish(20)
	if _, err := s.Head(ctx); err != nil {
		t.Fatalf("the refused head must not replace the last accepted one: %v", err)
	}
	l.Fork(3)
	if _, err := s.Head(ctx); !errors.As(err, &ie) || ie.Kind != logsource.RootChanged {
		t.Fatalf("same size, different root is an incident: %v", err)
	}

	bad := ctlogtest.New(t, 4, ctlogtest.Options{BadSTHSignature: true})
	if _, err := fakeSource(t, bad).Head(ctx); !errors.Is(err, merkle.ErrBadSignature) || errors.Is(err, logsource.ErrIncident) {
		t.Fatalf("a bad signature is reported as such: %v", err)
	}
}

func TestCheckHeadTimestamps(t *testing.T) {
	last := &logsource.SignedHead{SignedTreeHead: merkle.SignedTreeHead{TreeSize: 5, Timestamp: 1000, RootHash: [32]byte{1}}}
	older := logsource.SignedHead{SignedTreeHead: merkle.SignedTreeHead{TreeSize: 5, Timestamp: 999, RootHash: [32]byte{1}}}
	var ie *logsource.IncidentError
	if err := logsource.CheckHead(last, older); !errors.As(err, &ie) || ie.Kind != logsource.TimestampBackwards {
		t.Fatalf("an older timestamp is an incident: %v", err)
	}
	resigned := logsource.SignedHead{SignedTreeHead: merkle.SignedTreeHead{TreeSize: 5, Timestamp: 2000, RootHash: [32]byte{1}}}
	if err := logsource.CheckHead(last, resigned); err != nil {
		t.Fatalf("the same tree signed later is fine: %v", err)
	}
	if err := logsource.CheckHead(nil, older); err != nil {
		t.Fatalf("with no last head anything signed is accepted: %v", err)
	}
}

func TestSourceFetch(t *testing.T) {
	l := ctlogtest.New(t, 10, ctlogtest.Options{PageSize: 4})
	s := fakeSource(t, l)
	got, err := s.Fetch(ctx, 2, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("one page of 4, got %d", len(got))
	}
	caFP := sha256.Sum256(leaf.Decode(l.Entries[0].LeafInput, l.Entries[0].ExtraData).Chain[0])
	for i, e := range got {
		want := l.Entries[2+i]
		if e.Index != uint64(2+i) || !bytes.Equal(e.LeafInput, want.LeafInput) || e.Leaf.Code != leaf.OK {
			t.Fatalf("entry %d: index %d code %q", 2+i, e.Index, e.Leaf.Code)
		}
		if len(e.Chain) != 1 || e.Chain[0] != caFP {
			t.Fatalf("entry %d: chain must be fingerprinted", 2+i)
		}
		if e.Size() != len(want.LeafInput)+len(want.ExtraData) {
			t.Fatal("Size counts the exact bytes")
		}
	}
	der, err := s.Issuer(ctx, caFP)
	if err != nil || sha256.Sum256(der) != caFP {
		t.Fatalf("Issuer must serve the cached chain certificate: %v", err)
	}
	if _, err := s.Issuer(ctx, [32]byte{9}); !errors.Is(err, logsource.ErrIssuerUnknown) {
		t.Fatalf("unknown fingerprint: %v", err)
	}
	if _, err := s.Fetch(ctx, 5, 5); err == nil {
		t.Fatal("an empty range is refused")
	}
}

func TestSourceConsistencyProofNeedsNoRequestForTrivialSizes(t *testing.T) {
	l := ctlogtest.New(t, 8, ctlogtest.Options{})
	s := fakeSource(t, l)
	for _, sz := range [][2]uint64{{0, 8}, {8, 8}} {
		p, err := s.ConsistencyProof(ctx, sz[0], sz[1])
		if err != nil || p != nil {
			t.Fatalf("%v: %v %v", sz, p, err)
		}
	}
	if l.Requests("get-sth-consistency") != 0 {
		t.Fatal("trivial proofs must not hit the log")
	}
	if p, err := s.ConsistencyProof(ctx, 3, 8); err != nil || len(p) == 0 {
		t.Fatalf("real proof: %v %v", p, err)
	}
}

func TestChainCache(t *testing.T) {
	c := logsource.NewChainCache(10)
	a, b := [32]byte{1}, [32]byte{2}
	if err := c.Put(a, []byte("123456")); err != nil {
		t.Fatal(err)
	}
	if err := c.Put(a, []byte("123456")); err != nil || c.Bytes() != 6 {
		t.Fatalf("a known certificate is free: %v, %d bytes", err, c.Bytes())
	}
	if err := c.Put(b, []byte("12345")); !errors.Is(err, logsource.ErrChainCacheFull) {
		t.Fatalf("11 bytes exceed the 10-byte bound: %v", err)
	}
	src := []byte("abc")
	c.Put(b, src)
	src[0] = 'X'
	if got, _ := c.Get(b); string(got) != "abc" {
		t.Fatal("Put must copy, so the caller's buffer can be reused")
	}
	c.Reset()
	if c.Len() != 0 || c.Bytes() != 0 {
		t.Fatal("Reset empties the cache")
	}
}

// TestSourceFetchRealPage serves the real argon2027h1 fixture page through
// get-entries and decodes it with the production Source.
func TestSourceFetchRealPage(t *testing.T) {
	page, err := os.ReadFile("../../testdata/argon2027h1_entries_380000000.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("start") != "380000000" || r.URL.Query().Get("end") != "380000031" {
			http.Error(w, "unexpected range", http.StatusBadRequest)
			return
		}
		w.Write(page)
	}))
	defer srv.Close()
	info := logsource.LogInfo{Name: "argon2027h1", URL: srv.URL}
	cache := logsource.NewChainCache(logsource.DefaultChainCacheBytes)
	got, err := NewSource(info, nil, cache, nil).Fetch(ctx, 380000000, 380000032)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 32 || got[31].Index != 380000031 {
		t.Fatalf("got %d entries", len(got))
	}
	for _, e := range got {
		if e.Leaf.Code != leaf.OK || len(e.Chain) == 0 {
			t.Fatalf("entry %d: code %q, chain %d", e.Index, e.Leaf.Code, len(e.Chain))
		}
		for _, fp := range e.Chain {
			if der, ok := cache.Get(fp); !ok || sha256.Sum256(der) != fp {
				t.Fatalf("entry %d: chain certificate not cached under its SHA-256", e.Index)
			}
		}
	}
	if cache.Len() != 25 {
		t.Fatalf("the fixture's 32 entries reference 25 distinct chain certificates, got %d", cache.Len())
	}
}
```

Run: `go test ./internal/logsource/rfc6962/`
Expected: FAIL with `no required module provides package github.com/4rji/ctvault/internal/logsource`.

- [ ] **Step 4: Implement the LogSource**

Create `internal/logsource/logsource.go`:

```go
// Package logsource defines how CTVault reads one CT log (spec §5.1): the
// LogSource interface, the entries it yields, signed-head checks shared by
// every implementation, and the per-batch chain cache. The RFC 6962
// implementation lives in logsource/rfc6962; a tiled one can follow later.
package logsource

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/logreg"
	"github.com/4rji/ctvault/internal/merkle"
)

// LogInfo is a pinned log's identity.
type LogInfo struct {
	Name      string
	LogID     [32]byte
	PublicKey crypto.PublicKey
	URL       string
}

// InfoFromRecord turns a pinned log into a LogInfo, re-checking that the key
// hashes to the log ID.
func InfoFromRecord(r logreg.Record) (LogInfo, error) {
	pub, err := r.PublicKey()
	if err != nil {
		return LogInfo{}, fmt.Errorf("log %s: %w", r.Name, err)
	}
	id, err := base64.StdEncoding.DecodeString(r.LogID)
	if err != nil || len(id) != 32 {
		return LogInfo{}, fmt.Errorf("log %s: log_id is not a base64 32-byte hash", r.Name)
	}
	info := LogInfo{Name: r.Name, PublicKey: pub, URL: r.URL}
	copy(info.LogID[:], id)
	return info, nil
}

// SignedHead is a verified signed tree head and the response that carried it.
type SignedHead struct {
	merkle.SignedTreeHead
	Raw []byte // the response body exactly as received
}

// RawEntry is one log entry with its index taken from request position
// (spec §5.2), its exact bytes, and its decoded fields.
type RawEntry struct {
	Index     uint64
	LeafInput []byte
	ExtraData []byte
	Leaf      leaf.Entry
	Chain     [][32]byte // chain certificates by SHA-256; nil if the chain could not be decoded
}

// Size is the entry's weight in the fetcher's byte-bounded reorder buffer.
func (e *RawEntry) Size() int { return len(e.LeafInput) + len(e.ExtraData) }

// LogSource reads one log. Fetch covers [start, end) and may return fewer
// entries than asked, but at least one; it never returns more.
type LogSource interface {
	Info() LogInfo
	Head(ctx context.Context) (SignedHead, error)
	Fetch(ctx context.Context, start, end uint64) ([]RawEntry, error)
	ConsistencyProof(ctx context.Context, first, second uint64) ([][32]byte, error)
	Issuer(ctx context.Context, fp [32]byte) ([]byte, error)
}

// ErrIncident is matched by every *IncidentError: log misbehaviour that must
// stop ingestion with exit 5 (spec §12, amendment A1 §4).
var ErrIncident = errors.New("CT log misbehaviour")

// Incident kinds.
const (
	TreeShrank         = "tree_shrank"
	RootChanged        = "root_changed"
	TimestampBackwards = "timestamp_backwards"
)

// IncidentError records two signed heads that cannot both be honest.
type IncidentError struct {
	Kind      string
	Last, Got SignedHead
}

func (e *IncidentError) Error() string {
	return fmt.Sprintf("%v: %s (last accepted head: size %d, timestamp %d; new head: size %d, timestamp %d)",
		ErrIncident, e.Kind, e.Last.TreeSize, e.Last.Timestamp, e.Got.TreeSize, e.Got.Timestamp)
}

func (e *IncidentError) Is(target error) bool { return target == ErrIncident }

// CheckHead compares a newly verified head with the last accepted one. A
// smaller tree, a different root for the same size, or an older timestamp is
// an incident. last may be nil when no head was accepted yet.
func CheckHead(last *SignedHead, got SignedHead) error {
	if last == nil {
		return nil
	}
	kind := ""
	switch {
	case got.TreeSize < last.TreeSize:
		kind = TreeShrank
	case got.TreeSize == last.TreeSize && got.RootHash != last.RootHash:
		kind = RootChanged
	case got.Timestamp < last.Timestamp:
		kind = TimestampBackwards
	default:
		return nil
	}
	return &IncidentError{Kind: kind, Last: *last, Got: got}
}

// ErrIssuerUnknown means a chain certificate is not in the cache.
var ErrIssuerUnknown = errors.New("chain certificate not cached")

// FingerprintChain hashes each chain certificate and stores it in the cache.
func FingerprintChain(c *ChainCache, chain [][]byte) ([][32]byte, error) {
	if chain == nil {
		return nil, nil
	}
	fps := make([][32]byte, len(chain))
	for i, der := range chain {
		fps[i] = sha256.Sum256(der)
		if err := c.Put(fps[i], der); err != nil {
			return nil, err
		}
	}
	return fps, nil
}
```

Create `internal/logsource/chaincache.go`:

```go
package logsource

import (
	"errors"
	"fmt"
	"sync"
)

// DefaultChainCacheBytes bounds the chain cache. Measured on 32,768
// contiguous real argon2027h1 entries: 167 distinct chain certificates,
// 184 KiB in total, so the bound leaves about 350x headroom.
const DefaultChainCacheBytes = 64 << 20

// ErrChainCacheFull means a batch referenced more distinct chain bytes than
// the bound allows. The batch is abandoned rather than dropping anything.
var ErrChainCacheFull = errors.New("chain cache full")

// ChainCache holds chain certificate DER by SHA-256 for the batch in flight
// (amendment A1 §4). It is safe for concurrent use. Entries are removed only
// by Reset, which the writer calls after the batch commits, so the cache
// never grows across batches.
type ChainCache struct {
	mu    sync.Mutex
	max   int
	bytes int
	certs map[[32]byte][]byte
}

// NewChainCache returns a cache holding at most maxBytes of DER.
func NewChainCache(maxBytes int) *ChainCache {
	return &ChainCache{max: maxBytes, certs: map[[32]byte][]byte{}}
}

// Put stores a copy of der under fp; storing a known fp is free.
func (c *ChainCache) Put(fp [32]byte, der []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.certs[fp]; ok {
		return nil
	}
	if c.bytes+len(der) > c.max {
		return fmt.Errorf("%w: %d bytes cached, limit %d", ErrChainCacheFull, c.bytes, c.max)
	}
	c.certs[fp] = append([]byte(nil), der...)
	c.bytes += len(der)
	return nil
}

// Get returns the DER stored under fp.
func (c *ChainCache) Get(fp [32]byte) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	der, ok := c.certs[fp]
	return der, ok
}

// Len and Bytes report the cache's contents.
func (c *ChainCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.certs)
}

func (c *ChainCache) Bytes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytes
}

// Reset empties the cache. Call it only after the batch has committed.
func (c *ChainCache) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.certs = map[[32]byte][]byte{}
	c.bytes = 0
}
```

Create `internal/logsource/rfc6962/source.go`:

```go
package rfc6962

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/merkle"
)

// Source is the RFC 6962 LogSource. Chains arrive inline with every entry, so
// it hashes them and serves Issuer from the per-batch chain cache.
type Source struct {
	client *Client
	info   logsource.LogInfo
	chains *logsource.ChainCache

	mu   sync.Mutex
	last *logsource.SignedHead
}

var _ logsource.LogSource = (*Source)(nil)

// NewSource reads the log described by info. last is the last head accepted
// for this log (nil if none); Head refuses any head inconsistent with it.
func NewSource(info logsource.LogInfo, hc *http.Client, chains *logsource.ChainCache, last *logsource.SignedHead) *Source {
	return &Source{client: New(info.URL, hc), info: info, chains: chains, last: last}
}

// Info returns the pinned log identity.
func (s *Source) Info() logsource.LogInfo { return s.info }

// Client exposes the HTTP client for calls outside the LogSource interface,
// such as get-proof-by-hash.
func (s *Source) Client() *Client { return s.client }

// Head fetches the signed tree head, verifies its signature with the pinned
// key and checks it against the last accepted head. Only a head that passes
// both becomes the new last accepted head.
func (s *Source) Head(ctx context.Context) (logsource.SignedHead, error) {
	sth, raw, err := s.client.GetSTHRaw(ctx)
	if err != nil {
		return logsource.SignedHead{}, err
	}
	h := logsource.SignedHead{SignedTreeHead: sth, Raw: raw}
	if err := merkle.VerifySTH(s.info.PublicKey, sth); err != nil {
		return h, fmt.Errorf("log %s: %w", s.info.Name, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := logsource.CheckHead(s.last, h); err != nil {
		return h, fmt.Errorf("log %s: %w", s.info.Name, err)
	}
	s.last = &h
	return h, nil
}

// Fetch returns entries [start, start+n) for some 1 <= n <= end-start. Each
// entry's index is its request position, never derived from counts.
func (s *Source) Fetch(ctx context.Context, start, end uint64) ([]logsource.RawEntry, error) {
	if end <= start {
		return nil, fmt.Errorf("fetch: empty range [%d, %d)", start, end)
	}
	wire, err := s.client.GetEntries(ctx, start, end-1)
	if err != nil {
		return nil, err
	}
	out := make([]logsource.RawEntry, len(wire))
	for i, w := range wire {
		e := logsource.RawEntry{Index: start + uint64(i), LeafInput: w.LeafInput, ExtraData: w.ExtraData,
			Leaf: leaf.Decode(w.LeafInput, w.ExtraData)}
		if e.Chain, err = logsource.FingerprintChain(s.chains, e.Leaf.Chain); err != nil {
			return nil, err
		}
		out[i] = e
	}
	return out, nil
}

// ConsistencyProof fetches the proof from first to second. Sizes 0 and equal
// sizes need no proof, so no request is made.
func (s *Source) ConsistencyProof(ctx context.Context, first, second uint64) ([][32]byte, error) {
	if first == 0 || first == second {
		return nil, nil
	}
	return s.client.GetSTHConsistency(ctx, first, second)
}

// Issuer returns a chain certificate seen in the current batch.
func (s *Source) Issuer(_ context.Context, fp [32]byte) ([]byte, error) {
	if der, ok := s.chains.Get(fp); ok {
		return der, nil
	}
	return nil, fmt.Errorf("%w: %x", logsource.ErrIssuerUnknown, fp)
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test -race -count=1 ./internal/logsource/... -v`
Expected: PASS:
- `TestSourceHeadChecks`, `TestCheckHeadTimestamps`, `TestSourceFetch`
- `TestSourceConsistencyProofNeedsNoRequestForTrivialSizes`, `TestChainCache`
- `TestSourceFetchRealPage`: the 32 real entries reference 25 distinct chain certificates

- [ ] **Step 6: Gate and commit**

Run the four gate commands. All must pass.

```bash
git add internal/logsource
git commit -m "feat: get-entries, get-proof-by-hash, LogSource with head incidents and chain cache; quoted error bodies (minor 12)"
```

---

### Task A6: Fetcher and stop signals

Implements spec §5.2–5.3 and amendment A1 §4 (reorder buffer, two signal contexts).

**Files:**
- Create: `internal/fetch/fetch.go`, `internal/fetch/retry.go`, `internal/stop/stop.go`
- Create tests: `internal/fetch/fetch_test.go`, `internal/fetch/limiter_test.go`, `internal/fetch/retry_test.go`, `internal/stop/stop_test.go`

**Interfaces:**
- Consumes (Task A5): `logsource.LogSource`, `logsource.RawEntry` with `Size()`, `rfc6962.NewSource`, `rfc6962.HTTPError`, `rfc6962.ErrMalformed`.
- Produces:
  - `fetch.Run`:
    - `type Options struct{ Workers int; MaxRPS float64; PageSize, MaxBufferedEntries, MaxBufferedBytes int; StallTimeout, MinBackoff, MaxBackoff time.Duration }`; zero values take defaults
    - `type Stats struct{ Requests int64; Entries uint64; ShortReads, RateLimited, ServerErrors, FramingErrors, NetworkErrors, OtherErrors int64; FinalRPS float64; PeakBufEntries, PeakBufBytes int; RetryAfterWaits int64; LargestResponse int }`
    - `var ErrStalled`
    - `func Run(ctx, src logsource.LogSource, start, end uint64, o Options, emit func(logsource.RawEntry) error) (Stats, error)`; `emit` runs in the caller's goroutine, strictly in index order
  - `fetch` helpers:
    - `func Retry(ctx, o Options, fn func(context.Context) error) error`
    - `func Transient(err error) bool`
  - `stop`:
    - `type Contexts struct{ Soft, Hard context.Context }`
    - `func OnSignals(parent context.Context, onFirst, onSecond func()) *Contexts`
    - `func (*Contexts) Close()`

- [ ] **Step 1: Write the failing fetcher tests**

Create `internal/fetch/fetch_test.go`:

```go
package fetch

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
)

func source(t *testing.T, l *ctlogtest.Log) logsource.LogSource {
	t.Helper()
	pub, err := x509.ParsePKIXPublicKey(l.PublicKeyDER)
	if err != nil {
		t.Fatal(err)
	}
	info := logsource.LogInfo{Name: "fake", LogID: l.LogID, PublicKey: pub, URL: l.URL}
	return rfc6962.NewSource(info, nil, logsource.NewChainCache(logsource.DefaultChainCacheBytes), nil)
}

// fast options for tests: no real waiting between retries.
func fast(o Options) Options {
	o.MaxRPS = 1000
	o.MinBackoff, o.MaxBackoff = time.Millisecond, 5*time.Millisecond
	return o
}

// collect runs a fetch and checks that every entry of [start, end) arrives
// once, in order, with exactly the bytes the log holds.
func collect(t *testing.T, l *ctlogtest.Log, start, end uint64, o Options) Stats {
	t.Helper()
	next := start
	st, err := Run(context.Background(), source(t, l), start, end, o, func(e logsource.RawEntry) error {
		if e.Index != next {
			return fmt.Errorf("got index %d, want %d", e.Index, next)
		}
		if !bytes.Equal(e.LeafInput, l.Entries[e.Index].LeafInput) || !bytes.Equal(e.ExtraData, l.Entries[e.Index].ExtraData) {
			return fmt.Errorf("entry %d: bytes differ from the log", e.Index)
		}
		next++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if next != end || st.Entries != end-start {
		t.Fatalf("released up to %d (%d entries), want %d", next, st.Entries, end)
	}
	return st
}

func TestRunInOrderDespiteOutOfOrderCompletion(t *testing.T) {
	l := ctlogtest.New(t, 300, ctlogtest.Options{PageSize: 8, EntriesDelay: func(start uint64) time.Duration {
		return time.Duration(5-(start/8)%5) * 3 * time.Millisecond // earlier pages finish later
	}})
	st := collect(t, l, 0, 300, fast(Options{Workers: 6, PageSize: 8}))
	if st.Requests != 38 || st.LargestResponse != 8 {
		t.Fatalf("300 entries in pages of 8 take 38 requests of at most 8: %+v", st)
	}
}

func TestRunAlignsRequestsAndRequeuesShortReads(t *testing.T) {
	l := ctlogtest.New(t, 64, ctlogtest.Options{PageSize: 8, ShortReadEvery: 1})
	st := collect(t, l, 5, 40, fast(Options{Workers: 3, PageSize: 8}))
	if st.ShortReads == 0 || st.Requests <= 5 {
		t.Fatalf("every response is halved, so remainders must be refetched: %+v", st)
	}
}

func TestRunRetriesThrottlingAndFraming(t *testing.T) {
	l := ctlogtest.New(t, 200, ctlogtest.Options{PageSize: 8, RateLimitEvery: 3, NoRetryAfter: true,
		ServerErrorEvery: 5, CorruptJSONEvery: 4, InvalidBase64Every: 7})
	st := collect(t, l, 0, 200, fast(Options{Workers: 4, PageSize: 8}))
	if st.RateLimited == 0 || st.ServerErrors == 0 || st.FramingErrors == 0 {
		t.Fatalf("every fault class must have been hit and retried: %+v", st)
	}
	if st.FinalRPS >= 1000 {
		t.Fatalf("throttling must lower the rate: %v", st.FinalRPS)
	}
}

func TestRetryAfterPausesTheRun(t *testing.T) {
	l := ctlogtest.New(t, 24, ctlogtest.Options{PageSize: 8, RateLimitEvery: 2})
	t0 := time.Now()
	st := collect(t, l, 0, 24, fast(Options{Workers: 3, PageSize: 8}))
	if st.RetryAfterWaits == 0 || time.Since(t0) < time.Second {
		t.Fatalf("Retry-After: 1 must pause the run for a second: %v, %+v", time.Since(t0), st)
	}
}

// TestReorderBufferBounds: with a slow head of line and many workers, the
// buffer stays within its limits and the run still completes.
func TestReorderBufferBounds(t *testing.T) {
	l := ctlogtest.New(t, 256, ctlogtest.Options{PageSize: 4, EntriesDelay: func(start uint64) time.Duration {
		if start%32 == 0 {
			return 20 * time.Millisecond
		}
		return 0
	}})
	entryBytes := len(l.Entries[0].LeafInput) + len(l.Entries[0].ExtraData)
	for name, o := range map[string]Options{
		"entry bound":                   {Workers: 8, PageSize: 4, MaxBufferedEntries: 16},
		"byte bound":                    {Workers: 8, PageSize: 4, MaxBufferedBytes: 10 * entryBytes},
		"byte bound below one response": {Workers: 8, PageSize: 4, MaxBufferedBytes: 1},
	} {
		st := collect(t, l, 0, 256, fast(o))
		o = o.withDefaults()
		maxResponse := 4 * (entryBytes + 64)
		if st.PeakBufEntries > o.MaxBufferedEntries+o.PageSize {
			t.Errorf("%s: %d entries buffered, bound %d + one page", name, st.PeakBufEntries, o.MaxBufferedEntries)
		}
		if st.PeakBufBytes > o.MaxBufferedBytes+o.Workers*maxResponse {
			t.Errorf("%s: %d bytes buffered, bound %d + one response per worker", name, st.PeakBufBytes, o.MaxBufferedBytes)
		}
	}
}

// stub is a LogSource whose Fetch the test controls.
type stub struct {
	logsource.LogSource
	fetch func(ctx context.Context, start, end uint64) ([]logsource.RawEntry, error)
	calls atomic.Int64
}

func (s *stub) Fetch(ctx context.Context, start, end uint64) ([]logsource.RawEntry, error) {
	s.calls.Add(1)
	return s.fetch(ctx, start, end)
}

func entries(start, n uint64) []logsource.RawEntry {
	out := make([]logsource.RawEntry, n)
	for i := range out {
		out[i] = logsource.RawEntry{Index: start + uint64(i), LeafInput: []byte{1}}
	}
	return out
}

func TestStallRule(t *testing.T) {
	s := &stub{fetch: func(ctx context.Context, _, _ uint64) ([]logsource.RawEntry, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	t0 := time.Now()
	_, err := Run(context.Background(), s, 0, 10, fast(Options{StallTimeout: 200 * time.Millisecond}), func(logsource.RawEntry) error { return nil })
	if !errors.Is(err, ErrStalled) || time.Since(t0) > 2*time.Second {
		t.Fatalf("a run with no progress must stall out: %v after %v", err, time.Since(t0))
	}
}

func TestPermanentErrors(t *testing.T) {
	notFound := &stub{fetch: func(context.Context, uint64, uint64) ([]logsource.RawEntry, error) {
		return nil, &rfc6962.HTTPError{Status: 404}
	}}
	if _, err := Run(context.Background(), notFound, 0, 4, fast(Options{Workers: 1}), nil); err == nil || notFound.calls.Load() != maxOtherRetries+1 {
		t.Fatalf("an unexpected status is retried %d times, then fails: %v after %d calls", maxOtherRetries, err, notFound.calls.Load())
	}
	full := &stub{fetch: func(context.Context, uint64, uint64) ([]logsource.RawEntry, error) {
		return nil, logsource.ErrChainCacheFull
	}}
	if _, err := Run(context.Background(), full, 0, 4, fast(Options{Workers: 1}), nil); !errors.Is(err, logsource.ErrChainCacheFull) || full.calls.Load() != 1 {
		t.Fatalf("a local failure is not retried: %v", err)
	}
	ok := &stub{fetch: func(_ context.Context, start, end uint64) ([]logsource.RawEntry, error) {
		return entries(start, end-start), nil
	}}
	boom := errors.New("vault write failed")
	if _, err := Run(context.Background(), ok, 0, 100, fast(Options{}), func(logsource.RawEntry) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("an emit error ends the run: %v", err)
	}
}

// TestMisbehavingSourceIsRetried: wrong indexes or too many entries are
// framing errors; the request is retried and nothing wrong is released.
func TestMisbehavingSourceIsRetried(t *testing.T) {
	var n atomic.Int64
	s := &stub{fetch: func(_ context.Context, start, end uint64) ([]logsource.RawEntry, error) {
		switch n.Add(1) {
		case 1:
			return entries(start+1, end-start), nil // shifted indexes
		case 2:
			return entries(start, end-start+1), nil // one too many
		}
		return entries(start, end-start), nil
	}}
	var got []uint64
	st, err := Run(context.Background(), s, 0, 4, fast(Options{Workers: 1, PageSize: 4}), func(e logsource.RawEntry) error {
		got = append(got, e.Index)
		return nil
	})
	if err != nil || fmt.Sprint(got) != "[0 1 2 3]" || st.FramingErrors != 2 {
		t.Fatalf("got %v, %v, %+v", got, err, st)
	}
}

func TestContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &stub{fetch: func(ctx context.Context, start, end uint64) ([]logsource.RawEntry, error) {
		cancel()
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	if _, err := Run(ctx, s, 0, 8, fast(Options{}), nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation ends the run: %v", err)
	}
}

// fakeClock is a manually advanced clock for the rate controller.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }
func testRun(c *fakeClock, maxRPS float64) *run {
	return &run{opts: Options{MaxRPS: maxRPS}.withDefaults(), rps: maxRPS, now: c.now, lim: newTestLimiter(maxRPS)}
}

func TestRateHalvingAndIncrease(t *testing.T) {
	c := &fakeClock{t: time.Unix(1e9, 0)}
	r := testRun(c, 20)
	r.throttled(0)
	r.throttled(0) // same burst: counts once
	if r.rps != 10 {
		t.Fatalf("a burst of failures halves once: %v", r.rps)
	}
	c.add(decreaseCooldown)
	r.throttled(0)
	if r.rps != 5 {
		t.Fatalf("after the cooldown the next failure halves again: %v", r.rps)
	}
	c.add(time.Second)
	r.success()
	if r.rps != 5 {
		t.Fatalf("no increase within the cooldown: %v", r.rps)
	}
	for range 3 { // 2 s, 3 s and 4 s after the halving
		c.add(time.Second)
		r.success()
		r.success() // a second success in the same second adds nothing
	}
	if r.rps != 8 {
		t.Fatalf("one step per second once the cooldown has passed: %v, want 5+3", r.rps)
	}
	for range 40 {
		c.add(decreaseCooldown)
		r.throttled(0)
	}
	if r.rps != minRPS {
		t.Fatalf("the rate never drops below %v: %v", minRPS, r.rps)
	}
	for range 100 {
		c.add(time.Second)
		r.success()
	}
	if r.rps != 20 {
		t.Fatalf("the rate never exceeds MaxRPS: %v", r.rps)
	}
}

// TestRateSurvivesSparseFailures: requests at the current rate for 10
// minutes, every 50th failing regardless of rate (2%). The rate must stay
// high; halving on every failure would sink to the floor.
func TestRateSurvivesSparseFailures(t *testing.T) {
	c := &fakeClock{t: time.Unix(1e9, 0)}
	r := testRun(c, 20)
	n := 0
	for end := c.t.Add(10 * time.Minute); c.t.Before(end); {
		c.add(time.Duration(float64(time.Second) / r.rps))
		if n++; n%50 == 0 {
			r.throttled(0)
		} else {
			r.success()
		}
	}
	if r.rps < 8 {
		t.Fatalf("2%% independent failures must not collapse the rate: %v requests/s", r.rps)
	}
}

func TestBackoff(t *testing.T) {
	r := testRun(&fakeClock{}, 20)
	for attempt, want := range map[int]time.Duration{1: time.Second, 3: 4 * time.Second, 7: 60 * time.Second, 40: 60 * time.Second} {
		for range 50 {
			if d := r.backoff(attempt); d < want/2 || d > want {
				t.Fatalf("attempt %d: backoff %v outside [%v, %v]", attempt, d, want/2, want)
			}
		}
	}
}
```

Create `internal/fetch/limiter_test.go`:

```go
package fetch

import "golang.org/x/time/rate"

func newTestLimiter(rps float64) *rate.Limiter { return rate.NewLimiter(rate.Limit(rps), 1) }
```

Create `internal/fetch/retry_test.go`:

```go
package fetch

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/logsource/rfc6962"
)

func TestRetry(t *testing.T) {
	o := fast(Options{StallTimeout: time.Second})
	n := 0
	err := Retry(context.Background(), o, func(context.Context) error {
		if n++; n < 4 {
			return []error{&rfc6962.HTTPError{Status: 429}, &rfc6962.HTTPError{Status: 503}, rfc6962.ErrMalformed}[n-1]
		}
		return nil
	})
	if err != nil || n != 4 {
		t.Fatalf("transient errors are retried: %v after %d calls", err, n)
	}
	n = 0
	err = Retry(context.Background(), o, func(context.Context) error { n++; return &rfc6962.HTTPError{Status: 400} })
	if err == nil || n != maxOtherRetries+1 {
		t.Fatalf("other statuses get %d retries: %v after %d calls", maxOtherRetries, err, n)
	}
	boom := errors.New("local failure")
	n = 0
	if err := Retry(context.Background(), o, func(context.Context) error { n++; return boom }); !errors.Is(err, boom) || n != 1 {
		t.Fatalf("local errors are not retried: %v", err)
	}
	short := fast(Options{StallTimeout: 50 * time.Millisecond})
	if err := Retry(context.Background(), short, func(context.Context) error { return &rfc6962.HTTPError{Status: 503} }); !errors.Is(err, ErrStalled) {
		t.Fatalf("endless transient errors stall out: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Retry(ctx, o, func(context.Context) error { return &rfc6962.HTTPError{Status: 503} }); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation ends retries: %v", err)
	}
}

func TestRetryHonoursRetryAfter(t *testing.T) {
	n := 0
	t0 := time.Now()
	err := Retry(context.Background(), fast(Options{}), func(context.Context) error {
		if n++; n == 1 {
			return &rfc6962.HTTPError{Status: 429, RetryAfter: 300 * time.Millisecond}
		}
		return nil
	})
	if err != nil || time.Since(t0) < 300*time.Millisecond {
		t.Fatalf("Retry-After must be waited out: %v after %v", err, time.Since(t0))
	}
}
```

Run: `go test ./internal/fetch/`
Expected: FAIL with `no required module provides package golang.org/x/time/rate`.

- [ ] **Step 2: Implement the fetcher**

```bash
go get golang.org/x/time@v0.16.0
```

Create `internal/fetch/fetch.go`. Read its package comment first: it states every rule the tests check, including why halving is damped (Decision 2) and why the head-of-line request is always admitted (it is the deadlock guard for the bounded buffer).

```go
// Package fetch reads an index range from a LogSource with a pool of workers
// and hands the entries to the caller strictly in index order (spec §5.3,
// amendment A1 §4).
//
//   - Requests are aligned to the log's page size. A short response answers
//     only its own request; the rest of that request is queued again.
//   - One token bucket, capped at MaxRPS, paces every request. A 429 or 5xx
//     halves the rate, at most once per 2 s so that one burst of failures
//     from parallel workers counts once; Retry-After pauses all workers.
//     Sustained success (2 s without a halving) raises the rate by 1 request
//     per second, every second. Halving on every failure instead collapses to
//     the floor when even 2% of requests fail independently of the rate.
//   - A failed request retries with exponential backoff and jitter, from
//     MinBackoff up to MaxBackoff. Transport and framing errors retry too:
//     nothing advances until the exact bytes are known.
//   - The reorder buffer is bounded by entry count and by bytes. Workers pause
//     when either limit is reached, except for the request that fills the gap
//     at the head of the line, which is always admitted, so the buffer can
//     never deadlock. Responses already in flight still land, so the byte
//     bound can be exceeded by at most one response per worker.
//   - If no entry is released for StallTimeout, the run fails with ErrStalled.
package fetch

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
)

// ErrStalled means no entry was released for Options.StallTimeout.
var ErrStalled = errors.New("fetch: no progress within the stall timeout")

// Options tunes a run. Zero values take the defaults noted.
type Options struct {
	Workers            int           // default 4 (ingest.workers)
	MaxRPS             float64       // default 20 (ingest.max_rps)
	PageSize           int           // default 32, Argon's get-entries page
	MaxBufferedEntries int           // default 65,536 (fetch.max_buffered_entries)
	MaxBufferedBytes   int           // default 256 MiB (fetch.max_buffered_bytes)
	StallTimeout       time.Duration // default 15m (ingest.stall_timeout)
	MinBackoff         time.Duration // default 1s
	MaxBackoff         time.Duration // default 60s
}

func (o Options) withDefaults() Options {
	def := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&o.Workers, 4)
	def(&o.PageSize, 32)
	def(&o.MaxBufferedEntries, 65536)
	def(&o.MaxBufferedBytes, 256<<20)
	if o.MaxRPS <= 0 {
		o.MaxRPS = 20
	}
	if o.StallTimeout <= 0 {
		o.StallTimeout = 15 * time.Minute
	}
	if o.MinBackoff <= 0 {
		o.MinBackoff = time.Second
	}
	if o.MaxBackoff < o.MinBackoff {
		o.MaxBackoff = max(60*time.Second, o.MinBackoff)
	}
	return o
}

// Stats describes a run. The high-water marks show the buffer bounds held.
type Stats struct {
	Requests        int64   // get-entries requests sent
	Entries         uint64  // entries released in order
	ShortReads      int64   // responses with fewer entries than requested
	RateLimited     int64   // HTTP 429
	ServerErrors    int64   // HTTP 5xx
	FramingErrors   int64   // malformed responses (spec §5.4), retried
	NetworkErrors   int64   // timeouts, resets and the like, retried
	OtherErrors     int64   // other HTTP statuses, retried a few times
	FinalRPS        float64 // the token bucket's rate at the end
	PeakBufEntries  int     // most entries held in the reorder buffer at once
	PeakBufBytes    int     // most bytes held in the reorder buffer at once
	RetryAfterWaits int64   // pauses imposed by Retry-After
	LargestResponse int     // most entries one get-entries response carried: the log's page size
}

// maxOtherRetries bounds retries of unexpected HTTP statuses (400, 404, ...),
// which a correct request below the pinned head should never get.
const maxOtherRetries = 3

// Rate control: halve on throttling at most once per decreaseCooldown; once
// that long has passed since the last halving, add increaseStep every
// increaseEvery; never go below minRPS.
const (
	decreaseCooldown = 2 * time.Second
	increaseEvery    = time.Second
	increaseStep     = 1.0
	minRPS           = 0.25
)

type task struct {
	start, end uint64
	attempt    int
}

type run struct {
	src  logsource.LogSource
	opts Options
	end  uint64

	mu       sync.Mutex
	cond     *sync.Cond
	pending  []task // sorted by start
	buf      map[uint64][]logsource.RawEntry
	bufN     int
	bufBytes int
	next     uint64
	err      error
	progress time.Time

	now          func() time.Time
	lim          *rate.Limiter
	rps          float64
	lastDecrease time.Time
	lastIncrease time.Time
	pauseUntil   time.Time

	stats Stats
}

// Run fetches [start, end) and calls emit for every entry in index order, in
// the calling goroutine. It returns when the range is done, emit fails, the
// context ends, a request fails permanently, or the run stalls.
func Run(ctx context.Context, src logsource.LogSource, start, end uint64, opts Options, emit func(logsource.RawEntry) error) (Stats, error) {
	opts = opts.withDefaults()
	r := &run{src: src, opts: opts, end: end, buf: map[uint64][]logsource.RawEntry{}, next: start,
		progress: time.Now(), now: time.Now, rps: opts.MaxRPS, lim: rate.NewLimiter(rate.Limit(opts.MaxRPS), 1)}
	r.cond = sync.NewCond(&r.mu)
	page := uint64(opts.PageSize)
	for a := start; a < end; {
		b := min(end, (a/page+1)*page) // align to absolute page boundaries
		r.pending = append(r.pending, task{start: a, end: b})
		a = b
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // wake everyone on cancellation, and enforce the stall rule
		defer wg.Done()
		tick := time.NewTicker(min(time.Second, opts.StallTimeout/4))
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				r.fail(ctx.Err())
				return
			case <-tick.C:
				r.mu.Lock()
				stalled := time.Since(r.progress) > opts.StallTimeout
				r.mu.Unlock()
				if stalled {
					r.fail(fmt.Errorf("%w (%v; next index %d)", ErrStalled, opts.StallTimeout, r.nextIndex()))
				}
			}
		}
	}()
	for range opts.Workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.worker(ctx)
		}()
	}

	err := r.consume(emit)
	cancel()
	wg.Wait()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stats.FinalRPS = r.rps
	return r.stats, err
}

func (r *run) nextIndex() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.next
}

// fail records the first fatal error and wakes every waiter.
func (r *run) fail(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err == nil {
		r.err = err
	}
	r.cond.Broadcast()
}

// consume releases entries in index order.
func (r *run) consume(emit func(logsource.RawEntry) error) error {
	for {
		r.mu.Lock()
		for r.err == nil && r.next < r.end && r.buf[r.next] == nil {
			r.cond.Wait()
		}
		if r.err != nil {
			err := r.err
			r.mu.Unlock()
			return err
		}
		if r.next >= r.end {
			r.mu.Unlock()
			return nil
		}
		chunk := r.buf[r.next]
		delete(r.buf, r.next)
		r.bufN -= len(chunk)
		for i := range chunk {
			r.bufBytes -= chunk[i].Size()
		}
		r.next += uint64(len(chunk))
		r.progress = time.Now()
		r.stats.Entries += uint64(len(chunk))
		r.cond.Broadcast()
		r.mu.Unlock()
		for _, e := range chunk {
			if err := emit(e); err != nil {
				r.fail(err)
				return err
			}
		}
	}
}

// take waits for the lowest pending task that the buffer bounds admit.
func (r *run) take() (task, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for {
		if r.err != nil {
			return task{}, false
		}
		if len(r.pending) > 0 {
			t := r.pending[0]
			headOfLine := t.start == r.next
			fits := t.start-r.next < uint64(r.opts.MaxBufferedEntries) && r.bufBytes < r.opts.MaxBufferedBytes
			if headOfLine || fits {
				r.pending = r.pending[1:]
				return t, true
			}
		} else if r.next >= r.end {
			return task{}, false
		}
		r.cond.Wait()
	}
}

func (r *run) requeue(t task) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := sort.Search(len(r.pending), func(i int) bool { return r.pending[i].start >= t.start })
	r.pending = append(r.pending, task{})
	copy(r.pending[i+1:], r.pending[i:])
	r.pending[i] = t
	r.cond.Broadcast()
}

func (r *run) worker(ctx context.Context) {
	for {
		t, ok := r.take()
		if !ok {
			return
		}
		if err := r.pace(ctx); err != nil {
			r.fail(err)
			return
		}
		atomic.AddInt64(&r.stats.Requests, 1)
		entries, err := r.src.Fetch(ctx, t.start, t.end)
		if err == nil {
			err = r.deliver(t, entries)
		}
		if err == nil {
			continue
		}
		if ctx.Err() != nil {
			r.fail(ctx.Err())
			return
		}
		if !r.retryable(err, t) {
			r.fail(fmt.Errorf("fetch [%d, %d): %w", t.start, t.end, err))
			return
		}
		t.attempt++
		if err := sleep(ctx, r.backoff(t.attempt)); err != nil {
			r.fail(err)
			return
		}
		r.requeue(t)
	}
}

// deliver buffers a response and queues the unanswered rest of the request.
func (r *run) deliver(t task, entries []logsource.RawEntry) error {
	n := uint64(len(entries))
	if n == 0 || n > t.end-t.start {
		return fmt.Errorf("%w: %d entries for a request of %d", rfc6962.ErrMalformed, n, t.end-t.start)
	}
	for i := range entries {
		if entries[i].Index != t.start+uint64(i) {
			return fmt.Errorf("%w: entry %d carries index %d", rfc6962.ErrMalformed, t.start+uint64(i), entries[i].Index)
		}
	}
	r.success()
	r.mu.Lock()
	r.buf[t.start] = entries
	r.bufN += len(entries)
	for i := range entries {
		r.bufBytes += entries[i].Size()
	}
	r.stats.PeakBufEntries = max(r.stats.PeakBufEntries, r.bufN)
	r.stats.PeakBufBytes = max(r.stats.PeakBufBytes, r.bufBytes)
	r.stats.LargestResponse = max(r.stats.LargestResponse, len(entries))
	r.cond.Broadcast()
	r.mu.Unlock()
	if t.start+n < t.end {
		atomic.AddInt64(&r.stats.ShortReads, 1)
		r.requeue(task{start: t.start + n, end: t.end})
	}
	return nil
}

// retryable classifies an error and adjusts the rate. Context errors and
// local failures (a full chain cache) are permanent.
func (r *run) retryable(err error, t task) bool {
	var he *rfc6962.HTTPError
	var ne net.Error
	switch {
	case errors.As(err, &he) && (he.Status == 429 || he.Status >= 500):
		if he.Status == 429 {
			atomic.AddInt64(&r.stats.RateLimited, 1)
		} else {
			atomic.AddInt64(&r.stats.ServerErrors, 1)
		}
		r.throttled(he.RetryAfter)
		return true
	case errors.As(err, &he):
		atomic.AddInt64(&r.stats.OtherErrors, 1)
		return t.attempt < maxOtherRetries
	case errors.Is(err, rfc6962.ErrMalformed):
		atomic.AddInt64(&r.stats.FramingErrors, 1)
		return true
	case errors.As(err, &ne):
		atomic.AddInt64(&r.stats.NetworkErrors, 1)
		return true
	}
	return false
}

// pace waits for any Retry-After pause, then for a token.
func (r *run) pace(ctx context.Context) error {
	r.mu.Lock()
	wait := time.Until(r.pauseUntil)
	r.mu.Unlock()
	if wait > 0 {
		if err := sleep(ctx, wait); err != nil {
			return err
		}
	}
	return r.lim.Wait(ctx)
}

func (r *run) success() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if r.rps < r.opts.MaxRPS && now.Sub(r.lastDecrease) >= decreaseCooldown && now.Sub(r.lastIncrease) >= increaseEvery {
		r.rps = min(r.opts.MaxRPS, r.rps+increaseStep)
		r.lim.SetLimit(rate.Limit(r.rps))
		r.lastIncrease = now
	}
}

func (r *run) throttled(retryAfter time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if now.Sub(r.lastDecrease) >= decreaseCooldown {
		r.rps = max(minRPS, r.rps/2)
		r.lim.SetLimit(rate.Limit(r.rps))
		r.lastDecrease = now
	}
	if retryAfter > 0 {
		r.stats.RetryAfterWaits++
		if until := now.Add(retryAfter); until.After(r.pauseUntil) {
			r.pauseUntil = until
		}
	}
}

// backoff is MinBackoff × 2^(attempt−1), capped at MaxBackoff, with jitter
// drawn from the upper half of the interval.
func (r *run) backoff(attempt int) time.Duration {
	d := r.opts.MinBackoff << min(attempt-1, 30)
	if d <= 0 || d > r.opts.MaxBackoff {
		d = r.opts.MaxBackoff
	}
	return d/2 + rand.N(d/2+1)
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
```

Create `internal/fetch/retry.go`:

```go
package fetch

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"time"

	"github.com/4rji/ctvault/internal/logsource/rfc6962"
)

// Transient reports whether err is worth retrying: HTTP 429 or 5xx, a
// malformed response, or a network error.
func Transient(err error) bool {
	var he *rfc6962.HTTPError
	var ne net.Error
	switch {
	case errors.As(err, &he):
		return he.Status == 429 || he.Status >= 500
	case errors.Is(err, rfc6962.ErrMalformed), errors.As(err, &ne):
		return true
	}
	return false
}

// Retry runs fn until it succeeds, with the fetcher's backoff, for single
// requests such as proofs. Transient errors are retried until StallTimeout
// has passed since the first attempt; other HTTP statuses are retried
// maxOtherRetries times; anything else is returned at once. A Retry-After
// longer than the backoff is honoured.
func Retry(ctx context.Context, o Options, fn func(context.Context) error) error {
	o = o.withDefaults()
	deadline := time.Now().Add(o.StallTimeout)
	for attempt := 1; ; attempt++ {
		err := fn(ctx)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var he *rfc6962.HTTPError
		other := errors.As(err, &he) && !Transient(err)
		if (!Transient(err) && !other) || (other && attempt > maxOtherRetries) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%w: %v", ErrStalled, err)
		}
		d := min(o.MinBackoff<<min(attempt-1, 30), o.MaxBackoff)
		if d <= 0 {
			d = o.MaxBackoff
		}
		d = d/2 + rand.N(d/2+1)
		if he != nil && he.RetryAfter > d {
			d = he.RetryAfter
		}
		if err := sleep(ctx, d); err != nil {
			return err
		}
	}
}
```

- [ ] **Step 3: Run the tests to verify they pass, repeatedly**

Run: `go mod tidy && go test -race -count=1 ./internal/fetch/ -v`
Expected: PASS in about 5 s:
- `TestRunInOrderDespiteOutOfOrderCompletion`, `TestRunAlignsRequestsAndRequeuesShortReads`
- `TestRunRetriesThrottlingAndFraming`, `TestRetryAfterPausesTheRun`, which takes about 2 s because it waits out a real `Retry-After: 1`
- `TestReorderBufferBounds`, `TestStallRule`, `TestPermanentErrors`, `TestMisbehavingSourceIsRetried`, `TestContextCancel`
- `TestRateHalvingAndIncrease`, `TestRateSurvivesSparseFailures`, `TestBackoff`, `TestRetry`, `TestRetryHonoursRetryAfter`

Then run `go test -race -count=10 ./internal/fetch/` to show the concurrency tests are stable.
Expected: PASS.

If `TestRunRetriesThrottlingAndFraming` takes minutes instead of under a second, the rate controller is halving on every failure. That is the collapse Decision 2 prevents.

- [ ] **Step 4: Write the failing signal tests**

Create `internal/stop/stop_test.go`:

```go
package stop

import (
	"context"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func wait(t *testing.T, ctx context.Context, what string) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatalf("%s was not cancelled", what)
	}
}

func TestFirstSignalIsSoftSecondIsHard(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		var first, second atomic.Int32
		c := OnSignals(context.Background(), func() { first.Add(1) }, func() { second.Add(1) })
		if err := syscall.Kill(os.Getpid(), sig); err != nil {
			t.Fatal(err)
		}
		wait(t, c.Soft, "Soft")
		time.Sleep(50 * time.Millisecond)
		if c.Hard.Err() != nil || first.Load() != 1 || second.Load() != 0 {
			t.Fatalf("%v: one signal must cancel only Soft (first=%d second=%d)", sig, first.Load(), second.Load())
		}
		syscall.Kill(os.Getpid(), sig)
		wait(t, c.Hard, "Hard")
		if second.Load() != 1 {
			t.Fatalf("%v: the second signal runs onSecond", sig)
		}
		c.Close()
	}
}

func TestParentAndCloseEndBoth(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	c := OnSignals(parent, nil, nil)
	cancel()
	wait(t, c.Soft, "Soft after parent")
	wait(t, c.Hard, "Hard after parent")
	c.Close()

	c = OnSignals(context.Background(), nil, nil)
	c.Close()
	wait(t, c.Hard, "Hard after Close")
}
```

Run: `go test ./internal/stop/`
Expected: FAIL with `undefined: OnSignals`.

- [ ] **Step 5: Implement the stop package**

Create `internal/stop/stop.go`:

```go
// Package stop turns SIGINT and SIGTERM into two contexts (amendment A1 §4).
// The first signal cancels Soft: finish the work in hand, start nothing new.
// The second cancels Hard: abandon the work in flight; the next start
// recovers. Hard also ends when the parent context does, and Soft ends
// whenever Hard does.
package stop

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// Contexts holds the two stop levels.
type Contexts struct {
	Soft, Hard context.Context

	ch         chan os.Signal
	done       chan struct{}
	cancelSoft context.CancelFunc
	cancelHard context.CancelFunc
}

// OnSignals starts listening. onFirst, if set, runs once on the first signal
// (to tell the user what is happening); onSecond on the second.
func OnSignals(parent context.Context, onFirst, onSecond func()) *Contexts {
	hard, cancelHard := context.WithCancel(parent)
	soft, cancelSoft := context.WithCancel(hard)
	c := &Contexts{Soft: soft, Hard: hard, ch: make(chan os.Signal, 2), done: make(chan struct{}),
		cancelSoft: cancelSoft, cancelHard: cancelHard}
	signal.Notify(c.ch, syscall.SIGINT, syscall.SIGTERM)
	go c.loop(onFirst, onSecond)
	return c
}

func (c *Contexts) loop(onFirst, onSecond func()) {
	for n := 0; ; {
		select {
		case <-c.ch:
		case <-c.done:
			return
		}
		n++
		if n == 1 {
			if onFirst != nil {
				onFirst()
			}
			c.cancelSoft()
			continue
		}
		if onSecond != nil {
			onSecond()
		}
		c.cancelHard()
		return
	}
}

// Close stops listening and releases both contexts. Signals after Close get
// Go's default behaviour again.
func (c *Contexts) Close() {
	signal.Stop(c.ch)
	close(c.done)
	c.cancelHard()
}
```

Run: `go test -race -count=3 ./internal/stop/ -v`
Expected: PASS (`TestFirstSignalIsSoftSecondIsHard`, `TestParentAndCloseEndBoth`). The test sends SIGINT and SIGTERM to its own process, which the handler catches.

- [ ] **Step 6: Gate and commit**

Run the four gate commands. All must pass.

```bash
git add go.mod go.sum internal/fetch internal/stop
git commit -m "feat: ordered fetcher with damped AIMD pacing, Retry-After, bounded reorder buffer, stall rule; two-level stop signals"
```

---

### Task A7: Samples: format, capture, verify-on-load and replay

Implements amendment A1 §2.1–2.5 for the `sample` package, plus Plan 1 review minor 16.

**Files:**
- Modify: `internal/merkle/state.go`
- Create: `internal/merkle/inclusion.go`; test `internal/merkle/inclusion_test.go`
- Create: `internal/sample/manifest.go`, `internal/sample/writer.go`, `internal/sample/read.go`, `internal/sample/replay.go`, `internal/sample/capture.go`
- Create test: `internal/sample/sample_test.go`

**Interfaces:**
- Consumes:
  - From Task A6: `fetch.Run`, `fetch.Retry`, `fetch.Options`, `Stats.LargestResponse`
  - From Task A5: `rfc6962.Source` (`Head`, `ConsistencyProof`, `Client().GetProofByHash`, `Info`), `logsource.RawEntry`
  - From Task A4: `leaf.Entry.LeafHash`
  - Plan 1: `loglist.ParseKey`, `fsutil.MkdirAllSync`, `fsutil.SyncDir`
- Produces:
  - `merkle`:
    - `var ErrNoState`; zero-value `State` methods return an error instead of panicking
    - `UnmarshalJSON` requires both `size` and `compact_range`
    - `func VerifyInclusion(index, size uint64, leafHash, root [32]byte, p [][32]byte) error`
    - `func StateFromInclusion(index, size uint64, leafHash, root [32]byte, p [][32]byte) (*State, error)`
  - `sample` format:
    - `type Kind string` (`Canonical`, `Representative`)
    - `type Limits struct{ Boundary, Min, Max uint64 }`, `var DefaultLimits` = {5000, 50000, 500000}
    - `func (Limits) Check(kind, start, count) error`, `func (Limits) StartForHead(treeSize, count) (uint64, error)`
    - `func DirName(start, count uint64, suffix string) (string, error)`
    - `type Manifest`, `type Proofs`, `type Consistency`, `type Inclusion`, `type Node [32]byte`
  - `sample` writer:
    - `func Create(dest string, m Manifest, check func(written int64) error) (*Writer, error)`
    - `(*Writer).Add(logsource.RawEntry) error`, `(*Writer).Commit(Proofs) (*Sample, error)`, `(*Writer).Abort()`
    - `var ErrExists`
  - `sample` reader:
    - `func Open(dir string) (*Sample, error)`, which verifies fully
    - `type Sample struct{ Dir string; Manifest Manifest; Head merkle.SignedTreeHead; Proofs Proofs }`
    - `(*Sample).Frame(k int) ([]Entry, error)`, `(*Sample).Each(func(Entry) error) error`, `(*Sample).LogIDBytes() [32]byte`
    - `type Entry` with `Index`, `LeafInput` and `ExtraData`
    - `var ErrCorrupt`
  - `sample` replay and capture:
    - `func NewReplay(*Sample) *Replay` (an `http.Handler`)
    - `func Serve(ctx, *Sample) (url string, stop func(), err error)`
    - `type CaptureOptions`, `const SeedBytesPerEntry = 7409`, `const CheckEvery = 64 << 20`
    - `func Capture(ctx, samplesDir string, src *rfc6962.Source, o CaptureOptions) (*Sample, error)`

- [ ] **Step 1: Write the failing Merkle tests**

Create `internal/merkle/inclusion_test.go`:

```go
package merkle

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
)

// TestStateFromInclusionEveryLeaf checks the left-sibling rule against a
// reference tree: for every tree size 1-70 and every leaf, the range taken
// from the inclusion proof equals the range built by appending leaves.
func TestStateFromInclusionEveryLeaf(t *testing.T) {
	tree := testonly.New(rfc6962.DefaultHasher)
	var leaves [][32]byte
	for size := uint64(1); size <= 70; size++ {
		data := []byte{byte(size), byte(size >> 8), 7}
		tree.AppendData(data)
		leaves = append(leaves, LeafHash(data))
		var root [32]byte
		copy(root[:], tree.Hash())
		for index := range size {
			raw, err := tree.InclusionProof(index, size)
			if err != nil {
				t.Fatal(err)
			}
			p := make([][32]byte, len(raw))
			for i := range raw {
				copy(p[i][:], raw[i])
			}
			got, err := StateFromInclusion(index, size, leaves[index], root, p)
			if err != nil {
				t.Fatalf("size %d leaf %d: %v", size, index, err)
			}
			want := NewState()
			for _, h := range leaves[:index] {
				want.Append(h)
			}
			gr, _ := got.Root()
			wr, _ := want.Root()
			if got.Size() != index || gr != wr {
				t.Fatalf("size %d leaf %d: range from proof differs from the reference", size, index)
			}
			// The derived range continues correctly: append the rest and
			// reach the signed root.
			for _, h := range leaves[index:size] {
				got.Append(h)
			}
			if r, _ := got.Root(); r != root {
				t.Fatalf("size %d leaf %d: continuing from the derived range must reach the root", size, index)
			}
		}
	}
}

func TestStateFromInclusionRejectsBadProofs(t *testing.T) {
	tree := testonly.New(rfc6962.DefaultHasher)
	var leaves [][32]byte
	for i := range 13 {
		d := []byte{byte(i)}
		tree.AppendData(d)
		leaves = append(leaves, LeafHash(d))
	}
	var root [32]byte
	copy(root[:], tree.Hash())
	raw, _ := tree.InclusionProof(6, 13)
	p := make([][32]byte, len(raw))
	for i := range raw {
		copy(p[i][:], raw[i])
	}
	if _, err := StateFromInclusion(6, 13, leaves[6], root, p); err != nil {
		t.Fatal(err)
	}
	bad := append([][32]byte(nil), p...)
	bad[0][0] ^= 1
	if _, err := StateFromInclusion(6, 13, leaves[6], root, bad); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("an altered node must fail: %v", err)
	}
	if _, err := StateFromInclusion(7, 13, leaves[6], root, p); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("the wrong index must fail: %v", err)
	}
	if err := VerifyInclusion(6, 13, sha256.Sum256(nil), root, p); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("the wrong leaf must fail: %v", err)
	}
}

// TestZeroStateDoesNotPanic covers Plan 1 review minor 16.
func TestZeroStateDoesNotPanic(t *testing.T) {
	var s State
	if _, err := s.Root(); !errors.Is(err, ErrNoState) {
		t.Fatalf("Root: %v", err)
	}
	if err := s.Append([32]byte{}); !errors.Is(err, ErrNoState) {
		t.Fatalf("Append: %v", err)
	}
	if _, err := json.Marshal(&s); !errors.Is(err, ErrNoState) {
		t.Fatalf("Marshal: %v", err)
	}
	if s.Size() != 0 || s.Clone().Size() != 0 {
		t.Fatal("an uninitialized state has size 0")
	}
	for _, in := range []string{`{}`, `{"size": 3}`, `{"compact_range": []}`, `{"size": 0, "compact_range": null}`} {
		var d State
		if err := json.Unmarshal([]byte(in), &d); err == nil {
			t.Errorf("%s: a missing field must be refused, not read as an empty log", in)
		}
	}
	var empty State
	if err := json.Unmarshal([]byte(`{"size": 0, "compact_range": []}`), &empty); err != nil || empty.Size() != 0 {
		t.Fatalf("an explicit empty log is valid: %v", err)
	}
	if r, err := empty.Root(); err != nil || r != [32]byte(rfc6962.DefaultHasher.EmptyRoot()) {
		t.Fatalf("empty root: %v", err)
	}
}
```

Run: `go test ./internal/merkle/`
Expected: FAIL with `undefined: StateFromInclusion`.

- [ ] **Step 2: Implement inclusion and the safe zero State**

Replace `internal/merkle/state.go`:

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

// ErrNoState means a State was used without being created by NewState,
// Clone, StateFromInclusion or a successful UnmarshalJSON.
var ErrNoState = errors.New("merkle: state is not initialized")

// State is the compact Merkle range for leaves [0, Size) of one log. Its zero
// value is not usable: methods report ErrNoState (or size 0) instead of
// panicking (Plan 1 review, minor 16).
type State struct {
	r *compact.Range
}

// NewState returns the state of an empty log.
func NewState() *State { return &State{r: factory.NewEmptyRange(0)} }

// Size returns the number of leaves accumulated (0 for an uninitialized state).
func (s *State) Size() uint64 {
	if s.r == nil {
		return 0
	}
	return s.r.End()
}

// Append adds the next leaf hash. Callers must append in strict index order.
func (s *State) Append(leafHash [32]byte) error {
	if s.r == nil {
		return ErrNoState
	}
	return s.r.Append(leafHash[:], nil)
}

// Root returns the RFC 6962 root hash of leaves [0, Size).
func (s *State) Root() ([32]byte, error) {
	var out [32]byte
	if s.r == nil {
		return out, ErrNoState
	}
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
	if s.r == nil {
		return &State{}
	}
	c, err := factory.NewRange(0, s.r.End(), s.r.Hashes())
	if err != nil {
		panic(fmt.Sprintf("merkle: cloning a valid range failed: %v", err))
	}
	return &State{r: c}
}

type stateJSON struct {
	Size   *uint64  `json:"size"`
	Hashes []string `json:"compact_range"`
}

// MarshalJSON encodes the state as {"size": N, "compact_range": [hex...]}.
func (s *State) MarshalJSON() ([]byte, error) {
	if s.r == nil {
		return nil, ErrNoState
	}
	size := s.r.End()
	hs := s.r.Hashes()
	out := stateJSON{Size: &size, Hashes: make([]string, len(hs))}
	for i, h := range hs {
		out.Hashes[i] = hex.EncodeToString(h)
	}
	return json.Marshal(out)
}

// UnmarshalJSON decodes and validates the state. Both fields are required:
// a missing size or compact_range is an error, never an empty log.
func (s *State) UnmarshalJSON(b []byte) error {
	var in stateJSON
	if err := json.Unmarshal(b, &in); err != nil {
		return err
	}
	if in.Size == nil || in.Hashes == nil {
		return errors.New("merkle: state needs both size and compact_range")
	}
	hs := make([][]byte, len(in.Hashes))
	for i, h := range in.Hashes {
		d, err := hex.DecodeString(h)
		if err != nil || len(d) != sha256.Size {
			return fmt.Errorf("merkle: compact_range[%d] is not a 32-byte hex hash", i)
		}
		hs[i] = d
	}
	r, err := factory.NewRange(0, *in.Size, hs)
	if err != nil {
		return fmt.Errorf("merkle: invalid compact range for size %d: %w", *in.Size, err)
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

Create `internal/merkle/inclusion.go`:

```go
package merkle

import (
	"fmt"
	"slices"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

// VerifyInclusion checks that leafHash is leaf index of the tree of size with
// the given root.
func VerifyInclusion(index, size uint64, leafHash, root [32]byte, p [][32]byte) error {
	nodes := make([][]byte, len(p))
	for i := range p {
		nodes[i] = p[i][:]
	}
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, index, size, leafHash[:], nodes, root[:]); err != nil {
		return fmt.Errorf("%w: inclusion of leaf %d in tree %d: %v", ErrInconsistent, index, size, err)
	}
	return nil
}

// StateFromInclusion returns the authenticated compact range of leaves
// [0, index), taken from a verified inclusion proof for leaf index. In the
// RFC 9162 §2.1.3.2 verification walk, a proof node is a left sibling exactly
// when the low bit of fn is set or fn == sn; those left siblings, read from
// the top down, are the compact range of [0, index) (amendment A1 §2.4).
func StateFromInclusion(index, size uint64, leafHash, root [32]byte, p [][32]byte) (*State, error) {
	if err := VerifyInclusion(index, size, leafHash, root, p); err != nil {
		return nil, err
	}
	var left [][]byte
	fn, sn := index, size-1
	for _, node := range p {
		if sn == 0 {
			return nil, fmt.Errorf("%w: inclusion proof for leaf %d is too long", ErrInconsistent, index)
		}
		if fn&1 == 1 || fn == sn {
			left = append(left, node[:])
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		}
		fn >>= 1
		sn >>= 1
	}
	slices.Reverse(left)
	r, err := factory.NewRange(0, index, left)
	if err != nil {
		return nil, fmt.Errorf("%w: left siblings do not form the range [0, %d): %v", ErrInconsistent, index, err)
	}
	return &State{r: r}, nil
}
```

Run: `go test -race -count=1 ./internal/merkle/ -v`
Expected: PASS:
- `TestStateFromInclusionEveryLeaf`: every leaf of every tree size from 1 to 70, against a reference tree
- `TestStateFromInclusionRejectsBadProofs`, `TestZeroStateDoesNotPanic`
- the Plan 1 tests

- [ ] **Step 3: Write the failing sample tests**

Create `internal/sample/sample_test.go`. It shrinks the limits to frames of 8, so a 120-entry fake log is enough.

```go
package sample

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
)

// Small limits keep the fake log small: windows of 16-96 entries in frames of 8.
var testLimits = Limits{Boundary: 8, Min: 16, Max: 96}

type fixture struct {
	log  *ctlogtest.Log
	src  *rfc6962.Source
	dir  string // samples folder
	opts CaptureOptions
}

func newFixture(t *testing.T, n int) *fixture {
	t.Helper()
	l := ctlogtest.New(t, n, ctlogtest.Options{PageSize: 4})
	pub, err := x509.ParsePKIXPublicKey(l.PublicKeyDER)
	if err != nil {
		t.Fatal(err)
	}
	info := logsource.LogInfo{Name: "fakelog", LogID: l.LogID, PublicKey: pub, URL: l.URL}
	dir := t.TempDir()
	t.Cleanup(func() { makeWritable(dir) }) // runs before TempDir's removal
	return &fixture{log: l, dir: dir,
		src: rfc6962.NewSource(info, nil, logsource.NewChainCache(logsource.DefaultChainCacheBytes), nil),
		opts: CaptureOptions{Limits: testLimits, Key: base64.StdEncoding.EncodeToString(l.PublicKeyDER),
			LogListVersion: "test", Version: "test", Now: func() time.Time { return time.Unix(1790000000, 0) },
			Fetch: fetch.Options{MaxRPS: 1000, MinBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond}}}
}

// makeWritable undoes the read-only modes of published samples.
func makeWritable(dir string) {
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			os.Chmod(p, 0o755)
		}
		return nil
	})
}

func (f *fixture) capture(t *testing.T, kind Kind, start, count uint64, suffix string) (*Sample, error) {
	t.Helper()
	o := f.opts
	o.Kind, o.Start, o.Count, o.Suffix = kind, start, count, suffix
	return Capture(context.Background(), f.dir, f.src, o)
}

func checkEntries(t *testing.T, f *fixture, s *Sample) {
	t.Helper()
	next := s.Manifest.Start
	err := s.Each(func(e Entry) error {
		want := f.log.Entries[e.Index]
		if e.Index != next || !bytes.Equal(e.LeafInput, want.LeafInput) || !bytes.Equal(e.ExtraData, want.ExtraData) {
			t.Fatalf("entry %d differs from the log", e.Index)
		}
		next++
		return nil
	})
	if err != nil || next != s.Manifest.Start+s.Manifest.Count {
		t.Fatalf("Each: %v, stopped at %d", err, next)
	}
}

func TestCaptureCanonical(t *testing.T) {
	f := newFixture(t, 120)
	s, err := f.capture(t, Canonical, 0, 48, "")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(s.Dir) != "000000000000-000000000047" || filepath.Base(filepath.Dir(s.Dir)) != "fakelog" {
		t.Fatalf("folder %s", s.Dir)
	}
	m := s.Manifest
	if m.Kind != Canonical || m.Count != 48 || len(m.Frames) != 6 || m.PageSize != 4 || m.Head.TreeSize != 120 {
		t.Fatalf("manifest: %+v", m)
	}
	if len(s.Proofs.Consistency) != 6 || s.Proofs.Inclusion != nil {
		t.Fatalf("a canonical sample has one proof per boundary: %+v", s.Proofs)
	}
	checkEntries(t, f, s)
	for _, name := range []string{ManifestFile, EntriesFile, ProofsFile, "."} {
		fi, err := os.Stat(filepath.Join(s.Dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o222 != 0 {
			t.Fatalf("%s is writable (%v); samples are read-only", name, fi.Mode())
		}
	}
	if _, err := Open(s.Dir); err != nil {
		t.Fatalf("a published sample verifies on every load: %v", err)
	}
}

func TestCaptureRepresentative(t *testing.T) {
	f := newFixture(t, 120)
	s, err := f.capture(t, Representative, 40, 32, "")
	if err != nil {
		t.Fatal(err)
	}
	inc := s.Proofs.Inclusion
	if inc == nil || inc.LeafIndex != 40 || len(s.Proofs.Consistency) != 1 || s.Proofs.Consistency[0].First != 72 {
		t.Fatalf("a representative sample has the inclusion proof of leaf 40 and one consistency proof from 72: %+v", s.Proofs)
	}
	checkEntries(t, f, s)
}

// TestCaptureAtTheHead: "--start head" picks the last whole window, which
// may end exactly at the tree size; then the root itself must match.
func TestCaptureAtTheHead(t *testing.T) {
	f := newFixture(t, 120)
	start, err := testLimits.StartForHead(120, 32)
	if err != nil || start != 88 {
		t.Fatalf("StartForHead(120, 32) = %d, %v; want 88", start, err)
	}
	s, err := f.capture(t, Representative, start, 32, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Proofs.Consistency) != 0 {
		t.Fatal("a window ending at the head needs no consistency proof")
	}
	if _, err := testLimits.StartForHead(10, 32); err == nil {
		t.Fatal("a window larger than the log is refused")
	}
	o := f.opts
	o.Kind, o.StartAtHead, o.Count, o.Suffix = Representative, true, 32, "head"
	if s, err := Capture(context.Background(), f.dir, f.src, o); err != nil || s.Manifest.Start != 88 {
		t.Fatalf("StartAtHead resolves the window from the pinned head: %v", err)
	}
	o.Kind = Canonical
	if _, err := Capture(context.Background(), f.dir, f.src, o); err == nil {
		t.Fatal("--start head is for representative samples only")
	}
}

func TestCaptureRefusals(t *testing.T) {
	f := newFixture(t, 120)
	for name, tc := range map[string]struct {
		kind         Kind
		start, count uint64
		suffix       string
	}{
		"count not a multiple": {Canonical, 0, 20, ""},
		"count too small":      {Canonical, 0, 8, ""},
		"count too large":      {Canonical, 0, 104, ""},
		"canonical not at 0":   {Canonical, 8, 16, ""},
		"start not aligned":    {Representative, 4, 16, ""},
		"beyond the tree":      {Representative, 112, 16, ""},
		"bad suffix":           {Canonical, 0, 16, "../x"},
		"unknown kind":         {"other", 0, 16, ""},
	} {
		if _, err := f.capture(t, tc.kind, tc.start, tc.count, tc.suffix); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
	if entries, _ := os.ReadDir(f.dir); len(entries) != 0 {
		t.Fatalf("refusals must not create anything: %v", entries)
	}
}

func TestCaptureNeverOverwritesAndLeavesNothingOnFailure(t *testing.T) {
	f := newFixture(t, 120)
	if _, err := f.capture(t, Canonical, 0, 16, ""); err != nil {
		t.Fatal(err)
	}
	before := f.log.Requests("get-entries")
	if _, err := f.capture(t, Canonical, 0, 16, ""); !errors.Is(err, ErrExists) {
		t.Fatalf("a second capture of the same range: %v", err)
	}
	if f.log.Requests("get-entries") != before {
		t.Fatal("an existing sample is refused before fetching anything")
	}
	if s, err := f.capture(t, Canonical, 0, 16, "again"); err != nil || !strings.HasSuffix(s.Dir, "_again") {
		t.Fatalf("a new suffix captures the range again: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	o := f.opts
	o.Kind, o.Count, o.Suffix = Canonical, 48, "interrupted"
	o.Progress = func(done, _ uint64) {
		if done == 16 {
			cancel()
		}
	}
	if _, err := Capture(ctx, f.dir, f.src, o); !errors.Is(err, context.Canceled) {
		t.Fatalf("an interrupted capture fails: %v", err)
	}
	names, _ := filepath.Glob(filepath.Join(f.dir, "fakelog", "*"))
	for _, n := range names {
		if strings.Contains(n, "interrupted") || strings.Contains(filepath.Base(n), ".staging") {
			t.Fatalf("an interrupted capture left %s behind", n)
		}
	}
}

func TestDiskCheckAbortsCapture(t *testing.T) {
	f := newFixture(t, 120)
	o := f.opts
	o.Kind, o.Count = Canonical, 16
	var asked int64
	o.Check = func(need int64) error { asked = need; return errors.New("disk cap would be exceeded") }
	if _, err := Capture(context.Background(), f.dir, f.src, o); err == nil || asked != 16*SeedBytesPerEntry {
		t.Fatalf("the preflight asks for count x %d bytes and its refusal stops the capture: %v (asked %d)", SeedBytesPerEntry, err, asked)
	}
	if f.log.Requests("get-entries") != 0 {
		t.Fatal("nothing is fetched after a refused preflight")
	}
}

// copyWritable copies a published sample into a writable temp folder so a
// test can damage it.
func copyWritable(t *testing.T, s *Sample) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "copy")
	os.MkdirAll(dst, 0o755)
	for _, name := range []string{ManifestFile, EntriesFile, ProofsFile} {
		b, err := os.ReadFile(filepath.Join(s.Dir, name))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dst, name), b, 0o644)
	}
	return dst
}

func editJSON(t *testing.T, path string, edit func(map[string]any)) {
	t.Helper()
	b, _ := os.ReadFile(path)
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	edit(v)
	b, _ = json.Marshal(v)
	os.WriteFile(path, b, 0o644)
}

// resum records a file's new checksum in the manifest, as a careless editor
// would: checksums alone must not be the only defence.
func resum(t *testing.T, dir, name string) {
	t.Helper()
	sum, err := fileSum(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	editJSON(t, filepath.Join(dir, ManifestFile), func(m map[string]any) {
		m["files"].(map[string]any)[name] = map[string]any{"sha256": sum.SHA256, "bytes": sum.Bytes}
	})
}

func TestOpenDetectsTampering(t *testing.T) {
	f := newFixture(t, 120)
	s, err := f.capture(t, Canonical, 0, 32, "")
	if err != nil {
		t.Fatal(err)
	}
	for name, damage := range map[string]func(dir string){
		"entries byte flipped": func(dir string) {
			p := filepath.Join(dir, EntriesFile)
			b, _ := os.ReadFile(p)
			b[len(b)/2] ^= 1
			os.WriteFile(p, b, 0o644)
		},
		"proof removed, checksum updated": func(dir string) {
			editJSON(t, filepath.Join(dir, ProofsFile), func(p map[string]any) {
				p["consistency"] = p["consistency"].([]any)[1:]
			})
			resum(t, dir, ProofsFile)
		},
		"proof node altered, checksum updated": func(dir string) {
			editJSON(t, filepath.Join(dir, ProofsFile), func(p map[string]any) {
				c := p["consistency"].([]any)[0].(map[string]any)
				c["nodes"].([]any)[0] = base64.StdEncoding.EncodeToString(make([]byte, 32))
			})
			resum(t, dir, ProofsFile)
		},
		"head signature altered": func(dir string) {
			editJSON(t, filepath.Join(dir, ManifestFile), func(m map[string]any) {
				raw, _ := base64.StdEncoding.DecodeString(m["head_raw"].(string))
				raw = bytes.Replace(raw, []byte(`"timestamp":`), []byte(`"timestamp":1`), 1)
				m["head_raw"] = base64.StdEncoding.EncodeToString(raw)
			})
		},
		"other log's key": func(dir string) {
			other := ctlogtest.New(t, 1, ctlogtest.Options{})
			editJSON(t, filepath.Join(dir, ManifestFile), func(m map[string]any) {
				m["log"].(map[string]any)["key"] = base64.StdEncoding.EncodeToString(other.PublicKeyDER)
			})
		},
	} {
		dir := copyWritable(t, s)
		if _, err := Open(dir); err != nil {
			t.Fatalf("%s: the undamaged copy must verify: %v", name, err)
		}
		damage(dir)
		if _, err := Open(dir); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: want ErrCorrupt, got %v", name, err)
		}
	}
}

// TestCommitRefusesEntriesThatDoNotMatchTheProofs: an entry changed before
// publishing (new checksums and all) fails the Merkle check, and nothing is
// published.
func TestCommitRefusesEntriesThatDoNotMatchTheProofs(t *testing.T) {
	f := newFixture(t, 120)
	s, err := f.capture(t, Canonical, 0, 16, "")
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(f.dir, "fakelog", "forged")
	w, err := Create(dest, s.Manifest, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Abort()
	s.Each(func(e Entry) error {
		if e.Index == 9 {
			e.LeafInput = append([]byte(nil), e.LeafInput...)
			e.LeafInput[20] ^= 1
		}
		return w.Add(logsource.RawEntry{Index: e.Index, LeafInput: e.LeafInput, ExtraData: e.ExtraData})
	})
	if _, err := w.Commit(s.Proofs); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("want ErrCorrupt, got %v", err)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("a sample that fails verification must never become visible")
	}
}

func TestEntriesFileIsOneZstdStream(t *testing.T) {
	f := newFixture(t, 120)
	s, err := f.capture(t, Canonical, 0, 24, "")
	if err != nil {
		t.Fatal(err)
	}
	fh, _ := os.Open(filepath.Join(s.Dir, EntriesFile))
	defer fh.Close()
	dec, err := zstd.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Close()
	sc := bufio.NewScanner(dec)
	sc.Buffer(nil, maxLine)
	n := 0
	for sc.Scan() {
		n++
	}
	if sc.Err() != nil || n != 24 {
		t.Fatalf("plain zstd tools must read every line: %d lines, %v", n, sc.Err())
	}
}

func TestReplayServesTheSample(t *testing.T) {
	f := newFixture(t, 120)
	s, err := f.capture(t, Representative, 16, 32, "")
	if err != nil {
		t.Fatal(err)
	}
	url, stop, err := Serve(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if !strings.HasPrefix(url, "http://127.0.0.1:") {
		t.Fatalf("replay must listen on loopback only: %s", url)
	}
	info := f.src.Info()
	info.URL = url
	src := rfc6962.NewSource(info, nil, logsource.NewChainCache(logsource.DefaultChainCacheBytes), nil)
	head, err := src.Head(context.Background())
	if err != nil || !bytes.Equal(head.Raw, s.Manifest.HeadRaw) {
		t.Fatalf("get-sth must return the captured head byte for byte: %v", err)
	}
	next := uint64(16)
	st, err := fetch.Run(context.Background(), src, 16, 48, f.opts.Fetch, func(e logsource.RawEntry) error {
		if e.Index != next || !bytes.Equal(e.LeafInput, f.log.Entries[e.Index].LeafInput) {
			t.Fatalf("replayed entry %d differs", e.Index)
		}
		next++
		return nil
	})
	if err != nil || next != 48 || st.LargestResponse != 4 {
		t.Fatalf("replay: %v, next %d, page %d (captured page size 4)", err, next, st.LargestResponse)
	}
	if p, err := src.ConsistencyProof(context.Background(), 48, 120); err != nil || len(p) == 0 {
		t.Fatalf("stored consistency proof: %v", err)
	}
	idx, _, err := src.Client().GetProofByHash(context.Background(), s.Proofs.Inclusion.LeafHash, 120)
	if err != nil || idx != 16 {
		t.Fatalf("stored inclusion proof: %d %v", idx, err)
	}
	if _, err := src.Fetch(context.Background(), 48, 50); err == nil {
		t.Fatal("entries outside the sample are refused")
	}
}
```

Run: `go test ./internal/sample/`
Expected: FAIL with `no required module provides package github.com/klauspost/compress/zstd`.

- [ ] **Step 4: Implement the sample package**

```bash
go get github.com/klauspost/compress@v1.20.1
```

Create `internal/sample/manifest.go`:

```go
// Package sample captures, verifies and replays real-data samples of a CT log
// (amendment A1 §2). It is dev-only: production binaries must never import it
// (cmd/ctvault's guard test enforces this).
//
// A sample is a read-only folder:
//
//	sample.json          the manifest (Manifest)
//	entries.ndjson.zst   one JSON line per entry, {"i", "leaf_input", "extra_data"}, bytes exactly
//	                     as served; one zstd frame per Boundary entries, offsets in Manifest.Frames
//	proofs.json          the Merkle proofs that authenticate the entries against the signed head
package sample

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Format is the sample format version.
const Format = 1

// File names inside a sample folder.
const (
	ManifestFile = "sample.json"
	EntriesFile  = "entries.ndjson.zst"
	ProofsFile   = "proofs.json"
)

// Kind is canonical (fixed forever, may feed a dev vault) or representative
// (a window for measurements only).
type Kind string

const (
	Canonical      Kind = "canonical"
	Representative Kind = "representative"
)

// Limits are the size rules: Min <= count <= Max, and start and count are
// multiples of Boundary.
type Limits struct {
	Boundary, Min, Max uint64
}

// DefaultLimits are amendment A1 §2.1's rules.
var DefaultLimits = Limits{Boundary: 5000, Min: 50_000, Max: 500_000}

// Check validates a sample's start and count.
func (l Limits) Check(kind Kind, start, count uint64) error {
	switch {
	case kind != Canonical && kind != Representative:
		return fmt.Errorf("sample: unknown kind %q", kind)
	case count < l.Min || count > l.Max || count%l.Boundary != 0:
		return fmt.Errorf("sample: --entries must be %d-%d and a multiple of %d, got %d", l.Min, l.Max, l.Boundary, count)
	case kind == Canonical && start != 0:
		return errors.New("sample: a canonical sample starts at index 0")
	case start%l.Boundary != 0:
		return fmt.Errorf("sample: --start must be a multiple of %d, got %d", l.Boundary, start)
	}
	return nil
}

// StartForHead is "--start head": the last whole window that fits under the
// tree, floor((treeSize - count) / boundary) * boundary.
func (l Limits) StartForHead(treeSize, count uint64) (uint64, error) {
	if treeSize < count {
		return 0, fmt.Errorf("sample: the log has %d entries, fewer than the %d requested", treeSize, count)
	}
	return (treeSize - count) / l.Boundary * l.Boundary, nil
}

var validSuffix = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// DirName is "<first>-<last>" with 12-digit indexes (last inclusive, as in
// batch IDs), plus "_<suffix>" when given.
func DirName(start, count uint64, suffix string) (string, error) {
	name := fmt.Sprintf("%012d-%012d", start, start+count-1)
	if suffix == "" {
		return name, nil
	}
	if !validSuffix.MatchString(suffix) {
		return "", fmt.Errorf("sample: --suffix must match %s", validSuffix)
	}
	return name + "_" + suffix, nil
}

// LogRef identifies the log as pinned from Chrome's log list at capture.
type LogRef struct {
	Name           string `json:"name"`
	LogID          string `json:"log_id"` // base64, SHA-256 of Key
	Key            string `json:"key"`    // base64 SubjectPublicKeyInfo
	URL            string `json:"url"`
	LogListVersion string `json:"log_list_version"`
}

// FileSum is a file's size and SHA-256.
type FileSum struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// HeadSummary repeats the signed head's fields for people reading the
// manifest; HeadRaw is the authoritative copy.
type HeadSummary struct {
	TreeSize  uint64 `json:"tree_size"`
	Timestamp uint64 `json:"timestamp"`
	RootHash  string `json:"sha256_root_hash"`
}

// Manifest is sample.json.
type Manifest struct {
	Format         int                `json:"format"`
	Kind           Kind               `json:"kind"`
	Log            LogRef             `json:"log"`
	HeadRaw        []byte             `json:"head_raw"` // get-sth body exactly as received (base64 in JSON)
	Head           HeadSummary        `json:"head"`
	Start          uint64             `json:"start"`
	Count          uint64             `json:"count"`
	Boundary       uint64             `json:"boundary"`
	PageSize       int                `json:"page_size"` // most entries the log served per get-entries
	Frames         []int64            `json:"frames"`    // offset of each zstd frame in EntriesFile
	CapturedAt     time.Time          `json:"captured_at"`
	CTVaultVersion string             `json:"ctvault_version"`
	Files          map[string]FileSum `json:"files"`
}

// ID is "<log>/<folder name>", the sample ID used in measurement reports.
func (m Manifest) ID(dirName string) string { return m.Log.Name + "/" + dirName }

// Node is a Merkle hash, base64 in JSON.
type Node [32]byte

func (n Node) MarshalText() ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(n[:])), nil
}

func (n *Node) UnmarshalText(b []byte) error {
	d, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil || len(d) != 32 {
		return errors.New("sample: a proof node is not a base64 32-byte hash")
	}
	copy(n[:], d)
	return nil
}

func nodes(p [][32]byte) []Node {
	out := make([]Node, len(p))
	for i := range p {
		out[i] = p[i]
	}
	return out
}

func hashes(p []Node) [][32]byte {
	out := make([][32]byte, len(p))
	for i := range p {
		out[i] = p[i]
	}
	return out
}

// Consistency is a consistency proof from First to Second.
type Consistency struct {
	First  uint64 `json:"first"`
	Second uint64 `json:"second"`
	Nodes  []Node `json:"nodes"`
}

// Inclusion is the inclusion proof of the representative window's first leaf.
type Inclusion struct {
	LeafIndex uint64 `json:"leaf_index"`
	TreeSize  uint64 `json:"tree_size"`
	LeafHash  Node   `json:"leaf_hash"`
	AuditPath []Node `json:"audit_path"`
}

// Proofs is proofs.json.
type Proofs struct {
	Consistency []Consistency `json:"consistency"`
	Inclusion   *Inclusion    `json:"inclusion,omitempty"`
}

func (p Proofs) find(first, second uint64) (Consistency, bool) {
	for _, c := range p.Consistency {
		if c.First == first && c.Second == second {
			return c, true
		}
	}
	return Consistency{}, false
}
```

Create `internal/sample/writer.go`:

```go
package sample

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/sys/unix"

	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/logsource"
)

// ErrExists means the destination sample already exists. Samples are never
// overwritten; capture the same range again with a new --suffix.
var ErrExists = errors.New("sample already exists")

// CheckEvery is how often, in bytes written, the writer calls its disk check.
const CheckEvery = 64 << 20

// line is one entries.ndjson line; []byte fields encode as standard base64.
type line struct {
	Index     uint64 `json:"i"`
	LeafInput []byte `json:"leaf_input"`
	ExtraData []byte `json:"extra_data"`
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// Writer streams a sample into a staging folder next to its destination.
// Nothing becomes visible until Commit has verified the whole sample.
type Writer struct {
	dest, staging string
	m             Manifest
	f             *os.File
	cw            *countingWriter
	enc           *zstd.Encoder
	next          uint64
	inFrame       uint64
	check         func(written int64) error
	lastCheck     int64
}

// Create starts a sample for dest. check, if set, is called every CheckEvery
// bytes with the bytes written so far, and its error aborts the capture.
func Create(dest string, m Manifest, check func(written int64) error) (*Writer, error) {
	if _, err := os.Lstat(dest); err == nil {
		return nil, fmt.Errorf("%w: %s", ErrExists, dest)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	parent := filepath.Dir(dest)
	if err := fsutil.MkdirAllSync(parent, 0o755); err != nil {
		return nil, err
	}
	staging, err := os.MkdirTemp(parent, ".staging-"+filepath.Base(dest)+"-")
	if err != nil {
		return nil, err
	}
	f, err := os.Create(filepath.Join(staging, EntriesFile))
	if err != nil {
		os.RemoveAll(staging)
		return nil, err
	}
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		f.Close()
		os.RemoveAll(staging)
		return nil, err
	}
	m.Frames = nil
	return &Writer{dest: dest, staging: staging, m: m, f: f, cw: &countingWriter{w: f}, enc: enc,
		next: m.Start, check: check}, nil
}

// Staging returns the staging folder (for tests and error messages).
func (w *Writer) Staging() string { return w.staging }

// Add appends the next entry; indexes must be consecutive from Start.
func (w *Writer) Add(e logsource.RawEntry) error {
	if e.Index != w.next || e.Index >= w.m.Start+w.m.Count {
		return fmt.Errorf("sample: got entry %d, want %d", e.Index, w.next)
	}
	if w.inFrame == 0 {
		w.m.Frames = append(w.m.Frames, w.cw.n)
		w.enc.Reset(w.cw)
	}
	b, err := json.Marshal(line{Index: e.Index, LeafInput: e.LeafInput, ExtraData: e.ExtraData})
	if err != nil {
		return err
	}
	if _, err := w.enc.Write(append(b, '\n')); err != nil {
		return err
	}
	w.next++
	if w.inFrame++; w.inFrame == w.m.Boundary {
		if err := w.enc.Close(); err != nil {
			return err
		}
		w.inFrame = 0
	}
	if w.check != nil && w.cw.n-w.lastCheck >= CheckEvery {
		w.lastCheck = w.cw.n
		return w.check(w.cw.n)
	}
	return nil
}

// Commit writes the proofs and the manifest, verifies the staged sample with
// the same checks as every later load, makes it read-only and renames it into
// place without replacing anything. It returns the opened sample.
func (w *Writer) Commit(p Proofs) (*Sample, error) {
	if w.next != w.m.Start+w.m.Count || w.inFrame != 0 {
		return nil, fmt.Errorf("sample: %d of %d entries written", w.next-w.m.Start, w.m.Count)
	}
	if err := w.f.Sync(); err != nil {
		return nil, err
	}
	if err := w.f.Close(); err != nil {
		return nil, err
	}
	w.f = nil
	pb, err := json.MarshalIndent(p, "", " ")
	if err != nil {
		return nil, err
	}
	if err := writeSynced(filepath.Join(w.staging, ProofsFile), pb); err != nil {
		return nil, err
	}
	w.m.Files = map[string]FileSum{}
	for _, name := range []string{EntriesFile, ProofsFile} {
		sum, err := fileSum(filepath.Join(w.staging, name))
		if err != nil {
			return nil, err
		}
		w.m.Files[name] = sum
	}
	mb, err := json.MarshalIndent(w.m, "", " ")
	if err != nil {
		return nil, err
	}
	if err := writeSynced(filepath.Join(w.staging, ManifestFile), mb); err != nil {
		return nil, err
	}
	if _, err := Open(w.staging); err != nil {
		return nil, fmt.Errorf("sample: verification before publishing failed: %w", err)
	}
	for _, name := range []string{EntriesFile, ProofsFile, ManifestFile} {
		if err := os.Chmod(filepath.Join(w.staging, name), 0o444); err != nil {
			return nil, err
		}
	}
	if err := os.Chmod(w.staging, 0o555); err != nil {
		return nil, err
	}
	if err := fsutil.SyncDir(w.staging); err != nil {
		return nil, err
	}
	parent := filepath.Dir(w.dest)
	if err := unix.Renameat2(unix.AT_FDCWD, w.staging, unix.AT_FDCWD, w.dest, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			err = fmt.Errorf("%w: %s", ErrExists, w.dest)
		}
		return nil, err
	}
	w.staging = ""
	if err := fsutil.SyncDir(parent); err != nil {
		return nil, err
	}
	return Open(w.dest)
}

// Abort removes the staging folder. It is safe after a failed Commit and a
// no-op after a successful one.
func (w *Writer) Abort() {
	if w.f != nil {
		w.f.Close()
		w.f = nil
	}
	w.enc.Close()
	if w.staging == "" {
		return
	}
	os.Chmod(w.staging, 0o755)
	os.RemoveAll(w.staging)
	w.staging = ""
}

func writeSynced(path string, b []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func fileSum(path string) (FileSum, error) {
	f, err := os.Open(path)
	if err != nil {
		return FileSum{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return FileSum{}, err
	}
	return FileSum{SHA256: hex.EncodeToString(h.Sum(nil)), Bytes: n}, nil
}
```

Create `internal/sample/read.go`:

```go
package sample

import (
	"bufio"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"

	"github.com/4rji/ctvault/internal/loglist"
	"github.com/4rji/ctvault/internal/merkle"
)

// ErrCorrupt means a sample failed verification: a checksum, the signed
// head, an entry or a Merkle proof. A corrupt sample is never used.
var ErrCorrupt = errors.New("sample failed verification")

// maxLine bounds one entries.ndjson line (an entry with a long chain is a few
// tens of KiB in base64).
const maxLine = 16 << 20

// Entry is one sampled log entry, bytes exactly as served.
type Entry = line

// Sample is a verified sample.
type Sample struct {
	Dir      string
	Manifest Manifest
	Head     merkle.SignedTreeHead
	Proofs   Proofs
	pub      crypto.PublicKey
}

// Open loads and fully verifies the sample in dir (amendment A1 §2.4):
// file checksums, the signed head with the pinned key, every entry, and the
// Merkle proofs that tie the entries to the signed root.
func Open(dir string) (*Sample, error) {
	s, err := load(dir)
	if err != nil {
		return nil, err
	}
	if err := s.verifyMerkle(); err != nil {
		return nil, err
	}
	return s, nil
}

func corrupt(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(format, args...))
}

func load(dir string) (*Sample, error) {
	s := &Sample{Dir: dir}
	b, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.Manifest); err != nil {
		return nil, corrupt("%s: %v", ManifestFile, err)
	}
	m := s.Manifest
	if m.Format != Format {
		return nil, corrupt("unsupported format %d", m.Format)
	}
	lim := Limits{Boundary: m.Boundary, Min: 1, Max: ^uint64(0)}
	if m.Boundary == 0 || lim.Check(m.Kind, m.Start, m.Count) != nil || uint64(len(m.Frames)) != m.Count/m.Boundary {
		return nil, corrupt("inconsistent range: start %d, count %d, boundary %d, %d frames", m.Start, m.Count, m.Boundary, len(m.Frames))
	}
	for _, name := range []string{EntriesFile, ProofsFile} {
		want, ok := m.Files[name]
		got, err := fileSum(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		if !ok || got != want {
			return nil, corrupt("%s: sha256 %s (%d bytes), manifest records %s (%d bytes)", name, got.SHA256, got.Bytes, want.SHA256, want.Bytes)
		}
	}
	if s.pub, err = loglist.ParseKey(m.Log.Key, m.Log.LogID); err != nil {
		return nil, corrupt("pinned key: %v", err)
	}
	var head struct {
		TreeSize  *uint64 `json:"tree_size"`
		Timestamp uint64  `json:"timestamp"`
		Root      []byte  `json:"sha256_root_hash"`
		Sig       []byte  `json:"tree_head_signature"`
	}
	if err := json.Unmarshal(m.HeadRaw, &head); err != nil || head.TreeSize == nil || len(head.Root) != 32 {
		return nil, corrupt("signed head is unreadable")
	}
	s.Head = merkle.SignedTreeHead{TreeSize: *head.TreeSize, Timestamp: head.Timestamp, Signature: head.Sig}
	copy(s.Head.RootHash[:], head.Root)
	if err := merkle.VerifySTH(s.pub, s.Head); err != nil {
		return nil, corrupt("signed head: %v", err)
	}
	if m.Start+m.Count > s.Head.TreeSize {
		return nil, corrupt("entries end at %d, beyond the signed tree of %d", m.Start+m.Count, s.Head.TreeSize)
	}
	pb, err := os.ReadFile(filepath.Join(dir, ProofsFile))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(pb, &s.Proofs); err != nil {
		return nil, corrupt("%s: %v", ProofsFile, err)
	}
	return s, nil
}

// Frame decodes frame k: entries [Start + k*Boundary, Start + (k+1)*Boundary).
func (s *Sample) Frame(k int) ([]Entry, error) {
	m := s.Manifest
	if k < 0 || k >= len(m.Frames) {
		return nil, fmt.Errorf("sample: no frame %d", k)
	}
	end := m.Files[EntriesFile].Bytes
	if k+1 < len(m.Frames) {
		end = m.Frames[k+1]
	}
	f, err := os.Open(filepath.Join(s.Dir, EntriesFile))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if m.Frames[k] < 0 || end < m.Frames[k] {
		return nil, corrupt("frame %d has offsets %d-%d", k, m.Frames[k], end)
	}
	dec, err := zstd.NewReader(io.NewSectionReader(f, m.Frames[k], end-m.Frames[k]), zstd.WithDecoderConcurrency(1))
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	first := m.Start + uint64(k)*m.Boundary
	out := make([]Entry, 0, m.Boundary)
	sc := bufio.NewScanner(dec)
	sc.Buffer(make([]byte, 64<<10), maxLine)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, corrupt("frame %d line %d: %v", k, len(out)+1, err)
		}
		if e.Index != first+uint64(len(out)) || e.LeafInput == nil || e.ExtraData == nil {
			return nil, corrupt("frame %d: entry %d out of place", k, e.Index)
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, corrupt("frame %d: %v", k, err)
	}
	if uint64(len(out)) != m.Boundary {
		return nil, corrupt("frame %d holds %d entries, want %d", k, len(out), m.Boundary)
	}
	return out, nil
}

// Each calls fn for every entry in index order.
func (s *Sample) Each(fn func(Entry) error) error {
	for k := range s.Manifest.Frames {
		entries, err := s.Frame(k)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := fn(e); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkpoint verifies the accumulated range at size m against the head.
func (s *Sample) checkpoint(st *merkle.State) error {
	m, size := st.Size(), s.Head.TreeSize
	root, err := st.Root()
	if err != nil {
		return err
	}
	if m == size {
		if root != s.Head.RootHash {
			return corrupt("root at %d differs from the signed root", m)
		}
		return nil
	}
	c, ok := s.Proofs.find(m, size)
	if !ok {
		return corrupt("no consistency proof from %d to %d", m, size)
	}
	if err := merkle.VerifyConsistency(m, size, root, s.Head.RootHash, hashes(c.Nodes)); err != nil {
		return corrupt("entries up to %d: %v", m, err)
	}
	return nil
}

func (s *Sample) verifyMerkle() error {
	m := s.Manifest
	var st *merkle.State
	switch m.Kind {
	case Canonical:
		st = merkle.NewState()
	case Representative:
		inc := s.Proofs.Inclusion
		if inc == nil || inc.LeafIndex != m.Start || inc.TreeSize != s.Head.TreeSize {
			return corrupt("representative sample lacks the inclusion proof of leaf %d", m.Start)
		}
		var err error
		if st, err = merkle.StateFromInclusion(m.Start, s.Head.TreeSize, inc.LeafHash, s.Head.RootHash, hashes(inc.AuditPath)); err != nil {
			return corrupt("%v", err)
		}
	}
	err := s.Each(func(e Entry) error {
		h := merkle.LeafHash(e.LeafInput)
		if e.Index == m.Start && m.Kind == Representative && h != s.Proofs.Inclusion.LeafHash {
			return corrupt("entry %d is not the leaf the inclusion proof covers", e.Index)
		}
		if err := st.Append(h); err != nil {
			return err
		}
		if m.Kind == Canonical && (e.Index+1-m.Start)%m.Boundary == 0 {
			return s.checkpoint(st)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if m.Kind == Representative {
		return s.checkpoint(st)
	}
	return nil
}

// LogIDBytes returns the sampled log's ID.
func (s *Sample) LogIDBytes() [32]byte {
	var id [32]byte
	b, _ := base64.StdEncoding.DecodeString(s.Manifest.Log.LogID)
	copy(id[:], b)
	return id
}
```

Create `internal/sample/replay.go`:

```go
package sample

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Replay serves a verified sample as an RFC 6962 log on loopback, so the real
// client and fetcher run unchanged (amendment A1 §2.5): get-sth returns the
// captured head byte for byte, get-entries serves at the captured page size,
// and the stored proofs answer get-sth-consistency and get-proof-by-hash.
type Replay struct {
	s *Sample

	mu    sync.Mutex
	cache map[int][]Entry // decoded frames, at most two
	order []int
}

// NewReplay returns the handler for s.
func NewReplay(s *Sample) *Replay { return &Replay{s: s, cache: map[int][]Entry{}} }

func (rp *Replay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/ct/v1/get-sth":
		w.Header().Set("Content-Type", "application/json")
		w.Write(rp.s.Manifest.HeadRaw)
	case "/ct/v1/get-entries":
		rp.entries(w, r)
	case "/ct/v1/get-sth-consistency":
		first, err1 := strconv.ParseUint(r.URL.Query().Get("first"), 10, 64)
		second, err2 := strconv.ParseUint(r.URL.Query().Get("second"), 10, 64)
		c, ok := rp.s.Proofs.find(first, second)
		if err1 != nil || err2 != nil || !ok {
			http.Error(w, "no stored proof for this range", http.StatusBadRequest)
			return
		}
		reply(w, map[string]any{"consistency": c.Nodes})
	case "/ct/v1/get-proof-by-hash":
		inc := rp.s.Proofs.Inclusion
		h, _ := base64.StdEncoding.DecodeString(r.URL.Query().Get("hash"))
		size, _ := strconv.ParseUint(r.URL.Query().Get("tree_size"), 10, 64)
		if inc == nil || string(h) != string(inc.LeafHash[:]) || size != inc.TreeSize {
			http.Error(w, "no stored proof for this leaf", http.StatusNotFound)
			return
		}
		reply(w, map[string]any{"leaf_index": inc.LeafIndex, "audit_path": inc.AuditPath})
	default:
		http.NotFound(w, r)
	}
}

func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (rp *Replay) entries(w http.ResponseWriter, r *http.Request) {
	m := rp.s.Manifest
	start, err1 := strconv.ParseUint(r.URL.Query().Get("start"), 10, 64)
	end, err2 := strconv.ParseUint(r.URL.Query().Get("end"), 10, 64)
	if err1 != nil || err2 != nil || end < start || start < m.Start || start >= m.Start+m.Count {
		http.Error(w, "range outside the sample", http.StatusBadRequest)
		return
	}
	end = min(end, start+uint64(max(m.PageSize, 1))-1, m.Start+m.Count-1)
	type wire struct {
		LeafInput []byte `json:"leaf_input"`
		ExtraData []byte `json:"extra_data"`
	}
	out := make([]wire, 0, end-start+1)
	for i := start; i <= end; i++ {
		e, err := rp.entry(i)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out = append(out, wire{e.LeafInput, e.ExtraData})
	}
	reply(w, map[string]any{"entries": out})
}

// entry returns entry i, decoding its frame if it is not one of the two most
// recently used.
func (rp *Replay) entry(i uint64) (Entry, error) {
	m := rp.s.Manifest
	k := int((i - m.Start) / m.Boundary)
	rp.mu.Lock()
	defer rp.mu.Unlock()
	frame, ok := rp.cache[k]
	if !ok {
		var err error
		if frame, err = rp.s.Frame(k); err != nil {
			return Entry{}, err
		}
		rp.cache[k] = frame
		rp.order = append(rp.order, k)
		if len(rp.order) > 2 {
			delete(rp.cache, rp.order[0])
			rp.order = rp.order[1:]
		}
	}
	return frame[(i-m.Start)%m.Boundary], nil
}

// Serve listens on 127.0.0.1 and serves the sample until ctx ends. It
// returns the log URL (ending in "/") and a function that stops the server.
func Serve(ctx context.Context, s *Sample) (string, func(), error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	srv := &http.Server{Handler: NewReplay(s), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			ln.Close()
		}
	}()
	stop := func() { srv.Close() }
	context.AfterFunc(ctx, stop)
	return "http://" + ln.Addr().String() + "/", stop, nil
}
```

Create `internal/sample/capture.go`:

```go
package sample

import (
	"context"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"time"

	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/loglist"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
)

// CaptureOptions describes one capture.
type CaptureOptions struct {
	Kind           Kind
	Start          uint64 // representative only
	StartAtHead    bool   // representative only: "--start head", resolved from the pinned head
	Count          uint64
	Suffix         string
	Limits         Limits        // zero means DefaultLimits
	Fetch          fetch.Options // workers, rate and stall timeout
	Key            string        // base64 SPKI pinned from the log list
	LogListVersion string
	Version        string // CTVault version for the manifest
	Now            func() time.Time
	// Check, if set, is the disk guard: called before the capture with the
	// estimated size, then every CheckEvery bytes written.
	Check    func(need int64) error
	Progress func(done, total uint64) // called after every frame
}

// SeedBytesPerEntry is the disk-guard preflight estimate of a sample's size:
// the uncompressed JSON size of an entry as served (spec §3.2: 7,409 B). It is
// deliberately conservative: 32,768 real argon2027h1 entries took 900 B each
// in entries.ndjson.zst (measured 2026-10-04).
const SeedBytesPerEntry = 7409

// Capture pins the log's current signed head, fetches the range through the
// real fetcher, collects the proofs and publishes the verified sample under
// samplesDir/<log>/<folder>. On any failure or cancellation nothing becomes
// visible.
func Capture(ctx context.Context, samplesDir string, src *rfc6962.Source, o CaptureOptions) (*Sample, error) {
	if o.Limits == (Limits{}) {
		o.Limits = DefaultLimits
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.StartAtHead && o.Kind != Representative {
		return nil, fmt.Errorf("sample: --start head is for representative samples")
	}
	// Check everything that does not depend on the log before contacting it.
	if o.StartAtHead {
		o.Start = 0
	}
	if err := o.Limits.Check(o.Kind, o.Start, o.Count); err != nil {
		return nil, err
	}
	if _, err := DirName(o.Start, o.Count, o.Suffix); err != nil {
		return nil, err
	}
	info := src.Info()
	var head logsource.SignedHead
	if err := fetch.Retry(ctx, o.Fetch, func(ctx context.Context) (err error) {
		head, err = src.Head(ctx)
		return err
	}); err != nil {
		return nil, err
	}
	if o.StartAtHead {
		var err error
		if o.Start, err = o.Limits.StartForHead(head.TreeSize, o.Count); err != nil {
			return nil, err
		}
	}
	name, err := DirName(o.Start, o.Count, o.Suffix)
	if err != nil {
		return nil, err
	}
	if o.Start+o.Count > head.TreeSize {
		return nil, fmt.Errorf("sample: the log currently has only %d entries; [%d, %d) does not fit", head.TreeSize, o.Start, o.Start+o.Count)
	}
	if o.Check != nil {
		if err := o.Check(int64(o.Count) * SeedBytesPerEntry); err != nil {
			return nil, err
		}
	}
	m := Manifest{
		Format: Format, Kind: o.Kind, Start: o.Start, Count: o.Count, Boundary: o.Limits.Boundary,
		Log: LogRef{Name: info.Name, LogID: base64.StdEncoding.EncodeToString(info.LogID[:]), Key: o.Key,
			URL: info.URL, LogListVersion: o.LogListVersion},
		HeadRaw: head.Raw,
		Head: HeadSummary{TreeSize: head.TreeSize, Timestamp: head.Timestamp,
			RootHash: base64.StdEncoding.EncodeToString(head.RootHash[:])},
		CapturedAt: o.Now().UTC(), CTVaultVersion: o.Version,
	}
	if _, err := loglist.ParseKey(o.Key, m.Log.LogID); err != nil {
		return nil, fmt.Errorf("sample: log %s: %w", info.Name, err)
	}
	dest := filepath.Join(samplesDir, info.Name, name)
	var check func(int64) error
	if o.Check != nil {
		check = func(int64) error { return o.Check(CheckEvery) }
	}
	w, err := Create(dest, m, check)
	if err != nil {
		return nil, err
	}
	defer w.Abort()

	var first [32]byte
	end := o.Start + o.Count
	st, err := fetch.Run(ctx, src, o.Start, end, o.Fetch, func(e logsource.RawEntry) error {
		if e.Index == o.Start {
			first = e.Leaf.LeafHash
		}
		if err := w.Add(e); err != nil {
			return err
		}
		if o.Progress != nil && (e.Index+1-o.Start)%o.Limits.Boundary == 0 {
			o.Progress(e.Index+1-o.Start, o.Count)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	w.m.PageSize = st.LargestResponse

	var p Proofs
	proof := func(first, second uint64) error {
		if first == second {
			return nil
		}
		var ns [][32]byte
		if err := fetch.Retry(ctx, o.Fetch, func(ctx context.Context) (err error) {
			ns, err = src.ConsistencyProof(ctx, first, second)
			return err
		}); err != nil {
			return fmt.Errorf("consistency proof %d → %d: %w", first, second, err)
		}
		p.Consistency = append(p.Consistency, Consistency{First: first, Second: second, Nodes: nodes(ns)})
		return nil
	}
	switch o.Kind {
	case Canonical:
		for b := o.Start + o.Limits.Boundary; b <= end; b += o.Limits.Boundary {
			if err := proof(b, head.TreeSize); err != nil {
				return nil, err
			}
		}
	case Representative:
		var idx uint64
		var path [][32]byte
		if err := fetch.Retry(ctx, o.Fetch, func(ctx context.Context) (err error) {
			idx, path, err = src.Client().GetProofByHash(ctx, first, head.TreeSize)
			return err
		}); err != nil {
			return nil, fmt.Errorf("inclusion proof of leaf %d: %w", o.Start, err)
		}
		if idx != o.Start {
			return nil, fmt.Errorf("sample: leaf %d also appears at index %d, so the log proves that one; choose another --start", o.Start, idx)
		}
		p.Inclusion = &Inclusion{LeafIndex: idx, TreeSize: head.TreeSize, LeafHash: first, AuditPath: nodes(path)}
		if err := proof(end, head.TreeSize); err != nil {
			return nil, err
		}
	}
	return w.Commit(p)
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go mod tidy && go test -race -count=1 ./internal/sample/ -v`
Expected: PASS:
- `TestCaptureCanonical`, `TestCaptureRepresentative`, `TestCaptureAtTheHead`
- `TestCaptureRefusals`, `TestCaptureNeverOverwritesAndLeavesNothingOnFailure`, `TestDiskCheckAbortsCapture`
- `TestOpenDetectsTampering`, `TestCommitRefusesEntriesThatDoNotMatchTheProofs`
- `TestEntriesFileIsOneZstdStream`, `TestReplayServesTheSample`

Then run `ls -d /tmp/Test* 2>/dev/null`. Expected: nothing. The fixture's cleanup makes the read-only samples writable, so `t.TempDir` can remove them.

- [ ] **Step 6: Gate and commit**

Run the four gate commands. All must pass. `TestProductionBinaryExcludesDevCode` must still pass, because nothing in production imports `sample`.

```bash
git add go.mod go.sum internal/merkle internal/sample
git commit -m "feat: verified real-data samples (capture, verify on load, loopback replay); inclusion-derived ranges; safe zero State (minor 16)"
```

---

### Task A8: Dev sample commands, real-data tests and docs

Implements amendment A1 §2.3 commands, §2.5 (`sampletest`) and §9 (the real-data layer of the test matrix), plus the documentation part of task 16.

**Files:**
- Modify: `internal/cli/cli.go`, `cmd/ctvault/deps_dev.go`, `internal/cli/build_prod_test.go`, `README.md`
- Create: `internal/cli/sample_dev.go`
- Create test: `internal/cli/sample_dev_test.go`
- Create: `internal/sampletest/sampletest.go`
- Create: `internal/integration/doc.go`, `internal/integration/realdata_test.go`

**Interfaces:**
- Consumes:
  - From Task A7: `sample.Capture`, `CaptureOptions` (with `StartAtHead`), `Open`, `Serve`, `Representatives`
  - Task A6: `stop.OnSignals`
  - Task A5: `logsource.InfoFromRecord`
  - Task A2: `diskguard.Guard.Check`
  - Plan 1: `loglist.Fetch`, `Find`, `logreg.FromList`
- Produces:
  - `cli`:
    - `Deps.Statfs diskguard.StatFunc` (`DefaultDeps` sets `diskguard.Statfs`)
    - `Deps.DevBase string` (empty in production)
  - Dev build only:
    - `ctvault-dev sample capture --log <name> --entries N [--start S|head] [--suffix X] [--log-list URL]`
    - `ctvault-dev sample verify <dir>`
    - Exit codes: 2 for bad flags, 3 for the disk cap, 5 for a failed verification
  - `sampletest`:
    - `func Base(testing.TB) string`
    - `func Canonical(testing.TB, log string) *sample.Sample`, which skips with instructions when no sample is cached
    - `func Representatives(testing.TB, log string) []*sample.Sample`
    - `func Serve(testing.TB, *sample.Sample) *rfc6962.Source`
  - `go test -tags realdata ./internal/integration/`

- [ ] **Step 1: Write the failing CLI tests**

Create `internal/cli/sample_dev_test.go`:

```go
//go:build ctvault_dev

package cli

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/sample"
)

// sampleEnv points the dev CLI at a fake log named "fakelog" through a log
// list naming it, with sample limits small enough for a 120-entry log.
func sampleEnv(t *testing.T, used float64) (*env, *ctlogtest.Log) {
	t.Helper()
	l := ctlogtest.New(t, 120, ctlogtest.Options{PageSize: 4})
	list := map[string]any{"version": "test", "log_list_timestamp": "2026-10-04T00:00:00Z",
		"operators": []any{map[string]any{"name": "Test", "logs": []any{map[string]any{
			"description": "Test 'fakelog' log", "log_id": base64.StdEncoding.EncodeToString(l.LogID[:]),
			"key": base64.StdEncoding.EncodeToString(l.PublicKeyDER), "url": l.URL, "mmd": 86400,
			"state": map[string]any{"usable": map[string]any{"timestamp": "2026-01-01T00:00:00Z"}}}}}}}
	b, _ := json.Marshal(list)
	listPath := filepath.Join(t.TempDir(), "log_list.json")
	os.WriteFile(listPath, b, 0o644)

	e := newEnv(t, nil)
	e.deps.HTTP = &http.Client{}
	e.deps.LogListSource = listPath
	e.deps.DevBase = t.TempDir()
	t.Cleanup(func() {
		filepath.WalkDir(e.deps.DevBase, func(p string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				os.Chmod(p, 0o755)
			}
			return nil
		})
	})
	const total = 1 << 40
	e.deps.Statfs = func(string) (diskguard.Usage, error) {
		return diskguard.Usage{Total: total, Avail: uint64((1 - used) * total), Dev: 1}, nil
	}
	old := sampleLimits
	sampleLimits = sample.Limits{Boundary: 8, Min: 16, Max: 96}
	t.Cleanup(func() { sampleLimits = old })
	return e, l
}

func TestSampleCaptureAndVerify(t *testing.T) {
	e, _ := sampleEnv(t, 0.5)
	out := e.mustRun("sample", "capture", "--log", "fakelog", "--entries", "48")
	dir := filepath.Join(e.deps.DevBase, "samples", "fakelog", "000000000000-000000000047")
	if !strings.Contains(out, "captured and verified canonical sample fakelog/000000000000-000000000047") || !strings.Contains(out, dir) {
		t.Fatalf("capture output: %s", out)
	}
	if !strings.Contains(e.stderr.String(), "fetched 48 / 48 entries") {
		t.Fatalf("progress: %s", e.stderr)
	}
	if out := e.mustRun("sample", "verify", dir); !strings.Contains(out, "verified canonical sample") {
		t.Fatalf("verify output: %s", out)
	}
	if code := e.run("sample", "capture", "--log", "fakelog", "--entries", "48"); code != exitcode.Error || !strings.Contains(e.stderr.String(), "already exists") {
		t.Fatalf("an existing sample: exit %d, %s", code, e.stderr)
	}
	out = e.mustRun("sample", "capture", "--log", "fakelog", "--entries", "32", "--start", "head")
	if !strings.Contains(out, "representative sample fakelog/000000000088-000000000119") {
		t.Fatalf("--start head: %s", out)
	}
}

func TestSampleCaptureRefusals(t *testing.T) {
	e, l := sampleEnv(t, 0.5)
	for _, tc := range []struct {
		args []string
		code int
	}{
		{[]string{"--log", "fakelog", "--entries", "20"}, exitcode.Usage},
		{[]string{"--log", "fakelog", "--entries", "16", "--start", "abc"}, exitcode.Usage},
		{[]string{"--entries", "16"}, exitcode.Usage},
		{[]string{"--log", "nosuchlog", "--entries", "16"}, exitcode.Error},
	} {
		if code := e.run(append([]string{"sample", "capture"}, tc.args...)...); code != tc.code {
			t.Errorf("%v: exit %d, want %d (%s)", tc.args, code, tc.code, e.stderr)
		}
	}
	if l.Requests("all") != 0 {
		t.Fatal("refused captures must not contact the log")
	}
}

func TestSampleCaptureRespectsTheDiskCap(t *testing.T) {
	e, l := sampleEnv(t, 0.86) // the normal disk is already above the 85% cap
	if code := e.run("sample", "capture", "--log", "fakelog", "--entries", "16"); code != exitcode.DiskCap || !strings.Contains(e.stderr.String(), "disk cap") {
		t.Fatalf("exit %d, want %d: %s", code, exitcode.DiskCap, e.stderr)
	}
	if l.Requests("get-entries") != 0 {
		t.Fatal("nothing is fetched after a refused preflight")
	}
	if names, _ := filepath.Glob(filepath.Join(e.deps.DevBase, "samples", "fakelog", "*")); len(names) != 0 {
		t.Fatalf("nothing may be left behind: %v", names)
	}
}

func TestSampleVerifyRefusesDamage(t *testing.T) {
	e, _ := sampleEnv(t, 0.5)
	e.mustRun("sample", "capture", "--log", "fakelog", "--entries", "16")
	dir := filepath.Join(e.deps.DevBase, "samples", "fakelog", "000000000000-000000000015")
	os.Chmod(dir, 0o755)
	p := filepath.Join(dir, sample.EntriesFile)
	os.Chmod(p, 0o644)
	b, _ := os.ReadFile(p)
	b[len(b)/2] ^= 1
	os.WriteFile(p, b, 0o644)
	if code := e.run("sample", "verify", dir); code != exitcode.Verification {
		t.Fatalf("a damaged sample: exit %d, want %d: %s", code, exitcode.Verification, e.stderr)
	}
}
```

Replace `internal/cli/build_prod_test.go` (adds `TestProductionBuildHasNoSampleCommand`):

```go
//go:build !ctvault_dev

package cli

import (
	"strings"
	"testing"
)

func TestProductionBuildHasNoDevBanner(t *testing.T) {
	e := newEnv(t, realSTH(t))
	e.mustRun("version")
	if strings.Contains(e.stdout.String()+e.stderr.String(), "DEV BUILD") {
		t.Fatalf("production output mentions a dev build: %q %q", e.stdout, e.stderr)
	}
}

func TestProductionBuildHasNoSampleCommand(t *testing.T) {
	e := newEnv(t, realSTH(t))
	if code := e.run("sample", "verify", "x"); code == 0 || !strings.Contains(e.stderr.String(), `unknown command "sample"`) {
		t.Fatalf("production must not know sample: exit %d, %s", code, e.stderr)
	}
}
```

Run: `go test -tags ctvault_dev ./internal/cli/`
Expected: FAIL with `e.deps.DevBase undefined (type Deps has no field or method DevBase)`.

The production test already passes (`go test -run NoSample ./internal/cli/`). It guards against the command ever leaking into production.

- [ ] **Step 2: Implement the commands and the wiring**

Replace `internal/cli/cli.go`:

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

	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/lock"
	"github.com/4rji/ctvault/internal/loglist"
	"github.com/4rji/ctvault/internal/volume"
)

// Volumes is the volume policy the commands use: volume.Checker in production
// builds, volume.DevProbe in ctvault_dev builds (amendment A1 §1).
type Volumes interface {
	Init(root string, opts volume.InitOptions) (volume.VaultID, error)
	Check(root string) (volume.VaultID, error)
	AddDir(root, dir string, opts volume.InitOptions) (volume.VaultID, error)
}

// Deps are the host services the commands use.
type Deps struct {
	Volumes       Volumes
	HTTP          *http.Client
	Now           func() time.Time
	Stdout        io.Writer
	Stderr        io.Writer
	Getenv        func(string) string
	Statfs        diskguard.StatFunc
	LogListSource string
	Version       string
	// DevBase is <home>/.cache/ctvault-dev in ctvault_dev builds, where dev
	// vaults and samples live; production builds leave it empty.
	DevBase string
}

// DefaultDeps wires the real host with the production volume policy.
func DefaultDeps(version string) Deps {
	return Deps{
		Volumes: volume.Checker{Probe: volume.HostProbe{}, Now: time.Now},
		HTTP:    &http.Client{Timeout: 60 * time.Second}, Now: time.Now,
		Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv, Statfs: diskguard.Statfs,
		LogListSource: loglist.DefaultURL, Version: version,
	}
}

// devBanner is printed on stderr by every command of a ctvault_dev binary.
const devBanner = "WARNING: DEV BUILD (ctvault_dev) — not for production. Vaults and samples live only under ~/.cache/ctvault-dev/."

// extraCommands lets build-tagged files add commands (the dev build's
// "sample" commands); production builds register none.
var extraCommands []func(*app) *cobra.Command

// Main runs one command and returns its exit code (spec §11.2).
func Main(args []string, d Deps) int {
	if volume.DevBuild() {
		fmt.Fprintln(d.Stderr, devBanner)
	}
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
	root.AddCommand(newVersionCmd(a), newInitCmd(a), newLogsCmd(a), newVaultCmd(a))
	for _, extra := range extraCommands {
		root.AddCommand(extra(a))
	}
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
	id, err := a.d.Volumes.Check(a.root)
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
			if volume.DevBuild() {
				fmt.Fprintln(c.OutOrStdout(), "ctvault", a.d.Version, "DEV BUILD — not for production")
				return nil
			}
			fmt.Fprintln(c.OutOrStdout(), "ctvault", a.d.Version)
			return nil
		},
	}
}
```

Create `internal/cli/sample_dev.go`:

```go
//go:build ctvault_dev

package cli

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/loglist"
	"github.com/4rji/ctvault/internal/logreg"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/sample"
	"github.com/4rji/ctvault/internal/stop"
)

func init() { extraCommands = append(extraCommands, newSampleCmd) }

// sampleLimits are amendment A1 §2.1's rules; tests in this package shrink
// them. There is no flag or environment variable for them.
var sampleLimits = sample.DefaultLimits

func newSampleCmd(a *app) *cobra.Command {
	return groupCmd("sample", "Capture and verify real-data samples (dev build only)",
		sampleCaptureCmd(a), sampleVerifyCmd(a))
}

// sampleErr maps sample errors to exit codes: a failed verification is 5, a
// full disk 3.
func sampleErr(err error) error {
	switch {
	case errors.Is(err, sample.ErrCorrupt):
		return exitcode.With(exitcode.Verification, err)
	case errors.Is(err, diskguard.ErrCap):
		return exitcode.With(exitcode.DiskCap, err)
	}
	return err
}

func sampleCaptureCmd(a *app) *cobra.Command {
	var logName, start, suffix, logList string
	var count uint64
	o := config.Default()
	cmd := &cobra.Command{
		Use:   "capture --log <name> --entries N [--start S|head] [--suffix X]",
		Short: "Capture a sample: canonical [0, N) by default, representative with --start",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(c *cobra.Command, _ []string) error {
			if a.d.DevBase == "" {
				return errors.New("no dev base folder")
			}
			if logName == "" {
				return exitcode.Withf(exitcode.Usage, "--log is required (for example --log argon2027h1)")
			}
			opts := sample.CaptureOptions{Kind: sample.Canonical, Count: count, Suffix: suffix, Limits: sampleLimits,
				Version: a.d.Version, Now: a.d.Now,
				Fetch: fetch.Options{Workers: o.Ingest.Workers, MaxRPS: o.Ingest.MaxRPS, StallTimeout: o.Ingest.StallTimeout.Duration,
					MaxBufferedEntries: o.Fetch.MaxBufferedEntries, MaxBufferedBytes: int(o.Fetch.MaxBufferedBytes)}}
			switch start {
			case "":
			case "head":
				opts.Kind, opts.StartAtHead = sample.Representative, true
			default:
				s, err := strconv.ParseUint(start, 10, 64)
				if err != nil {
					return exitcode.Withf(exitcode.Usage, "--start must be an index or \"head\", got %q", start)
				}
				opts.Kind, opts.Start = sample.Representative, s
			}
			if err := sampleLimits.Check(opts.Kind, 0, count); err != nil {
				return exitcode.With(exitcode.Usage, err)
			}
			list, err := loglist.Fetch(c.Context(), a.d.HTTP, logList)
			if err != nil {
				return err
			}
			r, err := list.Find(logName)
			if err != nil {
				return err
			}
			rec := logreg.FromList(list, r, a.d.Now())
			info, err := logsource.InfoFromRecord(rec)
			if err != nil {
				return exitcode.With(exitcode.Verification, err)
			}
			opts.Key, opts.LogListVersion = rec.Key, rec.LogListVersion

			samples := filepath.Join(a.d.DevBase, "samples")
			guard := diskguard.Guard{Cap: o.Disk.MaxUsedFraction, Stat: a.d.Statfs}
			opts.Check = func(need int64) error { return guard.Check(a.d.DevBase, uint64(need)) }
			errOut := c.ErrOrStderr()
			opts.Progress = func(done, total uint64) { fmt.Fprintf(errOut, "fetched %d / %d entries\n", done, total) }

			stops := stop.OnSignals(c.Context(), func() {
				fmt.Fprintln(errOut, "interrupted: stopping the capture; no sample will be written")
			}, nil)
			defer stops.Close()
			src := rfc6962.NewSource(info, a.d.HTTP, logsource.NewChainCache(logsource.DefaultChainCacheBytes), nil)
			s, err := sample.Capture(stops.Soft, samples, src, opts)
			if err != nil {
				return sampleErr(err)
			}
			printSample(c, s, "captured and verified")
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&logName, "log", "", "log name from Chrome's log list (for example argon2027h1)")
	f.Uint64Var(&count, "entries", 100000, "number of entries (50,000-500,000, a multiple of 5,000)")
	f.StringVar(&start, "start", "", "first index of a representative window, or \"head\" for the newest whole window")
	f.StringVar(&suffix, "suffix", "", "folder suffix, to capture an existing range again")
	f.StringVar(&logList, "log-list", a.d.LogListSource, "log list URL or file")
	return cmd
}

func sampleVerifyCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "verify <sample dir>",
		Short: "Verify a sample's checksums, signed head and Merkle proofs",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(c *cobra.Command, args []string) error {
			s, err := sample.Open(args[0])
			if err != nil {
				return sampleErr(err)
			}
			printSample(c, s, "verified")
			return nil
		},
	}
}

func printSample(c *cobra.Command, s *sample.Sample, verb string) {
	m := s.Manifest
	out := c.OutOrStdout()
	entries := m.Files[sample.EntriesFile]
	fmt.Fprintf(out, "%s %s sample %s\n", verb, m.Kind, m.ID(filepath.Base(s.Dir)))
	fmt.Fprintf(out, "  folder     %s\n  entries    [%d, %d) of %s\n  head       tree_size %d, signature verified\n",
		s.Dir, m.Start, m.Start+m.Count, m.Log.Name, m.Head.TreeSize)
	fmt.Fprintf(out, "  proofs     %d consistency", len(s.Proofs.Consistency))
	if s.Proofs.Inclusion != nil {
		fmt.Fprintf(out, ", 1 inclusion")
	}
	fmt.Fprintf(out, "\n  page size  %d\n  size       %d bytes (%d B per entry)\n", m.PageSize, entries.Bytes, entries.Bytes/int64(m.Count))
}
```

Replace `cmd/ctvault/deps_dev.go`:

```go
//go:build ctvault_dev

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/4rji/ctvault/internal/cli"
	"github.com/4rji/ctvault/internal/volume"
)

// deps wires the dev volume policy (amendment A1 §1): dev vaults only under
// ~/.cache/ctvault-dev/vaults/, samples under ~/.cache/ctvault-dev/samples/.
func deps(version string) cli.Deps {
	d := cli.DefaultDeps(version)
	base, err := volume.DefaultDevBase()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ctvault-dev:", err)
		os.Exit(1)
	}
	d.DevBase = base
	d.Volumes = volume.DevProbe{Base: filepath.Join(base, "vaults"), Probe: volume.HostProbe{}, Now: time.Now}
	return d
}
```

Run: `go test -race -count=1 -tags ctvault_dev ./internal/cli/ -v -run Sample && go test -race -count=1 ./internal/cli/ ./cmd/ctvault/`
Expected: PASS:
- `TestSampleCaptureAndVerify`, `TestSampleCaptureRefusals`, `TestSampleCaptureRespectsTheDiskCap`, `TestSampleVerifyRefusesDamage`
- `TestProductionBuildHasNoSampleCommand`, `TestProductionBinaryExcludesDevCode`

- [ ] **Step 3: Add the real-data test layer**

Create `internal/sampletest/sampletest.go`:

```go
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
```

Create `internal/integration/doc.go`:

```go
// Package integration holds the real-data tests (build tag realdata). They
// read the samples cached by "ctvault-dev sample capture" over loopback and
// never touch the network; without a cached sample they skip.
//
//	go test -race -tags realdata ./internal/integration/
package integration
```

Create `internal/integration/realdata_test.go`:

```go
//go:build realdata

package integration

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/sample"
	"github.com/4rji/ctvault/internal/sampletest"
)

const realLog = "argon2027h1"

// decodeStats summarises decoded entries.
type decodeStats struct {
	types    map[leaf.Type]int
	codes    map[leaf.Code]int
	precerts map[[16]byte]bool
	finals   [][16]byte
}

func newDecodeStats() *decodeStats {
	return &decodeStats{types: map[leaf.Type]int{}, codes: map[leaf.Code]int{}, precerts: map[[16]byte]bool{}}
}

func (d *decodeStats) add(t *testing.T, idx uint64, e leaf.Entry) {
	if e.Code.LeafStructure() {
		t.Errorf("entry %d: the log served a leaf that cannot be interpreted: %s", idx, e.Code)
	}
	d.types[e.Type]++
	d.codes[e.Code]++
	if k, ok := e.IssuanceKey(); ok {
		if e.Type == leaf.TypePrecert {
			d.precerts[k] = true
		} else {
			d.finals = append(d.finals, k)
		}
	}
}

func (d *decodeStats) log(t *testing.T, what string) {
	linked := 0
	for _, k := range d.finals {
		if d.precerts[k] {
			linked++
		}
	}
	t.Logf("%s: x509 %d, precert %d; leaf codes %v; %d of %d final certs link to a precert in the window",
		what, d.types[leaf.TypeX509], d.types[leaf.TypePrecert], d.codes, linked, len(d.finals))
}

// TestCanonicalSampleThroughTheFetcher replays the canonical sample through
// the production client, fetcher and leaf decoder, rebuilds the Merkle range
// from the fetched leaves and checks it against the signed head.
func TestCanonicalSampleThroughTheFetcher(t *testing.T) {
	s := sampletest.Canonical(t, realLog)
	src := sampletest.Serve(t, s)
	m := s.Manifest
	head, err := src.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	st := merkle.NewState()
	stats := newDecodeStats()
	fs, err := fetch.Run(context.Background(), src, m.Start, m.Start+m.Count, fetch.Options{MaxRPS: 1000},
		func(e logsource.RawEntry) error {
			stats.add(t, e.Index, e.Leaf)
			return st.Append(e.Leaf.LeafHash)
		})
	if err != nil {
		t.Fatal(err)
	}
	root, _ := st.Root()
	end := m.Start + m.Count
	if end == head.TreeSize {
		if root != head.RootHash {
			t.Fatal("the fetched leaves do not reach the signed root")
		}
	} else {
		proof, err := src.ConsistencyProof(context.Background(), end, head.TreeSize)
		if err != nil {
			t.Fatal(err)
		}
		if err := merkle.VerifyConsistency(end, head.TreeSize, root, head.RootHash, proof); err != nil {
			t.Fatalf("the fetched leaves are not a prefix of the signed tree: %v", err)
		}
	}
	stats.log(t, m.ID(filepath.Base(s.Dir)))
	t.Logf("fetch: %d requests, page size %d, peak buffer %d entries / %d bytes", fs.Requests, fs.LargestResponse, fs.PeakBufEntries, fs.PeakBufBytes)
}

// TestRepresentativeSamplesDecode opens (and so verifies) every cached
// representative sample and decodes every entry.
func TestRepresentativeSamplesDecode(t *testing.T) {
	samples := sampletest.Representatives(t, realLog)
	if len(samples) == 0 {
		t.Skipf("no representative sample of %s cached; capture one with:\n  ctvault-dev sample capture --log %s --start head --entries 100000", realLog, realLog)
	}
	for _, s := range samples {
		stats := newDecodeStats()
		err := s.Each(func(e sample.Entry) error {
			stats.add(t, e.Index, leaf.Decode(e.LeafInput, e.ExtraData))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		stats.log(t, s.Manifest.ID(filepath.Base(s.Dir)))
	}
}
```

Run: `go vet -tags realdata ./... && go test -race -count=1 -tags realdata ./internal/integration/ -v`
Expected: both tests SKIP, each with the exact `ctvault-dev sample capture` command to run, unless a sample is already cached.

- [ ] **Step 4: Update the README**

Replace `README.md`:

````markdown
# CTVault

A local, cryptographically verified Certificate Transparency research archive.
Design: `docs/superpowers/specs/2026-10-04-ctvault-design.md`.

**Status:** Plan 2A (collector). You can create a vault on a dedicated ext4
volume, pin CT logs from Chrome's log list and verify a log's live signed tree
head. The collector (RFC 6962 entries, leaf decoding, the rate-limited
fetcher) is built and tested, and the dev build captures verified real-data
samples. Ingestion into the vault arrives in Plan 2B.

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

| Layer | Command | Network |
|---|---|---|
| Unit tests, fake-log fault injection, production guard tests | `go test -race ./...` | none |
| Dev-build behaviour | `go test -race -tags ctvault_dev ./...` | none |
| Real-data tests (skip without a cached sample) | `go test -race -tags realdata ./internal/integration/` | none (loopback replay) |
| Leaf decoder fuzzing | `go test -run '^$' -fuzz FuzzDecode -fuzztime 60s ./internal/leaf/` | none |
| Live sample capture | `ctvault-dev sample capture ...` (below) | Google, opt-in |

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

Log names are the conventional names from the log list, lowercased:
`argon2027h1`, `wyvern2027h1`, `oak2026h2`, `mammoth2026h2` and so on.
`logs list --available` shows them. Tiled (static-ct-api) logs are listed in
Chrome's log list but cannot be pinned in v1.

The vault must be a dedicated volume. `init` refuses the system disk, including
a loop image, LVM or LUKS device stored on it, as well as any disk that already
holds files other than `lost+found`.

Exit codes: 0 OK, 1 error, 2 usage, 3 disk cap reached, 4 volume check failed,
5 verification or corruption failure.

## Development build (real data on the normal disk)

Until the external SSD is available, real CT data may live on the normal disk
only through the dev build. It is a separate binary, selected at compile time;
the production binary contains none of its code and refuses its vaults.

```bash
go build -tags ctvault_dev -o ctvault-dev ./cmd/ctvault
./ctvault-dev version        # "... DEV BUILD — not for production"
```

Everything it writes lives under `~/.cache/ctvault-dev/` (home from the OS user
database, not `$HOME`): dev vaults in `vaults/`, samples in `samples/`. It
keeps the same 85% disk cap, applied to the normal disk.

### Real-data samples

```bash
# Canonical sample: argon2027h1 [0, 100000). Fixed forever once captured.
./ctvault-dev sample capture --log argon2027h1 --entries 100000

# Representative sample: the newest whole window, or one starting at S.
./ctvault-dev sample capture --log argon2027h1 --start head --entries 100000
./ctvault-dev sample capture --log argon2027h1 --start 200000000 --entries 100000

# Re-check a sample at any time.
./ctvault-dev sample verify ~/.cache/ctvault-dev/samples/argon2027h1/000000000000-000000099999
```

- `--entries` is 50,000-500,000 and a multiple of 5,000; `--start` is a
  multiple of 5,000. A 100,000-entry sample takes about 76-90 MB (760-900 B
  per entry measured) and a few minutes at the log's rate limit.
- A sample is published only after it verifies: the file checksums, the
  signed head with the key pinned from Chrome's log list, and the Merkle
  proofs that tie every entry to that head. It is then read-only and never
  overwritten; to capture the same range again, add `--suffix <name>`.
- An interrupted or failed capture (Ctrl-C, network loss, full disk) leaves
  nothing behind.
- Every later load verifies the sample again, so a damaged sample is refused
  (exit 5) instead of feeding wrong data.
- Canonical samples will feed dev vaults (`update --replay`, Plan 2B);
  representative samples are for measurements only.

## Pending verification

**Real-SSD smoke test: not run yet.** As of 2026-10-04 there was no access to
the external drive. Every automated test passes, but `init` and `logs` have not
yet been run end to end on the real drive and enclosure (USB/UAS, and LUKS if
used). Run this before starting Plan 2 if possible, and in any case before
trusting the vault with data. The drive must be mounted at `/mnt/ctvault`,
ext4, and empty apart from `lost+found`:

```bash
go build -o ctvault ./cmd/ctvault
./ctvault init /mnt/ctvault
./ctvault --root /mnt/ctvault logs add argon2027h1
./ctvault --root /mnt/ctvault logs info argon2027h1
```

Expected:
- `init` reports `durability tested`.
- `logs info` ends with `signature  verified with pinned key`, with a
  `tree_size` above 384,397,626.

Do not substitute a loop image; `init` refuses one stored on the system disk.

The other physical checks also wait for the drive. None of them blocks Plan 2:

1. The real-SSD smoke test above.
2. Filesystem UUID resolution on the real drive and enclosure (USB/UAS, and
   LUKS if used).
3. Unplugging the drive in the middle of a batch.
4. The mount disappearing, or the drive being remounted at a different path.
5. Real disk-cap behaviour on the 4 TB drive (statfs, ext4 reserved blocks,
   projections).
6. Enclosure throughput and fsync latency.
7. The `dm-log-writes` power-loss gate on ext4 (Plan 6).
````

- [ ] **Step 5: Gate and commit**

Run the four gate commands, plus `go vet -tags realdata ./...`. All must pass.

```bash
git add internal/cli cmd/ctvault internal/sampletest internal/integration README.md
git commit -m "feat: ctvault-dev sample capture/verify with disk cap and signals; sampletest and realdata tests; dev workflow docs"
```

- [ ] **Step 6: Live check (opt-in; ask your human partner first)**

This step contacts Google and writes about 76–90 MB to `~/.cache/ctvault-dev/samples/`. Run it only with your partner's go-ahead. The canonical sample is permanent.

```bash
go build -tags ctvault_dev -o ctvault-dev ./cmd/ctvault
./ctvault-dev sample capture --log argon2027h1 --entries 100000
go test -race -count=1 -tags realdata ./internal/integration/ -v
```

Expected:
- **The capture** prints progress every 5,000 entries and ends with `captured and verified canonical sample argon2027h1/000000000000-000000099999` and a size of about 760–900 B per entry.
- **The real-data tests** pass:
  - `TestCanonicalSampleThroughTheFetcher` logs the entry-type mix, the leaf-code counts and the precert links.
  - `TestRepresentativeSamplesDecode` skips until a representative sample exists.
