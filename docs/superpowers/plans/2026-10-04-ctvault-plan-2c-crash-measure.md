# CTVault Plan 2C (Crash Suite and Measurements) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove that Plan 2's ingest survives being killed anywhere, and measure what it stores on real data. When this plan is done:
- A subprocess SIGKILL suite kills the writer at every named commit boundary and at random moments (25 kills by default, 200 with `-tags nightly`). It checks spec §13.5's invariants after every recovery, and requires every surviving ingest to equal a clean one.
- `ctvault-dev sample measure` runs a canonical or representative sample through the production per-entry pipeline in a throwaway workspace, and writes a measurement report (amendment A1 §8).
- Real-data tests ingest the canonical sample end to end, crash and recover on real certificates, query the result through `views.sql`, and write measurement reports.
- The ten minors deferred by the Plan 2B review (M1–M3, M5–M11) are resolved, and two recovery bugs found by the new suites are fixed.

**Architecture:** Plan 2C mostly hardens and tests what Plan 2B built. New code:
- `internal/vaulttest` (test-only): spec §13.5's invariants, the `cert_id` assignments seen before recovery, and a semantic dump for recovery equivalence (amendment A1 §7).
- `internal/commit/crash_test.go`: the SIGKILL harness. The child process is the test binary itself.
- `internal/measure` (dev and realdata builds only): the survey pass, the measurement workspace and the report.
- `ingest.(*Writer).Seed` (dev and realdata builds only): a measurement workspace that starts mid-log, for representative samples.

**Tech Stack:** Go 1.26.8 with cgo, and Plan 2B's dependencies. Nothing new.

**Spec:**
- `docs/superpowers/specs/2026-10-04-ctvault-design.md` ("the spec")
- **Amendment A1:** `docs/superpowers/specs/2026-10-04-ctvault-plan2-amendment.md` (approved)

This plan implements amendment A1's tasks 13 (crash suite), 14 (`sample measure`), 15 (real-data integration) and 16 (docs), plus the Plan 2B review's deferred minors. In detail:
- **Spec:** §6.2 (segment headers), §8.5–8.6 (recovery, `cert_id` never reused), §12, §13.5 (crash boundaries and invariants).
- **Amendment:** §2.6 (measurement runs), §5, §7 (recovery equivalence, `views.sql`), §8 (reports), §9 (test matrix), §10 (pending physical verification).

It builds on Plan 2B as committed (eeb728f).

## Global Constraints

- **Platform:** Linux only, `go 1.26.8`, cgo with a C compiler.
- **Dependencies:** unchanged from Plan 2B. No new modules.
- **Production safety is unchanged.**
  - Dev and measurement code lives only in files built with `ctvault_dev` (or `ctvault_dev || realdata`).
  - `internal/measure`, `internal/sample`, `internal/vaulttest` and the other test packages are banned from production builds by `TestProductionBinaryExcludesDevCode`.
  - The only environment variable production reads is `CTVAULT_ROOT`.
- **Exit codes:** "0 OK, 1 error, 2 usage, 3 disk cap reached, 4 volume check failed, 5 verification or corruption failure" (spec §11.2).
- **"Never silently drop, skip or reuse data"** (spec §12):
  - `cert_id` "is never reused", and gaps are allowed after a crash (spec §6.1, §8.6).
  - "No partial batch is ever visible" (spec §13.5).
  - Pebble "can only lag the dataset, never lead it" (spec §8.5).
- **Recovery equivalence is semantic:** "The recovered dataset must match a clean ingest on log indexes, leaf hashes, certificate content by SHA-256, issuance keys, chain contents, error codes and timestamps. `cert_id` and `chain_id` may differ, provided every reference stays internally consistent" (amendment A1 §7).
- **Reports never change anything:** "They do not rewrite `ctvault.toml`, compiled defaults or disk-guard seeds" (amendment A1 §8).
- **Measurements never create or modify a vault** (amendment A1 §2.6).
- **Quality gates, for every task:**
  - `gofmt -l .` prints nothing.
  - `go vet` is clean with no tags, and with `ctvault_dev`, `realdata` and `nightly`.
  - `go test -race ./...` and `go test -race -tags ctvault_dev ./...` pass.
- **Temp space:** the crash suite and the real-data tests write hundreds of MB under `TMPDIR`. On a machine whose `/tmp` is a small tmpfs, point `TMPDIR` (and `GOTMPDIR`) at a real disk.

## Review Focus

1. **The writer is killed anywhere.**
   - Expected: every restart recovers to the last committed batch. Nothing partial is visible, no truncated record's `cert_id` is ever committed later, Pebble agrees with the vault, nothing is left in `tmp/`, and the finished ingest equals a clean one.
   - Pinned by `TestCrashAtEveryBoundary` and `TestRandomKillLoop` (Task C5, extended in C6), and `TestRecoveryEquivalenceOnRealData` (Task C8).
2. **The writer that recovers stops before committing anything** (`update` finds nothing to do, or a Ctrl-C).
   - Expected: the next start still resumes `cert_id` allocation at `ID_FLOOR`.
   - Pinned by `TestCrashSkipSurvivesARestartWithoutACommit` (Task C6). This was a real bug in Plan 2B.
3. **An abandon cannot be completed** (the vault cannot be cut back).
   - Expected: the writer refuses every further batch, and `update` stops even with `--follow`, so recovery runs at the next start.
   - Pinned by `TestAbandonFailureStopsTheWriter` (Task C2) and `TestAfterCycle` (Task C4).
4. **The log serves a head smaller than, or forked from, what the vault has committed**, with no stored head (a deleted `state/heads/` file).
   - Expected: an incident with exit 5. It is not reported as "up to date".
   - Pinned by `TestUpdateChecksTheHeadAgainstTheCommittedTip` (Task C4).
5. **A measurement is mistaken for a vault, or changes one.**
   - Expected: the workspace is never a vault. It has no `VAULT_ID`, it is removed after the run, and a seeded (mid-log) workspace cannot even be reopened. Reports change no setting.
   - Pinned by `TestSeedStartsAMeasurementMidLog` and `TestMeasureLeavesNothingOnFailure` (Task C7).

## Decisions This Plan Adds

These choices are **not** in the approved sections. They were settled while building and testing this plan. Review them.

| # | Decision | Why |
|---|---|---|
| 1 | **The ten deferred Plan 2B minors are resolved as follows** (they had not been ruled on): M1 exit codes after a second Ctrl-C (C4); M2 an abandon failure stops `--follow`, and `Truncate` refuses to extend a short segment (C1, C2, C4); M3 training runs after the disk preflight and stops on Ctrl-C (C3); M5 every head is checked against the committed tip (C4); M6 a reservoir-sampled canary plus `cert_id` range lookups (C3); M7 a typed-empty `views.sql` before the first commit (C3); M8 segment headers checked against the vault UUID (C1); M9 head-incident write errors are reported (C4); M10 hook points for P3, P6 and a torn append (C1, C2); M11 no cache re-warm after a second Ctrl-C (C2). | They are the 2B review's own findings. Each is pinned by a test that failed before its fix. |
| 2 | **A torn append is simulated only when a hook is set**: the record is written in two halves with `vault.append.mid_record` between them. | Production writes stay one `WriteAt`; crash tests get a real torn record. |
| 3 | **Recovery checks every committed segment's header**: segments 1 to the tail exist, each names its own number and this vault's UUID, and none lies beyond the committed tail after truncation. | Spec §6.2 puts the vault UUID in each header; nothing compared it (M8). A segment restored from another vault is corruption (exit 5). |
| 4 | **A failed abandon breaks the writer** (`ingest.ErrAbandonFailed`): every later `Batch` returns it, and `update` exits even under `--follow`. | Continuing with a vault that could not be cut back would append after uncommitted data. Recovery at the next start is the safe path. |
| 5 | **The writer's DuckDB spill folder is `tmp/duckdb-writer`**: emptied at `Open`, removed at `Close`. Readers keep `tmp/duckdb-<pid>`. This **reverses 2B ruling 14**. | Spec §13.5 requires "no `tmp/` leftovers" after recovery, but a killed writer's `duckdb-<pid>` folder could never be told apart from a live reader's. The writer lock makes the fixed name the writer's own. |
| 6 | **A stopped attempt leaves the delta cache cold**, and the next attempt warms it (M11). | After a second Ctrl-C the process is exiting; re-reading `delta.warm_batches` batches first only delays it. |
| 7 | **The P0 order is volume checks, then the disk preflight, then dictionary training.** Training runs in a goroutine; a cancelled context returns at once, and the abandoned result is discarded and retried by a later run (M3). | Training takes about 3.5 minutes. A batch the disk guard refuses must not train or write dictionary files first. |
| 8 | **The canary reads vault records from a reservoir of 4,096** (Algorithm R, seeded by the batch range) over all of the batch's new records, and checks `cert_id` range counts in `entries.parquet`: the whole range plus random sub-ranges (M6, spec §8.3 P6(e)). | It previously read only the first 4,096 new records. |
| 9 | **`views.sql` is valid before the first commit**: typed, empty views with the committed columns. It is rewritten after every commit, and only when it changes (M7). | The README tells users to `.read` it. The glob version fails in DuckDB with "No files found" until a batch exists. |
| 10 | **After a second Ctrl-C, an error keeps its own exit code** (corruption stays 5, a full disk 3); only an uncoded error becomes 1. An abandon failure always stops `update`. | M1: an incident that coincided with the second Ctrl-C lost its exit 5. |
| 11 | **Every head fetched by `update` is checked against the committed tip.** A head smaller than the committed size, or one that the committed `merkle_after` does not prove to be a prefix of, is an incident (exit 5) and is not stored. Incidents now record `committed_size` and `committed_root`. | M5: with no `state/heads/` file, such a head was reported as "up to date". |
| 12 | **Crash-suite design:** the test binary re-executes itself as the child (`CTVAULT_CRASH_CHILD` names a JSON config; it is read only by the test file, never by production code). 15 named boundaries, each killed once at a fixed occurrence. The random loop waits a uniform delay in [0, clean-ingest time) before each SIGKILL. `-short` skips both. | A real SIGKILL tests what an in-process panic cannot: open file descriptors, unflushed buffers and Pebble's own recovery. |
| 13 | **The SIGKILL suite does not assert ext4 behaviour.** Data written before a SIGKILL survives in the page cache on any filesystem, so spec §13.6's ext4 assertion belongs to the `dm-log-writes` power-loss gate (Plan 6). | A SIGKILL cannot lose acknowledged writes; only power loss can. |
| 14 | **Recovery removes the temp files of interrupted atomic writes** (`.<name>.tmp-<digits>`, the only names `fsutil.WriteFileAtomic` creates). It looks in the root, `state/` and its folders except Pebble's, and each vault folder's `dict/`, and logs each removal. | Found by the random kill loop: a writer killed inside `WriteIntent` left one in `state/intent/`. This goes beyond amendment A1 §7's `tmp/` scope, but only for names that no other process writes. |
| 15 | **Recovery keeps the intent of an uncommitted batch, marked abandoned, until a later batch commits.** This **reverses Plan 2B**, which deleted it. | Found by this plan's real-data recovery test. Recovery resumed `cert_id` allocation at `ID_FLOOR` only in memory. If the writer that recovered stopped before committing, the next start reused the IDs of the records it had truncated, against spec §8.6. The in-process abandon already kept its intent. Now both paths behave the same. |
| 16 | **A measurement verifies each batch against Merkle roots recomputed from the sample**, which `sample.Open` has already verified against the signed head. A representative sample holds a consistency proof only at the end of its window. | Each batch's root is still recomputed by the writer from the replayed entries. The unsigned heads exist only in the workspace's manifests, and the workspace is deleted. |
| 17 | **`ingest.(*Writer).Seed`** starts a measurement workspace mid-log. It is compiled only into `ctvault_dev` and `realdata` builds. A seeded workspace cannot be reopened, because loading the manifests refuses a first batch that does not start at 0. | Representative samples begin mid-log, while vaults always ingest from index 0 (spec §5.5). |
| 18 | **The measurement workspace is `<dev base>/tmp/measure-<pid>`**, removed when the run ends, whatever the outcome. Workspaces of processes that no longer run are removed at the next start. | A SIGKILLed measurement would otherwise leave hundreds of MB behind. |
| 19 | **The report's comparison with the spec:** spec §3.4's 1.96× (dictionary, contiguous sample) and 1.21× (no dictionary), the 17.1% `leaf-delta` saving against a dictionary-compressed final certificate, and spec §10.2's vault budget of 765 B per entry (its upper end). "More than 10% worse" means measured/spec < 1/1.1 for ratios, and spec/measured < 1/1.1 for sizes. | Amendment A1 §5 names the rule but not the figures. Those are the spec's only C-zstd numbers. |
| 20 | **The real-data layer runs without `-race`, with a 90-minute timeout:** `go test -tags realdata -timeout 90m ./internal/integration/`. This amends amendment A1 §9's command. | Training dictionary 1 on 20,000 real certificates takes about 3.5 minutes without the race detector. The race detector multiplies CPU-bound work, and the fake-log suites already run every code path concurrently under `-race`. |
| 21 | **A report's dependency versions come from the Go build info.** A `go test` binary lists none, so the real-data tests pass the versions from `go.mod`, and the report records where they came from (`dependencies_from`). | Amendment A1 §8 requires the dependency versions. The first real-data reports had none, and showed `klauspost/compress (version unknown)`. |

## Evidence Behind This Plan (measured 2026-10-04)

1. **The crash suite runs fast and catches real faults.**
   - Without `-race`: the 15 named boundaries take about 20 s, and the 25-kill loop about 16 s (17 kills and 9 complete ingests, each compared with a clean one).
   - With `-race`, the `commit` package takes 154 s. `-short` skips the suite.
   - Two mutations of recovery are caught exactly where expected:
     - Skipping the Pebble catch-up fails `P8.after_rename` and `P9.before_pebble`: "pebble and the vault disagree: 41 index entries, 81 records".
     - Leaving `tmp/stage` behind fails `P6`, `P7` and `P8.before_rename`.
2. **Bugs found by the new tests while writing this plan, and fixed in it:**
   - **Plan 1: `merkle.State.Clone` shared the compact range's hash list.** A clone's appends overwrote the original's last nodes.
     - After any failed attempt of a batch other than the first (a canary or Merkle retry, a stall, a full disk under `--follow`), the committed tip was corrupted. The retry then *always* failed verification: a false incident with exit 5, and corrupted `merkle_before` evidence.
     - Found by `TestRefetchAfterAFailedCanaryCommits`. Pinned by `TestCloneIsIndependent` (Task C2).
   - **Plan 2B: a writer killed inside `fsutil.WriteFileAtomic` left `.<name>.tmp-<n>` behind**, and recovery never removed it.
     - Found by the random kill loop, in `state/intent/`. Pinned by `TestRecoverRemovesInterruptedAtomicWrites` (Task C6).
   - **Plan 2B: `cert_id`s were reused after a crash** when the writer that recovered stopped before committing.
     - Found by the real-data recovery test: the next `cert_id` after 5 crashes equalled a clean run's (30,540). After the fix it is 272,149.
     - Pinned by `TestCrashSkipSurvivesARestartWithoutACommit` and by the crash suite's new truncated-ID check (Task C6). The check failed on the unfixed code: "cert_id 57 belonged to a record recovery truncated, and was committed later".
3. **The representative sample** `argon2027h1/000397220000-000397319999` was captured live:
   - Signed head 397,320,051; 85.6 MB (855 B/entry); 5 m 44 s at the log's rate limit (about 290 entries/s), then verified.
   - It is stored under the dev base, on a separate data disk through a symlink.
4. **The canonical sample through `sample measure`** (10,000-entry batches; the shard's start, not representative):
   - **Vault:** 1079 B/entry overall, and 985 once dictionary 1 is used. **Parquet:** 55. **Pebble:** 72.
   - **Full leaf records with dictionary 1:** 1.58×. The spec's C-zstd figure is 1.96×, so this is **flagged**: more than 10% worse.
   - **Links:** 2.0% (1,603 of 81,052) of finals link to an earlier precert, and 55 more have their precert later in the window. Every eligible final became a `leaf-delta`.
   - **Dedup and errors:** no leaf duplicates, 99.79% of chain references deduplicated, 0 leaf errors.
   - **Training:** dictionary 1 took 213 s to train. That batch took 215.6 s against about 3 s for the others.
5. **The representative sample through `sample measure`:**
   - **Vault:** 745 B/entry overall, and 638 once dictionary 1 is used: inside spec §10.2's budget of 765 and the disk-guard seed of 840. **Parquet:** 55. **Pebble:** 71. The Pebble seed is 60, so it is 18% over.
   - **Full leaf records with dictionary 1:** 1.71×, 12.7% below the spec's 1.96×, so this is **flagged** (amendment A1 §5). Without a dictionary: 1.10× (spec 1.21×, −9.0%).
   - **Links:** 9.2% (3,943 of 42,834) of finals link to an earlier precert, and 2,674 more have their precert later in the window. Spec §10.2's "minus about 8% from `leaf-delta` at about 80% linking" does not hold at the log's head: there `leaf-delta` saves 25.8% per linked final, but on few finals.
   - **Delays from precert to final:** p50 1.6 s, p95 2 m 31 s, p99 3 m 38 s.
   - **Dedup and errors:** no leaf duplicates, 99.93% of chain references deduplicated, 0 leaf errors.
   - **Training:** dictionary 1 took 215 s, in the fourth batch. Every other batch took 1.5–3.6 s.
6. **Real data end to end**:
   - The canonical sample was ingested with production settings in 4 m 0 s. It passed every invariant, the `views.sql` queries, the literal `BLOB` lookup and 1,000 verified read-backs.
   - The recovery-equivalence test (5 crashes over 30,000 entries) takes 76 s.

## Carried to Plan 3

- **Compression:** the measured gaps against the spec's C-zstd figures (Evidence 4–5). Amendment A1 §5 leaves any change of compression library or level to Plan 3.
- **Disk-guard seeds and `delta.warm_batches`:** the reports give the numbers. Changing them needs a reviewed edit (amendment A1 §8).
- **The physical checks of amendment A1 §10**, which still wait for the external SSD.
- **Crash boundaries for `ACTIVE.json` and rebuilds** (spec §13.5), which arrive with the derived tables (Plans 3 and 6).

## Before You Start

- Work from the repository root, with Plan 2B committed (eeb728f).
- **cgo:** a C compiler must be installed (`gcc`).
- **Temp space:** see Global Constraints. On this machine:
  - `TMPDIR=/mnt/disk/ctvault/tmp GOTMPDIR=/mnt/disk/ctvault/gotmp`
  - `GOCACHE=/mnt/disk/ctvault/gocache`
- The real-data tests need the canonical sample (and use any representative sample) under `~/.cache/ctvault-dev/samples/`. Without one they skip, saying how to capture it.

## File Structure

```text
internal/vault/writer.go          + HookAppendMidRecord: a record written in two halves when a hook is set
internal/vault/truncate.go        Truncate refuses to extend a short or missing tail segment
internal/vault/check.go           CheckSegments: committed segments exist, own number, this vault's UUID
internal/commit/recover.go        + segment check; + removal of interrupted atomic writes; abandoned intents kept
internal/ingest/writer.go         spill folder tmp/duckdb-writer; Tip; cold cache after a stopped abandon
internal/ingest/batch.go          hooks P3, P6, P9; ErrAbandonFailed; P0 order; cancellable training; reservoir canary
internal/merkle/state.go          Clone deep-copies (Plan 1 bug)
internal/dataset/canary.go        + cert_id range lookups (P6(e))
internal/dataset/views.go         typed-empty views before the first commit
internal/cli/update.go            afterCycle exit codes; head checked against the committed tip; incident write errors
internal/index/index.go           + EachCert
internal/fsutil/fsutil.go         + IsAtomicTemp
internal/vaulttest/vaulttest.go   (test-only) invariants, assignments, BeyondTail, semantic Dump and Diff
internal/commit/crash_test.go     SIGKILL harness: named boundaries and the random kill loop
internal/commit/killloop_test.go, killloop_nightly_test.go   25 kills by default, 200 with -tags nightly
internal/sample/read.go           + StartState, LogInfo
internal/ingest/measure_dev.go    (ctvault_dev || realdata) Writer.Seed, Writer.Committed
internal/measure/measure.go       (ctvault_dev || realdata) survey, workspace, ingest, vault scan
internal/measure/report.go        (ctvault_dev || realdata) Report, gap rule, JSON and Markdown
internal/cli/sample_dev.go        (dev) + sample measure
internal/integration/vault_realdata_test.go   (realdata) end to end, recovery equivalence, reports
README.md                         status, measurements, crash suite, test matrix
```

---

### Task C1: Vault integrity hooks and checks (M2b, M8, M10)

Spec §6.2 (segment headers), §8.5 (truncation) and §13.5 (a torn append).

**Files:**
- Modify: `internal/vault/writer.go`, `internal/vault/truncate.go`, `internal/commit/recover.go`, `internal/ingest/writer.go`
- Create: `internal/vault/check.go`
- Tests: `internal/vault/integrity_test.go` (new), `internal/vault/vault_test.go`, `internal/commit/protocol_test.go`

**Interfaces:**
- Produces:
  - `vault.HookAppendMidRecord = "vault.append.mid_record"`
  - `vault.CheckSegments(dirs []string, uuid [16]byte, tail Tail) error`
  - `commit.RecoverOptions.VaultUUID [16]byte`: every committed segment header must carry it
- Changes: `vault.Truncate` returns `ErrCorrupt` instead of extending a short segment. `ingest.Open` passes `Options.VaultUUID` to recovery.

- [ ] **Step 1: Write the failing tests**

Create `internal/vault/integrity_test.go`:

```go
package vault

import (
	"errors"
	"os"
	"slices"
	"testing"
)

// TestTornAppendHook: with a hook set, a record is written in two halves
// around HookAppendMidRecord, so a kill there leaves a torn record (spec
// §13.5); recovery's tools see the intact records before it.
func TestTornAppendHook(t *testing.T) {
	dirs := vaultDirs(t, 1)
	cs := certs(t, 4)
	n := 0
	w, err := OpenWriter(Options{Dirs: dirs, VaultUUID: testUUID, SegmentSize: 1 << 20, Now: fixedNow,
		Hook: func(p string) {
			if p == HookAppendMidRecord {
				if n++; n == 3 {
					panic("killed mid-record")
				}
			}
		}}, codec(t), Tail{})
	if err != nil {
		t.Fatal(err)
	}
	w.AppendCert(KindLeaf, 1, cs[0], 0)
	w.AppendCert(KindLeaf, 2, cs[1], 0)
	intact := w.Tail()
	func() {
		defer func() { recover() }()
		w.AppendCert(KindLeaf, 3, cs[2], 0)
		t.Fatal("the hook did not fire")
	}()
	w.Close()
	segs, _ := FindSegments(dirs)
	fi, _ := os.Stat(segs[1])
	if uint64(fi.Size()) <= intact.Offset {
		t.Fatalf("half of record 3 must be on disk: segment is %d bytes, intact records end at %d", fi.Size(), intact.Offset)
	}
	u, err := InspectTail(dirs, Tail{Segment: 1, Offset: HeaderSize})
	if err != nil || u.MaxCertID != 2 {
		t.Fatalf("InspectTail: %+v, %v; want max cert_id 2", u, err)
	}
	if err := Scan(dirs, Tail{}, Tail{Segment: 1, Offset: uint64(fi.Size())}, func(Loc, Record) error { return nil }); !errors.Is(err, ErrTorn) {
		t.Fatalf("the half-written record is torn: %v", err)
	}
}

// TestTruncateNeverExtends: cutting a segment back to a tail it does not
// reach would fill it with zeros; that, or a missing tail segment, is
// corruption, and the file is left alone.
func TestTruncateNeverExtends(t *testing.T) {
	dirs := vaultDirs(t, 1)
	w := openWriter(t, dirs, 1<<20, Tail{}, nil)
	w.AppendCert(KindLeaf, 1, certs(t, 1)[0], 0)
	end := w.Tail()
	w.Close()
	if err := Truncate(dirs, Tail{Segment: 1, Offset: end.Offset + 100}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a tail beyond the segment's end: %v", err)
	}
	segs, _ := FindSegments(dirs)
	if fi, _ := os.Stat(segs[1]); uint64(fi.Size()) != end.Offset {
		t.Fatalf("the segment changed: %d bytes, want %d", fi.Size(), end.Offset)
	}
	if err := Truncate(dirs, Tail{Segment: 2, Offset: HeaderSize}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a missing tail segment: %v", err)
	}
}

// TestCheckSegments: every committed segment exists, sits at or before the
// tail, and carries an intact header with its own number and this vault's
// UUID (spec §6.2). A segment restored from another vault is corruption.
func TestCheckSegments(t *testing.T) {
	dirs := vaultDirs(t, 1)
	w := openWriter(t, dirs, 4<<10, Tail{}, nil)
	for i, der := range certs(t, 24) {
		w.AppendCert(KindLeaf, uint64(i+1), der, 0)
	}
	tail := w.Tail()
	w.Close()
	if tail.Segment < 3 {
		t.Fatalf("the test needs three segments, got %d", tail.Segment)
	}
	if err := CheckSegments(dirs, testUUID, tail); err != nil {
		t.Fatalf("a clean vault: %v", err)
	}
	if err := CheckSegments(dirs, [16]byte{9}, tail); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("another vault's UUID: %v", err)
	}
	if err := CheckSegments(dirs, testUUID, Tail{Segment: 2, Offset: HeaderSize}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a segment beyond the tail: %v", err)
	}
	segs, _ := FindSegments(dirs)
	rewrite := func(id uint64, edit func(*Header)) {
		f, _ := os.OpenFile(segs[id], os.O_RDWR, 0)
		defer f.Close()
		b := make([]byte, HeaderSize)
		f.ReadAt(b, 0)
		h, _ := DecodeHeader(b)
		edit(&h)
		f.WriteAt(h.Encode(), 0)
	}
	rewrite(2, func(h *Header) { h.Segment = 3 })
	if err := CheckSegments(dirs, testUUID, tail); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("segment file 2 holding segment 3: %v", err)
	}
	rewrite(2, func(h *Header) { h.Segment = 2 })
	b, _ := os.ReadFile(segs[2])
	os.WriteFile(segs[2], slices.Concat([]byte("garbage!"), b[8:]), 0o644)
	if err := CheckSegments(dirs, testUUID, tail); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a damaged header: %v", err)
	}
	os.WriteFile(segs[2], b, 0o644)
	os.Remove(segs[2])
	if err := CheckSegments(dirs, testUUID, tail); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a missing segment: %v", err)
	}
}
```

Replace `internal/vault/vault_test.go` with:

```go
package vault

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/ctlogtest"
)

var testUUID = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

func fixedNow() time.Time { return time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC) }

// vaultDirs makes n vault directories with segments/ and dict/.
func vaultDirs(t *testing.T, n int) []string {
	t.Helper()
	var dirs []string
	for i := range n {
		d := filepath.Join(t.TempDir(), fmt.Sprintf("v%d", i))
		for _, sub := range []string{SegmentsDir, DictDir} {
			if err := os.MkdirAll(filepath.Join(d, sub), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		dirs = append(dirs, d)
	}
	return dirs
}

// certs returns n distinct real certificates from the fake-log generator.
func certs(t *testing.T, n int) [][]byte {
	t.Helper()
	g, err := ctlogtest.NewGenerator()
	if err != nil {
		t.Fatal(err)
	}
	es, err := g.Entries(n)
	if err != nil {
		t.Fatal(err)
	}
	out := make([][]byte, n)
	for i, e := range es {
		out[i] = e.CertDER
	}
	return out
}

func codec(t *testing.T) *Codec {
	t.Helper()
	c, err := NewCodec()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestHeader(t *testing.T) {
	h := Header{Version: FormatVersion, VaultUUID: testUUID, Segment: 7, FirstCertID: 42, Created: fixedNow()}
	b := h.Encode()
	if len(b) != HeaderSize || string(b[:8]) != Magic {
		t.Fatalf("header layout: %d bytes, magic %q", len(b), b[:8])
	}
	got, err := DecodeHeader(b)
	if err != nil || got != h {
		t.Fatalf("round trip: %+v, %v", got, err)
	}
	bad := slices.Clone(b)
	bad[30] ^= 1
	if _, err := DecodeHeader(bad); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a flipped bit must fail the checksum: %v", err)
	}
	if _, err := DecodeHeader(b[:20]); !errors.Is(err, ErrTorn) {
		t.Fatalf("a short header is torn: %v", err)
	}
	if u, err := ParseUUID("01020304-0506-0708-090a-0b0c0d0e0f10"); err != nil || u != testUUID {
		t.Fatalf("ParseUUID: %x %v", u, err)
	}
	if _, err := ParseUUID("not-a-uuid"); err == nil {
		t.Fatal("a bad UUID is refused")
	}
}

func TestRecordCodec(t *testing.T) {
	for _, r := range []Record{
		{Kind: KindLeaf, CertID: 1, DictID: 0, Frame: []byte("frame")},
		{Kind: KindChain, CertID: 1 << 40, DictID: 3, Frame: []byte("x")},
		{Kind: KindDelta, CertID: 9, BaseSeg: 2, BaseOff: 300, Frame: []byte("delta")},
	} {
		b := AppendRecord(nil, r)
		got, err := ParseRecord(append(b, 0xff, 0xff)) // trailing bytes belong to the next record
		if err != nil || got.Kind != r.Kind || got.CertID != r.CertID || got.DictID != r.DictID ||
			got.BaseSeg != r.BaseSeg || got.BaseOff != r.BaseOff || string(got.Frame) != string(r.Frame) || got.TotalLen != len(b) {
			t.Fatalf("round trip of %+v: %+v, %v", r, got, err)
		}
		if _, err := ParseRecord(b[:len(b)-1]); !errors.Is(err, ErrTorn) {
			t.Fatalf("a record cut short is torn: %v", err)
		}
	}
	if _, err := ParseRecord(AppendRecord(nil, Record{Kind: 9, CertID: 1})); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("an unknown kind is corruption: %v", err)
	}
}

func openWriter(t *testing.T, dirs []string, segSize uint64, tail Tail, check func(string, uint64) error) *Writer {
	t.Helper()
	w, err := OpenWriter(Options{Dirs: dirs, VaultUUID: testUUID, SegmentSize: segSize, Check: check, Now: fixedNow}, codec(t), tail)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestWriteReadAcrossSegments(t *testing.T) {
	dirs := vaultDirs(t, 1)
	cs := certs(t, 60)
	w := openWriter(t, dirs, 8<<10, Tail{}, nil)
	locs := make([]Loc, len(cs))
	for i, der := range cs {
		kind := byte(KindLeaf)
		if i%7 == 0 {
			kind = KindChain
		}
		loc, err := w.AppendCert(kind, uint64(i+1), der, 0)
		if err != nil {
			t.Fatal(err)
		}
		locs[i] = loc
	}
	if err := w.Sync(); err != nil {
		t.Fatal(err)
	}
	tail := w.Tail()
	w.Close()
	if tail.Segment < 3 {
		t.Fatalf("60 certificates in 8 KiB segments need several segments, got %d", tail.Segment)
	}
	r, err := OpenReader(dirs, codec(t))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for i, der := range cs {
		got, err := r.ReadVerified(locs[i], sha256.Sum256(der))
		if err != nil || string(got) != string(der) {
			t.Fatalf("cert %d: %v", i+1, err)
		}
	}
	// Each segment's header names its first cert_id and the vault.
	segs, _ := FindSegments(dirs)
	b, _ := os.ReadFile(segs[2])
	h, err := DecodeHeader(b)
	if err != nil || h.VaultUUID != testUUID || h.Segment != 2 || h.FirstCertID != firstIn(locs, 2) {
		t.Fatalf("segment 2 header %+v, %v", h, err)
	}
	// A reopened writer continues after the tail and leaves earlier records
	// intact.
	w2 := openWriter(t, dirs, 8<<10, tail, nil)
	loc, err := w2.AppendCert(KindLeaf, 61, cs[0], 0)
	if err != nil || loc.Segment != tail.Segment || loc.Offset != tail.Offset {
		t.Fatalf("append after reopen at %+v: %+v, %v", tail, loc, err)
	}
	w2.Sync()
	w2.Close()
	r2, _ := OpenReader(dirs, codec(t))
	defer r2.Close()
	for i, der := range append(cs, cs[0]) {
		l := loc
		if i < len(cs) {
			l = locs[i]
		}
		if _, err := r2.ReadVerified(l, sha256.Sum256(der)); err != nil {
			t.Fatalf("after reopening, record %d: %v", i+1, err)
		}
	}
}

func firstIn(locs []Loc, seg uint64) uint64 {
	for i, l := range locs {
		if l.Segment == seg {
			return uint64(i + 1)
		}
	}
	return 0
}

// TestRolloverPicksFirstDirWithRoom: new segments go to the first vault
// directory that passes the disk guard (spec §6.2), and a full vault is an
// error, never a silent skip.
func TestRolloverPicksFirstDirWithRoom(t *testing.T) {
	dirs := vaultDirs(t, 2)
	full := map[string]bool{dirs[0]: true}
	check := func(dir string, need uint64) error {
		if full[dir] {
			return fmt.Errorf("%s: disk cap would be exceeded", dir)
		}
		return nil
	}
	w := openWriter(t, dirs, 8<<10, Tail{}, check)
	if _, err := w.AppendCert(KindLeaf, 1, certs(t, 1)[0], 0); err != nil {
		t.Fatal(err)
	}
	w.Close()
	if _, err := os.Stat(filepath.Join(dirs[1], SegmentsDir, SegmentName(1))); err != nil {
		t.Fatalf("segment 1 must go to the second directory: %v", err)
	}
	full[dirs[1]] = true
	w = openWriter(t, dirs, 8<<10, w.Tail(), check)
	var err error
	for i := 0; err == nil && i < 20; i++ {
		_, err = w.AppendCert(KindLeaf, uint64(i+2), certs(t, 1)[0], 0)
	}
	if err == nil {
		t.Fatal("with every directory full, the next rollover must fail")
	}
	w.Close()
}

func TestAppendsRecheckTheCap(t *testing.T) {
	dirs := vaultDirs(t, 1)
	var calls []uint64
	check := func(dir string, need uint64) error {
		calls = append(calls, need)
		if len(calls) > 3 {
			return errors.New("disk cap would be exceeded")
		}
		return nil
	}
	w, err := OpenWriter(Options{Dirs: dirs, VaultUUID: testUUID, SegmentSize: 1 << 30, Check: check, CheckEvery: 2000, Now: fixedNow}, codec(t), Tail{})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	cs := certs(t, 20)
	for i := 0; i < 20; i++ {
		if _, err = w.AppendCert(KindLeaf, uint64(i+1), cs[i], 0); err != nil {
			break
		}
	}
	if err == nil || len(calls) != 4 || calls[0] != 1<<30 || calls[1] != 2000 {
		t.Fatalf("one check before the segment, then one per 2000 bytes, and a refusal stops appends: %v, calls %v", err, calls)
	}
}

func TestReadDetectsCorruption(t *testing.T) {
	dirs := vaultDirs(t, 1)
	c := certs(t, 2)
	w := openWriter(t, dirs, 1<<20, Tail{}, nil)
	loc, _ := w.AppendCert(KindLeaf, 1, c[0], 0)
	loc2, _ := w.AppendCert(KindLeaf, 2, c[1], 0)
	w.Sync()
	w.Close()
	r, _ := OpenReader(dirs, codec(t))
	defer r.Close()
	if _, err := r.ReadVerified(loc, sha256.Sum256(c[1])); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a SHA-256 mismatch is corruption: %v", err)
	}
	if _, err := r.ReadVerified(Loc{Segment: loc.Segment, Offset: loc.Offset, Len: loc.Len + 1}, sha256.Sum256(c[0])); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a wrong length is corruption: %v", err)
	}
	if _, err := r.ReadVerified(Loc{Segment: 9, Offset: 64, Len: 10}, [32]byte{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a missing segment is corruption: %v", err)
	}
	r.Close()
	segs, _ := FindSegments(dirs)
	b, _ := os.ReadFile(segs[1])
	b[loc2.Offset+uint64(loc2.Len)-6] ^= 0xff // inside the frame
	os.WriteFile(segs[1], b, 0o644)
	r2, _ := OpenReader(dirs, codec(t))
	defer r2.Close()
	if _, err := r2.ReadVerified(loc2, sha256.Sum256(c[1])); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a damaged frame is corruption: %v", err)
	}
	if _, err := r2.ReadVerified(loc, sha256.Sum256(c[0])); err != nil {
		t.Fatalf("the intact record still reads: %v", err)
	}
}

func TestDecompressChecksTheFrameDictionary(t *testing.T) {
	c := codec(t)
	frame, err := c.Compress([]byte("certificate"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Decompress(frame, 1); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a record claiming dictionary 1 for a dictionary-less frame is corrupt: %v", err)
	}
	if _, err := c.Compress([]byte("x"), 5); err == nil {
		t.Fatal("an unknown dictionary is refused")
	}
}

func TestDuplicateSegmentIsCorruption(t *testing.T) {
	dirs := vaultDirs(t, 2)
	for _, d := range dirs {
		os.WriteFile(filepath.Join(d, SegmentsDir, SegmentName(3)), Header{Version: 1, Segment: 3}.Encode(), 0o644)
	}
	if _, err := FindSegments(dirs); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("segment 3 in two directories: %v", err)
	}
	os.WriteFile(filepath.Join(dirs[0], SegmentsDir, "junk.seg"), nil, 0o644)
	if _, err := FindSegments(dirs[:1]); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("an unexpected segment file name: %v", err)
	}
}

// TestInspectAndTruncateUncommittedData walks spec §8.5's first recovery
// row: data beyond the committed tail, ending in a torn record.
func TestInspectAndTruncateUncommittedData(t *testing.T) {
	dirs := vaultDirs(t, 1)
	cs := certs(t, 40)
	w := openWriter(t, dirs, 8<<10, Tail{}, nil)
	for i := range 10 {
		w.AppendCert(KindLeaf, uint64(i+1), cs[i], 0)
	}
	w.Sync()
	committed := w.Tail()
	for i := 10; i < 40; i++ { // an uncommitted batch that rolls into new segments
		w.AppendCert(KindLeaf, uint64(i+1), cs[i], 0)
	}
	last := w.Tail()
	w.Close()
	segs, _ := FindSegments(dirs)
	f, _ := os.OpenFile(segs[last.Segment], os.O_WRONLY|os.O_APPEND, 0)
	f.Write(AppendRecord(nil, Record{Kind: KindLeaf, CertID: 99, Frame: make([]byte, 500)})[:100]) // torn
	f.Close()

	if _, err := OpenWriter(Options{Dirs: dirs, SegmentSize: 8 << 10}, codec(t), committed); err == nil {
		t.Fatal("a writer must refuse to open over uncommitted data")
	}
	u, err := InspectTail(dirs, committed)
	if err != nil || u.MaxCertID != 40 || u.Bytes == 0 {
		t.Fatalf("InspectTail: %+v, %v; want max cert_id 40 (the torn record 99 is not intact)", u, err)
	}
	var seen []uint64
	err = Scan(dirs, Tail{}, last, func(l Loc, r Record) error { seen = append(seen, r.CertID); return nil })
	if err != nil || len(seen) != 40 {
		t.Fatalf("Scan up to the last intact record: %d records, %v", len(seen), err)
	}
	if err := Scan(dirs, committed, Tail{Segment: last.Segment, Offset: last.Offset + 100}, func(Loc, Record) error { return nil }); !errors.Is(err, ErrTorn) {
		t.Fatalf("scanning into the torn record: %v", err)
	}
	if err := Truncate(dirs, committed); err != nil {
		t.Fatal(err)
	}
	after, _ := FindSegments(dirs)
	fi, _ := os.Stat(after[committed.Segment])
	if len(after) != int(committed.Segment) || uint64(fi.Size()) != committed.Offset {
		t.Fatalf("after Truncate: %d segments, tail segment %d bytes; want %d segments ending at %d", len(after), fi.Size(), committed.Segment, committed.Offset)
	}
	if u, err := InspectTail(dirs, committed); err != nil || u.Bytes != 0 || u.MaxCertID != 0 {
		t.Fatalf("nothing remains beyond the tail: %+v, %v", u, err)
	}
	w = openWriter(t, dirs, 8<<10, committed, nil)
	if _, err := w.AppendCert(KindLeaf, 41, cs[0], 0); err != nil {
		t.Fatal(err)
	}
	w.Close()
}

func TestOpenWriterRefusesSegmentsBeyondTail(t *testing.T) {
	dirs := vaultDirs(t, 1)
	w := openWriter(t, dirs, 4<<10, Tail{}, nil)
	for i, der := range certs(t, 12) {
		w.AppendCert(KindLeaf, uint64(i+1), der, 0)
	}
	w.Close()
	if _, err := OpenWriter(Options{Dirs: dirs, SegmentSize: 4 << 10}, codec(t), Tail{Segment: 1, Offset: HeaderSize}); err == nil {
		t.Fatal("later segments beyond the tail must be refused")
	}
}

func TestRolloverHooks(t *testing.T) {
	dirs := vaultDirs(t, 1)
	var points []string
	w, err := OpenWriter(Options{Dirs: dirs, VaultUUID: testUUID, SegmentSize: 1 << 20, Now: fixedNow,
		Hook: func(p string) { points = append(points, p) }}, codec(t), Tail{})
	if err != nil {
		t.Fatal(err)
	}
	w.AppendCert(KindLeaf, 1, []byte("der"), 0)
	w.Close()
	want := []string{HookRolloverBeforeHeader, HookRolloverAfterHeader, HookRolloverBeforeDirSync, HookAppendMidRecord}
	if !slices.Equal(points, want) {
		t.Fatalf("hook order %v, want %v", points, want)
	}
}

func TestPreferStartsNewSegmentsInTheReservedDirectory(t *testing.T) {
	dirs := vaultDirs(t, 2)
	w := openWriter(t, dirs, 1<<20, Tail{}, nil)
	defer w.Close()
	cs := certs(t, 3)
	a, _ := w.AppendCert(KindLeaf, 1, cs[0], 0)
	w.Prefer(dirs[1])
	b, _ := w.AppendCert(KindLeaf, 2, cs[1], 0)
	c, _ := w.AppendCert(KindLeaf, 3, cs[2], 0)
	segs, _ := FindSegments(dirs)
	if a.Segment != 1 || b.Segment != 2 || c.Segment != 2 || filepath.Dir(filepath.Dir(segs[2])) != dirs[1] {
		t.Fatalf("after Prefer, appends continue in a new segment in the preferred directory: %v %v %v, %s", a, b, c, segs[2])
	}
	w.Prefer(dirs[1])
	d, _ := w.AppendCert(KindLeaf, 4, cs[0], 0)
	if d.Segment != 2 {
		t.Fatal("preferring the current directory again does not roll over")
	}
}

func TestPreferAfterReopenKeepsTheTailSegment(t *testing.T) {
	dirs := vaultDirs(t, 2)
	w := openWriter(t, dirs, 1<<20, Tail{}, nil)
	w.AppendCert(KindLeaf, 1, certs(t, 1)[0], 0)
	w.Sync()
	tail := w.Tail()
	w.Close()
	w = openWriter(t, dirs, 1<<20, tail, nil)
	defer w.Close()
	w.Prefer(dirs[0])
	if loc, _ := w.AppendCert(KindLeaf, 2, certs(t, 1)[0], 0); loc.Segment != 1 {
		t.Fatalf("a reopened writer preferring the tail segment's own directory must not roll over: segment %d", loc.Segment)
	}
}
```

Replace `internal/commit/protocol_test.go` with:

```go
package commit

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

// env is a vault root with the writer's resources.
type env struct {
	t      *testing.T
	p      Paths
	dirs   []string
	idx    *index.Index
	codec  *vault.Codec
	stager *dataset.Stager
	certs  [][]byte
	hooks  []string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"state/intent", "state/logs", "vault/segments", "vault/dict", "dataset", "tmp/stage", "tmp/rebuild"} {
		os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	e := &env{t: t, p: Paths{Root: root}, dirs: []string{filepath.Join(root, "vault")}}
	var err error
	if e.idx, err = index.Open(filepath.Join(root, "state", "pebble")); err != nil {
		t.Fatal(err)
	}
	if e.codec, err = vault.NewCodec(); err != nil {
		t.Fatal(err)
	}
	if e.stager, err = dataset.NewStager(dataset.Options{TempDir: filepath.Join(root, "tmp", "duckdb-test"), MaxTempBytes: 1 << 30}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.stager.Close(); e.codec.Close(); e.idx.Close() })
	g, _ := ctlogtest.NewGenerator()
	es, _ := g.Entries(60)
	for _, x := range es {
		e.certs = append(e.certs, x.CertDER)
	}
	return e
}

func (e *env) hook(p string) { e.hooks = append(e.hooks, p) }

func (e *env) recover() Recovered {
	e.t.Helper()
	r, err := Recover(RecoverOptions{Paths: e.p, VaultDirs: e.dirs, Index: e.idx, Codec: e.codec, ChainIDs: e.stager.ChainIDs})
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

// batch runs one batch of n entries through the protocol up to stopAfter:
// "intent", "vault" (records synced), "stage", "publish", "pebble" or "done".
func (e *env) batch(first, n uint64, ids *IDs, seq uint64, before *merkle.State, tail vault.Tail, stopAfter string) (Manifest, *merkle.State, vault.Tail) {
	e.t.Helper()
	t := e.t
	id := BatchID{Log: "fakelog", First: first, Last: first + n - 1}
	in := Intent{BatchID: id.String(), Log: id.Log, First: id.First, Last: id.Last, VaultTail: tail,
		NextCertID: ids.Peek(), MerkleBefore: before, StartedAt: time.Unix(1, 0).UTC()}
	if err := WriteIntent(e.p, in, e.hook); err != nil {
		t.Fatal(err)
	}
	if stopAfter == "intent" {
		return Manifest{}, nil, tail
	}
	w, err := vault.OpenWriter(vault.Options{Dirs: e.dirs, SegmentSize: 8 << 10}, e.codec, tail)
	if err != nil {
		t.Fatal(err)
	}
	state := before.Clone()
	var rows []dataset.EntryRow
	var chains []dataset.ChainRow
	pb := e.idx.NewBatch()
	defer pb.Close()
	firstID := ids.Peek()
	for i := range n {
		der := e.certs[(first+i)%uint64(len(e.certs))]
		cid, _ := ids.Next()
		loc, err := w.AppendCert(vault.KindLeaf, cid, der, 0)
		if err != nil {
			t.Fatal(err)
		}
		pb.AddCert(sha256.Sum256(der), index.Ref{CertID: cid, Loc: loc})
		lh := merkle.LeafHash([]byte{byte(first + i)})
		state.Append(lh)
		rows = append(rows, dataset.EntryRow{Idx: first + i, CTTimestamp: 1, EntryType: "x509", CertID: cid, LeafHash: lh})
	}
	chainID := sha256.Sum256([]byte{byte(first)})
	chains = append(chains, dataset.ChainRow{ChainID: chainID, Position: 0, CertID: firstID})
	pb.AddChain(chainID)
	w.Sync()
	end := w.Tail()
	w.Close()
	if stopAfter == "vault" {
		return Manifest{}, state, end
	}
	files, err := e.stager.Stage(context.Background(), e.p.StageDir(id), rows, chains)
	if err != nil {
		t.Fatal(err)
	}
	if stopAfter == "stage" {
		return Manifest{}, state, end
	}
	m := Manifest{Format: ManifestFormat, CommitSeq: seq, BatchID: id.String(), Log: id.Log, First: id.First, Last: id.Last,
		MerkleAfter: state, Verified: Verified{Method: "root_equals_sth"}, CertIDRange: &[2]uint64{firstID, ids.Peek() - 1},
		NextCertID: ids.Peek(), Vault: Span{Start: tail, End: end}, Builders: map[string]int{}, Files: files,
		Counts: Counts{Entries: int(n), NewCerts: int(n)}, CTVaultVersion: "test", CommittedAt: time.Unix(2, 0).UTC()}
	if err := Publish(e.p, m, e.hook); err != nil {
		t.Fatal(err)
	}
	if stopAfter == "publish" {
		return m, state, end
	}
	pb.SetApplied(id.Log, seq)
	if err := pb.Commit(); err != nil {
		t.Fatal(err)
	}
	if stopAfter == "pebble" {
		return m, state, end
	}
	if err := RemoveIntent(e.p, id, e.hook); err != nil {
		t.Fatal(err)
	}
	return m, state, end
}

func (e *env) ids(next uint64) *IDs {
	ids, err := LoadIDs(e.p.StateDir(), next, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	return ids
}

func TestCleanCommitAndHookOrder(t *testing.T) {
	e := newEnv(t)
	m, _, end := e.batch(0, 10, e.ids(1), 1, merkle.NewState(), vault.Tail{}, "done")
	want := []string{HookAfterIntent, HookAfterManifest, HookBeforeRename, HookAfterRename, HookBeforeIntentDelete}
	if !slices.Equal(e.hooks, want) {
		t.Fatalf("hooks %v, want %v", e.hooks, want)
	}
	r := e.recover()
	if r.Crashed || r.Tail != end || r.NextCertID != m.NextCertID || len(r.Committed) != 1 || len(r.Actions) != 0 {
		t.Fatalf("a clean vault needs nothing: %+v", r)
	}
	if _, err := os.Stat(e.p.StageDir(m.ID())); !os.IsNotExist(err) {
		t.Fatal("the staging directory is gone after the commit point")
	}
	if err := Publish(e.p, m, nil); err == nil {
		t.Fatal("a committed batch directory is never replaced")
	}
}

// TestRecoverAfterCrashBeforeCommit covers spec §8.5 rows 1-2: vault data
// beyond the committed tail, and an intent whose batch never committed.
func TestRecoverAfterCrashBeforeCommit(t *testing.T) {
	e := newEnv(t)
	ids := e.ids(1)
	m1, s1, end1 := e.batch(0, 10, ids, 1, merkle.NewState(), vault.Tail{}, "done")
	e.batch(10, 15, ids, 2, s1, end1, "stage") // crash after staging: vault data, intent and staging remain
	r := e.recover()
	if !r.Crashed || r.Tail != end1 || len(r.Committed) != 1 {
		t.Fatalf("recovery: %+v", r)
	}
	floor, _ := ReadFloor(e.p.StateDir())
	if r.NextCertID != floor || floor <= 25 {
		t.Fatalf("IDs 11-25 were assigned by the lost attempt; allocation must resume at the floor %d, got %d", floor, r.NextCertID)
	}
	if u, _ := vault.InspectTail(e.dirs, end1); u.Bytes != 0 {
		t.Fatal("uncommitted vault data must be truncated")
	}
	if left, _ := ReadIntents(e.p); len(left) != 0 {
		t.Fatal("the intent must be removed")
	}
	if left, _ := os.ReadDir(filepath.Join(e.p.Root, "tmp", "stage")); len(left) != 0 {
		t.Fatal("the staging directory must be removed")
	}
	// The vault keeps working from the committed tail.
	ids2 := e.ids(r.NextCertID)
	m2, _, _ := e.batch(10, 5, ids2, 2, m1.MerkleAfter, r.Tail, "done")
	if m2.CertIDRange[0] != floor {
		t.Fatalf("the retried batch starts at the floor: %v", m2.CertIDRange)
	}
}

// TestRecoverFinishesACommittedBatch covers spec §8.5 rows 3-4: a crash
// between the commit point and the Pebble apply.
func TestRecoverFinishesACommittedBatch(t *testing.T) {
	e := newEnv(t)
	ids := e.ids(1)
	m1, s1, end1 := e.batch(0, 10, ids, 1, merkle.NewState(), vault.Tail{}, "done")
	m2, _, end2 := e.batch(10, 8, ids, 2, s1, end1, "publish")
	if seq, _ := e.idx.Applied("fakelog"); seq != 1 {
		t.Fatalf("Pebble lags: applied %d", seq)
	}
	r := e.recover()
	if r.Crashed || r.Tail != end2 || r.NextCertID != m2.NextCertID || len(r.Committed) != 2 {
		t.Fatalf("a committed batch is kept as is: %+v", r)
	}
	if seq, _ := e.idx.Applied("fakelog"); seq != 2 {
		t.Fatalf("Pebble must catch up to commit_seq 2, got %d", seq)
	}
	for i := range 8 {
		der := e.certs[(10+i)%len(e.certs)]
		ref, ok, err := e.idx.Lookup(sha256.Sum256(der))
		if err != nil || !ok || ref.CertID != m2.CertIDRange[0]+uint64(i) {
			t.Fatalf("certificate %d of the batch must be re-indexed: %+v %v %v", i, ref, ok, err)
		}
	}
	b := e.idx.NewBatch()
	defer b.Close()
	if has, _ := b.HasChain(sha256.Sum256([]byte{10})); !has {
		t.Fatal("the batch's chains must be re-indexed")
	}
	if left, _ := ReadIntents(e.p); len(left) != 0 {
		t.Fatal("the intent of a committed batch is removed")
	}
	_ = m1
	if again := e.recover(); len(again.Actions) != 0 {
		t.Fatalf("recovery is idempotent: %v", again.Actions)
	}
}

func TestRecoverRefusesDamagedCommits(t *testing.T) {
	for name, damage := range map[string]func(e *env, m Manifest){
		"missing manifest": func(e *env, m Manifest) { os.Remove(filepath.Join(e.p.BatchDir(m.ID()), ManifestFile)) },
		"garbage manifest": func(e *env, m Manifest) {
			os.WriteFile(filepath.Join(e.p.BatchDir(m.ID()), ManifestFile), []byte("{"), 0o644)
		},
		"truncated parquet": func(e *env, m Manifest) {
			p := filepath.Join(e.p.BatchDir(m.ID()), dataset.EntriesFile)
			b, _ := os.ReadFile(p)
			os.WriteFile(p, b[:len(b)/2], 0o644)
		},
		"gap between batches": func(e *env, m Manifest) {
			os.Rename(e.p.BatchDir(m.ID()), filepath.Join(filepath.Dir(e.p.BatchDir(m.ID())), "batch=000000000010-000000000019"))
		},
	} {
		e := newEnv(t)
		ids := e.ids(1)
		_, s1, end1 := e.batch(0, 5, ids, 1, merkle.NewState(), vault.Tail{}, "done")
		m2, _, _ := e.batch(5, 5, ids, 2, s1, end1, "done")
		damage(e, m2)
		_, err := Recover(RecoverOptions{Paths: e.p, VaultDirs: e.dirs, Index: e.idx, Codec: e.codec, ChainIDs: e.stager.ChainIDs})
		if !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: want ErrCorrupt, got %v", name, err)
		}
	}
}

func TestRecoverCleansOnlyStageAndRebuild(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"tmp/stage/leftover/x", "tmp/rebuild/old/y", "tmp/duckdb-123/spill", "tmp/notes/keep"} {
		os.MkdirAll(filepath.Dir(filepath.Join(e.p.Root, p)), 0o755)
		os.WriteFile(filepath.Join(e.p.Root, p), []byte("x"), 0o644)
	}
	e.recover()
	for p, want := range map[string]bool{"tmp/stage/leftover": false, "tmp/rebuild/old": false, "tmp/duckdb-123/spill": true, "tmp/notes/keep": true} {
		if _, err := os.Stat(filepath.Join(e.p.Root, p)); (err == nil) != want {
			t.Errorf("%s: present=%v, want %v (amendment A1 §7: only tmp/stage and tmp/rebuild)", p, err == nil, want)
		}
	}
}

func TestAbandonInProcess(t *testing.T) {
	e := newEnv(t)
	ids := e.ids(1)
	_, s1, end1 := e.batch(0, 5, ids, 1, merkle.NewState(), vault.Tail{}, "done")
	e.batch(5, 10, ids, 2, s1, end1, "stage")
	in, _ := ReadIntents(e.p)
	if len(in) != 1 {
		t.Fatal("one intent in flight")
	}
	if err := Abandon(e.p, e.dirs, in[0]); err != nil {
		t.Fatal(err)
	}
	if u, _ := vault.InspectTail(e.dirs, end1); u.Bytes != 0 {
		t.Fatal("the vault is cut back to the batch's start")
	}
	if left, _ := ReadIntents(e.p); len(left) != 1 || !left[0].Abandoned {
		t.Fatal("the intent stays, marked abandoned, so a restart skips the touched cert_ids")
	}
	if _, err := os.Stat(e.p.StageDir(in[0].ID())); !os.IsNotExist(err) {
		t.Fatal("staging is removed")
	}
	floor, _ := ReadFloor(e.p.StateDir())
	if r := e.recover(); !r.Crashed || r.NextCertID != floor {
		t.Fatalf("a restart after an abandon resumes at the floor %d: %+v", floor, r)
	}
	if left, _ := ReadIntents(e.p); len(left) != 0 {
		t.Fatal("recovery removes the abandoned intent")
	}
}

func (e *env) recoverErr() error {
	_, err := Recover(RecoverOptions{Paths: e.p, VaultDirs: e.dirs, Index: e.idx, Codec: e.codec, ChainIDs: e.stager.ChainIDs})
	return err
}

// TestRecoverRefusesToTruncateUnexplainedData: vault data beyond the
// committed tail that no in-flight batch explains belongs to committed
// batches whose directories went missing (a mistaken rm, a partial
// restore). Truncating it would destroy the only copy; recovery must stop
// with nothing changed.
func TestRecoverRefusesToTruncateUnexplainedData(t *testing.T) {
	e := newEnv(t)
	ids := e.ids(1)
	_, s1, end1 := e.batch(0, 10, ids, 1, merkle.NewState(), vault.Tail{}, "done")
	m2, _, _ := e.batch(10, 10, ids, 2, s1, end1, "done")
	os.RemoveAll(e.p.BatchDir(m2.ID()))
	before, _ := vault.InspectTail(e.dirs, end1)
	if err := e.recoverErr(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("recovery must refuse: %v", err)
	}
	if after, _ := vault.InspectTail(e.dirs, end1); after.Bytes != before.Bytes || before.Bytes == 0 {
		t.Fatalf("nothing may be truncated: %d bytes before, %d after", before.Bytes, after.Bytes)
	}
	os.RemoveAll(filepath.Join(e.p.Root, "dataset", "log=fakelog"))
	if err := e.recoverErr(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a vault with no committed batches at all must not be wiped: %v", err)
	}
}

// TestRecoverRefusesAnIndexAheadOfTheDataset: Pebble is applied after the
// commit point, so it can lag the dataset but never lead it (spec §8.5).
func TestRecoverRefusesAnIndexAheadOfTheDataset(t *testing.T) {
	e := newEnv(t)
	e.batch(0, 10, e.ids(1), 1, merkle.NewState(), vault.Tail{}, "done")
	b := e.idx.NewBatch()
	b.SetApplied("fakelog", 3)
	b.Commit()
	b.Close()
	if err := e.recoverErr(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("an index ahead of the dataset means committed batches are missing: %v", err)
	}
}

// TestRecoverRefusesAForeignSegment: a committed segment whose header names
// another vault (a restore from the wrong backup) is corruption, found
// before Pebble is rebuilt from it (spec §6.2).
func TestRecoverRefusesAForeignSegment(t *testing.T) {
	e := newEnv(t)
	e.batch(0, 10, e.ids(1), 1, merkle.NewState(), vault.Tail{}, "done")
	segs, _ := vault.FindSegments(e.dirs)
	f, _ := os.OpenFile(segs[1], os.O_RDWR, 0)
	b := make([]byte, vault.HeaderSize)
	f.ReadAt(b, 0)
	h, _ := vault.DecodeHeader(b)
	h.VaultUUID = [16]byte{7}
	f.WriteAt(h.Encode(), 0)
	f.Close()
	if err := e.recoverErr(); !errors.Is(err, vault.ErrCorrupt) {
		t.Fatalf("a segment of another vault: %v", err)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/vault/ ./internal/commit/`
Expected: FAIL with `undefined: HookAppendMidRecord` and `undefined: CheckSegments` in `internal/vault`; in `internal/commit`, `TestRecoverRefusesAForeignSegment: a segment of another vault: <nil>`.

- [ ] **Step 3: Implement**

Replace `internal/vault/writer.go` with:

```go
package vault

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/4rji/ctvault/internal/fsutil"
)

// CheckEvery is how often, in bytes appended, the writer re-checks the disk
// cap by default (spec §10.1: "every 256 MiB of vault appends").
const CheckEvery = 256 << 20

// Options configure a Writer.
type Options struct {
	Dirs        []string // vault directories, in VAULT_ID order (absolute paths)
	VaultUUID   [16]byte
	SegmentSize uint64 // vault.segment_size
	// Check is the disk guard: it returns an error if writing need more
	// bytes in dir would cross the cap.
	Check func(dir string, need uint64) error
	// CheckEvery overrides the 256 MiB re-check interval (tests use less).
	CheckEvery uint64
	// Hook, if set, is called at named crash points (tests only).
	Hook func(point string)
	Now  func() time.Time
}

// Hook points the writer passes to Options.Hook.
const (
	HookRolloverBeforeHeader  = "vault.rollover.before_header"
	HookRolloverAfterHeader   = "vault.rollover.after_header"
	HookRolloverBeforeDirSync = "vault.rollover.before_dir_sync"
	// HookAppendMidRecord fires with half of a record written: a kill there
	// leaves a torn record (spec §13.5).
	HookAppendMidRecord = "vault.append.mid_record"
)

// Writer appends records after the committed tail. It is used by one
// goroutine, the batch writer.
type Writer struct {
	o         Options
	codec     *Codec
	segs      map[uint64]string
	f         *os.File
	seg       uint64
	off       uint64
	sinceChk  uint64
	unsynced  bool
	dirOfSeg  string
	preferred string // vault directory the current batch reserved space on
	forceRoll bool   // the current segment is elsewhere: roll over first
}

// OpenWriter positions a writer at the committed tail. The tail segment must
// end exactly at tail.Offset: recovery truncates anything beyond it first.
func OpenWriter(o Options, codec *Codec, tail Tail) (*Writer, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.CheckEvery == 0 {
		o.CheckEvery = CheckEvery
	}
	segs, err := FindSegments(o.Dirs)
	if err != nil {
		return nil, err
	}
	w := &Writer{o: o, codec: codec, segs: segs, seg: tail.Segment, off: tail.Offset}
	for id := range segs {
		if id > tail.Segment {
			return nil, fmt.Errorf("vault: segment %d lies beyond the committed tail %d; run recovery first", id, tail.Segment)
		}
	}
	if tail.Segment == 0 {
		return w, nil
	}
	p, ok := segs[tail.Segment]
	if !ok {
		return nil, corrupt("tail segment %d is missing", tail.Segment)
	}
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if uint64(fi.Size()) != tail.Offset {
		f.Close()
		return nil, fmt.Errorf("vault: segment %d is %d bytes but the committed tail is %d; run recovery first", tail.Segment, fi.Size(), tail.Offset)
	}
	w.f, w.dirOfSeg = f, filepath.Dir(filepath.Dir(p)) // the vault directory, as rollover records it
	return w, nil
}

// Prefer makes new segments go to dir first: the directory the batch
// preflight reserved the vault peak on. If the current segment lives
// elsewhere, the next append starts a new segment in dir.
func (w *Writer) Prefer(dir string) {
	w.preferred = dir
	w.forceRoll = w.f != nil && w.dirOfSeg != dir
}

// Tail returns the position the next record will take.
func (w *Writer) Tail() Tail { return Tail{Segment: w.seg, Offset: w.off} }

func (w *Writer) hook(p string) {
	if w.o.Hook != nil {
		w.o.Hook(p)
	}
}

// rollover syncs the current segment and creates the next one in the first
// vault directory that passes the disk guard.
func (w *Writer) rollover(firstCertID uint64) error {
	if w.f != nil {
		if err := w.f.Sync(); err != nil {
			return err
		}
		if err := w.f.Close(); err != nil {
			return err
		}
		w.f = nil
	}
	var dir string
	var refusals []error
	order := w.o.Dirs
	if w.preferred != "" {
		order = append([]string{w.preferred}, w.o.Dirs...)
	}
	for _, d := range order {
		if w.o.Check == nil {
			dir = d
			break
		}
		err := w.o.Check(d, w.o.SegmentSize)
		if err == nil {
			dir = d
			break
		}
		refusals = append(refusals, err)
	}
	if dir == "" {
		return fmt.Errorf("vault: no vault directory has room for a new segment: %w", refusals[len(refusals)-1])
	}
	id := w.seg + 1
	p := filepath.Join(dir, SegmentsDir, SegmentName(id))
	w.hook(HookRolloverBeforeHeader)
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	h := Header{Version: FormatVersion, VaultUUID: w.o.VaultUUID, Segment: id, FirstCertID: firstCertID, Created: w.o.Now()}
	if _, err := f.WriteAt(h.Encode(), 0); err != nil {
		f.Close()
		return err
	}
	w.hook(HookRolloverAfterHeader)
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	w.hook(HookRolloverBeforeDirSync)
	if err := fsutil.SyncDir(filepath.Dir(p)); err != nil {
		f.Close()
		return err
	}
	w.f, w.seg, w.off, w.dirOfSeg = f, id, HeaderSize, dir
	w.segs[id] = p
	return nil
}

// append writes one record, rolling over first when it would not fit.
func (w *Writer) append(r Record) (Loc, error) {
	rec := AppendRecord(nil, r)
	if w.f == nil || w.forceRoll || w.off+uint64(len(rec)) > w.o.SegmentSize {
		if err := w.rollover(r.CertID); err != nil {
			return Loc{}, err
		}
		w.forceRoll = false
	}
	if w.o.Check != nil {
		w.sinceChk += uint64(len(rec))
		if w.sinceChk >= w.o.CheckEvery {
			if err := w.o.Check(w.dirOfSeg, w.o.CheckEvery); err != nil {
				return Loc{}, err
			}
			w.sinceChk = 0
		}
	}
	if err := w.write(rec); err != nil {
		return Loc{}, err
	}
	loc := Loc{Segment: w.seg, Offset: w.off, Len: uint32(len(rec))}
	w.off += uint64(len(rec))
	w.unsynced = true
	return loc, nil
}

// write puts rec at the tracked offset (a reopened segment's file position
// is 0). With a hook set, as in crash tests, the record goes down in two
// halves with HookAppendMidRecord between them.
func (w *Writer) write(rec []byte) error {
	first := rec
	if w.o.Hook != nil {
		first = rec[:len(rec)/2]
	}
	if _, err := w.f.WriteAt(first, int64(w.off)); err != nil {
		return err
	}
	if len(first) == len(rec) {
		return nil
	}
	w.hook(HookAppendMidRecord)
	_, err := w.f.WriteAt(rec[len(first):], int64(w.off)+int64(len(first)))
	return err
}

// AppendCert vaults der as a leaf (KindLeaf) or chain (KindChain) record
// compressed with dictionary dictID.
func (w *Writer) AppendCert(kind byte, certID uint64, der []byte, dictID uint64) (Loc, error) {
	if kind != KindLeaf && kind != KindChain {
		return Loc{}, fmt.Errorf("vault: AppendCert with kind %d", kind)
	}
	frame, err := w.codec.Compress(der, dictID)
	if err != nil {
		return Loc{}, err
	}
	return w.append(Record{Kind: kind, CertID: certID, DictID: dictID, Frame: frame})
}

// AppendDelta vaults der as a leaf-delta record against the leaf record at
// base, which must lie earlier in the vault: a committed record, or one of
// the in-flight batch (truncation always removes the newest records first).
func (w *Writer) AppendDelta(certID uint64, der []byte, base Loc) (Loc, error) {
	baseDER, err := w.readLeaf(base)
	if err != nil {
		return Loc{}, err
	}
	frame, err := w.codec.CompressDelta(der, baseDER)
	if err != nil {
		return Loc{}, err
	}
	return w.append(Record{Kind: KindDelta, CertID: certID, BaseSeg: base.Segment, BaseOff: base.Offset, Frame: frame})
}

// readLeaf decodes the leaf record at loc, which may still be unsynced.
func (w *Writer) readLeaf(loc Loc) ([]byte, error) {
	b, err := w.readAt(loc.Segment, loc.Offset, int(loc.Len))
	if err != nil {
		return nil, err
	}
	rec, err := ParseRecord(b)
	if err != nil || rec.TotalLen != int(loc.Len) || rec.Kind != KindLeaf {
		return nil, corrupt("delta base %d:%d is not a leaf record", loc.Segment, loc.Offset)
	}
	return w.codec.Decompress(rec.Frame, rec.DictID)
}

// Sync makes every appended record durable (commit step P3).
func (w *Writer) Sync() error {
	if w.f == nil || !w.unsynced {
		return nil
	}
	if err := w.f.Sync(); err != nil {
		return err
	}
	w.unsynced = false
	return nil
}

// readAt reads n bytes of segment id at off, including unsynced data.
func (w *Writer) readAt(id, off uint64, n int) ([]byte, error) {
	p, ok := w.segs[id]
	if !ok {
		return nil, corrupt("segment %d does not exist", id)
	}
	f := w.f
	if id != w.seg || f == nil {
		var err error
		if f, err = os.Open(p); err != nil {
			return nil, err
		}
		defer f.Close()
	}
	b := make([]byte, n)
	if _, err := f.ReadAt(b, int64(off)); err != nil && err != io.EOF {
		return nil, err
	}
	return b, nil
}

// Close closes the current segment without syncing it.
func (w *Writer) Close() error {
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
```

Replace `internal/vault/truncate.go` with:

```go
package vault

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"

	"github.com/4rji/ctvault/internal/fsutil"
)

// Uncommitted describes vault data beyond the committed tail.
type Uncommitted struct {
	Bytes     uint64 // bytes beyond the tail
	MaxCertID uint64 // highest cert_id in an intact record there, 0 if none
}

// InspectTail measures the data beyond the committed tail (spec §8.5): the
// highest cert_id seen there must be lifted into ID_FLOOR before Truncate
// discards it. Torn records at the end are expected and tolerated. Records
// are streamed, and a segment that ends exactly at the tail is not read.
func InspectTail(dirs []string, tail Tail) (Uncommitted, error) {
	segs, err := FindSegments(dirs)
	if err != nil {
		return Uncommitted{}, err
	}
	var u Uncommitted
	for id, p := range segs {
		if id < tail.Segment {
			continue
		}
		fi, err := os.Stat(p)
		if err != nil {
			return u, err
		}
		size := uint64(fi.Size())
		start := uint64(HeaderSize) // records follow the header even if it is torn or damaged
		if id == tail.Segment {
			if size < tail.Offset {
				return u, corrupt("segment %d is %d bytes, shorter than the committed tail %d", id, size, tail.Offset)
			}
			u.Bytes += size - tail.Offset
			start = tail.Offset
		} else {
			u.Bytes += size
		}
		if start >= size {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			return u, err
		}
		// A torn or garbage record ends the scan: that is the crash point.
		_ = eachRecord(f, id, start, size, func(_ Loc, rec Record) error {
			u.MaxCertID = max(u.MaxCertID, rec.CertID)
			return nil
		})
		f.Close()
	}
	return u, nil
}

// Truncate removes everything beyond the committed tail: the tail segment is
// cut back to tail.Offset, later segments are deleted, and both are synced.
// Delta records only point backwards, so no committed record loses its base.
// A tail segment that is missing or shorter than tail.Offset is corruption:
// truncating would extend it with zeros.
func Truncate(dirs []string, tail Tail) error {
	segs, err := FindSegments(dirs)
	if err != nil {
		return err
	}
	if tail.Segment > 0 {
		p, ok := segs[tail.Segment]
		if !ok {
			return corrupt("tail segment %d is missing", tail.Segment)
		}
		fi, err := os.Stat(p)
		if err != nil {
			return err
		}
		if uint64(fi.Size()) < tail.Offset {
			return corrupt("segment %d is %d bytes, shorter than the tail %d it would be cut to", tail.Segment, fi.Size(), tail.Offset)
		}
	}
	for id, p := range segs {
		switch {
		case id > tail.Segment:
			if err := os.Remove(p); err != nil {
				return err
			}
			if err := fsutil.SyncDir(filepath.Dir(p)); err != nil {
				return err
			}
		case id == tail.Segment:
			f, err := os.OpenFile(p, os.O_RDWR, 0)
			if err != nil {
				return err
			}
			if tail.Offset > math.MaxInt64 {
				f.Close()
				return errors.New("vault: tail offset out of range")
			}
			err = f.Truncate(int64(tail.Offset))
			if err == nil {
				err = f.Sync()
			}
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return fmt.Errorf("truncating segment %d: %w", id, err)
			}
		}
	}
	return nil
}
```

Create `internal/vault/check.go`:

```go
package vault

import (
	"errors"
	"io"
	"os"
)

// CheckSegments verifies the committed vault's segment files (spec §6.2):
// segments 1 to tail.Segment all exist, none lies beyond the tail, and every
// header is intact and names its own segment and this vault's UUID. A
// missing segment, or one restored from another vault, is corruption.
func CheckSegments(dirs []string, uuid [16]byte, tail Tail) error {
	segs, err := FindSegments(dirs)
	if err != nil {
		return err
	}
	for id := range segs {
		if id > tail.Segment {
			return corrupt("segment %d lies beyond the committed tail %d", id, tail.Segment)
		}
	}
	for id := uint64(1); id <= tail.Segment; id++ {
		p, ok := segs[id]
		if !ok {
			return corrupt("segment %d is missing", id)
		}
		if err := checkHeader(p, id, uuid); err != nil {
			return err
		}
	}
	return nil
}

func checkHeader(p string, id uint64, uuid [16]byte) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	b := make([]byte, HeaderSize)
	n, err := f.ReadAt(b, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	h, err := DecodeHeader(b[:n])
	if err != nil {
		return corrupt("segment %d: %v", id, err)
	}
	if h.Segment != id {
		return corrupt("segment file %d holds segment %d", id, h.Segment)
	}
	if h.VaultUUID != uuid {
		return corrupt("segment %d belongs to another vault (UUID %x)", id, h.VaultUUID)
	}
	return nil
}
```

Replace `internal/commit/recover.go` with:

```go
package commit

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/vault"
)

// RecoverOptions are the writer's resources, under the writer lock.
type RecoverOptions struct {
	Paths     Paths
	VaultDirs []string
	VaultUUID [16]byte // every segment header must carry it
	Index     *index.Index
	Codec     *vault.Codec // with every dictionary loaded
	// ChainIDs reads the chain_id column of a committed chains.parquet.
	ChainIDs func(path string) ([][32]byte, error)
}

// Recovered is the committed state after recovery.
type Recovered struct {
	Committed  []Manifest // by commit_seq
	Tail       vault.Tail // committed vault tail
	NextCertID uint64     // where cert_id allocation resumes
	Crashed    bool       // an attempt was lost; IDs resume at ID_FLOOR
	Actions    []string   // what recovery did, for the log
}

// LastSeq returns the highest committed commit_seq, 0 if none.
func (r Recovered) LastSeq() uint64 {
	if len(r.Committed) == 0 {
		return 0
	}
	return r.Committed[len(r.Committed)-1].CommitSeq
}

// Recover brings the vault back to its last committed state (spec §8.5). It
// runs at writer start, under the lock, before any work:
//
//  1. Committed batches are read and checked; a damaged one is corruption.
//  2. Vault data beyond the committed tail lifts ID_FLOOR above every
//     cert_id seen there, then is truncated.
//  3. Intents of committed batches are dropped; intents of uncommitted
//     batches lose their staging directory, then the intent.
//  4. Only tmp/stage/* and tmp/rebuild/* are cleaned (amendment A1 §7).
//  5. Every committed segment must exist and carry this vault's UUID.
//  6. Pebble catches up on committed batches it has not applied, by
//     re-reading their vault ranges and chains.parquet; this is idempotent.
func Recover(o RecoverOptions) (Recovered, error) {
	var r Recovered
	committed, err := ListCommitted(o.Paths.Root)
	if err != nil {
		return r, err
	}
	r.Committed, r.NextCertID = committed, 1
	if n := len(committed); n > 0 {
		r.Tail, r.NextCertID = committed[n-1].Vault.End, committed[n-1].NextCertID
	}

	// Pebble is applied after the commit point, so it may lag the dataset but
	// never lead it. A log applied beyond its highest committed batch means
	// committed batch directories are missing: stop before changing anything.
	applied, err := o.Index.AppliedLogs()
	if err != nil {
		return r, err
	}
	highest := map[string]uint64{}
	for _, m := range committed {
		highest[m.Log] = max(highest[m.Log], m.CommitSeq)
	}
	for log, seq := range applied {
		if seq > highest[log] {
			return r, corrupt("the index has applied commit_seq %d of log %s, but its highest committed batch is %d: "+
				"committed batch directories are missing; restore them (nothing was changed)", seq, log, highest[log])
		}
	}

	intents, err := ReadIntents(o.Paths)
	if err != nil {
		return r, err
	}
	u, err := vault.InspectTail(o.VaultDirs, r.Tail)
	if err != nil {
		return r, err
	}
	if u.Bytes > 0 {
		// Every legitimate crash leaves the intent of the batch in flight,
		// written (P1) before its first append, whose vault tail is the
		// committed tail. Data nothing explains belongs to committed batches
		// whose directories are gone: never truncate it.
		explained := false
		for _, in := range intents {
			_, err := os.Stat(filepath.Join(o.Paths.BatchDir(in.ID()), ManifestFile))
			if in.VaultTail == r.Tail && err != nil {
				explained = true
			}
		}
		if !explained {
			return r, corrupt("%d bytes of vault data lie beyond the committed tail %d:%d and no batch in flight explains them: "+
				"committed batch directories may be missing; restore them (nothing was changed)", u.Bytes, r.Tail.Segment, r.Tail.Offset)
		}
		r.Crashed = true
		ids, err := LoadIDs(o.Paths.StateDir(), 1, nil)
		if err != nil {
			return r, err
		}
		if err := ids.Raise(u.MaxCertID + 1); err != nil {
			return r, err
		}
		if err := vault.Truncate(o.VaultDirs, r.Tail); err != nil {
			return r, err
		}
		r.Actions = append(r.Actions, fmt.Sprintf("truncated %d uncommitted vault bytes (highest cert_id %d)", u.Bytes, u.MaxCertID))
	}

	for _, in := range intents {
		if _, err := os.Stat(filepath.Join(o.Paths.BatchDir(in.ID()), ManifestFile)); err == nil {
			r.Actions = append(r.Actions, "batch "+in.BatchID+" was committed; finishing it")
		} else {
			r.Crashed = true
			if err := os.RemoveAll(o.Paths.StageDir(in.ID())); err != nil {
				return r, err
			}
			r.Actions = append(r.Actions, "abandoned uncommitted batch "+in.BatchID)
		}
		if err := RemoveIntent(o.Paths, in.ID(), nil); err != nil {
			return r, err
		}
	}

	for _, sub := range []string{"stage", "rebuild"} {
		dir := filepath.Join(o.Paths.Root, "tmp", sub)
		left, _ := os.ReadDir(dir)
		for _, e := range left {
			if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
				return r, err
			}
			r.Actions = append(r.Actions, "removed leftover tmp/"+sub+"/"+e.Name())
		}
	}

	if err := vault.CheckSegments(o.VaultDirs, o.VaultUUID, r.Tail); err != nil {
		return r, err
	}

	if err := catchUp(o, committed, &r); err != nil {
		return r, err
	}

	if r.Crashed {
		floor, err := ReadFloor(o.Paths.StateDir())
		if err != nil {
			return r, err
		}
		r.NextCertID = max(r.NextCertID, floor)
	}
	return r, nil
}

// catchUp re-applies committed batches that Pebble has not recorded (spec
// §8.5: Pebble only ever lags the dataset).
func catchUp(o RecoverOptions, committed []Manifest, r *Recovered) error {
	applied := map[string]uint64{}
	var reader *vault.Reader
	defer func() {
		if reader != nil {
			reader.Close()
		}
	}()
	for _, m := range committed {
		seq, ok := applied[m.Log]
		if !ok {
			var err error
			if seq, err = o.Index.Applied(m.Log); err != nil {
				return err
			}
			applied[m.Log] = seq
		}
		if m.CommitSeq <= seq {
			continue
		}
		if reader == nil {
			var err error
			if reader, err = vault.OpenReader(o.VaultDirs, o.Codec); err != nil {
				return err
			}
		}
		b := o.Index.NewBatch()
		err := vault.Scan(o.VaultDirs, m.Vault.Start, m.Vault.End, func(loc vault.Loc, rec vault.Record) error {
			der, _, err := reader.Read(loc)
			if err != nil {
				return err
			}
			return b.AddCert(sha256.Sum256(der), index.Ref{CertID: rec.CertID, Loc: loc})
		})
		if err == nil {
			var ids [][32]byte
			ids, err = o.ChainIDs(filepath.Join(o.Paths.BatchDir(m.ID()), dataset.ChainsFile))
			for _, id := range ids {
				if err == nil {
					err = b.AddChain(id)
				}
			}
		}
		if err == nil {
			err = b.SetApplied(m.Log, m.CommitSeq)
		}
		if err == nil {
			err = b.Commit()
		}
		b.Close()
		if err != nil {
			return fmt.Errorf("re-applying batch %s to the index: %w", m.BatchID, err)
		}
		applied[m.Log] = m.CommitSeq
		r.Actions = append(r.Actions, "re-applied batch "+m.BatchID+" to the index")
	}
	return nil
}
```

Replace `internal/ingest/writer.go` with:

```go
// Package ingest runs batches: it fetches a range of a log, verifies it
// against a pinned signed tree head, vaults new certificates, stages the
// source-layer Parquet files and commits through the protocol of spec §8.3.
package ingest

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

// Options configure a Writer. The caller holds the writer lock and has run
// the volume checks.
type Options struct {
	Root      string
	VaultDirs []string // absolute, in VAULT_ID order
	VaultUUID [16]byte
	Config    config.Config
	Guard     diskguard.Guard
	Fetch     fetch.Options // workers, rate and stall timeout from Config, plus test overrides
	Version   string
	Now       func() time.Time
	Out       io.Writer    // one line per batch and recovery action
	Hook      func(string) // crash points, tests only
	// CheckVolumes repeats the volume checks (spec §9.2) at every batch
	// preflight; a failure stops the batch before anything is written.
	CheckVolumes func() error

	// DictSamples is how many leaf certificates train dictionary 1 (20,000;
	// tests use fewer). Train defaults to vault.Train.
	DictSamples int
	Train       func(samples [][]byte, id uint64) ([]byte, error)
	// CanarySamples is how many rows and vault records the canary checks
	// per batch (default 64).
	CanarySamples int
}

// Writer is the single writer of a vault.
type Writer struct {
	o      Options
	paths  commit.Paths
	idx    *index.Index
	codec  *vault.Codec
	stager *dataset.Stager
	ids    *commit.IDs
	vw     *vault.Writer
	delta  *vault.DeltaCache
	dictID uint64

	trainTried bool

	committed []commit.Manifest
	tips      map[string]commit.LogTip
}

func (w *Writer) logf(format string, args ...any) {
	if w.o.Out != nil {
		fmt.Fprintf(w.o.Out, format+"\n", args...)
	}
}

// Open recovers the vault (spec §8.5) and prepares the writer: index,
// dictionaries, cert_id allocator, vault tail, delta cache warm-up and
// views.sql.
func Open(o Options) (*Writer, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.DictSamples == 0 {
		o.DictSamples = vault.TrainingSamples
	}
	if o.Train == nil {
		o.Train = vault.Train
	}
	if o.CanarySamples == 0 {
		o.CanarySamples = 64
	}
	w := &Writer{o: o, paths: commit.Paths{Root: o.Root}}
	ok := false
	defer func() {
		if !ok {
			w.Close()
		}
	}()
	var err error
	if w.idx, err = index.Open(filepath.Join(o.Root, "state", "pebble")); err != nil {
		return nil, err
	}
	if w.codec, err = vault.NewCodec(); err != nil {
		return nil, err
	}
	dicts, err := vault.LoadDicts(o.VaultDirs)
	if err != nil {
		return nil, err
	}
	for _, d := range dicts {
		if err := w.codec.AddDict(d.Manifest.ID, d.Content); err != nil {
			return nil, err
		}
		w.dictID = d.Manifest.ID
	}
	spill := filepath.Join(o.Root, "tmp", fmt.Sprintf("duckdb-%d", os.Getpid()))
	if w.stager, err = dataset.NewStager(dataset.Options{TempDir: spill, MaxTempBytes: w.spillLimit()}); err != nil {
		return nil, err
	}
	rec, err := commit.Recover(commit.RecoverOptions{Paths: w.paths, VaultDirs: o.VaultDirs, VaultUUID: o.VaultUUID, Index: w.idx,
		Codec: w.codec, ChainIDs: w.stager.ChainIDs})
	if err != nil {
		return nil, err
	}
	for _, a := range rec.Actions {
		w.logf("recovery: %s", a)
	}
	w.committed, w.tips = rec.Committed, commit.Tips(rec.Committed)
	if w.ids, err = commit.LoadIDs(w.paths.StateDir(), rec.NextCertID, o.Hook); err != nil {
		return nil, err
	}
	if w.vw, err = vault.OpenWriter(w.vaultOptions(), w.codec, rec.Tail); err != nil {
		return nil, err
	}
	if err := w.warm(); err != nil {
		return nil, err
	}
	if _, err := dataset.WriteViews(o.Root); err != nil {
		return nil, err
	}
	ok = true
	return w, nil
}

func (w *Writer) vaultOptions() vault.Options {
	return vault.Options{Dirs: w.o.VaultDirs, VaultUUID: w.o.VaultUUID, SegmentSize: uint64(w.o.Config.Vault.SegmentSize),
		Check: w.o.Guard.Check, Hook: w.o.Hook, Now: w.o.Now}
}

// SpillBudget caps the writer's DuckDB spill. Spec §10.1 sets every DuckDB
// session's spill limit to the headroom below the cap minus 1 GiB, and
// amendment A1 §7 adds the limit to every batch's peak; together no batch
// could ever start. The writer therefore spills at most this budget, and
// the preflight counts it (Plan 2B decision). Plan 2's tables fit in memory.
const SpillBudget = 4 << 30

// spillLimit is the writer's max_temp_directory_size: the budget, or less
// when the headroom below the cap minus a 1 GiB margin is smaller, but at
// least 64 MiB.
func (w *Writer) spillLimit() uint64 {
	const margin, floor = 1 << 30, 64 << 20
	u, err := w.o.Guard.Stat(w.o.Root)
	if err != nil || u.Total == 0 {
		return floor
	}
	lim := uint64(w.o.Guard.Cap * float64(u.Total))
	if used := u.Used(); lim > used+margin+floor {
		return min(SpillBudget, lim-used-margin)
	}
	return floor
}

// warm refills the delta cache from the last delta.warm_batches committed
// batches (amendment A1 §5).
func (w *Writer) warm() error {
	if w.delta == nil {
		w.delta = vault.NewDeltaCache(w.o.Config.Ingest.DeltaLRUEntries)
	} else {
		w.delta.Reset() // reuse the cache's memory (207 MiB at the default size)
	}
	n := w.o.Config.Delta.WarmBatches
	var ranges []vault.Range
	for i := max(0, len(w.committed)-n); i < len(w.committed); i++ {
		ranges = append(ranges, vault.Range{Start: w.committed[i].Vault.Start, End: w.committed[i].Vault.End})
	}
	return vault.Warm(w.o.VaultDirs, w.codec, w.delta, ranges, leaf.PrecertIssuanceDigest)
}

// Next returns the first index of log not yet committed.
func (w *Writer) Next(log string) uint64 { return w.tips[log].Next }

// LastCommitSeq returns the highest commit_seq.
func (w *Writer) LastCommitSeq() uint64 {
	if len(w.committed) == 0 {
		return 0
	}
	return w.committed[len(w.committed)-1].CommitSeq
}

// Close releases every resource; it never commits anything. Closing twice
// is harmless.
func (w *Writer) Close() error {
	var errs []error
	if w.vw != nil {
		errs = append(errs, w.vw.Close())
		w.vw = nil
	}
	if w.stager != nil {
		errs = append(errs, w.stager.Close())
		w.stager = nil
	}
	if w.codec != nil {
		w.codec.Close()
		w.codec = nil
	}
	if w.idx != nil {
		errs = append(errs, w.idx.Close())
		w.idx = nil
	}
	return errors.Join(errs...)
}

// ErrVerification wraps a batch that failed Merkle verification or the
// canary twice: an incident (spec §12, exit 5).
var ErrVerification = errors.New("batch failed verification twice")

// errRetry marks a verification or canary failure; the batch is refetched
// once. A Merkle failure carries the evidence an incident records (spec
// §12): our compact range before the batch, the root we computed at end,
// and the proof the log served.
type errRetry struct {
	err    error
	before *merkle.State
	root   [32]byte
	end    uint64
	proof  [][32]byte
}

func (e errRetry) Error() string { return e.err.Error() }
func (e errRetry) Unwrap() error { return e.err }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race ./internal/vault/ ./internal/commit/ ./internal/ingest/`
Expected: PASS.

- [ ] **Step 5: Quality gate** (Global Constraints)

- [ ] **Step 6: Checkpoint.** Record the task in the ledger. The user commits.

---

### Task C2: Engine hooks, abandon failure, the writer's spill folder (M2a, M10, M11)

Spec §8.3 (P3, P6, P9), §13.5, amendment A1 §7 (the `tmp/` scope). It also fixes a Plan 1 bug in `merkle.State.Clone` that this task's tests found.

**Files:**
- Modify: `internal/ingest/batch.go`, `internal/ingest/writer.go`, `internal/merkle/state.go`
- Tests: `internal/ingest/safety_test.go` (new), `internal/merkle/clone_test.go` (new), `internal/ingest/ingest_test.go`

**Interfaces:**
- Produces (`ingest`):
  - hook points `HookAfterVaultSync = "commit.P3.after_vault_sync"`, `HookDuringCanary = "commit.P6.during_canary"`, `HookBeforePebble = "commit.P9.before_pebble"`, `HookAfterPebble = "commit.P9.after_pebble"`
  - `ErrAbandonFailed`: after it, every `Batch` call returns it
  - `WriterSpillDir = "duckdb-writer"`
- Changes:
  - `merkle.(*State).Clone` copies the hash list.
  - An attempt abandoned under a cancelled context empties the delta cache and marks it cold. The next attempt warms it.

- [ ] **Step 1: Write the failing tests**

Create `internal/ingest/safety_test.go`:

```go
package ingest

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/vault"
)

// TestEngineHookOrder: a clean batch passes every named commit boundary of
// spec §13.5 in protocol order.
func TestEngineHookOrder(t *testing.T) {
	h := newHarness(t, entries(t, 40), ctlogtest.Options{})
	var points []string
	h.opts.Hook = func(p string) {
		if strings.HasPrefix(p, "commit.") {
			points = append(points, p)
		}
	}
	h.ingest(h.open(), h.head(), 0, 40, 40)
	want := []string{commit.HookAfterIntent, HookAfterVaultSync, HookDuringCanary, commit.HookAfterManifest,
		commit.HookBeforeRename, commit.HookAfterRename, HookBeforePebble, HookAfterPebble, commit.HookBeforeIntentDelete}
	if !slices.Equal(points, want) {
		t.Fatalf("hooks %v\nwant %v", points, want)
	}
}

// TestAbandonFailureStopsTheWriter: when an attempt cannot be cleaned up in
// process, the writer refuses every further batch instead of writing over
// a vault in an unknown state; the next start recovers.
func TestAbandonFailureStopsTheWriter(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	h := newHarness(t, entries(t, 40), ctlogtest.Options{})
	intents := filepath.Join(h.root, "state", "intent")
	bctx, cancel := context.WithCancel(ctx)
	h.opts.Hook = func(p string) {
		if p == HookAfterVaultSync {
			os.Chmod(intents, 0o555) // the abandon cannot mark its intent
			cancel()                 // and the batch fails: a second Ctrl-C
		}
	}
	t.Cleanup(func() { os.Chmod(intents, 0o755) })
	w := h.open()
	sth := h.head()
	if _, err := w.Batch(bctx, h.src, sth, 0, 20); !errors.Is(err, ErrAbandonFailed) || !errors.Is(err, context.Canceled) {
		t.Fatalf("the batch error and the failed abandon: %v", err)
	}
	os.Chmod(intents, 0o755)
	requests := h.log.Requests("get-entries")
	if _, err := w.Batch(ctx, h.src, sth, 0, 20); !errors.Is(err, ErrAbandonFailed) {
		t.Fatalf("a writer whose abandon failed must refuse more batches: %v", err)
	}
	if h.log.Requests("get-entries") != requests {
		t.Fatal("the refused batch must not fetch anything")
	}
	w.Close()
	h.opts.Hook = nil
	h.ingest(h.open(), sth, 0, 40, 20)
}

// TestAbandonAfterHardStopSkipsTheWarmUp: an attempt abandoned because the
// process is stopping does not re-read the vault to warm the delta cache;
// the cache is emptied, and warmed again only if another batch runs.
func TestAbandonAfterHardStopSkipsTheWarmUp(t *testing.T) {
	h := newHarness(t, entries(t, 100), ctlogtest.Options{})
	sth := h.head()
	w := h.open()
	h.ingest(w, sth, 0, 51, 51) // ends with the precert of pair 25
	bctx, cancel := context.WithCancel(ctx)
	h.opts.Hook = func(p string) {
		if p == HookAfterVaultSync {
			cancel()
		}
	}
	w.o.Hook = h.opts.Hook
	if _, err := w.Batch(bctx, h.src, sth, 51, 100); !errors.Is(err, context.Canceled) {
		t.Fatalf("the stopped batch: %v", err)
	}
	if !w.cold || w.delta.Len() != 0 {
		t.Fatalf("after a stop the cache is emptied and left cold: cold %v, %d entries", w.cold, w.delta.Len())
	}
	w.o.Hook = nil
	ms := h.ingest(w, sth, 51, 100, 49)
	if ms[0].Counts.DeltaRecords != 25 || w.cold {
		t.Fatalf("the next batch warms the cache first: %d deltas, want 25 (cold %v)", ms[0].Counts.DeltaRecords, w.cold)
	}
}

// TestWriterSpillFolderIsItsOwn: the writer's DuckDB spill folder is
// tmp/duckdb-writer. A killed writer's leftover is emptied at the next
// start (the lock makes it ours), and Close removes it; readers' spill
// folders and other files in tmp/ are never touched (amendment A1 §7).
func TestWriterSpillFolderIsItsOwn(t *testing.T) {
	h := newHarness(t, entries(t, 20), ctlogtest.Options{})
	tmp := filepath.Join(h.root, "tmp")
	for _, f := range []string{"duckdb-writer/leftover.tmp", "duckdb-4242/reader.tmp", "mine.txt"} {
		os.MkdirAll(filepath.Dir(filepath.Join(tmp, f)), 0o755)
		os.WriteFile(filepath.Join(tmp, f), []byte("x"), 0o644)
	}
	w := h.open()
	if _, err := os.Stat(filepath.Join(tmp, "duckdb-writer", "leftover.tmp")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the killed writer's spill file must go: %v", err)
	}
	h.ingest(w, h.head(), 0, 20, 20)
	w.Close()
	var left []string
	filepath.WalkDir(tmp, func(p string, d os.DirEntry, err error) error {
		if err == nil && p != tmp {
			rel, _ := filepath.Rel(tmp, p)
			left = append(left, rel)
		}
		return nil
	})
	want := []string{"duckdb-4242", "duckdb-4242/reader.tmp", "mine.txt", "rebuild", "stage"}
	if !slices.Equal(left, want) {
		t.Fatalf("tmp/ after Close: %v, want %v", left, want)
	}
}

// TestRefetchAfterAFailedCanaryCommits: spec §8.3 P6 retries a batch once.
// The retry must verify: the failed attempt must not have touched the
// committed Merkle tip it started from.
func TestRefetchAfterAFailedCanaryCommits(t *testing.T) {
	h := newHarness(t, entries(t, 80), ctlogtest.Options{})
	sth := h.head()
	w := h.open()
	h.ingest(w, sth, 0, 40, 40)
	start := w.vw.Tail()
	segs, _ := vault.FindSegments(h.vaultDirs())
	fired := false
	h.opts.Hook = func(p string) {
		if p == HookDuringCanary && !fired {
			fired = true // damage every record of this attempt once
			f, _ := os.OpenFile(segs[start.Segment], os.O_RDWR, 0)
			fi, _ := f.Stat()
			f.WriteAt(bytes.Repeat([]byte{0xff}, int(fi.Size())-int(start.Offset)), int64(start.Offset))
			f.Close()
		}
	}
	w.o.Hook = h.opts.Hook
	m, err := w.Batch(ctx, h.src, sth, 40, 80)
	if err != nil || !fired || w.Next("fakelog") != 80 {
		t.Fatalf("the refetched batch must commit: %v (canary failed once: %v)", err, fired)
	}
	if root, _ := m.MerkleAfter.Root(); root != sth.RootHash {
		t.Fatal("the committed batch must verify to the signed root")
	}
}
```

Create `internal/merkle/clone_test.go`:

```go
package merkle

import "testing"

// TestCloneIsIndependent: appending to a clone must never change the
// original. The compact range's hash list was shared, so a clone's merges
// overwrote the original's last node: an abandoned batch attempt then
// corrupted the committed tip, and every retry failed verification.
func TestCloneIsIndependent(t *testing.T) {
	s := NewState()
	for i := range 3 {
		s.Append(LeafHash([]byte{byte(i)}))
	}
	want, _ := s.Root()
	c := s.Clone()
	for i := range 5 {
		c.Append(LeafHash([]byte{byte(10 + i)}))
	}
	if got, _ := s.Root(); got != want || s.Size() != 3 {
		t.Fatalf("appending to the clone changed the original (size %d)", s.Size())
	}
}
```

Replace `internal/ingest/ingest_test.go` with:

```go
package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/vault"
)

var ctx = context.Background()

type harness struct {
	t      *testing.T
	root   string
	log    *ctlogtest.Log
	chains *logsource.ChainCache
	src    *rfc6962.Source
	opts   Options
	out    bytes.Buffer
}

func entries(t *testing.T, n int) []ctlogtest.Entry {
	t.Helper()
	g, err := ctlogtest.NewGenerator()
	if err != nil {
		t.Fatal(err)
	}
	es, err := g.Entries(n)
	if err != nil {
		t.Fatal(err)
	}
	return es
}

func newHarness(t *testing.T, es []ctlogtest.Entry, lo ctlogtest.Options) *harness {
	t.Helper()
	h := &harness{t: t, root: t.TempDir()}
	for _, d := range []string{"state/intent", "state/incidents", "state/logs", "vault/segments", "vault/dict", "dataset", "tmp/stage", "tmp/rebuild"} {
		os.MkdirAll(filepath.Join(h.root, d), 0o755)
	}
	h.log = ctlogtest.NewWithEntries(t, es, lo)
	pub, _ := x509.ParsePKIXPublicKey(h.log.PublicKeyDER)
	h.chains = logsource.NewChainCache(logsource.DefaultChainCacheBytes)
	h.src = rfc6962.NewSource(logsource.LogInfo{Name: "fakelog", LogID: h.log.LogID, PublicKey: pub, URL: h.log.URL}, nil, h.chains, nil)
	cfg := config.Default()
	cfg.Ingest.DeltaLRUEntries = 1000
	cfg.Vault.SegmentSize = 64 << 10
	free := func(string) (diskguard.Usage, error) {
		return diskguard.Usage{Total: 1 << 40, Avail: 1 << 39, Dev: 1}, nil
	}
	h.opts = Options{Root: h.root, VaultDirs: []string{filepath.Join(h.root, "vault")}, Config: cfg,
		Guard: diskguard.Guard{Cap: 0.85, Stat: free}, Version: "test", Out: &h.out, DictSamples: 1 << 30, CanarySamples: 16,
		Fetch: fetch.Options{MaxRPS: 1000, MinBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond},
		Now:   func() time.Time { return time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC) }}
	return h
}

func (h *harness) open() *Writer {
	h.t.Helper()
	w, err := Open(h.opts)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { w.Close() })
	return w
}

func (h *harness) head() logsource.SignedHead {
	h.t.Helper()
	sth, err := h.src.Head(ctx)
	if err != nil {
		h.t.Fatal(err)
	}
	return sth
}

// ingest commits [from, to) in batches of size and resets the chain cache
// after each, as update does.
func (h *harness) ingest(w *Writer, sth logsource.SignedHead, from, to, size uint64) []commit.Manifest {
	h.t.Helper()
	var ms []commit.Manifest
	for first := from; first < to; first += size {
		m, err := w.Batch(ctx, h.src, sth, first, min(first+size, to))
		if err != nil {
			h.t.Fatalf("batch at %d: %v", first, err)
		}
		h.chains.Reset()
		ms = append(ms, m)
	}
	return ms
}

func (h *harness) vaultDirs() []string { return h.opts.VaultDirs }

func TestIngestCommitsVerifiedBatches(t *testing.T) {
	es := entries(t, 200)
	h := newHarness(t, es, ctlogtest.Options{})
	w := h.open()
	sth := h.head()
	ms := h.ingest(w, sth, 0, 200, 50)
	if w.Next("fakelog") != 200 || w.LastCommitSeq() != 4 {
		t.Fatalf("next %d, commit_seq %d", w.Next("fakelog"), w.LastCommitSeq())
	}
	if ms[0].Verified.Method != "consistency_proof" || ms[3].Verified.Method != "root_equals_sth" {
		t.Fatalf("verification methods %q, %q", ms[0].Verified.Method, ms[3].Verified.Method)
	}
	if root, _ := ms[3].MerkleAfter.Root(); root != sth.RootHash {
		t.Fatal("the final compact range must reach the signed root")
	}
	total := 0
	for i, m := range ms {
		total += m.Counts.NewCerts
		if m.Counts.Entries != 50 || m.Counts.DeltaRecords != 25 || m.Files["entries.parquet"].Rows != 50 {
			t.Fatalf("batch %d: %+v; every final certificate follows its precert, so 25 deltas", i, m.Counts)
		}
		if want := map[bool]int{true: 1, false: 0}[i == 0]; m.Files["chains.parquet"].Rows != want {
			t.Fatalf("batch %d: %d chain rows; the CA chain is written once, in batch 0", i, m.Files["chains.parquet"].Rows)
		}
	}
	if total != 201 {
		t.Fatalf("200 certificates plus the CA: %d new certificates", total)
	}
	w.Close()
	idx, _ := index.Open(filepath.Join(h.root, "state", "pebble"))
	defer idx.Close()
	codec, _ := vault.NewCodec()
	defer codec.Close()
	r, _ := vault.OpenReader(h.vaultDirs(), codec)
	defer r.Close()
	for _, e := range es {
		sha := sha256.Sum256(e.CertDER)
		ref, ok, err := idx.Lookup(sha)
		if err != nil || !ok {
			t.Fatalf("certificate missing from the index: %v", err)
		}
		if _, err := r.ReadVerified(ref.Loc, sha); err != nil {
			t.Fatal(err)
		}
	}
	if seq, _ := idx.Applied("fakelog"); seq != 4 {
		t.Fatalf("applied %d", seq)
	}
	if v, err := os.ReadFile(filepath.Join(h.root, "views.sql")); err != nil || !bytes.Contains(v, []byte("CREATE OR REPLACE VIEW entries")) {
		t.Fatalf("views.sql: %v", err)
	}
}

func TestDedupAndLeafErrors(t *testing.T) {
	es := entries(t, 20)
	dup := es[2] // the same certificate logged again later
	dup.LeafInput = ctlogtest.MerkleTreeLeaf(dup.Timestamp+5, dup.Type, dup.PrecertTBS, dup.IssuerKeyHash)
	es = append(es, dup, ctlogtest.MalformedEntry(7))
	h := newHarness(t, es, ctlogtest.Options{})
	w := h.open()
	ms := h.ingest(w, h.head(), 0, 22, 22)
	m := ms[0]
	if m.Counts.LeafErrors != 1 || m.Files[commit.QuarantineFile].Rows != 1 || m.Counts.NewCerts != 21 {
		t.Fatalf("one quarantined leaf error, and the duplicate is not vaulted again: %+v %+v", m.Counts, m.Files)
	}
	q, _ := os.ReadFile(filepath.Join(h.root, "dataset", "log=fakelog", "batch=000000000000-000000000021", commit.QuarantineFile))
	if !bytes.Contains(q, []byte(`"idx":21`)) || !bytes.Contains(q, []byte(`"leaf_error":"leaf_bad_version"`)) {
		t.Fatalf("quarantine.ndjson: %s", q)
	}
}

func TestForkedLogIsAnIncident(t *testing.T) {
	es := entries(t, 100)
	h := newHarness(t, es, ctlogtest.Options{})
	h.log.Fork(10) // heads and proofs come from a tree whose leaf 10 differs
	w := h.open()
	floor0, _ := commit.ReadFloor(filepath.Join(h.root, "state"))
	_, err := w.Batch(ctx, h.src, h.head(), 0, 40)
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("a forked log must be an incident after one refetch: %v", err)
	}
	if h.log.Requests("get-entries") < 4 {
		t.Fatal("the batch must have been fetched twice")
	}
	inc, _ := os.ReadDir(filepath.Join(h.root, "state", "incidents"))
	if len(inc) != 1 {
		t.Fatalf("one incident directory, got %d", len(inc))
	}
	// Spec §12: the evidence holds the STH, the proof, our compact range and
	// the raw response, since the fetched data itself is truncated.
	b, err := os.ReadFile(filepath.Join(h.root, "state", "incidents", inc[0].Name(), "incident.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ev map[string]any
	json.Unmarshal(b, &ev)
	for _, k := range []string{"sth", "sth_raw", "merkle_before", "computed_root", "end", "proof", "causes"} {
		if ev[k] == nil {
			t.Errorf("incident evidence lacks %q: %s", k, b)
		}
	}
	if c, _ := ev["causes"].([]any); len(c) != 2 {
		t.Errorf("both attempts' causes are recorded: %v", ev["causes"])
	}
	if w.Next("fakelog") != 0 || w.LastCommitSeq() != 0 {
		t.Fatal("nothing may be committed")
	}
	if u, _ := vault.InspectTail(h.vaultDirs(), vault.Tail{}); u.Bytes != 0 {
		t.Fatal("the vault must be cut back")
	}
	if f, _ := commit.ReadFloor(filepath.Join(h.root, "state")); f <= floor0 {
		t.Fatal("IDs touched by the attempts are skipped")
	}
}

// crashAt makes the hook panic at point, like a SIGKILL there.
func crashAt(point string) func(string) {
	return func(p string) {
		if p == point {
			panic("crash at " + p)
		}
	}
}

func (h *harness) crashingBatch(w *Writer, sth logsource.SignedHead, first, end uint64) {
	h.t.Helper()
	defer func() {
		if recover() == nil {
			h.t.Fatal("the hook did not fire")
		}
		w.Close()
		h.chains.Reset()
	}()
	w.Batch(ctx, h.src, sth, first, end)
}

// TestRecoveryAfterCrashes kills a batch before the commit point and another
// after it but before the Pebble apply; each reopen recovers and ingestion
// ends in the same verified state as a clean run.
func TestRecoveryAfterCrashes(t *testing.T) {
	es := entries(t, 120)
	for _, point := range []string{commit.HookAfterIntent, vault.HookAppendMidRecord, vault.HookRolloverAfterHeader, HookAfterVaultSync,
		HookDuringCanary, commit.HookBeforeRename, HookBeforePebble} {
		t.Run(point, func(t *testing.T) {
			h := newHarness(t, es, ctlogtest.Options{})
			h.opts.Config.Vault.SegmentSize = 8 << 10 // batches roll over segments
			sth := h.head()
			first := h.open()
			h.ingest(first, sth, 0, 40, 40)
			first.Close()
			h.opts.Hook = crashAt(point)
			w := h.open()
			h.crashingBatch(w, sth, 40, 80)
			h.opts.Hook = nil
			w = h.open()
			if !strings.Contains(h.out.String(), "recovery:") {
				t.Fatalf("recovery must report what it did: %s", h.out.String())
			}
			h.ingest(w, sth, w.Next("fakelog"), 120, 40)
			if w.Next("fakelog") != 120 {
				t.Fatalf("next %d", w.Next("fakelog"))
			}
			ms, err := commit.ListCommitted(h.root)
			if err != nil || len(ms) != 3 {
				t.Fatalf("three contiguous committed batches: %d, %v", len(ms), err)
			}
			if root, _ := ms[2].MerkleAfter.Root(); root != sth.RootHash {
				t.Fatal("the recovered vault must verify to the signed root")
			}
			seen := map[uint64]bool{}
			for _, m := range ms {
				if m.CertIDRange == nil {
					continue
				}
				for id := m.CertIDRange[0]; id <= m.CertIDRange[1]; id++ {
					if seen[id] {
						t.Fatalf("cert_id %d committed twice", id)
					}
					seen[id] = true
				}
			}
		})
	}
}

func TestDiskCapRefusesBeforeAnyWrite(t *testing.T) {
	h := newHarness(t, entries(t, 20), ctlogtest.Options{})
	h.opts.Guard.Stat = func(string) (diskguard.Usage, error) {
		return diskguard.Usage{Total: 100 << 30, Avail: 10 << 30, Dev: 1}, nil // 90% used
	}
	w := h.open()
	if _, err := w.Batch(ctx, h.src, h.head(), 0, 20); !errors.Is(err, diskguard.ErrCap) {
		t.Fatalf("a full disk refuses the batch: %v", err)
	}
	if in, _ := commit.ReadIntents(commit.Paths{Root: h.root}); len(in) != 0 || h.log.Requests("get-entries") != 0 {
		t.Fatal("nothing may be written or fetched")
	}
}

func TestDictionaryTraining(t *testing.T) {
	es := entries(t, 100)
	h := newHarness(t, es, ctlogtest.Options{})
	h.opts.DictSamples = 20
	w := h.open()
	ms := h.ingest(w, h.head(), 0, 100, 50)
	if ms[0].Dictionary.ID != 0 || ms[1].Dictionary.ID != 1 {
		t.Fatalf("batch 0 has no dictionary yet; batch 1 trains and uses dictionary 1: %+v %+v", ms[0].Dictionary, ms[1].Dictionary)
	}
	ds, err := vault.LoadDicts(h.vaultDirs())
	if err != nil || len(ds) != 1 || ds[0].Manifest.Training.Records != 20 {
		t.Fatalf("dictionary 1 on disk: %v %v", ds, err)
	}

	f := newHarness(t, es, ctlogtest.Options{})
	f.opts.DictSamples = 20
	calls := 0
	f.opts.Train = func([][]byte, uint64) ([]byte, error) { calls++; return nil, errors.New("training blew up") }
	fw := f.open()
	failed := 0
	for _, m := range f.ingest(fw, f.head(), 0, 100, 25) {
		if m.Dictionary.ID != 0 {
			t.Fatal("after a failed training every batch goes on without a dictionary")
		}
		if m.Dictionary.TrainingError != "" {
			failed++
		}
	}
	if failed != 1 || calls != 1 {
		t.Fatalf("the failure is recorded in the batch that tried, and training is tried once per run: %d records, %d calls", failed, calls)
	}
}

// TestWarmUpAfterRestart: a final certificate whose precert was committed
// before a restart is still delta-encoded, thanks to the warm-up.
func TestWarmUpAfterRestart(t *testing.T) {
	es := entries(t, 100)
	for warm, want := range map[int]int{4: 25, 0: 24} {
		h := newHarness(t, es, ctlogtest.Options{})
		h.opts.Config.Delta.WarmBatches = warm
		sth := h.head()
		w := h.open()
		h.ingest(w, sth, 0, 51, 51) // ends with the precert of pair 25
		w.Close()
		ms := h.ingest(h.open(), sth, 51, 100, 49)
		if ms[0].Counts.DeltaRecords != want {
			t.Fatalf("warm_batches %d: %d deltas, want %d", warm, ms[0].Counts.DeltaRecords, want)
		}
	}
}

// TestErrorAfterTheCommitPointKeepsTheBatch: an error after the commit
// rename (here the directory fsync fails with EACCES) must never abandon
// the batch: its vault data stays, and the next start finishes it.
func TestErrorAfterTheCommitPointKeepsTheBatch(t *testing.T) {
	es := entries(t, 40)
	h := newHarness(t, es, ctlogtest.Options{})
	logDir := filepath.Join(h.root, "dataset", "log=fakelog")
	h.opts.Hook = func(p string) {
		if p == commit.HookAfterRename {
			os.Chmod(logDir, 0)
		}
	}
	t.Cleanup(func() { os.Chmod(logDir, 0o755) })
	w := h.open()
	_, err := w.Batch(ctx, h.src, h.head(), 0, 40)
	var after errCommitted
	if !errors.As(err, &after) {
		t.Fatalf("an error after the rename must be reported as after the commit point: %v", err)
	}
	os.Chmod(logDir, 0o755)
	if u, _ := vault.InspectTail(h.vaultDirs(), vault.Tail{}); u.Bytes == 0 {
		t.Fatal("the committed batch's vault data must survive")
	}
	w.Close()
	h.opts.Hook = nil
	w = h.open()
	if w.Next("fakelog") != 40 {
		t.Fatalf("the batch stays committed: next %d", w.Next("fakelog"))
	}
	w.Close()
	idx, _ := index.Open(filepath.Join(h.root, "state", "pebble"))
	defer idx.Close()
	codec, _ := vault.NewCodec()
	defer codec.Close()
	r, _ := vault.OpenReader(h.vaultDirs(), codec)
	defer r.Close()
	sha := sha256.Sum256(es[7].CertDER)
	ref, ok, _ := idx.Lookup(sha)
	if !ok {
		t.Fatal("recovery re-applies the batch to the index")
	}
	if _, err := r.ReadVerified(ref.Loc, sha); err != nil {
		t.Fatalf("the certificate must still read back: %v", err)
	}
}

// TestAbandonedIDsAreNeverReusedAfterARestart: cert_ids an abandoned attempt
// touched are skipped forever (spec §8.6), also when the process exits after
// the abandon (an incident, a second Ctrl-C) and a later run starts afresh.
func TestAbandonedIDsAreNeverReusedAfterARestart(t *testing.T) {
	h := newHarness(t, entries(t, 60), ctlogtest.Options{})
	h.log.Fork(10)
	w := h.open()
	if _, err := w.Batch(ctx, h.src, h.head(), 0, 40); !errors.Is(err, ErrVerification) {
		t.Fatalf("setup: the forked log must end in an incident: %v", err)
	}
	w.Close()
	floor, _ := commit.ReadFloor(filepath.Join(h.root, "state"))

	honest := newHarness(t, entries(t, 60), ctlogtest.Options{}) // other certificates, same vault
	honest.opts.Root, honest.opts.VaultDirs = h.root, h.opts.VaultDirs
	hw := honest.open()
	ms := honest.ingest(hw, honest.head(), 0, 40, 40)
	if got := ms[0].CertIDRange[0]; got < floor {
		t.Fatalf("the first cert_id after the restart is %d; IDs below the floor %d were touched by the abandoned attempts", got, floor)
	}
	if in, _ := commit.ReadIntents(commit.Paths{Root: h.root}); len(in) != 0 {
		t.Fatalf("a successful commit clears the abandoned intent: %d left", len(in))
	}
}

// TestVolumeCheckRunsBeforeEveryBatch: spec §8.3 P0 and §9.2 repeat the
// volume checks at every batch preflight, so a vanished SSD stops ingestion
// before anything is written.
func TestVolumeCheckRunsBeforeEveryBatch(t *testing.T) {
	h := newHarness(t, entries(t, 80), ctlogtest.Options{})
	checks := 0
	gone := errors.New("volume check failed: the SSD is gone")
	h.opts.CheckVolumes = func() error {
		if checks++; checks > 1 {
			return gone
		}
		return nil
	}
	w := h.open()
	sth := h.head()
	if _, err := w.Batch(ctx, h.src, sth, 0, 40); err != nil {
		t.Fatal(err)
	}
	h.chains.Reset()
	if _, err := w.Batch(ctx, h.src, sth, 40, 80); !errors.Is(err, gone) {
		t.Fatalf("the second batch must stop on the failed check: %v", err)
	}
	if in, _ := commit.ReadIntents(commit.Paths{Root: h.root}); len(in) != 0 || w.Next("fakelog") != 40 {
		t.Fatal("nothing may be started after a failed volume check")
	}
}

// TestCorruptionFoundByTrainingStops: vault corruption is never ignored
// (spec §12), including when dictionary training reads committed records.
func TestCorruptionFoundByTrainingStops(t *testing.T) {
	h := newHarness(t, entries(t, 80), ctlogtest.Options{})
	h.opts.DictSamples = 20
	w := h.open()
	sth := h.head()
	h.ingest(w, sth, 0, 40, 40)
	segs, _ := vault.FindSegments(h.vaultDirs())
	b, _ := os.ReadFile(segs[1])
	b[vault.HeaderSize+40] ^= 0xff // inside the first record's frame
	os.WriteFile(segs[1], b, 0o644)
	if _, err := w.Batch(ctx, h.src, sth, 40, 80); !errors.Is(err, vault.ErrCorrupt) {
		t.Fatalf("training over a damaged record must stop the batch as corruption: %v", err)
	}
	if in, _ := commit.ReadIntents(commit.Paths{Root: h.root}); len(in) != 0 {
		t.Fatal("nothing may be started")
	}
}

// TestSegmentsGoWhereThePreflightReserved: with a second vault directory on
// another disk (vault add-dir, spec §10.2), a batch that only fits there
// must write its segments there, not onto the root volume.
func TestSegmentsGoWhereThePreflightReserved(t *testing.T) {
	h := newHarness(t, entries(t, 80), ctlogtest.Options{})
	second := filepath.Join(t.TempDir(), "disk2")
	os.MkdirAll(filepath.Join(second, "segments"), 0o755)
	os.MkdirAll(filepath.Join(second, "dict"), 0o755)
	h.opts.VaultDirs = append(h.opts.VaultDirs, second)
	h.opts.Guard.Stat = func(p string) (diskguard.Usage, error) {
		if strings.HasPrefix(p, second) {
			return diskguard.Usage{Total: 1 << 40, Avail: 1 << 40, Dev: 2}, nil
		}
		// The root volume: 6.5 GiB below the cap, enough for the root's own
		// peak (spill budget, Pebble reserve) but not for a vault peak too.
		return diskguard.Usage{Total: 100 << 30, Avail: 21<<30 + 512<<20, Dev: 1}, nil
	}
	w := h.open()
	h.ingest(w, h.head(), 0, 80, 40)
	segs, _ := vault.FindSegments(h.opts.VaultDirs)
	for id, p := range segs {
		if !strings.HasPrefix(p, second) {
			t.Fatalf("segment %d went to %s; the preflight reserved the vault peak on %s", id, p, second)
		}
	}
	if len(segs) == 0 {
		t.Fatal("no segments written")
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/ingest/ ./internal/merkle/`
Expected: FAIL with `undefined: HookAfterVaultSync`, `undefined: HookDuringCanary` and `undefined: ErrAbandonFailed` in `internal/ingest`.

`TestRefetchAfterAFailedCanaryCommits` fails even with the hooks in place until `Clone` is fixed: "failed verification twice". The original's compact range shared its hash list with the clone.

- [ ] **Step 3: Implement**

Replace `internal/merkle/state.go` with:

```go
package merkle

import (
	"bytes"
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

// Clone returns an independent copy. The compact range's hash list is
// copied: compact.Range keeps the slice it is given, and a shared list let
// a clone's appends overwrite the original's nodes.
func (s *State) Clone() *State {
	if s.r == nil {
		return &State{}
	}
	hs := make([][]byte, 0, len(s.r.Hashes()))
	for _, h := range s.r.Hashes() {
		hs = append(hs, bytes.Clone(h))
	}
	c, err := factory.NewRange(0, s.r.End(), hs)
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

Replace `internal/ingest/batch.go` with:

```go
package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

// Batch ingests entries [first, end) of src and commits them, verified
// against the pinned head sth (spec §8.3). A failed Merkle verification or
// canary abandons the attempt and refetches the batch once; a second
// failure writes an incident and returns ErrVerification. Any other error
// abandons the batch and is returned as is (a stall, a full disk, a second
// signal). The caller resets src's chain cache after every call.
func (w *Writer) Batch(ctx context.Context, src logsource.LogSource, sth logsource.SignedHead, first, end uint64) (commit.Manifest, error) {
	if w.broken != nil {
		return commit.Manifest{}, w.broken
	}
	m, err := w.attempt(ctx, src, sth, first, end)
	var firstTry, secondTry errRetry
	if !errors.As(err, &firstTry) {
		return m, err
	}
	w.logf("batch %s: %v; refetching it once", w.batchID(src, first, end), err)
	m, err = w.attempt(ctx, src, sth, first, end)
	if !errors.As(err, &secondTry) {
		return m, err
	}
	dir, ierr := w.incident(w.batchID(src, first, end), sth, firstTry, secondTry)
	if ierr != nil {
		return m, errors.Join(fmt.Errorf("%w: %v", ErrVerification, err), ierr)
	}
	return m, fmt.Errorf("%w: %v (incident written to %s)", ErrVerification, err, dir)
}

func (w *Writer) batchID(src logsource.LogSource, first, end uint64) commit.BatchID {
	return commit.BatchID{Log: src.Info().Name, First: first, Last: end - 1}
}

// batch is one attempt's in-memory state.
type batch struct {
	w       *Writer
	ctx     context.Context
	src     logsource.LogSource
	pb      *index.Batch
	before  *merkle.State // the compact range before the batch
	state   *merkle.State
	rows    []dataset.EntryRow
	chains  []dataset.ChainRow
	quar    bytes.Buffer
	counts  commit.Counts
	firstID uint64
	lastID  uint64
	samples []sample
}

type sample struct {
	sha [32]byte
	loc vault.Loc
}

func (w *Writer) attempt(ctx context.Context, src logsource.LogSource, sth logsource.SignedHead, first, end uint64) (commit.Manifest, error) {
	id := w.batchID(src, first, end)
	tip := w.tips[id.Log]
	if first != tip.Next || end <= first || end > sth.TreeSize {
		return commit.Manifest{}, fmt.Errorf("batch %s: must start at %d and end within the signed tree of %d", id, tip.Next, sth.TreeSize)
	}
	state := merkle.NewState()
	if tip.State != nil {
		state = tip.State.Clone()
	}
	// P0: volume checks, dictionary training, then the disk-guard peak
	// preflight. A cache left cold by a stopped attempt is warmed first.
	if w.cold {
		if err := w.warm(); err != nil {
			return commit.Manifest{}, err
		}
		w.cold = false
	}
	if w.o.CheckVolumes != nil {
		if err := w.o.CheckVolumes(); err != nil {
			return commit.Manifest{}, err
		}
	}
	dict, err := w.maybeTrain()
	if err != nil {
		return commit.Manifest{}, err
	}
	dir, err := w.preflight(end - first)
	if err != nil {
		return commit.Manifest{}, err
	}
	w.vw.Prefer(dir)
	// P1
	in := commit.Intent{BatchID: id.String(), Log: id.Log, First: id.First, Last: id.Last, STH: toSTH(sth),
		VaultTail: w.vw.Tail(), NextCertID: w.ids.Peek(), MerkleBefore: state.Clone(), Builders: map[string]int{},
		StartedAt: w.o.Now().UTC()}
	if err := commit.WriteIntent(w.paths, in, w.o.Hook); err != nil {
		return commit.Manifest{}, err
	}
	b := &batch{w: w, ctx: ctx, src: src, pb: w.idx.NewBatch(), state: state, before: in.MerkleBefore}
	defer b.pb.Close()
	m, err := w.run(b, in, sth, dict)
	var after errCommitted
	if err != nil && !errors.As(err, &after) {
		if aerr := w.abandon(ctx, in); aerr != nil {
			w.broken = fmt.Errorf("%w: %s: %v", ErrAbandonFailed, id, aerr)
			return m, errors.Join(err, w.broken)
		}
	}
	return m, err
}

// ErrAbandonFailed means an attempt could not be cleaned up in process: the
// vault could not be cut back, or its intent could not be marked. The
// writer then refuses every further batch, and the next start recovers
// (spec §8.5).
var ErrAbandonFailed = errors.New("abandoning the batch failed; run update again to recover")

// run is P2-P10 of one attempt.
func (w *Writer) run(b *batch, in commit.Intent, sth logsource.SignedHead, dict commit.DictInfo) (commit.Manifest, error) {
	id := in.ID()
	// P2
	if _, err := fetch.Run(b.ctx, b.src, id.First, id.Last+1, w.o.Fetch, b.add); err != nil {
		return commit.Manifest{}, err
	}
	// P3
	if err := w.vw.Sync(); err != nil {
		return commit.Manifest{}, err
	}
	w.hook(HookAfterVaultSync)
	// P4
	verified, err := w.verify(b, sth, id.Last+1)
	if err != nil {
		return commit.Manifest{}, err
	}
	// P5
	stage := w.paths.StageDir(id)
	files, err := w.stager.Stage(b.ctx, stage, b.rows, b.chains)
	if err != nil {
		return commit.Manifest{}, err
	}
	if b.quar.Len() > 0 {
		p := filepath.Join(stage, commit.QuarantineFile)
		if err := os.WriteFile(p, b.quar.Bytes(), 0o644); err != nil {
			return commit.Manifest{}, err
		}
		fi, err := dataset.Sum(p)
		if err != nil {
			return commit.Manifest{}, err
		}
		fi.Rows = b.counts.LeafErrors
		files[commit.QuarantineFile] = fi
	}
	if err := w.o.Guard.Check(w.o.Root, 0); err != nil { // spec §10.1: a hard check after every staged write
		return commit.Manifest{}, err
	}
	// P6
	if err := w.canary(b, stage); err != nil {
		return commit.Manifest{}, err
	}
	// P7, P8
	seq := w.LastCommitSeq() + 1
	m := commit.Manifest{Format: commit.ManifestFormat, CommitSeq: seq, BatchID: id.String(), Log: id.Log,
		First: id.First, Last: id.Last, STH: toSTH(sth), MerkleAfter: b.state, Verified: verified,
		NextCertID: w.ids.Peek(), Vault: commit.Span{Start: in.VaultTail, End: w.vw.Tail()}, Builders: map[string]int{},
		Files: files, Counts: b.counts, Dictionary: dict, CTVaultVersion: w.o.Version, CommittedAt: w.o.Now().UTC()}
	m.Counts.Entries = len(b.rows)
	if b.firstID != 0 {
		m.CertIDRange = &[2]uint64{b.firstID, b.lastID}
	}
	perr := commit.Publish(w.paths, m, w.o.Hook)
	if perr != nil && !errors.Is(perr, commit.ErrPostCommit) {
		return m, perr // the rename did not happen: abandon
	}
	// From here the batch is committed; failures below are repaired by
	// recovery at the next start, never by abandoning.
	w.committed = append(w.committed, m)
	w.tips[id.Log] = commit.LogTip{Next: id.Last + 1, State: b.state}
	if perr != nil {
		return m, errCommitted{perr}
	}
	// P9
	if err := b.pb.SetApplied(id.Log, seq); err != nil {
		return m, errCommitted{err}
	}
	w.hook(HookBeforePebble)
	if err := b.pb.Commit(); err != nil {
		return m, errCommitted{err}
	}
	w.hook(HookAfterPebble)
	// P10
	if err := commit.RemoveIntent(w.paths, id, w.o.Hook); err != nil {
		return m, errCommitted{err}
	}
	if err := commit.ClearAbandoned(w.paths); err != nil {
		return m, errCommitted{err}
	}
	w.logf("batch %s: %d entries, %d new certificates (%d deltas), %d leaf errors, %d vault bytes, verified by %s; commit_seq %d",
		id, m.Counts.Entries, m.Counts.NewCerts, m.Counts.DeltaRecords, m.Counts.LeafErrors, m.Counts.VaultBytes, verified.Method, seq)
	return m, nil
}

// Hook points of the engine's own steps, for crash tests (spec §13.5).
const (
	HookAfterVaultSync = "commit.P3.after_vault_sync"
	HookDuringCanary   = "commit.P6.during_canary" // between the Parquet and the vault checks
	HookBeforePebble   = "commit.P9.before_pebble"
	HookAfterPebble    = "commit.P9.after_pebble"
)

func (w *Writer) hook(p string) {
	if w.o.Hook != nil {
		w.o.Hook(p)
	}
}

// errCommitted wraps a failure after the commit point: the batch is
// committed, so it must not be abandoned.
type errCommitted struct{ err error }

func (e errCommitted) Error() string { return "after commit: " + e.err.Error() }
func (e errCommitted) Unwrap() error { return e.err }

// abandon discards an attempt: vault, staging and intent go, the Pebble
// batch is discarded by the caller, cert_ids skip to the floor, and the
// delta cache forgets records that no longer exist. When ctx is done the
// process is stopping: the cache is emptied and left cold instead of
// re-reading the vault, and the next attempt warms it.
func (w *Writer) abandon(ctx context.Context, in commit.Intent) error {
	if err := w.vw.Close(); err != nil {
		return err
	}
	if err := commit.Abandon(w.paths, w.o.VaultDirs, in); err != nil {
		return err
	}
	w.ids.SkipToFloor()
	var err error
	if w.vw, err = vault.OpenWriter(w.vaultOptions(), w.codec, in.VaultTail); err != nil {
		return err
	}
	if ctx.Err() != nil {
		w.delta.Reset()
		w.cold = true
		return nil
	}
	return w.warm()
}

// add handles one entry in index order (P2).
func (b *batch) add(e logsource.RawEntry) error {
	if err := b.state.Append(e.Leaf.LeafHash); err != nil {
		return err
	}
	row := dataset.EntryRow{Idx: e.Index, CTTimestamp: e.Leaf.Timestamp, EntryType: e.Leaf.Type.String(), LeafHash: e.Leaf.LeafHash}
	if k, ok := e.Leaf.IssuanceKey(); ok {
		row.IssuanceKey, row.HasIssuanceKey = k, true
	}
	if e.Leaf.HasIssuerKeyHash {
		row.IssuerKeyHash, row.HasIssuerKeyHash = e.Leaf.IssuerKeyHash, true
	}
	if e.Leaf.Code != leaf.OK {
		row.LeafError = string(e.Leaf.Code)
		b.counts.LeafErrors++
		line, _ := json.Marshal(map[string]any{"idx": e.Index, "leaf_error": e.Leaf.Code,
			"leaf_input": base64.StdEncoding.EncodeToString(e.LeafInput), "extra_data": base64.StdEncoding.EncodeToString(e.ExtraData)})
		b.quar.Write(append(line, '\n'))
	}
	if e.Leaf.CertDER != nil {
		id, err := b.vaultLeaf(e.Leaf)
		if err != nil {
			return err
		}
		row.CertID = id
	}
	if e.Chain != nil {
		chainID, err := b.vaultChain(e.Chain)
		if err != nil {
			return err
		}
		row.ChainID, row.HasChainID = chainID, true
	}
	b.rows = append(b.rows, row)
	return nil
}

func (b *batch) assign() (uint64, error) {
	id, err := b.w.ids.Next()
	if err != nil {
		return 0, err
	}
	if b.firstID == 0 {
		b.firstID = id
	}
	b.lastID = id
	return id, nil
}

func (b *batch) vaulted(sha [32]byte, ref index.Ref) error {
	b.counts.NewCerts++
	b.counts.VaultBytes += uint64(ref.Loc.Len)
	if len(b.samples) < 4096 {
		b.samples = append(b.samples, sample{sha, ref.Loc})
	}
	return b.pb.AddCert(sha, ref)
}

// vaultLeaf stores a leaf certificate unless it is already vaulted. A final
// certificate whose precert is cached becomes a leaf-delta record.
func (b *batch) vaultLeaf(l leaf.Entry) (uint64, error) {
	sha := sha256.Sum256(l.CertDER)
	if ref, ok, err := b.pb.Lookup(sha); err != nil || ok {
		return ref.CertID, err
	}
	id, err := b.assign()
	if err != nil {
		return 0, err
	}
	var loc vault.Loc
	if base, ok := b.w.delta.Get(l.IssuanceDigest); ok && l.Type == leaf.TypeX509 && l.HasIssuanceDigest {
		if loc, err = b.w.vw.AppendDelta(id, l.CertDER, base); err != nil {
			return 0, err
		}
		b.counts.DeltaRecords++
	} else if loc, err = b.w.vw.AppendCert(vault.KindLeaf, id, l.CertDER, b.w.dictID); err != nil {
		return 0, err
	}
	if l.Type == leaf.TypePrecert && l.HasIssuanceDigest {
		b.w.delta.Put(l.IssuanceDigest, loc)
	}
	return id, b.vaulted(sha, index.Ref{CertID: id, Loc: loc})
}

// vaultChain stores unseen chain certificates and returns the chain_id,
// adding chains.parquet rows the first time a chain is seen.
func (b *batch) vaultChain(fps [][32]byte) ([32]byte, error) {
	ids := make([]uint64, len(fps))
	h := sha256.New()
	for i, fp := range fps {
		h.Write(fp[:])
		ref, ok, err := b.pb.Lookup(fp)
		if err != nil {
			return [32]byte{}, err
		}
		if ok {
			ids[i] = ref.CertID
			continue
		}
		der, err := b.src.Issuer(b.ctx, fp)
		if err != nil {
			return [32]byte{}, err
		}
		if sha256.Sum256(der) != fp {
			return [32]byte{}, fmt.Errorf("chain certificate %x does not match its fingerprint", fp[:8])
		}
		if ids[i], err = b.assign(); err != nil {
			return [32]byte{}, err
		}
		loc, err := b.w.vw.AppendCert(vault.KindChain, ids[i], der, b.w.dictID)
		if err != nil {
			return [32]byte{}, err
		}
		if err := b.vaulted(fp, index.Ref{CertID: ids[i], Loc: loc}); err != nil {
			return [32]byte{}, err
		}
	}
	var chainID [32]byte
	copy(chainID[:], h.Sum(nil))
	seen, err := b.pb.HasChain(chainID)
	if err != nil || seen {
		return chainID, err
	}
	for i, id := range ids {
		b.chains = append(b.chains, dataset.ChainRow{ChainID: chainID, Position: uint16(i), CertID: id})
	}
	return chainID, b.pb.AddChain(chainID)
}

// verify is P4 (spec §5.5): the computed root at end must equal the signed
// root, or be proven a prefix of it.
func (w *Writer) verify(b *batch, sth logsource.SignedHead, end uint64) (commit.Verified, error) {
	root, err := b.state.Root()
	if err != nil {
		return commit.Verified{}, err
	}
	if end == sth.TreeSize {
		if root != sth.RootHash {
			return commit.Verified{}, errRetry{err: errors.New("the computed root differs from the signed root"),
				before: b.before, root: root, end: end}
		}
		return commit.Verified{Method: "root_equals_sth"}, nil
	}
	var proof [][32]byte
	if err := fetch.Retry(b.ctx, w.o.Fetch, func(ctx context.Context) (err error) {
		proof, err = b.src.ConsistencyProof(ctx, end, sth.TreeSize)
		return err
	}); err != nil {
		return commit.Verified{}, err
	}
	if err := merkle.VerifyConsistency(end, sth.TreeSize, root, sth.RootHash, proof); err != nil {
		return commit.Verified{}, errRetry{err: err, before: b.before, root: root, end: end, proof: proof}
	}
	return commit.Verified{Method: "consistency_proof", ProofNodes: len(proof)}, nil
}

// canary is P6: the staged files, and vault reads of sampled new records.
func (w *Writer) canary(b *batch, stage string) error {
	rnd := rand.New(rand.NewPCG(b.rows[0].Idx, uint64(len(b.rows))))
	if err := w.stager.Canary(b.ctx, stage, b.rows, b.chains, w.o.CanarySamples, rnd); err != nil {
		return errRetry{err: err}
	}
	w.hook(HookDuringCanary)
	r, err := vault.OpenReader(w.o.VaultDirs, w.codec)
	if err != nil {
		return err
	}
	defer r.Close()
	for range min(w.o.CanarySamples, len(b.samples)) {
		s := b.samples[rnd.IntN(len(b.samples))]
		if _, err := r.ReadVerified(s.loc, s.sha); err != nil {
			return errRetry{err: err}
		}
	}
	return nil
}

// maybeTrain trains dictionary 1 once the committed vault holds
// DictSamples leaf certificates; a training failure is recorded and
// ingestion goes on with dictionary 0 (amendment A1 §5). It is tried once
// per process. Vault corruption met while reading the samples is returned:
// corruption is never ignored (spec §12).
func (w *Writer) maybeTrain() (commit.DictInfo, error) {
	if w.dictID != 0 || w.trainTried {
		return commit.DictInfo{ID: w.dictID}, nil
	}
	samples, tr, err := vault.TrainingSet(w.o.VaultDirs, w.codec, w.vw.Tail(), w.o.DictSamples)
	if err != nil {
		return commit.DictInfo{}, fmt.Errorf("reading dictionary training samples: %w", err)
	}
	if len(samples) < w.o.DictSamples {
		return commit.DictInfo{ID: 0}, nil
	}
	w.trainTried = true
	w.logf("training dictionary 1 on %d leaf certificates", len(samples))
	content, err := w.o.Train(samples, 1)
	if err == nil {
		var d vault.Dict
		if d, err = vault.InstallDict(w.o.VaultDirs, 1, content, tr, w.o.Now()); err == nil {
			err = w.codec.AddDict(1, d.Content)
		}
	}
	if err != nil {
		w.logf("dictionary training failed; continuing without a dictionary: %v", err)
		return commit.DictInfo{ID: 0, TrainingError: err.Error()}, nil
	}
	w.dictID = 1
	return commit.DictInfo{ID: 1}, nil
}

// preflight is the spec §10.1 peak check before a batch starts. It returns
// the vault directory whose filesystem holds the vault peak; the batch's new
// segments go there.
func (w *Writer) preflight(n uint64) (string, error) {
	var vaultHist, parquetHist []float64
	for i := max(0, len(w.committed)-diskguard.MinHistory); i < len(w.committed); i++ {
		m := w.committed[i]
		if m.Counts.Entries == 0 {
			continue
		}
		var pq int64
		for _, f := range m.Files {
			pq += f.Bytes
		}
		vaultHist = append(vaultHist, float64(m.Counts.VaultBytes)/float64(m.Counts.Entries))
		parquetHist = append(parquetHist, float64(pq)/float64(m.Counts.Entries))
	}
	cfg := w.o.Config
	peak := diskguard.EstimatePeak(diskguard.PeakInput{Entries: n,
		VaultP95: diskguard.P95(vaultHist, diskguard.SeedVaultBytesPerEntry), ParquetP95: diskguard.P95(parquetHist, diskguard.SeedParquetBytesPerEntry),
		PebbleP95: diskguard.SeedPebbleBytesPerEntry, Safety: cfg.Disk.SafetyFactor,
		PebbleSize: dirSize(filepath.Join(w.o.Root, "state", "pebble")), DuckDBSpill: w.spillLimit()})
	var err error
	for _, d := range w.o.VaultDirs {
		if err = w.o.Guard.Preflight([]diskguard.Target{{Path: w.o.Root, Need: peak.Root}, {Path: d, Need: peak.Vault}}); err == nil {
			return d, nil
		}
	}
	return "", err
}

func dirSize(dir string) uint64 {
	var n uint64
	filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				n += uint64(fi.Size())
			}
		}
		return nil
	})
	return n
}

func toSTH(h logsource.SignedHead) commit.STH {
	return commit.STH{TreeSize: h.TreeSize, Timestamp: h.Timestamp, RootHash: hex.EncodeToString(h.RootHash[:]),
		Signature: base64.StdEncoding.EncodeToString(h.Signature)}
}

// incident writes the evidence of a batch that failed verification twice
// (spec §12): the pinned head as received, both attempts' causes, and for a
// Merkle failure our compact range before the batch, the root we computed
// and the proof the log served. The fetched data itself is truncated.
func (w *Writer) incident(id commit.BatchID, sth logsource.SignedHead, first, second errRetry) (string, error) {
	dir := filepath.Join(w.o.Root, "state", "incidents", w.o.Now().UTC().Format("20060102T150405Z")+"_"+id.Log+"_"+fmt.Sprint(id.First))
	if err := fsutil.MkdirAllSync(dir, 0o755); err != nil {
		return "", err
	}
	ev := map[string]any{"batch_id": id.String(), "causes": []string{first.Error(), second.Error()}, "sth": toSTH(sth),
		"sth_raw": base64.StdEncoding.EncodeToString(sth.Raw), "time": w.o.Now().UTC().Format(time.RFC3339)}
	if second.before != nil {
		proof := make([]string, len(second.proof))
		for i, n := range second.proof {
			proof[i] = hex.EncodeToString(n[:])
		}
		ev["merkle_before"], ev["computed_root"], ev["end"], ev["proof"] = second.before, hex.EncodeToString(second.root[:]), second.end, proof
	}
	b, err := json.MarshalIndent(ev, "", " ")
	if err != nil {
		return dir, err
	}
	return dir, fsutil.WriteFileAtomic(filepath.Join(dir, "incident.json"), b, 0o644)
}
```

Replace `internal/ingest/writer.go` with:

```go
// Package ingest runs batches: it fetches a range of a log, verifies it
// against a pinned signed tree head, vaults new certificates, stages the
// source-layer Parquet files and commits through the protocol of spec §8.3.
package ingest

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

// Options configure a Writer. The caller holds the writer lock and has run
// the volume checks.
type Options struct {
	Root      string
	VaultDirs []string // absolute, in VAULT_ID order
	VaultUUID [16]byte
	Config    config.Config
	Guard     diskguard.Guard
	Fetch     fetch.Options // workers, rate and stall timeout from Config, plus test overrides
	Version   string
	Now       func() time.Time
	Out       io.Writer    // one line per batch and recovery action
	Hook      func(string) // crash points, tests only
	// CheckVolumes repeats the volume checks (spec §9.2) at every batch
	// preflight; a failure stops the batch before anything is written.
	CheckVolumes func() error

	// DictSamples is how many leaf certificates train dictionary 1 (20,000;
	// tests use fewer). Train defaults to vault.Train.
	DictSamples int
	Train       func(samples [][]byte, id uint64) ([]byte, error)
	// CanarySamples is how many rows and vault records the canary checks
	// per batch (default 64).
	CanarySamples int
}

// Writer is the single writer of a vault.
type Writer struct {
	o      Options
	paths  commit.Paths
	idx    *index.Index
	codec  *vault.Codec
	stager *dataset.Stager
	ids    *commit.IDs
	vw     *vault.Writer
	delta  *vault.DeltaCache
	dictID uint64

	trainTried bool
	cold       bool  // the delta cache was emptied by a stopped attempt
	broken     error // an abandon failed: no more batches (ErrAbandonFailed)
	spill      string

	committed []commit.Manifest
	tips      map[string]commit.LogTip
}

func (w *Writer) logf(format string, args ...any) {
	if w.o.Out != nil {
		fmt.Fprintf(w.o.Out, format+"\n", args...)
	}
}

// WriterSpillDir is the writer's DuckDB spill folder under tmp/ (spec §10.1
// gives readers tmp/duckdb-<pid>; there is only ever one writer).
const WriterSpillDir = "duckdb-writer"

// Open recovers the vault (spec §8.5) and prepares the writer: index,
// dictionaries, cert_id allocator, vault tail, delta cache warm-up and
// views.sql.
func Open(o Options) (*Writer, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.DictSamples == 0 {
		o.DictSamples = vault.TrainingSamples
	}
	if o.Train == nil {
		o.Train = vault.Train
	}
	if o.CanarySamples == 0 {
		o.CanarySamples = 64
	}
	w := &Writer{o: o, paths: commit.Paths{Root: o.Root}}
	ok := false
	defer func() {
		if !ok {
			w.Close()
		}
	}()
	var err error
	if w.idx, err = index.Open(filepath.Join(o.Root, "state", "pebble")); err != nil {
		return nil, err
	}
	if w.codec, err = vault.NewCodec(); err != nil {
		return nil, err
	}
	dicts, err := vault.LoadDicts(o.VaultDirs)
	if err != nil {
		return nil, err
	}
	for _, d := range dicts {
		if err := w.codec.AddDict(d.Manifest.ID, d.Content); err != nil {
			return nil, err
		}
		w.dictID = d.Manifest.ID
	}
	// The writer's DuckDB spill folder has a fixed name: the writer lock
	// makes it ours, so a killed writer's leftover is emptied here.
	// Readers' tmp/duckdb-<pid> folders are never touched (amendment A1 §7).
	w.spill = filepath.Join(o.Root, "tmp", WriterSpillDir)
	if left, _ := os.ReadDir(w.spill); len(left) > 0 {
		w.logf("recovery: emptied the writer's leftover DuckDB spill folder tmp/%s", WriterSpillDir)
	}
	if err := os.RemoveAll(w.spill); err != nil {
		return nil, err
	}
	if w.stager, err = dataset.NewStager(dataset.Options{TempDir: w.spill, MaxTempBytes: w.spillLimit()}); err != nil {
		return nil, err
	}
	rec, err := commit.Recover(commit.RecoverOptions{Paths: w.paths, VaultDirs: o.VaultDirs, VaultUUID: o.VaultUUID, Index: w.idx,
		Codec: w.codec, ChainIDs: w.stager.ChainIDs})
	if err != nil {
		return nil, err
	}
	for _, a := range rec.Actions {
		w.logf("recovery: %s", a)
	}
	w.committed, w.tips = rec.Committed, commit.Tips(rec.Committed)
	if w.ids, err = commit.LoadIDs(w.paths.StateDir(), rec.NextCertID, o.Hook); err != nil {
		return nil, err
	}
	if w.vw, err = vault.OpenWriter(w.vaultOptions(), w.codec, rec.Tail); err != nil {
		return nil, err
	}
	if err := w.warm(); err != nil {
		return nil, err
	}
	if _, err := dataset.WriteViews(o.Root); err != nil {
		return nil, err
	}
	ok = true
	return w, nil
}

func (w *Writer) vaultOptions() vault.Options {
	return vault.Options{Dirs: w.o.VaultDirs, VaultUUID: w.o.VaultUUID, SegmentSize: uint64(w.o.Config.Vault.SegmentSize),
		Check: w.o.Guard.Check, Hook: w.o.Hook, Now: w.o.Now}
}

// SpillBudget caps the writer's DuckDB spill. Spec §10.1 sets every DuckDB
// session's spill limit to the headroom below the cap minus 1 GiB, and
// amendment A1 §7 adds the limit to every batch's peak; together no batch
// could ever start. The writer therefore spills at most this budget, and
// the preflight counts it (Plan 2B decision). Plan 2's tables fit in memory.
const SpillBudget = 4 << 30

// spillLimit is the writer's max_temp_directory_size: the budget, or less
// when the headroom below the cap minus a 1 GiB margin is smaller, but at
// least 64 MiB.
func (w *Writer) spillLimit() uint64 {
	const margin, floor = 1 << 30, 64 << 20
	u, err := w.o.Guard.Stat(w.o.Root)
	if err != nil || u.Total == 0 {
		return floor
	}
	lim := uint64(w.o.Guard.Cap * float64(u.Total))
	if used := u.Used(); lim > used+margin+floor {
		return min(SpillBudget, lim-used-margin)
	}
	return floor
}

// warm refills the delta cache from the last delta.warm_batches committed
// batches (amendment A1 §5).
func (w *Writer) warm() error {
	if w.delta == nil {
		w.delta = vault.NewDeltaCache(w.o.Config.Ingest.DeltaLRUEntries)
	} else {
		w.delta.Reset() // reuse the cache's memory (207 MiB at the default size)
	}
	n := w.o.Config.Delta.WarmBatches
	var ranges []vault.Range
	for i := max(0, len(w.committed)-n); i < len(w.committed); i++ {
		ranges = append(ranges, vault.Range{Start: w.committed[i].Vault.Start, End: w.committed[i].Vault.End})
	}
	return vault.Warm(w.o.VaultDirs, w.codec, w.delta, ranges, leaf.PrecertIssuanceDigest)
}

// Next returns the first index of log not yet committed.
func (w *Writer) Next(log string) uint64 { return w.tips[log].Next }

// LastCommitSeq returns the highest commit_seq.
func (w *Writer) LastCommitSeq() uint64 {
	if len(w.committed) == 0 {
		return 0
	}
	return w.committed[len(w.committed)-1].CommitSeq
}

// Close releases every resource; it never commits anything. Closing twice
// is harmless.
func (w *Writer) Close() error {
	var errs []error
	if w.vw != nil {
		errs = append(errs, w.vw.Close())
		w.vw = nil
	}
	if w.stager != nil {
		errs = append(errs, w.stager.Close(), os.RemoveAll(w.spill))
		w.stager = nil
	}
	if w.codec != nil {
		w.codec.Close()
		w.codec = nil
	}
	if w.idx != nil {
		errs = append(errs, w.idx.Close())
		w.idx = nil
	}
	return errors.Join(errs...)
}

// ErrVerification wraps a batch that failed Merkle verification or the
// canary twice: an incident (spec §12, exit 5).
var ErrVerification = errors.New("batch failed verification twice")

// errRetry marks a verification or canary failure; the batch is refetched
// once. A Merkle failure carries the evidence an incident records (spec
// §12): our compact range before the batch, the root we computed at end,
// and the proof the log served.
type errRetry struct {
	err    error
	before *merkle.State
	root   [32]byte
	end    uint64
	proof  [][32]byte
}

func (e errRetry) Error() string { return e.err.Error() }
func (e errRetry) Unwrap() error { return e.err }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race ./internal/ingest/ ./internal/merkle/`
Expected: PASS.

- [ ] **Step 5: Quality gate**

- [ ] **Step 6: Checkpoint.**

---

### Task C3: P0 order, cancellable training, the canary, `views.sql` (M3, M6, M7)

Spec §8.3 (P0, P6), §10.1, amendment A1 §5 (training) and §7 (`views.sql`).

**Files:**
- Modify: `internal/ingest/batch.go`, `internal/dataset/canary.go`, `internal/dataset/views.go`
- Tests: `internal/ingest/train_test.go` (new), `internal/dataset/views_test.go` (new)

**Interfaces:**
- Produces: `dataset.Views(root string, committed bool) []byte`
- Changes:
  - P0 runs the volume checks, then the disk preflight, then training. Training returns at once on a cancelled context.
  - The canary reads vault records from a 4,096-record reservoir over the whole batch, and checks `cert_id` range counts.
  - `WriteViews` runs after every commit.

- [ ] **Step 1: Write the failing tests**

Create `internal/ingest/train_test.go`:

```go
package ingest

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/vault"
)

// TestTrainingWaitsForThePreflight: a batch the disk guard refuses must
// not first spend minutes training, nor write dictionary files.
func TestTrainingWaitsForThePreflight(t *testing.T) {
	h := newHarness(t, entries(t, 100), ctlogtest.Options{})
	h.opts.DictSamples = 20
	calls := 0
	h.opts.Train = func(s [][]byte, id uint64) ([]byte, error) { calls++; return vault.Train(s, id) }
	w := h.open()
	sth := h.head()
	h.ingest(w, sth, 0, 50, 50)
	h.opts.Guard.Stat = func(string) (diskguard.Usage, error) {
		return diskguard.Usage{Total: 100 << 30, Avail: 10 << 30, Dev: 1}, nil // 90% used
	}
	w.o.Guard = h.opts.Guard
	if _, err := w.Batch(ctx, h.src, sth, 50, 100); !errors.Is(err, diskguard.ErrCap) {
		t.Fatalf("the full disk refuses the batch: %v", err)
	}
	if ds, _ := vault.LoadDicts(h.vaultDirs()); calls != 0 || len(ds) != 0 {
		t.Fatalf("a refused batch trained %d times and left %d dictionaries", calls, len(ds))
	}
}

// TestTrainingStopsOnHardStop: training takes minutes; a second Ctrl-C
// must not wait for it. Nothing is written, and a later run trains again.
func TestTrainingStopsOnHardStop(t *testing.T) {
	h := newHarness(t, entries(t, 100), ctlogtest.Options{})
	h.opts.DictSamples = 20
	release := make(chan struct{})
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	var calls atomic.Int32 // trainings run on their own goroutines
	h.opts.Train = func(s [][]byte, id uint64) ([]byte, error) {
		if calls.Add(1) == 1 {
			<-release // a training that would run for minutes
		}
		return vault.Train(s, id)
	}
	w := h.open()
	t.Cleanup(free) // runs before the writer closes
	sth := h.head()
	h.ingest(w, sth, 0, 50, 50)
	bctx, cancel := context.WithCancel(ctx)
	time.AfterFunc(100*time.Millisecond, cancel)
	done := make(chan error, 1)
	go func() {
		_, err := w.Batch(bctx, h.src, sth, 50, 100)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("a hard stop during training: %v", err)
		}
	case <-time.After(10 * time.Second):
		free()
		<-done
		t.Fatal("a hard stop waited for the training to finish")
	}
	free()
	if in, _ := commit.ReadIntents(commit.Paths{Root: h.root}); len(in) != 0 {
		t.Fatal("training comes before the intent: nothing to abandon")
	}
	m, err := w.Batch(ctx, h.src, sth, 50, 100)
	if err != nil || m.Dictionary.ID != 1 || calls.Load() != 2 {
		t.Fatalf("the next batch trains again: %v, dictionary %d, %d calls", err, m.Dictionary.ID, calls.Load())
	}
}

// TestCanarySamplesTheWholeBatch: the vault records the canary reads are a
// uniform sample of the batch, not its first few thousand.
func TestCanarySamplesTheWholeBatch(t *testing.T) {
	r := newReservoir(100, 1, 2)
	for i := range 10000 {
		r.add(sample{loc: vault.Loc{Offset: uint64(i)}})
	}
	late := 0
	for _, s := range r.items {
		if s.loc.Offset >= 5000 {
			late++
		}
	}
	if len(r.items) != 100 || late < 30 || late > 70 {
		t.Fatalf("%d samples, %d from the batch's second half; want 100 and about 50", len(r.items), late)
	}
}

// TestViewsAreRewrittenAfterTheFirstCommit: views.sql changes from the
// empty form to the committed one as soon as a batch commits.
func TestViewsAreRewrittenAfterTheFirstCommit(t *testing.T) {
	h := newHarness(t, entries(t, 20), ctlogtest.Options{})
	w := h.open()
	read := func() string {
		b, _ := os.ReadFile(filepath.Join(h.root, dataset.ViewsFile))
		return string(b)
	}
	if !strings.Contains(read(), "WHERE false") {
		t.Fatal("a new vault has the empty views")
	}
	h.ingest(w, h.head(), 0, 20, 20)
	if !strings.Contains(read(), "read_parquet") {
		t.Fatalf("after the first commit views.sql reads the batches:\n%s", read())
	}
}
```

Create `internal/dataset/views_test.go`:

```go
package dataset

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
)

func describe(t *testing.T, s *Stager, view string) string {
	t.Helper()
	rows, err := s.db.Query(`SELECT column_name, column_type FROM (DESCRIBE ` + view + `)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n, ty string
		rows.Scan(&n, &ty)
		out = append(out, n+" "+ty)
	}
	return fmt.Sprint(out)
}

func loadViews(t *testing.T, s *Stager, root string) {
	t.Helper()
	v, err := os.ReadFile(filepath.Join(root, ViewsFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(string(v)); err != nil {
		t.Fatalf("views.sql does not load: %v", err)
	}
}

// TestViewsWorkBeforeTheFirstBatch: a new vault's views.sql loads and
// shows empty tables with the committed columns; after the first batch
// commits it changes and shows the batch.
func TestViewsWorkBeforeTheFirstBatch(t *testing.T) {
	root := t.TempDir()
	if changed, err := WriteViews(root); err != nil || !changed {
		t.Fatalf("first write: %v %v", changed, err)
	}
	empty := stager(t)
	loadViews(t, empty, root)
	var n, c, b int
	empty.db.QueryRow(`SELECT (SELECT count(*) FROM entries), (SELECT count(*) FROM chains), (SELECT count(*) FROM batches)`).Scan(&n, &c, &b)
	if n != 0 || c != 0 || b != 0 {
		t.Fatalf("an empty vault: %d entries, %d chain rows, %d batches", n, c, b)
	}

	s := stager(t)
	dir := filepath.Join(root, "dataset", "log=argon2027h1", "batch=000000000000-000000000039")
	es, cs := rows(40)
	if _, err := s.Stage(ctx, dir, es, cs); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "_COMMIT.json"), []byte(`{"format":1,"commit_seq":1}`), 0o644)
	if changed, err := WriteViews(root); err != nil || !changed {
		t.Fatalf("the first commit changes views.sql: %v %v", changed, err)
	}
	full := stager(t)
	loadViews(t, full, root)
	full.db.QueryRow(`SELECT count(*) FROM entries`).Scan(&n)
	if n != 40 {
		t.Fatalf("after the first commit: %d entries", n)
	}
	for _, v := range []string{"entries", "chains"} {
		if got, want := describe(t, empty, v), describe(t, full, v); got != want {
			t.Fatalf("%s before the first batch has columns %s\nafter: %s", v, got, want)
		}
	}
}

// TestCanaryChecksCertIDRanges: spec §8.3 P6(e), cert_id range lookups
// through the reader's predicate.
func TestCanaryChecksCertIDRanges(t *testing.T) {
	s := stager(t)
	dir := filepath.Join(t.TempDir(), "b")
	es, cs := rows(40)
	if _, err := s.Stage(ctx, dir, es, cs); err != nil {
		t.Fatal(err)
	}
	if err := s.Canary(ctx, dir, es, cs, 8, rand.New(rand.NewPCG(5, 6))); err != nil {
		t.Fatal(err)
	}
	bad := append([]EntryRow(nil), es...)
	bad[4].CertID = 0 // the file holds a cert_id the batch does not
	if err := s.Canary(ctx, dir, bad, cs, 0, rand.New(rand.NewPCG(5, 6))); !errors.Is(err, ErrCanary) {
		t.Fatalf("a cert_id range that reads back a different count: %v", err)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/ingest/ ./internal/dataset/`
Expected: FAIL with `undefined: newReservoir` in `internal/ingest`; in `internal/dataset`, `views.sql does not load: IO Error: No files found that match the pattern ".../dataset/log=*/batch=*/entries.parquet"` and `a cert_id range that reads back a different count: <nil>`. `TestTrainingStopsOnHardStop` fails on its own deadline, not by hanging.

- [ ] **Step 3: Implement**

Replace `internal/ingest/batch.go` with:

```go
package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

// Batch ingests entries [first, end) of src and commits them, verified
// against the pinned head sth (spec §8.3). A failed Merkle verification or
// canary abandons the attempt and refetches the batch once; a second
// failure writes an incident and returns ErrVerification. Any other error
// abandons the batch and is returned as is (a stall, a full disk, a second
// signal). The caller resets src's chain cache after every call.
func (w *Writer) Batch(ctx context.Context, src logsource.LogSource, sth logsource.SignedHead, first, end uint64) (commit.Manifest, error) {
	if w.broken != nil {
		return commit.Manifest{}, w.broken
	}
	m, err := w.attempt(ctx, src, sth, first, end)
	var firstTry, secondTry errRetry
	if !errors.As(err, &firstTry) {
		return m, err
	}
	w.logf("batch %s: %v; refetching it once", w.batchID(src, first, end), err)
	m, err = w.attempt(ctx, src, sth, first, end)
	if !errors.As(err, &secondTry) {
		return m, err
	}
	dir, ierr := w.incident(w.batchID(src, first, end), sth, firstTry, secondTry)
	if ierr != nil {
		return m, errors.Join(fmt.Errorf("%w: %v", ErrVerification, err), ierr)
	}
	return m, fmt.Errorf("%w: %v (incident written to %s)", ErrVerification, err, dir)
}

func (w *Writer) batchID(src logsource.LogSource, first, end uint64) commit.BatchID {
	return commit.BatchID{Log: src.Info().Name, First: first, Last: end - 1}
}

// batch is one attempt's in-memory state.
type batch struct {
	w       *Writer
	ctx     context.Context
	src     logsource.LogSource
	pb      *index.Batch
	before  *merkle.State // the compact range before the batch
	state   *merkle.State
	rows    []dataset.EntryRow
	chains  []dataset.ChainRow
	quar    bytes.Buffer
	counts  commit.Counts
	firstID uint64
	lastID  uint64
	samples *reservoir // vault records the canary reads back
}

type sample struct {
	sha [32]byte
	loc vault.Loc
}

// canaryReservoir is how many new vault records a batch keeps for the
// canary to choose from.
const canaryReservoir = 4096

// reservoir keeps a uniform random sample of a stream (Algorithm R), so the
// canary reads records from the whole batch, not only its start.
type reservoir struct {
	items []sample
	seen  int
	rnd   *rand.Rand
}

func newReservoir(n int, seed1, seed2 uint64) *reservoir {
	return &reservoir{items: make([]sample, 0, n), rnd: rand.New(rand.NewPCG(seed1, seed2))}
}

func (r *reservoir) add(s sample) {
	r.seen++
	if len(r.items) < cap(r.items) {
		r.items = append(r.items, s)
	} else if j := r.rnd.IntN(r.seen); j < len(r.items) {
		r.items[j] = s
	}
}

func (w *Writer) attempt(ctx context.Context, src logsource.LogSource, sth logsource.SignedHead, first, end uint64) (commit.Manifest, error) {
	id := w.batchID(src, first, end)
	tip := w.tips[id.Log]
	if first != tip.Next || end <= first || end > sth.TreeSize {
		return commit.Manifest{}, fmt.Errorf("batch %s: must start at %d and end within the signed tree of %d", id, tip.Next, sth.TreeSize)
	}
	state := merkle.NewState()
	if tip.State != nil {
		state = tip.State.Clone()
	}
	// P0: volume checks, the disk-guard peak preflight, then dictionary
	// training, which may take minutes and so runs only for a batch that
	// can start. A cache left cold by a stopped attempt is warmed first.
	if w.cold {
		if err := w.warm(); err != nil {
			return commit.Manifest{}, err
		}
		w.cold = false
	}
	if w.o.CheckVolumes != nil {
		if err := w.o.CheckVolumes(); err != nil {
			return commit.Manifest{}, err
		}
	}
	dir, err := w.preflight(end - first)
	if err != nil {
		return commit.Manifest{}, err
	}
	dict, err := w.maybeTrain(ctx)
	if err != nil {
		return commit.Manifest{}, err
	}
	w.vw.Prefer(dir)
	// P1
	in := commit.Intent{BatchID: id.String(), Log: id.Log, First: id.First, Last: id.Last, STH: toSTH(sth),
		VaultTail: w.vw.Tail(), NextCertID: w.ids.Peek(), MerkleBefore: state.Clone(), Builders: map[string]int{},
		StartedAt: w.o.Now().UTC()}
	if err := commit.WriteIntent(w.paths, in, w.o.Hook); err != nil {
		return commit.Manifest{}, err
	}
	b := &batch{w: w, ctx: ctx, src: src, pb: w.idx.NewBatch(), state: state, before: in.MerkleBefore,
		samples: newReservoir(canaryReservoir, first, end)}
	defer b.pb.Close()
	m, err := w.run(b, in, sth, dict)
	var after errCommitted
	if err != nil && !errors.As(err, &after) {
		if aerr := w.abandon(ctx, in); aerr != nil {
			w.broken = fmt.Errorf("%w: %s: %v", ErrAbandonFailed, id, aerr)
			return m, errors.Join(err, w.broken)
		}
	}
	return m, err
}

// ErrAbandonFailed means an attempt could not be cleaned up in process: the
// vault could not be cut back, or its intent could not be marked. The
// writer then refuses every further batch, and the next start recovers
// (spec §8.5).
var ErrAbandonFailed = errors.New("abandoning the batch failed; run update again to recover")

// run is P2-P10 of one attempt.
func (w *Writer) run(b *batch, in commit.Intent, sth logsource.SignedHead, dict commit.DictInfo) (commit.Manifest, error) {
	id := in.ID()
	// P2
	if _, err := fetch.Run(b.ctx, b.src, id.First, id.Last+1, w.o.Fetch, b.add); err != nil {
		return commit.Manifest{}, err
	}
	// P3
	if err := w.vw.Sync(); err != nil {
		return commit.Manifest{}, err
	}
	w.hook(HookAfterVaultSync)
	// P4
	verified, err := w.verify(b, sth, id.Last+1)
	if err != nil {
		return commit.Manifest{}, err
	}
	// P5
	stage := w.paths.StageDir(id)
	files, err := w.stager.Stage(b.ctx, stage, b.rows, b.chains)
	if err != nil {
		return commit.Manifest{}, err
	}
	if b.quar.Len() > 0 {
		p := filepath.Join(stage, commit.QuarantineFile)
		if err := os.WriteFile(p, b.quar.Bytes(), 0o644); err != nil {
			return commit.Manifest{}, err
		}
		fi, err := dataset.Sum(p)
		if err != nil {
			return commit.Manifest{}, err
		}
		fi.Rows = b.counts.LeafErrors
		files[commit.QuarantineFile] = fi
	}
	if err := w.o.Guard.Check(w.o.Root, 0); err != nil { // spec §10.1: a hard check after every staged write
		return commit.Manifest{}, err
	}
	// P6
	if err := w.canary(b, stage); err != nil {
		return commit.Manifest{}, err
	}
	// P7, P8
	seq := w.LastCommitSeq() + 1
	m := commit.Manifest{Format: commit.ManifestFormat, CommitSeq: seq, BatchID: id.String(), Log: id.Log,
		First: id.First, Last: id.Last, STH: toSTH(sth), MerkleAfter: b.state, Verified: verified,
		NextCertID: w.ids.Peek(), Vault: commit.Span{Start: in.VaultTail, End: w.vw.Tail()}, Builders: map[string]int{},
		Files: files, Counts: b.counts, Dictionary: dict, CTVaultVersion: w.o.Version, CommittedAt: w.o.Now().UTC()}
	m.Counts.Entries = len(b.rows)
	if b.firstID != 0 {
		m.CertIDRange = &[2]uint64{b.firstID, b.lastID}
	}
	perr := commit.Publish(w.paths, m, w.o.Hook)
	if perr != nil && !errors.Is(perr, commit.ErrPostCommit) {
		return m, perr // the rename did not happen: abandon
	}
	// From here the batch is committed; failures below are repaired by
	// recovery at the next start, never by abandoning.
	w.committed = append(w.committed, m)
	w.tips[id.Log] = commit.LogTip{Next: id.Last + 1, State: b.state}
	if perr != nil {
		return m, errCommitted{perr}
	}
	// P9
	if err := b.pb.SetApplied(id.Log, seq); err != nil {
		return m, errCommitted{err}
	}
	w.hook(HookBeforePebble)
	if err := b.pb.Commit(); err != nil {
		return m, errCommitted{err}
	}
	w.hook(HookAfterPebble)
	// P10
	if err := commit.RemoveIntent(w.paths, id, w.o.Hook); err != nil {
		return m, errCommitted{err}
	}
	if err := commit.ClearAbandoned(w.paths); err != nil {
		return m, errCommitted{err}
	}
	if _, err := dataset.WriteViews(w.o.Root); err != nil { // the first commit changes it
		return m, errCommitted{err}
	}
	w.logf("batch %s: %d entries, %d new certificates (%d deltas), %d leaf errors, %d vault bytes, verified by %s; commit_seq %d",
		id, m.Counts.Entries, m.Counts.NewCerts, m.Counts.DeltaRecords, m.Counts.LeafErrors, m.Counts.VaultBytes, verified.Method, seq)
	return m, nil
}

// Hook points of the engine's own steps, for crash tests (spec §13.5).
const (
	HookAfterVaultSync = "commit.P3.after_vault_sync"
	HookDuringCanary   = "commit.P6.during_canary" // between the Parquet and the vault checks
	HookBeforePebble   = "commit.P9.before_pebble"
	HookAfterPebble    = "commit.P9.after_pebble"
)

func (w *Writer) hook(p string) {
	if w.o.Hook != nil {
		w.o.Hook(p)
	}
}

// errCommitted wraps a failure after the commit point: the batch is
// committed, so it must not be abandoned.
type errCommitted struct{ err error }

func (e errCommitted) Error() string { return "after commit: " + e.err.Error() }
func (e errCommitted) Unwrap() error { return e.err }

// abandon discards an attempt: vault, staging and intent go, the Pebble
// batch is discarded by the caller, cert_ids skip to the floor, and the
// delta cache forgets records that no longer exist. When ctx is done the
// process is stopping: the cache is emptied and left cold instead of
// re-reading the vault, and the next attempt warms it.
func (w *Writer) abandon(ctx context.Context, in commit.Intent) error {
	if err := w.vw.Close(); err != nil {
		return err
	}
	if err := commit.Abandon(w.paths, w.o.VaultDirs, in); err != nil {
		return err
	}
	w.ids.SkipToFloor()
	var err error
	if w.vw, err = vault.OpenWriter(w.vaultOptions(), w.codec, in.VaultTail); err != nil {
		return err
	}
	if ctx.Err() != nil {
		w.delta.Reset()
		w.cold = true
		return nil
	}
	return w.warm()
}

// add handles one entry in index order (P2).
func (b *batch) add(e logsource.RawEntry) error {
	if err := b.state.Append(e.Leaf.LeafHash); err != nil {
		return err
	}
	row := dataset.EntryRow{Idx: e.Index, CTTimestamp: e.Leaf.Timestamp, EntryType: e.Leaf.Type.String(), LeafHash: e.Leaf.LeafHash}
	if k, ok := e.Leaf.IssuanceKey(); ok {
		row.IssuanceKey, row.HasIssuanceKey = k, true
	}
	if e.Leaf.HasIssuerKeyHash {
		row.IssuerKeyHash, row.HasIssuerKeyHash = e.Leaf.IssuerKeyHash, true
	}
	if e.Leaf.Code != leaf.OK {
		row.LeafError = string(e.Leaf.Code)
		b.counts.LeafErrors++
		line, _ := json.Marshal(map[string]any{"idx": e.Index, "leaf_error": e.Leaf.Code,
			"leaf_input": base64.StdEncoding.EncodeToString(e.LeafInput), "extra_data": base64.StdEncoding.EncodeToString(e.ExtraData)})
		b.quar.Write(append(line, '\n'))
	}
	if e.Leaf.CertDER != nil {
		id, err := b.vaultLeaf(e.Leaf)
		if err != nil {
			return err
		}
		row.CertID = id
	}
	if e.Chain != nil {
		chainID, err := b.vaultChain(e.Chain)
		if err != nil {
			return err
		}
		row.ChainID, row.HasChainID = chainID, true
	}
	b.rows = append(b.rows, row)
	return nil
}

func (b *batch) assign() (uint64, error) {
	id, err := b.w.ids.Next()
	if err != nil {
		return 0, err
	}
	if b.firstID == 0 {
		b.firstID = id
	}
	b.lastID = id
	return id, nil
}

func (b *batch) vaulted(sha [32]byte, ref index.Ref) error {
	b.counts.NewCerts++
	b.counts.VaultBytes += uint64(ref.Loc.Len)
	b.samples.add(sample{sha, ref.Loc})
	return b.pb.AddCert(sha, ref)
}

// vaultLeaf stores a leaf certificate unless it is already vaulted. A final
// certificate whose precert is cached becomes a leaf-delta record.
func (b *batch) vaultLeaf(l leaf.Entry) (uint64, error) {
	sha := sha256.Sum256(l.CertDER)
	if ref, ok, err := b.pb.Lookup(sha); err != nil || ok {
		return ref.CertID, err
	}
	id, err := b.assign()
	if err != nil {
		return 0, err
	}
	var loc vault.Loc
	if base, ok := b.w.delta.Get(l.IssuanceDigest); ok && l.Type == leaf.TypeX509 && l.HasIssuanceDigest {
		if loc, err = b.w.vw.AppendDelta(id, l.CertDER, base); err != nil {
			return 0, err
		}
		b.counts.DeltaRecords++
	} else if loc, err = b.w.vw.AppendCert(vault.KindLeaf, id, l.CertDER, b.w.dictID); err != nil {
		return 0, err
	}
	if l.Type == leaf.TypePrecert && l.HasIssuanceDigest {
		b.w.delta.Put(l.IssuanceDigest, loc)
	}
	return id, b.vaulted(sha, index.Ref{CertID: id, Loc: loc})
}

// vaultChain stores unseen chain certificates and returns the chain_id,
// adding chains.parquet rows the first time a chain is seen.
func (b *batch) vaultChain(fps [][32]byte) ([32]byte, error) {
	ids := make([]uint64, len(fps))
	h := sha256.New()
	for i, fp := range fps {
		h.Write(fp[:])
		ref, ok, err := b.pb.Lookup(fp)
		if err != nil {
			return [32]byte{}, err
		}
		if ok {
			ids[i] = ref.CertID
			continue
		}
		der, err := b.src.Issuer(b.ctx, fp)
		if err != nil {
			return [32]byte{}, err
		}
		if sha256.Sum256(der) != fp {
			return [32]byte{}, fmt.Errorf("chain certificate %x does not match its fingerprint", fp[:8])
		}
		if ids[i], err = b.assign(); err != nil {
			return [32]byte{}, err
		}
		loc, err := b.w.vw.AppendCert(vault.KindChain, ids[i], der, b.w.dictID)
		if err != nil {
			return [32]byte{}, err
		}
		if err := b.vaulted(fp, index.Ref{CertID: ids[i], Loc: loc}); err != nil {
			return [32]byte{}, err
		}
	}
	var chainID [32]byte
	copy(chainID[:], h.Sum(nil))
	seen, err := b.pb.HasChain(chainID)
	if err != nil || seen {
		return chainID, err
	}
	for i, id := range ids {
		b.chains = append(b.chains, dataset.ChainRow{ChainID: chainID, Position: uint16(i), CertID: id})
	}
	return chainID, b.pb.AddChain(chainID)
}

// verify is P4 (spec §5.5): the computed root at end must equal the signed
// root, or be proven a prefix of it.
func (w *Writer) verify(b *batch, sth logsource.SignedHead, end uint64) (commit.Verified, error) {
	root, err := b.state.Root()
	if err != nil {
		return commit.Verified{}, err
	}
	if end == sth.TreeSize {
		if root != sth.RootHash {
			return commit.Verified{}, errRetry{err: errors.New("the computed root differs from the signed root"),
				before: b.before, root: root, end: end}
		}
		return commit.Verified{Method: "root_equals_sth"}, nil
	}
	var proof [][32]byte
	if err := fetch.Retry(b.ctx, w.o.Fetch, func(ctx context.Context) (err error) {
		proof, err = b.src.ConsistencyProof(ctx, end, sth.TreeSize)
		return err
	}); err != nil {
		return commit.Verified{}, err
	}
	if err := merkle.VerifyConsistency(end, sth.TreeSize, root, sth.RootHash, proof); err != nil {
		return commit.Verified{}, errRetry{err: err, before: b.before, root: root, end: end, proof: proof}
	}
	return commit.Verified{Method: "consistency_proof", ProofNodes: len(proof)}, nil
}

// canary is P6: the staged files, and vault reads of sampled new records.
func (w *Writer) canary(b *batch, stage string) error {
	rnd := rand.New(rand.NewPCG(b.rows[0].Idx, uint64(len(b.rows))))
	if err := w.stager.Canary(b.ctx, stage, b.rows, b.chains, w.o.CanarySamples, rnd); err != nil {
		return errRetry{err: err}
	}
	w.hook(HookDuringCanary)
	r, err := vault.OpenReader(w.o.VaultDirs, w.codec)
	if err != nil {
		return err
	}
	defer r.Close()
	for range min(w.o.CanarySamples, len(b.samples.items)) {
		s := b.samples.items[rnd.IntN(len(b.samples.items))]
		if _, err := r.ReadVerified(s.loc, s.sha); err != nil {
			return errRetry{err: err}
		}
	}
	return nil
}

// maybeTrain trains dictionary 1 once the committed vault holds
// DictSamples leaf certificates; a training failure is recorded and
// ingestion goes on with dictionary 0 (amendment A1 §5). It is tried once
// per process. Vault corruption met while reading the samples is returned:
// corruption is never ignored (spec §12). Training takes minutes, so a
// cancelled ctx returns at once; the abandoned training finishes in the
// background and is discarded, and a later run trains again.
func (w *Writer) maybeTrain(ctx context.Context) (commit.DictInfo, error) {
	if w.dictID != 0 || w.trainTried {
		return commit.DictInfo{ID: w.dictID}, nil
	}
	samples, tr, err := vault.TrainingSet(w.o.VaultDirs, w.codec, w.vw.Tail(), w.o.DictSamples)
	if err != nil {
		return commit.DictInfo{}, fmt.Errorf("reading dictionary training samples: %w", err)
	}
	if len(samples) < w.o.DictSamples {
		return commit.DictInfo{ID: 0}, nil
	}
	w.trainTried = true
	w.logf("training dictionary 1 on %d leaf certificates", len(samples))
	type trained struct {
		content []byte
		err     error
	}
	done := make(chan trained, 1)
	go func() {
		c, err := w.o.Train(samples, 1)
		done <- trained{c, err}
	}()
	var res trained
	select {
	case res = <-done:
	case <-ctx.Done():
		w.trainTried = false
		return commit.DictInfo{}, ctx.Err()
	}
	content, err := res.content, res.err
	if err == nil {
		var d vault.Dict
		if d, err = vault.InstallDict(w.o.VaultDirs, 1, content, tr, w.o.Now()); err == nil {
			err = w.codec.AddDict(1, d.Content)
		}
	}
	if err != nil {
		w.logf("dictionary training failed; continuing without a dictionary: %v", err)
		return commit.DictInfo{ID: 0, TrainingError: err.Error()}, nil
	}
	w.dictID = 1
	return commit.DictInfo{ID: 1}, nil
}

// preflight is the spec §10.1 peak check before a batch starts. It returns
// the vault directory whose filesystem holds the vault peak; the batch's new
// segments go there.
func (w *Writer) preflight(n uint64) (string, error) {
	var vaultHist, parquetHist []float64
	for i := max(0, len(w.committed)-diskguard.MinHistory); i < len(w.committed); i++ {
		m := w.committed[i]
		if m.Counts.Entries == 0 {
			continue
		}
		var pq int64
		for _, f := range m.Files {
			pq += f.Bytes
		}
		vaultHist = append(vaultHist, float64(m.Counts.VaultBytes)/float64(m.Counts.Entries))
		parquetHist = append(parquetHist, float64(pq)/float64(m.Counts.Entries))
	}
	cfg := w.o.Config
	peak := diskguard.EstimatePeak(diskguard.PeakInput{Entries: n,
		VaultP95: diskguard.P95(vaultHist, diskguard.SeedVaultBytesPerEntry), ParquetP95: diskguard.P95(parquetHist, diskguard.SeedParquetBytesPerEntry),
		PebbleP95: diskguard.SeedPebbleBytesPerEntry, Safety: cfg.Disk.SafetyFactor,
		PebbleSize: dirSize(filepath.Join(w.o.Root, "state", "pebble")), DuckDBSpill: w.spillLimit()})
	var err error
	for _, d := range w.o.VaultDirs {
		if err = w.o.Guard.Preflight([]diskguard.Target{{Path: w.o.Root, Need: peak.Root}, {Path: d, Need: peak.Vault}}); err == nil {
			return d, nil
		}
	}
	return "", err
}

func dirSize(dir string) uint64 {
	var n uint64
	filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				n += uint64(fi.Size())
			}
		}
		return nil
	})
	return n
}

func toSTH(h logsource.SignedHead) commit.STH {
	return commit.STH{TreeSize: h.TreeSize, Timestamp: h.Timestamp, RootHash: hex.EncodeToString(h.RootHash[:]),
		Signature: base64.StdEncoding.EncodeToString(h.Signature)}
}

// incident writes the evidence of a batch that failed verification twice
// (spec §12): the pinned head as received, both attempts' causes, and for a
// Merkle failure our compact range before the batch, the root we computed
// and the proof the log served. The fetched data itself is truncated.
func (w *Writer) incident(id commit.BatchID, sth logsource.SignedHead, first, second errRetry) (string, error) {
	dir := filepath.Join(w.o.Root, "state", "incidents", w.o.Now().UTC().Format("20060102T150405Z")+"_"+id.Log+"_"+fmt.Sprint(id.First))
	if err := fsutil.MkdirAllSync(dir, 0o755); err != nil {
		return "", err
	}
	ev := map[string]any{"batch_id": id.String(), "causes": []string{first.Error(), second.Error()}, "sth": toSTH(sth),
		"sth_raw": base64.StdEncoding.EncodeToString(sth.Raw), "time": w.o.Now().UTC().Format(time.RFC3339)}
	if second.before != nil {
		proof := make([]string, len(second.proof))
		for i, n := range second.proof {
			proof[i] = hex.EncodeToString(n[:])
		}
		ev["merkle_before"], ev["computed_root"], ev["end"], ev["proof"] = second.before, hex.EncodeToString(second.root[:]), second.end, proof
	}
	b, err := json.MarshalIndent(ev, "", " ")
	if err != nil {
		return dir, err
	}
	return dir, fsutil.WriteFileAtomic(filepath.Join(dir, "incident.json"), b, 0o644)
}
```

Replace `internal/dataset/canary.go` with:

```go
package dataset

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"slices"
	"time"
)

// ErrCanary means a staged file does not hold what was written; the batch is
// not committed (spec §8.3 P6).
var ErrCanary = errors.New("canary failed")

func canaryErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCanary, fmt.Sprintf(format, args...))
}

// expected column types, as DuckDB reads them back. ct_ts is checked again
// in the Parquet schema, because DuckDB reads TIMESTAMP_MS back as TIMESTAMP.
var (
	entriesSchema = []string{"idx UBIGINT", "ct_ts TIMESTAMP", "entry_type VARCHAR", "cert_id UBIGINT",
		"leaf_hash BLOB", "issuance_key BLOB", "issuer_key_hash BLOB", "chain_id BLOB", "leaf_error VARCHAR"}
	chainsSchema = []string{"chain_id BLOB", "position USMALLINT", "cert_id UBIGINT"}
)

// Canary checks staged files against the rows they were written from:
// column names and types, no bloom filter anywhere, row counts, n random
// rows read back field by field through literal BLOB lookups, the path
// readers use, and cert_id range counts (spec §8.3 P6(e)): the batch's
// whole range and n random sub-ranges.
func (s *Stager) Canary(ctx context.Context, dir string, entries []EntryRow, chains []ChainRow, n int, rnd *rand.Rand) error {
	ep, cp := filepath.Join(dir, EntriesFile), filepath.Join(dir, ChainsFile)
	for _, f := range []struct {
		path   string
		schema []string
		rows   int
	}{{ep, entriesSchema, len(entries)}, {cp, chainsSchema, len(chains)}} {
		if err := s.checkSchema(ctx, f.path, f.schema); err != nil {
			return err
		}
		var blooms, rows int
		if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM parquet_metadata(`+quote(f.path)+`) WHERE bloom_filter_offset IS NOT NULL`).Scan(&blooms); err != nil {
			return err
		}
		if blooms != 0 {
			return canaryErr("%s has %d bloom filters; none are allowed", filepath.Base(f.path), blooms)
		}
		if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM read_parquet(`+quote(f.path)+`)`).Scan(&rows); err != nil {
			return err
		}
		if rows != f.rows {
			return canaryErr("%s has %d rows, want %d", filepath.Base(f.path), rows, f.rows)
		}
	}
	var unit string
	if err := s.db.QueryRowContext(ctx, `SELECT logical_type FROM parquet_schema(`+quote(ep)+`) WHERE name = 'ct_ts'`).Scan(&unit); err != nil {
		return err
	}
	if !bytes.Contains([]byte(unit), []byte("MILLIS=MilliSeconds")) {
		return canaryErr("ct_ts is %q, want TIMESTAMP_MS", unit)
	}
	for range min(n, len(entries)) {
		if err := s.checkEntry(ctx, ep, entries[rnd.IntN(len(entries))]); err != nil {
			return err
		}
	}
	if err := s.checkCertRanges(ctx, ep, entries, n, rnd); err != nil {
		return err
	}
	for range min(n, len(chains)) {
		r := chains[rnd.IntN(len(chains))]
		var cert uint64
		err := s.db.QueryRowContext(ctx, `SELECT cert_id FROM read_parquet(`+quote(cp)+`) WHERE chain_id = ?::BLOB AND position = ?`,
			r.ChainID[:], r.Position).Scan(&cert)
		if err != nil || cert != r.CertID {
			return canaryErr("chain %x position %d: cert_id %d, %v; want %d", r.ChainID[:4], r.Position, cert, err, r.CertID)
		}
	}
	return nil
}

// checkCertRanges counts rows by cert_id range, as readers select them.
func (s *Stager) checkCertRanges(ctx context.Context, path string, entries []EntryRow, n int, rnd *rand.Rand) error {
	var ids []uint64
	for _, e := range entries {
		if e.CertID != 0 {
			ids = append(ids, e.CertID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	slices.Sort(ids)
	ranges := [][2]uint64{{ids[0], ids[len(ids)-1]}}
	for range min(n, len(ids)) {
		a, b := ids[rnd.IntN(len(ids))], ids[rnd.IntN(len(ids))]
		ranges = append(ranges, [2]uint64{min(a, b), max(a, b)})
	}
	for _, r := range ranges {
		lo, _ := slices.BinarySearch(ids, r[0]) // the first id >= r[0]
		hi, _ := slices.BinarySearch(ids, r[1]+1)
		var got int
		if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM read_parquet(`+quote(path)+`) WHERE cert_id BETWEEN ? AND ?`, r[0], r[1]).Scan(&got); err != nil {
			return err
		}
		if got != hi-lo {
			return canaryErr("cert_id range [%d, %d] has %d rows, want %d", r[0], r[1], got, hi-lo)
		}
	}
	return nil
}

func (s *Stager) checkSchema(ctx context.Context, path string, want []string) error {
	rows, err := s.db.QueryContext(ctx, `SELECT column_name, column_type FROM (DESCRIBE SELECT * FROM read_parquet(`+quote(path)+`))`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var name, typ string
		if err := rows.Scan(&name, &typ); err != nil {
			return err
		}
		got = append(got, name+" "+typ)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		return canaryErr("%s schema %v, want %v", filepath.Base(path), got, want)
	}
	return rows.Err()
}

// checkEntry finds a row by its leaf hash literal and compares every field.
func (s *Stager) checkEntry(ctx context.Context, path string, want EntryRow) error {
	var idx uint64
	var ts sql.NullTime
	var etype string
	var cert sql.NullInt64
	var ikey, ikh, chain []byte
	var lerr sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT idx, ct_ts, entry_type, cert_id, issuance_key, issuer_key_hash, chain_id, leaf_error
		FROM read_parquet(`+quote(path)+`) WHERE leaf_hash = ?::BLOB AND idx = ?`, want.LeafHash[:], want.Idx).
		Scan(&idx, &ts, &etype, &cert, &ikey, &ikh, &chain, &lerr)
	if err != nil {
		return canaryErr("entry %d: %v", want.Idx, err)
	}
	wantTS := sql.NullTime{}
	if want.CTTimestamp != 0 {
		wantTS = sql.NullTime{Time: time.UnixMilli(int64(want.CTTimestamp)).UTC(), Valid: true}
	}
	ok := idx == want.Idx && ts.Valid == wantTS.Valid && ts.Time.Equal(wantTS.Time) && etype == want.EntryType &&
		cert.Valid == (want.CertID != 0) && uint64(cert.Int64) == want.CertID &&
		blobIs(ikey, want.HasIssuanceKey, want.IssuanceKey[:]) && blobIs(ikh, want.HasIssuerKeyHash, want.IssuerKeyHash[:]) &&
		blobIs(chain, want.HasChainID, want.ChainID[:]) && lerr.String == want.LeafError && lerr.Valid == (want.LeafError != "")
	if !ok {
		return canaryErr("entry %d reads back differently", want.Idx)
	}
	return nil
}

func blobIs(got []byte, has bool, want []byte) bool {
	if !has {
		return got == nil
	}
	return bytes.Equal(got, want)
}
```

Replace `internal/dataset/views.go` with:

```go
package dataset

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/4rji/ctvault/internal/fsutil"
)

// ViewsFile is generated at the vault root for the DuckDB CLI and Jupyter.
const ViewsFile = "views.sql"

// Views returns views.sql for a vault at root (absolute). Plan 2's minimal
// set: entries, chains and batches over committed batch directories only;
// staging lives in tmp/, never under dataset/. Until the first batch
// commits, the globs would match nothing and DuckDB would refuse to load
// the file, so the views are empty with the committed columns instead.
func Views(root string, committed bool) []byte {
	head := fmt.Sprintf(`-- Generated by ctvault; do not edit. Load with: .read %s
`, filepath.Join(root, ViewsFile))
	if !committed {
		return []byte(head + `-- No batch is committed yet: the views are empty. ctvault rewrites this
-- file when the first batch commits.
CREATE OR REPLACE VIEW entries AS
  SELECT NULL::UBIGINT AS idx, NULL::TIMESTAMP AS ct_ts, NULL::VARCHAR AS entry_type, NULL::UBIGINT AS cert_id,
    NULL::BLOB AS leaf_hash, NULL::BLOB AS issuance_key, NULL::BLOB AS issuer_key_hash, NULL::BLOB AS chain_id,
    NULL::VARCHAR AS leaf_error, NULL::VARCHAR AS batch, NULL::VARCHAR AS log
  WHERE false;
CREATE OR REPLACE VIEW chains AS
  SELECT NULL::BLOB AS chain_id, NULL::USMALLINT AS position, NULL::UBIGINT AS cert_id,
    NULL::VARCHAR AS batch, NULL::VARCHAR AS log
  WHERE false;
CREATE OR REPLACE VIEW batches AS
  SELECT NULL::UBIGINT AS commit_seq, NULL::VARCHAR AS batch_id, NULL::VARCHAR AS log,
    NULL::UBIGINT AS first, NULL::UBIGINT AS last
  WHERE false;
`)
	}
	ds := filepath.Join(root, "dataset")
	glob := func(name string) string { return quote(filepath.Join(ds, "log=*", "batch=*", name)) }
	return []byte(head + fmt.Sprintf(`-- Globs see a commit at once, but a join running while a batch commits can
-- see it in one table and not yet in another (spec §7.6).
CREATE OR REPLACE VIEW entries AS
  SELECT * FROM read_parquet(%s, hive_partitioning = true, union_by_name = true);
CREATE OR REPLACE VIEW chains AS
  SELECT * FROM read_parquet(%s, hive_partitioning = true, union_by_name = true);
CREATE OR REPLACE VIEW batches AS
  SELECT * FROM read_json(%s, format = 'auto', union_by_name = true);
`, glob(EntriesFile), glob(ChainsFile), glob("_COMMIT.json")))
}

// WriteViews regenerates views.sql and replaces it atomically only when its
// contents change (amendment A1 §7). It reports whether it wrote. The
// writer calls it at start and after every commit.
func WriteViews(root string) (bool, error) {
	done, err := filepath.Glob(filepath.Join(root, "dataset", "log=*", "batch=*", "_COMMIT.json"))
	if err != nil {
		return false, err
	}
	want := Views(root, len(done) > 0)
	p := filepath.Join(root, ViewsFile)
	got, err := os.ReadFile(p)
	if err == nil && bytes.Equal(got, want) {
		return false, nil
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	return true, fsutil.WriteFileAtomic(p, want, 0o644)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race ./internal/ingest/ ./internal/dataset/`
Expected: PASS.

- [ ] **Step 5: Quality gate**

- [ ] **Step 6: Checkpoint.**

---

### Task C4: `update` exit codes and head checks (M1, M2a, M5, M9)

Spec §11.2, §12, amendment A1 §4 (head checks).

**Files:**
- Modify: `internal/cli/update.go`, `internal/ingest/writer.go`
- Test: `internal/cli/update_cycle_test.go` (new)

**Interfaces:**
- Produces: `ingest.(*Writer).Tip(log string) commit.LogTip`
- Changes in `update`:
  - `afterCycle` decides what follows a cycle's error. `--follow` waits out a full disk or a stall, but never `ErrAbandonFailed`. After a second interrupt a coded error keeps its exit code.
  - Every fetched head is checked against the committed tip, inside the head's refetch-once. A head that is smaller, or not proven to extend the tip, is an incident (exit 5) and is not stored.
  - A head incident that cannot be written is reported, and the exit stays 5.

- [ ] **Step 1: Write the failing tests**

Create `internal/cli/update_cycle_test.go`:

```go
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
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/cli/`
Expected: FAIL with `undefined: afterCycle` in `internal/cli`.

- [ ] **Step 3: Implement**

Replace `internal/cli/update.go` with:

```go
package cli

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/ingest"
	"github.com/4rji/ctvault/internal/logreg"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/stop"
	"github.com/4rji/ctvault/internal/vault"
	"github.com/4rji/ctvault/internal/volume"
)

// headRetryDelay is how long update waits before refetching a signed head
// that failed its checks (spec §12: refetch once). A lagging frontend gets
// time to catch up. Tests shorten it.
var headRetryDelay = 5 * time.Second

// updateRun is one invocation of update. Build-tagged files may add flags
// and replace the log source (the dev build's --replay).
type updateRun struct {
	a        *app
	follow   bool
	until    uint64
	untilSet bool
	logName  string
	// source opens a log; maxEnd > 0 bounds what it can serve.
	source func(c *cobra.Command, info logsource.LogInfo, chains *logsource.ChainCache, last *logsource.SignedHead) (src logsource.LogSource, maxEnd uint64, closeFn func(), err error)
	// prepare runs before anything else, check once config and the log's
	// position are known (the dev build's replay rules); both nil in
	// production.
	prepare func(c *cobra.Command) error
	check   func(cfg config.Config, next uint64) error
}

// updateHooks let build-tagged files extend update; production has none.
var updateHooks []func(*cobra.Command, *updateRun)

func newUpdateCmd(a *app) *cobra.Command {
	u := &updateRun{a: a}
	u.source = func(_ *cobra.Command, info logsource.LogInfo, chains *logsource.ChainCache, last *logsource.SignedHead) (logsource.LogSource, uint64, func(), error) {
		return rfc6962.NewSource(info, a.d.HTTP, chains, last), 0, func() {}, nil
	}
	cmd := &cobra.Command{
		Use:     "update [--follow] [--until N] [--log NAME]",
		Aliases: []string{"ingest"},
		Short:   "Ingest pinned logs up to their current signed tree head",
		Args:    usageArgs(cobra.NoArgs),
		RunE: func(c *cobra.Command, _ []string) error {
			u.untilSet = c.Flags().Changed("until")
			return u.run(c)
		},
	}
	f := cmd.Flags()
	f.BoolVar(&u.follow, "follow", false, "keep ingesting, one cycle every ingest.follow_interval")
	f.Uint64Var(&u.until, "until", 0, "stop at index N (exclusive); never changes the stored head")
	f.StringVar(&u.logName, "log", "", "ingest only this pinned log")
	for _, h := range updateHooks {
		h(cmd, u)
	}
	return cmd
}

func (u *updateRun) run(c *cobra.Command) error {
	a := u.a
	if u.prepare != nil {
		if err := u.prepare(c); err != nil {
			return err
		}
	}
	root, id, err := a.openVault(c)
	if err != nil {
		return err
	}
	lk, err := a.writerLock(root)
	if err != nil {
		return err
	}
	defer lk.Release()
	cfg, err := config.Load(root)
	if err != nil {
		return exitcode.With(exitcode.Usage, err)
	}
	recs, err := u.logs(root)
	if err != nil {
		return err
	}
	uuid, err := vault.ParseUUID(id.VaultUUID)
	if err != nil {
		return exitcode.With(exitcode.Verification, err)
	}
	out := c.OutOrStdout()
	w, err := ingest.Open(ingest.Options{Root: root, VaultDirs: vaultDirs(root, id), VaultUUID: uuid, Config: cfg,
		Guard: diskguard.Guard{Cap: cfg.Disk.MaxUsedFraction, Stat: a.d.Statfs}, Version: a.d.Version, Now: a.d.Now, Out: out,
		CheckVolumes: func() error {
			_, err := a.d.Volumes.Check(root)
			return err
		},
		Fetch: fetch.Options{Workers: cfg.Ingest.Workers, MaxRPS: cfg.Ingest.MaxRPS, StallTimeout: cfg.Ingest.StallTimeout.Duration,
			MaxBufferedEntries: cfg.Fetch.MaxBufferedEntries, MaxBufferedBytes: int(cfg.Fetch.MaxBufferedBytes)}})
	if err != nil {
		return ingestErr(err)
	}
	defer w.Close()
	stops := stop.OnSignals(c.Context(), func() {
		fmt.Fprintln(c.ErrOrStderr(), "interrupt: finishing the current batch, then stopping; press Ctrl-C again to abandon it")
	}, func() {
		fmt.Fprintln(c.ErrOrStderr(), "interrupt: abandoning the current batch; it will be fetched again next time")
	})
	defer stops.Close()
	for {
		for _, rec := range recs {
			warning, err := afterCycle(u.cycle(c, stops, w, rec, cfg, root), u.follow, stops.Hard.Err() != nil)
			if err != nil {
				return err
			}
			if warning != "" {
				fmt.Fprintln(c.ErrOrStderr(), warning)
			}
			if stops.Soft.Err() != nil {
				fmt.Fprintln(out, "stopped after the last committed batch; run update again to continue")
				return nil
			}
		}
		if !u.follow {
			return nil
		}
		select {
		case <-stops.Soft.Done():
			fmt.Fprintln(out, "stopped between cycles")
			return nil
		case <-time.After(cfg.Ingest.FollowInterval.Duration):
		}
	}
}

// afterCycle decides what update does after a cycle: a nil error goes on;
// under --follow a full disk or a stall is a warning and waits for the next
// cycle; anything else ends the run with its exit code (spec §11.2). A
// writer whose abandon failed always ends the run. After a second interrupt
// an error keeps its own exit code (an incident stays 5), and only an error
// without one becomes "stopped" with exit 1.
func afterCycle(err error, follow, hardStopped bool) (warning string, stop error) {
	switch {
	case err == nil:
		return "", nil
	case errors.Is(err, ingest.ErrAbandonFailed):
		return "", ingestErr(err)
	case hardStopped:
		if coded := ingestErr(err); exitcode.Of(coded) != exitcode.Error {
			return "", coded
		}
		return "", exitcode.Withf(exitcode.Error, "stopped by a second interrupt; the batch in progress was abandoned")
	case follow && errors.Is(err, diskguard.ErrCap):
		return fmt.Sprintf("warning: %v; pausing until the next cycle", err), nil
	case follow && errors.Is(err, fetch.ErrStalled):
		return fmt.Sprintf("warning: %v; retrying next cycle", err), nil
	}
	return "", ingestErr(err)
}

func (u *updateRun) logs(root string) ([]logreg.Record, error) {
	if u.logName != "" {
		r, err := logreg.Get(root, u.logName)
		return []logreg.Record{r}, err
	}
	recs, err := logreg.List(root)
	if err == nil && len(recs) == 0 {
		err = errors.New("no logs are pinned; run: ctvault logs add <name>")
	}
	return recs, err
}

// vaultDirs lists the vault directories recorded in VAULT_ID, absolute.
func vaultDirs(root string, id volume.VaultID) []string {
	var out []string
	for _, v := range id.Volumes {
		if v.Role != volume.RoleVaultDir {
			continue
		}
		p := v.Path
		if !filepath.IsAbs(p) {
			p = filepath.Join(root, p)
		}
		out = append(out, p)
	}
	return out
}

// cycle is one update cycle for one log (spec §5.6, amendment A1 §3).
func (u *updateRun) cycle(c *cobra.Command, stops *stop.Contexts, w *ingest.Writer, rec logreg.Record, cfg config.Config, root string) error {
	out := c.OutOrStdout()
	next := w.Next(rec.Name)
	if u.untilSet && next >= u.until {
		fmt.Fprintf(out, "%s: already at index %d (--until %d); nothing to do\n", rec.Name, next, u.until)
		return nil
	}
	if u.check != nil {
		if err := u.check(cfg, next); err != nil {
			return err
		}
	}
	info, err := logsource.InfoFromRecord(rec)
	if err != nil {
		return exitcode.With(exitcode.Verification, err)
	}
	state := filepath.Join(root, "state")
	last, err := logsource.LoadHead(state, rec.Name, info)
	if err != nil {
		return exitcode.With(exitcode.Verification, err)
	}
	chains := logsource.NewChainCache(logsource.DefaultChainCacheBytes)
	src, maxEnd, closeSrc, err := u.source(c, info, chains, last)
	if err != nil {
		return err
	}
	defer closeSrc()
	head, err := u.head(stops.Hard, src, rec.Name, last, w.Tip(rec.Name), state)
	if err != nil {
		return err
	}
	if err := logsource.SaveHead(state, rec.Name, head, u.a.d.Now()); err != nil {
		return err
	}
	end := head.TreeSize
	if maxEnd > 0 {
		end = min(end, maxEnd)
	}
	if u.untilSet {
		if u.until > end {
			return exitcode.Withf(exitcode.Error, "%s: --until %d is beyond the log, which currently has only %d entries", rec.Name, u.until, end)
		}
		end = u.until
	}
	if next >= end {
		fmt.Fprintf(out, "%s: up to date at index %d (signed tree size %d)\n", rec.Name, next, head.TreeSize)
		return nil
	}
	size := uint64(cfg.Ingest.BatchSize)
	fmt.Fprintf(out, "%s: signed tree size %d verified; ingesting [%d, %d) in batches of up to %d\n", rec.Name, head.TreeSize, next, end, size)
	for first := next; first < end; {
		if stops.Soft.Err() != nil {
			return nil
		}
		last := min(first+size, end)
		_, err := w.Batch(stops.Hard, src, head, first, last)
		chains.Reset()
		if err != nil {
			return err
		}
		first = last
	}
	return nil
}

// head fetches and checks the signed head, against the last accepted head
// (by src) and against the committed tip (checkTip); a bad signature or an
// incident is refetched once after headRetryDelay, then written as an
// incident.
func (u *updateRun) head(ctx context.Context, src logsource.LogSource, log string, last *logsource.SignedHead, tip commit.LogTip, state string) (logsource.SignedHead, error) {
	get := func() (h logsource.SignedHead, err error) {
		err = fetch.Retry(ctx, fetch.Options{}, func(ctx context.Context) (err error) {
			h, err = src.Head(ctx)
			return err
		})
		if err == nil {
			err = checkTip(ctx, src, tip, h)
		}
		return h, err
	}
	h, err := get()
	if err == nil || !(errors.Is(err, logsource.ErrIncident) || errors.Is(err, merkle.ErrBadSignature)) {
		return h, err
	}
	select {
	case <-ctx.Done():
		return h, ctx.Err()
	case <-time.After(headRetryDelay):
	}
	h2, err2 := get()
	if err2 == nil {
		return h2, nil
	}
	dir := filepath.Join(state, "incidents", u.a.d.Now().UTC().Format("20060102T150405Z")+"_"+log+"_head")
	ev := map[string]any{"log": log, "first_error": err.Error(), "second_error": err2.Error(),
		"got_raw": base64.StdEncoding.EncodeToString(h2.Raw)}
	if last != nil {
		ev["last_accepted_raw"] = base64.StdEncoding.EncodeToString(last.Raw)
	}
	if tip.State != nil {
		root, _ := tip.State.Root()
		ev["committed_size"], ev["committed_root"] = tip.Next, hex.EncodeToString(root[:])
	}
	if werr := writeIncident(dir, ev); werr != nil {
		return h2, exitcode.With(exitcode.Verification, fmt.Errorf("%s: %w (the incident could not be written to %s: %v)", log, err2, dir, werr))
	}
	return h2, exitcode.With(exitcode.Verification, fmt.Errorf("%s: %w (incident written to %s)", log, err2, dir))
}

func writeIncident(dir string, ev map[string]any) error {
	b, err := json.MarshalIndent(ev, "", " ")
	if err != nil {
		return err
	}
	if err := fsutil.MkdirAllSync(dir, 0o755); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(dir, "incident.json"), b, 0o644)
}

// checkTip refuses a signed head that contradicts what is committed: fewer
// entries than the committed checkpoint, or a tree that does not extend the
// committed Merkle state (proven by a consistency proof). It runs on every
// head, so a vault without a stored head, or with nothing left to ingest,
// is still protected.
func checkTip(ctx context.Context, src logsource.LogSource, tip commit.LogTip, h logsource.SignedHead) error {
	if tip.State == nil {
		return nil
	}
	root, err := tip.State.Root()
	if err != nil {
		return err
	}
	switch {
	case h.TreeSize < tip.Next:
		return fmt.Errorf("%w: the signed head has %d entries, fewer than the %d already committed", logsource.ErrIncident, h.TreeSize, tip.Next)
	case h.TreeSize == tip.Next:
		if root != h.RootHash {
			return fmt.Errorf("%w: the signed head's root differs from the committed tree of %d entries", logsource.ErrIncident, tip.Next)
		}
		return nil
	}
	var proof [][32]byte
	if err := fetch.Retry(ctx, fetch.Options{}, func(ctx context.Context) (err error) {
		proof, err = src.ConsistencyProof(ctx, tip.Next, h.TreeSize)
		return err
	}); err != nil {
		return err
	}
	if err := merkle.VerifyConsistency(tip.Next, h.TreeSize, root, h.RootHash, proof); err != nil {
		return fmt.Errorf("%w: the signed head does not extend the committed tree of %d entries: %v", logsource.ErrIncident, tip.Next, err)
	}
	return nil
}

// ingestErr maps ingestion failures to spec §11.2 exit codes.
func ingestErr(err error) error {
	switch {
	case exitcode.Of(err) != exitcode.Error:
		return err
	case errors.Is(err, diskguard.ErrCap):
		return exitcode.With(exitcode.DiskCap, err)
	case errors.Is(err, volume.ErrVolume):
		return exitcode.With(exitcode.Volume, err)
	case errors.Is(err, ingest.ErrVerification), errors.Is(err, logsource.ErrIncident), errors.Is(err, merkle.ErrBadSignature),
		errors.Is(err, vault.ErrCorrupt), errors.Is(err, commit.ErrCorrupt), errors.Is(err, logsource.ErrBadHeadFile):
		return exitcode.With(exitcode.Verification, err)
	}
	return err
}
```

Replace `internal/ingest/writer.go` with:

```go
// Package ingest runs batches: it fetches a range of a log, verifies it
// against a pinned signed tree head, vaults new certificates, stages the
// source-layer Parquet files and commits through the protocol of spec §8.3.
package ingest

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

// Options configure a Writer. The caller holds the writer lock and has run
// the volume checks.
type Options struct {
	Root      string
	VaultDirs []string // absolute, in VAULT_ID order
	VaultUUID [16]byte
	Config    config.Config
	Guard     diskguard.Guard
	Fetch     fetch.Options // workers, rate and stall timeout from Config, plus test overrides
	Version   string
	Now       func() time.Time
	Out       io.Writer    // one line per batch and recovery action
	Hook      func(string) // crash points, tests only
	// CheckVolumes repeats the volume checks (spec §9.2) at every batch
	// preflight; a failure stops the batch before anything is written.
	CheckVolumes func() error

	// DictSamples is how many leaf certificates train dictionary 1 (20,000;
	// tests use fewer). Train defaults to vault.Train.
	DictSamples int
	Train       func(samples [][]byte, id uint64) ([]byte, error)
	// CanarySamples is how many rows and vault records the canary checks
	// per batch (default 64).
	CanarySamples int
}

// Writer is the single writer of a vault.
type Writer struct {
	o      Options
	paths  commit.Paths
	idx    *index.Index
	codec  *vault.Codec
	stager *dataset.Stager
	ids    *commit.IDs
	vw     *vault.Writer
	delta  *vault.DeltaCache
	dictID uint64

	trainTried bool
	cold       bool  // the delta cache was emptied by a stopped attempt
	broken     error // an abandon failed: no more batches (ErrAbandonFailed)
	spill      string

	committed []commit.Manifest
	tips      map[string]commit.LogTip
}

func (w *Writer) logf(format string, args ...any) {
	if w.o.Out != nil {
		fmt.Fprintf(w.o.Out, format+"\n", args...)
	}
}

// WriterSpillDir is the writer's DuckDB spill folder under tmp/ (spec §10.1
// gives readers tmp/duckdb-<pid>; there is only ever one writer).
const WriterSpillDir = "duckdb-writer"

// Open recovers the vault (spec §8.5) and prepares the writer: index,
// dictionaries, cert_id allocator, vault tail, delta cache warm-up and
// views.sql.
func Open(o Options) (*Writer, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.DictSamples == 0 {
		o.DictSamples = vault.TrainingSamples
	}
	if o.Train == nil {
		o.Train = vault.Train
	}
	if o.CanarySamples == 0 {
		o.CanarySamples = 64
	}
	w := &Writer{o: o, paths: commit.Paths{Root: o.Root}}
	ok := false
	defer func() {
		if !ok {
			w.Close()
		}
	}()
	var err error
	if w.idx, err = index.Open(filepath.Join(o.Root, "state", "pebble")); err != nil {
		return nil, err
	}
	if w.codec, err = vault.NewCodec(); err != nil {
		return nil, err
	}
	dicts, err := vault.LoadDicts(o.VaultDirs)
	if err != nil {
		return nil, err
	}
	for _, d := range dicts {
		if err := w.codec.AddDict(d.Manifest.ID, d.Content); err != nil {
			return nil, err
		}
		w.dictID = d.Manifest.ID
	}
	// The writer's DuckDB spill folder has a fixed name: the writer lock
	// makes it ours, so a killed writer's leftover is emptied here.
	// Readers' tmp/duckdb-<pid> folders are never touched (amendment A1 §7).
	w.spill = filepath.Join(o.Root, "tmp", WriterSpillDir)
	if left, _ := os.ReadDir(w.spill); len(left) > 0 {
		w.logf("recovery: emptied the writer's leftover DuckDB spill folder tmp/%s", WriterSpillDir)
	}
	if err := os.RemoveAll(w.spill); err != nil {
		return nil, err
	}
	if w.stager, err = dataset.NewStager(dataset.Options{TempDir: w.spill, MaxTempBytes: w.spillLimit()}); err != nil {
		return nil, err
	}
	rec, err := commit.Recover(commit.RecoverOptions{Paths: w.paths, VaultDirs: o.VaultDirs, VaultUUID: o.VaultUUID, Index: w.idx,
		Codec: w.codec, ChainIDs: w.stager.ChainIDs})
	if err != nil {
		return nil, err
	}
	for _, a := range rec.Actions {
		w.logf("recovery: %s", a)
	}
	w.committed, w.tips = rec.Committed, commit.Tips(rec.Committed)
	if w.ids, err = commit.LoadIDs(w.paths.StateDir(), rec.NextCertID, o.Hook); err != nil {
		return nil, err
	}
	if w.vw, err = vault.OpenWriter(w.vaultOptions(), w.codec, rec.Tail); err != nil {
		return nil, err
	}
	if err := w.warm(); err != nil {
		return nil, err
	}
	if _, err := dataset.WriteViews(o.Root); err != nil {
		return nil, err
	}
	ok = true
	return w, nil
}

func (w *Writer) vaultOptions() vault.Options {
	return vault.Options{Dirs: w.o.VaultDirs, VaultUUID: w.o.VaultUUID, SegmentSize: uint64(w.o.Config.Vault.SegmentSize),
		Check: w.o.Guard.Check, Hook: w.o.Hook, Now: w.o.Now}
}

// SpillBudget caps the writer's DuckDB spill. Spec §10.1 sets every DuckDB
// session's spill limit to the headroom below the cap minus 1 GiB, and
// amendment A1 §7 adds the limit to every batch's peak; together no batch
// could ever start. The writer therefore spills at most this budget, and
// the preflight counts it (Plan 2B decision). Plan 2's tables fit in memory.
const SpillBudget = 4 << 30

// spillLimit is the writer's max_temp_directory_size: the budget, or less
// when the headroom below the cap minus a 1 GiB margin is smaller, but at
// least 64 MiB.
func (w *Writer) spillLimit() uint64 {
	const margin, floor = 1 << 30, 64 << 20
	u, err := w.o.Guard.Stat(w.o.Root)
	if err != nil || u.Total == 0 {
		return floor
	}
	lim := uint64(w.o.Guard.Cap * float64(u.Total))
	if used := u.Used(); lim > used+margin+floor {
		return min(SpillBudget, lim-used-margin)
	}
	return floor
}

// warm refills the delta cache from the last delta.warm_batches committed
// batches (amendment A1 §5).
func (w *Writer) warm() error {
	if w.delta == nil {
		w.delta = vault.NewDeltaCache(w.o.Config.Ingest.DeltaLRUEntries)
	} else {
		w.delta.Reset() // reuse the cache's memory (207 MiB at the default size)
	}
	n := w.o.Config.Delta.WarmBatches
	var ranges []vault.Range
	for i := max(0, len(w.committed)-n); i < len(w.committed); i++ {
		ranges = append(ranges, vault.Range{Start: w.committed[i].Vault.Start, End: w.committed[i].Vault.End})
	}
	return vault.Warm(w.o.VaultDirs, w.codec, w.delta, ranges, leaf.PrecertIssuanceDigest)
}

// Next returns the first index of log not yet committed.
func (w *Writer) Next(log string) uint64 { return w.tips[log].Next }

// Tip returns log's committed position and Merkle state (State is nil when
// nothing of log is committed).
func (w *Writer) Tip(log string) commit.LogTip { return w.tips[log] }

// LastCommitSeq returns the highest commit_seq.
func (w *Writer) LastCommitSeq() uint64 {
	if len(w.committed) == 0 {
		return 0
	}
	return w.committed[len(w.committed)-1].CommitSeq
}

// Close releases every resource; it never commits anything. Closing twice
// is harmless.
func (w *Writer) Close() error {
	var errs []error
	if w.vw != nil {
		errs = append(errs, w.vw.Close())
		w.vw = nil
	}
	if w.stager != nil {
		errs = append(errs, w.stager.Close(), os.RemoveAll(w.spill))
		w.stager = nil
	}
	if w.codec != nil {
		w.codec.Close()
		w.codec = nil
	}
	if w.idx != nil {
		errs = append(errs, w.idx.Close())
		w.idx = nil
	}
	return errors.Join(errs...)
}

// ErrVerification wraps a batch that failed Merkle verification or the
// canary twice: an incident (spec §12, exit 5).
var ErrVerification = errors.New("batch failed verification twice")

// errRetry marks a verification or canary failure; the batch is refetched
// once. A Merkle failure carries the evidence an incident records (spec
// §12): our compact range before the batch, the root we computed at end,
// and the proof the log served.
type errRetry struct {
	err    error
	before *merkle.State
	root   [32]byte
	end    uint64
	proof  [][32]byte
}

func (e errRetry) Error() string { return e.err.Error() }
func (e errRetry) Unwrap() error { return e.err }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race ./internal/cli/ && go test -race -tags ctvault_dev ./internal/cli/`
Expected: PASS.

- [ ] **Step 5: Quality gate**

- [ ] **Step 6: Checkpoint.**

---

### Task C5: The SIGKILL crash suite

Spec §13.5 (named boundaries and invariants), amendment A1 §7 (recovery equivalence) and §9 (25 kills by default, 200+ with `nightly`).

**Files:**
- Modify: `internal/index/index.go`, `cmd/ctvault/guard_test.go` (bans `internal/vaulttest`)
- Create: `internal/vaulttest/vaulttest.go` (test-only), `internal/commit/crash_test.go`, `internal/commit/killloop_test.go`, `internal/commit/killloop_nightly_test.go`
- Test: `internal/index/index_test.go`

**Interfaces:**
- Produces:
  - `index.(*Index).EachCert(fn func(sha [32]byte, r Ref) error) error`
  - `vaulttest.Vault{Root, Dirs, UUID}` with `Committed`, `Assignments`, `CheckRecovered`, `Dump`, and `vaulttest.Diff`
- The harness:
  - **Child:** `TestCrashChild` runs only when `CTVAULT_CRASH_CHILD` names a JSON config. It ingests from a fake log and blocks on its kill point.
  - **Parent:** the parent SIGKILLs it, checks the invariants, and runs recovery.
  - **Random loop:** `TestRandomKillLoop` kills `killLoopRuns` times (25, or 200 with `-tags nightly`) after uniform random delays.
  - **Short mode:** both suites skip with `-short`.

- [ ] **Step 1: Write the tests and the test infrastructure**

Replace `internal/index/index_test.go` with:

```go
package index

import (
	"bytes"
	"crypto/sha256"
	"maps"
	"path/filepath"
	"testing"

	"github.com/4rji/ctvault/internal/vault"
)

func TestBatchSeesItsOwnWritesAndCommitsDurably(t *testing.T) {
	dir := t.TempDir()
	x, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	sha := [32]byte{1}
	ref := Ref{CertID: 1 << 40, Loc: vault.Loc{Segment: 3, Offset: 1 << 33, Len: 1500}}
	b := x.NewBatch()
	if _, ok, _ := b.Lookup(sha); ok {
		t.Fatal("empty index")
	}
	b.AddCert(sha, ref)
	if got, ok, err := b.Lookup(sha); err != nil || !ok || got != ref {
		t.Fatalf("a duplicate within the batch must be found: %+v %v %v", got, ok, err)
	}
	if _, ok, _ := x.Lookup(sha); ok {
		t.Fatal("nothing is visible before the commit point")
	}
	b.AddChain([32]byte{9})
	if has, _ := b.HasChain([32]byte{9}); !has {
		t.Fatal("a chain added in this batch is known")
	}
	b.SetApplied("argon2027h1", 7)
	if err := b.Commit(); err != nil {
		t.Fatal(err)
	}
	b.Close()
	x.Close()

	x, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	if got, ok, err := x.Lookup(sha); err != nil || !ok || got != ref {
		t.Fatalf("committed entry after reopen: %+v %v %v", got, ok, err)
	}
	if seq, err := x.Applied("argon2027h1"); err != nil || seq != 7 {
		t.Fatalf("applied/<log>: %d %v", seq, err)
	}
	if seq, _ := x.Applied("other"); seq != 0 {
		t.Fatal("a log never applied reports 0")
	}
	b2 := x.NewBatch()
	defer b2.Close()
	if has, _ := b2.HasChain([32]byte{9}); !has {
		t.Fatal("committed chains are remembered")
	}
}

func TestDiscardedBatchLeavesNothing(t *testing.T) {
	x, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	b := x.NewBatch()
	b.AddCert([32]byte{2}, Ref{CertID: 5})
	b.Close() // an abandoned batch
	if _, ok, _ := x.Lookup([32]byte{2}); ok {
		t.Fatal("an abandoned batch must not reach the index")
	}
}

func TestRefEncoding(t *testing.T) {
	r := Ref{CertID: 123456789, Loc: vault.Loc{Segment: 70000, Offset: 1<<40 + 5, Len: 1<<32 - 1}}
	got, err := decodeRef(encodeRef(r))
	if err != nil || got != r {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if _, err := decodeRef(append(encodeRef(r), 0)); err == nil {
		t.Fatal("trailing bytes are malformed")
	}
	if _, err := decodeRef([]byte{0x80}); err == nil {
		t.Fatal("a truncated varint is malformed")
	}
}

// TestEachCert lists every certificate entry in SHA-256 order, and only
// those: chain and applied keys are skipped.
func TestEachCert(t *testing.T) {
	x, err := Open(filepath.Join(t.TempDir(), "pebble"))
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	b := x.NewBatch()
	want := map[[32]byte]Ref{}
	for i := range 5 {
		sha := sha256.Sum256([]byte{byte(i)})
		r := Ref{CertID: uint64(i + 1), Loc: vault.Loc{Segment: 1, Offset: uint64(64 + 100*i), Len: 100}}
		b.AddCert(sha, r)
		want[sha] = r
	}
	b.AddChain(sha256.Sum256([]byte("chain")))
	b.SetApplied("fakelog", 3)
	if err := b.Commit(); err != nil {
		t.Fatal(err)
	}
	b.Close()
	got := map[[32]byte]Ref{}
	var prev [32]byte
	err = x.EachCert(func(sha [32]byte, r Ref) error {
		if bytes.Compare(sha[:], prev[:]) <= 0 {
			t.Fatalf("not in SHA-256 order: %x after %x", sha[:4], prev[:4])
		}
		prev, got[sha] = sha, r
		return nil
	})
	if err != nil || !maps.Equal(got, want) {
		t.Fatalf("EachCert: %v, %d entries, want %d", err, len(got), len(want))
	}
}
```

Create `internal/vaulttest/vaulttest.go`:

```go
// Package vaulttest checks a vault the way the crash suite needs (spec
// §13.5) and compares a recovered vault with a clean one (amendment A1 §7).
// It is test infrastructure: production binaries never import it.
package vaulttest

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	_ "github.com/duckdb/duckdb-go/v2" // the "duckdb" database/sql driver

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

// Vault is a vault root and its vault directories.
type Vault struct {
	Root string
	Dirs []string
	UUID [16]byte
}

// reader opens the vault's records with every dictionary loaded.
func (v Vault) reader(t testing.TB) *vault.Reader {
	t.Helper()
	c, err := vault.NewCodec()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	ds, err := vault.LoadDicts(v.Dirs)
	if err != nil {
		t.Fatalf("dictionaries: %v", err)
	}
	for _, d := range ds {
		if err := c.AddDict(d.Manifest.ID, d.Content); err != nil {
			t.Fatal(err)
		}
	}
	r, err := vault.OpenReader(v.Dirs, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

// record is a vault record with its certificate's SHA-256.
type record struct {
	loc    vault.Loc
	certID uint64
	sha    [32]byte
}

// scan reads the records in [from, to), resolving each to its SHA-256. A
// torn record ends the scan when torn is allowed.
func (v Vault) scan(t testing.TB, from, to vault.Tail, torn bool) []record {
	t.Helper()
	r := v.reader(t)
	var out []record
	err := vault.Scan(v.Dirs, from, to, func(loc vault.Loc, rec vault.Record) error {
		der, _, err := r.Read(loc)
		if err != nil {
			return err
		}
		out = append(out, record{loc, rec.CertID, sha256.Sum256(der)})
		return nil
	})
	if err != nil && !(torn && errors.Is(err, vault.ErrTorn)) {
		t.Fatalf("reading the vault: %v", err)
	}
	return out
}

// Assignments returns the cert_id and SHA-256 of every record in the
// segments, beyond the committed tail too, up to a torn record. Called after
// a kill and before recovery, it sees what the killed attempt assigned.
func (v Vault) Assignments(t testing.TB) map[uint64][32]byte {
	t.Helper()
	segs, err := vault.FindSegments(v.Dirs)
	if err != nil {
		t.Fatal(err)
	}
	out := map[uint64][32]byte{}
	if len(segs) == 0 {
		return out
	}
	last := slices.Max(slices.Collect(maps.Keys(segs)))
	for _, rec := range v.scan(t, vault.Tail{}, vault.Tail{Segment: last, Offset: math.MaxInt64}, true) {
		if prev, dup := out[rec.certID]; dup && prev != rec.sha {
			t.Fatalf("cert_id %d holds two different certificates in one vault", rec.certID)
		}
		out[rec.certID] = rec.sha
	}
	return out
}

func fileSHA256(t testing.TB, p string) string {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Committed is what a reader snapshot sees: every directory under
// dataset/log=*/ must be a committed batch whose files match _COMMIT.json
// byte for byte, so no partial batch is ever visible. It returns each
// batch directory's _COMMIT.json.
func (v Vault) Committed(t testing.TB) map[string][]byte {
	t.Helper()
	ms, err := commit.ListCommitted(v.Root)
	if err != nil {
		t.Fatalf("committed batches: %v", err)
	}
	paths := commit.Paths{Root: v.Root}
	out := map[string][]byte{}
	for _, m := range ms {
		dir := paths.BatchDir(m.ID())
		for name, fi := range m.Files {
			if got := fileSHA256(t, filepath.Join(dir, name)); got != fi.SHA256 {
				t.Fatalf("%s/%s does not match its checksum", dir, name)
			}
		}
		b, err := os.ReadFile(filepath.Join(dir, commit.ManifestFile))
		if err != nil {
			t.Fatal(err)
		}
		out[dir] = b
	}
	logs, _ := filepath.Glob(filepath.Join(v.Root, "dataset", "*", "*"))
	for _, d := range logs {
		if _, ok := out[d]; !ok {
			t.Fatalf("%s is visible under dataset/ but is not a committed batch", d)
		}
	}
	return out
}

// CheckRecovered asserts spec §13.5's invariants on a vault whose writer
// has opened (recovered) and closed it:
//   - committed batches are contiguous and every file matches its checksum;
//   - the vault holds nothing beyond the committed tail, and its segments
//     are intact;
//   - every committed record has a unique cert_id and a unique certificate;
//   - Pebble agrees with the vault, and applied/<log> is each log's last
//     commit_seq;
//   - each batch's Merkle state equals a recomputation from entries.parquet;
//   - no intent remains, and tmp/ holds only empty stage/ and rebuild/.
func (v Vault) CheckRecovered(t testing.TB) {
	t.Helper()
	v.Committed(t)
	ms, _ := commit.ListCommitted(v.Root)
	var tail vault.Tail
	if len(ms) > 0 {
		tail = ms[len(ms)-1].Vault.End
	}
	if u, err := vault.InspectTail(v.Dirs, tail); err != nil || u.Bytes != 0 {
		t.Fatalf("data beyond the committed tail after recovery: %+v, %v", u, err)
	}
	if err := vault.CheckSegments(v.Dirs, v.UUID, tail); err != nil {
		t.Fatal(err)
	}
	refs := map[[32]byte]index.Ref{}
	ids := map[uint64]bool{}
	for _, rec := range v.scan(t, vault.Tail{}, tail, false) {
		if ids[rec.certID] {
			t.Fatalf("cert_id %d is committed twice", rec.certID)
		}
		if _, dup := refs[rec.sha]; dup {
			t.Fatalf("certificate %x is vaulted twice", rec.sha[:8])
		}
		ids[rec.certID], refs[rec.sha] = true, index.Ref{CertID: rec.certID, Loc: rec.loc}
	}

	idx, err := index.Open(filepath.Join(v.Root, "state", "pebble"))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	n := 0
	err = idx.EachCert(func(sha [32]byte, r index.Ref) error {
		if want, ok := refs[sha]; !ok || want != r {
			return fmt.Errorf("pebble has %x → %+v, the vault %+v (%v)", sha[:8], r, want, ok)
		}
		n++
		return nil
	})
	if err != nil || n != len(refs) {
		t.Fatalf("pebble and the vault disagree: %v (%d index entries, %d records)", err, n, len(refs))
	}
	last := map[string]uint64{}
	for _, m := range ms {
		last[m.Log] = m.CommitSeq
	}
	if applied, err := idx.AppliedLogs(); err != nil || !maps.Equal(applied, last) {
		t.Fatalf("applied %v, want %v (%v)", applied, last, err)
	}

	db := duck(t)
	states := map[string]*merkle.State{}
	paths := commit.Paths{Root: v.Root}
	for _, m := range ms {
		st, ok := states[m.Log]
		if !ok {
			st = merkle.NewState()
			states[m.Log] = st
		}
		for i, e := range entries(t, db, filepath.Join(paths.BatchDir(m.ID()), dataset.EntriesFile)) {
			if e.idx != m.First+uint64(i) {
				t.Fatalf("batch %s: row %d has index %d", m.BatchID, i, e.idx)
			}
			st.Append(e.leafHash)
		}
		want, _ := m.MerkleAfter.Root()
		if got, _ := st.Root(); got != want || st.Size() != m.Last+1 {
			t.Fatalf("batch %s: the Merkle state recomputed from entries.parquet differs from merkle_after", m.BatchID)
		}
	}

	if left, _ := os.ReadDir(filepath.Join(v.Root, "state", "intent")); len(left) != 0 {
		t.Fatalf("intents left after recovery: %v", left)
	}
	var tmp []string
	filepath.WalkDir(filepath.Join(v.Root, "tmp"), func(p string, d os.DirEntry, err error) error {
		if rel, _ := filepath.Rel(v.Root, p); err == nil && rel != "tmp" {
			tmp = append(tmp, rel)
		}
		return nil
	})
	if !slices.Equal(tmp, []string{"tmp/rebuild", "tmp/stage"}) {
		t.Fatalf("tmp/ after recovery: %v", tmp)
	}
}

func duck(t testing.TB) *sql.DB {
	t.Helper()
	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

type row struct {
	idx                uint64
	ts                 sql.Null[int64]
	typ                string
	certID             sql.Null[uint64]
	leafHash           [32]byte
	ikey, ikh, chainID []byte
	leafErr            sql.Null[string]
}

func entries(t testing.TB, db *sql.DB, path string) []row {
	t.Helper()
	rs, err := db.Query(`SELECT idx, epoch_ms(ct_ts), entry_type, cert_id, leaf_hash, issuance_key, issuer_key_hash, chain_id, leaf_error
		FROM read_parquet(` + quote(path) + `) ORDER BY idx`)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	var out []row
	for rs.Next() {
		var r row
		var lh []byte
		if err := rs.Scan(&r.idx, &r.ts, &r.typ, &r.certID, &lh, &r.ikey, &r.ikh, &r.chainID, &r.leafErr); err != nil {
			t.Fatal(err)
		}
		copy(r.leafHash[:], lh)
		out = append(out, r)
	}
	if err := rs.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// Entry is one log entry's content without internal IDs: certificates and
// chains are given by SHA-256 (hex), and NULL fields are empty.
type Entry struct {
	Idx           uint64
	LeafHash      string
	Timestamp     string // milliseconds, "" when NULL
	Type          string
	IssuanceKey   string
	IssuerKeyHash string
	LeafError     string
	Cert          string
	Chain         []string
}

// Dump returns every committed entry by log, in index order. A recovered
// ingest must equal a clean one on all of it; only cert_id and chain_id may
// differ (amendment A1 §7). Dump also checks that every reference resolves:
// each cert_id to one vault record, each chain_id to positions 0..n-1
// written by exactly one batch, and every committed record is referenced.
func (v Vault) Dump(t testing.TB) map[string][]Entry {
	t.Helper()
	ms, err := commit.ListCommitted(v.Root)
	if err != nil {
		t.Fatal(err)
	}
	var tail vault.Tail
	if len(ms) > 0 {
		tail = ms[len(ms)-1].Vault.End
	}
	certs := map[uint64]string{}
	for _, rec := range v.scan(t, vault.Tail{}, tail, false) {
		certs[rec.certID] = hex.EncodeToString(rec.sha[:])
	}
	used := map[uint64]bool{}
	cert := func(id uint64) string {
		s, ok := certs[id]
		if !ok {
			t.Fatalf("cert_id %d is referenced but not in the committed vault", id)
		}
		used[id] = true
		return s
	}

	db := duck(t)
	paths := commit.Paths{Root: v.Root}
	chains := map[string][]uint64{}
	for _, m := range ms {
		rs, err := db.Query(`SELECT chain_id, position, cert_id FROM read_parquet(` + quote(filepath.Join(paths.BatchDir(m.ID()), dataset.ChainsFile)) + `) ORDER BY chain_id, position`)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for rs.Next() {
			var id []byte
			var pos uint16
			var c uint64
			if err := rs.Scan(&id, &pos, &c); err != nil {
				t.Fatal(err)
			}
			k := string(id)
			if !seen[k] && len(chains[k]) > 0 {
				t.Fatalf("chain %x is written by two batches", id[:4])
			}
			if seen[k] = true; int(pos) != len(chains[k]) {
				t.Fatalf("chain %x: position %d out of order", id[:4], pos)
			}
			chains[k] = append(chains[k], c)
		}
		rs.Close()
	}

	out := map[string][]Entry{}
	for _, m := range ms {
		for _, r := range entries(t, db, filepath.Join(paths.BatchDir(m.ID()), dataset.EntriesFile)) {
			e := Entry{Idx: r.idx, LeafHash: hex.EncodeToString(r.leafHash[:]), Type: r.typ,
				IssuanceKey: hex.EncodeToString(r.ikey), IssuerKeyHash: hex.EncodeToString(r.ikh), LeafError: r.leafErr.V}
			if r.ts.Valid {
				e.Timestamp = fmt.Sprint(r.ts.V)
			}
			if r.certID.Valid {
				e.Cert = cert(r.certID.V)
			}
			if r.chainID != nil {
				ids, ok := chains[string(r.chainID)]
				if !ok {
					t.Fatalf("entry %d: chain %x has no chains.parquet rows", r.idx, r.chainID[:4])
				}
				e.Chain = []string{}
				for _, id := range ids {
					e.Chain = append(e.Chain, cert(id))
				}
			}
			out[m.Log] = append(out[m.Log], e)
		}
	}
	for id := range certs {
		if !used[id] {
			t.Fatalf("committed record cert_id %d is referenced by no entry or chain", id)
		}
	}
	return out
}

// Diff describes the first difference between two dumps, "" if equal.
func Diff(got, want map[string][]Entry) string {
	for _, log := range slices.Sorted(maps.Keys(want)) {
		g, w := got[log], want[log]
		for i := range min(len(g), len(w)) {
			if a, b := fmt.Sprintf("%+v", g[i]), fmt.Sprintf("%+v", w[i]); a != b {
				return fmt.Sprintf("log %s entry %d:\n got  %s\n want %s", log, w[i].Idx, a, b)
			}
		}
		if len(g) != len(w) {
			return fmt.Sprintf("log %s: %d entries, want %d", log, len(g), len(w))
		}
	}
	if len(got) != len(want) {
		return fmt.Sprintf("%d logs, want %d", len(got), len(want))
	}
	return ""
}
```

Create `internal/commit/killloop_test.go`:

```go
//go:build !nightly

package commit_test

// killLoopRuns is the random kill loop's length in the normal suite
// (amendment A1 §9); -tags nightly runs 200.
const killLoopRuns = 25
```

Create `internal/commit/killloop_nightly_test.go`:

```go
//go:build nightly

package commit_test

// killLoopRuns is the nightly random kill loop's length (spec §13.5: 200
// or more).
const killLoopRuns = 200
```

Create `internal/commit/crash_test.go`:

```go
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
	w, err := ingest.Open(options(c.Root, hook))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
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
	t    *testing.T
	v    vaulttest.Vault
	cfg  crashConfig
	ids  map[uint64][32]byte // every cert_id assignment seen, over all attempts
	seen map[string][]byte   // every committed batch's _COMMIT.json
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
		ids: map[uint64][32]byte{}, seen: map[string][]byte{}}
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
	for id, sha := range r.v.Assignments(t) {
		if prev, ok := r.ids[id]; ok && prev != sha {
			t.Fatalf("cert_id %d was reused for a different certificate", id)
		}
		r.ids[id] = sha
	}
	w, err := ingest.Open(options(r.v.Root, nil))
	if err != nil {
		t.Fatalf("recovery: %v", err)
	}
	w.Close()
	r.v.CheckRecovered(t)
}

// clean ingests the whole log in a child that is never killed and returns
// its content and how long the child took.
func clean(t *testing.T, l *ctlogtest.Log, end, batch uint64) (map[string][]vaulttest.Entry, time.Duration) {
	t.Helper()
	r := newCrashRun(t, l, end, batch)
	start := time.Now()
	if r.child("", 0, 0) {
		t.Fatal("the clean child was killed")
	}
	took := time.Since(start)
	r.restart()
	return r.v.Dump(t), took
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
```

Replace `cmd/ctvault/guard_test.go` with:

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
	banned := []string{"/internal/volume/volumetest", "/internal/ctlogtest", "/internal/sampletest", "/internal/sample", "/internal/vaulttest"}
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
		// The _dev.go naming rule is CTVault's own; third-party packages
		// (prometheus/procfs's net_dev.go, via Pebble) may use the suffix.
		if !strings.HasPrefix(p.ImportPath, "github.com/4rji/ctvault/") {
			continue
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

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/index/ ./internal/commit/`
Expected: FAIL with `x.EachCert undefined (type *Index has no field or method EachCert)` in `internal/index`, and `idx.EachCert undefined` in `internal/vaulttest`.

- [ ] **Step 3: Implement**

Replace `internal/index/index.go` with:

```go
// Package index is the writer-private Pebble database (spec §6.3): it maps
// each vaulted certificate's SHA-256 to its cert_id and vault location for
// deduplication, remembers which chains were already written, and records
// the last commit_seq applied per log. Readers never open it (D18), and it
// is rebuildable from the vault.
package index

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/cockroachdb/pebble/v2"

	"github.com/4rji/ctvault/internal/vault"
)

// Key prefixes. "ch/" (chains already written to chains.parquet) is new in
// Plan 2B; it is rebuildable from the committed chains.parquet files.
const (
	prefixCert    = "c/"
	prefixChain   = "ch/"
	prefixApplied = "applied/"
)

// Ref is a vaulted certificate.
type Ref struct {
	CertID uint64
	Loc    vault.Loc
}

func certKey(sha [32]byte) []byte  { return append([]byte(prefixCert), sha[:]...) }
func chainKey(id [32]byte) []byte  { return append([]byte(prefixChain), id[:]...) }
func appliedKey(log string) []byte { return []byte(prefixApplied + log) }

func encodeRef(r Ref) []byte {
	b := binary.AppendUvarint(nil, r.CertID)
	b = binary.AppendUvarint(b, r.Loc.Segment)
	b = binary.AppendUvarint(b, r.Loc.Offset)
	return binary.AppendUvarint(b, uint64(r.Loc.Len))
}

func decodeRef(b []byte) (Ref, error) {
	var vals [4]uint64
	for i := range vals {
		v, n := binary.Uvarint(b)
		if n <= 0 {
			return Ref{}, errors.New("index: malformed certificate entry")
		}
		vals[i], b = v, b[n:]
	}
	if len(b) != 0 || vals[3] > 1<<32-1 {
		return Ref{}, errors.New("index: malformed certificate entry")
	}
	return Ref{CertID: vals[0], Loc: vault.Loc{Segment: vals[1], Offset: vals[2], Len: uint32(vals[3])}}, nil
}

// quiet drops Pebble's informational log lines ("Found 0 WALs") but keeps
// its fatal errors.
type quiet struct{}

func (quiet) Infof(string, ...any)  {}
func (quiet) Errorf(string, ...any) {}
func (quiet) Fatalf(format string, args ...any) {
	panic(fmt.Sprintf(format, args...))
}

// Index is an open Pebble database.
type Index struct {
	db *pebble.DB
}

// Open opens (or creates) the database in dir (state/pebble).
func Open(dir string) (*Index, error) {
	db, err := pebble.Open(dir, &pebble.Options{Logger: quiet{}})
	if err != nil {
		return nil, fmt.Errorf("opening index %s: %w", dir, err)
	}
	return &Index{db: db}, nil
}

// Close closes the database.
func (x *Index) Close() error { return x.db.Close() }

func lookup(get func([]byte) ([]byte, io.Closer, error), sha [32]byte) (Ref, bool, error) {
	v, cl, err := get(certKey(sha))
	if errors.Is(err, pebble.ErrNotFound) {
		return Ref{}, false, nil
	}
	if err != nil {
		return Ref{}, false, err
	}
	defer cl.Close()
	r, err := decodeRef(v)
	return r, err == nil, err
}

// Lookup finds a committed certificate.
func (x *Index) Lookup(sha [32]byte) (Ref, bool, error) {
	return lookup(func(k []byte) ([]byte, io.Closer, error) { return x.db.Get(k) }, sha)
}

// Applied returns the last commit_seq applied for log, 0 if none.
func (x *Index) Applied(log string) (uint64, error) {
	v, cl, err := x.db.Get(appliedKey(log))
	if errors.Is(err, pebble.ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer cl.Close()
	n, k := binary.Uvarint(v)
	if k <= 0 {
		return 0, errors.New("index: malformed applied entry")
	}
	return n, nil
}

// AppliedLogs returns the last commit_seq applied for every log.
func (x *Index) AppliedLogs() (map[string]uint64, error) {
	it, err := x.db.NewIter(&pebble.IterOptions{LowerBound: []byte(prefixApplied), UpperBound: []byte(prefixApplied + "\xff")})
	if err != nil {
		return nil, err
	}
	defer it.Close()
	out := map[string]uint64{}
	for it.First(); it.Valid(); it.Next() {
		n, k := binary.Uvarint(it.Value())
		if k <= 0 {
			return nil, errors.New("index: malformed applied entry")
		}
		out[string(it.Key()[len(prefixApplied):])] = n
	}
	return out, it.Error()
}

// EachCert calls fn for every vaulted certificate, in SHA-256 order (for
// checks that compare the index with the vault).
func (x *Index) EachCert(fn func(sha [32]byte, r Ref) error) error {
	upper := []byte(prefixCert)
	upper[len(upper)-1]++ // "c0": just past every "c/" key, before "ch/"
	it, err := x.db.NewIter(&pebble.IterOptions{LowerBound: []byte(prefixCert), UpperBound: upper})
	if err != nil {
		return err
	}
	defer it.Close()
	for it.First(); it.Valid(); it.Next() {
		k := it.Key()
		if len(k) != len(prefixCert)+32 {
			return errors.New("index: malformed certificate key")
		}
		r, err := decodeRef(it.Value())
		if err != nil {
			return err
		}
		var sha [32]byte
		copy(sha[:], k[len(prefixCert):])
		if err := fn(sha, r); err != nil {
			return err
		}
	}
	return it.Error()
}

// Batch holds one batch's index writes in memory until the commit point
// (spec §6.3: "an in-memory indexed batch until commit, which also catches
// duplicates within a batch").
type Batch struct {
	b *pebble.Batch
}

// NewBatch starts an indexed batch.
func (x *Index) NewBatch() *Batch { return &Batch{b: x.db.NewIndexedBatch()} }

// Lookup sees the batch's own writes over the committed database.
func (b *Batch) Lookup(sha [32]byte) (Ref, bool, error) {
	return lookup(func(k []byte) ([]byte, io.Closer, error) { return b.b.Get(k) }, sha)
}

// AddCert records a newly vaulted certificate.
func (b *Batch) AddCert(sha [32]byte, r Ref) error { return b.b.Set(certKey(sha), encodeRef(r), nil) }

// HasChain reports whether chain id was written before or in this batch.
func (b *Batch) HasChain(id [32]byte) (bool, error) {
	_, cl, err := b.b.Get(chainKey(id))
	if errors.Is(err, pebble.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	cl.Close()
	return true, nil
}

// AddChain records a chain written to this batch's chains.parquet.
func (b *Batch) AddChain(id [32]byte) error { return b.b.Set(chainKey(id), nil, nil) }

// SetApplied records the batch's commit_seq for its log (spec §8.3 P9).
func (b *Batch) SetApplied(log string, seq uint64) error {
	return b.b.Set(appliedKey(log), binary.AppendUvarint(nil, seq), nil)
}

// Commit applies the batch durably (Sync = true).
func (b *Batch) Commit() error { return b.b.Commit(pebble.Sync) }

// Close discards an uncommitted batch, or releases a committed one.
func (b *Batch) Close() error { return b.b.Close() }
```

- [ ] **Step 4: Run the suite**

Run: `go test -v -run 'CrashAtEvery|RandomKill' ./internal/commit/`
Expected: PASS. Measured without `-race`:
- the 15 boundaries take about 20 s
- the 25-kill loop takes about 16 s (17 kills and 9 complete ingests, compared with a clean one)
- with `-race`, the whole `commit` package takes about 150 s

**Check that the suite can fail.** In a scratch copy, make recovery skip the Pebble catch-up:

```go
if err := error(nil); err != nil { // was: catchUp(o, committed, &r)
```

`P8.after_rename` and `P9.before_pebble` must then fail with "pebble and the vault disagree". Make recovery leave `tmp/stage` behind instead, and `P6`, `P7` and `P8.before_rename` must fail on `tmp/` leftovers.

- [ ] **Step 5: Quality gate**

- [ ] **Step 6: Checkpoint.**

---

### Task C6: Two recovery bugs the suites found

Spec §8.5–8.6 (IDs are never reused) and §13.5 (no leftovers). Both bugs were found while writing this plan:
- **Leftover temp files.** The random kill loop (Task C5) caught a writer killed inside `fsutil.WriteFileAtomic`, which left `.<name>.tmp-<n>` in `state/intent/`. Recovery never removed it.
- **Reused `cert_id`s.** The real-data recovery test (Task C8) showed that `cert_id`s did not skip after a crash. Recovery skipped them only in memory, and deleted the evidence. If the writer that recovered stopped before committing, the next start handed the truncated records' IDs out again.

The crash suite missed the second bug. A rerun assigns the same IDs to the same certificates, and the suite only flagged an ID reused for a different certificate. It now tracks every `cert_id` recovery truncates, and fails if one is ever committed later.

**Files:**
- Modify: `internal/fsutil/fsutil.go`, `internal/commit/recover.go`
- Tests: `internal/fsutil/fsutil_test.go`, `internal/commit/protocol_test.go`, `internal/commit/crash_test.go`, `internal/vaulttest/vaulttest.go`

**Interfaces:**
- Produces:
  - `fsutil.IsAtomicTemp(name string) bool`
  - `vaulttest.(Vault).BeyondTail(t) map[uint64][32]byte`
- Changes in `commit.Recover`:
  - Interrupted atomic writes are removed from the root, `state/` and its folders except Pebble's, and each vault folder's `dict/`. Each removal is logged as a recovery action.
  - An uncommitted batch's intent is kept, marked `abandoned`, until a later commit runs `ClearAbandoned`. Every start until then resumes at `ID_FLOOR`.
  - The 2B tests that expected the intent to be removed now expect it to be kept, abandoned.

- [ ] **Step 1: Write the failing tests**

Replace `internal/fsutil/fsutil_test.go` with:

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

// TestIsAtomicTemp: only the names WriteFileAtomic creates match.
func TestIsAtomicTemp(t *testing.T) {
	dir := t.TempDir()
	f, err := os.CreateTemp(dir, "."+"ID_FLOOR"+".tmp-*") // the pattern WriteFileAtomic uses
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	for name, want := range map[string]bool{
		filepath.Base(f.Name()): true, ".views.sql.tmp-12": true, ".a.json.tmp-0": true,
		"views.sql": false, ".tmp-12": false, ".x.tmp-": false, ".x.tmp-12a": false, "x.tmp-12": false, ".hidden": false,
	} {
		if IsAtomicTemp(name) != want {
			t.Errorf("IsAtomicTemp(%q) = %v", name, !want)
		}
	}
}
```

Replace `internal/commit/protocol_test.go` with:

```go
package commit

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

// env is a vault root with the writer's resources.
type env struct {
	t      *testing.T
	p      Paths
	dirs   []string
	idx    *index.Index
	codec  *vault.Codec
	stager *dataset.Stager
	certs  [][]byte
	hooks  []string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"state/intent", "state/logs", "vault/segments", "vault/dict", "dataset", "tmp/stage", "tmp/rebuild"} {
		os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	e := &env{t: t, p: Paths{Root: root}, dirs: []string{filepath.Join(root, "vault")}}
	var err error
	if e.idx, err = index.Open(filepath.Join(root, "state", "pebble")); err != nil {
		t.Fatal(err)
	}
	if e.codec, err = vault.NewCodec(); err != nil {
		t.Fatal(err)
	}
	if e.stager, err = dataset.NewStager(dataset.Options{TempDir: filepath.Join(root, "tmp", "duckdb-test"), MaxTempBytes: 1 << 30}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.stager.Close(); e.codec.Close(); e.idx.Close() })
	g, _ := ctlogtest.NewGenerator()
	es, _ := g.Entries(60)
	for _, x := range es {
		e.certs = append(e.certs, x.CertDER)
	}
	return e
}

func (e *env) hook(p string) { e.hooks = append(e.hooks, p) }

func (e *env) recover() Recovered {
	e.t.Helper()
	r, err := Recover(RecoverOptions{Paths: e.p, VaultDirs: e.dirs, Index: e.idx, Codec: e.codec, ChainIDs: e.stager.ChainIDs})
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

// batch runs one batch of n entries through the protocol up to stopAfter:
// "intent", "vault" (records synced), "stage", "publish", "pebble" or "done".
func (e *env) batch(first, n uint64, ids *IDs, seq uint64, before *merkle.State, tail vault.Tail, stopAfter string) (Manifest, *merkle.State, vault.Tail) {
	e.t.Helper()
	t := e.t
	id := BatchID{Log: "fakelog", First: first, Last: first + n - 1}
	in := Intent{BatchID: id.String(), Log: id.Log, First: id.First, Last: id.Last, VaultTail: tail,
		NextCertID: ids.Peek(), MerkleBefore: before, StartedAt: time.Unix(1, 0).UTC()}
	if err := WriteIntent(e.p, in, e.hook); err != nil {
		t.Fatal(err)
	}
	if stopAfter == "intent" {
		return Manifest{}, nil, tail
	}
	w, err := vault.OpenWriter(vault.Options{Dirs: e.dirs, SegmentSize: 8 << 10}, e.codec, tail)
	if err != nil {
		t.Fatal(err)
	}
	state := before.Clone()
	var rows []dataset.EntryRow
	var chains []dataset.ChainRow
	pb := e.idx.NewBatch()
	defer pb.Close()
	firstID := ids.Peek()
	for i := range n {
		der := e.certs[(first+i)%uint64(len(e.certs))]
		cid, _ := ids.Next()
		loc, err := w.AppendCert(vault.KindLeaf, cid, der, 0)
		if err != nil {
			t.Fatal(err)
		}
		pb.AddCert(sha256.Sum256(der), index.Ref{CertID: cid, Loc: loc})
		lh := merkle.LeafHash([]byte{byte(first + i)})
		state.Append(lh)
		rows = append(rows, dataset.EntryRow{Idx: first + i, CTTimestamp: 1, EntryType: "x509", CertID: cid, LeafHash: lh})
	}
	chainID := sha256.Sum256([]byte{byte(first)})
	chains = append(chains, dataset.ChainRow{ChainID: chainID, Position: 0, CertID: firstID})
	pb.AddChain(chainID)
	w.Sync()
	end := w.Tail()
	w.Close()
	if stopAfter == "vault" {
		return Manifest{}, state, end
	}
	files, err := e.stager.Stage(context.Background(), e.p.StageDir(id), rows, chains)
	if err != nil {
		t.Fatal(err)
	}
	if stopAfter == "stage" {
		return Manifest{}, state, end
	}
	m := Manifest{Format: ManifestFormat, CommitSeq: seq, BatchID: id.String(), Log: id.Log, First: id.First, Last: id.Last,
		MerkleAfter: state, Verified: Verified{Method: "root_equals_sth"}, CertIDRange: &[2]uint64{firstID, ids.Peek() - 1},
		NextCertID: ids.Peek(), Vault: Span{Start: tail, End: end}, Builders: map[string]int{}, Files: files,
		Counts: Counts{Entries: int(n), NewCerts: int(n)}, CTVaultVersion: "test", CommittedAt: time.Unix(2, 0).UTC()}
	if err := Publish(e.p, m, e.hook); err != nil {
		t.Fatal(err)
	}
	if stopAfter == "publish" {
		return m, state, end
	}
	pb.SetApplied(id.Log, seq)
	if err := pb.Commit(); err != nil {
		t.Fatal(err)
	}
	if stopAfter == "pebble" {
		return m, state, end
	}
	if err := RemoveIntent(e.p, id, e.hook); err != nil {
		t.Fatal(err)
	}
	return m, state, end
}

func (e *env) ids(next uint64) *IDs {
	ids, err := LoadIDs(e.p.StateDir(), next, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	return ids
}

func TestCleanCommitAndHookOrder(t *testing.T) {
	e := newEnv(t)
	m, _, end := e.batch(0, 10, e.ids(1), 1, merkle.NewState(), vault.Tail{}, "done")
	want := []string{HookAfterIntent, HookAfterManifest, HookBeforeRename, HookAfterRename, HookBeforeIntentDelete}
	if !slices.Equal(e.hooks, want) {
		t.Fatalf("hooks %v, want %v", e.hooks, want)
	}
	r := e.recover()
	if r.Crashed || r.Tail != end || r.NextCertID != m.NextCertID || len(r.Committed) != 1 || len(r.Actions) != 0 {
		t.Fatalf("a clean vault needs nothing: %+v", r)
	}
	if _, err := os.Stat(e.p.StageDir(m.ID())); !os.IsNotExist(err) {
		t.Fatal("the staging directory is gone after the commit point")
	}
	if err := Publish(e.p, m, nil); err == nil {
		t.Fatal("a committed batch directory is never replaced")
	}
}

// TestRecoverAfterCrashBeforeCommit covers spec §8.5 rows 1-2: vault data
// beyond the committed tail, and an intent whose batch never committed.
func TestRecoverAfterCrashBeforeCommit(t *testing.T) {
	e := newEnv(t)
	ids := e.ids(1)
	m1, s1, end1 := e.batch(0, 10, ids, 1, merkle.NewState(), vault.Tail{}, "done")
	e.batch(10, 15, ids, 2, s1, end1, "stage") // crash after staging: vault data, intent and staging remain
	r := e.recover()
	if !r.Crashed || r.Tail != end1 || len(r.Committed) != 1 {
		t.Fatalf("recovery: %+v", r)
	}
	floor, _ := ReadFloor(e.p.StateDir())
	if r.NextCertID != floor || floor <= 25 {
		t.Fatalf("IDs 11-25 were assigned by the lost attempt; allocation must resume at the floor %d, got %d", floor, r.NextCertID)
	}
	if u, _ := vault.InspectTail(e.dirs, end1); u.Bytes != 0 {
		t.Fatal("uncommitted vault data must be truncated")
	}
	if left, _ := ReadIntents(e.p); len(left) != 1 || !left[0].Abandoned {
		t.Fatalf("the intent must stay, marked abandoned, until a later commit: %+v", left)
	}
	if left, _ := os.ReadDir(filepath.Join(e.p.Root, "tmp", "stage")); len(left) != 0 {
		t.Fatal("the staging directory must be removed")
	}
	// The vault keeps working from the committed tail.
	ids2 := e.ids(r.NextCertID)
	m2, _, _ := e.batch(10, 5, ids2, 2, m1.MerkleAfter, r.Tail, "done")
	if m2.CertIDRange[0] != floor {
		t.Fatalf("the retried batch starts at the floor: %v", m2.CertIDRange)
	}
	if err := ClearAbandoned(e.p); err != nil {
		t.Fatal(err)
	}
	if left, _ := ReadIntents(e.p); len(left) != 0 {
		t.Fatalf("a later commit clears the abandoned intent: %+v", left)
	}
}

// TestCrashSkipSurvivesARestartWithoutACommit: the writer that recovers may
// stop before committing anything (update finds nothing to do, a Ctrl-C).
// The next start must still resume at ID_FLOOR, or it would hand out again
// the cert_ids of the records recovery truncated (spec §8.6).
func TestCrashSkipSurvivesARestartWithoutACommit(t *testing.T) {
	e := newEnv(t)
	ids := e.ids(1)
	_, s1, end1 := e.batch(0, 10, ids, 1, merkle.NewState(), vault.Tail{}, "done")
	e.batch(10, 15, ids, 2, s1, end1, "vault") // cert_ids 11-25 written past the tail, then a kill
	e.recover()
	floor, _ := ReadFloor(e.p.StateDir())
	r := e.recover() // the second start, with nothing committed in between
	if !r.Crashed || r.NextCertID != floor {
		t.Fatalf("the second start resumes at %d, want the floor %d (crashed=%v)", r.NextCertID, floor, r.Crashed)
	}
}

// TestRecoverFinishesACommittedBatch covers spec §8.5 rows 3-4: a crash
// between the commit point and the Pebble apply.
func TestRecoverFinishesACommittedBatch(t *testing.T) {
	e := newEnv(t)
	ids := e.ids(1)
	m1, s1, end1 := e.batch(0, 10, ids, 1, merkle.NewState(), vault.Tail{}, "done")
	m2, _, end2 := e.batch(10, 8, ids, 2, s1, end1, "publish")
	if seq, _ := e.idx.Applied("fakelog"); seq != 1 {
		t.Fatalf("Pebble lags: applied %d", seq)
	}
	r := e.recover()
	if r.Crashed || r.Tail != end2 || r.NextCertID != m2.NextCertID || len(r.Committed) != 2 {
		t.Fatalf("a committed batch is kept as is: %+v", r)
	}
	if seq, _ := e.idx.Applied("fakelog"); seq != 2 {
		t.Fatalf("Pebble must catch up to commit_seq 2, got %d", seq)
	}
	for i := range 8 {
		der := e.certs[(10+i)%len(e.certs)]
		ref, ok, err := e.idx.Lookup(sha256.Sum256(der))
		if err != nil || !ok || ref.CertID != m2.CertIDRange[0]+uint64(i) {
			t.Fatalf("certificate %d of the batch must be re-indexed: %+v %v %v", i, ref, ok, err)
		}
	}
	b := e.idx.NewBatch()
	defer b.Close()
	if has, _ := b.HasChain(sha256.Sum256([]byte{10})); !has {
		t.Fatal("the batch's chains must be re-indexed")
	}
	if left, _ := ReadIntents(e.p); len(left) != 0 {
		t.Fatal("the intent of a committed batch is removed")
	}
	_ = m1
	if again := e.recover(); len(again.Actions) != 0 {
		t.Fatalf("recovery is idempotent: %v", again.Actions)
	}
}

func TestRecoverRefusesDamagedCommits(t *testing.T) {
	for name, damage := range map[string]func(e *env, m Manifest){
		"missing manifest": func(e *env, m Manifest) { os.Remove(filepath.Join(e.p.BatchDir(m.ID()), ManifestFile)) },
		"garbage manifest": func(e *env, m Manifest) {
			os.WriteFile(filepath.Join(e.p.BatchDir(m.ID()), ManifestFile), []byte("{"), 0o644)
		},
		"truncated parquet": func(e *env, m Manifest) {
			p := filepath.Join(e.p.BatchDir(m.ID()), dataset.EntriesFile)
			b, _ := os.ReadFile(p)
			os.WriteFile(p, b[:len(b)/2], 0o644)
		},
		"gap between batches": func(e *env, m Manifest) {
			os.Rename(e.p.BatchDir(m.ID()), filepath.Join(filepath.Dir(e.p.BatchDir(m.ID())), "batch=000000000010-000000000019"))
		},
	} {
		e := newEnv(t)
		ids := e.ids(1)
		_, s1, end1 := e.batch(0, 5, ids, 1, merkle.NewState(), vault.Tail{}, "done")
		m2, _, _ := e.batch(5, 5, ids, 2, s1, end1, "done")
		damage(e, m2)
		_, err := Recover(RecoverOptions{Paths: e.p, VaultDirs: e.dirs, Index: e.idx, Codec: e.codec, ChainIDs: e.stager.ChainIDs})
		if !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: want ErrCorrupt, got %v", name, err)
		}
	}
}

func TestRecoverCleansOnlyStageAndRebuild(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"tmp/stage/leftover/x", "tmp/rebuild/old/y", "tmp/duckdb-123/spill", "tmp/notes/keep"} {
		os.MkdirAll(filepath.Dir(filepath.Join(e.p.Root, p)), 0o755)
		os.WriteFile(filepath.Join(e.p.Root, p), []byte("x"), 0o644)
	}
	e.recover()
	for p, want := range map[string]bool{"tmp/stage/leftover": false, "tmp/rebuild/old": false, "tmp/duckdb-123/spill": true, "tmp/notes/keep": true} {
		if _, err := os.Stat(filepath.Join(e.p.Root, p)); (err == nil) != want {
			t.Errorf("%s: present=%v, want %v (amendment A1 §7: only tmp/stage and tmp/rebuild)", p, err == nil, want)
		}
	}
}

func TestAbandonInProcess(t *testing.T) {
	e := newEnv(t)
	ids := e.ids(1)
	_, s1, end1 := e.batch(0, 5, ids, 1, merkle.NewState(), vault.Tail{}, "done")
	e.batch(5, 10, ids, 2, s1, end1, "stage")
	in, _ := ReadIntents(e.p)
	if len(in) != 1 {
		t.Fatal("one intent in flight")
	}
	if err := Abandon(e.p, e.dirs, in[0]); err != nil {
		t.Fatal(err)
	}
	if u, _ := vault.InspectTail(e.dirs, end1); u.Bytes != 0 {
		t.Fatal("the vault is cut back to the batch's start")
	}
	if left, _ := ReadIntents(e.p); len(left) != 1 || !left[0].Abandoned {
		t.Fatal("the intent stays, marked abandoned, so a restart skips the touched cert_ids")
	}
	if _, err := os.Stat(e.p.StageDir(in[0].ID())); !os.IsNotExist(err) {
		t.Fatal("staging is removed")
	}
	floor, _ := ReadFloor(e.p.StateDir())
	for restart := 1; restart <= 2; restart++ {
		if r := e.recover(); !r.Crashed || r.NextCertID != floor {
			t.Fatalf("restart %d after an abandon resumes at the floor %d: %+v", restart, floor, r)
		}
		if left, _ := ReadIntents(e.p); len(left) != 1 || !left[0].Abandoned {
			t.Fatalf("restart %d: the abandoned intent stays until a later commit: %+v", restart, left)
		}
	}
}

func (e *env) recoverErr() error {
	_, err := Recover(RecoverOptions{Paths: e.p, VaultDirs: e.dirs, Index: e.idx, Codec: e.codec, ChainIDs: e.stager.ChainIDs})
	return err
}

// TestRecoverRefusesToTruncateUnexplainedData: vault data beyond the
// committed tail that no in-flight batch explains belongs to committed
// batches whose directories went missing (a mistaken rm, a partial
// restore). Truncating it would destroy the only copy; recovery must stop
// with nothing changed.
func TestRecoverRefusesToTruncateUnexplainedData(t *testing.T) {
	e := newEnv(t)
	ids := e.ids(1)
	_, s1, end1 := e.batch(0, 10, ids, 1, merkle.NewState(), vault.Tail{}, "done")
	m2, _, _ := e.batch(10, 10, ids, 2, s1, end1, "done")
	os.RemoveAll(e.p.BatchDir(m2.ID()))
	before, _ := vault.InspectTail(e.dirs, end1)
	if err := e.recoverErr(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("recovery must refuse: %v", err)
	}
	if after, _ := vault.InspectTail(e.dirs, end1); after.Bytes != before.Bytes || before.Bytes == 0 {
		t.Fatalf("nothing may be truncated: %d bytes before, %d after", before.Bytes, after.Bytes)
	}
	os.RemoveAll(filepath.Join(e.p.Root, "dataset", "log=fakelog"))
	if err := e.recoverErr(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a vault with no committed batches at all must not be wiped: %v", err)
	}
}

// TestRecoverRefusesAnIndexAheadOfTheDataset: Pebble is applied after the
// commit point, so it can lag the dataset but never lead it (spec §8.5).
func TestRecoverRefusesAnIndexAheadOfTheDataset(t *testing.T) {
	e := newEnv(t)
	e.batch(0, 10, e.ids(1), 1, merkle.NewState(), vault.Tail{}, "done")
	b := e.idx.NewBatch()
	b.SetApplied("fakelog", 3)
	b.Commit()
	b.Close()
	if err := e.recoverErr(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("an index ahead of the dataset means committed batches are missing: %v", err)
	}
}

// TestRecoverRefusesAForeignSegment: a committed segment whose header names
// another vault (a restore from the wrong backup) is corruption, found
// before Pebble is rebuilt from it (spec §6.2).
func TestRecoverRefusesAForeignSegment(t *testing.T) {
	e := newEnv(t)
	e.batch(0, 10, e.ids(1), 1, merkle.NewState(), vault.Tail{}, "done")
	segs, _ := vault.FindSegments(e.dirs)
	f, _ := os.OpenFile(segs[1], os.O_RDWR, 0)
	b := make([]byte, vault.HeaderSize)
	f.ReadAt(b, 0)
	h, _ := vault.DecodeHeader(b)
	h.VaultUUID = [16]byte{7}
	f.WriteAt(h.Encode(), 0)
	f.Close()
	if err := e.recoverErr(); !errors.Is(err, vault.ErrCorrupt) {
		t.Fatalf("a segment of another vault: %v", err)
	}
}

// TestRecoverRemovesInterruptedAtomicWrites: a writer killed inside
// fsutil.WriteFileAtomic leaves ".<name>.tmp-<n>" behind (found by the
// random kill loop in state/intent). Recovery removes such leftovers from
// the vault's metadata folders, leaves Pebble's folder and every other
// name alone.
func TestRecoverRemovesInterruptedAtomicWrites(t *testing.T) {
	e := newEnv(t)
	gone := []string{"state/intent/.fakelog__000000000080-000000000119.json.tmp-432468658", "state/.ID_FLOOR.tmp-1",
		"state/heads/.fakelog.json.tmp-7", ".views.sql.tmp-99", "vault/dict/.1.dict.tmp-5"}
	kept := []string{"state/notes.tmp", "state/pebble/.keep.tmp-3", "tmp/duckdb-1/.x.tmp-4", "state/.hidden"}
	for _, p := range append(slices.Clone(gone), kept...) {
		os.MkdirAll(filepath.Dir(filepath.Join(e.p.Root, p)), 0o755)
		os.WriteFile(filepath.Join(e.p.Root, p), []byte("x"), 0o644)
	}
	r := e.recover()
	for _, p := range gone {
		if _, err := os.Stat(filepath.Join(e.p.Root, p)); err == nil {
			t.Errorf("%s survived recovery", p)
		}
	}
	for _, p := range kept {
		if _, err := os.Stat(filepath.Join(e.p.Root, p)); err != nil {
			t.Errorf("%s was removed: %v", p, err)
		}
	}
	if !slices.Contains(r.Actions, "removed the leftover of an interrupted write: state/.ID_FLOOR.tmp-1") {
		t.Errorf("actions: %q", r.Actions)
	}
}
```

Replace `internal/vaulttest/vaulttest.go` with:

```go
// Package vaulttest checks a vault the way the crash suite needs (spec
// §13.5) and compares a recovered vault with a clean one (amendment A1 §7).
// It is test infrastructure: production binaries never import it.
package vaulttest

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	_ "github.com/duckdb/duckdb-go/v2" // the "duckdb" database/sql driver

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

// Vault is a vault root and its vault directories.
type Vault struct {
	Root string
	Dirs []string
	UUID [16]byte
}

// reader opens the vault's records with every dictionary loaded.
func (v Vault) reader(t testing.TB) *vault.Reader {
	t.Helper()
	c, err := vault.NewCodec()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	ds, err := vault.LoadDicts(v.Dirs)
	if err != nil {
		t.Fatalf("dictionaries: %v", err)
	}
	for _, d := range ds {
		if err := c.AddDict(d.Manifest.ID, d.Content); err != nil {
			t.Fatal(err)
		}
	}
	r, err := vault.OpenReader(v.Dirs, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

// record is a vault record with its certificate's SHA-256.
type record struct {
	loc    vault.Loc
	certID uint64
	sha    [32]byte
}

// scan reads the records in [from, to), resolving each to its SHA-256. A
// torn record ends the scan when torn is allowed.
func (v Vault) scan(t testing.TB, from, to vault.Tail, torn bool) []record {
	t.Helper()
	r := v.reader(t)
	var out []record
	err := vault.Scan(v.Dirs, from, to, func(loc vault.Loc, rec vault.Record) error {
		der, _, err := r.Read(loc)
		if err != nil {
			return err
		}
		out = append(out, record{loc, rec.CertID, sha256.Sum256(der)})
		return nil
	})
	if err != nil && !(torn && errors.Is(err, vault.ErrTorn)) {
		t.Fatalf("reading the vault: %v", err)
	}
	return out
}

// BeyondTail returns the cert_id and SHA-256 of every record past the
// committed tail, up to a torn record: what recovery will truncate.
func (v Vault) BeyondTail(t testing.TB) map[uint64][32]byte {
	t.Helper()
	ms, err := commit.ListCommitted(v.Root)
	if err != nil {
		t.Fatal(err)
	}
	var tail vault.Tail
	if len(ms) > 0 {
		tail = ms[len(ms)-1].Vault.End
	}
	segs, err := vault.FindSegments(v.Dirs)
	if err != nil {
		t.Fatal(err)
	}
	out := map[uint64][32]byte{}
	if len(segs) == 0 {
		return out
	}
	last := slices.Max(slices.Collect(maps.Keys(segs)))
	for _, rec := range v.scan(t, tail, vault.Tail{Segment: last, Offset: math.MaxInt64}, true) {
		out[rec.certID] = rec.sha
	}
	return out
}

// Assignments returns the cert_id and SHA-256 of every record in the
// segments, beyond the committed tail too, up to a torn record. Called after
// a kill and before recovery, it sees what the killed attempt assigned.
func (v Vault) Assignments(t testing.TB) map[uint64][32]byte {
	t.Helper()
	segs, err := vault.FindSegments(v.Dirs)
	if err != nil {
		t.Fatal(err)
	}
	out := map[uint64][32]byte{}
	if len(segs) == 0 {
		return out
	}
	last := slices.Max(slices.Collect(maps.Keys(segs)))
	for _, rec := range v.scan(t, vault.Tail{}, vault.Tail{Segment: last, Offset: math.MaxInt64}, true) {
		if prev, dup := out[rec.certID]; dup && prev != rec.sha {
			t.Fatalf("cert_id %d holds two different certificates in one vault", rec.certID)
		}
		out[rec.certID] = rec.sha
	}
	return out
}

func fileSHA256(t testing.TB, p string) string {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Committed is what a reader snapshot sees: every directory under
// dataset/log=*/ must be a committed batch whose files match _COMMIT.json
// byte for byte, so no partial batch is ever visible. It returns each
// batch directory's _COMMIT.json.
func (v Vault) Committed(t testing.TB) map[string][]byte {
	t.Helper()
	ms, err := commit.ListCommitted(v.Root)
	if err != nil {
		t.Fatalf("committed batches: %v", err)
	}
	paths := commit.Paths{Root: v.Root}
	out := map[string][]byte{}
	for _, m := range ms {
		dir := paths.BatchDir(m.ID())
		for name, fi := range m.Files {
			if got := fileSHA256(t, filepath.Join(dir, name)); got != fi.SHA256 {
				t.Fatalf("%s/%s does not match its checksum", dir, name)
			}
		}
		b, err := os.ReadFile(filepath.Join(dir, commit.ManifestFile))
		if err != nil {
			t.Fatal(err)
		}
		out[dir] = b
	}
	logs, _ := filepath.Glob(filepath.Join(v.Root, "dataset", "*", "*"))
	for _, d := range logs {
		if _, ok := out[d]; !ok {
			t.Fatalf("%s is visible under dataset/ but is not a committed batch", d)
		}
	}
	return out
}

// CheckRecovered asserts spec §13.5's invariants on a vault whose writer
// has opened (recovered) and closed it:
//   - committed batches are contiguous and every file matches its checksum;
//   - the vault holds nothing beyond the committed tail, and its segments
//     are intact;
//   - every committed record has a unique cert_id and a unique certificate;
//   - Pebble agrees with the vault, and applied/<log> is each log's last
//     commit_seq;
//   - each batch's Merkle state equals a recomputation from entries.parquet;
//   - only intents marked abandoned remain, for uncommitted batches, and
//     tmp/ holds only empty stage/ and rebuild/;
//   - no interrupted atomic write left its temp file anywhere.
func (v Vault) CheckRecovered(t testing.TB) {
	t.Helper()
	v.Committed(t)
	ms, _ := commit.ListCommitted(v.Root)
	var tail vault.Tail
	if len(ms) > 0 {
		tail = ms[len(ms)-1].Vault.End
	}
	if u, err := vault.InspectTail(v.Dirs, tail); err != nil || u.Bytes != 0 {
		t.Fatalf("data beyond the committed tail after recovery: %+v, %v", u, err)
	}
	if err := vault.CheckSegments(v.Dirs, v.UUID, tail); err != nil {
		t.Fatal(err)
	}
	refs := map[[32]byte]index.Ref{}
	ids := map[uint64]bool{}
	for _, rec := range v.scan(t, vault.Tail{}, tail, false) {
		if ids[rec.certID] {
			t.Fatalf("cert_id %d is committed twice", rec.certID)
		}
		if _, dup := refs[rec.sha]; dup {
			t.Fatalf("certificate %x is vaulted twice", rec.sha[:8])
		}
		ids[rec.certID], refs[rec.sha] = true, index.Ref{CertID: rec.certID, Loc: rec.loc}
	}

	idx, err := index.Open(filepath.Join(v.Root, "state", "pebble"))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	n := 0
	err = idx.EachCert(func(sha [32]byte, r index.Ref) error {
		if want, ok := refs[sha]; !ok || want != r {
			return fmt.Errorf("pebble has %x → %+v, the vault %+v (%v)", sha[:8], r, want, ok)
		}
		n++
		return nil
	})
	if err != nil || n != len(refs) {
		t.Fatalf("pebble and the vault disagree: %v (%d index entries, %d records)", err, n, len(refs))
	}
	last := map[string]uint64{}
	for _, m := range ms {
		last[m.Log] = m.CommitSeq
	}
	if applied, err := idx.AppliedLogs(); err != nil || !maps.Equal(applied, last) {
		t.Fatalf("applied %v, want %v (%v)", applied, last, err)
	}

	db := duck(t)
	states := map[string]*merkle.State{}
	paths := commit.Paths{Root: v.Root}
	for _, m := range ms {
		st, ok := states[m.Log]
		if !ok {
			st = merkle.NewState()
			states[m.Log] = st
		}
		for i, e := range entries(t, db, filepath.Join(paths.BatchDir(m.ID()), dataset.EntriesFile)) {
			if e.idx != m.First+uint64(i) {
				t.Fatalf("batch %s: row %d has index %d", m.BatchID, i, e.idx)
			}
			st.Append(e.leafHash)
		}
		want, _ := m.MerkleAfter.Root()
		if got, _ := st.Root(); got != want || st.Size() != m.Last+1 {
			t.Fatalf("batch %s: the Merkle state recomputed from entries.parquet differs from merkle_after", m.BatchID)
		}
	}

	ins, err := commit.ReadIntents(commit.Paths{Root: v.Root})
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range ins {
		if _, err := os.Stat(filepath.Join(paths.BatchDir(in.ID()), commit.ManifestFile)); !in.Abandoned || err == nil {
			t.Fatalf("intent of %s left after recovery (abandoned=%v, committed=%v)", in.BatchID, in.Abandoned, err == nil)
		}
	}
	filepath.WalkDir(v.Root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && fsutil.IsAtomicTemp(d.Name()) {
			t.Errorf("an interrupted write's temp file survived recovery: %s", p)
		}
		return nil
	})
	var tmp []string
	filepath.WalkDir(filepath.Join(v.Root, "tmp"), func(p string, d os.DirEntry, err error) error {
		if rel, _ := filepath.Rel(v.Root, p); err == nil && rel != "tmp" {
			tmp = append(tmp, rel)
		}
		return nil
	})
	if !slices.Equal(tmp, []string{"tmp/rebuild", "tmp/stage"}) {
		t.Fatalf("tmp/ after recovery: %v", tmp)
	}
}

func duck(t testing.TB) *sql.DB {
	t.Helper()
	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

type row struct {
	idx                uint64
	ts                 sql.Null[int64]
	typ                string
	certID             sql.Null[uint64]
	leafHash           [32]byte
	ikey, ikh, chainID []byte
	leafErr            sql.Null[string]
}

func entries(t testing.TB, db *sql.DB, path string) []row {
	t.Helper()
	rs, err := db.Query(`SELECT idx, epoch_ms(ct_ts), entry_type, cert_id, leaf_hash, issuance_key, issuer_key_hash, chain_id, leaf_error
		FROM read_parquet(` + quote(path) + `) ORDER BY idx`)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	var out []row
	for rs.Next() {
		var r row
		var lh []byte
		if err := rs.Scan(&r.idx, &r.ts, &r.typ, &r.certID, &lh, &r.ikey, &r.ikh, &r.chainID, &r.leafErr); err != nil {
			t.Fatal(err)
		}
		copy(r.leafHash[:], lh)
		out = append(out, r)
	}
	if err := rs.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// Entry is one log entry's content without internal IDs: certificates and
// chains are given by SHA-256 (hex), and NULL fields are empty.
type Entry struct {
	Idx           uint64
	LeafHash      string
	Timestamp     string // milliseconds, "" when NULL
	Type          string
	IssuanceKey   string
	IssuerKeyHash string
	LeafError     string
	Cert          string
	Chain         []string
}

// Dump returns every committed entry by log, in index order. A recovered
// ingest must equal a clean one on all of it; only cert_id and chain_id may
// differ (amendment A1 §7). Dump also checks that every reference resolves:
// each cert_id to one vault record, each chain_id to positions 0..n-1
// written by exactly one batch, and every committed record is referenced.
func (v Vault) Dump(t testing.TB) map[string][]Entry {
	t.Helper()
	ms, err := commit.ListCommitted(v.Root)
	if err != nil {
		t.Fatal(err)
	}
	var tail vault.Tail
	if len(ms) > 0 {
		tail = ms[len(ms)-1].Vault.End
	}
	certs := map[uint64]string{}
	for _, rec := range v.scan(t, vault.Tail{}, tail, false) {
		certs[rec.certID] = hex.EncodeToString(rec.sha[:])
	}
	used := map[uint64]bool{}
	cert := func(id uint64) string {
		s, ok := certs[id]
		if !ok {
			t.Fatalf("cert_id %d is referenced but not in the committed vault", id)
		}
		used[id] = true
		return s
	}

	db := duck(t)
	paths := commit.Paths{Root: v.Root}
	chains := map[string][]uint64{}
	for _, m := range ms {
		rs, err := db.Query(`SELECT chain_id, position, cert_id FROM read_parquet(` + quote(filepath.Join(paths.BatchDir(m.ID()), dataset.ChainsFile)) + `) ORDER BY chain_id, position`)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for rs.Next() {
			var id []byte
			var pos uint16
			var c uint64
			if err := rs.Scan(&id, &pos, &c); err != nil {
				t.Fatal(err)
			}
			k := string(id)
			if !seen[k] && len(chains[k]) > 0 {
				t.Fatalf("chain %x is written by two batches", id[:4])
			}
			if seen[k] = true; int(pos) != len(chains[k]) {
				t.Fatalf("chain %x: position %d out of order", id[:4], pos)
			}
			chains[k] = append(chains[k], c)
		}
		rs.Close()
	}

	out := map[string][]Entry{}
	for _, m := range ms {
		for _, r := range entries(t, db, filepath.Join(paths.BatchDir(m.ID()), dataset.EntriesFile)) {
			e := Entry{Idx: r.idx, LeafHash: hex.EncodeToString(r.leafHash[:]), Type: r.typ,
				IssuanceKey: hex.EncodeToString(r.ikey), IssuerKeyHash: hex.EncodeToString(r.ikh), LeafError: r.leafErr.V}
			if r.ts.Valid {
				e.Timestamp = fmt.Sprint(r.ts.V)
			}
			if r.certID.Valid {
				e.Cert = cert(r.certID.V)
			}
			if r.chainID != nil {
				ids, ok := chains[string(r.chainID)]
				if !ok {
					t.Fatalf("entry %d: chain %x has no chains.parquet rows", r.idx, r.chainID[:4])
				}
				e.Chain = []string{}
				for _, id := range ids {
					e.Chain = append(e.Chain, cert(id))
				}
			}
			out[m.Log] = append(out[m.Log], e)
		}
	}
	for id := range certs {
		if !used[id] {
			t.Fatalf("committed record cert_id %d is referenced by no entry or chain", id)
		}
	}
	return out
}

// Diff describes the first difference between two dumps, "" if equal.
func Diff(got, want map[string][]Entry) string {
	for _, log := range slices.Sorted(maps.Keys(want)) {
		g, w := got[log], want[log]
		for i := range min(len(g), len(w)) {
			if a, b := fmt.Sprintf("%+v", g[i]), fmt.Sprintf("%+v", w[i]); a != b {
				return fmt.Sprintf("log %s entry %d:\n got  %s\n want %s", log, w[i].Idx, a, b)
			}
		}
		if len(g) != len(w) {
			return fmt.Sprintf("log %s: %d entries, want %d", log, len(g), len(w))
		}
	}
	if len(got) != len(want) {
		return fmt.Sprintf("%d logs, want %d", len(got), len(want))
	}
	return ""
}
```

Replace `internal/commit/crash_test.go` with:

```go
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
	w, err := ingest.Open(options(c.Root, hook))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
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
// its content and how long the child took.
func clean(t *testing.T, l *ctlogtest.Log, end, batch uint64) (map[string][]vaulttest.Entry, time.Duration) {
	t.Helper()
	r := newCrashRun(t, l, end, batch)
	start := time.Now()
	if r.child("", 0, 0) {
		t.Fatal("the clean child was killed")
	}
	took := time.Since(start)
	r.restart()
	return r.v.Dump(t), took
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
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/fsutil/ ./internal/commit/`
Expected: FAIL with `undefined: IsAtomicTemp` in `internal/fsutil` (and `internal/vaulttest`). With only `IsAtomicTemp` added, the new assertions fail: `TestRecoverRemovesInterruptedAtomicWrites: state/intent/.fakelog__000000000080-000000000119.json.tmp-432468658 survived recovery` (and the 4 other leftovers), `TestCrashSkipSurvivesARestartWithoutACommit: the second start resumes at 11, want the floor 65537 (crashed=false)`, and `TestCrashAtEveryBoundary: cert_id 57 belonged to a record recovery truncated, and was committed later (spec §8.6: IDs are never reused)`.

- [ ] **Step 3: Implement**

Replace `internal/fsutil/fsutil.go` with:

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
	"strings"
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

// IsAtomicTemp reports whether name is a temporary file of WriteFileAtomic,
// ".<name>.tmp-<digits>": a writer killed before the rename leaves one.
func IsAtomicTemp(name string) bool {
	i := strings.LastIndex(name, ".tmp-")
	if !strings.HasPrefix(name, ".") || i < 2 || i+len(".tmp-") == len(name) {
		return false
	}
	for _, c := range name[i+len(".tmp-"):] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
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

Replace `internal/commit/recover.go` with:

```go
package commit

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/vault"
)

// RecoverOptions are the writer's resources, under the writer lock.
type RecoverOptions struct {
	Paths     Paths
	VaultDirs []string
	VaultUUID [16]byte // every segment header must carry it
	Index     *index.Index
	Codec     *vault.Codec // with every dictionary loaded
	// ChainIDs reads the chain_id column of a committed chains.parquet.
	ChainIDs func(path string) ([][32]byte, error)
}

// Recovered is the committed state after recovery.
type Recovered struct {
	Committed  []Manifest // by commit_seq
	Tail       vault.Tail // committed vault tail
	NextCertID uint64     // where cert_id allocation resumes
	Crashed    bool       // an attempt was lost; IDs resume at ID_FLOOR
	Actions    []string   // what recovery did, for the log
}

// LastSeq returns the highest committed commit_seq, 0 if none.
func (r Recovered) LastSeq() uint64 {
	if len(r.Committed) == 0 {
		return 0
	}
	return r.Committed[len(r.Committed)-1].CommitSeq
}

// Recover brings the vault back to its last committed state (spec §8.5). It
// runs at writer start, under the lock, before any work:
//
//  1. Committed batches are read and checked; a damaged one is corruption.
//  2. Vault data beyond the committed tail lifts ID_FLOOR above every
//     cert_id seen there, then is truncated.
//  3. Intents of committed batches are dropped; uncommitted batches lose
//     their staging directory, and their intents stay, marked abandoned,
//     until a later batch commits: every start until then resumes cert_id
//     allocation at ID_FLOOR, even if the writer that recovered stops
//     before committing anything (spec §8.6: IDs are never reused).
//  4. Only tmp/stage/* and tmp/rebuild/* are cleaned (amendment A1 §7),
//     plus the temp files of interrupted atomic writes in the vault's
//     metadata folders.
//  5. Every committed segment must exist and carry this vault's UUID.
//  6. Pebble catches up on committed batches it has not applied, by
//     re-reading their vault ranges and chains.parquet; this is idempotent.
func Recover(o RecoverOptions) (Recovered, error) {
	var r Recovered
	committed, err := ListCommitted(o.Paths.Root)
	if err != nil {
		return r, err
	}
	r.Committed, r.NextCertID = committed, 1
	if n := len(committed); n > 0 {
		r.Tail, r.NextCertID = committed[n-1].Vault.End, committed[n-1].NextCertID
	}

	// Pebble is applied after the commit point, so it may lag the dataset but
	// never lead it. A log applied beyond its highest committed batch means
	// committed batch directories are missing: stop before changing anything.
	applied, err := o.Index.AppliedLogs()
	if err != nil {
		return r, err
	}
	highest := map[string]uint64{}
	for _, m := range committed {
		highest[m.Log] = max(highest[m.Log], m.CommitSeq)
	}
	for log, seq := range applied {
		if seq > highest[log] {
			return r, corrupt("the index has applied commit_seq %d of log %s, but its highest committed batch is %d: "+
				"committed batch directories are missing; restore them (nothing was changed)", seq, log, highest[log])
		}
	}

	intents, err := ReadIntents(o.Paths)
	if err != nil {
		return r, err
	}
	u, err := vault.InspectTail(o.VaultDirs, r.Tail)
	if err != nil {
		return r, err
	}
	if u.Bytes > 0 {
		// Every legitimate crash leaves the intent of the batch in flight,
		// written (P1) before its first append, whose vault tail is the
		// committed tail. Data nothing explains belongs to committed batches
		// whose directories are gone: never truncate it.
		explained := false
		for _, in := range intents {
			_, err := os.Stat(filepath.Join(o.Paths.BatchDir(in.ID()), ManifestFile))
			if in.VaultTail == r.Tail && err != nil {
				explained = true
			}
		}
		if !explained {
			return r, corrupt("%d bytes of vault data lie beyond the committed tail %d:%d and no batch in flight explains them: "+
				"committed batch directories may be missing; restore them (nothing was changed)", u.Bytes, r.Tail.Segment, r.Tail.Offset)
		}
		r.Crashed = true
		ids, err := LoadIDs(o.Paths.StateDir(), 1, nil)
		if err != nil {
			return r, err
		}
		if err := ids.Raise(u.MaxCertID + 1); err != nil {
			return r, err
		}
		if err := vault.Truncate(o.VaultDirs, r.Tail); err != nil {
			return r, err
		}
		r.Actions = append(r.Actions, fmt.Sprintf("truncated %d uncommitted vault bytes (highest cert_id %d)", u.Bytes, u.MaxCertID))
	}

	for _, in := range intents {
		if _, err := os.Stat(filepath.Join(o.Paths.BatchDir(in.ID()), ManifestFile)); err == nil {
			r.Actions = append(r.Actions, "batch "+in.BatchID+" was committed; finishing it")
			if err := RemoveIntent(o.Paths, in.ID(), nil); err != nil {
				return r, err
			}
			continue
		}
		r.Crashed = true
		if err := os.RemoveAll(o.Paths.StageDir(in.ID())); err != nil {
			return r, err
		}
		if !in.Abandoned {
			in.Abandoned = true
			if err := WriteIntent(o.Paths, in, nil); err != nil {
				return r, err
			}
			r.Actions = append(r.Actions, "abandoned uncommitted batch "+in.BatchID)
		}
	}

	for _, sub := range []string{"stage", "rebuild"} {
		dir := filepath.Join(o.Paths.Root, "tmp", sub)
		left, _ := os.ReadDir(dir)
		for _, e := range left {
			if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
				return r, err
			}
			r.Actions = append(r.Actions, "removed leftover tmp/"+sub+"/"+e.Name())
		}
	}

	if err := removeInterruptedWrites(o, &r); err != nil {
		return r, err
	}

	if err := vault.CheckSegments(o.VaultDirs, o.VaultUUID, r.Tail); err != nil {
		return r, err
	}

	if err := catchUp(o, committed, &r); err != nil {
		return r, err
	}

	if r.Crashed {
		floor, err := ReadFloor(o.Paths.StateDir())
		if err != nil {
			return r, err
		}
		r.NextCertID = max(r.NextCertID, floor)
	}
	return r, nil
}

// catchUp re-applies committed batches that Pebble has not recorded (spec
// §8.5: Pebble only ever lags the dataset).
func catchUp(o RecoverOptions, committed []Manifest, r *Recovered) error {
	applied := map[string]uint64{}
	var reader *vault.Reader
	defer func() {
		if reader != nil {
			reader.Close()
		}
	}()
	for _, m := range committed {
		seq, ok := applied[m.Log]
		if !ok {
			var err error
			if seq, err = o.Index.Applied(m.Log); err != nil {
				return err
			}
			applied[m.Log] = seq
		}
		if m.CommitSeq <= seq {
			continue
		}
		if reader == nil {
			var err error
			if reader, err = vault.OpenReader(o.VaultDirs, o.Codec); err != nil {
				return err
			}
		}
		b := o.Index.NewBatch()
		err := vault.Scan(o.VaultDirs, m.Vault.Start, m.Vault.End, func(loc vault.Loc, rec vault.Record) error {
			der, _, err := reader.Read(loc)
			if err != nil {
				return err
			}
			return b.AddCert(sha256.Sum256(der), index.Ref{CertID: rec.CertID, Loc: loc})
		})
		if err == nil {
			var ids [][32]byte
			ids, err = o.ChainIDs(filepath.Join(o.Paths.BatchDir(m.ID()), dataset.ChainsFile))
			for _, id := range ids {
				if err == nil {
					err = b.AddChain(id)
				}
			}
		}
		if err == nil {
			err = b.SetApplied(m.Log, m.CommitSeq)
		}
		if err == nil {
			err = b.Commit()
		}
		b.Close()
		if err != nil {
			return fmt.Errorf("re-applying batch %s to the index: %w", m.BatchID, err)
		}
		applied[m.Log] = m.CommitSeq
		r.Actions = append(r.Actions, "re-applied batch "+m.BatchID+" to the index")
	}
	return nil
}

// removeInterruptedWrites deletes what a writer killed inside
// fsutil.WriteFileAtomic leaves behind: ".<name>.tmp-<digits>" files in the
// root (views.sql), state/ and its folders (intents, ID_FLOOR, heads, log
// records, incidents) and each vault folder's dict/. Pebble's folder and
// every other name are left alone. The writer lock excludes every other
// writer of these folders.
func removeInterruptedWrites(o RecoverOptions, r *Recovered) error {
	root, state := o.Paths.Root, o.Paths.StateDir()
	dirs := []string{root}
	err := filepath.WalkDir(state, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p == filepath.Join(state, "pebble") {
				return filepath.SkipDir
			}
			dirs = append(dirs, p)
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	for _, v := range o.VaultDirs {
		dirs = append(dirs, filepath.Join(v, "dict"))
	}
	for _, dir := range dirs {
		es, err := os.ReadDir(dir)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		for _, e := range es {
			if !e.Type().IsRegular() || !fsutil.IsAtomicTemp(e.Name()) {
				continue
			}
			p := filepath.Join(dir, e.Name())
			if err := os.Remove(p); err != nil {
				return err
			}
			if rel, err := filepath.Rel(root, p); err == nil && !strings.HasPrefix(rel, "..") {
				p = rel
			}
			r.Actions = append(r.Actions, "removed the leftover of an interrupted write: "+p)
		}
	}
	return nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race ./internal/fsutil/ ./internal/commit/`. Then run `go test -run 'CrashAtEvery|RandomKill' ./internal/commit/` three times.
Expected: PASS every time.

- [ ] **Step 5: Quality gate**

- [ ] **Step 6: Checkpoint.**

---

### Task C7: `sample measure` and measurement reports

Amendment A1 §2.6 and §8.

**Files:**
- Modify: `internal/sample/read.go`, `internal/cli/sample_dev.go`, `cmd/ctvault/guard_test.go` (bans `internal/measure`)
- Create: `internal/ingest/measure_dev.go`, `internal/measure/measure.go`, `internal/measure/report.go`. All are built with `//go:build ctvault_dev || realdata`.
- Tests: `internal/ingest/measure_dev_test.go`, `internal/measure/measure_test.go`, `internal/cli/sample_dev_test.go`

**Interfaces:**
- Produces:
  - `sample`:
    - `(*Sample).StartState() (*merkle.State, error)`: the authenticated compact range `[0, Start)`
    - `(*Sample).LogInfo(url string) logsource.LogInfo`
  - `ingest` (dev and realdata builds):
    - `(*Writer).Seed(log string, state *merkle.State) error`
    - `(*Writer).Committed() []commit.Manifest`
  - `measure`:
    - `Run(ctx, *sample.Sample, Options) (Report, Paths, error)`, `Markdown(Report) string`, `DefaultBatchSize = 10000`
    - `Options{Base, Version, Now, Stat, Out, BatchSize, Dependencies, DictSamples, CanarySamples}`. `Dependencies` is used only when the build info lists none (a `go test` binary).
  - CLI: `ctvault-dev sample measure <sample dir> [--batch-size N]`. A sample that fails verification exits 5, and the disk cap exits 3.
- How a run works:
  1. A survey pass decodes every entry. It records links (a final certificate whose precert, with the same 32-byte issuance digest, comes earlier in the window), the delays, duplicates and error codes, and the Merkle root at every batch end.
  2. The workspace `<base>/tmp/measure-<pid>` is a vault layout with no `VAULT_ID`.
  3. The production writer commits batch by batch, fed by the sample's loopback replay. A representative workspace is seeded first.
  4. A vault scan groups records by kind, dictionary and entry type. It prices each `leaf-delta` frame against the same certificate compressed in full.
  5. The report is written as JSON and Markdown under `<base>/reports/<log>/<sample dir>/<UTC time>.json`, never overwriting an older one.
  6. The workspace is removed.

- [ ] **Step 1: Write the failing tests**

Create `internal/ingest/measure_dev_test.go`:

```go
//go:build ctvault_dev || realdata

package ingest

import (
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/merkle"
)

// TestSeedStartsAMeasurementMidLog: a seeded writer commits a window that
// starts mid-log, verified against the real head, and the workspace can
// never be reopened as a vault.
func TestSeedStartsAMeasurementMidLog(t *testing.T) {
	h := newHarness(t, entries(t, 40), ctlogtest.Options{})
	w := h.open()
	st := merkle.NewState()
	for _, e := range h.log.Entries[:16] {
		if err := st.Append(merkle.LeafHash(e.LeafInput)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Seed("fakelog", st); err != nil {
		t.Fatal(err)
	}
	ms := h.ingest(w, h.head(), 16, 40, 12)
	if ms[0].First != 16 || ms[1].Last != 39 || ms[1].Verified.Method != "root_equals_sth" {
		t.Fatalf("manifests: %+v / %+v", ms[0], ms[1])
	}
	if got := w.Committed(); len(got) != 2 || got[1].CommitSeq != 2 {
		t.Fatalf("Committed() = %d manifests", len(got))
	}
	if err := w.Seed("fakelog", merkle.NewState()); err == nil {
		t.Fatal("Seed accepted a log that already has committed batches")
	}
	w.Close()
	if _, err := Open(h.opts); err == nil || !strings.Contains(err.Error(), "not contiguous at index 0") {
		t.Fatalf("reopening a seeded workspace: %v, want the contiguity refusal", err)
	}
}

// TestSeedWithAWrongStateFailsVerification: the seed is not trusted; a
// batch whose compact range is wrong fails Merkle verification.
func TestSeedWithAWrongStateFailsVerification(t *testing.T) {
	h := newHarness(t, entries(t, 40), ctlogtest.Options{})
	w := h.open()
	st := merkle.NewState()
	for _, e := range h.log.Entries[1:17] { // shifted by one: the wrong range
		st.Append(merkle.LeafHash(e.LeafInput))
	}
	if err := w.Seed("fakelog", st); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Batch(ctx, h.src, h.head(), 16, 40); err == nil {
		t.Fatal("a batch over a wrong seed committed")
	}
}
```

Create `internal/measure/measure_test.go`:

```go
//go:build ctvault_dev || realdata

package measure

import (
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

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/sample"
)

var now = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

// fakeSample captures a sample of a fake log holding es (frames of 8).
func fakeSample(t *testing.T, es []ctlogtest.Entry, kind sample.Kind, start, count uint64) *sample.Sample {
	t.Helper()
	l := ctlogtest.NewWithEntries(t, es, ctlogtest.Options{PageSize: 8})
	pub, err := x509.ParsePKIXPublicKey(l.PublicKeyDER)
	if err != nil {
		t.Fatal(err)
	}
	src := rfc6962.NewSource(logsource.LogInfo{Name: "fakelog", LogID: l.LogID, PublicKey: pub, URL: l.URL}, nil,
		logsource.NewChainCache(logsource.DefaultChainCacheBytes), nil)
	dir := t.TempDir()
	t.Cleanup(func() { // published samples are read-only; let TempDir remove them
		filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				os.Chmod(p, 0o755)
			}
			return nil
		})
	})
	s, err := sample.Capture(context.Background(), dir, src, sample.CaptureOptions{Kind: kind, Start: start, Count: count,
		Limits: sample.Limits{Boundary: 8, Min: 16, Max: 96}, Key: base64.StdEncoding.EncodeToString(l.PublicKeyDER),
		LogListVersion: "test", Version: "test", Now: func() time.Time { return now },
		Fetch: fetch.Options{MaxRPS: 1000, MinBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func generated(t *testing.T, n int) []ctlogtest.Entry {
	t.Helper()
	g, err := ctlogtest.NewGenerator()
	if err != nil {
		t.Fatal(err)
	}
	es, err := g.Entries(n)
	if err != nil {
		t.Fatal(err)
	}
	return es
}

func options(t *testing.T, base string) Options {
	free := func(string) (diskguard.Usage, error) {
		return diskguard.Usage{Total: 1 << 40, Avail: 1 << 39, Dev: 1}, nil
	}
	return Options{Base: base, Version: "test", Now: func() time.Time { return now }, Stat: free,
		BatchSize: 32, DictSamples: 16, CanarySamples: 8,
		Dependencies: map[string]string{"github.com/klauspost/compress": "v1.20.1"}}
}

// TestMeasureCanonical runs a canonical sample with known contents: 46
// precert/final pairs, a duplicate final, a duplicate precert, a malformed
// leaf and one more duplicate final.
func TestMeasureCanonical(t *testing.T) {
	es := generated(t, 92)
	es = append(es, es[1], es[2], ctlogtest.MalformedEntry(1790000999000), es[3])
	s := fakeSample(t, es, sample.Canonical, 0, 96)
	base := t.TempDir()
	r, paths, err := Run(context.Background(), s, options(t, base))
	if err != nil {
		t.Fatal(err)
	}
	if r.Sample.Count != 96 || r.Run.Batches != 3 || len(r.Batches) != 3 {
		t.Fatalf("sample %+v, run %+v", r.Sample, r.Run)
	}
	if r.Batches[0].Dictionary != 0 || r.Batches[1].Dictionary != 1 || r.Batches[2].Dictionary != 1 {
		t.Fatalf("dictionary 1 is trained after the first batch's 16 precerts: %+v", r.Batches)
	}
	// 46 finals plus 2 duplicates, all after their precert in index order.
	l := r.Links
	if l.Finals != 48 || l.Linked != 48 || l.LinkRate != 1 || l.DeltaEligible != 46 || l.DeltaRecords != 46 || l.DeltaHitRate != 1 {
		t.Fatalf("links %+v", l)
	}
	if l.DelayMS.P50 != 1000 || l.DelayMS.P99 != 1000 {
		t.Fatalf("every generated final is logged 1 s after its precert: %+v", l.DelayMS)
	}
	d := r.Dedup
	if d.LeafCerts != 95 || d.UniqueLeafCerts != 92 || d.LeafHits != 3 || d.ChainRefs == 0 || d.ChainRecords == 0 || d.ChainRecords >= d.ChainRefs {
		t.Fatalf("dedup %+v", d)
	}
	if r.Errors.Total != 1 || r.Errors.ByCode["leaf_bad_version"] != 1 || r.Errors.Structural != 1 {
		t.Fatalf("errors %+v", r.Errors)
	}
	var leafRecords, deltaRecords int
	for _, g := range r.Compression.Groups {
		switch g.Kind {
		case "leaf":
			leafRecords += g.Records
		case "delta":
			deltaRecords += g.Records
		}
		if g.Ratio <= 0 || g.StoredBytes == 0 {
			t.Fatalf("group %+v", g)
		}
	}
	if leafRecords+deltaRecords != 92 || deltaRecords != 46 {
		t.Fatalf("records: %d full leaf + %d delta, want 46 + 46", leafRecords, deltaRecords)
	}
	z := r.Sizes
	if z.Vault <= 0 || z.VaultFiles < z.Vault || z.Parquet <= 0 || z.Pebble <= 0 || z.ParquetByFile["entries.parquet"] <= 0 {
		t.Fatalf("sizes %+v", z)
	}
	deltas := 0
	for _, ds := range r.Compression.Deltas {
		deltas += ds.Records
		if ds.FullBytes == 0 || ds.StoredBytes == 0 {
			t.Fatalf("delta saving %+v", ds)
		}
	}
	if len(r.Compression.Deltas) != 2 || r.Compression.Deltas[0].Dictionary != 0 || r.Compression.Deltas[1].Dictionary != 1 || deltas != 46 {
		t.Fatalf("delta savings by dictionary: %+v", r.Compression.Deltas)
	}
	if !strings.Contains(strings.Join(r.Notes, "\n"), "batch 32-63 trained dictionary 1") {
		t.Fatalf("notes lack the training batch: %q", r.Notes)
	}
	if r.Provenance.GoVersion == "" || r.Provenance.CTVaultVersion != "test" || r.Sample.ID != "fakelog/000000000000-000000000095" {
		t.Fatalf("provenance %+v, sample %+v", r.Provenance, r.Sample)
	}
	// A test binary's build info lists no dependencies; the caller's
	// versions are used and labelled.
	p := r.Provenance
	if p.Dependencies["github.com/klauspost/compress"] != "v1.20.1" || p.DependenciesFrom != "go.mod" || p.ZstdLibrary != "github.com/klauspost/compress v1.20.1" {
		t.Fatalf("dependencies %v from %q, zstd %q", p.Dependencies, p.DependenciesFrom, p.ZstdLibrary)
	}
	// The report is written, the workspace is gone.
	wantDir := filepath.Join(base, "reports", "fakelog", "000000000000-000000000095")
	if filepath.Dir(paths.JSON) != wantDir || filepath.Dir(paths.Markdown) != wantDir {
		t.Fatalf("report paths %+v, want under %s", paths, wantDir)
	}
	b, err := os.ReadFile(paths.JSON)
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(b, &back); err != nil || back.Links != r.Links {
		t.Fatalf("report JSON does not round-trip: %v", err)
	}
	md, err := os.ReadFile(paths.Markdown)
	if err != nil || !strings.Contains(string(md), "fakelog/000000000000-000000000095") {
		t.Fatalf("markdown summary: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(base, "tmp", "measure-*")); len(left) != 0 {
		t.Fatalf("workspace left behind: %v", left)
	}
}

// TestMeasureFinalBeforePrecert: a final certificate logged before its
// precert cannot link or delta-encode; it is counted apart.
func TestMeasureFinalBeforePrecert(t *testing.T) {
	es := generated(t, 16)
	es[2], es[3] = es[3], es[2]
	o := options(t, t.TempDir())
	o.BatchSize = 8
	r, _, err := Run(context.Background(), fakeSample(t, es, sample.Canonical, 0, 16), o)
	if err != nil {
		t.Fatal(err)
	}
	if l := r.Links; l.Finals != 8 || l.Linked != 7 || l.PrecertLater != 1 || l.DeltaEligible != 7 || l.DeltaRecords != 7 {
		t.Fatalf("links %+v", l)
	}
}

// TestMeasureRepresentative: a window that starts mid-log is seeded from the
// sample's inclusion proof and measured; a final whose precert is before the
// window does not link.
func TestMeasureRepresentative(t *testing.T) {
	es := generated(t, 80)
	s := fakeSample(t, es, sample.Representative, 24, 48)
	o := options(t, t.TempDir())
	o.BatchSize = 16
	r, _, err := Run(context.Background(), s, o)
	if err != nil {
		t.Fatal(err)
	}
	if r.Sample.Kind != "representative" || r.Sample.Start != 24 || len(r.Batches) != 3 || r.Batches[0].First != 24 || r.Batches[2].Last != 71 {
		t.Fatalf("sample %+v, batches %+v", r.Sample, r.Batches)
	}
	if r.Links.Finals != 24 || r.Links.Linked != 24 {
		t.Fatalf("the window starts on a precert, so all 24 finals link: %+v", r.Links)
	}
	if !strings.Contains(strings.Join(r.Notes, "\n"), "starts mid-log") {
		t.Fatalf("notes lack the representative caveat: %q", r.Notes)
	}

	small := fakeSample(t, es, sample.Representative, 8, 16) // [8, 24), two batches of 8
	o.BatchSize = 8
	r, _, err = Run(context.Background(), small, o)
	if err != nil || r.Links.Finals != 8 || r.Links.Linked != 8 {
		t.Fatalf("%v %+v", err, r.Links)
	}
}

// TestMeasureLeavesNothingOnFailure: a run interrupted after a committed
// batch leaves no workspace and no report, and a stale workspace of a dead
// process is removed.
func TestMeasureLeavesNothingOnFailure(t *testing.T) {
	s := fakeSample(t, generated(t, 32), sample.Canonical, 0, 32)
	base := t.TempDir()
	stale := filepath.Join(base, "tmp", "measure-999999999")
	if err := os.MkdirAll(filepath.Join(stale, "vault"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	o := options(t, base)
	o.BatchSize = 16
	o.Out = cancelOnWrite(cancel) // the writer's line for the first committed batch
	if _, _, err := Run(ctx, s, o); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run interrupted after its first batch: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(base, "tmp", "measure-*")); len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}
	if reports, _ := filepath.Glob(filepath.Join(base, "reports", "*", "*", "*")); len(reports) != 0 {
		t.Fatalf("a failed run wrote a report: %v", reports)
	}
}

type cancelOnWrite func()

func (c cancelOnWrite) Write(p []byte) (int, error) { c(); return len(p), nil }

func TestPercentiles(t *testing.T) {
	var v []int64
	for i := int64(1); i <= 100; i++ {
		v = append(v, 101-i)
	}
	if p := percentiles(v); p.P50 != 50 || p.P95 != 95 || p.P99 != 99 {
		t.Fatalf("nearest-rank percentiles of 1..100: %+v", p)
	}
	if p := percentiles(nil); p != (Delays{}) {
		t.Fatalf("no values: %+v", p)
	}
}

// TestGapRule is amendment A1 §5's rule: more than 10% worse than the
// spec's figure is flagged.
func TestGapRule(t *testing.T) {
	for _, c := range []struct {
		higherIsBetter bool
		spec, measured float64
		exceeds        bool
	}{
		{true, 1.96, 1.80, false}, // 8.9% lower ratio
		{true, 1.96, 1.70, true},  // 15% lower
		{false, 765, 840, false},  // 9.8% more bytes
		{false, 765, 850, true},   // 11% more
		{true, 1.96, 2.40, false},
	} {
		g := gap("x", c.spec, c.measured, c.higherIsBetter)
		if g.Exceeds != c.exceeds {
			t.Errorf("%+v: exceeds = %v", c, g.Exceeds)
		}
	}
}

// TestReportWriteFailsOnAnUnreadableFolder: a reports folder that cannot be
// searched is an error, never an endless search for a free name.
func TestReportWriteFailsOnAnUnreadableFolder(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "reports", "fakelog", "x")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o600); err != nil { // no search permission
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
	done := make(chan error, 1)
	go func() {
		_, err := write(base, Report{Sample: SampleInfo{ID: "fakelog/x"}, Provenance: Provenance{ReportedAt: now}})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("writing into an unsearchable folder succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("write is still looking for a free report name")
	}
}
```

Replace `internal/cli/sample_dev_test.go` with:

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

// TestSampleCaptureCreatesTheDevBase: on a fresh machine ~/.cache/ctvault-dev
// does not exist yet. The first capture must create it rather than fail its
// disk check, which stats the folder.
func TestSampleCaptureCreatesTheDevBase(t *testing.T) {
	e, _ := sampleEnv(t, 0.5)
	fake := e.deps.Statfs
	home := t.TempDir()
	t.Cleanup(func() { // runs before home's removal: published samples are read-only
		filepath.WalkDir(home, func(p string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				os.Chmod(p, 0o755)
			}
			return nil
		})
	})
	e.deps.DevBase = filepath.Join(home, ".cache", "ctvault-dev")
	e.deps.Statfs = func(p string) (diskguard.Usage, error) { // like statfs(2): a missing path fails
		if _, err := os.Stat(p); err != nil {
			return diskguard.Usage{}, err
		}
		return fake(p)
	}
	e.mustRun("sample", "capture", "--log", "fakelog", "--entries", "16")
	if _, err := os.Stat(filepath.Join(e.deps.DevBase, "samples", "fakelog", "000000000000-000000000015", sample.ManifestFile)); err != nil {
		t.Fatalf("the sample must be published under the new dev base: %v", err)
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

func TestSampleVerifyRefusesAPartialCopy(t *testing.T) {
	e, _ := sampleEnv(t, 0.5)
	e.mustRun("sample", "capture", "--log", "fakelog", "--entries", "16")
	dir := filepath.Join(e.deps.DevBase, "samples", "fakelog", "000000000000-000000000015")
	os.Chmod(dir, 0o755)
	os.Remove(filepath.Join(dir, sample.ProofsFile))
	if code := e.run("sample", "verify", dir); code != exitcode.Verification {
		t.Fatalf("a sample missing %s: exit %d, want %d: %s", sample.ProofsFile, code, exitcode.Verification, e.stderr)
	}
}

// TestSampleMeasure: measure writes a report under the dev base and leaves
// no workspace; a full disk stops it before anything is written (exit 3).
func TestSampleMeasure(t *testing.T) {
	e, _ := sampleEnv(t, 0.5)
	e.mustRun("sample", "capture", "--log", "fakelog", "--entries", "48")
	dir := filepath.Join(e.deps.DevBase, "samples", "fakelog", "000000000000-000000000047")
	out := e.mustRun("sample", "measure", dir, "--batch-size", "16")
	if !strings.Contains(out, "# Measurement: fakelog/000000000000-000000000047") || !strings.Contains(out, "report: ") {
		t.Fatalf("measure output: %s", out)
	}
	reports, _ := filepath.Glob(filepath.Join(e.deps.DevBase, "reports", "fakelog", "000000000000-000000000047", "*.json"))
	if len(reports) != 1 {
		t.Fatalf("reports: %v", reports)
	}
	if left, _ := filepath.Glob(filepath.Join(e.deps.DevBase, "tmp", "measure-*")); len(left) != 0 {
		t.Fatalf("workspace left behind: %v", left)
	}
	if code := e.run("sample", "measure", dir, "--batch-size", "0"); code != exitcode.Usage {
		t.Fatalf("--batch-size 0: exit %d", code)
	}
	e.deps.Statfs = func(string) (diskguard.Usage, error) {
		return diskguard.Usage{Total: 1 << 40, Avail: 1 << 36, Dev: 1}, nil // 94% used
	}
	if code := e.run("sample", "measure", dir, "--batch-size", "16"); code != exitcode.DiskCap {
		t.Fatalf("full disk: exit %d, %s", code, e.stderr)
	}
	if reports, _ := filepath.Glob(filepath.Join(e.deps.DevBase, "reports", "fakelog", "000000000000-000000000047", "*.json")); len(reports) != 1 {
		t.Fatalf("a refused run wrote a report: %v", reports)
	}
}
```

Replace `cmd/ctvault/guard_test.go` with:

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
	banned := []string{"/internal/volume/volumetest", "/internal/ctlogtest", "/internal/sampletest", "/internal/sample", "/internal/vaulttest", "/internal/measure"}
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
		// The _dev.go naming rule is CTVault's own; third-party packages
		// (prometheus/procfs's net_dev.go, via Pebble) may use the suffix.
		if !strings.HasPrefix(p.ImportPath, "github.com/4rji/ctvault/") {
			continue
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

- [ ] **Step 2: Run them to verify they fail**

Run: `go test -tags ctvault_dev ./internal/ingest/ ./internal/measure/ ./internal/cli/`
Expected: FAIL with `w.Seed undefined (type *Writer has no field or method Seed)` in `internal/ingest`, `undefined: Options` in `internal/measure`, and in `internal/cli` `TestSampleMeasure: ... exit 2` (no `measure` command yet)`.

- [ ] **Step 3: Implement**

Replace `internal/sample/read.go` with:

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
	"io/fs"
	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"

	"github.com/4rji/ctvault/internal/loglist"
	"github.com/4rji/ctvault/internal/logsource"
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
// Merkle proofs that tie every leaf_input to the signed root. extra_data is
// not part of a CT log's Merkle tree, so only the checksums protect it.
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
		if errors.Is(err, fs.ErrNotExist) {
			return nil, corrupt("%s is missing (an incomplete copy?)", name)
		}
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

// StartState returns the authenticated compact range of [0, Start): empty
// for a canonical sample, and for a representative one the left siblings of
// the inclusion proof of leaf Start (amendment A1 §2.4).
func (s *Sample) StartState() (*merkle.State, error) {
	m := s.Manifest
	if m.Kind == Canonical {
		return merkle.NewState(), nil
	}
	inc := s.Proofs.Inclusion
	if inc == nil || inc.LeafIndex != m.Start || inc.TreeSize != s.Head.TreeSize {
		return nil, corrupt("representative sample lacks the inclusion proof of leaf %d", m.Start)
	}
	st, err := merkle.StateFromInclusion(m.Start, s.Head.TreeSize, inc.LeafHash, s.Head.RootHash, hashes(inc.AuditPath))
	if err != nil {
		return nil, corrupt("%v", err)
	}
	return st, nil
}

func (s *Sample) verifyMerkle() error {
	m := s.Manifest
	st, err := s.StartState()
	if err != nil {
		return err
	}
	err = s.Each(func(e Entry) error {
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

// LogInfo returns the sampled log with its pinned key, served at url.
func (s *Sample) LogInfo(url string) logsource.LogInfo {
	return logsource.LogInfo{Name: s.Manifest.Log.Name, LogID: s.LogIDBytes(), PublicKey: s.pub, URL: url}
}

// LogIDBytes returns the sampled log's ID.
func (s *Sample) LogIDBytes() [32]byte {
	var id [32]byte
	b, _ := base64.StdEncoding.DecodeString(s.Manifest.Log.LogID)
	copy(id[:], b)
	return id
}
```

Create `internal/ingest/measure_dev.go`:

```go
//go:build ctvault_dev || realdata

package ingest

import (
	"fmt"
	"slices"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/merkle"
)

// Seed makes log start at state's size, with state as the compact range
// before it, in a measurement workspace (amendment A1 §2.6): a
// representative sample begins mid-log. The seed is not trusted: every
// batch is still Merkle-verified from it. Vaults always ingest from index 0
// (spec §5.5) and never call Seed: this file is not part of production
// builds, and a workspace whose first batch does not start at 0 cannot be
// reopened, because loading the manifests refuses the gap.
func (w *Writer) Seed(log string, state *merkle.State) error {
	if _, ok := w.tips[log]; ok {
		return fmt.Errorf("seed: log %s already has committed batches", log)
	}
	w.tips[log] = commit.LogTip{Next: state.Size(), State: state.Clone()}
	return nil
}

// Committed returns the committed batches' manifests in commit order.
func (w *Writer) Committed() []commit.Manifest { return slices.Clone(w.committed) }
```

Create `internal/measure/measure.go`:

```go
//go:build ctvault_dev || realdata

// Package measure runs a real-data sample through the production per-entry
// pipeline in a throwaway workspace and reports what it observed (amendment
// A1 §2.6 and §8): decoding, the issuance key, dedup, the vault writer with
// dictionaries and leaf-delta, and Parquet staging, committed batch by batch
// exactly as update commits them. It never creates or changes a vault, and
// a report never changes a setting: disk-guard seeds and defaults change
// only by a reviewed edit.
package measure

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/ingest"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/sample"
	"github.com/4rji/ctvault/internal/vault"
)

// DefaultBatchSize is the dev build's batch size (amendment A1 §2.5).
const DefaultBatchSize = 10000

// replayRPS lifts the live rate limit: the replay is on loopback.
const replayRPS = 1000

// Options configure a measurement run.
type Options struct {
	Base    string // the dev base: the workspace goes under Base/tmp, the report under Base/reports
	Version string // CTVault version, for the provenance
	Now     func() time.Time
	Stat    diskguard.StatFunc // the disk guard's statfs
	Out     io.Writer          // progress: the writer's line per batch; nil discards

	BatchSize uint64 // entries per committed batch; default DefaultBatchSize
	// Dependencies are module versions for the provenance when the binary's
	// build info lists none (a go test binary): the caller reads go.mod.
	Dependencies map[string]string
	// Tests shrink these; zero means the production values.
	DictSamples   int
	CanarySamples int
}

// Paths are a written report's files.
type Paths struct{ JSON, Markdown string }

// Run measures s, writes the report under o.Base/reports/<sample-id>/ and
// returns it. The workspace is removed whatever happens; a run that fails
// or is interrupted writes no report.
func Run(ctx context.Context, s *sample.Sample, o Options) (Report, Paths, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Out == nil {
		o.Out = io.Discard
	}
	if o.BatchSize == 0 {
		o.BatchSize = DefaultBatchSize
	}
	if err := ctx.Err(); err != nil {
		return Report{}, Paths{}, err
	}
	sv, err := surveySample(ctx, s, o.BatchSize)
	if err != nil {
		return Report{}, Paths{}, err
	}
	ws, err := workspace(o.Base)
	if err != nil {
		return Report{}, Paths{}, err
	}
	defer os.RemoveAll(ws)
	res, err := ingestAll(ctx, s, o, ws, sv)
	if err != nil {
		return Report{}, Paths{}, err
	}
	r := build(s, o, sv, res)
	p, err := write(o.Base, r)
	return r, p, err
}

// survey is what one pass over the sample's own entries finds: the facts
// the writer does not record (links, delays, duplicates, error codes) and
// the Merkle root at every batch end.
type survey struct {
	heads []logsource.SignedHead // one per batch: its end and the root there

	types      map[string]int    // entry types
	codes      map[leaf.Code]int // leaf error codes
	leafType   map[[32]byte]string
	chainCerts map[[32]byte]bool
	leafCerts  int
	chainRefs  int

	finals, linked, eligible int
	precertLater             int     // finals whose precert comes later in the window
	delays                   []int64 // ms from a precert to its final certificate
}

// surveySample decodes every entry in index order. The roots it records at
// batch ends come from leaves that sample.Open verified against the signed
// head; the writer recomputes them from the replayed entries, so each batch
// is still Merkle-verified (a representative sample has a consistency proof
// only at the end of its window).
func surveySample(ctx context.Context, s *sample.Sample, batch uint64) (*survey, error) {
	st, err := s.StartState()
	if err != nil {
		return nil, err
	}
	m := s.Manifest
	end := m.Start + m.Count
	sv := &survey{types: map[string]int{}, codes: map[leaf.Code]int{}, leafType: map[[32]byte]string{}, chainCerts: map[[32]byte]bool{}}
	precertAt := map[[32]byte]uint64{} // issuance digest → the first precert's timestamp
	var unlinked [][32]byte            // finals met before any precert of theirs
	err = s.Each(func(e sample.Entry) error {
		if err := st.Append(merkle.LeafHash(e.LeafInput)); err != nil {
			return err
		}
		l := leaf.Decode(e.LeafInput, e.ExtraData)
		sv.types[l.Type.String()]++
		if l.Code != leaf.OK {
			sv.codes[l.Code]++
		}
		newCert := false
		if l.CertDER != nil {
			sv.leafCerts++
			sha := sha256.Sum256(l.CertDER)
			if _, seen := sv.leafType[sha]; !seen {
				sv.leafType[sha], newCert = l.Type.String(), true
			}
		}
		for _, c := range l.Chain {
			sv.chainRefs++
			sv.chainCerts[sha256.Sum256(c)] = true
		}
		if l.HasIssuanceDigest {
			switch l.Type {
			case leaf.TypePrecert:
				if _, ok := precertAt[l.IssuanceDigest]; !ok {
					precertAt[l.IssuanceDigest] = l.Timestamp
				}
			case leaf.TypeX509:
				sv.finals++
				if ts, ok := precertAt[l.IssuanceDigest]; ok {
					sv.linked++
					sv.delays = append(sv.delays, int64(l.Timestamp)-int64(ts))
					if newCert {
						sv.eligible++
					}
				} else {
					unlinked = append(unlinked, l.IssuanceDigest)
				}
			}
		}
		if n := e.Index + 1; (n-m.Start)%batch == 0 || n == end {
			root, err := st.Root()
			if err != nil {
				return err
			}
			h := logsource.SignedHead{}
			h.TreeSize, h.RootHash, h.Timestamp = n, root, m.Head.Timestamp
			sv.heads = append(sv.heads, h)
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		return nil
	})
	for _, d := range unlinked {
		if _, ok := precertAt[d]; ok {
			sv.precertLater++
		}
	}
	return sv, err
}

// workspace creates <base>/tmp/measure-<pid> with a vault's folder layout
// (no VAULT_ID: it is never a vault), after removing the workspaces of
// processes that no longer run (a killed measurement).
func workspace(base string) (string, error) {
	tmp := filepath.Join(base, "tmp")
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return "", err
	}
	names, err := filepath.Glob(filepath.Join(tmp, "measure-*"))
	if err != nil {
		return "", err
	}
	for _, n := range names {
		pid, err := strconv.Atoi(strings.TrimPrefix(filepath.Base(n), "measure-"))
		if err == nil && pid > 0 && errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
			if err := os.RemoveAll(n); err != nil {
				return "", err
			}
		}
	}
	ws := filepath.Join(tmp, fmt.Sprintf("measure-%d", os.Getpid()))
	if err := os.RemoveAll(ws); err != nil {
		return "", err
	}
	for _, d := range []string{"state/intent", "state/incidents", "state/logs", "vault/segments", "vault/dict", "dataset", "tmp/stage", "tmp/rebuild"} {
		if err := os.MkdirAll(filepath.Join(ws, d), 0o755); err != nil {
			return "", err
		}
	}
	return ws, nil
}

// result is what the ingest left in the workspace.
type result struct {
	manifests []commit.Manifest
	seconds   []float64 // per batch
	pebble    int64     // state/pebble after the writer closed
	segments  int64     // segment files, headers included
	groups    map[groupKey]*Group
	deltas    map[uint64]*DeltaSaving // by the dictionary of the delta's batch
	chainRecs int
}

type groupKey struct {
	kind      string
	dict      uint64
	entryType string
}

// ingestAll commits the sample batch by batch through the production writer,
// fed by the sample's replay over loopback, then scans what it wrote.
func ingestAll(ctx context.Context, s *sample.Sample, o Options, ws string, sv *survey) (*result, error) {
	url, stop, err := sample.Serve(ctx, s)
	if err != nil {
		return nil, err
	}
	defer stop()
	chains := logsource.NewChainCache(logsource.DefaultChainCacheBytes)
	src := rfc6962.NewSource(s.LogInfo(url), &http.Client{Timeout: 60 * time.Second}, chains, nil)

	cfg := config.Default()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	dirs := []string{filepath.Join(ws, "vault")}
	w, err := ingest.Open(ingest.Options{Root: ws, VaultDirs: dirs, VaultUUID: id, Config: cfg,
		Guard: diskguard.Guard{Cap: cfg.Disk.MaxUsedFraction, Stat: o.Stat}, Version: o.Version, Now: o.Now, Out: o.Out,
		Fetch: fetch.Options{Workers: cfg.Ingest.Workers, MaxRPS: replayRPS, PageSize: s.Manifest.PageSize,
			StallTimeout: cfg.Ingest.StallTimeout.Duration, MaxBufferedEntries: cfg.Fetch.MaxBufferedEntries,
			MaxBufferedBytes: int(cfg.Fetch.MaxBufferedBytes)},
		DictSamples: o.DictSamples, CanarySamples: o.CanarySamples})
	if err != nil {
		return nil, err
	}
	defer w.Close()
	m := s.Manifest
	if m.Kind == sample.Representative {
		st, err := s.StartState()
		if err != nil {
			return nil, err
		}
		if err := w.Seed(m.Log.Name, st); err != nil {
			return nil, err
		}
	}
	res := &result{groups: map[groupKey]*Group{}, deltas: map[uint64]*DeltaSaving{}}
	first := m.Start
	for _, h := range sv.heads {
		t0 := time.Now()
		if _, err := w.Batch(ctx, src, h, first, h.TreeSize); err != nil {
			return nil, err
		}
		chains.Reset()
		res.seconds = append(res.seconds, time.Since(t0).Seconds())
		first = h.TreeSize
	}
	res.manifests = w.Committed()
	if err := w.Close(); err != nil {
		return nil, err
	}
	res.pebble = dirSize(filepath.Join(ws, "state", "pebble"))
	res.segments = dirSize(filepath.Join(ws, "vault", "segments"))
	return res, scanVault(dirs, sv, res)
}

// scanVault reads back every record the run wrote, grouped by record kind,
// dictionary and entry type, and prices each leaf-delta record against the
// same certificate stored in full with the batch's dictionary.
func scanVault(dirs []string, sv *survey, res *result) error {
	codec, err := vault.NewCodec()
	if err != nil {
		return err
	}
	defer codec.Close()
	dicts, err := vault.LoadDicts(dirs)
	if err != nil {
		return err
	}
	for _, d := range dicts {
		if err := codec.AddDict(d.Manifest.ID, d.Content); err != nil {
			return err
		}
	}
	r, err := vault.OpenReader(dirs, codec)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, m := range res.manifests {
		err := vault.Scan(dirs, m.Vault.Start, m.Vault.End, func(loc vault.Loc, rec vault.Record) error {
			der, _, err := r.Read(loc)
			if err != nil {
				return err
			}
			sha := sha256.Sum256(der)
			k := groupKey{dict: rec.DictID}
			switch rec.Kind {
			case vault.KindChain:
				if !sv.chainCerts[sha] {
					return fmt.Errorf("vault record %d:%d is a chain certificate the sample does not hold", loc.Segment, loc.Offset)
				}
				k.kind, k.entryType = "chain", "chain"
				res.chainRecs++
			case vault.KindLeaf, vault.KindDelta:
				t, ok := sv.leafType[sha]
				if !ok {
					return fmt.Errorf("vault record %d:%d is a certificate the sample does not hold", loc.Segment, loc.Offset)
				}
				k.kind, k.entryType = "leaf", t
				if rec.Kind == vault.KindDelta {
					k.kind, k.dict = "delta", m.Dictionary.ID
					full, err := codec.Compress(der, m.Dictionary.ID)
					if err != nil {
						return err
					}
					ds := res.deltas[m.Dictionary.ID]
					if ds == nil {
						ds = &DeltaSaving{Dictionary: m.Dictionary.ID}
						res.deltas[m.Dictionary.ID] = ds
					}
					ds.Records++
					ds.StoredBytes += uint64(len(rec.Frame))
					ds.FullBytes += uint64(len(full))
				}
			}
			g := res.groups[k]
			if g == nil {
				g = &Group{Kind: k.kind, Dictionary: k.dict, EntryType: k.entryType}
				res.groups[k] = g
			}
			g.Records++
			g.RawBytes += uint64(len(der))
			g.StoredBytes += uint64(rec.TotalLen)
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func dirSize(dir string) int64 {
	var n int64
	filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}
```

Create `internal/measure/report.go`:

```go
//go:build ctvault_dev || realdata

package measure

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/sample"
	"github.com/4rji/ctvault/internal/vault"
)

// ReportFormat is the report's JSON format version.
const ReportFormat = 1

// Report is one measurement (amendment A1 §8). Bytes per entry divide by
// the sample's entries.
type Report struct {
	Format      int         `json:"format"`
	Provenance  Provenance  `json:"provenance"`
	Sample      SampleInfo  `json:"sample"`
	Run         RunInfo     `json:"run"`
	Sizes       Sizes       `json:"bytes_per_entry"`
	Compression Compression `json:"compression"`
	Links       Links       `json:"links"`
	Dedup       Dedup       `json:"dedup"`
	Errors      Errors      `json:"errors"`
	Batches     []Batch     `json:"batches"`
	Notes       []string    `json:"notes"`
}

// Provenance says what produced the numbers.
type Provenance struct {
	CTVaultVersion   string            `json:"ctvault_version"`
	Module           string            `json:"module"` // path and version from the Go build info
	VCSRevision      string            `json:"vcs_revision,omitempty"`
	VCSModified      bool              `json:"vcs_modified,omitempty"`
	GoVersion        string            `json:"go_version"`
	Dependencies     map[string]string `json:"dependencies"`
	DependenciesFrom string            `json:"dependencies_from"` // "build info", or "go.mod" for a test binary
	ZstdLibrary      string            `json:"zstd_library"`
	ReportedAt       time.Time         `json:"reported_at"`
}

// SampleInfo identifies the measured sample.
type SampleInfo struct {
	ID           string    `json:"id"`
	Kind         string    `json:"kind"`
	Log          string    `json:"log"`
	Start        uint64    `json:"start"`
	Count        uint64    `json:"count"`
	CapturedAt   time.Time `json:"captured_at"`
	HeadTreeSize uint64    `json:"head_tree_size"`
}

// RunInfo describes the run.
type RunInfo struct {
	BatchSize        uint64         `json:"batch_size"`
	Batches          int            `json:"batches"`
	IngestSeconds    float64        `json:"ingest_seconds"`
	EntriesPerSecond float64        `json:"entries_per_second"`
	DictSamples      int            `json:"dict_samples"`
	DeltaWarmBatches int            `json:"delta_warm_batches"`
	DeltaLRUEntries  int            `json:"delta_lru_entries"`
	EntryTypes       map[string]int `json:"entry_types"`
}

// Sizes are bytes per entry.
type Sizes struct {
	Vault               float64            `json:"vault"`       // record bytes
	VaultFiles          float64            `json:"vault_files"` // segment files, headers included
	VaultWithDictionary float64            `json:"vault_with_dictionary"`
	Parquet             float64            `json:"parquet"`
	ParquetByFile       map[string]float64 `json:"parquet_by_file"`
	Pebble              float64            `json:"pebble"` // state/pebble after close, WAL included
	Total               float64            `json:"total"`  // vault files + Parquet + Pebble
	SeedVault           int                `json:"seed_vault"`
	SeedParquet         int                `json:"seed_parquet"`
	SeedPebble          int                `json:"seed_pebble"`
}

// Group is one kind of vault record: full leaf, leaf-delta or chain, by
// dictionary (for deltas, the dictionary its batch used) and entry type.
type Group struct {
	Kind        string  `json:"kind"`
	Dictionary  uint64  `json:"dictionary"`
	EntryType   string  `json:"entry_type"`
	Records     int     `json:"records"`
	RawBytes    uint64  `json:"raw_bytes"`    // DER
	StoredBytes uint64  `json:"stored_bytes"` // whole records
	Ratio       float64 `json:"ratio"`
	MeanStored  float64 `json:"mean_stored"`
}

// DeltaSaving prices leaf-delta frames against the same certificates
// compressed in full with their batch's dictionary.
type DeltaSaving struct {
	Dictionary  uint64  `json:"dictionary"`
	Records     int     `json:"records"`
	StoredBytes uint64  `json:"stored_frame_bytes"`
	FullBytes   uint64  `json:"full_frame_bytes"`
	Saving      float64 `json:"saving"`
}

// Gap compares a measured value with the spec's figure. Gap is negative
// when the measurement is worse; Exceeds flags more than 10% worse
// (amendment A1 §5).
type Gap struct {
	What     string  `json:"what"`
	Spec     float64 `json:"spec"`
	Measured float64 `json:"measured"`
	Gap      float64 `json:"gap"`
	Exceeds  bool    `json:"exceeds_10_percent"`
}

// Compression is the vault's compression, overall and per group.
type Compression struct {
	RawBytes    uint64        `json:"raw_bytes"`
	StoredBytes uint64        `json:"stored_bytes"`
	Ratio       float64       `json:"ratio"`
	Groups      []Group       `json:"groups"`
	Deltas      []DeltaSaving `json:"leaf_delta"` // by dictionary
	Spec        []Gap         `json:"spec_gaps"`
}

// Delays are nearest-rank percentiles in milliseconds.
type Delays struct {
	P50 int64 `json:"p50"`
	P95 int64 `json:"p95"`
	P99 int64 `json:"p99"`
}

// Links are the precert→final relationships seen in the window.
type Links struct {
	Finals        int     `json:"finals"`         // x509 entries with an issuance key
	Linked        int     `json:"linked"`         // ... whose precert is earlier in the window
	PrecertLater  int     `json:"precert_later"`  // ... whose precert comes later in the window
	LinkRate      float64 `json:"link_rate"`      // linked / finals
	DeltaEligible int     `json:"delta_eligible"` // linked finals vaulted for the first time
	DeltaRecords  int     `json:"delta_records"`
	DeltaHitRate  float64 `json:"delta_hit_rate"` // delta records / eligible
	DelayMS       Delays  `json:"delay_ms"`       // linked final's timestamp minus its precert's
}

// Dedup counts certificates already vaulted when they were met again.
type Dedup struct {
	LeafCerts       int     `json:"leaf_certs"`
	UniqueLeafCerts int     `json:"unique_leaf_certs"`
	LeafHits        int     `json:"leaf_hits"`
	LeafHitRate     float64 `json:"leaf_hit_rate"`
	ChainRefs       int     `json:"chain_refs"`
	ChainRecords    int     `json:"chain_records"`
	ChainHitRate    float64 `json:"chain_hit_rate"`
}

// Errors are the leaf error codes (spec §5.4, amendment A1 §4): leaf
// structure codes, and semantic ones (extra_data, chain and precert checks).
type Errors struct {
	Total      int            `json:"total"`
	Structural int            `json:"structural"`
	Semantic   int            `json:"semantic"`
	ByCode     map[string]int `json:"by_code"`
	Committed  int            `json:"committed"` // the manifests' leaf_errors, which must equal Total
}

// Batch is one committed batch.
type Batch struct {
	First         uint64  `json:"first"`
	Last          uint64  `json:"last"`
	Entries       int     `json:"entries"`
	NewCerts      int     `json:"new_certs"`
	DeltaRecords  int     `json:"delta_records"`
	LeafErrors    int     `json:"leaf_errors"`
	VaultBytes    uint64  `json:"vault_bytes"`
	ParquetBytes  int64   `json:"parquet_bytes"`
	Dictionary    uint64  `json:"dictionary"`
	TrainingError string  `json:"training_error,omitempty"`
	Seconds       float64 `json:"seconds"`
}

// The spec's figures (§3.4 with C zstd level 19, §10.2).
const (
	specDictRatio   = 1.96  // per certificate, 110 KB dictionary, contiguous sample
	specNoDictRatio = 1.21  // per certificate, no dictionary
	specDeltaSaving = 0.171 // final certificate against its own precert
	specVaultBudget = 765   // §10.2 vault B/entry, upper end
)

func ratio(a, b uint64) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func perEntry(n int64, entries uint64) float64 {
	if entries == 0 {
		return 0
	}
	return float64(n) / float64(entries)
}

// gap compares measured with spec; for a size (higherIsBetter false) more
// bytes is worse.
func gap(what string, spec, measured float64, higherIsBetter bool) Gap {
	g := Gap{What: what, Spec: spec, Measured: measured}
	if spec > 0 && measured > 0 {
		if higherIsBetter {
			g.Gap = measured/spec - 1
		} else {
			g.Gap = spec/measured - 1
		}
		g.Exceeds = g.Gap < 1/1.1-1
	}
	return g
}

// percentiles returns nearest-rank percentiles of v (which it sorts).
func percentiles(v []int64) Delays {
	if len(v) == 0 {
		return Delays{}
	}
	slices.Sort(v)
	at := func(p int) int64 { return v[max(0, (p*len(v)+99)/100-1)] }
	return Delays{P50: at(50), P95: at(95), P99: at(99)}
}

// reportedDeps are the dependencies amendment A1 §8 names.
var reportedDeps = []string{"github.com/duckdb/duckdb-go/v2", "github.com/cockroachdb/pebble/v2", "github.com/klauspost/compress", "github.com/transparency-dev/merkle"}

// provenance reads the Go build info. A go test binary's build info lists
// no dependencies; fallback (read from go.mod by the caller) fills them in,
// and the report says where they came from.
func provenance(version string, now time.Time, fallback map[string]string) Provenance {
	p := Provenance{CTVaultVersion: version, Dependencies: map[string]string{}, ZstdLibrary: vault.LibraryVersion(), ReportedAt: now.UTC()}
	if bi, ok := debug.ReadBuildInfo(); ok {
		p.Module, p.GoVersion = bi.Main.Path+"@"+bi.Main.Version, bi.GoVersion
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				p.VCSRevision = s.Value
			case "vcs.modified":
				p.VCSModified = s.Value == "true"
			}
		}
		for _, d := range bi.Deps {
			if slices.Contains(reportedDeps, d.Path) {
				p.Dependencies[d.Path] = d.Version
			}
		}
	}
	if len(p.Dependencies) > 0 {
		p.DependenciesFrom = "build info"
		return p
	}
	for _, path := range reportedDeps {
		if v, ok := fallback[path]; ok {
			p.Dependencies[path], p.DependenciesFrom = v, "go.mod"
		}
	}
	if v, ok := p.Dependencies["github.com/klauspost/compress"]; ok {
		p.ZstdLibrary = "github.com/klauspost/compress " + v
	}
	return p
}

func build(s *sample.Sample, o Options, sv *survey, res *result) Report {
	m := s.Manifest
	n := m.Count
	cfg := res.manifests // shorthand below
	r := Report{Format: ReportFormat, Provenance: provenance(o.Version, o.Now(), o.Dependencies),
		Sample: SampleInfo{ID: m.ID(filepath.Base(s.Dir)), Kind: string(m.Kind), Log: m.Log.Name, Start: m.Start, Count: n,
			CapturedAt: m.CapturedAt, HeadTreeSize: s.Head.TreeSize}}
	dictSamples := o.DictSamples
	if dictSamples == 0 {
		dictSamples = vault.TrainingSamples
	}
	def := defaultsForReport()
	r.Run = RunInfo{BatchSize: o.BatchSize, Batches: len(cfg), DictSamples: dictSamples, DeltaWarmBatches: def.warm,
		DeltaLRUEntries: def.lru, EntryTypes: sv.types}

	var vaultBytes, dictVault, dictEntries uint64
	var parquet int64
	byFile := map[string]int64{}
	committedErrors := 0
	for i, mf := range cfg {
		var pq int64
		for name, f := range mf.Files {
			pq += f.Bytes
			byFile[name] += f.Bytes
		}
		r.Batches = append(r.Batches, Batch{First: mf.First, Last: mf.Last, Entries: mf.Counts.Entries, NewCerts: mf.Counts.NewCerts,
			DeltaRecords: mf.Counts.DeltaRecords, LeafErrors: mf.Counts.LeafErrors, VaultBytes: mf.Counts.VaultBytes,
			ParquetBytes: pq, Dictionary: mf.Dictionary.ID, TrainingError: mf.Dictionary.TrainingError, Seconds: res.seconds[i]})
		r.Run.IngestSeconds += res.seconds[i]
		vaultBytes += mf.Counts.VaultBytes
		parquet += pq
		committedErrors += mf.Counts.LeafErrors
		if mf.Dictionary.ID > 0 {
			dictVault += mf.Counts.VaultBytes
			dictEntries += uint64(mf.Counts.Entries)
		}
	}
	if r.Run.IngestSeconds > 0 {
		r.Run.EntriesPerSecond = float64(n) / r.Run.IngestSeconds
	}
	z := Sizes{Vault: perEntry(int64(vaultBytes), n), VaultFiles: perEntry(res.segments, n), Parquet: perEntry(parquet, n),
		ParquetByFile: map[string]float64{}, Pebble: perEntry(res.pebble, n), SeedVault: diskguard.SeedVaultBytesPerEntry,
		SeedParquet: diskguard.SeedParquetBytesPerEntry, SeedPebble: diskguard.SeedPebbleBytesPerEntry}
	if dictEntries > 0 {
		z.VaultWithDictionary = float64(dictVault) / float64(dictEntries)
	}
	for name, b := range byFile {
		z.ParquetByFile[name] = perEntry(b, n)
	}
	z.Total = z.VaultFiles + z.Parquet + z.Pebble
	r.Sizes = z

	var c Compression
	var dictRaw, dictStored, plainRaw, plainStored uint64
	for _, g := range res.groups {
		g.Ratio, g.MeanStored = ratio(g.RawBytes, g.StoredBytes), float64(g.StoredBytes)/float64(g.Records)
		c.Groups = append(c.Groups, *g)
		c.RawBytes += g.RawBytes
		c.StoredBytes += g.StoredBytes
		if g.Kind == "leaf" && g.Dictionary > 0 {
			dictRaw, dictStored = dictRaw+g.RawBytes, dictStored+g.StoredBytes
		}
		if g.Kind == "leaf" && g.Dictionary == 0 {
			plainRaw, plainStored = plainRaw+g.RawBytes, plainStored+g.StoredBytes
		}
	}
	slices.SortFunc(c.Groups, func(a, b Group) int {
		return strings.Compare(fmt.Sprintf("%s/%d/%s", a.Kind, a.Dictionary, a.EntryType), fmt.Sprintf("%s/%d/%s", b.Kind, b.Dictionary, b.EntryType))
	})
	c.Ratio = ratio(c.RawBytes, c.StoredBytes)
	var withDict DeltaSaving
	for _, ds := range res.deltas {
		ds.Saving = 1 - ratio(ds.StoredBytes, ds.FullBytes)
		c.Deltas = append(c.Deltas, *ds)
		if ds.Dictionary > 0 {
			withDict.Records += ds.Records
			withDict.StoredBytes += ds.StoredBytes
			withDict.FullBytes += ds.FullBytes
		}
	}
	slices.SortFunc(c.Deltas, func(a, b DeltaSaving) int { return int(a.Dictionary) - int(b.Dictionary) })
	steady := z.VaultWithDictionary
	if steady == 0 {
		steady = z.Vault
	}
	c.Spec = append(c.Spec, gap("vault bytes per entry (spec §10.2 budget, upper end)", specVaultBudget, steady, false))
	if dictStored > 0 {
		c.Spec = append(c.Spec, gap("full leaf records with a dictionary, ratio (spec §3.4, contiguous sample)", specDictRatio, ratio(dictRaw, dictStored), true))
	}
	if plainStored > 0 {
		c.Spec = append(c.Spec, gap("full leaf records without a dictionary, ratio (spec §3.4)", specNoDictRatio, ratio(plainRaw, plainStored), true))
	}
	if withDict.Records > 0 { // the spec's figure is against a dictionary-compressed final certificate
		c.Spec = append(c.Spec, gap("leaf-delta saving over a full record with a dictionary (spec §3.4)", specDeltaSaving,
			1-ratio(withDict.StoredBytes, withDict.FullBytes), true))
	}
	r.Compression = c

	deltaRecords := 0
	for _, mf := range cfg {
		deltaRecords += mf.Counts.DeltaRecords
	}
	r.Links = Links{Finals: sv.finals, Linked: sv.linked, PrecertLater: sv.precertLater, LinkRate: ratio(uint64(sv.linked), uint64(sv.finals)),
		DeltaEligible: sv.eligible, DeltaRecords: deltaRecords, DeltaHitRate: ratio(uint64(deltaRecords), uint64(sv.eligible)),
		DelayMS: percentiles(sv.delays)}
	unique := len(sv.leafType)
	r.Dedup = Dedup{LeafCerts: sv.leafCerts, UniqueLeafCerts: unique, LeafHits: sv.leafCerts - unique,
		LeafHitRate: ratio(uint64(sv.leafCerts-unique), uint64(sv.leafCerts)), ChainRefs: sv.chainRefs, ChainRecords: res.chainRecs,
		ChainHitRate: ratio(uint64(sv.chainRefs-res.chainRecs), uint64(sv.chainRefs))}
	e := Errors{ByCode: map[string]int{}, Committed: committedErrors}
	for code, k := range sv.codes {
		e.ByCode[string(code)] = k
		e.Total += k
		if code.LeafStructure() {
			e.Structural += k
		} else {
			e.Semantic += k
		}
	}
	r.Errors = e
	r.Notes = notes(r, m)
	return r
}

// defaults are the delta settings every run uses: config.Default's.
type defaults struct{ warm, lru int }

func defaultsForReport() defaults {
	c := config.Default()
	return defaults{warm: c.Delta.WarmBatches, lru: c.Ingest.DeltaLRUEntries}
}

func notes(r Report, m sample.Manifest) []string {
	var out []string
	switch m.Kind {
	case sample.Canonical:
		out = append(out, "Canonical sample: the start of a shard is not representative (amendment A1 §2.1); tune seeds and defaults from a representative sample.")
	case sample.Representative:
		out = append(out, fmt.Sprintf("Representative sample: the window starts mid-log at index %d, so precerts logged before it are unknown. Early finals cannot link or delta-encode, and dedup sees only the window.", m.Start))
	}
	dict := false
	for i, b := range r.Batches {
		dict = dict || b.Dictionary > 0
		if i > 0 && b.Dictionary != r.Batches[i-1].Dictionary {
			out = append(out, fmt.Sprintf("batch %d-%d trained dictionary %d before it started; its %.1f s include the training.", b.First, b.Last, b.Dictionary, b.Seconds))
		}
		if b.TrainingError != "" {
			out = append(out, fmt.Sprintf("Dictionary training failed in batch %d-%d: %s", b.First, b.Last, b.TrainingError))
		}
	}
	if !dict {
		out = append(out, fmt.Sprintf("No batch used a trained dictionary: dictionary 1 trains once %d full leaf records are committed, before a later batch starts.", r.Run.DictSamples))
	}
	for _, g := range r.Compression.Spec {
		if g.Exceeds {
			out = append(out, fmt.Sprintf("%s: measured %.3g against the spec's %.3g, more than 10%% worse; Plan 3 decides on any change (amendment A1 §5).", g.What, g.Measured, g.Spec))
		}
	}
	if r.Errors.Total != r.Errors.Committed {
		out = append(out, fmt.Sprintf("The survey found %d leaf errors but the batches committed %d.", r.Errors.Total, r.Errors.Committed))
	}
	out = append(out, "The spec's compression figures are C zstd level 19. The vault uses pure-Go klauspost/compress: full records at SpeedBetterCompression, deltas at SpeedDefault.",
		"This report changes nothing. Disk-guard seeds and the delta warm-up default change only by a reviewed edit (amendment A1 §8).")
	return out
}

// write stores r as <base>/reports/<sample-id>/<UTC time>.json, plus a
// Markdown summary next to it. An existing report is never overwritten.
func write(base string, r Report) (Paths, error) {
	dir := filepath.Join(base, "reports", filepath.FromSlash(r.Sample.ID))
	if err := fsutil.MkdirAllSync(dir, 0o755); err != nil {
		return Paths{}, err
	}
	stem := r.Provenance.ReportedAt.Format("20060102T150405Z")
	for i := 2; ; i++ {
		_, err := os.Stat(filepath.Join(dir, stem+".json"))
		if errors.Is(err, fs.ErrNotExist) {
			break
		}
		if err != nil {
			return Paths{}, err
		}
		stem = fmt.Sprintf("%s-%d", r.Provenance.ReportedAt.Format("20060102T150405Z"), i)
	}
	b, err := json.MarshalIndent(r, "", " ")
	if err != nil {
		return Paths{}, err
	}
	p := Paths{JSON: filepath.Join(dir, stem+".json"), Markdown: filepath.Join(dir, stem+".md")}
	if err := fsutil.WriteFileAtomic(p.JSON, append(b, '\n'), 0o644); err != nil {
		return Paths{}, err
	}
	return p, fsutil.WriteFileAtomic(p.Markdown, []byte(Markdown(r)), 0o644)
}

// Markdown is a short human summary of r.
func Markdown(r Report) string {
	var b strings.Builder
	f := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	z, c, l, d := r.Sizes, r.Compression, r.Links, r.Dedup
	f("# Measurement: %s\n\n", r.Sample.ID)
	f("- Sample: %s, entries [%d, %d) of %s, captured %s\n", r.Sample.Kind, r.Sample.Start, r.Sample.Start+r.Sample.Count, r.Sample.Log, r.Sample.CapturedAt.UTC().Format(time.RFC3339))
	rev := "revision " + r.Provenance.VCSRevision
	if r.Provenance.VCSRevision == "" {
		rev = "no VCS revision"
	} else if r.Provenance.VCSModified {
		rev += ", modified"
	}
	f("- CTVault %s (%s, %s), %s, %s\n", r.Provenance.CTVaultVersion, r.Provenance.Module, rev, r.Provenance.GoVersion, r.Provenance.ZstdLibrary)
	deps := []string{}
	for _, d := range reportedDeps {
		if v, ok := r.Provenance.Dependencies[d]; ok {
			deps = append(deps, d+" "+v)
		}
	}
	f("- Dependencies (from %s): %s\n", r.Provenance.DependenciesFrom, strings.Join(deps, ", "))
	f("- Run: %d batches of %d, %.1f s of ingest (%.0f entries/s), reported %s\n\n", r.Run.Batches, r.Run.BatchSize, r.Run.IngestSeconds, r.Run.EntriesPerSecond, r.Provenance.ReportedAt.Format(time.RFC3339))
	f("## Bytes per entry\n\n| Component | Measured | Disk-guard seed |\n|---|---|---|\n")
	f("| Vault (records) | %.1f | %d |\n| Vault (segment files) | %.1f | |\n| Vault, batches with a dictionary | %.1f | |\n", z.Vault, z.SeedVault, z.VaultFiles, z.VaultWithDictionary)
	f("| Parquet | %.1f | %d |\n| Pebble | %.1f | %d |\n| **Total** | **%.1f** | %d |\n\n", z.Parquet, z.SeedParquet, z.Pebble, z.SeedPebble, z.Total, z.SeedVault+z.SeedParquet+z.SeedPebble)
	f("## Compression\n\nOverall %.2f× (%d raw DER bytes in %d record bytes).\n\n| Records | Dictionary | Entry type | Count | Ratio | Mean bytes |\n|---|---|---|---|---|---|\n", c.Ratio, c.RawBytes, c.StoredBytes)
	for _, g := range c.Groups {
		f("| %s | %d | %s | %d | %.2f× | %.0f |\n", g.Kind, g.Dictionary, g.EntryType, g.Records, g.Ratio, g.MeanStored)
	}
	f("\n")
	for _, ds := range c.Deltas {
		f("leaf-delta in batches with dictionary %d: %d records, %.1f%% smaller than the same certificates stored in full.\n", ds.Dictionary, ds.Records, 100*ds.Saving)
	}
	f("\n| Against the spec | Spec | Measured | Gap | More than 10%% worse |\n|---|---|---|---|---|\n")
	for _, g := range c.Spec {
		f("| %s | %.3g | %.3g | %+.1f%% | %v |\n", g.What, g.Spec, g.Measured, 100*g.Gap, g.Exceeds)
	}
	f("\n## Links, dedup and errors\n\n")
	f("- precert→final: %d of %d finals link (%.1f%%), %d more have their precert later in the window; delay p50 %s, p95 %s, p99 %s\n", l.Linked, l.Finals, 100*l.LinkRate, l.PrecertLater,
		time.Duration(l.DelayMS.P50)*time.Millisecond, time.Duration(l.DelayMS.P95)*time.Millisecond, time.Duration(l.DelayMS.P99)*time.Millisecond)
	f("- leaf-delta hit rate: %d of %d eligible finals (%.1f%%)\n", l.DeltaRecords, l.DeltaEligible, 100*l.DeltaHitRate)
	f("- dedup: leaf %d of %d (%.2f%%), chain %d of %d references (%.2f%%)\n", d.LeafHits, d.LeafCerts, 100*d.LeafHitRate, d.ChainRefs-d.ChainRecords, d.ChainRefs, 100*d.ChainHitRate)
	f("- leaf errors: %d (%d structural, %d semantic) %v\n\n", r.Errors.Total, r.Errors.Structural, r.Errors.Semantic, r.Errors.ByCode)
	f("## Batches\n\n| Range | Entries | New certs | Deltas | Vault B/entry | Parquet B/entry | Dictionary | Seconds |\n|---|---|---|---|---|---|---|---|\n")
	for _, x := range r.Batches {
		f("| %d-%d | %d | %d | %d | %.1f | %.1f | %d | %.1f |\n", x.First, x.Last, x.Entries, x.NewCerts, x.DeltaRecords,
			perEntry(int64(x.VaultBytes), uint64(x.Entries)), perEntry(x.ParquetBytes, uint64(x.Entries)), x.Dictionary, x.Seconds)
	}
	f("\n## Notes\n\n")
	for _, n := range r.Notes {
		f("- %s\n", n)
	}
	return b.String()
}
```

Replace `internal/cli/sample_dev.go` with:

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
	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/loglist"
	"github.com/4rji/ctvault/internal/logreg"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/measure"
	"github.com/4rji/ctvault/internal/sample"
	"github.com/4rji/ctvault/internal/stop"
)

func init() { extraCommands = append(extraCommands, newSampleCmd) }

// sampleLimits are amendment A1 §2.1's rules; tests in this package shrink
// them. There is no flag or environment variable for them.
var sampleLimits = sample.DefaultLimits

func newSampleCmd(a *app) *cobra.Command {
	return groupCmd("sample", "Capture, verify and measure real-data samples (dev build only)",
		sampleCaptureCmd(a), sampleVerifyCmd(a), sampleMeasureCmd(a))
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

			// On a fresh machine the dev base does not exist yet; create the
			// samples folder (inside the base) so the disk check can stat it.
			samples := filepath.Join(a.d.DevBase, "samples")
			if err := fsutil.MkdirAllSync(samples, 0o700); err != nil {
				return err
			}
			guard := diskguard.Guard{Cap: o.Disk.MaxUsedFraction, Stat: a.d.Statfs}
			opts.Check = func(need int64) error { return guard.Check(samples, uint64(need)) }
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

func sampleMeasureCmd(a *app) *cobra.Command {
	var batch uint64
	cmd := &cobra.Command{
		Use:   "measure <sample dir> [--batch-size N]",
		Short: "Run a sample through the per-entry pipeline in a throwaway workspace and write a measurement report",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(c *cobra.Command, args []string) error {
			if a.d.DevBase == "" {
				return errors.New("no dev base folder")
			}
			if batch == 0 || batch > 500000 {
				return exitcode.Withf(exitcode.Usage, "--batch-size must be 1-500,000, got %d", batch)
			}
			s, err := sample.Open(args[0])
			if err != nil {
				return sampleErr(err)
			}
			errOut := c.ErrOrStderr()
			stops := stop.OnSignals(c.Context(), func() {
				fmt.Fprintln(errOut, "interrupted: stopping the measurement; no report will be written")
			}, nil)
			defer stops.Close()
			r, p, err := measure.Run(stops.Soft, s, measure.Options{Base: a.d.DevBase, Version: a.d.Version, Now: a.d.Now,
				Stat: a.d.Statfs, Out: errOut, BatchSize: batch})
			if err != nil {
				return ingestErr(sampleErr(err))
			}
			out := c.OutOrStdout()
			fmt.Fprint(out, measure.Markdown(r))
			fmt.Fprintf(out, "\nreport: %s\nsummary: %s\n", p.JSON, p.Markdown)
			return nil
		},
	}
	cmd.Flags().Uint64Var(&batch, "batch-size", measure.DefaultBatchSize, "entries per committed batch")
	return cmd
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

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race -tags ctvault_dev ./internal/ingest/ ./internal/measure/ ./internal/cli/`
Expected: PASS.

**Check that the tests can fail.** Each of these mutations, in a scratch copy, must fail `TestMeasureCanonical` or `TestMeasureLeavesNothingOnFailure`:
- counting every linked final as delta-eligible: "DeltaEligible:48"
- not removing the workspace: "workspace left behind"
- labelling delta records as full leaf records: "92 full leaf + 0 delta"
- breaking the delay arithmetic: the p50 is no longer 1000 ms

- [ ] **Step 5: Quality gate**

- [ ] **Step 6: Checkpoint.**

---

### Task C8: Real-data integration tests

Amendment A1 §7 (recovery equivalence), §8 (reports) and §9 (the `realdata` layer).

**Files:**
- Create: `internal/integration/vault_realdata_test.go` (`//go:build realdata`)

**The tests:**
- `TestCanonicalIngestEndToEnd`:
  - Ingests the whole canonical sample in 10,000-entry batches, with production settings. Dictionary 1 trains on 20,000 real certificates.
  - Each batch is verified against the sample's signed head with the stored consistency proofs.
  - Then it checks the invariants (`CheckRecovered`), loads `views.sql` into DuckDB and checks counts, entry types, batches and the chain join.
  - It checks a literal `BLOB` lookup on `issuer_key_hash` (amendment A1 §6).
  - Finally it reads 1,000 random certificates back through Pebble and the vault, verified, matching `entries.cert_id`.
- `TestRecoveryEquivalenceOnRealData`:
  - Ingests 30,000 real entries in 5,000-entry batches, with dictionary 1 training before the second batch.
  - It crashes at P1 (in the training batch), mid-record, P6, P8 (before the rename) and P9 (before the Pebble apply), and recovers each time.
  - The result must equal a clean ingest by `vaulttest.Diff`, and its next `cert_id` must lie beyond the clean one: IDs skipped.
- `TestMeasurementReports`: measures every cached sample and writes its report under the dev base.

- [ ] **Step 1: Write the tests**

Create `internal/integration/vault_realdata_test.go`:

```go
//go:build realdata

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"fmt"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/duckdb/duckdb-go/v2" // the "duckdb" database/sql driver

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/ingest"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/measure"
	"github.com/4rji/ctvault/internal/sample"
	"github.com/4rji/ctvault/internal/sampletest"
	"github.com/4rji/ctvault/internal/vault"
	"github.com/4rji/ctvault/internal/vaulttest"
)

// realVault is a fresh vault in a temp folder, ingesting a canonical sample
// replayed over loopback through the production client, fetcher and writer.
type realVault struct {
	t      *testing.T
	s      *sample.Sample
	v      vaulttest.Vault
	opts   ingest.Options
	src    *rfc6962.Source
	chains *logsource.ChainCache
	head   logsource.SignedHead
	out    bytes.Buffer
}

func newRealVault(t *testing.T, s *sample.Sample, dictSamples int) *realVault {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"state/intent", "state/incidents", "state/logs", "vault/segments", "vault/dict", "dataset", "tmp/stage", "tmp/rebuild"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var id [16]byte
	rand.Read(id[:])
	r := &realVault{t: t, s: s, v: vaulttest.Vault{Root: root, Dirs: []string{filepath.Join(root, "vault")}, UUID: id}}
	url, stop, err := sample.Serve(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	r.chains = logsource.NewChainCache(logsource.DefaultChainCacheBytes)
	r.src = rfc6962.NewSource(s.LogInfo(url), nil, r.chains, nil)
	if r.head, err = r.src.Head(context.Background()); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	r.opts = ingest.Options{Root: root, VaultDirs: r.v.Dirs, VaultUUID: id, Config: cfg,
		Guard: diskguard.Guard{Cap: cfg.Disk.MaxUsedFraction, Stat: diskguard.Statfs}, Version: "realdata-test", Out: &r.out,
		Fetch:       fetch.Options{MaxRPS: 1000, PageSize: s.Manifest.PageSize, MinBackoff: time.Millisecond, MaxBackoff: 10 * time.Millisecond},
		DictSamples: dictSamples}
	return r
}

func (r *realVault) open() *ingest.Writer {
	r.t.Helper()
	w, err := ingest.Open(r.opts)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { w.Close() })
	return w
}

// ingest commits [w's next index, to) in batches of size, verified against
// the sample's signed head with its stored consistency proofs.
func (r *realVault) ingest(w *ingest.Writer, to, size uint64) {
	r.t.Helper()
	log := r.s.Manifest.Log.Name
	for first := w.Next(log); first < to; first = w.Next(log) {
		if _, err := w.Batch(context.Background(), r.src, r.head, first, min(first+size, to)); err != nil {
			r.t.Fatalf("batch at %d: %v\n%s", first, err, r.out.String())
		}
		r.chains.Reset()
	}
}

// expected decodes the sample's entries [0, n) directly, for comparison.
type expected struct {
	types map[string]int
	certs map[uint64][]byte // idx → leaf certificate DER
}

func decodeSample(t *testing.T, s *sample.Sample, n uint64) expected {
	t.Helper()
	e := expected{types: map[string]int{}, certs: map[uint64][]byte{}}
	err := s.Each(func(x sample.Entry) error {
		if x.Index >= n {
			return nil
		}
		l := leaf.Decode(x.LeafInput, x.ExtraData)
		e.types[l.Type.String()]++
		if l.CertDER != nil {
			e.certs[x.Index] = l.CertDER
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func queryInt(t *testing.T, db *sql.DB, q string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// TestCanonicalIngestEndToEnd ingests the whole canonical sample into a
// vault with the production settings (dictionary 1 trains on 20,000 real
// certificates), then checks the vault's invariants, queries it through
// views.sql and reads certificates back.
func TestCanonicalIngestEndToEnd(t *testing.T) {
	s := sampletest.Canonical(t, realLog)
	n := s.Manifest.Count
	r := newRealVault(t, s, 0)
	w := r.open()
	start := time.Now()
	r.ingest(w, n, 10000)
	t.Logf("ingested %d entries in %v", n, time.Since(start).Round(time.Second))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r.v.CheckRecovered(t)

	ms, err := commit.ListCommitted(r.v.Root)
	if err != nil || uint64(len(ms)) != n/10000 {
		t.Fatalf("%d batches, %v", len(ms), err)
	}
	trained := false
	for _, m := range ms {
		if m.Verified.Method != "consistency_proof" {
			t.Fatalf("batch %s verified by %q", m.BatchID, m.Verified.Method)
		}
		trained = trained || m.Dictionary.ID == 1
	}
	ds, err := vault.LoadDicts(r.v.Dirs)
	if err != nil || !trained || len(ds) != 1 || ds[0].Manifest.Training.Records != vault.TrainingSamples {
		t.Fatalf("dictionary 1 trained on %d real certificates: %v %v", vault.TrainingSamples, ds, err)
	}

	want := decodeSample(t, s, n)
	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	views, err := os.ReadFile(filepath.Join(r.v.Root, dataset.ViewsFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(views)); err != nil {
		t.Fatalf("loading views.sql: %v", err)
	}
	if got := queryInt(t, db, `SELECT count(*) FROM entries`); got != int64(n) {
		t.Fatalf("entries: %d rows", got)
	}
	if got := queryInt(t, db, `SELECT count(DISTINCT idx) FROM entries WHERE idx BETWEEN 0 AND ?`, n-1); got != int64(n) {
		t.Fatalf("entries: %d distinct indexes in [0, %d)", got, n)
	}
	for typ, k := range want.types {
		if got := queryInt(t, db, `SELECT count(*) FROM entries WHERE entry_type = ?`, typ); got != int64(k) {
			t.Fatalf("entry_type %s: %d rows, the sample has %d", typ, got, k)
		}
	}
	if got := queryInt(t, db, `SELECT count(*) FROM batches`); got != int64(len(ms)) {
		t.Fatalf("batches view: %d rows", got)
	}
	// Every chain starts at position 0, and each entry's chain resolves.
	if a, b := queryInt(t, db, `SELECT count(*) FROM entries WHERE chain_id IS NOT NULL`),
		queryInt(t, db, `SELECT count(*) FROM entries e JOIN (SELECT DISTINCT chain_id FROM chains WHERE position = 0) c USING (chain_id)`); a != b || a == 0 {
		t.Fatalf("%d entries have a chain, %d resolve to one", a, b)
	}
	// Amendment A1 §6 on real data: a literal lookup on a BLOB column finds
	// every row (a bloom filter would have returned none).
	var ikh string
	var rows int64
	if err := db.QueryRow(`SELECT hex(issuer_key_hash), count(*) FROM entries WHERE issuer_key_hash IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 1`).Scan(&ikh, &rows); err != nil {
		t.Fatal(err)
	}
	if got := queryInt(t, db, fmt.Sprintf(`SELECT count(*) FROM entries WHERE issuer_key_hash = from_hex('%s')`, ikh)); got != rows || rows == 0 {
		t.Fatalf("literal issuer_key_hash lookup: %d rows, want %d", got, rows)
	}

	// Certificates read back through Pebble and the vault, verified.
	idx, err := index.Open(filepath.Join(r.v.Root, "state", "pebble"))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	codec, err := vault.NewCodec()
	if err != nil {
		t.Fatal(err)
	}
	defer codec.Close()
	for _, d := range ds {
		codec.AddDict(d.Manifest.ID, d.Content)
	}
	vr, err := vault.OpenReader(r.v.Dirs, codec)
	if err != nil {
		t.Fatal(err)
	}
	defer vr.Close()
	rnd := mrand.New(mrand.NewPCG(1, 2))
	for range 1000 {
		i := rnd.Uint64N(n)
		der, ok := want.certs[i]
		if !ok {
			continue
		}
		sha := sha256.Sum256(der)
		ref, ok, err := idx.Lookup(sha)
		if err != nil || !ok {
			t.Fatalf("entry %d: certificate %x not in the index (%v)", i, sha[:8], err)
		}
		got, err := vr.ReadVerified(ref.Loc, sha)
		if err != nil || !bytes.Equal(got, der) {
			t.Fatalf("entry %d: reading certificate %x back: %v", i, sha[:8], err)
		}
		if c := queryInt(t, db, `SELECT count(*) FROM entries WHERE idx = ? AND cert_id = ?`, i, ref.CertID); c != 1 {
			t.Fatalf("entry %d: entries.parquet does not point at cert_id %d", i, ref.CertID)
		}
	}
}

// TestRecoveryEquivalenceOnRealData crashes an ingest of real entries at
// commit boundaries, across dictionary training and leaf-delta batches,
// recovers each time, and requires the result to equal a clean ingest on
// everything but internal IDs (amendment A1 §7).
func TestRecoveryEquivalenceOnRealData(t *testing.T) {
	s := sampletest.Canonical(t, realLog)
	const n, size, dict = 30000, 5000, 2000 // dictionary 1 trains before the second batch
	clean := newRealVault(t, s, dict)
	cw := clean.open()
	clean.ingest(cw, n, size)
	cw.Close()
	want := clean.v.Dump(t)

	r := newRealVault(t, s, dict)
	crashes := []struct {
		at    uint64 // the batch that crashes
		point string
	}{
		{5000, commit.HookAfterIntent}, // the batch that trains dictionary 1
		{10000, vault.HookAppendMidRecord},
		{15000, ingest.HookDuringCanary},
		{20000, commit.HookBeforeRename},
		{25000, ingest.HookBeforePebble},
	}
	for _, c := range crashes {
		w := r.open()
		r.ingest(w, c.at, size)
		w.Close()
		r.opts.Hook = func(p string) {
			if p == c.point {
				panic("crash at " + p)
			}
		}
		w = r.open()
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("batch at %d: %s did not fire", c.at, c.point)
				}
			}()
			w.Batch(context.Background(), r.src, r.head, c.at, c.at+size)
		}()
		w.Close()
		r.chains.Reset()
		r.opts.Hook = nil
		w = r.open() // recovers
		w.Close()
		r.v.CheckRecovered(t)
		if !strings.Contains(r.out.String(), "recovery:") {
			t.Fatalf("crash at %s (batch %d): recovery reported nothing", c.point, c.at)
		}
	}
	w := r.open()
	r.ingest(w, n, size)
	w.Close()
	r.v.CheckRecovered(t)
	if d := vaulttest.Diff(r.v.Dump(t), want); d != "" {
		t.Fatalf("the recovered ingest differs from a clean one: %s", d)
	}
	ms, _ := commit.ListCommitted(r.v.Root)
	got, want2 := ms[len(ms)-1].NextCertID, lastNext(t, clean.v.Root)
	if got <= want2 {
		t.Fatalf("after crashes cert_ids resume at ID_FLOOR, leaving gaps: next %d, clean %d", got, want2)
	}
	t.Logf("%d crashes recovered; %d batches equal a clean ingest of %d real entries (next cert_id %d, clean %d)",
		len(crashes), len(ms), n, got, want2)
}

func lastNext(t *testing.T, root string) uint64 {
	ms, err := commit.ListCommitted(root)
	if err != nil || len(ms) == 0 {
		t.Fatal(err)
	}
	return ms[len(ms)-1].NextCertID
}

// TestMeasurementReports measures every cached sample of the log and writes
// the reports under the dev base (amendment A1 §8).
func TestMeasurementReports(t *testing.T) {
	samples := []*sample.Sample{sampletest.Canonical(t, realLog)}
	samples = append(samples, sampletest.Representatives(t, realLog)...)
	base := filepath.Dir(sampletest.Base(t))
	for _, s := range samples {
		id := s.Manifest.ID(filepath.Base(s.Dir))
		t.Run(strings.ReplaceAll(id, "/", "_"), func(t *testing.T) {
			r, p, err := measure.Run(context.Background(), s, measure.Options{Base: base, Version: "realdata-test", Stat: diskguard.Statfs,
				Dependencies: goModVersions(t)})
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Provenance.Dependencies) != 4 {
				t.Fatalf("provenance lacks dependency versions: %v", r.Provenance.Dependencies)
			}
			if r.Errors.Total != r.Errors.Committed || r.Sizes.Vault <= 0 || r.Sizes.Parquet <= 0 || r.Sizes.Pebble <= 0 {
				t.Fatalf("inconsistent report: errors %+v, sizes %+v", r.Errors, r.Sizes)
			}
			full := 0
			for _, g := range r.Compression.Groups {
				if g.Kind == "leaf" || g.Kind == "delta" {
					full += g.Records
				}
			}
			if full != r.Dedup.UniqueLeafCerts {
				t.Fatalf("%d leaf and delta records for %d unique leaf certificates", full, r.Dedup.UniqueLeafCerts)
			}
			t.Logf("report %s\n%s", p.JSON, measure.Markdown(r))
		})
	}
}

// goModVersions reads the required module versions from go.mod: a go test
// binary's build info lists no dependencies.
func goModVersions(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "require "))
		if len(f) >= 2 && strings.Contains(f[0], ".") && strings.HasPrefix(f[1], "v") {
			out[f[0]] = f[1]
		}
	}
	return out
}
```

- [ ] **Step 2: Run them**

Run: `go test -tags realdata -timeout 90m -v ./internal/integration/`
Expected: PASS. They skip with capture instructions when no canonical sample is cached. Measured times: the whole layer took 14.7 minutes: end to end 259 s (ingest 4 m 0 s), recovery equivalence 76 s, and the two measurements 252 s and 249 s.

Without Task C6's fix, `TestRecoveryEquivalenceOnRealData` fails with "after crashes cert_ids resume at ID_FLOOR, leaving gaps: next 30540, clean 30540".

- [ ] **Step 3: Quality gate**

- [ ] **Step 4: Checkpoint.**

---

### Task C9: Docs

Amendment A1 §2 (samples), §8, §9 and §10.

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update the README**

Replace `README.md` with:

````markdown
# CTVault

A local, cryptographically verified Certificate Transparency research archive.
Design: `docs/superpowers/specs/2026-10-04-ctvault-design.md`.

**Status:** Plan 2C (crash suite and measurements). `ctvault update` ingests
pinned logs into the vault:
- Every batch is verified against a signed tree head.
- Every unique certificate is stored compressed and deduplicated.
- `entries` and `chains` are written as Parquet, with `views.sql` for the
  DuckDB CLI.
- A crash at any point recovers to the last committed batch. A test suite
  proves it by killing the writer (SIGKILL) at every commit boundary and at
  random moments.

The derived `certs` and `names` tables arrive in Plan 3.

## Requirements

- Linux, with the vault on a dedicated, mounted **ext4** volume (an external
  SSD). xfs, btrfs and f2fs work only with `--allow-untested-fs`; exFAT, NTFS,
  FAT, FUSE, network filesystems and tmpfs are always rejected.
- Go 1.26.8 or newer. With the default `GOTOOLCHAIN=auto`, an older `go`
  downloads the right toolchain automatically.
- A C compiler (`gcc`) for cgo: CTVault embeds DuckDB. The DuckDB library
  makes the binary about 100 MB, and a first build takes a minute or two.

## Build and test

```bash
go build -o ctvault ./cmd/ctvault
go test -race ./...
```

| Layer | Command | Network |
|---|---|---|
| Unit tests, fake-log fault injection, crash boundaries and a 25-kill loop, production guard tests | `go test -race ./...` | none |
| Dev-build behaviour, measurements | `go test -race -tags ctvault_dev ./...` | none |
| Real-data end to end, recovery equivalence, measurement reports (skip without a cached sample) | `go test -tags realdata -timeout 90m ./internal/integration/` | none (loopback replay) |
| Long crash loop (200 kills) | `go test -tags nightly -run RandomKill ./internal/commit/` | none |
| Leaf decoder fuzzing | `go test -run '^$' -fuzz FuzzDecode -fuzztime 60s ./internal/leaf/` | none |
| Live sample capture | `ctvault-dev sample capture ...` (below) | Google, opt-in |

- **The crash suite** (`internal/commit/crash_test.go`) re-runs the test
  binary as a child, kills it with SIGKILL, then checks after every recovery:
  - committed batches are intact, and nothing partial is visible;
  - nothing is left beyond the vault tail or in `tmp/`;
  - Pebble agrees with the vault;
  - no `cert_id` of a truncated record is ever committed later;
  - a finished ingest equals a clean one.

  `-short` skips it. With `-race`, the `commit` package takes about
  2.5 minutes.
- **The real-data layer runs without `-race`.** Training the compression
  dictionary on 20,000 real certificates takes about 3.5 minutes, and the
  race detector multiplies that. The fake-log suites run the same code under
  `-race`. The whole layer takes about 15 minutes.
- **Temp space:** the crash suite and the real-data tests write a few hundred
  MB under `TMPDIR`. If `/tmp` is a small tmpfs, point `TMPDIR` (and
  `GOTMPDIR`) at a disk.

## Usage

```bash
# The SSD must be mounted at /mnt/ctvault and contain nothing but lost+found.
./ctvault init /mnt/ctvault
export CTVAULT_ROOT=/mnt/ctvault

./ctvault logs list --available        # RFC 6962 logs in Chrome's log list
./ctvault logs add argon2027h1          # pin the log and its public key
./ctvault logs info argon2027h1         # fetch and verify the live signed tree head
./ctvault vault add-dir /mnt/disk2/ctvault-vault   # optional extra vault disk

./ctvault update                         # ingest up to the current signed head
./ctvault update --until 1000000         # stop at index 1,000,000 (exclusive)
./ctvault update --follow                # keep ingesting, one cycle every 10 minutes
```

`update` (alias `ingest`):
- **Batches:** commits batches of `ingest.batch_size` entries, each verified
  by a consistency proof or the signed root.
- **Ctrl-C:** the first finishes the current batch; the second abandons it,
  and it is fetched again next time.
- **Log misbehaviour:** a shrinking log, a fork or a bad signature is an
  incident. It is refetched once, then evidence is written to
  `state/incidents/` and `update` exits 5.
- **Full disk:** at the disk cap it exits 3 before a batch starts; with
  `--follow` it waits for the next cycle instead.
- **Crashes:** the next start recovers to the last committed batch. The
  certificate IDs a lost batch may have used are skipped, never reused, so
  `cert_id` values can have gaps.
- **A batch that cannot be cleaned up** (the vault cannot be cut back) stops
  `update`, even with `--follow`. The next start recovers it.

The dataset can be queried without CTVault running:
`duckdb -c ".read /mnt/ctvault/views.sql" -c "SELECT count(*) FROM entries"`.

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
database, not `$HOME`):
- dev vaults in `vaults/`;
- samples in `samples/`;
- measurement reports in `reports/`;
- measurement workspaces in `tmp/`.

It keeps the same 85% disk cap, applied to the disk that holds that folder.
`~/.cache/ctvault-dev` may be a symlink to a folder on another local disk; the
dev build resolves it. A dev vault created before such a move is refused
afterwards, because its `VAULT_ID` records the old filesystem's UUID.

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
  multiple of 5,000. A 100,000-entry sample takes about 76-100 MB (760-974 B
  per entry measured; the canonical `[0, 100000)` window took 97.5 MB) and
  about 4 minutes at the log's rate limit.
- A sample is published only after it verifies: the file checksums, the
  signed head with the key pinned from Chrome's log list, and the Merkle
  proofs that tie every entry's `leaf_input` (the logged certificate or
  precertificate TBS and its timestamp) to that head. It is then read-only
  and never overwritten; to capture the same range again, add
  `--suffix <name>`.
- The chains in `extra_data` are not part of a CT log's Merkle tree (RFC
  6962), so no proof covers them; in a sample they are protected by the
  checksums only. Precertificate cross-checks still flag a chain that does
  not match the logged TBS.
- An interrupted or failed capture (Ctrl-C, network loss, full disk) leaves
  nothing behind.
- Every later load verifies the sample again, so a damaged sample is refused
  (exit 5) instead of feeding wrong data.
- Representative samples are for measurements only.

### Dev vaults and replay

A dev vault lives under `~/.cache/ctvault-dev/vaults/` and starts with
10,000-entry batches. A canonical sample feeds it over loopback through the
same client, fetcher and writer as the live log:

```bash
./ctvault-dev init ~/.cache/ctvault-dev/vaults/argon
./ctvault-dev --root ~/.cache/ctvault-dev/vaults/argon logs add argon2027h1
./ctvault-dev --root ~/.cache/ctvault-dev/vaults/argon update \
  --replay ~/.cache/ctvault-dev/samples/argon2027h1/000000000000-000000099999
```

- `--replay` refuses representative samples and samples of another log.
- With `--replay`, `ingest.batch_size` and `--until` must be multiples of
  5,000, the sample's proof boundaries.
- Measured on 2026-10-04: the 100,000-entry canonical sample replays in
  about 4 minutes, including one-time training of the compression dictionary
  (about 3.5 minutes).
- The resulting vault holds about 1.1 KB of vault data, 54 B of Parquet and
  67 B of index per entry. The shard's first entries are 81% final
  certificates, so they compress worse than the log's average.

### Measurements

```bash
./ctvault-dev sample measure ~/.cache/ctvault-dev/samples/argon2027h1/000397220000-000397319999
```

- **What runs:** the sample, canonical or representative, goes through the
  production per-entry pipeline: decoding, the issuance key, dedup, the vault
  writer with dictionaries and `leaf-delta`, and Parquet staging. It commits
  batch by batch (`--batch-size`, default 10,000), as `update` does.
- **Where:** in a throwaway workspace under `~/.cache/ctvault-dev/tmp/`, which
  is deleted afterwards. It never creates or changes a vault.
- **The report** is written to
  `~/.cache/ctvault-dev/reports/<log>/<sample>/<UTC time>.json`, with a
  Markdown summary next to it, and the summary is also printed. It records:
  - the provenance: CTVault, Go and dependency versions, the sample, the time;
  - bytes per entry for the vault, Parquet and Pebble, against the
    disk-guard seeds;
  - compression by record kind, dictionary and entry type, and the gap
    against the spec's C-zstd figures (flagged when more than 10% worse);
  - precert→final links and delays, the `leaf-delta` hit rate, dedup, leaf
    errors, and every batch.
- **Reports change nothing.** Disk-guard seeds and defaults change only by a
  reviewed edit.

Measured on 2026-10-04, in 10,000-entry batches:

| | Canonical `[0, 100000)` | Representative `[397220000, 397320000)` |
|---|---|---|
| Vault, B/entry (with dictionary 1) | 1079 (985) | 745 (638) |
| Parquet, B/entry | 55 | 55 |
| Pebble, B/entry | 72 | 71 |
| Full leaf records with a dictionary | 1.58× | 1.71× |
| Finals linked to a precert in the window | 2.0% (1,603 of 81,052) | 9.2% (3,943 of 42,834) |
| `leaf-delta` saving (dictionary batches) | 37.0% | 25.8% |

The spec's figures are 1.96× with a dictionary and a vault budget of 765
B/entry. Pure-Go zstd (klauspost) at its "better" level compresses full
records 12.7% below 1.96× on the representative window, more than amendment A1
§5's 10% threshold, so the reports flag it and Plan 3 decides. The
representative vault, 638 B/entry, still fits the 765 B/entry budget. Only 9%
of final certificates there have their precert in the same window, so
`leaf-delta` matters little; the dictionary does the work.

## Pending verification

**Real-SSD smoke test: not run yet.** As of 2026-10-04 there was no access to
the external drive. Every automated test passes, but `init` and `logs` have
not yet been run end to end on the real drive and enclosure (USB/UAS, and LUKS
if used). Run it before trusting the vault with data. The drive must be
mounted at `/mnt/ctvault`, ext4, and empty apart from `lost+found`:

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

- [ ] **Step 2: Check every command in it**

Run the build and test commands in the README's table. Then run `ctvault-dev sample verify` and `ctvault-dev sample measure` on the cached samples.

- [ ] **Step 3: Checkpoint.**

---

## Final Verification

- The quality gate on the finished tree, plus:
  - `go test -tags nightly -run RandomKill ./internal/commit/` (200 kills)
  - `go test -tags realdata -timeout 90m ./internal/integration/`
- A whole-branch review, as for Plan 2B, with the Review Focus above.
- The measurement reports of both samples sit under `~/.cache/ctvault-dev/reports/`. Their numbers go to the user, with the flagged gaps.
