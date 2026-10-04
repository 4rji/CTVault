# CTVault Plan 2B (Vault) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `ctvault update` ingest pinned CT logs into the vault. When this plan is done, every batch:
- is verified against a signed tree head;
- stores each unique certificate's DER exactly once, compressed with a trained dictionary and with `leaf-delta`;
- writes `entries.parquet` and `chains.parquet`;
- commits atomically.

A crash at any point recovers to the last committed batch without ever reusing a `cert_id`. The dev build replays a cached canonical sample into a dev vault.

**Architecture:** New packages, one job each:
- `vault`: segments, records, dictionaries, `leaf-delta`.
- `index`: the writer-private Pebble store.
- `commit`: `ID_FLOOR`, intents, `_COMMIT.json`, the commit point, recovery.
- `dataset`: DuckDB staging, the canary, `views.sql`.
- `ingest`: one batch through spec §8.3's steps P0–P10.

The `update` command drives `ingest` with Plan 2A's verified log source, fetcher and two-level stop signals. Everything is tested offline, against the fake log or a loopback replay.

**Tech Stack:**
- Go 1.26.8 with **cgo** (DuckDB is embedded).
- New:
  - `github.com/cockroachdb/pebble/v2` v2.1.7
  - `github.com/duckdb/duckdb-go/v2` v2.10506.0 (DuckDB 1.5.6)
- Plan 2A's `klauspost/compress` v1.20.1 now also provides dictionary training and raw-content dictionaries.

**Spec:**
- `docs/superpowers/specs/2026-10-04-ctvault-design.md` ("the spec")
- **Amendment A1:** `docs/superpowers/specs/2026-10-04-ctvault-plan2-amendment.md` (approved)

This plan implements the amendment's tasks 7–12, plus `update --replay` from task 14. In detail:
- **Spec:** §4.3 (layout), §5.5–5.6, §6.1–6.5, §7.6 (`views.sql`, Plan 2 subset), §8.1–8.6, §10.1 (preflight and hard checks), §11.2 (`update`), §12.
- **Amendment:** §2.5 (replay), §3 (`--until`), §5, §6 and §7.

It builds on Plan 2A as committed (2caa9d7).

## Global Constraints

- **Platform:** Linux only, `go 1.26.8`.
- **Builds need cgo and a C compiler.** The first build of DuckDB takes about a minute, and the binary is about 100 MB.
- **Pinned dependencies:**
  - New: `github.com/cockroachdb/pebble/v2@v2.1.7`, `github.com/duckdb/duckdb-go/v2@v2.10506.0`
  - Unchanged: Plan 2A's dependencies
  - No others.
- **Production safety is unchanged.** Dev code lives only in `//go:build ctvault_dev` files, and the only environment variable production reads is `CTVAULT_ROOT`.
- **Exit codes:** "0 OK, 1 error, 2 usage, 3 disk cap reached, 4 volume check failed, 5 verification or corruption failure" (spec §11.2).
- **"Never silently drop, skip or reuse data"** (spec §12):
  - `cert_id` "is never reused", and gaps are allowed after a crash (spec §6.1, §8.6).
  - "No partial batch is ever visible" (spec §13.5).
  - Pebble "can only lag the dataset, never lead it" (spec §8.5).
- **ID_FLOOR:** "blocks of 65,536. The next block is reserved durably before the current one is exhausted: the advance happens when fewer than 32,768 reserved IDs remain" (amendment A1 §7).
- **Parquet:** "binary columns are allowed only in files written with `WRITE_BLOOM_FILTER false`" (amendment A1 §6), and the canary asserts "no bloom filter exists on any `BLOB` column".
- **Dictionaries** "are immutable, never deleted, and replicated into every vault directory's `dict/`" (spec §6.2). A training failure means ingestion "continues with dictionary 0, and the failure is recorded in `_COMMIT.json`" (amendment A1 §5).
- **Cleanup scope:** "recovery and cleanup delete only `tmp/stage/*` and `tmp/rebuild/*`, never all of `tmp/`" (amendment A1 §7).
- **`--until N`:** "N is an exclusive end index", "If `checkpoint >= N`, exit 0 without fetching anything, not even a signed head", and "`--until` never changes the persisted log head" (amendment A1 §3).
- **Quality gates, for every task:**
  - `gofmt -l .` prints nothing
  - `go vet` is clean with no tags, with `ctvault_dev` and with `realdata`
  - `go test -race ./...` and `go test -race -tags ctvault_dev ./...` pass

## Review Focus

The failure modes a person running a multi-week catch-up is most likely to meet, each pinned by a test in the task that owns the code.

1. **The machine dies mid-batch** (power loss, OOM kill, Ctrl-C twice).
   - Expected: the next start recovers to the last committed batch. No partial batch is visible, no `cert_id` is reused, and Pebble catches up.
   - Pinned by:
     - `TestRecoveryAfterCrashes` (Task B6): kills before the rename, before the Pebble apply, and inside a segment rollover.
     - `TestRecoverAfterCrashBeforeCommit` and `TestRecoverFinishesACommittedBatch` (Task B5).
2. **The log serves data that does not match its signed head** (a fork, an altered entry, a shrinking tree).
   - Expected: nothing is committed; the batch is refetched once; then evidence goes to `state/incidents/` and the exit code is 5.
   - Pinned by `TestForkedLogIsAnIncident` (Task B6) and `TestUpdateIncidents` (Task B7).
3. **The disk fills up.**
   - Expected: the batch is refused before anything is written (exit 3), the cap is re-checked during appends, and `--follow` pauses.
   - Pinned by `TestDiskCapRefusesBeforeAnyWrite` (Task B6), `TestAppendsRecheckTheCap` (Task B1) and `TestUpdateDiskCapAndLock` (Task B7).
4. **The same certificate arrives again**: re-logged, or seen both as a chain certificate and as a leaf.
   - Expected: it is stored once, and later entries reference the same `cert_id`.
   - Pinned by `TestDedupAndLeafErrors` (Task B6) and `TestBatchSeesItsOwnWritesAndCommitsDurably` (Task B3).
5. **The user stops `update --follow`.**
   - Expected: the first Ctrl-C ends after the current batch with exit 0, and nothing is lost.
   - Pinned by `TestUpdateFollowStopsOnFirstSignal` (Task B7).

## Decisions This Plan Adds

These choices are **not** in the approved sections. They were settled while building and testing this plan. Review them.

| # | Decision | Why |
|---|---|---|
| 1 | **Segment header:** a fixed 64 bytes (magic, version, vault UUID, segment ID, first `cert_id`, creation time) closed by a CRC32C. | A header torn during rollover is detected instead of read as data. |
| 2 | **Trained-dictionary frames keep zstd's own dictionary ID** (1 byte), and every read checks it against the record's `dict_id`. Delta frames omit it, as spec §6.2 says. | klauspost always writes a trained dictionary's ID. The cross-check means a record can never be decoded with the wrong dictionary. |
| 3 | **Compression levels:** "better" for leaf and chain records, "default" for delta records. | Measured: the better level is 648 B/cert at 0.1 ms, while the best level is 635 B/cert at 4.4 ms, far too slow. For deltas both levels give 893 B, and default is 3.5× faster. |
| 4 | **Dictionary 1 is trained at a batch's preflight** once the committed vault holds 20,000 leaf records, read back from committed data. Training is tried once per process run. | It is crash-safe, and it costs one 3.5-minute training per vault (measured). |
| 5 | **Delta warm-up:** after a restart, the cache is refilled by rescanning the leaf records of the last `delta.warm_batches` batches. A precert's digest is recomputed from its own DER, as its TBS without the poison extension. | This matches the log's TBS digest for CA-issued precerts. Precerts issued by a precertificate signing certificate just miss the cache (optimization only). |
| 6 | **New Pebble key `ch/<chain_id>`** records chains already written. | It lets each batch write only "chains first seen in the batch" (spec §6.5). It is rebuildable from `chains.parquet`. |
| 7 | **The last accepted head is stored per log** in `state/heads/<log>.json` and re-verified with the pinned key on load. | The amendment requires a persisted head. `state/logs/` would make `logs list` read it as a pinned log. |
| 8 | **The startup check of committed batches** covers `_COMMIT.json` and each listed file's existence and size. Full checksums are left to `verify` (Plan 6), and `_COMMIT.json` file entries gain `bytes`. | Hashing every Parquet file at every start would grow with the dataset. |
| 9 | **P11, the optional post-commit audit, is deferred** to the read path (Plan 4). | It needs the query package. |
| 10 | **`--replay`:** ends by default at the sample's end. Batch size, `--until` and the vault's position must sit on the sample's 5,000-entry boundaries. Representative samples and other logs' samples are refused with exit 2. | The sample holds consistency proofs only at those boundaries. |
| 11 | **Dev `init` writes `batch_size = 10000`.** | Amendment A1 §2.5: "The dev default batch size is 10,000." |
| 12 | **Delta cache layout:** a ring plus a map keyed by the digest's first 16 bytes. A hit still requires all 32 bytes to match. | It takes 207 MiB for the default 2M entries, against 317 MiB keyed by the full digest. The spec estimated about 128 MB. `ingest.delta_lru_entries` lowers it on small machines. |
| 13 | **`ct_ts` is null only when the timestamp is unknown**; leaf-error rows keep a decodable timestamp. | This follows Plan 2A's ruling on leaf timestamps. |
| 14 | **Head incidents:** one refetch after a 5 s wait, then evidence in `state/incidents/<ts>_<log>_head/` and exit 5. | Spec §12 says "refetch once"; the wait lets a lagging frontend catch up. |
| 15 | **`_COMMIT.json` gains `counts.vault_bytes` and `committed_at`.** | They are the disk guard's per-entry history (spec §10.1 p95) and an audit timestamp. |
| 16 | **The writer's DuckDB spill limit** is `min(4 GiB, headroom below the cap − 1 GiB)`, and the batch preflight counts it. | Spec §10.1 sets the spill limit to the whole headroom minus 1 GiB, while amendment A1 §7 adds the limit to the peak. Together no batch could ever start; the first test run refused a 50-entry batch needing 360 GiB. |

## Evidence Behind This Plan (measured 2026-10-04)

1. **Dependencies:**
   - Pebble v2.1.7 and duckdb-go v2.10506.0 build with Go 1.26.8.
   - The DuckDB Appender takes `uint64`, `time.Time`, `[]byte` and `nil`, and `COPY … WRITE_BLOOM_FILTER false` writes no bloom filter.
   - DuckDB reads `TIMESTAMP_MS` back as `TIMESTAMP`, so the canary checks the Parquet logical type.
2. **The spec §3.6 bug reproduces** on the pinned DuckDB with only 2,000 rows: a literal lookup on a bloom-filtered, low-cardinality `BLOB` column returns 0 rows instead of 667. Without bloom filters it returns 667.
3. **Compression** on 32,768 contiguous real entries:
   - Dictionary 1 (110 KiB, trained on 20,000 certificates in 3 m 27 s) brings certificates from 989 B to 648 B. The spec's C-zstd figure is 568 B, so klauspost is **14% worse**. Amendment A1 §5's rule applies: "the report says so, and Plan 3 decides on any switch."
   - `leaf-delta` saves **23.8%** on linked final certificates (the spec measured 17.1%).
   - `dict.BuildZstdDict` **panics** on degenerate input. Training recovers and falls back to dictionary 0 (tested).
4. **The canonical sample `[0, 100000)` through the whole engine**, into a scratch vault with 10,000-entry batches:
   - All 10 batches were verified by consistency proofs, with 0 leaf errors.
   - Dictionary 1 was trained automatically before batch 4 (3 m 41 s).
   - **Vault:** 1,232–1,395 B/entry before the dictionary and 950–1,035 B/entry after.
   - **Parquet:** 54 B/entry. **Pebble:** 67 B/entry (the spec's seed is 60).
   - About 3,700 entries/s, not counting training.
   - The shard's start is 81% final certificates with SCT lists and few precerts to delta against, so its vault size exceeds the 840 B/entry seed. Representative measurements are Plan 2C's job, and the disk-guard seeds are unchanged.
5. **Bugs found by the tests while writing this plan**, and fixed in it:
   - A reopened segment was written at file position 0, overwriting its header.
   - The spill-limit conflict of Decision 16.
   - The production-binary guard flagged `prometheus/procfs`'s `net_dev.go`. The `_dev.go` rule now applies to CTVault's own packages only.

## Carried to Plan 2C

- The kill-loop suite (200+ SIGKILLs at random points), using the hook points this plan adds:
  - vault rollover
  - `ID_FLOOR` advance
  - P1, P7, P8, P9 and P10
- `sample measure` and measurement reports, on a representative sample.
- Real-data end-to-end and recovery-equivalence tests over the canonical sample.
- The docs pass.

## Before You Start

- Work from the repository root (Plan 2A committed).
- **cgo:** a C compiler must be installed (`gcc`).
- **Disk space for the build:**
  - The DuckDB module adds about 570 MB to the Go module cache.
  - The first build links for about a minute.
  - If `/tmp` is a small tmpfs, set `GOTMPDIR` to a folder on disk for builds.
- **Commits:** each task ends with a commit step. If your human partner has turned Git operations off, skip the `git` commands and record the checkpoint in the progress ledger instead.

## File Structure

```text
internal/vault/format.go       segment header (64 B, CRC32C), record codec, Loc, Tail, errors
internal/vault/codec.go        zstd: no dictionary, trained dictionaries, delta frames
internal/vault/segments.go     segment file names, FindSegments (duplicates are corruption)
internal/vault/writer.go       Writer: append, rollover to the first directory with room, cap re-checks, Sync, AppendDelta
internal/vault/reader.go       Reader: Read, ReadVerified (SHA-256), delta bases; Scan
internal/vault/truncate.go     InspectTail, Truncate (recovery)
internal/vault/dict.go         dictionary manifest, install and replicate, LoadDicts, Train, TrainingSet
internal/vault/delta.go        DeltaCache, Warm
internal/leaf/precert.go       + PrecertIssuanceDigest (warm-up)
internal/index/index.go        Pebble: c/<sha>, ch/<chain_id>, applied/<log>; indexed batches
internal/commit/idfloor.go     ID_FLOOR allocator
internal/commit/manifest.go    _COMMIT.json, BatchID, Paths, ListCommitted, Tips
internal/commit/protocol.go    intents (P1, P10), Publish (P7-P8), Abandon, hook points
internal/commit/recover.go     Recover (spec §8.5)
internal/dataset/stage.go      Stager: in-memory DuckDB, Appender → COPY (no bloom filters), ChainIDs
internal/dataset/canary.go     Canary (P6)
internal/dataset/views.go      views.sql, rewritten only when it changes
internal/ingest/writer.go      Writer: Open (recovery, dictionaries, warm-up), spill budget, Close
internal/ingest/batch.go       Batch: P0-P10, refetch once, incidents, dedup, leaf-delta, chains, training, preflight
internal/logsource/headstore.go   state/heads/<log>.json
internal/cli/update.go         update / ingest: --follow, --until, --log, signals, exit codes
internal/cli/update_dev.go     (dev only) --replay, dev init batch size
```

---

### Task B1: Vault segments and records

Implements spec §6.2 (segments, record format, `vault.dirs`), §8.5's vault rows (inspect and truncate the tail) and §10.1's vault hard checks.

**Files:**
- Create: `internal/vault/format.go`, `internal/vault/codec.go`, `internal/vault/segments.go`, `internal/vault/writer.go`, `internal/vault/reader.go`, `internal/vault/truncate.go`
- Create test: `internal/vault/vault_test.go`

**Interfaces:**
- Consumes:
  - Plan 1: `fsutil.SyncDir`
  - Plan 2A: `ctlogtest.NewGenerator` (tests only)
- Produces (`vault`):
  - Format:
    - kinds `KindLeaf=1`, `KindDelta=2`, `KindChain=3`
    - `Magic`, `HeaderSize=64`, `type Header` with `Encode() []byte` and `DecodeHeader([]byte) (Header, error)`
    - `ParseUUID(string) ([16]byte, error)`
    - `type Loc struct{ Segment, Offset uint64; Len uint32 }`
    - `type Tail struct{ Segment, Offset uint64 }` with `Before`
    - `type Record`, `AppendRecord`, `ParseRecord`
    - `ErrCorrupt`, `ErrTorn`
  - Codec: `type Codec` with `NewCodec()`, `Compress(der, dictID)`, `Decompress(frame, dictID)` and `Close()`
  - Segments: `SegmentsDir`, `DictDir`, `SegmentName(id)`, `FindSegments(dirs)`
  - Writer:
    - `type Options struct{ Dirs []string; VaultUUID [16]byte; SegmentSize uint64; Check func(dir string, need uint64) error; CheckEvery uint64; Hook func(string); Now func() time.Time }`
    - `OpenWriter(o, codec, tail) (*Writer, error)`
    - `(*Writer).AppendCert(kind byte, certID uint64, der []byte, dictID uint64) (Loc, error)`, plus `Sync`, `Tail` and `Close`
    - hook points `HookRolloverBeforeHeader`, `HookRolloverAfterHeader`, `HookRolloverBeforeDirSync`
  - Reader:
    - `OpenReader(dirs, codec)`
    - `(*Reader).Read(loc) ([]byte, Record, error)`, `ReadVerified(loc, sha) ([]byte, error)`, `Close()`
    - `Scan(dirs, from, to Tail, fn func(Loc, Record) error) error`
  - Recovery helpers:
    - `type Uncommitted struct{ Bytes, MaxCertID uint64 }`
    - `InspectTail(dirs, tail)`, `Truncate(dirs, tail)`

- [ ] **Step 1: Write the failing tests**

Create `internal/vault/vault_test.go`:

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
	want := []string{HookRolloverBeforeHeader, HookRolloverAfterHeader, HookRolloverBeforeDirSync}
	if !slices.Equal(points, want) {
		t.Fatalf("hook order %v, want %v", points, want)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/vault/`
Expected: FAIL with `undefined: SegmentsDir`.

- [ ] **Step 3: Implement the vault format, writer and reader**

Create `internal/vault/format.go`:

```go
// Package vault stores every unique certificate's DER, compressed, in
// append-only segment files (spec §6.2, amendment A1 §5). Records are
// located by (segment, offset); SHA-256 is never stored and is verified on
// every read.
package vault

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"time"
)

// Record kinds (spec §6.2).
const (
	KindLeaf  = 1 // ref: uvarint dict_id (0 = no dictionary)
	KindDelta = 2 // ref: uvarint base_segment, uvarint base_offset
	KindChain = 3 // ref: uvarint dict_id
)

// Segment header (spec §6.2): magic, format version, vault UUID, segment ID,
// first cert_id and creation time, fixed at 64 bytes and closed by a CRC32C
// so a header torn during rollover is detected.
const (
	Magic         = "CTVSEG01"
	FormatVersion = 1
	HeaderSize    = 64
)

var (
	// ErrCorrupt means committed vault data failed a check: a bad header, a
	// checksum or SHA-256 mismatch, an unresolvable delta base. It is never
	// ignored (spec §12: exit 5).
	ErrCorrupt = errors.New("vault corruption")
	// ErrTorn means a record ends past the end of its segment: a write that
	// a crash interrupted. Only data beyond the committed tail may be torn.
	ErrTorn = errors.New("torn vault record")
)

func corrupt(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(format, args...))
}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// Header is a segment's first 64 bytes.
type Header struct {
	Version     uint16
	VaultUUID   [16]byte
	Segment     uint64
	FirstCertID uint64
	Created     time.Time
}

// Encode lays the header out as magic(8) version(2) uuid(16) segment(8)
// first_cert_id(8) created_unix_ns(8) zero(10) crc32c(4).
func (h Header) Encode() []byte {
	b := make([]byte, HeaderSize)
	copy(b, Magic)
	binary.BigEndian.PutUint16(b[8:], h.Version)
	copy(b[10:26], h.VaultUUID[:])
	binary.BigEndian.PutUint64(b[26:], h.Segment)
	binary.BigEndian.PutUint64(b[34:], h.FirstCertID)
	binary.BigEndian.PutUint64(b[42:], uint64(h.Created.UnixNano()))
	binary.BigEndian.PutUint32(b[60:], crc32.Checksum(b[:60], castagnoli))
	return b
}

// DecodeHeader parses and checks a segment header.
func DecodeHeader(b []byte) (Header, error) {
	if len(b) < HeaderSize {
		return Header{}, fmt.Errorf("%w: segment header is %d bytes", ErrTorn, len(b))
	}
	if string(b[:8]) != Magic {
		return Header{}, corrupt("bad segment magic %q", b[:8])
	}
	if crc32.Checksum(b[:60], castagnoli) != binary.BigEndian.Uint32(b[60:64]) {
		return Header{}, corrupt("segment header checksum mismatch")
	}
	h := Header{Version: binary.BigEndian.Uint16(b[8:]), Segment: binary.BigEndian.Uint64(b[26:]),
		FirstCertID: binary.BigEndian.Uint64(b[34:]), Created: time.Unix(0, int64(binary.BigEndian.Uint64(b[42:]))).UTC()}
	copy(h.VaultUUID[:], b[10:26])
	if h.Version != FormatVersion {
		return h, corrupt("unsupported segment format %d", h.Version)
	}
	return h, nil
}

// ParseUUID turns a VAULT_ID uuid ("xxxxxxxx-xxxx-...") into 16 bytes.
func ParseUUID(s string) ([16]byte, error) {
	var out [16]byte
	hex := make([]byte, 0, 32)
	for i := 0; i < len(s); i++ {
		if s[i] != '-' {
			hex = append(hex, s[i])
		}
	}
	if len(hex) != 32 {
		return out, fmt.Errorf("vault: bad vault UUID %q", s)
	}
	for i := range out {
		hi, ok1 := unhex(hex[2*i])
		lo, ok2 := unhex(hex[2*i+1])
		if !ok1 || !ok2 {
			return out, fmt.Errorf("vault: bad vault UUID %q", s)
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// Loc locates a record: its segment, the offset of its first byte and its
// total length. Pebble stores it as "uvarint cert_id, segment, offset, len".
type Loc struct {
	Segment uint64
	Offset  uint64
	Len     uint32
}

// Tail is the end of the vault: the next record goes to Segment at Offset.
// The zero Tail is an empty vault.
type Tail struct {
	Segment uint64 `json:"segment"`
	Offset  uint64 `json:"offset"`
}

// Before reports whether t is strictly before u in vault order.
func (t Tail) Before(u Tail) bool {
	return t.Segment < u.Segment || (t.Segment == u.Segment && t.Offset < u.Offset)
}

// Record is one decoded record header plus its compressed frame.
type Record struct {
	Kind     byte
	CertID   uint64
	DictID   uint64 // KindLeaf, KindChain
	BaseSeg  uint64 // KindDelta
	BaseOff  uint64 // KindDelta
	Frame    []byte
	TotalLen int // bytes the record occupies, length prefix included
}

// AppendRecord appends "uvarint body_len | u8 kind | uvarint cert_id | ref |
// frame" to dst.
func AppendRecord(dst []byte, r Record) []byte {
	body := []byte{r.Kind}
	body = binary.AppendUvarint(body, r.CertID)
	switch r.Kind {
	case KindDelta:
		body = binary.AppendUvarint(body, r.BaseSeg)
		body = binary.AppendUvarint(body, r.BaseOff)
	default:
		body = binary.AppendUvarint(body, r.DictID)
	}
	body = append(body, r.Frame...)
	dst = binary.AppendUvarint(dst, uint64(len(body)))
	return append(dst, body...)
}

// ParseRecord reads one record from the start of b. A record that runs past
// the end of b is ErrTorn; one that cannot be interpreted is ErrCorrupt.
func ParseRecord(b []byte) (Record, error) {
	n, k := binary.Uvarint(b)
	if k == 0 {
		return Record{}, ErrTorn
	}
	if k < 0 || n == 0 || n > 1<<30 {
		return Record{}, corrupt("bad record length")
	}
	if uint64(len(b)-k) < n {
		return Record{}, ErrTorn
	}
	body := b[k : k+int(n)]
	r := Record{Kind: body[0], TotalLen: k + int(n)}
	p := 1
	next := func() (uint64, bool) {
		v, m := binary.Uvarint(body[p:])
		if m <= 0 {
			return 0, false
		}
		p += m
		return v, true
	}
	var ok bool
	if r.CertID, ok = next(); !ok {
		return r, corrupt("bad record cert_id")
	}
	switch r.Kind {
	case KindLeaf, KindChain:
		if r.DictID, ok = next(); !ok {
			return r, corrupt("bad record dict_id")
		}
	case KindDelta:
		var ok2 bool
		r.BaseSeg, ok = next()
		r.BaseOff, ok2 = next()
		if !ok || !ok2 {
			return r, corrupt("bad delta base")
		}
	default:
		return r, corrupt("unknown record kind %d", r.Kind)
	}
	r.Frame = body[p:]
	return r, nil
}
```

Create `internal/vault/codec.go`:

```go
package vault

import (
	"fmt"

	"github.com/klauspost/compress/zstd"
)

// maxCert bounds a decompressed certificate: RFC 6962 encodes certificates
// with 24-bit lengths.
const maxCert = 1 << 24

// Codec compresses and decompresses record frames. Frames carry a content
// checksum. A frame's own dictionary ID must equal the record's dict_id, so
// a record can never be decoded with the wrong dictionary. A Codec is not
// safe for concurrent use.
type Codec struct {
	enc map[uint64]*zstd.Encoder // dict_id → encoder
	dec *zstd.Decoder
}

// NewCodec returns a codec that knows only dict_id 0 (no dictionary).
func NewCodec() (*Codec, error) {
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBetterCompression), zstd.WithEncoderCRC(true),
		zstd.WithEncoderConcurrency(1))
	if err != nil {
		return nil, err
	}
	dec, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maxCert))
	if err != nil {
		return nil, err
	}
	return &Codec{enc: map[uint64]*zstd.Encoder{0: enc}, dec: dec}, nil
}

// Compress encodes der with dictionary dictID.
func (c *Codec) Compress(der []byte, dictID uint64) ([]byte, error) {
	e, ok := c.enc[dictID]
	if !ok {
		return nil, fmt.Errorf("vault: no dictionary %d", dictID)
	}
	return e.EncodeAll(der, nil), nil
}

// Decompress decodes a leaf or chain frame written with dictID.
func (c *Codec) Decompress(frame []byte, dictID uint64) ([]byte, error) {
	var h zstd.Header
	if err := h.Decode(frame); err != nil {
		return nil, corrupt("frame header: %v", err)
	}
	if uint64(h.DictionaryID) != dictID {
		return nil, corrupt("frame uses dictionary %d, record says %d", h.DictionaryID, dictID)
	}
	der, err := c.dec.DecodeAll(frame, nil)
	if err != nil {
		return nil, corrupt("decompressing: %v", err)
	}
	return der, nil
}

// Close releases the codec's encoders and decoders.
func (c *Codec) Close() {
	for _, e := range c.enc {
		e.Close()
	}
	c.dec.Close()
}
```

Create `internal/vault/segments.go`:

```go
package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// SegmentsDir and DictDir are the subfolders of every vault directory.
const (
	SegmentsDir = "segments"
	DictDir     = "dict"
)

// SegmentName is a segment's file name: its ID, zero-padded to 10 digits.
func SegmentName(id uint64) string { return fmt.Sprintf("%010d.seg", id) }

// FindSegments lists every segment file in the vault directories, by ID.
// The same ID in two places is corruption (spec §6.2).
func FindSegments(dirs []string) (map[uint64]string, error) {
	out := map[uint64]string{}
	for _, d := range dirs {
		names, err := os.ReadDir(filepath.Join(d, SegmentsDir))
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			base, ok := strings.CutSuffix(n.Name(), ".seg")
			if !ok || n.IsDir() {
				continue
			}
			id, err := strconv.ParseUint(base, 10, 64)
			if err != nil || SegmentName(id) != n.Name() {
				return nil, corrupt("unexpected file %s in %s", n.Name(), d)
			}
			p := filepath.Join(d, SegmentsDir, n.Name())
			if prev, dup := out[id]; dup {
				return nil, corrupt("segment %d exists twice: %s and %s", id, prev, p)
			}
			out[id] = p
		}
	}
	return out, nil
}
```

Create `internal/vault/writer.go`. Note the `WriteAt` calls: a reopened segment's file position is 0, so plain `Write` would overwrite the header. `TestWriteReadAcrossSegments` reads every record back after a reopen to pin this.

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
)

// Writer appends records after the committed tail. It is used by one
// goroutine, the batch writer.
type Writer struct {
	o        Options
	codec    *Codec
	segs     map[uint64]string
	f        *os.File
	seg      uint64
	off      uint64
	sinceChk uint64
	unsynced bool
	dirOfSeg string
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
	w.f, w.dirOfSeg = f, filepath.Dir(p)
	return w, nil
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
	for _, d := range w.o.Dirs {
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
	if w.f == nil || w.off+uint64(len(rec)) > w.o.SegmentSize {
		if err := w.rollover(r.CertID); err != nil {
			return Loc{}, err
		}
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
	// Write at the tracked offset: a reopened segment's file position is 0.
	if _, err := w.f.WriteAt(rec, int64(w.off)); err != nil {
		return Loc{}, err
	}
	loc := Loc{Segment: w.seg, Offset: w.off, Len: uint32(len(rec))}
	w.off += uint64(len(rec))
	w.unsynced = true
	return loc, nil
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

Create `internal/vault/reader.go`:

```go
package vault

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
)

// Reader reads committed records. It is not safe for concurrent use.
type Reader struct {
	codec *Codec
	segs  map[uint64]string
	files map[uint64]*os.File
}

// OpenReader indexes the segments of the vault directories.
func OpenReader(dirs []string, codec *Codec) (*Reader, error) {
	segs, err := FindSegments(dirs)
	if err != nil {
		return nil, err
	}
	return &Reader{codec: codec, segs: segs, files: map[uint64]*os.File{}}, nil
}

func (r *Reader) file(id uint64) (*os.File, error) {
	if f, ok := r.files[id]; ok {
		return f, nil
	}
	p, ok := r.segs[id]
	if !ok {
		return nil, corrupt("segment %d does not exist", id)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	r.files[id] = f
	return f, nil
}

// record reads and parses the record at loc.
func (r *Reader) record(loc Loc) (Record, error) {
	f, err := r.file(loc.Segment)
	if err != nil {
		return Record{}, err
	}
	b := make([]byte, loc.Len)
	if _, err := f.ReadAt(b, int64(loc.Offset)); err != nil {
		if errors.Is(err, io.EOF) {
			return Record{}, corrupt("record %d:%d runs past the end of its segment", loc.Segment, loc.Offset)
		}
		return Record{}, err
	}
	rec, err := ParseRecord(b)
	if err != nil {
		return rec, corrupt("record %d:%d: %v", loc.Segment, loc.Offset, err)
	}
	if rec.TotalLen != int(loc.Len) {
		return rec, corrupt("record %d:%d is %d bytes, location says %d", loc.Segment, loc.Offset, rec.TotalLen, loc.Len)
	}
	return rec, nil
}

// Read returns the certificate DER of the record at loc, and its record.
func (r *Reader) Read(loc Loc) ([]byte, Record, error) {
	rec, err := r.record(loc)
	if err != nil {
		return nil, rec, err
	}
	switch rec.Kind {
	case KindLeaf, KindChain:
		der, err := r.codec.Decompress(rec.Frame, rec.DictID)
		return der, rec, err
	}
	return nil, rec, corrupt("record %d:%d has kind %d", loc.Segment, loc.Offset, rec.Kind)
}

// ReadVerified reads the record at loc and checks its SHA-256. A mismatch is
// corruption (spec §6.2: "SHA-256 is recomputed on read and verified").
func (r *Reader) ReadVerified(loc Loc, want [32]byte) ([]byte, error) {
	der, _, err := r.Read(loc)
	if err != nil {
		return nil, err
	}
	if sha256.Sum256(der) != want {
		return nil, corrupt("record %d:%d does not match its SHA-256", loc.Segment, loc.Offset)
	}
	return der, nil
}

// Close closes the open segment files.
func (r *Reader) Close() {
	for _, f := range r.files {
		f.Close()
	}
	r.files = map[uint64]*os.File{}
}

// Scan calls fn for every record from position from up to (excluding) to,
// in vault order. A record cut short at the very end of the last segment is
// ErrTorn; anything else malformed is ErrCorrupt.
func Scan(dirs []string, from, to Tail, fn func(Loc, Record) error) error {
	segs, err := FindSegments(dirs)
	if err != nil {
		return err
	}
	for id := max(from.Segment, 1); id <= to.Segment; id++ {
		p, ok := segs[id]
		if !ok {
			return corrupt("segment %d is missing", id)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if _, err := DecodeHeader(b); err != nil {
			return fmt.Errorf("segment %d: %w", id, err)
		}
		off := uint64(HeaderSize)
		if id == from.Segment && from.Offset > off {
			off = from.Offset
		}
		end := uint64(len(b))
		if id == to.Segment {
			end = min(end, to.Offset)
		}
		for off < end {
			rec, err := ParseRecord(b[off:end])
			if err != nil {
				return fmt.Errorf("segment %d offset %d: %w", id, off, err)
			}
			if err := fn(Loc{Segment: id, Offset: off, Len: uint32(rec.TotalLen)}, rec); err != nil {
				return err
			}
			off += uint64(rec.TotalLen)
		}
	}
	return nil
}
```

Create `internal/vault/truncate.go`:

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
// discards it. Torn records at the end are expected and tolerated.
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
		start := uint64(0)
		if id == tail.Segment {
			if size < tail.Offset {
				return u, corrupt("segment %d is %d bytes, shorter than the committed tail %d", id, size, tail.Offset)
			}
			start = tail.Offset
		}
		u.Bytes += size - start
		b, err := os.ReadFile(p)
		if err != nil {
			return u, err
		}
		off := start
		if id > tail.Segment {
			// Records follow the header even if the header itself is torn or
			// damaged; their cert_ids still count.
			off = HeaderSize
		}
		for off < size {
			rec, err := ParseRecord(b[off:])
			if err != nil {
				break // torn or garbage: the crash point
			}
			u.MaxCertID = max(u.MaxCertID, rec.CertID)
			off += uint64(rec.TotalLen)
		}
	}
	return u, nil
}

// Truncate removes everything beyond the committed tail: the tail segment is
// cut back to tail.Offset, later segments are deleted, and both are synced.
// Delta records only point backwards, so no committed record loses its base.
func Truncate(dirs []string, tail Tail) error {
	segs, err := FindSegments(dirs)
	if err != nil {
		return err
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

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race -count=1 ./internal/vault/ -v`
Expected: PASS:
- `TestHeader`, `TestRecordCodec`, `TestWriteReadAcrossSegments`
- `TestRolloverPicksFirstDirWithRoom`, `TestAppendsRecheckTheCap`
- `TestReadDetectsCorruption`, `TestDecompressChecksTheFrameDictionary`, `TestDuplicateSegmentIsCorruption`
- `TestInspectAndTruncateUncommittedData`, `TestOpenWriterRefusesSegmentsBeyondTail`, `TestRolloverHooks`

- [ ] **Step 5: Gate and commit**

Run the gate commands from Global Constraints. All must pass.

```bash
git add internal/vault go.mod go.sum
git commit -m "feat: vault segments and records with checked headers, rollover across vault dirs, verified reads, tail truncation"
```

---

### Task B2: Dictionaries and leaf-delta

Implements spec §6.2 (dictionaries, `leaf-delta`) and amendment A1 §5.

**Files:**
- Modify: `internal/vault/codec.go`, `internal/vault/writer.go`, `internal/vault/reader.go`, `internal/leaf/precert.go`
- Create: `internal/vault/dict.go`, `internal/vault/delta.go`
- Create tests: `internal/vault/dict_test.go`, `internal/vault/delta_test.go`, `internal/leaf/digest_test.go`

**Interfaces:**
- Consumes: Task B1's `Codec`, `Writer`, `Reader` and `Scan`; Plan 2A's `leaf.Decode` and `IssuanceDigest`.
- Produces:
  - `vault` codec:
    - `(*Codec).AddDict(id, content)`
    - `(*Codec).CompressDelta(der, base)` and `DecompressDelta(frame, base)`
  - `vault` writer and reader:
    - `(*Writer).AppendDelta(certID, der, base Loc) (Loc, error)`
    - `Read` resolves delta bases
  - `vault` dictionaries:
    - `TrainingSamples=20000`, `MaxDictSize`
    - `type DictManifest`, `type Training struct{ Records int; FirstCertID, LastCertID uint64 }`, `type Dict`
    - `LoadDicts(dirs)`, `InstallDict(dirs, id, content, training, now)`
    - `Train(samples, id)`, `TrainingSet(dirs, codec, tail, n)`, `LibraryVersion()`
  - `vault` delta cache:
    - `type DeltaCache` with `NewDeltaCache(capacity)`, `Put`, `Get` and `Len`
    - `type Range struct{ Start, End Tail }`
    - `Warm(dirs, codec, cache, ranges, digest)`
  - `leaf.PrecertIssuanceDigest(der []byte) ([32]byte, bool)`

- [ ] **Step 1: Write the failing tests**

Create `internal/vault/dict_test.go`:

```go
package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"strings"
	"testing"
)

func trainOn(t *testing.T, n int) ([][]byte, []byte) {
	t.Helper()
	cs := certs(t, n)
	content, err := Train(cs, 1)
	if err != nil {
		t.Fatal(err)
	}
	return cs, content
}

func TestTrainInstallLoadAndUse(t *testing.T) {
	cs, content := trainOn(t, 120)
	dirs := vaultDirs(t, 2)
	tr := Training{Records: 120, FirstCertID: 1, LastCertID: 120}
	if _, err := InstallDict(dirs, 1, content, tr, fixedNow()); err != nil {
		t.Fatal(err)
	}
	ds, err := LoadDicts(dirs)
	if err != nil || len(ds) != 1 {
		t.Fatalf("LoadDicts: %d dictionaries, %v", len(ds), err)
	}
	m := ds[0].Manifest
	if m.ID != 1 || m.Training != tr || m.Bytes != len(content) || !strings.HasPrefix(m.Library, "github.com/klauspost/compress") {
		t.Fatalf("manifest %+v", m)
	}
	c := codec(t)
	if err := c.AddDict(1, ds[0].Content); err != nil {
		t.Fatal(err)
	}
	w, err := OpenWriter(Options{Dirs: dirs, VaultUUID: testUUID, SegmentSize: 1 << 20, Now: fixedNow}, c, Tail{})
	if err != nil {
		t.Fatal(err)
	}
	var with, without int
	for i, der := range cs[:20] {
		a, _ := w.AppendCert(KindLeaf, uint64(2*i+1), der, 1)
		b, _ := w.AppendCert(KindLeaf, uint64(2*i+2), der, 0)
		with, without = with+int(a.Len), without+int(b.Len)
		r, _ := OpenReader(dirs, c)
		if got, err := r.ReadVerified(a, sha256.Sum256(der)); err != nil || string(got) != string(der) {
			t.Fatalf("dictionary record %d: %v", i, err)
		}
		r.Close()
	}
	w.Close()
	if with >= without {
		t.Fatalf("the trained dictionary must shrink records: %d vs %d bytes", with, without)
	}
	frame, _ := c.Compress(cs[0], 1)
	if _, err := c.Decompress(frame, 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a dictionary-1 frame in a record claiming no dictionary is corrupt: %v", err)
	}
}

func TestDictsAreImmutableAndReplicated(t *testing.T) {
	_, content := trainOn(t, 80)
	dirs := vaultDirs(t, 2)
	if _, err := InstallDict(dirs, 1, content, Training{}, fixedNow()); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallDict(dirs, 1, content, Training{}, fixedNow()); err == nil {
		t.Fatal("a dictionary ID is never reused")
	}
	cp, mp := dictFiles(dirs[1], 1)
	os.Remove(mp)
	os.Remove(cp)
	if _, err := LoadDicts(dirs); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(mp); err != nil {
		t.Fatal("LoadDicts must restore a replica an interrupted install left missing")
	}
	cp0, _ := dictFiles(dirs[0], 1)
	os.Chmod(cp0, 0o644)
	b, _ := os.ReadFile(cp0)
	b[10] ^= 1
	os.WriteFile(cp0, b, 0o644)
	if _, err := LoadDicts(dirs); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a dictionary that no longer matches its manifest is corruption: %v", err)
	}
}

// TestTrainFailureFallsBack: ingestion continues with dictionary 0 when
// training fails (amendment A1 §5), including when the library panics.
func TestTrainFailureFallsBack(t *testing.T) {
	if _, err := Train([][]byte{[]byte("a"), []byte("b")}, 1); err == nil {
		t.Fatal("degenerate samples (the library divides by zero on them) must give an error, not a panic")
	}
	noise := make([][]byte, 60)
	for i := range noise {
		noise[i] = make([]byte, 1500)
		rand.Read(noise[i])
	}
	if _, err := Train(noise, 1); err == nil {
		t.Fatal("a dictionary that does not shrink its own samples is unusable")
	}
}

func TestTrainingSetReadsCommittedLeaves(t *testing.T) {
	dirs := vaultDirs(t, 1)
	cs := certs(t, 10)
	w := openWriter(t, dirs, 1<<20, Tail{}, nil)
	w.AppendCert(KindChain, 1, cs[0], 0)
	for i := 1; i < 10; i++ {
		w.AppendCert(KindLeaf, uint64(i+1), cs[i], 0)
	}
	w.Sync()
	tail := w.Tail()
	w.AppendCert(KindLeaf, 11, cs[0], 0) // beyond the committed tail
	w.Close()
	got, tr, err := TrainingSet(dirs, codec(t), tail, 5)
	if err != nil || len(got) != 5 || string(got[0]) != string(cs[1]) || tr != (Training{Records: 5, FirstCertID: 2, LastCertID: 6}) {
		t.Fatalf("the first 5 leaf records (chains skipped): %d, %+v, %v", len(got), tr, err)
	}
	all, tr, _ := TrainingSet(dirs, codec(t), tail, 100)
	if len(all) != 9 || tr.LastCertID != 10 {
		t.Fatalf("never past the committed tail: %d records, %+v", len(all), tr)
	}
}
```

Create `internal/vault/delta_test.go`:

```go
package vault

import (
	"crypto/sha256"
	"errors"
	"os"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/leaf"
)

func pairs(t *testing.T, n int) (pres, finals [][]byte) {
	t.Helper()
	g, err := ctlogtest.NewGenerator()
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		p, f, err := g.Pair("delta.example.test", uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		pres, finals = append(pres, p.CertDER), append(finals, f.CertDER)
	}
	return pres, finals
}

func TestDeltaRoundTrip(t *testing.T) {
	dirs := vaultDirs(t, 1)
	pres, finals := pairs(t, 5)
	w := openWriter(t, dirs, 1<<20, Tail{}, nil)
	var bases, deltas, fulls []Loc
	for i := range pres {
		b, _ := w.AppendCert(KindLeaf, uint64(3*i+1), pres[i], 0)
		d, err := w.AppendDelta(uint64(3*i+2), finals[i], b) // base still unsynced: same batch
		if err != nil {
			t.Fatal(err)
		}
		f, _ := w.AppendCert(KindLeaf, uint64(3*i+3), finals[i], 0)
		bases, deltas, fulls = append(bases, b), append(deltas, d), append(fulls, f)
	}
	w.Sync()
	w.Close()
	r, _ := OpenReader(dirs, codec(t))
	defer r.Close()
	saved := 0
	for i := range finals {
		got, err := r.ReadVerified(deltas[i], sha256.Sum256(finals[i]))
		if err != nil || string(got) != string(finals[i]) {
			t.Fatalf("delta %d: %v", i, err)
		}
		saved += int(fulls[i].Len) - int(deltas[i].Len)
	}
	if saved <= 0 {
		t.Fatalf("a final certificate against its own precert must be smaller than in full (saved %d bytes)", saved)
	}
}

func TestDeltaCorruption(t *testing.T) {
	dirs := vaultDirs(t, 1)
	pres, finals := pairs(t, 1)
	w := openWriter(t, dirs, 1<<20, Tail{}, nil)
	chain, _ := w.AppendCert(KindChain, 1, pres[0], 0)
	if _, err := w.AppendDelta(2, finals[0], chain); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a delta base must be a leaf record: %v", err)
	}
	base, _ := w.AppendCert(KindLeaf, 3, pres[0], 0)
	d, _ := w.AppendDelta(4, finals[0], base)
	w.Sync()
	w.Close()

	// A record claiming a base that is not a leaf, or lies ahead, is corrupt.
	segs, _ := FindSegments(dirs)
	b, _ := os.ReadFile(segs[1])
	forged := AppendRecord(nil, Record{Kind: KindDelta, CertID: 5, BaseSeg: 1, BaseOff: chain.Offset, Frame: []byte{0x28, 0xb5}})
	ahead := AppendRecord(nil, Record{Kind: KindDelta, CertID: 6, BaseSeg: 1, BaseOff: 1 << 20, Frame: []byte{0x28, 0xb5}})
	os.WriteFile(segs[1], append(append(b, forged...), ahead...), 0o644)
	r, _ := OpenReader(dirs, codec(t))
	defer r.Close()
	if _, err := r.ReadVerified(d, sha256.Sum256(finals[0])); err != nil {
		t.Fatalf("the real delta still reads: %v", err)
	}
	fl := Loc{Segment: 1, Offset: uint64(len(b)), Len: uint32(len(forged))}
	if _, _, err := r.Read(fl); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a chain record as delta base: %v", err)
	}
	al := Loc{Segment: 1, Offset: uint64(len(b) + len(forged)), Len: uint32(len(ahead))}
	if _, _, err := r.Read(al); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a base ahead of the delta: %v", err)
	}
}

func TestDeltaCache(t *testing.T) {
	c := NewDeltaCache(3)
	for i := range 4 {
		c.Put([32]byte{byte(i + 1)}, Loc{Segment: uint64(i)})
	}
	if _, ok := c.Get([32]byte{1}); ok || c.Len() != 3 {
		t.Fatalf("the oldest entry is evicted at capacity: len %d", c.Len())
	}
	if l, ok := c.Get([32]byte{4}); !ok || l.Segment != 3 {
		t.Fatal("the newest entry is cached")
	}
	c.Put([32]byte{4}, Loc{Segment: 9})
	if l, _ := c.Get([32]byte{4}); l.Segment != 9 || c.Len() != 3 {
		t.Fatal("re-putting a digest updates it in place")
	}
	off := NewDeltaCache(0)
	off.Put([32]byte{1}, Loc{})
	if _, ok := off.Get([32]byte{1}); ok {
		t.Fatal("capacity 0 disables the cache")
	}
}

// TestWarmFindsPrecertsInRanges: after a restart the cache is refilled from
// the last committed batches; only precerts enter it, keyed so that their
// final certificates find them.
func TestWarmFindsPrecertsInRanges(t *testing.T) {
	dirs := vaultDirs(t, 1)
	g, _ := ctlogtest.NewGenerator()
	w := openWriter(t, dirs, 4<<10, Tail{}, nil)
	var rs []Range
	var finalDigests [][32]byte
	var preLocs []Loc
	id := uint64(0)
	for batch := range 3 {
		start := w.Tail()
		for i := range 3 {
			p, f, _ := g.Pair("warm.example.test", uint64(batch*10+i))
			id++
			l, _ := w.AppendCert(KindLeaf, id, p.CertDER, 0)
			id++
			w.AppendCert(KindLeaf, id, f.CertDER, 0)
			preLocs = append(preLocs, l)
			finalDigests = append(finalDigests, leaf.Decode(f.LeafInput, f.ExtraData).IssuanceDigest)
		}
		rs = append(rs, Range{Start: start, End: w.Tail()})
	}
	w.Sync()
	w.Close()
	c := NewDeltaCache(100)
	if err := Warm(dirs, codec(t), c, rs[1:], leaf.PrecertIssuanceDigest); err != nil {
		t.Fatal(err)
	}
	if c.Len() != 6 {
		t.Fatalf("two batches hold 6 precerts (finals are not cached): %d", c.Len())
	}
	if _, ok := c.Get(finalDigests[0]); ok {
		t.Fatal("the first batch was outside the warm-up window")
	}
	if l, ok := c.Get(finalDigests[4]); !ok || l != preLocs[4] {
		t.Fatalf("final 4 must find its precert: %+v %v", l, ok)
	}
}

// TestDeltaCacheNeedsTheFullDigest: two digests sharing their first 16
// bytes never return each other's precert.
func TestDeltaCacheNeedsTheFullDigest(t *testing.T) {
	c := NewDeltaCache(10)
	a, b := [32]byte{7}, [32]byte{7}
	b[31] = 1
	c.Put(a, Loc{Segment: 1})
	if _, ok := c.Get(b); ok {
		t.Fatal("a 16-byte prefix match is not a hit")
	}
	c.Put(b, Loc{Segment: 2})
	if l, ok := c.Get(b); !ok || l.Segment != 2 {
		t.Fatal("the newer of two colliding digests wins")
	}
	if _, ok := c.Get(a); ok {
		t.Fatal("the displaced digest misses (stored in full instead)")
	}
	for i := range 20 { // wrap the ring past the displaced slot
		c.Put([32]byte{byte(100 + i)}, Loc{Segment: uint64(i)})
	}
	if c.Len() != 10 {
		t.Fatalf("len %d after wrapping, want 10", c.Len())
	}
}
```

Create `internal/leaf/digest_test.go`:

```go
package leaf_test

import (
	"testing"

	"github.com/4rji/ctvault/internal/leaf"
)

func TestPrecertIssuanceDigest(t *testing.T) {
	g := generator(t)
	pre, fin := pair(t, g, false)
	got, ok := leaf.PrecertIssuanceDigest(pre.CertDER)
	if !ok || got != leaf.Decode(fin.LeafInput, fin.ExtraData).IssuanceDigest {
		t.Fatal("a CA-issued precert's own DER must give the digest its final certificate links on")
	}
	if _, ok := leaf.PrecertIssuanceDigest(fin.CertDER); ok {
		t.Fatal("a final certificate (no poison) is not a precert")
	}
	if _, ok := leaf.PrecertIssuanceDigest([]byte{0x30, 0x00}); ok {
		t.Fatal("unparseable DER is not a precert")
	}
	sPre, sFin := pair(t, g, true)
	if d, ok := leaf.PrecertIssuanceDigest(sPre.CertDER); !ok || d == leaf.Decode(sFin.LeafInput, sFin.ExtraData).IssuanceDigest {
		t.Fatal("a signer-issued precert gets a digest that misses (its TBS carries the signer's name)")
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/vault/ ./internal/leaf/`
Expected: FAIL with `undefined: leaf.PrecertIssuanceDigest` in `internal/leaf`, and `w.AppendDelta undefined (type *Writer has no field or method AppendDelta)` in `internal/vault`.

- [ ] **Step 3: Implement dictionaries and deltas**

Replace `internal/vault/codec.go`:

```go
package vault

import (
	"fmt"

	"github.com/klauspost/compress/zstd"
)

// maxCert bounds a decompressed certificate: RFC 6962 encodes certificates
// with 24-bit lengths.
const maxCert = 1 << 24

// Codec compresses and decompresses record frames. Frames carry a content
// checksum. A frame's own dictionary ID must equal the record's dict_id, so
// a record can never be decoded with the wrong dictionary. Leaf and chain
// frames use the better level; delta frames use the default level, which is
// as small for deltas and 3.5x faster (measured 2026-10-04). Delta frames
// use their base certificate as a raw dictionary with ID 0, so the frame's
// dictionary ID is omitted (spec §6.2). A Codec is not safe for concurrent
// use.
type Codec struct {
	enc      map[uint64]*zstd.Encoder // dict_id → encoder
	dicts    map[uint64][]byte        // trained dictionaries by ID
	dec      *zstd.Decoder            // leaf and chain frames
	deltaEnc *zstd.Encoder            // reset with each base
	deltaDec *zstd.Decoder            // reset with each base
}

func newDecoder(dicts map[uint64][]byte) (*zstd.Decoder, error) {
	opts := []zstd.DOption{zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maxCert)}
	var ds [][]byte
	for _, d := range dicts {
		ds = append(ds, d)
	}
	if len(ds) > 0 {
		opts = append(opts, zstd.WithDecoderDicts(ds...))
	}
	return zstd.NewReader(nil, opts...)
}

// NewCodec returns a codec that knows dict_id 0 (no dictionary).
func NewCodec() (*Codec, error) {
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBetterCompression), zstd.WithEncoderCRC(true),
		zstd.WithEncoderConcurrency(1))
	if err != nil {
		return nil, err
	}
	dec, err := newDecoder(nil)
	if err != nil {
		return nil, err
	}
	deltaEnc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderCRC(true),
		zstd.WithEncoderConcurrency(1))
	if err != nil {
		return nil, err
	}
	deltaDec, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maxCert))
	if err != nil {
		return nil, err
	}
	return &Codec{enc: map[uint64]*zstd.Encoder{0: enc}, dicts: map[uint64][]byte{}, dec: dec,
		deltaEnc: deltaEnc, deltaDec: deltaDec}, nil
}

// AddDict registers trained dictionary id (a zstd dictionary whose own ID
// is id) for compression and decompression.
func (c *Codec) AddDict(id uint64, content []byte) error {
	if id == 0 {
		return fmt.Errorf("vault: dictionary ID 0 means no dictionary")
	}
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBetterCompression), zstd.WithEncoderCRC(true),
		zstd.WithEncoderConcurrency(1), zstd.WithEncoderDict(content))
	if err != nil {
		return fmt.Errorf("vault: dictionary %d: %w", id, err)
	}
	dicts := map[uint64][]byte{id: content}
	for k, v := range c.dicts {
		dicts[k] = v
	}
	dec, err := newDecoder(dicts)
	if err != nil {
		enc.Close()
		return fmt.Errorf("vault: dictionary %d: %w", id, err)
	}
	c.dec.Close()
	c.dec, c.dicts, c.enc[id] = dec, dicts, enc
	return nil
}

// CompressDelta encodes der against base (spec §6.2 leaf-delta).
func (c *Codec) CompressDelta(der, base []byte) ([]byte, error) {
	if err := c.deltaEnc.ResetWithOptions(nil, zstd.WithEncoderDictRaw(0, base)); err != nil {
		return nil, err
	}
	return c.deltaEnc.EncodeAll(der, nil), nil
}

// DecompressDelta decodes a delta frame against its base.
func (c *Codec) DecompressDelta(frame, base []byte) ([]byte, error) {
	var h zstd.Header
	if err := h.Decode(frame); err != nil {
		return nil, corrupt("delta frame header: %v", err)
	}
	if h.DictionaryID != 0 {
		return nil, corrupt("delta frame names dictionary %d", h.DictionaryID)
	}
	if err := c.deltaDec.ResetWithOptions(nil, zstd.WithDecoderDictRaw(0, base)); err != nil {
		return nil, err
	}
	der, err := c.deltaDec.DecodeAll(frame, nil)
	if err != nil {
		return nil, corrupt("decompressing delta: %v", err)
	}
	return der, nil
}

// Compress encodes der with dictionary dictID.
func (c *Codec) Compress(der []byte, dictID uint64) ([]byte, error) {
	e, ok := c.enc[dictID]
	if !ok {
		return nil, fmt.Errorf("vault: no dictionary %d", dictID)
	}
	return e.EncodeAll(der, nil), nil
}

// Decompress decodes a leaf or chain frame written with dictID.
func (c *Codec) Decompress(frame []byte, dictID uint64) ([]byte, error) {
	var h zstd.Header
	if err := h.Decode(frame); err != nil {
		return nil, corrupt("frame header: %v", err)
	}
	if uint64(h.DictionaryID) != dictID {
		return nil, corrupt("frame uses dictionary %d, record says %d", h.DictionaryID, dictID)
	}
	der, err := c.dec.DecodeAll(frame, nil)
	if err != nil {
		return nil, corrupt("decompressing: %v", err)
	}
	return der, nil
}

// Close releases the codec's encoders and decoders.
func (c *Codec) Close() {
	for _, e := range c.enc {
		e.Close()
	}
	c.dec.Close()
	c.deltaEnc.Close()
	c.deltaDec.Close()
}
```

Replace `internal/vault/writer.go`:

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
)

// Writer appends records after the committed tail. It is used by one
// goroutine, the batch writer.
type Writer struct {
	o        Options
	codec    *Codec
	segs     map[uint64]string
	f        *os.File
	seg      uint64
	off      uint64
	sinceChk uint64
	unsynced bool
	dirOfSeg string
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
	w.f, w.dirOfSeg = f, filepath.Dir(p)
	return w, nil
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
	for _, d := range w.o.Dirs {
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
	if w.f == nil || w.off+uint64(len(rec)) > w.o.SegmentSize {
		if err := w.rollover(r.CertID); err != nil {
			return Loc{}, err
		}
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
	// Write at the tracked offset: a reopened segment's file position is 0.
	if _, err := w.f.WriteAt(rec, int64(w.off)); err != nil {
		return Loc{}, err
	}
	loc := Loc{Segment: w.seg, Offset: w.off, Len: uint32(len(rec))}
	w.off += uint64(len(rec))
	w.unsynced = true
	return loc, nil
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

Replace `internal/vault/reader.go`:

```go
package vault

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// Reader reads committed records. It is not safe for concurrent use.
type Reader struct {
	codec *Codec
	segs  map[uint64]string
	files map[uint64]*os.File
}

// OpenReader indexes the segments of the vault directories.
func OpenReader(dirs []string, codec *Codec) (*Reader, error) {
	segs, err := FindSegments(dirs)
	if err != nil {
		return nil, err
	}
	return &Reader{codec: codec, segs: segs, files: map[uint64]*os.File{}}, nil
}

func (r *Reader) file(id uint64) (*os.File, error) {
	if f, ok := r.files[id]; ok {
		return f, nil
	}
	p, ok := r.segs[id]
	if !ok {
		return nil, corrupt("segment %d does not exist", id)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	r.files[id] = f
	return f, nil
}

// recordAt reads the record that starts at (segment, offset), whose length
// is taken from its own prefix: delta references carry no length.
func (r *Reader) recordAt(seg, off uint64) (Record, Loc, error) {
	f, err := r.file(seg)
	if err != nil {
		return Record{}, Loc{}, err
	}
	var prefix [binary.MaxVarintLen64]byte
	n, err := f.ReadAt(prefix[:], int64(off))
	if err != nil && !errors.Is(err, io.EOF) {
		return Record{}, Loc{}, err
	}
	body, k := binary.Uvarint(prefix[:n])
	if k <= 0 || body > 1<<30 {
		return Record{}, Loc{}, corrupt("no record at %d:%d", seg, off)
	}
	loc := Loc{Segment: seg, Offset: off, Len: uint32(uint64(k) + body)}
	rec, err := r.record(loc)
	return rec, loc, err
}

// record reads and parses the record at loc.
func (r *Reader) record(loc Loc) (Record, error) {
	f, err := r.file(loc.Segment)
	if err != nil {
		return Record{}, err
	}
	b := make([]byte, loc.Len)
	if _, err := f.ReadAt(b, int64(loc.Offset)); err != nil {
		if errors.Is(err, io.EOF) {
			return Record{}, corrupt("record %d:%d runs past the end of its segment", loc.Segment, loc.Offset)
		}
		return Record{}, err
	}
	rec, err := ParseRecord(b)
	if err != nil {
		return rec, corrupt("record %d:%d: %v", loc.Segment, loc.Offset, err)
	}
	if rec.TotalLen != int(loc.Len) {
		return rec, corrupt("record %d:%d is %d bytes, location says %d", loc.Segment, loc.Offset, rec.TotalLen, loc.Len)
	}
	return rec, nil
}

// Read returns the certificate DER of the record at loc, and its record.
func (r *Reader) Read(loc Loc) ([]byte, Record, error) {
	rec, err := r.record(loc)
	if err != nil {
		return nil, rec, err
	}
	switch rec.Kind {
	case KindLeaf, KindChain:
		der, err := r.codec.Decompress(rec.Frame, rec.DictID)
		return der, rec, err
	case KindDelta:
		if rec.BaseSeg > loc.Segment || (rec.BaseSeg == loc.Segment && rec.BaseOff >= loc.Offset) {
			return nil, rec, corrupt("delta %d:%d points forward to %d:%d", loc.Segment, loc.Offset, rec.BaseSeg, rec.BaseOff)
		}
		base, _, err := r.recordAt(rec.BaseSeg, rec.BaseOff)
		if err != nil {
			return nil, rec, corrupt("delta %d:%d: unresolvable base: %v", loc.Segment, loc.Offset, err)
		}
		if base.Kind != KindLeaf {
			return nil, rec, corrupt("delta %d:%d: base is a kind %d record", loc.Segment, loc.Offset, base.Kind)
		}
		baseDER, err := r.codec.Decompress(base.Frame, base.DictID)
		if err != nil {
			return nil, rec, err
		}
		der, err := r.codec.DecompressDelta(rec.Frame, baseDER)
		return der, rec, err
	}
	return nil, rec, corrupt("record %d:%d has kind %d", loc.Segment, loc.Offset, rec.Kind)
}

// ReadVerified reads the record at loc and checks its SHA-256. A mismatch is
// corruption (spec §6.2: "SHA-256 is recomputed on read and verified").
func (r *Reader) ReadVerified(loc Loc, want [32]byte) ([]byte, error) {
	der, _, err := r.Read(loc)
	if err != nil {
		return nil, err
	}
	if sha256.Sum256(der) != want {
		return nil, corrupt("record %d:%d does not match its SHA-256", loc.Segment, loc.Offset)
	}
	return der, nil
}

// Close closes the open segment files.
func (r *Reader) Close() {
	for _, f := range r.files {
		f.Close()
	}
	r.files = map[uint64]*os.File{}
}

// Scan calls fn for every record from position from up to (excluding) to,
// in vault order. A record cut short at the very end of the last segment is
// ErrTorn; anything else malformed is ErrCorrupt.
func Scan(dirs []string, from, to Tail, fn func(Loc, Record) error) error {
	segs, err := FindSegments(dirs)
	if err != nil {
		return err
	}
	for id := max(from.Segment, 1); id <= to.Segment; id++ {
		p, ok := segs[id]
		if !ok {
			return corrupt("segment %d is missing", id)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if _, err := DecodeHeader(b); err != nil {
			return fmt.Errorf("segment %d: %w", id, err)
		}
		off := uint64(HeaderSize)
		if id == from.Segment && from.Offset > off {
			off = from.Offset
		}
		end := uint64(len(b))
		if id == to.Segment {
			end = min(end, to.Offset)
		}
		for off < end {
			rec, err := ParseRecord(b[off:end])
			if err != nil {
				return fmt.Errorf("segment %d offset %d: %w", id, off, err)
			}
			if err := fn(Loc{Segment: id, Offset: off, Len: uint32(rec.TotalLen)}, rec); err != nil {
				return err
			}
			off += uint64(rec.TotalLen)
		}
	}
	return nil
}
```

Create `internal/vault/dict.go`. `Train` recovers from a panic: `dict.BuildZstdDict` divides by zero on degenerate input, as `TestTrainFailureFallsBack` shows.

```go
package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/dict"

	"github.com/4rji/ctvault/internal/fsutil"
)

// Dictionary training (spec §6.2, amendment A1 §5).
const (
	TrainingSamples = 20000     // the first 20,000 leaf certificates in vault order
	MaxDictSize     = 110 << 10 // spec §3.4: a global 110 KB dictionary
)

// DictManifest is dict/<id>.json, written next to dict/<id>.zdict in every
// vault directory. Nothing assumes that retraining with another library
// version would reproduce the same bytes.
type DictManifest struct {
	Format    int       `json:"format"`
	ID        uint64    `json:"id"`
	SHA256    string    `json:"sha256"`
	Bytes     int       `json:"bytes"`
	Library   string    `json:"library"` // e.g. "github.com/klauspost/compress v1.20.1"
	Training  Training  `json:"training"`
	CreatedAt time.Time `json:"created_at"`
}

// Training records which certificates a dictionary was trained on.
type Training struct {
	Records     int    `json:"records"`
	FirstCertID uint64 `json:"first_cert_id"`
	LastCertID  uint64 `json:"last_cert_id"`
}

// Dict is a verified dictionary.
type Dict struct {
	Manifest DictManifest
	Content  []byte
}

// LibraryVersion names the zstd implementation in this binary.
func LibraryVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/klauspost/compress" {
				return d.Path + " " + d.Version
			}
		}
	}
	return "github.com/klauspost/compress (version unknown)"
}

func dictFiles(dir string, id uint64) (content, manifest string) {
	base := filepath.Join(dir, DictDir, strconv.FormatUint(id, 10))
	return base + ".zdict", base + ".json"
}

// LoadDicts reads every dictionary, checks each against its manifest, and
// repairs replicas that an interrupted install left missing. Dictionaries
// are immutable: two different copies of one ID are corruption.
func LoadDicts(dirs []string) ([]Dict, error) {
	found := map[uint64]Dict{}
	for _, d := range dirs {
		names, err := os.ReadDir(filepath.Join(d, DictDir))
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			base, ok := strings.CutSuffix(n.Name(), ".json")
			if !ok {
				continue
			}
			id, err := strconv.ParseUint(base, 10, 64)
			if err != nil || id == 0 {
				return nil, corrupt("unexpected dictionary manifest %s in %s", n.Name(), d)
			}
			got, err := readDict(d, id)
			if err != nil {
				return nil, err
			}
			if prev, ok := found[id]; ok && !bytes.Equal(prev.Content, got.Content) {
				return nil, corrupt("dictionary %d differs between vault directories", id)
			}
			found[id] = got
		}
	}
	var out []Dict
	for _, dct := range found {
		out = append(out, dct)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Manifest.ID < out[j].Manifest.ID })
	for _, dct := range out {
		if err := replicate(dirs, dct); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func readDict(dir string, id uint64) (Dict, error) {
	cp, mp := dictFiles(dir, id)
	mb, err := os.ReadFile(mp)
	if err != nil {
		return Dict{}, err
	}
	var m DictManifest
	if err := json.Unmarshal(mb, &m); err != nil || m.ID != id {
		return Dict{}, corrupt("dictionary manifest %s is unreadable", mp)
	}
	content, err := os.ReadFile(cp)
	if err != nil {
		return Dict{}, corrupt("dictionary %d content: %v", id, err)
	}
	sum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) != m.SHA256 || len(content) != m.Bytes {
		return Dict{}, corrupt("dictionary %d in %s does not match its manifest", id, dir)
	}
	return Dict{Manifest: m, Content: content}, nil
}

// replicate writes dct to every directory that lacks it: content first, then
// the manifest, which marks the copy complete.
func replicate(dirs []string, dct Dict) error {
	mb, err := json.MarshalIndent(dct.Manifest, "", " ")
	if err != nil {
		return err
	}
	for _, d := range dirs {
		cp, mp := dictFiles(d, dct.Manifest.ID)
		if _, err := os.Stat(mp); err == nil {
			continue
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := fsutil.WriteFileAtomic(cp, dct.Content, 0o444); err != nil {
			return err
		}
		if err := fsutil.WriteFileAtomic(mp, mb, 0o444); err != nil {
			return err
		}
	}
	return nil
}

// InstallDict persists a new dictionary in every vault directory. Records may
// use it only after InstallDict returns.
func InstallDict(dirs []string, id uint64, content []byte, t Training, now time.Time) (Dict, error) {
	for _, d := range dirs {
		if _, mp := dictFiles(d, id); fileExists(mp) {
			return Dict{}, fmt.Errorf("vault: dictionary %d already exists; dictionaries are immutable", id)
		}
	}
	sum := sha256.Sum256(content)
	dct := Dict{Content: content, Manifest: DictManifest{Format: 1, ID: id, SHA256: hex.EncodeToString(sum[:]),
		Bytes: len(content), Library: LibraryVersion(), Training: t, CreatedAt: now.UTC()}}
	return dct, replicate(dirs, dct)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// Train builds a dictionary from samples and checks that it helps: the
// samples must compress smaller with it than without. A library panic, an
// error or an unhelpful dictionary is reported as an error, and ingestion
// continues with dictionary 0 (amendment A1 §5).
func Train(samples [][]byte, id uint64) (content []byte, err error) {
	defer func() {
		if p := recover(); p != nil {
			content, err = nil, fmt.Errorf("vault: dictionary training panicked: %v", p)
		}
	}()
	content, err = dict.BuildZstdDict(samples, dict.Options{MaxDictSize: MaxDictSize, HashBytes: 6, ZstdDictID: uint32(id)})
	if err != nil {
		return nil, fmt.Errorf("vault: dictionary training: %w", err)
	}
	c, err := NewCodec()
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if err := c.AddDict(id, content); err != nil {
		return nil, err
	}
	var with, without int
	for _, s := range samples {
		a, _ := c.Compress(s, id)
		b, _ := c.Compress(s, 0)
		with, without = with+len(a), without+len(b)
	}
	if with >= without {
		return nil, fmt.Errorf("vault: trained dictionary does not help (%d bytes with it, %d without)", with, without)
	}
	return content, nil
}

// TrainingSet reads the first n leaf records in vault order, up to the
// committed tail, from committed data only, so training is crash-safe.
func TrainingSet(dirs []string, codec *Codec, tail Tail, n int) ([][]byte, Training, error) {
	var out [][]byte
	var t Training
	stop := errors.New("enough")
	err := Scan(dirs, Tail{}, tail, func(loc Loc, rec Record) error {
		if rec.Kind != KindLeaf {
			return nil
		}
		der, err := codec.Decompress(rec.Frame, rec.DictID)
		if err != nil {
			return err
		}
		if t.Records == 0 {
			t.FirstCertID = rec.CertID
		}
		out = append(out, der)
		t.Records, t.LastCertID = t.Records+1, rec.CertID
		if len(out) == n {
			return stop
		}
		return nil
	})
	if err != nil && !errors.Is(err, stop) {
		return nil, t, err
	}
	return out, t, nil
}
```

Create `internal/vault/delta.go`:

```go
package vault

// DeltaCache maps a precert's full 32-byte issuance digest to its vault
// record, for recently vaulted precerts (spec §6.2, amendment A1 §5). It is
// an optimization only: an eviction or a restart simply stores the final
// certificate in full. Entries are evicted oldest first, which for
// precerts inserted once and looked up once behaves like an LRU.
//
// Layout: a ring of (full digest, location) and a map from the digest's
// first 16 bytes to a ring slot. A hit requires all 32 bytes to match. On a
// 16-byte prefix collision the newer precert wins, which only costs a
// delta. The default 2M entries take 207 MiB of heap (measured 2026-10-04;
// spec §6.2 estimated about 128 MB), against 317 MiB for a map keyed by the
// full digest. Lower ingest.delta_lru_entries on small machines.
type DeltaCache struct {
	idx  map[[16]byte]int32
	ring []cacheSlot
	next int
}

type cacheSlot struct {
	digest [32]byte
	loc    Loc
	used   bool
}

// NewDeltaCache holds at most capacity entries (ingest.delta_lru_entries);
// capacity 0 disables the cache.
func NewDeltaCache(capacity int) *DeltaCache {
	return &DeltaCache{idx: make(map[[16]byte]int32, capacity), ring: make([]cacheSlot, capacity)}
}

func prefix(d [32]byte) (p [16]byte) {
	copy(p[:], d[:16])
	return p
}

// Put records a precert's location, evicting the oldest entry when full.
func (c *DeltaCache) Put(digest [32]byte, loc Loc) {
	if len(c.ring) == 0 {
		return
	}
	k := prefix(digest)
	if i, ok := c.idx[k]; ok && c.ring[i].digest == digest {
		c.ring[i].loc = loc
		return
	}
	slot := &c.ring[c.next]
	if slot.used {
		if old := prefix(slot.digest); c.idx[old] == int32(c.next) {
			delete(c.idx, old)
		}
	}
	*slot = cacheSlot{digest: digest, loc: loc, used: true}
	c.idx[k] = int32(c.next)
	c.next = (c.next + 1) % len(c.ring)
}

// Get returns the precert record for digest.
func (c *DeltaCache) Get(digest [32]byte) (Loc, bool) {
	i, ok := c.idx[prefix(digest)]
	if !ok || c.ring[i].digest != digest {
		return Loc{}, false
	}
	return c.ring[i].loc, true
}

// Len returns the number of cached precerts.
func (c *DeltaCache) Len() int { return len(c.idx) }

// Range is a span of the vault, [Start, End), as recorded in _COMMIT.json.
type Range struct {
	Start, End Tail
}

// Warm refills the cache from the leaf records in ranges, normally the last
// delta.warm_batches committed batches. digest returns a precert's issuance
// digest, or false for any other certificate.
func Warm(dirs []string, codec *Codec, c *DeltaCache, ranges []Range, digest func(der []byte) ([32]byte, bool)) error {
	for _, rg := range ranges {
		err := Scan(dirs, rg.Start, rg.End, func(loc Loc, rec Record) error {
			if rec.Kind != KindLeaf {
				return nil
			}
			der, err := codec.Decompress(rec.Frame, rec.DictID)
			if err != nil {
				return err
			}
			if d, ok := digest(der); ok {
				c.Put(d, loc)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}
```

Replace `internal/leaf/precert.go` (adds `PrecertIssuanceDigest` at the end):

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

// PrecertIssuanceDigest recomputes a vaulted precertificate's issuance digest
// from its own DER: SHA-256 of its TBS without the poison extension. For a
// CA-issued precert this equals the log's TBS digest. A precert issued by a
// precertificate signing certificate gets a different digest and simply
// misses the delta cache. It reports false for anything that is not a
// parseable precertificate. The delta cache warm-up uses it (amendment A1 §5).
func PrecertIssuanceDigest(der []byte) ([32]byte, bool) {
	c, err := parseCert(der)
	if err != nil || !c.hasExtension(oidPoison) {
		return [32]byte{}, false
	}
	tbs, err := c.rebuildTBS(rewrite{drop: oidPoison})
	if err != nil {
		return [32]byte{}, false
	}
	return sha256.Sum256(tbs), true
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race -count=1 ./internal/vault/ ./internal/leaf/ -v`
Expected: PASS:
- `TestTrainInstallLoadAndUse`, `TestDictsAreImmutableAndReplicated`, `TestTrainFailureFallsBack`, `TestTrainingSetReadsCommittedLeaves`
- `TestDeltaRoundTrip`, `TestDeltaCorruption`, `TestDeltaCache`, `TestDeltaCacheNeedsTheFullDigest`, `TestWarmFindsPrecertsInRanges`
- `TestPrecertIssuanceDigest`, and every Task B1 and Plan 2A test

Training on about 100 generator certificates takes a few seconds.

- [ ] **Step 5: Gate and commit**

Run the gate commands. All must pass.

```bash
git add internal/vault internal/leaf
git commit -m "feat: trained zstd dictionaries with manifests and fallback; leaf-delta records, delta cache and warm-up"
```

---

### Task B3: ID_FLOOR and the Pebble index

Implements spec §6.3 and §8.6, and amendment A1 §7 (early reservation).

**Files:**
- Create: `internal/commit/idfloor.go`, `internal/index/index.go`
- Create tests: `internal/commit/idfloor_test.go`, `internal/index/index_test.go`

**Interfaces:**
- Consumes: `fsutil.WriteFileAtomic`; `vault.Loc` (Task B1).
- Produces:
  - `commit` (`ID_FLOOR`):
    - `IDBlock=65536`, `IDLowWater=32768`, `ErrCorrupt`
    - `ReadFloor(stateDir) (uint64, error)`, `LoadIDs(stateDir, next, hook) (*IDs, error)`
    - `(*IDs).Next() (uint64, error)`, `Peek`, `Floor`, `SkipToFloor`, `Raise(v)`
    - hook points `HookIDFloorBeforeAdvance` and `HookIDFloorAfterAdvance`
  - `index`:
    - `type Ref struct{ CertID uint64; Loc vault.Loc }`
    - `Open(dir)`, `(*Index).Lookup(sha)`, `Applied(log)`, `NewBatch()`, `Close()`
    - `(*Batch).Lookup(sha)`, `AddCert(sha, ref)`, `HasChain(id)`, `AddChain(id)`, `SetApplied(log, seq)`, `Commit()`, `Close()`

- [ ] **Step 1: Write the failing tests**

Create `internal/commit/idfloor_test.go`:

```go
package commit

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestIDsStayBelowTheDurableFloor checks the spec §8.6 invariant for every
// ID handed out: a crash at any moment leaves every assigned ID below the
// floor on disk.
func TestIDsStayBelowTheDurableFloor(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadIDs(dir, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := uint64(1); i <= 100_000; i++ { // three reservations
		id, err := a.Next()
		if err != nil {
			t.Fatal(err)
		}
		if id != i {
			t.Fatalf("IDs are sequential: got %d, want %d", id, i)
		}
		onDisk, err := ReadFloor(dir)
		if err != nil || id >= onDisk {
			t.Fatalf("id %d handed out with ID_FLOOR %d on disk", id, onDisk)
		}
		if onDisk-id < IDLowWater-1 {
			t.Fatalf("the next block must be reserved before fewer than %d IDs remain (id %d, floor %d)", IDLowWater, id, onDisk)
		}
	}
}

func TestReservationIsInBlocks(t *testing.T) {
	dir := t.TempDir()
	var advances int
	a, _ := LoadIDs(dir, 1, func(p string) {
		if p == HookIDFloorAfterAdvance {
			advances++
		}
	})
	for range 100_000 {
		a.Next()
	}
	// floor starts at 0: 1+65536, then +65536 each time fewer than 32768 remain.
	if advances != 3 || a.Floor() != 1+3*IDBlock {
		t.Fatalf("100,000 IDs take 3 reservations: %d, floor %d", advances, a.Floor())
	}
}

// TestRestartAfterCrashSkipsToFloor: IDs a lost attempt touched are never
// reused, while a clean restart continues from the committed next_cert_id.
func TestRestartAfterCrashSkipsToFloor(t *testing.T) {
	dir := t.TempDir()
	a, _ := LoadIDs(dir, 1, nil)
	for range 10 {
		a.Next()
	}
	floor := a.Floor()
	clean, _ := LoadIDs(dir, 11, nil) // committed next_cert_id after a clean commit
	if id, _ := clean.Next(); id != 11 {
		t.Fatalf("a clean restart continues at the committed next_cert_id: %d", id)
	}
	crashed, _ := LoadIDs(dir, 11, nil)
	crashed.SkipToFloor()
	if id, _ := crashed.Next(); id != floor {
		t.Fatalf("after a crash the next ID is the floor %d, got %d", floor, id)
	}
	if crashed.Floor() <= floor {
		t.Fatal("handing out the floor itself must reserve a new block first")
	}
}

func TestRaiseAndCorruptFloor(t *testing.T) {
	dir := t.TempDir()
	a, _ := LoadIDs(dir, 1, nil)
	if err := a.Raise(500_000); err != nil {
		t.Fatal(err)
	}
	if v, _ := ReadFloor(dir); v != 500_000 {
		t.Fatalf("Raise is durable: %d", v)
	}
	a.Raise(10) // never lowers
	if v, _ := ReadFloor(dir); v != 500_000 {
		t.Fatalf("ID_FLOOR only increases: %d", v)
	}
	os.WriteFile(filepath.Join(dir, idFile), []byte("garbage\n"), 0o644)
	if _, err := LoadIDs(dir, 1, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("an unreadable ID_FLOOR is corruption: %v", err)
	}
}
```

Create `internal/index/index_test.go`:

```go
package index

import (
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
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/commit/ ./internal/index/`
Expected: FAIL with `undefined: LoadIDs` in `internal/commit`, and `undefined: Open` in `internal/index`.

- [ ] **Step 3: Implement**

```bash
go get github.com/cockroachdb/pebble/v2@v2.1.7
```

Create `internal/commit/idfloor.go`:

```go
// Package commit implements the batch commit protocol and recovery (spec §8)
// and the cert_id allocator with its durable high-water mark, ID_FLOOR
// (spec §8.6, amendment A1 §7).
package commit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/4rji/ctvault/internal/fsutil"
)

// ID_FLOOR reservation (amendment A1 §7): blocks of 65,536 IDs, and the next
// block is reserved durably once fewer than 32,768 reserved IDs remain.
const (
	IDBlock    = 65536
	IDLowWater = 32768
	idFile     = "ID_FLOOR"
)

// ErrCorrupt means committed state cannot be read safely (spec §12: exit 5).
var ErrCorrupt = errors.New("corrupt vault state")

// Hook points the allocator passes to its hook (tests only).
const (
	HookIDFloorBeforeAdvance = "idfloor.before_advance"
	HookIDFloorAfterAdvance  = "idfloor.after_advance"
)

// IDs hands out cert_ids. Every ID it returns is below the durable
// ID_FLOOR, so after a crash every ID that may have been assigned is below
// it, and IDs are never reused (spec §8.6). Not safe for concurrent use.
type IDs struct {
	path  string
	next  uint64
	floor uint64
	hook  func(string)
}

// ReadFloor reads state/ID_FLOOR; a missing file is 0 (a fresh vault).
func ReadFloor(stateDir string) (uint64, error) {
	b, err := os.ReadFile(filepath.Join(stateDir, idFile))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %s is not a number", ErrCorrupt, idFile)
	}
	return v, nil
}

// LoadIDs starts the allocator at next. Callers pass the committed
// next_cert_id after a clean shutdown, or the floor after a crash.
func LoadIDs(stateDir string, next uint64, hook func(string)) (*IDs, error) {
	floor, err := ReadFloor(stateDir)
	if err != nil {
		return nil, err
	}
	return &IDs{path: filepath.Join(stateDir, idFile), next: max(next, 1), floor: floor, hook: hook}, nil
}

// Floor returns the durable high-water mark.
func (a *IDs) Floor() uint64 { return a.floor }

// Peek returns the next ID Next would return.
func (a *IDs) Peek() uint64 { return a.next }

// SkipToFloor makes the next ID the floor: IDs an abandoned attempt may have
// touched are never handed out again.
func (a *IDs) SkipToFloor() { a.next = max(a.next, a.floor) }

// Raise lifts the floor durably to at least v, for example above the
// highest cert_id found beyond the committed tail during recovery.
func (a *IDs) Raise(v uint64) error {
	if v <= a.floor {
		return nil
	}
	return a.write(v)
}

func (a *IDs) write(v uint64) error {
	if a.hook != nil {
		a.hook(HookIDFloorBeforeAdvance)
	}
	if err := fsutil.WriteFileAtomic(a.path, []byte(strconv.FormatUint(v, 10)+"\n"), 0o644); err != nil {
		return err
	}
	a.floor = v
	if a.hook != nil {
		a.hook(HookIDFloorAfterAdvance)
	}
	return nil
}

// Next returns a fresh cert_id, first reserving the next block durably when
// fewer than IDLowWater reserved IDs remain.
func (a *IDs) Next() (uint64, error) {
	if a.floor < a.next+IDLowWater {
		if err := a.write(max(a.floor, a.next) + IDBlock); err != nil {
			return 0, fmt.Errorf("advancing ID_FLOOR: %w", err)
		}
	}
	id := a.next
	a.next++
	return id, nil
}
```

Create `internal/index/index.go`. Pebble's default logger prints informational lines ("Found 0 WALs"), which the `quiet` logger drops.

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

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go mod tidy && go test -race -count=1 ./internal/commit/ ./internal/index/ -v`
Expected: PASS:
- `TestIDsStayBelowTheDurableFloor`, about 3 s: it reads ID_FLOOR from disk after each of 100,000 IDs
- `TestReservationIsInBlocks`, `TestRestartAfterCrashSkipsToFloor`, `TestRaiseAndCorruptFloor`
- `TestBatchSeesItsOwnWritesAndCommitsDurably`, `TestDiscardedBatchLeavesNothing`, `TestRefEncoding`

- [ ] **Step 5: Gate and commit**

Run the gate commands. All must pass.

```bash
git add go.mod go.sum internal/commit internal/index
git commit -m "feat: ID_FLOOR allocator with early block reservation; writer-private Pebble index"
```

---

### Task B4: DuckDB staging, canary and views.sql

Implements spec §6.4–6.5, §7.6 (Plan 2 subset), §8.3 P5–P6 and §10.1 (DuckDB spill), amendment A1 §6, and spec §13.7's regression test.

**Files:**
- Create: `internal/dataset/stage.go`, `internal/dataset/canary.go`, `internal/dataset/views.go`
- Create test: `internal/dataset/dataset_test.go`

**Interfaces:**
- Consumes: `fsutil`.
- Produces (`dataset`):
  - Rows and files:
    - `EntriesFile`, `ChainsFile`
    - `type EntryRow`, `type ChainRow`
    - `type FileInfo struct{ SHA256 string; Bytes int64; Rows int }`
  - Stager:
    - `type Options struct{ TempDir string; MaxTempBytes uint64; Threads int }`
    - `NewStager(o)`, `(*Stager).Stage(ctx, dir, entries, chains) (map[string]FileInfo, error)`, `Close()`
    - `(*Stager).Canary(ctx, dir, entries, chains, n, rnd) error`, `ErrCanary`
    - `Sum(path) (FileInfo, error)`
  - Views: `ViewsFile`, `Views(root) []byte`, `WriteViews(root) (bool, error)`

- [ ] **Step 1: Write the failing tests**

Create `internal/dataset/dataset_test.go`:

```go
package dataset

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var ctx = context.Background()

func stager(t *testing.T) *Stager {
	t.Helper()
	s, err := NewStager(Options{TempDir: filepath.Join(t.TempDir(), "duckdb-1"), MaxTempBytes: 1 << 30, Threads: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// rows makes n entries covering every column state: precerts with an issuer
// key hash, x509 entries, and leaf errors with NULL certificate fields.
func rows(n int) ([]EntryRow, []ChainRow) {
	var es []EntryRow
	var cs []ChainRow
	for i := range n {
		r := EntryRow{Idx: uint64(1000 + i), CTTimestamp: 1790000000000 + uint64(i), EntryType: "x509", CertID: uint64(i + 1),
			LeafHash: sha256.Sum256([]byte{byte(i), byte(i >> 8)}), HasIssuanceKey: true, HasChainID: true}
		r.IssuanceKey[0], r.ChainID = byte(i), sha256.Sum256([]byte{byte(i % 3)})
		switch i % 4 {
		case 1:
			r.EntryType, r.HasIssuerKeyHash = "precert", true
			r.IssuerKeyHash[5] = 7
		case 3:
			r = EntryRow{Idx: r.Idx, LeafHash: r.LeafHash, EntryType: "unknown", LeafError: "leaf_bad_version"}
		}
		es = append(es, r)
	}
	for c := range 3 {
		for p := range 2 {
			cs = append(cs, ChainRow{ChainID: sha256.Sum256([]byte{byte(c)}), Position: uint16(p), CertID: uint64(500 + 10*c + p)})
		}
	}
	return es, cs
}

func TestStageAndCanary(t *testing.T) {
	s := stager(t)
	dir := filepath.Join(t.TempDir(), "stage", "b1")
	es, cs := rows(200)
	files, err := s.Stage(ctx, dir, es, cs)
	if err != nil {
		t.Fatal(err)
	}
	for name, rowsWant := range map[string]int{EntriesFile: 200, ChainsFile: 6} {
		fi := files[name]
		sum, err := Sum(filepath.Join(dir, name))
		if err != nil || fi.Rows != rowsWant || fi.Bytes == 0 || sum.SHA256 != fi.SHA256 {
			t.Fatalf("%s: %+v (recomputed %+v, %v)", name, fi, sum, err)
		}
	}
	if err := s.Canary(ctx, dir, es, cs, 1000, rand.New(rand.NewPCG(1, 2))); err != nil {
		t.Fatalf("every row must read back: %v", err)
	}
}

func TestCanaryCatchesMismatches(t *testing.T) {
	s := stager(t)
	dir := filepath.Join(t.TempDir(), "b")
	es, cs := rows(40)
	if _, err := s.Stage(ctx, dir, es, cs); err != nil {
		t.Fatal(err)
	}
	rnd := func() *rand.Rand { return rand.New(rand.NewPCG(3, 4)) }
	if err := s.Canary(ctx, dir, es[:39], cs, 5, rnd()); !errors.Is(err, ErrCanary) {
		t.Fatalf("a row count mismatch: %v", err)
	}
	bad := append([]EntryRow(nil), es...)
	for i := range bad {
		bad[i].CertID++
	}
	if err := s.Canary(ctx, dir, bad, cs, 5, rnd()); !errors.Is(err, ErrCanary) {
		t.Fatalf("a field that reads back differently: %v", err)
	}
	badChains := append([]ChainRow(nil), cs...)
	for i := range badChains {
		badChains[i].CertID++
	}
	if err := s.Canary(ctx, dir, es, badChains, 5, rnd()); !errors.Is(err, ErrCanary) {
		t.Fatalf("a chain that reads back differently: %v", err)
	}
}

func TestCanaryRefusesBloomFilters(t *testing.T) {
	s := stager(t)
	dir := filepath.Join(t.TempDir(), "b")
	es, cs := rows(40)
	if _, err := s.Stage(ctx, dir, es, cs); err != nil {
		t.Fatal(err)
	}
	// Rewrite entries.parquet the default way, which adds bloom filters.
	p := filepath.Join(dir, EntriesFile)
	if _, err := s.db.Exec(`COPY (SELECT * FROM read_parquet(` + quote(p) + `)) TO ` + quote(p+".bloom") + ` (FORMAT parquet)`); err != nil {
		t.Fatal(err)
	}
	os.Rename(p+".bloom", p)
	if err := s.Canary(ctx, dir, es, cs, 5, rand.New(rand.NewPCG(5, 6))); !errors.Is(err, ErrCanary) || !strings.Contains(err.Error(), "bloom") {
		t.Fatalf("a bloom-filtered file must fail the canary: %v", err)
	}
}

// TestDuckDBBloomFilterBugRegression reproduces spec §3.6 on the pinned
// DuckDB: a literal lookup on a bloom-filtered, low-cardinality BLOB column
// finds nothing. When DuckDB fixes it this test fails, so decision D19 (no
// bloom filters on BLOB columns) can be revisited; the writer keeps them off
// either way.
func TestDuckDBBloomFilterBugRegression(t *testing.T) {
	s := stager(t)
	dir := t.TempDir()
	const data = `SELECT unhex(sha256((i % 3)::VARCHAR)) AS ikh FROM range(2000) t(i)`
	lookup := `SELECT count(*) FROM read_parquet(?) WHERE ikh = unhex(sha256('1'))`
	bloom, plain := filepath.Join(dir, "bloom.parquet"), filepath.Join(dir, "plain.parquet")
	if _, err := s.db.Exec(`COPY (` + data + `) TO ` + quote(bloom) + ` (FORMAT parquet)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`COPY (` + data + `) TO ` + quote(plain) + ` ` + copyOptions); err != nil {
		t.Fatal(err)
	}
	var withBloom, without int
	s.db.QueryRow(lookup, bloom).Scan(&withBloom)
	s.db.QueryRow(lookup, plain).Scan(&without)
	if without != 667 {
		t.Fatalf("control: CTVault's writer settings must find all 667 rows, got %d", without)
	}
	if withBloom == 667 {
		t.Error("DuckDB no longer shows the BLOB bloom-filter bug (spec §3.6); D19 can be revisited")
	} else if withBloom != 0 {
		t.Fatalf("unexpected count %d with bloom filters", withBloom)
	}
}

func TestStagerConfinesSpill(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "duckdb-42")
	s, err := NewStager(Options{TempDir: dir, MaxTempBytes: 3 << 30})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var temp, max string
	s.db.QueryRow(`SELECT current_setting('temp_directory'), current_setting('max_temp_directory_size')`).Scan(&temp, &max)
	if temp != dir || !strings.HasPrefix(max, "3.0 GiB") {
		t.Fatalf("temp_directory %q, max_temp_directory_size %q", temp, max)
	}
}

// TestViewsSeeCommittedBatchesOnly loads views.sql into a fresh DuckDB
// session over two committed batches and a staged one.
func TestViewsSeeCommittedBatchesOnly(t *testing.T) {
	s := stager(t)
	root := t.TempDir()
	for i, b := range []string{"batch=000000000000-000000000039", "batch=000000000040-000000000079"} {
		dir := filepath.Join(root, "dataset", "log=argon2027h1", b)
		es, cs := rows(40)
		for j := range es {
			es[j].Idx = uint64(40*i + j)
		}
		if _, err := s.Stage(ctx, dir, es, cs); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, "_COMMIT.json"), []byte(fmt.Sprintf(`{"format":1,"commit_seq":%d}`, i+1)), 0o644)
	}
	es, cs := rows(40)
	if _, err := s.Stage(ctx, filepath.Join(root, "tmp", "stage", "x"), es, cs); err != nil {
		t.Fatal(err)
	}
	if changed, err := WriteViews(root); err != nil || !changed {
		t.Fatalf("first write: %v %v", changed, err)
	}
	if changed, _ := WriteViews(root); changed {
		t.Fatal("views.sql is rewritten only when it changes")
	}
	v, _ := os.ReadFile(filepath.Join(root, ViewsFile))
	if _, err := s.db.Exec(string(v)); err != nil {
		t.Fatal(err)
	}
	var n, logs, batches int
	s.db.QueryRow(`SELECT count(*), count(DISTINCT log) FROM entries`).Scan(&n, &logs)
	s.db.QueryRow(`SELECT count(*) FROM batches`).Scan(&batches)
	var chains int
	s.db.QueryRow(`SELECT count(*) FROM chains`).Scan(&chains)
	if n != 80 || logs != 1 || batches != 2 || chains != 12 {
		t.Fatalf("views: %d entries in %d logs, %d batches, %d chain rows; want 80, 1, 2, 12 (staging excluded)", n, logs, batches, chains)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/dataset/`
Expected: FAIL with `undefined: Stager`.

- [ ] **Step 3: Implement**

```bash
go get github.com/duckdb/duckdb-go/v2@v2.10506.0
```

Create `internal/dataset/stage.go`:

```go
// Package dataset writes the source-layer Parquet files of a batch through
// embedded DuckDB (spec §6.4-6.5, amendment A1 §6), checks them (the canary,
// spec §8.3 P6) and generates views.sql (spec §7.6).
package dataset

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	duckdb "github.com/duckdb/duckdb-go/v2"

	"github.com/4rji/ctvault/internal/fsutil"
)

// File names in a batch directory.
const (
	EntriesFile = "entries.parquet"
	ChainsFile  = "chains.parquet"
)

// EntryRow is one entries.parquet row (amendment A1 §6). Zero-valued
// optional fields are written as NULL.
type EntryRow struct {
	Idx              uint64
	CTTimestamp      uint64 // ms since the epoch; 0 = unknown (NULL)
	EntryType        string // "x509", "precert" or "unknown"
	CertID           uint64 // 0 = no certificate (NULL)
	LeafHash         [32]byte
	IssuanceKey      [16]byte
	HasIssuanceKey   bool
	IssuerKeyHash    [32]byte
	HasIssuerKeyHash bool
	ChainID          [32]byte
	HasChainID       bool
	LeafError        string // "" = NULL
}

// ChainRow is one chains.parquet row: chains first seen in the batch.
type ChainRow struct {
	ChainID  [32]byte
	Position uint16
	CertID   uint64
}

// FileInfo describes a staged file for _COMMIT.json.
type FileInfo struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Rows   int    `json:"rows"`
}

// Options configure the embedded DuckDB session.
type Options struct {
	TempDir      string // <root>/tmp/duckdb-<pid> (spec §10.1)
	MaxTempBytes uint64 // max_temp_directory_size: headroom below the cap minus 1 GiB
	Threads      int    // 0 = DuckDB's default
}

// Stager owns one in-memory DuckDB session. Not safe for concurrent use.
type Stager struct {
	connector *duckdb.Connector
	db        *sql.DB
}

// NewStager opens an in-memory DuckDB session with spill confined to
// o.TempDir and capped at o.MaxTempBytes.
func NewStager(o Options) (*Stager, error) {
	if err := os.MkdirAll(o.TempDir, 0o755); err != nil {
		return nil, err
	}
	settings := []string{
		fmt.Sprintf("SET temp_directory = %s", quote(o.TempDir)),
		fmt.Sprintf("SET max_temp_directory_size = '%dB'", o.MaxTempBytes),
	}
	if o.Threads > 0 {
		settings = append(settings, fmt.Sprintf("SET threads = %d", o.Threads))
	}
	c, err := duckdb.NewConnector("", func(execer driver.ExecerContext) error {
		for _, q := range settings {
			if _, err := execer.ExecContext(context.Background(), q, nil); err != nil {
				return fmt.Errorf("duckdb %q: %w", q, err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &Stager{connector: c, db: sql.OpenDB(c)}, nil
}

// Close closes the session.
func (s *Stager) Close() error {
	err := s.db.Close()
	if cerr := s.connector.Close(); err == nil {
		err = cerr
	}
	return err
}

// quote makes a SQL string literal.
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

const entriesDDL = `CREATE OR REPLACE TABLE entries_stage (
	idx UBIGINT, ct_ts TIMESTAMP_MS, entry_type VARCHAR, cert_id UBIGINT,
	leaf_hash BLOB, issuance_key BLOB, issuer_key_hash BLOB, chain_id BLOB, leaf_error VARCHAR)`

const chainsDDL = `CREATE OR REPLACE TABLE chains_stage (chain_id BLOB, position USMALLINT, cert_id UBIGINT)`

// copyOptions writes zstd Parquet with no bloom filter on any column:
// DuckDB 1.5.6 returns wrong answers for literal lookups on bloom-filtered
// BLOB columns (spec §3.6, amendment A1 §6).
const copyOptions = `(FORMAT parquet, COMPRESSION zstd, WRITE_BLOOM_FILTER false)`

func nullable(ok bool, v any) any {
	if !ok {
		return nil
	}
	return v
}

func entryValues(r EntryRow) []driver.Value {
	var ts, cert, lerr any
	if r.CTTimestamp != 0 {
		ts = time.UnixMilli(int64(r.CTTimestamp)).UTC()
	}
	if r.CertID != 0 {
		cert = r.CertID
	}
	if r.LeafError != "" {
		lerr = r.LeafError
	}
	return []driver.Value{r.Idx, ts, r.EntryType, cert, r.LeafHash[:],
		nullable(r.HasIssuanceKey, r.IssuanceKey[:]), nullable(r.HasIssuerKeyHash, r.IssuerKeyHash[:]),
		nullable(r.HasChainID, r.ChainID[:]), lerr}
}

// load appends rows into the temp tables of one connection.
func (s *Stager) load(ctx context.Context, conn *sql.Conn, entries []EntryRow, chains []ChainRow) error {
	for _, q := range []string{entriesDDL, chainsDDL} {
		if _, err := conn.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return conn.Raw(func(dc any) error {
		ea, err := duckdb.NewAppenderFromConn(dc.(driver.Conn), "", "entries_stage")
		if err != nil {
			return err
		}
		for _, r := range entries {
			if err := ea.AppendRow(entryValues(r)...); err != nil {
				ea.Close()
				return fmt.Errorf("staging entry %d: %w", r.Idx, err)
			}
		}
		if err := ea.Close(); err != nil {
			return err
		}
		ca, err := duckdb.NewAppenderFromConn(dc.(driver.Conn), "", "chains_stage")
		if err != nil {
			return err
		}
		for _, r := range chains {
			if err := ca.AppendRow(r.ChainID[:], r.Position, r.CertID); err != nil {
				ca.Close()
				return err
			}
		}
		return ca.Close()
	})
}

// Stage writes entries.parquet and chains.parquet into dir (tmp/stage/<batch>)
// and syncs them (spec §8.3 P5). Rows are written in index order, and chains
// by chain_id then position.
func (s *Stager) Stage(ctx context.Context, dir string, entries []EntryRow, chains []ChainRow) (map[string]FileInfo, error) {
	if err := fsutil.MkdirAllSync(dir, 0o755); err != nil {
		return nil, err
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := s.load(ctx, conn, entries, chains); err != nil {
		return nil, err
	}
	out := map[string]FileInfo{}
	for _, f := range []struct {
		name, query string
		rows        int
	}{
		{EntriesFile, `SELECT * FROM entries_stage ORDER BY idx`, len(entries)},
		{ChainsFile, `SELECT * FROM chains_stage ORDER BY chain_id, position`, len(chains)},
	} {
		p := filepath.Join(dir, f.name)
		if _, err := conn.ExecContext(ctx, fmt.Sprintf("COPY (%s) TO %s %s", f.query, quote(p), copyOptions)); err != nil {
			return nil, fmt.Errorf("writing %s: %w", f.name, err)
		}
		info, err := syncAndSum(p)
		if err != nil {
			return nil, err
		}
		info.Rows = f.rows
		out[f.name] = info
	}
	if _, err := conn.ExecContext(ctx, `DROP TABLE entries_stage; DROP TABLE chains_stage`); err != nil {
		return nil, err
	}
	return out, fsutil.SyncDir(dir)
}

// syncAndSum fsyncs a file and returns its size and SHA-256.
func syncAndSum(p string) (FileInfo, error) {
	f, err := os.Open(p)
	if err != nil {
		return FileInfo{}, err
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return FileInfo{}, err
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return FileInfo{}, err
	}
	return FileInfo{SHA256: hex.EncodeToString(h.Sum(nil)), Bytes: n}, nil
}

// Sum returns a committed file's size and SHA-256, for recovery and verify.
func Sum(p string) (FileInfo, error) { return syncAndSum(p) }
```

Create `internal/dataset/canary.go`:

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
// column names and types, no bloom filter anywhere, row counts, and n random
// rows read back field by field through literal BLOB lookups, the path
// readers use.
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

Create `internal/dataset/views.go`:

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
// staging lives in tmp/, never under dataset/.
func Views(root string) []byte {
	ds := filepath.Join(root, "dataset")
	glob := func(name string) string { return quote(filepath.Join(ds, "log=*", "batch=*", name)) }
	return []byte(fmt.Sprintf(`-- Generated by ctvault; do not edit. Load with: .read %s
-- Globs see a commit at once, but a join running while a batch commits can
-- see it in one table and not yet in another (spec §7.6).
CREATE OR REPLACE VIEW entries AS
  SELECT * FROM read_parquet(%s, hive_partitioning = true, union_by_name = true);
CREATE OR REPLACE VIEW chains AS
  SELECT * FROM read_parquet(%s, hive_partitioning = true, union_by_name = true);
CREATE OR REPLACE VIEW batches AS
  SELECT * FROM read_json(%s, format = 'auto', union_by_name = true);
`, filepath.Join(root, ViewsFile), glob(EntriesFile), glob(ChainsFile), glob("_COMMIT.json")))
}

// WriteViews regenerates views.sql and replaces it atomically only when its
// contents change (amendment A1 §7). It reports whether it wrote.
func WriteViews(root string) (bool, error) {
	want := Views(root)
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

Run: `go mod tidy && go test -race -count=1 ./internal/dataset/ -v`
Expected: PASS:
- `TestStageAndCanary`, `TestCanaryCatchesMismatches`, `TestCanaryRefusesBloomFilters`
- `TestDuckDBBloomFilterBugRegression`: the bug is still present in DuckDB 1.5.6. If this test fails one day, DuckDB has fixed it.
- `TestStagerConfinesSpill`, `TestViewsSeeCommittedBatchesOnly`

The first run links DuckDB through cgo, which takes about a minute.

- [ ] **Step 5: Gate and commit**

Run the gate commands. All must pass.

```bash
git add go.mod go.sum internal/dataset
git commit -m "feat: entries/chains Parquet staging through embedded DuckDB without bloom filters; canary; views.sql"
```

---

### Task B5: The commit protocol and recovery

Implements spec §8.2–8.5 and amendment A1 §7 (scoped cleanup, semantic recovery).

**Files:**
- Create: `internal/commit/manifest.go`, `internal/commit/protocol.go`, `internal/commit/recover.go`
- Modify: `internal/dataset/stage.go` (adds `ChainIDs`)
- Create test: `internal/commit/protocol_test.go`

**Interfaces:**
- Consumes:
  - Tasks B1–B2: `vault.InspectTail`, `Truncate`, `Scan`, `OpenReader`, `Tail`
  - Task B3: `index`, `commit.LoadIDs`
  - Task B4: `dataset.FileInfo`, `Stager`
  - Plan 1: `merkle.State`
- Produces (`commit`):
  - Names and paths:
    - `ManifestFile`, `QuarantineFile`, `ManifestFormat`
    - `type BatchID struct{ Log string; First, Last uint64 }`
    - `type Paths struct{ Root string }` with `BatchDir`, `StageDir`, `IntentPath`, `StateDir`
  - The manifest:
    - `type STH`, `type Verified`, `type Span`, `type Counts`, `type DictInfo`, `type Manifest`
    - `ListCommitted(root)`, `type LogTip`, `Tips(committed)`
  - The protocol:
    - `type Intent`, `WriteIntent`, `ReadIntents`, `RemoveIntent`, `Publish`, `Abandon`
    - hook points `HookAfterIntent`, `HookAfterManifest`, `HookBeforeRename`, `HookAfterRename`, `HookBeforeIntentDelete`
  - Recovery:
    - `type RecoverOptions`, `type Recovered`
    - `Recover(o) (Recovered, error)`
  - `dataset`: `(*Stager).ChainIDs(path) ([][32]byte, error)`

- [ ] **Step 1: Write the failing tests**

Create `internal/commit/protocol_test.go`:

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
	if left, _ := ReadIntents(e.p); len(left) != 0 {
		t.Fatal("the intent is removed")
	}
	if _, err := os.Stat(e.p.StageDir(in[0].ID())); !os.IsNotExist(err) {
		t.Fatal("staging is removed")
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/commit/`
Expected: FAIL with `undefined: Paths`.

- [ ] **Step 3: Implement**

Create `internal/commit/manifest.go`:

```go
package commit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

// ManifestFile is the commit marker inside a batch directory (spec §8.4).
const (
	ManifestFile   = "_COMMIT.json"
	QuarantineFile = "quarantine.ndjson"
	ManifestFormat = 1
)

// BatchID names a batch: "<log>/<first>-<last>", indexes inclusive and
// zero-padded to 12 digits (spec §6.1).
type BatchID struct {
	Log         string
	First, Last uint64
}

func (b BatchID) span() string { return fmt.Sprintf("%012d-%012d", b.First, b.Last) }

// String is the batch ID as written in _COMMIT.json.
func (b BatchID) String() string { return b.Log + "/" + b.span() }

// file is the batch ID as a single path element (intents, staging).
func (b BatchID) file() string { return b.Log + "__" + b.span() }

// Paths locates the commit protocol's files under a vault root.
type Paths struct{ Root string }

func (p Paths) BatchDir(b BatchID) string {
	return filepath.Join(p.Root, "dataset", "log="+b.Log, "batch="+b.span())
}
func (p Paths) StageDir(b BatchID) string { return filepath.Join(p.Root, "tmp", "stage", b.file()) }
func (p Paths) IntentPath(b BatchID) string {
	return filepath.Join(p.Root, "state", "intent", b.file()+".json")
}
func (p Paths) StateDir() string { return filepath.Join(p.Root, "state") }

// STH is the pinned signed tree head a batch was verified against.
type STH struct {
	TreeSize  uint64 `json:"tree_size"`
	Timestamp uint64 `json:"timestamp"`
	RootHash  string `json:"root_hash"` // hex
	Signature string `json:"signature"` // base64 DigitallySigned
}

// Verified records how the batch was checked against the STH (spec §5.5).
type Verified struct {
	Method     string `json:"method"` // "consistency_proof" or "root_equals_sth"
	ProofNodes int    `json:"proof_nodes"`
}

// Span is a vault range [Start, End).
type Span struct {
	Start vault.Tail `json:"start"`
	End   vault.Tail `json:"end"`
}

// Counts summarise a batch.
type Counts struct {
	Entries      int `json:"entries"`
	NewCerts     int `json:"new_certs"` // leaf and chain certificates vaulted by this batch
	DeltaRecords int `json:"delta_records"`
	LeafErrors   int `json:"leaf_errors"`
}

// DictInfo records the dictionary new records used and any training
// failure (amendment A1 §5).
type DictInfo struct {
	ID            uint64 `json:"id"`
	TrainingError string `json:"training_error,omitempty"`
}

// Manifest is _COMMIT.json (spec §8.4, Plan 2 subset: no derived builders yet).
type Manifest struct {
	Format         int                         `json:"format"`
	CommitSeq      uint64                      `json:"commit_seq"`
	BatchID        string                      `json:"batch_id"`
	Log            string                      `json:"log"`
	First          uint64                      `json:"first"`
	Last           uint64                      `json:"last"`
	STH            STH                         `json:"sth"`
	MerkleAfter    *merkle.State               `json:"merkle_after"`
	Verified       Verified                    `json:"verified"`
	CertIDRange    *[2]uint64                  `json:"cert_id_range"` // first and last assigned; null if none
	NextCertID     uint64                      `json:"next_cert_id"`
	Vault          Span                        `json:"vault"`
	Builders       map[string]int              `json:"builders"`
	Files          map[string]dataset.FileInfo `json:"files"`
	Counts         Counts                      `json:"counts"`
	Dictionary     DictInfo                    `json:"dictionary"`
	CTVaultVersion string                      `json:"ctvault_version"`
	CommittedAt    time.Time                   `json:"committed_at"`
}

// ID returns the manifest's batch ID.
func (m Manifest) ID() BatchID { return BatchID{Log: m.Log, First: m.First, Last: m.Last} }

func corrupt(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(format, args...))
}

// readManifest reads and checks a committed batch directory: its manifest
// must be complete and consistent with the directory name, and every listed
// file must exist with its recorded size. Full checksums are left to
// "ctvault verify" (amendment decision, Plan 2B).
func readManifest(dir, log, span string) (Manifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		return Manifest{}, corrupt("committed batch %s has no readable %s: %v", dir, ManifestFile, err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return m, corrupt("%s/%s: %v", dir, ManifestFile, err)
	}
	if m.Format != ManifestFormat || m.Log != log || m.ID().span() != span || m.BatchID != m.ID().String() ||
		m.First > m.Last || m.CommitSeq == 0 || m.MerkleAfter == nil || m.MerkleAfter.Size() != m.Last+1 {
		return m, corrupt("%s/%s is inconsistent with its directory", dir, ManifestFile)
	}
	for _, name := range []string{dataset.EntriesFile, dataset.ChainsFile} {
		if _, ok := m.Files[name]; !ok {
			return m, corrupt("%s/%s does not list %s", dir, ManifestFile, name)
		}
	}
	for name, fi := range m.Files {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil || st.Size() != fi.Bytes {
			return m, corrupt("%s/%s is missing or has the wrong size", dir, name)
		}
	}
	return m, nil
}

// ListCommitted reads every committed batch, ordered by commit_seq, and
// checks that each log's batches are contiguous from index 0 and that
// commit_seq values are unique.
func ListCommitted(root string) ([]Manifest, error) {
	logs, err := os.ReadDir(filepath.Join(root, "dataset"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var all []Manifest
	for _, l := range logs {
		log, ok := strings.CutPrefix(l.Name(), "log=")
		if !ok || !l.IsDir() {
			continue
		}
		batches, err := os.ReadDir(filepath.Join(root, "dataset", l.Name()))
		if err != nil {
			return nil, err
		}
		var mine []Manifest
		for _, b := range batches {
			span, ok := strings.CutPrefix(b.Name(), "batch=")
			if !ok || !b.IsDir() {
				continue
			}
			m, err := readManifest(filepath.Join(root, "dataset", l.Name(), b.Name()), log, span)
			if err != nil {
				return nil, err
			}
			mine = append(mine, m)
		}
		sort.Slice(mine, func(i, j int) bool { return mine[i].First < mine[j].First })
		next := uint64(0)
		for _, m := range mine {
			if m.First != next {
				return nil, corrupt("log %s: batches are not contiguous at index %d (next batch starts at %d)", log, next, m.First)
			}
			next = m.Last + 1
		}
		all = append(all, mine...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].CommitSeq < all[j].CommitSeq })
	for i := 1; i < len(all); i++ {
		if all[i].CommitSeq == all[i-1].CommitSeq {
			return nil, corrupt("commit_seq %d appears twice", all[i].CommitSeq)
		}
	}
	return all, nil
}

// LogTip is a log's committed position.
type LogTip struct {
	Next  uint64        // first index not yet committed
	State *merkle.State // compact range of [0, Next)
}

// Tips returns each log's committed position.
func Tips(committed []Manifest) map[string]LogTip {
	out := map[string]LogTip{}
	for _, m := range committed {
		if t, ok := out[m.Log]; !ok || m.Last+1 > t.Next {
			out[m.Log] = LogTip{Next: m.Last + 1, State: m.MerkleAfter}
		}
	}
	return out
}
```

Create `internal/commit/protocol.go`:

```go
package commit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"golang.org/x/sys/unix"

	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

// Named commit boundaries for crash tests (spec §13.5); production passes a
// nil hook.
const (
	HookAfterIntent        = "commit.P1.after_intent"
	HookAfterManifest      = "commit.P7.after_manifest"
	HookBeforeRename       = "commit.P8.before_rename"
	HookAfterRename        = "commit.P8.after_rename"
	HookBeforeIntentDelete = "commit.P10.before_intent_delete"
)

func call(hook func(string), p string) {
	if hook != nil {
		hook(p)
	}
}

// Intent is state/intent/<batch>.json, written before a batch touches the
// vault (spec §8.3 P1).
type Intent struct {
	BatchID      string         `json:"batch_id"`
	Log          string         `json:"log"`
	First        uint64         `json:"first"`
	Last         uint64         `json:"last"`
	STH          STH            `json:"sth"`
	VaultTail    vault.Tail     `json:"vault_tail"`
	NextCertID   uint64         `json:"next_cert_id"`
	MerkleBefore *merkle.State  `json:"merkle_before"`
	Builders     map[string]int `json:"builders"`
	StartedAt    time.Time      `json:"started_at"`
}

// ID returns the intent's batch ID.
func (in Intent) ID() BatchID { return BatchID{Log: in.Log, First: in.First, Last: in.Last} }

// WriteIntent is P1: the intent file and its directory are fsynced.
func WriteIntent(p Paths, in Intent, hook func(string)) error {
	b, err := json.MarshalIndent(in, "", " ")
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(p.IntentPath(in.ID()), b, 0o644); err != nil {
		return err
	}
	call(hook, HookAfterIntent)
	return nil
}

// ReadIntents lists the intents left in state/intent/.
func ReadIntents(p Paths) ([]Intent, error) {
	dir := filepath.Join(p.StateDir(), "intent")
	names, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Intent
	for _, n := range names {
		if filepath.Ext(n.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, n.Name()))
		if err != nil {
			return nil, err
		}
		var in Intent
		if err := json.Unmarshal(b, &in); err != nil || in.ID().file()+".json" != n.Name() {
			return nil, corrupt("intent %s is unreadable", n.Name())
		}
		out = append(out, in)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BatchID < out[j].BatchID })
	return out, nil
}

// RemoveIntent is P10.
func RemoveIntent(p Paths, id BatchID, hook func(string)) error {
	call(hook, HookBeforeIntentDelete)
	if err := os.Remove(p.IntentPath(id)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return fsutil.SyncDir(filepath.Dir(p.IntentPath(id)))
}

// Publish is P7 and P8: _COMMIT.json is written into the staged batch
// directory and fsynced, then the directory is renamed into dataset/ (the
// commit point) without replacing anything, and the parents are fsynced.
func Publish(p Paths, m Manifest, hook func(string)) error {
	id := m.ID()
	stage := p.StageDir(id)
	b, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(stage, ManifestFile), b, 0o644); err != nil {
		return err
	}
	call(hook, HookAfterManifest)
	dest := p.BatchDir(id)
	if err := fsutil.MkdirAllSync(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	call(hook, HookBeforeRename)
	if err := unix.Renameat2(unix.AT_FDCWD, stage, unix.AT_FDCWD, dest, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("committing %s: %w", id, err)
	}
	call(hook, HookAfterRename)
	for _, d := range []string{filepath.Dir(dest), filepath.Dir(filepath.Dir(dest)), filepath.Dir(stage)} {
		if err := fsutil.SyncDir(d); err != nil {
			return err
		}
	}
	return nil
}

// Abandon discards an uncommitted batch in process (a failed verification or
// canary, a stall, a second signal): the vault is cut back to the batch's
// start, staging is deleted, then the intent. The caller must also discard
// the batch's Pebble writes and skip cert_ids to the floor.
func Abandon(p Paths, vaultDirs []string, in Intent) error {
	if err := vault.Truncate(vaultDirs, in.VaultTail); err != nil {
		return err
	}
	if err := os.RemoveAll(p.StageDir(in.ID())); err != nil {
		return err
	}
	return RemoveIntent(p, in.ID(), nil)
}
```

Create `internal/commit/recover.go`:

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
//  5. Pebble catches up on committed batches it has not applied, by
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

	u, err := vault.InspectTail(o.VaultDirs, r.Tail)
	if err != nil {
		return r, err
	}
	if u.Bytes > 0 {
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

	intents, err := ReadIntents(o.Paths)
	if err != nil {
		return r, err
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

Replace `internal/dataset/stage.go` (adds `ChainIDs` at the end):

```go
// Package dataset writes the source-layer Parquet files of a batch through
// embedded DuckDB (spec §6.4-6.5, amendment A1 §6), checks them (the canary,
// spec §8.3 P6) and generates views.sql (spec §7.6).
package dataset

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	duckdb "github.com/duckdb/duckdb-go/v2"

	"github.com/4rji/ctvault/internal/fsutil"
)

// File names in a batch directory.
const (
	EntriesFile = "entries.parquet"
	ChainsFile  = "chains.parquet"
)

// EntryRow is one entries.parquet row (amendment A1 §6). Zero-valued
// optional fields are written as NULL.
type EntryRow struct {
	Idx              uint64
	CTTimestamp      uint64 // ms since the epoch; 0 = unknown (NULL)
	EntryType        string // "x509", "precert" or "unknown"
	CertID           uint64 // 0 = no certificate (NULL)
	LeafHash         [32]byte
	IssuanceKey      [16]byte
	HasIssuanceKey   bool
	IssuerKeyHash    [32]byte
	HasIssuerKeyHash bool
	ChainID          [32]byte
	HasChainID       bool
	LeafError        string // "" = NULL
}

// ChainRow is one chains.parquet row: chains first seen in the batch.
type ChainRow struct {
	ChainID  [32]byte
	Position uint16
	CertID   uint64
}

// FileInfo describes a staged file for _COMMIT.json.
type FileInfo struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Rows   int    `json:"rows"`
}

// Options configure the embedded DuckDB session.
type Options struct {
	TempDir      string // <root>/tmp/duckdb-<pid> (spec §10.1)
	MaxTempBytes uint64 // max_temp_directory_size: headroom below the cap minus 1 GiB
	Threads      int    // 0 = DuckDB's default
}

// Stager owns one in-memory DuckDB session. Not safe for concurrent use.
type Stager struct {
	connector *duckdb.Connector
	db        *sql.DB
}

// NewStager opens an in-memory DuckDB session with spill confined to
// o.TempDir and capped at o.MaxTempBytes.
func NewStager(o Options) (*Stager, error) {
	if err := os.MkdirAll(o.TempDir, 0o755); err != nil {
		return nil, err
	}
	settings := []string{
		fmt.Sprintf("SET temp_directory = %s", quote(o.TempDir)),
		fmt.Sprintf("SET max_temp_directory_size = '%dB'", o.MaxTempBytes),
	}
	if o.Threads > 0 {
		settings = append(settings, fmt.Sprintf("SET threads = %d", o.Threads))
	}
	c, err := duckdb.NewConnector("", func(execer driver.ExecerContext) error {
		for _, q := range settings {
			if _, err := execer.ExecContext(context.Background(), q, nil); err != nil {
				return fmt.Errorf("duckdb %q: %w", q, err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &Stager{connector: c, db: sql.OpenDB(c)}, nil
}

// Close closes the session.
func (s *Stager) Close() error {
	err := s.db.Close()
	if cerr := s.connector.Close(); err == nil {
		err = cerr
	}
	return err
}

// quote makes a SQL string literal.
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

const entriesDDL = `CREATE OR REPLACE TABLE entries_stage (
	idx UBIGINT, ct_ts TIMESTAMP_MS, entry_type VARCHAR, cert_id UBIGINT,
	leaf_hash BLOB, issuance_key BLOB, issuer_key_hash BLOB, chain_id BLOB, leaf_error VARCHAR)`

const chainsDDL = `CREATE OR REPLACE TABLE chains_stage (chain_id BLOB, position USMALLINT, cert_id UBIGINT)`

// copyOptions writes zstd Parquet with no bloom filter on any column:
// DuckDB 1.5.6 returns wrong answers for literal lookups on bloom-filtered
// BLOB columns (spec §3.6, amendment A1 §6).
const copyOptions = `(FORMAT parquet, COMPRESSION zstd, WRITE_BLOOM_FILTER false)`

func nullable(ok bool, v any) any {
	if !ok {
		return nil
	}
	return v
}

func entryValues(r EntryRow) []driver.Value {
	var ts, cert, lerr any
	if r.CTTimestamp != 0 {
		ts = time.UnixMilli(int64(r.CTTimestamp)).UTC()
	}
	if r.CertID != 0 {
		cert = r.CertID
	}
	if r.LeafError != "" {
		lerr = r.LeafError
	}
	return []driver.Value{r.Idx, ts, r.EntryType, cert, r.LeafHash[:],
		nullable(r.HasIssuanceKey, r.IssuanceKey[:]), nullable(r.HasIssuerKeyHash, r.IssuerKeyHash[:]),
		nullable(r.HasChainID, r.ChainID[:]), lerr}
}

// load appends rows into the temp tables of one connection.
func (s *Stager) load(ctx context.Context, conn *sql.Conn, entries []EntryRow, chains []ChainRow) error {
	for _, q := range []string{entriesDDL, chainsDDL} {
		if _, err := conn.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return conn.Raw(func(dc any) error {
		ea, err := duckdb.NewAppenderFromConn(dc.(driver.Conn), "", "entries_stage")
		if err != nil {
			return err
		}
		for _, r := range entries {
			if err := ea.AppendRow(entryValues(r)...); err != nil {
				ea.Close()
				return fmt.Errorf("staging entry %d: %w", r.Idx, err)
			}
		}
		if err := ea.Close(); err != nil {
			return err
		}
		ca, err := duckdb.NewAppenderFromConn(dc.(driver.Conn), "", "chains_stage")
		if err != nil {
			return err
		}
		for _, r := range chains {
			if err := ca.AppendRow(r.ChainID[:], r.Position, r.CertID); err != nil {
				ca.Close()
				return err
			}
		}
		return ca.Close()
	})
}

// Stage writes entries.parquet and chains.parquet into dir (tmp/stage/<batch>)
// and syncs them (spec §8.3 P5). Rows are written in index order, and chains
// by chain_id then position.
func (s *Stager) Stage(ctx context.Context, dir string, entries []EntryRow, chains []ChainRow) (map[string]FileInfo, error) {
	if err := fsutil.MkdirAllSync(dir, 0o755); err != nil {
		return nil, err
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := s.load(ctx, conn, entries, chains); err != nil {
		return nil, err
	}
	out := map[string]FileInfo{}
	for _, f := range []struct {
		name, query string
		rows        int
	}{
		{EntriesFile, `SELECT * FROM entries_stage ORDER BY idx`, len(entries)},
		{ChainsFile, `SELECT * FROM chains_stage ORDER BY chain_id, position`, len(chains)},
	} {
		p := filepath.Join(dir, f.name)
		if _, err := conn.ExecContext(ctx, fmt.Sprintf("COPY (%s) TO %s %s", f.query, quote(p), copyOptions)); err != nil {
			return nil, fmt.Errorf("writing %s: %w", f.name, err)
		}
		info, err := syncAndSum(p)
		if err != nil {
			return nil, err
		}
		info.Rows = f.rows
		out[f.name] = info
	}
	if _, err := conn.ExecContext(ctx, `DROP TABLE entries_stage; DROP TABLE chains_stage`); err != nil {
		return nil, err
	}
	return out, fsutil.SyncDir(dir)
}

// syncAndSum fsyncs a file and returns its size and SHA-256.
func syncAndSum(p string) (FileInfo, error) {
	f, err := os.Open(p)
	if err != nil {
		return FileInfo{}, err
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return FileInfo{}, err
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return FileInfo{}, err
	}
	return FileInfo{SHA256: hex.EncodeToString(h.Sum(nil)), Bytes: n}, nil
}

// Sum returns a committed file's size and SHA-256, for recovery and verify.
func Sum(p string) (FileInfo, error) { return syncAndSum(p) }

// ChainIDs reads the distinct chain_id values of a committed chains.parquet
// (recovery re-applies them to the index).
func (s *Stager) ChainIDs(path string) ([][32]byte, error) {
	rows, err := s.db.Query(`SELECT DISTINCT chain_id FROM read_parquet(` + quote(path) + `)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][32]byte
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		if len(b) != 32 {
			return nil, fmt.Errorf("%s: chain_id of %d bytes", path, len(b))
		}
		out = append(out, [32]byte(b))
	}
	return out, rows.Err()
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race -count=1 ./internal/commit/ -v`
Expected: PASS:
- `TestCleanCommitAndHookOrder`
- `TestRecoverAfterCrashBeforeCommit`, `TestRecoverFinishesACommittedBatch`
- `TestRecoverRefusesDamagedCommits`, `TestRecoverCleansOnlyStageAndRebuild`, `TestAbandonInProcess`
- the Task B3 tests

- [ ] **Step 5: Gate and commit**

Run the gate commands. All must pass.

```bash
git add internal/commit internal/dataset
git commit -m "feat: commit protocol (intent, _COMMIT.json, no-replace rename) and recovery per spec §8.5"
```

---

### Task B6: The batch engine

Implements spec §5.5, §8.3 P0–P10, §10.1 (preflight and hard checks) and §12 (incidents, refetch once), plus amendment A1 §5's dictionary training and delta warm-up.

**Files:**
- Create: `internal/ingest/writer.go`, `internal/ingest/batch.go`
- Modify: `internal/commit/manifest.go` (adds `counts.vault_bytes`)
- Create test: `internal/ingest/ingest_test.go`

**Interfaces:**
- Consumes:
  - Tasks B1–B5: everything above
  - Plan 2A: `fetch.Run`, `fetch.Retry`, `logsource.LogSource`, `logsource.SignedHead`, `leaf.Entry`, `diskguard.Guard.Preflight`, `diskguard.EstimatePeak`, `config.Config`
- Produces (`ingest`):
  - `type Options struct{ Root string; VaultDirs []string; VaultUUID [16]byte; Config config.Config; Guard diskguard.Guard; Fetch fetch.Options; Version string; Now func() time.Time; Out io.Writer; Hook func(string); DictSamples int; Train func([][]byte, uint64) ([]byte, error); CanarySamples int }`
  - `Open(o) (*Writer, error)`, `(*Writer).Batch(ctx, src, sth, first, end uint64) (commit.Manifest, error)`, `Next(log)`, `LastCommitSeq()`, `Close()`
  - `ErrVerification`, `SpillBudget`, `HookBeforePebble`, `HookAfterPebble`

- [ ] **Step 1: Write the failing tests**

Create `internal/ingest/ingest_test.go`:

```go
package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
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
	for _, point := range []string{"commit.P8.before_rename", HookBeforePebble, vault.HookRolloverAfterHeader} {
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
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/ingest/`
Expected: FAIL with `undefined: Options`.

- [ ] **Step 3: Implement**

Replace `internal/commit/manifest.go`:

```go
package commit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

// ManifestFile is the commit marker inside a batch directory (spec §8.4).
const (
	ManifestFile   = "_COMMIT.json"
	QuarantineFile = "quarantine.ndjson"
	ManifestFormat = 1
)

// BatchID names a batch: "<log>/<first>-<last>", indexes inclusive and
// zero-padded to 12 digits (spec §6.1).
type BatchID struct {
	Log         string
	First, Last uint64
}

func (b BatchID) span() string { return fmt.Sprintf("%012d-%012d", b.First, b.Last) }

// String is the batch ID as written in _COMMIT.json.
func (b BatchID) String() string { return b.Log + "/" + b.span() }

// file is the batch ID as a single path element (intents, staging).
func (b BatchID) file() string { return b.Log + "__" + b.span() }

// Paths locates the commit protocol's files under a vault root.
type Paths struct{ Root string }

func (p Paths) BatchDir(b BatchID) string {
	return filepath.Join(p.Root, "dataset", "log="+b.Log, "batch="+b.span())
}
func (p Paths) StageDir(b BatchID) string { return filepath.Join(p.Root, "tmp", "stage", b.file()) }
func (p Paths) IntentPath(b BatchID) string {
	return filepath.Join(p.Root, "state", "intent", b.file()+".json")
}
func (p Paths) StateDir() string { return filepath.Join(p.Root, "state") }

// STH is the pinned signed tree head a batch was verified against.
type STH struct {
	TreeSize  uint64 `json:"tree_size"`
	Timestamp uint64 `json:"timestamp"`
	RootHash  string `json:"root_hash"` // hex
	Signature string `json:"signature"` // base64 DigitallySigned
}

// Verified records how the batch was checked against the STH (spec §5.5).
type Verified struct {
	Method     string `json:"method"` // "consistency_proof" or "root_equals_sth"
	ProofNodes int    `json:"proof_nodes"`
}

// Span is a vault range [Start, End).
type Span struct {
	Start vault.Tail `json:"start"`
	End   vault.Tail `json:"end"`
}

// Counts summarise a batch. VaultBytes feeds the disk guard's per-entry
// history (spec §10.1).
type Counts struct {
	Entries      int    `json:"entries"`
	NewCerts     int    `json:"new_certs"` // leaf and chain certificates vaulted by this batch
	DeltaRecords int    `json:"delta_records"`
	LeafErrors   int    `json:"leaf_errors"`
	VaultBytes   uint64 `json:"vault_bytes"`
}

// DictInfo records the dictionary new records used and any training
// failure (amendment A1 §5).
type DictInfo struct {
	ID            uint64 `json:"id"`
	TrainingError string `json:"training_error,omitempty"`
}

// Manifest is _COMMIT.json (spec §8.4, Plan 2 subset: no derived builders yet).
type Manifest struct {
	Format         int                         `json:"format"`
	CommitSeq      uint64                      `json:"commit_seq"`
	BatchID        string                      `json:"batch_id"`
	Log            string                      `json:"log"`
	First          uint64                      `json:"first"`
	Last           uint64                      `json:"last"`
	STH            STH                         `json:"sth"`
	MerkleAfter    *merkle.State               `json:"merkle_after"`
	Verified       Verified                    `json:"verified"`
	CertIDRange    *[2]uint64                  `json:"cert_id_range"` // first and last assigned; null if none
	NextCertID     uint64                      `json:"next_cert_id"`
	Vault          Span                        `json:"vault"`
	Builders       map[string]int              `json:"builders"`
	Files          map[string]dataset.FileInfo `json:"files"`
	Counts         Counts                      `json:"counts"`
	Dictionary     DictInfo                    `json:"dictionary"`
	CTVaultVersion string                      `json:"ctvault_version"`
	CommittedAt    time.Time                   `json:"committed_at"`
}

// ID returns the manifest's batch ID.
func (m Manifest) ID() BatchID { return BatchID{Log: m.Log, First: m.First, Last: m.Last} }

func corrupt(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(format, args...))
}

// readManifest reads and checks a committed batch directory: its manifest
// must be complete and consistent with the directory name, and every listed
// file must exist with its recorded size. Full checksums are left to
// "ctvault verify" (amendment decision, Plan 2B).
func readManifest(dir, log, span string) (Manifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		return Manifest{}, corrupt("committed batch %s has no readable %s: %v", dir, ManifestFile, err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return m, corrupt("%s/%s: %v", dir, ManifestFile, err)
	}
	if m.Format != ManifestFormat || m.Log != log || m.ID().span() != span || m.BatchID != m.ID().String() ||
		m.First > m.Last || m.CommitSeq == 0 || m.MerkleAfter == nil || m.MerkleAfter.Size() != m.Last+1 {
		return m, corrupt("%s/%s is inconsistent with its directory", dir, ManifestFile)
	}
	for _, name := range []string{dataset.EntriesFile, dataset.ChainsFile} {
		if _, ok := m.Files[name]; !ok {
			return m, corrupt("%s/%s does not list %s", dir, ManifestFile, name)
		}
	}
	for name, fi := range m.Files {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil || st.Size() != fi.Bytes {
			return m, corrupt("%s/%s is missing or has the wrong size", dir, name)
		}
	}
	return m, nil
}

// ListCommitted reads every committed batch, ordered by commit_seq, and
// checks that each log's batches are contiguous from index 0 and that
// commit_seq values are unique.
func ListCommitted(root string) ([]Manifest, error) {
	logs, err := os.ReadDir(filepath.Join(root, "dataset"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var all []Manifest
	for _, l := range logs {
		log, ok := strings.CutPrefix(l.Name(), "log=")
		if !ok || !l.IsDir() {
			continue
		}
		batches, err := os.ReadDir(filepath.Join(root, "dataset", l.Name()))
		if err != nil {
			return nil, err
		}
		var mine []Manifest
		for _, b := range batches {
			span, ok := strings.CutPrefix(b.Name(), "batch=")
			if !ok || !b.IsDir() {
				continue
			}
			m, err := readManifest(filepath.Join(root, "dataset", l.Name(), b.Name()), log, span)
			if err != nil {
				return nil, err
			}
			mine = append(mine, m)
		}
		sort.Slice(mine, func(i, j int) bool { return mine[i].First < mine[j].First })
		next := uint64(0)
		for _, m := range mine {
			if m.First != next {
				return nil, corrupt("log %s: batches are not contiguous at index %d (next batch starts at %d)", log, next, m.First)
			}
			next = m.Last + 1
		}
		all = append(all, mine...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].CommitSeq < all[j].CommitSeq })
	for i := 1; i < len(all); i++ {
		if all[i].CommitSeq == all[i-1].CommitSeq {
			return nil, corrupt("commit_seq %d appears twice", all[i].CommitSeq)
		}
	}
	return all, nil
}

// LogTip is a log's committed position.
type LogTip struct {
	Next  uint64        // first index not yet committed
	State *merkle.State // compact range of [0, Next)
}

// Tips returns each log's committed position.
func Tips(committed []Manifest) map[string]LogTip {
	out := map[string]LogTip{}
	for _, m := range committed {
		if t, ok := out[m.Log]; !ok || m.Last+1 > t.Next {
			out[m.Log] = LogTip{Next: m.Last + 1, State: m.MerkleAfter}
		}
	}
	return out
}
```

Create `internal/ingest/writer.go`. Read the `SpillBudget` comment first: it is Decision 16.

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
	rec, err := commit.Recover(commit.RecoverOptions{Paths: w.paths, VaultDirs: o.VaultDirs, Index: w.idx,
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
	w.delta = vault.NewDeltaCache(w.o.Config.Ingest.DeltaLRUEntries)
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

// errRetry marks a first verification or canary failure.
type errRetry struct{ err error }

func (e errRetry) Error() string { return e.err.Error() }
func (e errRetry) Unwrap() error { return e.err }
```

Create `internal/ingest/batch.go`. After `commit.Publish`, an error is classified by whether `_COMMIT.json` reached `dataset/`. If it did, the batch is committed, it must never be abandoned, and recovery finishes P9 and P10 at the next start.

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
	m, err := w.attempt(ctx, src, sth, first, end)
	var retry errRetry
	if !errors.As(err, &retry) {
		return m, err
	}
	w.logf("batch %s: %v; refetching it once", w.batchID(src, first, end), err)
	m, err = w.attempt(ctx, src, sth, first, end)
	if !errors.As(err, &retry) {
		return m, err
	}
	dir, ierr := w.incident(w.batchID(src, first, end), sth, err)
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
	// P0: dictionary training, then the disk-guard peak preflight.
	dict := w.maybeTrain()
	if err := w.preflight(end - first); err != nil {
		return commit.Manifest{}, err
	}
	// P1
	in := commit.Intent{BatchID: id.String(), Log: id.Log, First: id.First, Last: id.Last, STH: toSTH(sth),
		VaultTail: w.vw.Tail(), NextCertID: w.ids.Peek(), MerkleBefore: state.Clone(), Builders: map[string]int{},
		StartedAt: w.o.Now().UTC()}
	if err := commit.WriteIntent(w.paths, in, w.o.Hook); err != nil {
		return commit.Manifest{}, err
	}
	b := &batch{w: w, ctx: ctx, src: src, pb: w.idx.NewBatch(), state: state}
	defer b.pb.Close()
	m, err := w.run(b, in, sth, dict)
	var after errCommitted
	if err != nil && !errors.As(err, &after) {
		if aerr := w.abandon(in); aerr != nil {
			return m, errors.Join(err, fmt.Errorf("abandoning %s: %w", id, aerr))
		}
	}
	return m, err
}

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
	if perr != nil {
		if _, err := os.Stat(filepath.Join(w.paths.BatchDir(id), commit.ManifestFile)); err != nil {
			return m, perr // the rename did not happen: abandon
		}
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
	if w.o.Hook != nil {
		w.o.Hook(HookBeforePebble)
	}
	if err := b.pb.Commit(); err != nil {
		return m, errCommitted{err}
	}
	if w.o.Hook != nil {
		w.o.Hook(HookAfterPebble)
	}
	// P10
	if err := commit.RemoveIntent(w.paths, id, w.o.Hook); err != nil {
		return m, errCommitted{err}
	}
	w.logf("batch %s: %d entries, %d new certificates (%d deltas), %d leaf errors, %d vault bytes, verified by %s; commit_seq %d",
		id, m.Counts.Entries, m.Counts.NewCerts, m.Counts.DeltaRecords, m.Counts.LeafErrors, m.Counts.VaultBytes, verified.Method, seq)
	return m, nil
}

// Hook points around the Pebble apply (P9).
const (
	HookBeforePebble = "commit.P9.before_pebble"
	HookAfterPebble  = "commit.P9.after_pebble"
)

// errCommitted wraps a failure after the commit point: the batch is
// committed, so it must not be abandoned.
type errCommitted struct{ err error }

func (e errCommitted) Error() string { return "after commit: " + e.err.Error() }
func (e errCommitted) Unwrap() error { return e.err }

// abandon discards an attempt: vault, staging and intent go, the Pebble
// batch is discarded by the caller, cert_ids skip to the floor, and the
// delta cache forgets records that no longer exist.
func (w *Writer) abandon(in commit.Intent) error {
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
			return commit.Verified{}, errRetry{errors.New("the computed root differs from the signed root")}
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
		return commit.Verified{}, errRetry{err}
	}
	return commit.Verified{Method: "consistency_proof", ProofNodes: len(proof)}, nil
}

// canary is P6: the staged files, and vault reads of sampled new records.
func (w *Writer) canary(b *batch, stage string) error {
	rnd := rand.New(rand.NewPCG(b.rows[0].Idx, uint64(len(b.rows))))
	if err := w.stager.Canary(b.ctx, stage, b.rows, b.chains, w.o.CanarySamples, rnd); err != nil {
		return errRetry{err}
	}
	r, err := vault.OpenReader(w.o.VaultDirs, w.codec)
	if err != nil {
		return err
	}
	defer r.Close()
	for range min(w.o.CanarySamples, len(b.samples)) {
		s := b.samples[rnd.IntN(len(b.samples))]
		if _, err := r.ReadVerified(s.loc, s.sha); err != nil {
			return errRetry{err}
		}
	}
	return nil
}

// maybeTrain trains dictionary 1 once the committed vault holds
// DictSamples leaf certificates; a failure is recorded and ingestion goes
// on with dictionary 0 (amendment A1 §5). It is tried once per process.
func (w *Writer) maybeTrain() commit.DictInfo {
	if w.dictID != 0 || w.trainTried {
		return commit.DictInfo{ID: w.dictID}
	}
	samples, tr, err := vault.TrainingSet(w.o.VaultDirs, w.codec, w.vw.Tail(), w.o.DictSamples)
	if err != nil || len(samples) < w.o.DictSamples {
		if err != nil {
			return commit.DictInfo{ID: 0, TrainingError: err.Error()}
		}
		return commit.DictInfo{ID: 0}
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
		return commit.DictInfo{ID: 0, TrainingError: err.Error()}
	}
	w.dictID = 1
	return commit.DictInfo{ID: 1}
}

// preflight is the spec §10.1 peak check before a batch starts.
func (w *Writer) preflight(n uint64) error {
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
			return nil
		}
	}
	return err
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
// (spec §12): the pinned head as received, and what was computed.
func (w *Writer) incident(id commit.BatchID, sth logsource.SignedHead, cause error) (string, error) {
	dir := filepath.Join(w.o.Root, "state", "incidents", w.o.Now().UTC().Format("20060102T150405Z")+"_"+id.Log+"_"+fmt.Sprint(id.First))
	if err := fsutil.MkdirAllSync(dir, 0o755); err != nil {
		return "", err
	}
	ev, _ := json.MarshalIndent(map[string]any{"batch_id": id.String(), "cause": cause.Error(), "sth": toSTH(sth),
		"sth_raw": base64.StdEncoding.EncodeToString(sth.Raw), "time": w.o.Now().UTC().Format(time.RFC3339)}, "", " ")
	return dir, fsutil.WriteFileAtomic(filepath.Join(dir, "incident.json"), ev, 0o644)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race -count=1 ./internal/ingest/ -v`
Expected: PASS:
- `TestIngestCommitsVerifiedBatches`, `TestDedupAndLeafErrors`, `TestForkedLogIsAnIncident`
- `TestRecoveryAfterCrashes`, with its 3 subtests
- `TestDiskCapRefusesBeforeAnyWrite`, `TestDictionaryTraining`, `TestWarmUpAfterRestart`

The run takes about 10 s.

- [ ] **Step 5: Gate and commit**

Run the gate commands. All must pass.

```bash
git add internal/ingest internal/commit
git commit -m "feat: batch engine — verified fetch, dedup, leaf-delta, staging, canary, commit, refetch once and incidents"
```

---

### Task B7: The `update` command and dev replay

Implements spec §5.6, §11.2 (`update`/`ingest`, `--follow`) and §12, amendment A1 §2.5 (`--replay`, dev batch size) and §3 (`--until`), and the README.

**Files:**
- Create: `internal/logsource/headstore.go`, `internal/cli/update.go`, `internal/cli/update_dev.go`
- Create tests: `internal/logsource/headstore_test.go`, `internal/cli/update_test.go`, `internal/cli/update_dev_test.go`
- Modify: `internal/cli/cli.go`, `internal/cli/vaultcmds.go`, `internal/config/config.go`, `internal/cli/build_prod_test.go`, `cmd/ctvault/guard_test.go`, `README.md`

**Interfaces:**
- Consumes:
  - Task B6: `ingest.Open` and `Batch`
  - Plan 2A: `stop.OnSignals`, `sample.Open` and `Serve`, `rfc6962.NewSource`, `logsource.InfoFromRecord`, `logreg`
- Produces:
  - `logsource`:
    - `HeadsDir`, `SaveHead(stateDir, log, h, now)`
    - `LoadHead(stateDir, log, info) (*SignedHead, error)`, `ErrBadHeadFile`
  - `config`: `WriteDefaultBatch(root, batchSize)`
  - The CLI:
    - `ctvault update [--follow] [--until N] [--log NAME]`, alias `ingest`
    - dev build only: `--replay <canonical sample>`

- [ ] **Step 1: Write the failing tests**

Create `internal/logsource/headstore_test.go`:

```go
package logsource_test

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
)

func info(t *testing.T, l *ctlogtest.Log) logsource.LogInfo {
	t.Helper()
	pub, err := x509.ParsePKIXPublicKey(l.PublicKeyDER)
	if err != nil {
		t.Fatal(err)
	}
	return logsource.LogInfo{Name: "fakelog", LogID: l.LogID, PublicKey: pub, URL: l.URL}
}

func TestHeadStore(t *testing.T) {
	l := ctlogtest.New(t, 10, ctlogtest.Options{})
	in := info(t, l)
	state := t.TempDir()
	if h, err := logsource.LoadHead(state, "fakelog", in); err != nil || h != nil {
		t.Fatalf("no stored head yet: %v %v", h, err)
	}
	h, err := rfc6962.NewSource(in, nil, logsource.NewChainCache(1<<20), nil).Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := logsource.SaveHead(state, "fakelog", h, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	got, err := logsource.LoadHead(state, "fakelog", in)
	if err != nil || got.TreeSize != 10 || got.RootHash != h.RootHash || string(got.Raw) != string(h.Raw) {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	other := info(t, ctlogtest.New(t, 1, ctlogtest.Options{}))
	if _, err := logsource.LoadHead(state, "fakelog", other); !errors.Is(err, logsource.ErrBadHeadFile) {
		t.Fatalf("a head that does not verify with the pinned key is refused: %v", err)
	}
	os.WriteFile(filepath.Join(state, logsource.HeadsDir, "fakelog.json"), []byte("{"), 0o644)
	if _, err := logsource.LoadHead(state, "fakelog", in); !errors.Is(err, logsource.ErrBadHeadFile) {
		t.Fatalf("an unreadable head file is refused: %v", err)
	}
}
```

Create `internal/cli/update_test.go`:

```go
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
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/lock"
	"github.com/4rji/ctvault/internal/logreg"
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
```

Create `internal/cli/update_dev_test.go`:

```go
//go:build ctvault_dev

package cli

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/sample"
	"github.com/4rji/ctvault/internal/volume"
	"github.com/4rji/ctvault/internal/volume/volumetest"
)

var sampleTestLimits = sample.Limits{Boundary: 8, Min: 16, Max: 96}

// captureFake captures a sample of the fake log with frames of 8 entries.
func captureFake(t *testing.T, l *ctlogtest.Log, kind sample.Kind, start, count uint64) *sample.Sample {
	t.Helper()
	pub, _ := x509.ParsePKIXPublicKey(l.PublicKeyDER)
	info := logsource.LogInfo{Name: "fakelog", LogID: l.LogID, PublicKey: pub, URL: l.URL}
	src := rfc6962.NewSource(info, nil, logsource.NewChainCache(logsource.DefaultChainCacheBytes), nil)
	dir := t.TempDir()
	t.Cleanup(func() {
		filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				os.Chmod(p, 0o755)
			}
			return nil
		})
	})
	s, err := sample.Capture(context.Background(), dir, src, sample.CaptureOptions{Kind: kind, Start: start, Count: count,
		Limits: sampleTestLimits, Key: base64.StdEncoding.EncodeToString(l.PublicKeyDER), LogListVersion: "test", Version: "test",
		Fetch: fetch.Options{MaxRPS: 1000, MinBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// devVault creates a dev vault on a fake ext4 mount, with batch_size set.
func devVault(t *testing.T, l *ctlogtest.Log, batchSize int) *env {
	t.Helper()
	e := newEnv(t, nil)
	p := volumetest.New()
	base := p.Mount(t, t.TempDir(), "ext4", "8:33", "dev-uuid")
	e.deps.Volumes = volume.DevProbe{Base: base, Probe: p, Now: e.deps.Now}
	e.deps.HTTP = &http.Client{}
	e.deps.Statfs = freeDisk
	e.root = filepath.Join(base, "vaults", "v1")
	e.mustRun("init", e.root)
	if b, _ := os.ReadFile(filepath.Join(e.root, config.FileName)); !strings.Contains(string(b), "batch_size = 10000") {
		t.Fatalf("a dev vault starts with 10,000-entry batches (amendment A1 §2.5): %s", b)
	}
	cfg := "[ingest]\nbatch_size = " + itoa(batchSize) + "\ndelta_lru_entries = 1000\n[vault]\nsegment_size = \"1MiB\"\n"
	os.WriteFile(filepath.Join(e.root, config.FileName), []byte(cfg), 0o644)
	pinFake(t, e.root, l)
	return e
}

func itoa(n int) string {
	b := []byte{}
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func TestReplayIngestsACanonicalSample(t *testing.T) {
	l := ctlogtest.New(t, 120, ctlogtest.Options{PageSize: 4})
	s := captureFake(t, l, sample.Canonical, 0, 48)
	e := devVault(t, l, 16)
	before := l.Requests("get-entries")
	out := e.mustRun("--root", e.root, "update", "--replay", s.Dir)
	ms := committed(t, e.root)
	if len(ms) != 3 || ms[2].Last != 47 || ms[2].Verified.Method != "consistency_proof" {
		t.Fatalf("48 sampled entries in 3 verified batches: %d batches; %s", len(ms), out)
	}
	if l.Requests("get-entries") != before {
		t.Fatal("replay must not contact the live log")
	}
	if out := e.mustRun("--root", e.root, "update", "--replay", s.Dir); !strings.Contains(out, "up to date at index 48") {
		t.Fatalf("the replay ends at the sample's end: %s", out)
	}
}

func TestReplayRefusals(t *testing.T) {
	l := ctlogtest.New(t, 120, ctlogtest.Options{PageSize: 4})
	canonical := captureFake(t, l, sample.Canonical, 0, 48)
	representative := captureFake(t, l, sample.Representative, 16, 32)
	other := ctlogtest.New(t, 10, ctlogtest.Options{})
	for name, tc := range map[string]struct {
		batch  int
		pinned *ctlogtest.Log
		args   []string
	}{
		"representative sample": {16, l, []string{"--replay", representative.Dir}},
		"batch size off grid":   {20, l, []string{"--replay", canonical.Dir}},
		"until past the sample": {16, l, []string{"--replay", canonical.Dir, "--until", "56"}},
		"until off grid":        {16, l, []string{"--replay", canonical.Dir, "--until", "20"}},
		"another log's sample":  {16, other, []string{"--replay", canonical.Dir}},
	} {
		e := devVault(t, tc.pinned, tc.batch)
		if code := e.run(append([]string{"--root", e.root, "update"}, tc.args...)...); code != exitcode.Usage {
			t.Errorf("%s: exit %d, want 2: %s", name, code, e.stderr)
		}
		if len(committed(t, e.root)) != 0 {
			t.Errorf("%s: nothing may be committed", name)
		}
	}
}
```

Replace `internal/cli/build_prod_test.go` (adds `TestProductionUpdateHasNoReplay`):

```go
//go:build !ctvault_dev

package cli

import (
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/exitcode"
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

func TestProductionUpdateHasNoReplay(t *testing.T) {
	e := newEnv(t, realSTH(t))
	if code := e.run("update", "--replay", "x"); code != exitcode.Usage || !strings.Contains(e.stderr.String(), "unknown flag") {
		t.Fatalf("production must not know --replay: exit %d, %s", code, e.stderr)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/logsource/ ./internal/cli/`
Expected: FAIL with `undefined: logsource.LoadHead` in `internal/logsource`, and `undefined: headRetryDelay` in `internal/cli`.

- [ ] **Step 3: Implement**

Create `internal/logsource/headstore.go`:

```go
package logsource

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/merkle"
)

// HeadsDir holds each log's last accepted signed head, state/heads/<log>.json
// (Plan 2B decision: the persisted head is the last signed head, amendment
// A1 §3; it never changes on --until).
const HeadsDir = "heads"

type headFile struct {
	TreeSize   uint64    `json:"tree_size"`
	Timestamp  uint64    `json:"timestamp"`
	RootHash   string    `json:"root_hash"` // hex
	Signature  string    `json:"signature"` // base64 DigitallySigned
	Raw        string    `json:"raw"`       // base64 of the response as received
	AcceptedAt time.Time `json:"accepted_at"`
}

func headPath(stateDir, log string) string { return filepath.Join(stateDir, HeadsDir, log+".json") }

// SaveHead records h as log's last accepted head, durably.
func SaveHead(stateDir, log string, h SignedHead, now time.Time) error {
	if err := fsutil.MkdirAllSync(filepath.Join(stateDir, HeadsDir), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(headFile{TreeSize: h.TreeSize, Timestamp: h.Timestamp,
		RootHash: hex.EncodeToString(h.RootHash[:]), Signature: base64.StdEncoding.EncodeToString(h.Signature),
		Raw: base64.StdEncoding.EncodeToString(h.Raw), AcceptedAt: now.UTC()}, "", " ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(headPath(stateDir, log), b, 0o644)
}

// ErrBadHeadFile means a stored head is unreadable or no longer verifies.
var ErrBadHeadFile = errors.New("stored signed head is damaged")

// LoadHead returns log's last accepted head, nil if none, after checking its
// signature with the pinned key again.
func LoadHead(stateDir, log string, info LogInfo) (*SignedHead, error) {
	b, err := os.ReadFile(headPath(stateDir, log))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f headFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrBadHeadFile, headPath(stateDir, log), err)
	}
	root, err1 := hex.DecodeString(f.RootHash)
	sig, err2 := base64.StdEncoding.DecodeString(f.Signature)
	raw, err3 := base64.StdEncoding.DecodeString(f.Raw)
	if err1 != nil || err2 != nil || err3 != nil || len(root) != 32 {
		return nil, fmt.Errorf("%w: %s", ErrBadHeadFile, headPath(stateDir, log))
	}
	h := SignedHead{SignedTreeHead: merkle.SignedTreeHead{TreeSize: f.TreeSize, Timestamp: f.Timestamp, Signature: sig}, Raw: raw}
	copy(h.RootHash[:], root)
	if err := merkle.VerifySTH(info.PublicKey, h.SignedTreeHead); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrBadHeadFile, headPath(stateDir, log), err)
	}
	return &h, nil
}
```

Create `internal/cli/update.go`:

```go
package cli

import (
	"context"
	"encoding/base64"
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
			err := u.cycle(c, stops, w, rec, cfg, root)
			switch {
			case err == nil:
			case stops.Hard.Err() != nil:
				return exitcode.Withf(exitcode.Error, "stopped by a second interrupt; the batch in progress was abandoned")
			case u.follow && errors.Is(err, diskguard.ErrCap):
				fmt.Fprintf(c.ErrOrStderr(), "warning: %v; pausing until the next cycle\n", err)
			case u.follow && errors.Is(err, fetch.ErrStalled):
				fmt.Fprintf(c.ErrOrStderr(), "warning: %v; retrying next cycle\n", err)
			default:
				return ingestErr(err)
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
	head, err := u.head(stops.Hard, src, rec.Name, last, state)
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

// head fetches and checks the signed head; a bad signature or an incident
// is refetched once after headRetryDelay, then written as an incident.
func (u *updateRun) head(ctx context.Context, src logsource.LogSource, log string, last *logsource.SignedHead, state string) (logsource.SignedHead, error) {
	get := func() (h logsource.SignedHead, err error) {
		err = fetch.Retry(ctx, fetch.Options{}, func(ctx context.Context) (err error) {
			h, err = src.Head(ctx)
			return err
		})
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
	b, _ := json.MarshalIndent(ev, "", " ")
	if werr := fsutil.MkdirAllSync(dir, 0o755); werr == nil {
		fsutil.WriteFileAtomic(filepath.Join(dir, "incident.json"), b, 0o644)
	}
	return h2, exitcode.With(exitcode.Verification, fmt.Errorf("%s: %w (incident written to %s)", log, err2, dir))
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

Create `internal/cli/update_dev.go`:

```go
//go:build ctvault_dev

package cli

import (
	"errors"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/sample"
)

// DevBatchSize is the dev build's default ingest.batch_size (amendment A1
// §2.5).
const DevBatchSize = 10000

func init() {
	updateHooks = append(updateHooks, addReplay)
	writeConfig = func(root string) error { return config.WriteDefaultBatch(root, DevBatchSize) }
}

// addReplay gives update --replay <canonical sample>: the sample is served
// over loopback and ingested by the unchanged client, fetcher and writer.
func addReplay(cmd *cobra.Command, u *updateRun) {
	var dir string
	var s *sample.Sample
	cmd.Flags().StringVar(&dir, "replay", "", "ingest a cached canonical sample over loopback instead of the live log (dev build only)")
	live := u.source
	u.prepare = func(c *cobra.Command) error {
		if dir == "" {
			return nil
		}
		var err error
		if s, err = sample.Open(dir); err != nil {
			if errors.Is(err, sample.ErrCorrupt) {
				return exitcode.With(exitcode.Verification, err)
			}
			return err
		}
		m := s.Manifest
		if m.Kind != sample.Canonical {
			return exitcode.Withf(exitcode.Usage, "--replay needs a canonical sample; representative samples are for measurements only")
		}
		if u.logName == "" {
			u.logName = m.Log.Name
		} else if u.logName != m.Log.Name {
			return exitcode.Withf(exitcode.Usage, "the sample is of log %s, not %s", m.Log.Name, u.logName)
		}
		if u.untilSet && (u.until%m.Boundary != 0 || u.until > m.Start+m.Count) {
			return exitcode.Withf(exitcode.Usage, "with --replay, --until must be a multiple of %d within the sample's %d entries", m.Boundary, m.Count)
		}
		return nil
	}
	u.check = func(cfg config.Config, next uint64) error {
		if s == nil {
			return nil
		}
		b := s.Manifest.Boundary
		if uint64(cfg.Ingest.BatchSize)%b != 0 || next%b != 0 {
			return exitcode.Withf(exitcode.Usage, "with --replay, ingest.batch_size (%d) and the vault's position (%d) must be multiples of %d: the sample has proofs only there", cfg.Ingest.BatchSize, next, b)
		}
		return nil
	}
	u.source = func(c *cobra.Command, info logsource.LogInfo, chains *logsource.ChainCache, last *logsource.SignedHead) (logsource.LogSource, uint64, func(), error) {
		if s == nil {
			return live(c, info, chains, last)
		}
		if s.LogIDBytes() != info.LogID {
			return nil, 0, nil, exitcode.Withf(exitcode.Usage, "the sample's log ID differs from the pinned log %s", info.Name)
		}
		url, stopFn, err := sample.Serve(c.Context(), s)
		if err != nil {
			return nil, 0, nil, err
		}
		info.URL = url
		src := rfc6962.NewSource(info, &http.Client{Timeout: 60 * time.Second}, chains, last)
		return src, s.Manifest.Start + s.Manifest.Count, stopFn, nil
	}
}
```

Replace `internal/cli/cli.go` (registers `update`):

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
	root.AddCommand(newVersionCmd(a), newInitCmd(a), newLogsCmd(a), newVaultCmd(a), newUpdateCmd(a))
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

Replace `internal/cli/vaultcmds.go` (adds `writeConfig`):

```go
package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/volume"
)

// writeConfig writes a new vault's ctvault.toml; the dev build replaces it
// to use 10,000-entry batches (amendment A1 §2.5).
var writeConfig = config.WriteDefault

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
			if err := writeConfig(args[0]); err != nil {
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

Replace `internal/config/config.go` (adds `WriteDefaultBatch`):

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
func WriteDefault(root string) error { return WriteDefaultBatch(root, Default().Ingest.BatchSize) }

// WriteDefaultBatch is WriteDefault with another ingest.batch_size.
func WriteDefaultBatch(root string, batchSize int) error {
	p := filepath.Join(root, FileName)
	if _, err := os.Stat(p); err == nil {
		return nil
	}
	body := strings.Replace(DefaultTOML, "batch_size = 500000", fmt.Sprintf("batch_size = %d", batchSize), 1)
	return fsutil.WriteFileAtomic(p, []byte(body), 0o644)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race -count=1 ./internal/logsource/ ./internal/cli/ -v -run 'HeadStore|Update|NoReplay' && go test -race -count=1 -tags ctvault_dev ./internal/cli/ -v -run Replay`
Expected: PASS:
- `TestHeadStore`
- `TestUpdateIngestsToTheHead`, `TestUpdateUntil`, `TestUpdateIncidents`, `TestUpdateDiskCapAndLock`
- `TestUpdateFollowStopsOnFirstSignal`, which sends SIGINT to its own process; the update handler catches it
- `TestProductionUpdateHasNoReplay`
- `TestReplayIngestsACanonicalSample`, `TestReplayRefusals`

- [ ] **Step 5: Narrow the binary guard to CTVault's own files**

The production binary now links Pebble, which pulls in `prometheus/procfs`, whose `net_dev.go` trips the `_dev.go` file rule. Replace `cmd/ctvault/guard_test.go`:

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

Run: `go test -count=1 ./cmd/ctvault/ -v`
Expected: PASS (`TestProductionBinaryExcludesDevCode`, `TestOnlyRootEnvVarIsRead`).

- [ ] **Step 6: Update the README**

Replace `README.md`:

````markdown
# CTVault

A local, cryptographically verified Certificate Transparency research archive.
Design: `docs/superpowers/specs/2026-10-04-ctvault-design.md`.

**Status:** Plan 2B (vault). `ctvault update` ingests pinned logs into the
vault:
- Every batch is verified against a signed tree head.
- Every unique certificate is stored compressed and deduplicated.
- `entries` and `chains` are written as Parquet, with `views.sql` for the
  DuckDB CLI.
- A crash at any point recovers to the last committed batch.

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

- [ ] **Step 7: Gate and commit**

Run the gate commands. All must pass.

```bash
git add internal cmd README.md
git commit -m "feat: ctvault update/ingest with --follow, --until, signals and incidents; dev --replay"
```

- [ ] **Step 8: Live check (opt-in; ask your human partner first)**

This writes a dev vault of about 110 MB under `~/.cache/ctvault-dev/vaults/`, and `logs add` reads Chrome's log list.

```bash
go build -tags ctvault_dev -o ctvault-dev ./cmd/ctvault
./ctvault-dev init ~/.cache/ctvault-dev/vaults/argon
./ctvault-dev --root ~/.cache/ctvault-dev/vaults/argon logs add argon2027h1
./ctvault-dev --root ~/.cache/ctvault-dev/vaults/argon update \
  --replay ~/.cache/ctvault-dev/samples/argon2027h1/000000000000-000000099999
duckdb -c ".read $HOME/.cache/ctvault-dev/vaults/argon/views.sql" -c "SELECT count(*), count(DISTINCT cert_id) FROM entries"
```

Expected:
- **`update`:** 10 batches, each "verified by consistency_proof", with dictionary 1 trained before the fourth. It takes about 4 minutes.
- **The DuckDB query** (if the `duckdb` CLI is installed) shows `100000` entries.

---

## Post-review fixes (applied after execution)

A fresh whole-change review found 2 Critical and 5 Important issues. One Minor was raised to Important, because corruption must never be ignored. Each was fixed test-first: a test that reproduced it failed first, then the whole suite ran. The code now differs from the task text above in these places:

1. **C1, recovery could truncate committed data.** If committed batch directories went missing (a mistaken `rm`, a partial restore), recovery truncated the vault data they referenced, and Pebble kept pointing at it.
   - `commit.Recover` now refuses with exit 5, changing nothing, in two cases: Pebble's `applied/<log>` is ahead of the highest committed batch (new `index.AppliedLogs`), or vault data beyond the committed tail is not explained by an uncommitted intent starting at that tail.
   - Tests: `TestRecoverRefusesToTruncateUnexplainedData`, `TestRecoverRefusesAnIndexAheadOfTheDataset`.
2. **C2, a committed batch could be abandoned.**
   - `commit.Publish` wraps any error after the rename in `commit.ErrPostCommit`, and the engine abandons only before the rename. It used to decide from a `stat` call, so an EACCES or EIO abandoned a committed batch.
   - Test: `TestErrorAfterTheCommitPointKeepsTheBatch`.
3. **I1, abandoned IDs were reused after a restart.**
   - `commit.Abandon` keeps the intent, marked `abandoned`, so the next start resumes at `ID_FLOOR`. A later successful commit clears it (`commit.ClearAbandoned`).
   - Test: `TestAbandonedIDsAreNeverReusedAfterARestart`.
4. **I2, segments went to the wrong vault directory.** `preflight` returns the vault directory it reserved space on, and `vault.Writer.Prefer` rolls the batch's new segments into it. A reopened writer now records the vault directory, not its `segments/` subfolder.
   - Tests: `TestSegmentsGoWhereThePreflightReserved`, `TestPreferStartsNewSegmentsInTheReservedDirectory`, `TestPreferAfterReopenKeepsTheTailSegment`.
5. **I3, whole segments were read into memory.**
   - `vault.Scan` and `InspectTail` stream records instead of loading whole segments, and `InspectTail` reads nothing past a clean tail.
   - `Warm` merges contiguous ranges, and the delta cache is reset and reused (`DeltaCache.Reset`).
   - Tests: `TestScanAndInspectStream`, `TestDeltaCacheReset`.
6. **I4, volume checks were not repeated per batch.** `ingest.Options.CheckVolumes` runs at every batch preflight (spec §9.2), and `update` exits 4 when the volume is gone.
   - Tests: `TestVolumeCheckRunsBeforeEveryBatch`, `TestUpdateStopsWhenTheVolumeDisappears`.
7. **I5, the incident evidence was too thin.** Batch incidents now record both attempts' causes, the STH and its raw bytes, the compact range before the batch, the computed root and end, and the proof nodes (spec §12).
   - Test: `TestForkedLogIsAnIncident`.
8. **M4, raised: corruption during training was ignored.** Corruption met while reading the dictionary training samples now stops the batch with exit 5, instead of being recorded as a training error.
   - Test: `TestCorruptionFoundByTrainingStops`.

Ten Minor findings are deferred. They are listed in the execution ledger and in the final report.
