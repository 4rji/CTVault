# CTVault Spec Amendment A1: dev build, real-data samples, `--until`, binary hashes

- **Date:** 2026-10-04
- **Status:** Draft, awaiting review
- **Amends:** `docs/superpowers/specs/2026-10-04-ctvault-design.md` ("the spec")
- **Origin:** Plan 2 design discussion. All six design sections were approved, with refinements.
- **Scope:** Plan 2, the source-layer ingest (phase 2 of spec §16). Plans 3 and 4 reuse the real-data samples defined here.

Everything not changed here stays as in the spec. **Production safety requirements are unchanged.** Nothing in this amendment lets a production build accept the normal disk, loosens any volume check, or adds a runtime flag or environment variable that affects safety.

---

## 0. Changes at a glance

| Spec section | Change |
|---|---|
| D19 (§2), §6.4 | Binary columns are allowed when the file is written with no bloom filters. Hex `VARCHAR` is reserved for columns that need bloom-pruned lookups, such as `certs.sha256` in Plan 3. (§6 here.) |
| §5.4–5.5 | Stricter head checks; leaf decoding and precert consistency checks; a bounded chain cache; a byte-bounded reorder buffer; two signal contexts. (§4 here.) |
| §5.6, §11.2 | New production flag `--until N`. (§3 here.) |
| §6.2 | Exact `issuer_key_hash` definition; delta matching on the full 32-byte digest; a dictionary manifest with a fallback; the delta cache is optional; a configurable warm-up window. (§5 here.) |
| §8, §10.1 | Early `ID_FLOOR` reservation; `views.sql` rewritten only on change; a graceful-stop message; DuckDB spill counted in the peak estimate. (§7 here.) |
| §9 | New §9.4: a dev build, `-tags ctvault_dev`. (§1 here.) |
| §13 | Real-data samples, measurement reports and a test matrix. (§2, §8 and §9 here.) |
| §15 | V1 resolved: pure-Go `klauspost/compress` v1.20.1 supports raw-content dictionaries. V2 (bloom and dictionary limits) moves to Plan 3. |
| Plan 1 review | Deferred minors 6, 7, 9, 10, 11, 12, 14 (the `tmp/` scope), 15 and 16 are folded into Plan 2. (§11 here.) |

---

## 1. Dev build, `-tags ctvault_dev` (new spec §9.4)

**Purpose:** run the real CTVault binary by hand against real CT data on the normal disk, before the external SSD is available. The dev binary is the **only** way to ingest real CT data onto the normal disk.

**Compile-time selection only:**
- `internal/volume/build_prod.go` (`//go:build !ctvault_dev`) defines `const devBuild = false`.
- `internal/volume/build_dev.go` (`//go:build ctvault_dev`) defines `const devBuild = true`.
- The dev probe (`devprobe.go`) and the dev-only CLI pieces (`sample …`, `update --replay`) live only in files tagged `ctvault_dev`.
- Build the dev binary with `go build -tags ctvault_dev -o ctvault-dev ./cmd/ctvault`.

**Rules:**

| Rule | Production binary | Dev binary |
|---|---|---|
| Where a vault may live | A dedicated mount point that is not on the system disk (spec §9, unchanged) | Only under `<home>/.cache/ctvault-dev/`. `<home>` comes from the OS user database, not `$HOME`. Symlinks are resolved and escapes are refused. |
| `VAULT_ID` | `"mode": "production"`. A missing `mode` (Plan 1 vaults) means production. | `"mode": "dev"`, `"durability": "dev-unsafe"`, plus the real filesystem UUID of the normal disk, checked on every start |
| Opening the other kind | Refuses dev vaults: exit 4, "dev vault created by a ctvault_dev build" | Refuses production vaults and any root outside the dev base |
| Filesystem policy | Spec §9.3, unchanged | Any local filesystem. Network filesystems, FUSE and tmpfs are refused. |
| Disk guard | Spec §10.1 | The same 85% cap, protecting the normal disk |
| Visible marking | — | `version` prints "DEV BUILD — not for production", and every command prints a warning banner on stderr |

- **No runtime switch.** The dev probe takes its base folder as a constructor argument: the dev binary passes the user's cache folder, and tests pass a temp folder. There is no flag or environment variable for it.
- **Guard tests** run in the normal `go test ./...`:
  1. `TestProductionBinaryExcludesDevCode`:
     - `go list -deps -json ./cmd/ctvault` with production tags must contain no `ctvault_dev` file and no test-only package (`volumetest`, `ctlogtest`, `sampletest`).
     - The built production binary must have no `DevProbe` symbol, checked with `go tool nm`.
  2. `TestProductionRefusesDevVault`: a dev-marked `VAULT_ID` on a fake mount must give exit 4.
  3. `TestOnlyRootEnvVarIsRead`: a scan of the production source for `os.Getenv` and `os.LookupEnv`. Only `CTVAULT_ROOT` is allowed, and it selects a path; it never loosens a check.
  4. Dev-tagged tests (`go test -tags ctvault_dev ./...`) cover dev init, the path restriction, banner and marking, and the refusal of production vaults.

---

## 2. Real-data samples

### 2.1 Two kinds of sample

| | Canonical sample | Representative sample |
|---|---|---|
| Purpose | Deterministic replay, recovery, correctness and regression tests | Measuring realistic sizes, compression and delta behaviour |
| Range | `argon2027h1` `[0, N)`, N = 100,000 by default | A window `[S, S+N)` chosen with `--start S` or `--start head` |
| Stability | **Fixed forever** once captured | Re-captured as needed; each capture is a new, immutable sample |
| May feed a vault | Yes, through `update --replay` (dev build) | **No.** Measurement only. Vaults always ingest from index 0 (spec §5.5). |

- **Size:** N must be between 50,000 and 500,000 and a multiple of 5,000.
- **`--start head`:** `S = floor((head.tree_size − N) / 5000) × 5000`, using the pinned head.

The start of a shard is **not assumed to be representative**. Tuning numbers come from representative samples (§8).

### 2.2 Cache layout

Everything lives outside the repository, under the dev base:

```text
<home>/.cache/ctvault-dev/
├── samples/<log>/<start>-<end>[<suffix>]/   read-only once complete
│   ├── sample.json          manifest (below)
│   ├── entries.ndjson.zst   one line per entry: {"i": idx, "leaf_input": b64, "extra_data": b64}, exactly as served
│   └── proofs.json          canonical: consistency proofs from every 5,000-entry boundary to the pinned head
│                            representative: an inclusion proof for leaf S, and a consistency proof S+N → head
├── vaults/<name>/            dev vaults (§1)
└── reports/<sample-id>/<timestamp>.json   measurement reports (§8)
```

`sample.json` records:
- `format`, `kind` (`canonical` or `representative`), the log's name, log ID, pinned key and URL, and the log-list version
- the pinned signed head, exactly as received
- `start`, `count`, and the page size the log served
- `captured_at`, the CTVault version, and the SHA-256 of every file

### 2.3 Capture (dev build only)

Commands:
- `ctvault-dev sample capture --log argon2027h1 [--start S|head] --entries N [--suffix X]`
- `ctvault-dev sample verify <dir>`

Capture works like this:
1. Resolve and pin the log from Chrome's log list, then fetch and verify a signed head.
2. Fetch the range through **Plan 2's real fetcher**, so capturing also exercises the live fetch path. Data **streams into temporary files** inside a staging folder next to the destination.
3. Verify (§2.4) **before anything becomes visible**.
4. fsync, make the files read-only, and atomically rename the staging folder into place.
   - Any failure or interruption leaves no visible sample.
   - **An existing sample is never overwritten.** A new capture of the same range needs a new `--suffix`.

### 2.4 Verification on every load

Every load, and `sample verify`, first checks the file checksums against the manifest and re-verifies the signed head with the pinned key. Then:
- **Canonical:** recompute the compact range of `[0, N)` from the stored leaves, and check the stored consistency proof at every 5,000 boundary against the signed root.
- **Representative:**
  1. Verify the inclusion proof for leaf S against the signed root.
  2. Its **left siblings form the authenticated compact range `[0, S)`**. This follows from RFC 9162 §2.1.3.2: a proof node is a left sibling exactly when the low bit of `fn` is set or `fn == sn`. It was checked for every leaf of every tree size from 1 to 70 against a reference tree, and live on `argon2027h1` with a 27-node proof.
  3. Append the window's leaves to reach `S+N`.
  4. Verify the consistency proof from `S+N` to the signed root.

A corrupted or altered sample is refused. Replay can never silently feed changed data.

### 2.5 Replay

- Replay is served over **loopback HTTP** (127.0.0.1), so the real RFC 6962 client and fetcher run unchanged. The server answers `get-sth`, `get-entries` at the captured page size (32 for Argon), and the stored proofs.
- **Go tests** use the test-only package `internal/sampletest`.
- **Dev binary:** `ctvault-dev update --replay <canonical sample dir>`. It refuses representative samples, and samples whose log ID differs from the vault's pinned log. `--replay` exists only in the dev build.
- With replay, the batch size and `--until` must fall on 5,000 boundaries. The dev default batch size is 10,000.

### 2.6 Measurement runs (dev build only)

- `ctvault-dev sample measure <sample dir>` runs the per-entry pipeline (decode, issuance key, dedup, vault writer with dictionaries and `leaf-delta`, Parquet staging) on a canonical or representative sample.
- It runs in a temporary workspace under the dev base, writes a measurement report (§8), and deletes the workspace.
- It never creates or modifies a vault.

---

## 3. `--until N` (production and dev; amends spec §5.6 and §11.2)

`update --until N` is an ingestion boundary, useful for staged ingestion, controlled catch-up, maintenance windows and testing a deployment against a bounded range.
- **N is an exclusive end index.** `--until 100000` ingests `[checkpoint, 100000)`.
- **If `checkpoint >= N`, exit 0 without fetching anything**, not even a signed head.
- **Otherwise, require `checkpoint < N <= pinned_head.tree_size`.** If N exceeds the pinned head's size, exit 1 ("the log currently has only X entries") without fetching entries.
- **The final batch may be partial** (it ends at N). Like every batch, it is verified by a consistency proof from N to the pinned head.
- **`--until` never changes the persisted log head** and never leads a later normal `update` to think the log ends at N. The checkpoint is just the last committed index, and the persisted head is the last signed head.

---

## 4. Collector refinements (amends spec §5.3–5.5)

**Head checks.** `Head()` verifies the signature with the pinned key. Against the last accepted head, each of these is an **incident** (exit 5):
- a smaller tree size
- the same tree size with a different root hash
- a timestamp that moves backwards

**Leaf decoding** (`internal/leaf`):
- The leaf hash is **always** RFC 6962's `SHA-256(0x00 ‖ leaf_input)` over the exact bytes, even when decoding fails.
- Fields that cannot be decoded safely stay null; nothing is guessed.
- Stable error codes:
  - **leaf structure:** `leaf_bad_version`, `leaf_bad_leaf_type`, `leaf_unknown_entry_type`, `leaf_truncated`, `leaf_trailing_bytes`
  - **extra_data:** `extra_truncated`, `extra_trailing_bytes`, `chain_cert_empty`
  - **issuer:** `chain_issuer_missing`, `chain_issuer_ambiguous`
  - **precert:** `issuer_key_hash_mismatch`, `precert_tbs_mismatch`, `issuance_key_unavailable`

**Precertificates:**
- The log's TBS bytes are kept exactly and are **authoritative**. Any reconstructed TBS is derived data used only for comparison and never replaces them.
- The issuer is identified from **chain relationships, never chain position**:
  - Its subject must equal the certificate's issuer.
  - Its subject key ID must equal the certificate's authority key ID when both are present.
  - A certificate with the CT precertificate-signing EKU (`1.3.6.1.4.1.11129.2.4.4`) is a precert-signing certificate, and the real issuer is the certificate that issued it.
  - No candidate gives `chain_issuer_missing`; more than one gives `chain_issuer_ambiguous`.
- **`issuer_key_hash` = SHA-256 over the issuer certificate's DER-encoded SubjectPublicKeyInfo.** A mismatch with the leaf's value gives `issuer_key_hash_mismatch`.
- The log's TBS must equal the precertificate's TBS with the poison extension removed. In the precert-signing case, its issuer name and authority key ID are also replaced by the real issuer's. A mismatch gives `precert_tbs_mismatch`.
- On any of these errors the entry is still committed, and its raw bytes go to `quarantine.ndjson`.

**Chain cache:**
- Chain DER is cached **per batch**, safe for concurrent use and bounded, and kept until the batch commits.
- Entries are evicted only after the commit, so the cache never grows across a multi-week run.

**Reorder buffer.** It is bounded by both **entry count** (`fetch.max_buffered_entries`, default 65,536) and **bytes** (`fetch.max_buffered_bytes`, default 256 MiB). Workers pause when either limit is reached.

**Signals use two contexts:**
- **The first** stops scheduling new batches after the current batch commits, and prints that CTVault is finishing the current batch. That may take a long time with 500k batches.
- **The second** cancels the batch in flight, which is then abandoned and recovered.

---

## 5. Vault refinements (amends spec §6.2)

- **`leaf-delta`** is chosen only after the relationship is confirmed: the cache is keyed by the **full 32-byte issuance digest**. The 16-byte `issuance_key` remains the join column. Every read verifies the rebuilt final certificate's full SHA-256.
- **The delta cache is an optimization only.** An eviction, a restart or a missing precert simply stores the final certificate in full.
- **Its warm-up window is configurable** (`delta.warm_batches`, default 4), to be tuned from representative-sample measurements by an explicit change.
- **Dictionaries are part of the vault format:**
  - Each one is persisted permanently with a manifest (`dict/<id>.json`). The manifest records its SHA-256, the zstd implementation and version that created it (for example `klauspost/compress v1.20.1`), the training sample (the first 20,000 leaf certificates in index order) and the creation time.
  - **Nothing assumes that retraining with a future library version reproduces the same bytes.**
  - If training fails or yields an unusable dictionary, ingestion continues with dictionary 0, and the failure is recorded in `_COMMIT.json`.
- **Compression library:** pure-Go `klauspost/compress` v1.20.1, using `WithEncoderDictRaw` and `WithDecoderDictRaw` for deltas and frame checksums on. If measured vault bytes per entry are more than 10% worse than the spec's C-zstd figures, the report says so, and Plan 3 decides on any switch.

---

## 6. Source-layer Parquet (amends D19 and spec §6.4)

**Revised rule D19:** binary columns are allowed **only in files written with `WRITE_BLOOM_FILTER false`**. A column that needs bloom-pruned lookups uses lowercase hex `VARCHAR`, because of the DuckDB `BLOB` bloom-filter bug in spec §3.6. That applies to `certs.sha256` in Plan 3.

**`entries`:**

| Column | Type |
|---|---|
| `idx` | `UBIGINT` |
| `ct_ts` | `TIMESTAMP_MS` |
| `entry_type` | `VARCHAR` (`x509`, `precert`, `unknown`; dictionary-encoded) |
| `cert_id` | `UBIGINT` |
| `leaf_hash` | `BLOB`, 32 bytes |
| `issuance_key` | `BLOB`, 16 bytes |
| `issuer_key_hash` | `BLOB`, 32 bytes, null except for precerts |
| `chain_id` | `BLOB`, 32 bytes |
| `leaf_error` | `VARCHAR` |

**`chains`:** `chain_id BLOB(32)`, `position USMALLINT`, `cert_id UBIGINT`.

**Writer:** embedded DuckDB `COPY … (FORMAT parquet, COMPRESSION zstd, WRITE_BLOOM_FILTER false)`. Measured on 32,768 real entries with the hash columns exactly as specified (that test file used a numeric `entry_type`, a synthetic `cert_id` and no `leaf_error` column, so Plan 2 re-measures the final layout):
- binary hashes: **54.8 B per entry**, against 59.5 B for hex
- low-cardinality hashes still get dictionary encoding (`issuer_key_hash` 0.66 B, `chain_id` 0.81 B)
- a literal `issuer_key_hash` lookup returns the correct 7,096 of 7,096 rows, where the bloom-filtered file returned 0

**Canary:** the schema equals the expected types, **no bloom filter exists on any `BLOB` column**, and row counts and sample lookups are correct. The DuckDB regression test still reproduces the bug with a bloom-filtered `BLOB` column and asserts the writer never produces one.

---

## 7. Commit, recovery and guard refinements (amends spec §8 and §10.1)

- **`ID_FLOOR`:** blocks of 65,536. The **next block is reserved durably before the current one is exhausted**: the advance happens when fewer than 32,768 reserved IDs remain. A 500k batch spans several blocks.
- **Canary placement:** the canary still runs against the staged files **before** the atomic batch-folder rename. Pebble stays private to the writer and may lag behind the dataset commit.
- **`views.sql`** (minimal in Plan 2: `entries`, `chains`, `batches`) is regenerated in memory and rewritten atomically **only when its contents change**.
- **Peak estimate:** the batch peak includes the DuckDB temporary and spill limit (`max_temp_directory_size`), even though Plan 2's tables normally fit in memory.
- **Scoped cleanup:** recovery and cleanup delete only `tmp/stage/*` and `tmp/rebuild/*`, never all of `tmp/`.
- **`merkle.State`:** decoding refuses a missing or zero-valued `merkle_after` instead of crashing.
- **Recovery equivalence is semantic.** After a crash, `cert_id` values are never reused, so a recovered ingest may have gaps and different internal IDs. The recovered dataset must match a clean ingest on log indexes, leaf hashes, certificate content by SHA-256, issuance keys, chain contents, error codes and timestamps. `cert_id` and `chain_id` may differ, provided every reference stays internally consistent.

---

## 8. Measurement reports

- They are written by the real-data integration tests and by `ctvault-dev sample measure`, to `<home>/.cache/ctvault-dev/reports/<sample-id>/<timestamp>.json`, plus a short Markdown summary.
- **Each report records:**
  - **provenance:**
    - the CTVault version, from Go build info including the module version and VCS revision when present
    - the Go version and the dependency versions (DuckDB, Pebble, `klauspost/compress`, transparency-dev/merkle)
    - the sample ID, kind, range, capture time and log, and the report time
  - **observed values:**
    - vault, Parquet and Pebble bytes per entry
    - the compression ratio, overall and per dictionary
    - the gap against the spec's C-zstd figures
    - the delta hit rate, the precert→final link rate, and the p50/p95/p99 delay between a precert and its final certificate
    - the dedup hit rate, and leaf and semantic error counts
- **Reports never change anything.** They do not rewrite `ctvault.toml`, compiled defaults or disk-guard seeds. Updating a seed or the delta warm-up default needs an explicit, reviewed code or config change, and safety estimates stay conservative.

---

## 9. Test matrix

| Layer | Command | Data | Network |
|---|---|---|---|
| Unit tests, fake-log fault injection, crash boundaries, production guard tests | `go test -race ./...` | fixtures and the fake log | none |
| Dev-build behaviour | `go test -race -tags ctvault_dev ./...` | dev probe in temp folders | none |
| Real-data end to end, recovery equivalence, measurements | `go test -race -tags realdata ./internal/integration/` | the cached canonical sample over loopback (plus a representative sample for measurements, if present) | none |
| Long crash loop | `go test -tags nightly ./internal/commit/` | the fake log, 200+ kills | none |
| Live capture and ingest | `ctvault-dev sample capture …`, `ctvault-dev update --until …` | Google, live | opt-in |

The fake CT log is used **only** for deterministic fault injection and edge cases: 429s, 5xx, malformed leaves, truncated responses, invalid base64, latency and out-of-order completion, forks, and bad signatures. Real-data tests skip with a clear message when the sample has not been captured.

---

## 10. Pending physical verification (does not block Plan 2)

These stay pending until the external SSD is available, and are listed in the README:
1. The Plan 1 real-SSD smoke test (`init`, `logs add`, `logs info` on the drive).
2. Filesystem UUID resolution on the real drive and enclosure (USB/UAS, and LUKS if used).
3. Unplugging the drive mid-batch.
4. The mount disappearing, or the drive being remounted at a different path.
5. Real disk-cap behaviour on the 4 TB drive (statfs, ext4 reserved blocks, projections).
6. Enclosure throughput and fsync latency.
7. The `dm-log-writes` power-loss gate on ext4 (Plan 6).

---

## 11. Plan 1 review minors folded into Plan 2

| Minor | Resolution in Plan 2 |
|---|---|
| 6 | `Check` always runs the root checks, and `VAULT_ID` must list exactly one root |
| 7 | Every layout folder must be on the root's filesystem; symlinks off the volume are refused |
| 9 | `Guard` refuses a cap that is not finite or lies outside (0, 0.95] |
| 10 | `EstimatePeak` saturates instead of overflowing |
| 11 | The config refuses non-finite or absurd values and uses an overflow-checked size multiply |
| 12 | Server error bodies are printed quoted with `%q` |
| 14 (`tmp/` scope only) | Cleanup is limited to `tmp/stage` and `tmp/rebuild` |
| 15 | The fake log gains 5xx, latency and out-of-order, and invalid-leaf modes; `Fork` validates its index; the precert and final-cert TBS invariant gets a test |
| 16 | A zero-valued `merkle_after` is refused when decoding |

Still deferred: 8 (st_dev confirmation for shadowed mounts), 13 (telling a corrupt `VAULT_ID` from a missing one), 14 (`add-dir` with `lost+found`, and retry after a crash) and 17 (the fixture guard ignoring new files).

---

## 12. Plan 2 task split

Sixteen TDD tasks, each ending green:
1. **Dev build:** `devBuild`, `DevProbe`, the `VAULT_ID` mode, the refusals both ways, the guard tests, and minors 6 and 7.
2. **Config and guard hardening** (minors 9–11), and the per-target guard wiring, including DuckDB spill.
3. **Leaf decoding:** error codes, chain-relationship issuer identification, precert cross-checks, the issuance key.
4. **RFC 6962 `GetEntries`:** the `LogSource` adapter, head checks and incidents, `get-proof-by-hash`, quoted error bodies (minor 12).
5. **Fake log fault modes** (minor 15).
6. **Fetcher:** request planning, the adaptive rate, retries, the reorder buffer bounded by entries and bytes, statistics, the two signal contexts.
7. **Vault segments and records:** writer, `ReadVerified`, multiple folders, scan and truncate.
8. **Dictionaries and `leaf-delta`:** the manifest and fallback; the full-digest delta match with configurable warm-up.
9. **Pebble dedup and `ID_FLOOR`** with early reservation.
10. **DuckDB staging:** binary hashes with no bloom filters, the canary, `views.sql` written only on change.
11. **The commit protocol:** `_COMMIT.json`, recovery, the scoped `tmp/` cleanup, minor 16.
12. **`update`:** `--follow`, `--until`, signals, exit codes and incidents.
13. **Crash and fault-injection suite:** the named boundaries, plus the kill loop (25 iterations by default, 200+ with `nightly`).
14. **Dev-only commands:** `sample capture`, `sample verify` and `sample measure` (canonical and representative), `--replay`, and `sampletest`.
15. **Real-data integration tests:** end to end, semantic recovery equivalence, DuckDB queries and measurement reports.
16. **Docs:** the dev workflow, sample handling and pending physical verification.

Versions pinned in the plan:
- `klauspost/compress` v1.20.1 (verified)
- `duckdb-go/v2` and Pebble, at the latest releases compatible with Go 1.26.8, checked against their current APIs when the plan is written
