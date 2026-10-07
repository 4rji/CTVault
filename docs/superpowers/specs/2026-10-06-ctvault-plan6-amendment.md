# CTVault Spec Amendment A5: Plan 6 (`verify`, `repair`, version transitions, the power-loss gate)

- **Date:** 2026-10-06
- **Status:**
  - Part 6A approved 2026-10-06, section by section and then as written ("ok"); built in the tree the same day (summary: `docs/superpowers/plans/2026-10-06-ctvault-plan-6a-verify-repair-summary.md`).
  - Part 6B (§7–§12) approved 2026-10-06 section by section and then as written ("ok"); built in the tree the same day (summary: `docs/superpowers/plans/2026-10-06-ctvault-plan-6b-transitions-summary.md`).
  - Part 6C (§13–§17) approved 2026-10-06 section by section and then as written ("sigue"); built in the tree, and the user's full privileged run passed the same day (summary: `docs/superpowers/plans/2026-10-06-ctvault-plan-6c-powerloss-summary.md`).
- **Amends:** `docs/superpowers/specs/2026-10-04-ctvault-design.md` §7.5, §7.6, §7.8, §8.5, §8.7, §10.1, §11, §13 and §14 ("the spec"), and amendments A1–A4.
- **Origin:** Plan 6 design discussion.
  - Plan 6 is phase 6 of spec §16, chosen before tiled logs (choice A).
  - It is split into three parts, each designed, built and summarized in turn: 6A → 6B → 6C.
- **Scope of this text:** Part 6A, `verify` and `repair` (§0–§6); Part 6B, version transitions (§7–§12); Part 6C, the power-loss gate (§13–§17).

Everything not changed here stays as in the spec and A1–A4. **Production safety requirements are unchanged.**

---

## 0. Plan 6 at a glance

| Part | What | Depends on |
|---|---|---|
| **6A: `verify` and `repair`** (this text) | `verify --quick` and `--full` (spec §8.7), which no earlier plan built. `repair` hardening: a `repair --reindex` that fits in memory at full scale, and the new `repair --derived`. | nothing |
| **6B: version transitions** | Side-by-side rebuild while ingestion builds both versions; catch-up through `state/rebuild.json`; the `ACTIVE.json` switch; `explore`'s "dataset version changed" banner; `gc` and the 24-hour cleanup; `--in-place` and `mixed`; `stats` warnings; queries that refuse mixed versions. | 6A: `verify` checks the vault after each transition |
| **6C: the power-loss gate** | `dm-log-writes` on a loopback ext4 device, replaying every flush point and checking spec §13.5's invariants. It needs root, so the user runs its privileged part. | 6A: `verify --full` is the invariant checker |

### Measurements behind the design (2026-10-06)

| What | Measured | Projected to `argon2027h1` today (383M entries) |
|---|---|---|
| Decoding and hashing every vault record, one core (the 1M-entry smoke vault) | 107,000 records/s (1,000,689 records in 9.4 s) | about 1 hour; about 15 minutes over 5 cores |
| Committed Parquet files | 167 MB per million entries | about 64 GB; about 500 GB when the log closes |
| `repair --reindex`'s check (a Go map of every certificate) | about 90 B per certificate | about 35 GB: it cannot run on the 7 GB host |
| Pebble's directory lock | taken even by a read-only open (Pebble v2.1.7 `Open`) | the index cannot be checked while `update` runs |

## 1. The command and its promises (refines spec §8.7)

| | |
|---|---|
| **Command** | `ctvault verify [--full] [--as-of N] [--json]`. Plain `verify` means `--quick`; `--quick` is also accepted. |
| **Reads** | A pinned snapshot, as `search` does (A3 §2): committed batches only, as of `--as-of` when given. It writes nothing but its own `tmp/duckdb-<pid>/` spill, and it never repairs. |
| **Lock** | None: `verify` never stops or waits for ingestion (choice A). The index check is the exception. It runs last, only when the writer lock is free, and holds the lock during that phase alone. When the lock is held, the report says `index: skipped — update (PID n) holds it`. An `update` started during the index phase exits 1 naming `verify`'s PID, as with any held lock. |
| **Report** | One line per check: `ok`, `FAIL` or `skipped`, with a short reason, then a summary. `--full` writes progress to stderr. `--json` writes the same report as JSON. |
| **Exit codes** | 0: nothing failed (skips are listed). 5: damage found. 1: `verify` could not run (an I/O error, no vault). 4: the existing volume-identity checks (spec §9.2). |
| **Not damage** | What a writer stopped mid-batch leaves: an intent, vault bytes past the committed tail, leftovers in `tmp/`. It is reported as `recovery pending: the next update or rebuild finishes it`, with exit 0. Post-commit audit failures in `state/health.json` are warnings: each batch stays committed (spec §8.3 P11). |
| **Every finding** | `verify` reads each batch's `_COMMIT.json` itself and reports every problem. Readers stop at the first one, because `ListCommitted` returns on the first error. |

**Which mode hashes files.** Spec §8.7 lists "`_COMMIT.json` checksums" under `--quick`. Hashing every committed file reads about 64 GB today, which takes minutes to tens of minutes. So:
- `--quick` (seconds) checks each listed file's presence and size against `_COMMIT.json` and `_DERIVED.json`, plus every manifest-level check;
- `--full` hashes every file.

## 2. The checks (refines spec §8.7)

### 2.1 `--quick`: manifests and metadata, no file contents

| Check | Fails when |
|---|---|
| **Batches** | A `_COMMIT.json` is missing, unreadable or malformed. A log's batches leave a gap or overlap from index 0. `commit_seq` is not 1..N, each exactly once. `merkle_after.size ≠ last + 1`. |
| **IDs** | `cert_id` ranges overlap, or do not increase with `commit_seq`. A `next_cert_id` lies inside a later batch's range. `state/ID_FLOOR` is below the highest `next_cert_id`. |
| **Vault** | Batch spans are not contiguous in `commit_seq` order. A segment is missing, or has a wrong header or vault UUID. The committed tail lies past a segment's end. A dictionary differs from its manifest, or a batch's dictionary is absent. |
| **Files** | A file listed in `_COMMIT.json` or `_DERIVED.json` is missing or has another size. A `_DERIVED.json` fails its own checksum. |
| **Tables** | `ACTIVE.json` is not valid for this binary. A complete table lacks its file in some batch. `views.sql` differs from what `ACTIVE.json` generates. |
| **STH signatures** | A recorded STH does not verify with the log's pinned key. |
| **Recovery pending** (not a failure) | An intent; vault bytes past the committed tail; leftovers in `tmp/stage`, `tmp/rebuild` or `state/pebble.reindex`; derived files that no manifest lists. |
| **Health** (a warning) | `state/health.json` records post-commit audit failures. |

### 2.2 `--full`: every byte, batch by batch in `commit_seq` order

| Check | Fails when |
|---|---|
| **File checksums** | A listed file's SHA-256 differs from its manifest. |
| **Records** | Every record in each batch's vault span is parsed, decoded (zstd) and hashed. A record fails to decode. A delta's base is ahead of it, or is not a leaf record. A record's SHA-256, location, kind or delta base differs from its `certs` row. A `certs` row has no record, or a record has no row. `cert_id`s do not strictly increase across the whole vault: this gives global uniqueness without a global set. |
| **References** | An entry's or a chain's `cert_id` names no certificate. |
| **Merkle** | Per log, the compact range rebuilt from `entries.leaf_hash` in `idx` order differs from any batch's `merkle_after`, or `idx` has a gap or a repeat. |
| **STHs re-verified** | §2.3. |
| **Index** (only when the writer lock is free) | §3.1's check, on the live index. A record lacks its key, or its key gives another `cert_id` or location. A certificate key has no record, including keys past the committed tail. A chain lacks its key. `applied/<log>` is ahead of the log's last `commit_seq`. When it is behind, that is recovery pending, not a failure. |

**Throughput:** one scanner per batch feeds one decoding worker per core.

**A batch whose table is still being built** has no `certs` file to compare with. Its records are still decoded and hashed, and their SHA-256 is checked through the index when the index check runs.

### 2.3 Re-verifying STHs offline

- **Up to the committed size:** while rebuilding each log's Merkle tree, `verify` computes the root at every recorded STH's `tree_size` and compares it with the STH's root. A completed update cycle ends exactly at its STH, so this covers every STH except those of a cycle that stopped early.
- **Beyond the committed size:** such an STH was proved at ingest by a consistency proof from the batch's end to its `tree_size`. Until now `_COMMIT.json` recorded only the proof's length (`verified.proof_nodes`).
  - **New:** ingest records the proof itself as `verified.proof`, a list of hex nodes (about 1.4 KB per batch). `verify` re-checks it offline with `merkle.VerifyConsistency`.
  - The field is optional; `_COMMIT.json` stays at format 1. Readers already ignore unknown fields: nothing in the code rejects them.
  - An older batch without the field is reported as `skipped: proved at ingest, proof not recorded`.

## 3. `repair` hardening (refines spec §8.5, §8.7 and A2 §5.6)

Every `repair` runs under the writer lock. It never deletes committed data and never rewrites a `_COMMIT.json`.

### 3.1 `repair --reindex` at full scale

A2 §5.6's check held a Go map of every certificate: about 35 GB at today's size. The check becomes a stream:
- **Certificates:** each vault record's key is looked up as the record is scanned; it must give that record's own `cert_id` and location. A certificate vaulted twice fails here, because its second record finds the first one's reference. Then the number of certificate keys must equal the number of records. With every record's key pointing at that record, equal counts leave no room for an extra key.
- **Chains:** every chain in `chains.parquet` must have its key, and the number of chain keys must equal the number of distinct chain IDs, which DuckDB counts with spill.
- **Applied positions:** `applied/<log>` is each log's last `commit_seq`, as before.
- **Memory** no longer grows with the vault. `verify --full`'s index check is this function, run on the live index.
- **Progress:** batches done out of the total, and records per second, on stderr.

### 3.2 `repair --derived [--batch ID]` (new)

- **Fixes:** a `certs` or `names` file that is missing or fails the checksum its manifest records.
- **How:** the file is rebuilt from the vault through `rebuild`'s path, which 3B-2 proved byte-identical on the fake log and on real data, and hashed.
  - **Equal to the recorded checksum:** it replaces the bad file by an atomic rename, and the batch is whole again.
  - **Not equal:** nothing is replaced, and `repair` exits 5 naming both checksums: the vault or the builder is not what wrote the file.
- **Which batches:** `--batch` names one. Without it, every batch: `repair` hashes each derived file itself, so it does not depend on an earlier `verify`.
- **Limit:** this binary rebuilds only its own table versions. A damaged file of an older version waits for 6B's version registry.

### 3.3 Source damage is reported, not repaired

Damage to vault records, `entries.parquet`, `chains.parquet` or a `_COMMIT.json` makes `repair` exit 5. The message names what is damaged and where, and says that restoring it needs a backup copy of that batch.

Rebuilding source data from the log (`--refetch`) would download the range again and re-assign the same IDs. It is future work (§6).

### 3.4 `repair` with no flag

It stays a usage error (exit 2). The message lists `--reindex` and `--derived` and suggests running `verify` first.

## 4. Tests and evidence (adds to spec §13)

1. **One fault at a time.** The writer-built test vault (`querytest`) passes `--quick` and `--full` with exit 0. Each fault, injected into a fresh copy, gives exit 5 with the failing check naming the batch, file or record:

   | Area | Faults |
   |---|---|
   | Batches | `_COMMIT.json` deleted or malformed; a batch directory removed (a gap); a duplicate `commit_seq`; a wrong `merkle_after.size` |
   | IDs and vault | overlapping `cert_id` ranges; `ID_FLOOR` lowered; a segment header byte flipped; a segment cut short; a dictionary byte flipped |
   | Files and tables | a file resized; a `_DERIVED.json` checksum broken; an invalid `ACTIVE.json`; an edited `views.sql` |
   | STH | a signature byte flipped; a recorded proof node altered; an older batch without a proof is skipped, not failed |
   | Content (`--full`) | a byte flipped in a Parquet file; a damaged record frame; a delta pointing forward |
   | Consistent but wrong | a `certs` row pointing at another record; an altered `leaf_hash`; a gap in `idx`; a dangling `cert_id`. Each file is rewritten and its checksum updated in `_COMMIT.json`, so the content checks are shown not to rely on checksums. |
   | Index | a missing key; an extra key; a key pointing at the wrong record; `applied` ahead. `applied` behind gives "recovery pending". A held lock skips the check and names the PID. |
   | Not damage | an intent, vault bytes past the tail, leftovers in `tmp/stage`: exit 0 with "recovery pending". An audit failure in `health.json`: a warning. |

   **Mutation checks:** removing each check makes its fault test fail.
2. **Behaviour:**
   - **Read-only:** a whole `verify --full` changes no file in the vault outside its own spill folder (a tree diff).
   - **`--quick` reads no Parquet content:** with a data file made unreadable, `--quick` passes and `--full` fails.
   - **Alongside ingestion:** `verify --full` runs while `update` commits batches from the fake log. It checks its pinned snapshot, passes, and skips the index check, naming the PID.
   - **Proofs:** new batches record `verified.proof`; a manifest with an unknown field still reads.
3. **`repair`:**
   - **`--derived`:** a damaged or deleted `certs` or `names` file comes back byte-identical, and `verify --full` then passes. A recorded checksum that cannot be reproduced gives exit 5 with nothing changed (a tree diff). A run killed after staging, or after the rename, leaves the batch consistent, and a rerun completes.
   - **`--reindex`:** A2 §5.7's tests still pass. The heap stays flat between reindexing N and 4N certificates, the pattern of `TestDerivedStageHoldsNoRows`.
   - **Source damage:** exit 5 naming the file and the batch; nothing changes.
4. **Real data and scale:**
   - the canonical sample (100,000 entries): `--quick` and `--full` exit 0, with timings;
   - the 1M-entry smoke vault (dev build): `--quick` and `--full` timings, records per second at 1 worker and at 5, and a projection to 383M entries;
   - `repair --reindex` on a copy under `/mnt/disk`: peak memory before and after the streaming change.
5. **The gate:** gofmt; `go vet` with 4 tag sets; race tests in production and dev builds.

## 5. Decisions this amendment adds (6A)

| # | Decision |
|---|---|
| 1 | Plan 6 is split into 6A → 6B → 6C, each designed, built and summarized in turn. (§0) |
| 2 | `verify` takes no lock and never stops ingestion. The index check runs only when the writer lock is free and is otherwise reported as skipped, naming the PID. (§1) |
| 3 | `--quick` checks file presence and size; `--full` hashes files. (§1) |
| 4 | Recovery-pending states and audit failures are not damage: exit 0, reported. (§1) |
| 5 | `verify` reports every finding, reading each `_COMMIT.json` itself. (§1) |
| 6 | `cert_id` uniqueness from strictly increasing IDs in vault order, without a global set. (§2.2) |
| 7 | The references check (entries and chains to certificates), beyond spec §8.7's list. (§2.2) |
| 8 | Ingest records consistency proofs as `verified.proof`; `verify` re-checks STHs offline, and older batches without a proof are skipped. (§2.3) |
| 9 | `repair --reindex` checks by lookups and counts, with memory that does not grow with the vault; `verify`'s index check is the same function. (§3.1) |
| 10 | `repair --derived` replaces a file only with one that reproduces its recorded checksum. (§3.2) |
| 11 | Source damage is reported, not repaired, in v1; `--refetch` is future work. (§3.3) |

## 6. Future work (adds to spec §14)

| Item | Seam already in place |
|---|---|
| `repair --refetch`: rebuild a damaged batch's source data from the log | The batch's range and `cert_id` assignments in `_COMMIT.json`; the deterministic stager |
| Incremental `verify --full` (only batches since the last clean run) | Each batch's `merkle_after` is a resumable Merkle state |

---

# Part 6B: version transitions (refines spec §7.5, §7.6, §7.8, A2 §4.6-4.7)

Origin: the Plan 6B design discussion. A transition runs inside `update`, in turns, with one writer and no background threads (choice A).

## 7. Table states and the version registry

**What a binary carries.** Each table has its current version N, and may keep the builder for N−1 for one release, so ingestion can build both during an upgrade (spec §7.5).
- Today it is `certs` v1 and `names` v1, with no N−1. There is no v2 yet: 6B builds the machinery and tests it with a **test-only v2**. The production registry does not change, and no upgrade happens until a real extractor change.
- A binary refuses an `ACTIVE.json` naming a version it does not carry. One older than N−1 needs the intermediate release; one newer needs a newer binary.

**The states of a table in `ACTIVE.json`:**

| State | `active` | `building` | `status` | What readers see |
|---|---|---|---|---|
| Complete | N | null | `complete` | the table at N |
| Upgrading | N−1 | N | `building` | the table at N−1, which every batch has; N only as `<table>_building` |
| New table | null | N | `building` | only `<table>_building` |
| Mixed (§10) | N−1 | N | `mixed` | refused, unless `--parser-version` or `--allow-mixed` is given |

While the old version is being retired (§9), a complete table also records `retiring` (the old version) and `switched_at`.

**Readers:**
- **A table is readable when it has an active version and is not `mixed`.** Until now readers accepted only `status: complete`, which would have made `search`, `fetch` and `explore` refuse to run for a whole upgrade.
- **Readers take each table's file name from `ACTIVE.json`.** Until now `query`, `fetch`, the post-commit audit and `verify` named `certs.p1.parquet` and `names.p1.parquet` directly.
- **A new version keeps the columns the queries use.** It may add columns; renaming or dropping one changes the query code in the same release.
- **`--as-of` uses today's `ACTIVE.json`.** Every batch has the active version's file, so an older snapshot's rows stay coherent. Exports already record the versions they used.

## 8. The upgrade inside `update`

**When it starts.** The first time a writer (`update` or `rebuild`) opens the vault with a binary whose version N is newer than the active N−1, it starts the upgrade, under the lock and after recovery: `ACTIVE.json` gets `building: N` (`seq + 1`). Readers keep using N−1.
- **The disk guard comes first.** A full copy of the table must fit under the cap: about 80 B per entry for `certs` and 35 B for `names` (spec §10.1).
- **If it does not fit,** the vault stays at N−1 and `update` warns: "`certs` v2 needs X GB more; free space or run `rebuild --in-place`". Ingestion never stops.

**New batches** build both N−1 and N, and `_COMMIT.json` lists both files: ingest already builds every version that is active or being built.

**Old batches in turns,** oldest first, through A2 §5.2's rebuild path (byte-identical and crash-safe):
- after each committed batch, `update` rebuilds up to `rebuild.batches_per_turn` old batches (config; default 1);
- under `--follow`, while waiting for the next cycle, it keeps rebuilding until the cycle is due or nothing is left;
- `rebuild` on its own still does everything at once while `update` is stopped.

**Expected pace.** At the log's live rate (about 140 entries/s, so about an hour per 500k batch) `update` is mostly idle, and the waits absorb the work. Rebuilding runs at about 10,000 entries/s (3B-2), about 50 s per full batch: about 11 hours of idle time for `argon2027h1`'s 766 batches today.

**The switch.** When every committed batch lists N and every N file matches its checksum (A2 §5.4's check), `ACTIVE.json` becomes `{active: N, complete}` (`seq + 1`) with `retiring: N−1` and `switched_at`, and `views.sql` is regenerated. This happens inside `update`, right after the last old batch; retirement follows (§9).

**Progress:** `stats` shows each upgrade, for example "`certs` v2: 312 of 766 batches rebuilt, about 4 h left".

**Details:**
- **No `state/rebuild.json`.** The spec uses it to track batches that fall behind. Here, which batches list N in their manifests is already a crash-safe record of the progress; a second file could only disagree with it.
- **A soft stop finishes the old batch being rebuilt,** as it finishes a batch being ingested (up to about 50 s at full size). A second interrupt abandons it, and recovery deletes what was staged.

## 9. Retiring the old version

**The record.** `_COMMIT.json` is never rewritten, and readers check every listed file's size. So a file is retired through its batch's `_DERIVED.json`, which gains a `retired` list:
1. write `_DERIVED.json` with `retired: ["certs.p1.parquet", …]`, atomically: the commit point;
2. delete the file and fsync the folder.

A retired file is not part of its batch, for readers, `verify` and the size checks alike. If a crash lands between the two steps, recovery deletes the retired file, as it deletes unlisted ones. `_DERIVED.json` stays at format 1; a binary from before 6B would call it damaged, but it already refuses the vault for its unknown table version.

**When:**
- **`ctvault gc`** (new; under the writer lock) retires every version that is neither active nor being built, right away, and reports what it freed (spec §7.8: "deleted by `ctvault gc`").
- **`update` and `rebuild`** retire them on their own once 24 hours have passed since `switched_at`. They check at writer start and at each `--follow` cycle, so an `update --follow` left running for weeks does not keep the old files.
- When no batch holds the retiring version any more, `retiring` and `switched_at` are removed (`seq + 1`).

**`explore`'s banner.** `explore` reads `ACTIVE.json`'s `seq` every 10 seconds: one small read, which writes nothing.
- When `seq` changes, the status line says "the dataset changed (`certs` v2 is active): press R to reload", and `R` re-pins as it does today.
- Rows already held for the shown list stay valid. Only lookups in retired files, such as opening a certificate's detail, fail until `R`.
- New commits do not change `seq`, so they never trigger the banner.

## 10. `--in-place` and `mixed`

**When:** only on request, with `ctvault rebuild --in-place`, when the disk cannot hold a side-by-side copy. `update` never chooses it by itself.

**Each batch switches over** in commit order:
1. build the batch's N file, unlisted (recovery would delete it after a crash);
2. write `_DERIVED.json` once, listing N and retiring N−1: the batch's commit point;
3. delete the N−1 file.

No batch is ever left with neither version, and the extra disk needed is one batch's files at a time.

**While it runs:**
- `ACTIVE.json` reads `{active: N−1, building: N, status: "mixed"}`.
- New batches build only N: disk is short.
- `update` keeps advancing the conversion in turns, as in §8.
- Once every batch has N, the table becomes `{active: N, complete}`, with nothing left to retire.

**Readers while `mixed`:**
- **They refuse by default,** for example: "`certs` is mixed (v1 in 300 batches, v2 in 466): pass `--parser-version 2` or `--allow-mixed`".
- **`--parser-version N`** reads only the batches that have version N. The result is partial: the output warns ("466 of 766 batches"), and exports record `partial` with the batch counts.
- **`--allow-mixed`** reads each batch's own version. Exports record `mixed` with the counts per version.
- `search` (and its exports), `fetch` and `explore` accept both flags.
- **`views.sql` has no `<table>` view.** It offers `<table>_building` (the batches at N) and `<table>_previous` (those at N−1), so an outside DuckDB session cannot mix versions without noticing.
- **`stats` warns prominently:** "`certs` is mixed since …: queries need a flag; `rebuild --in-place` finishes it".

## 11. Tests and evidence (adds to spec §13.8)

1. **A test-only `certs` v2** that adds one column.
2. **Side by side, v1 → v2 with `update` alone:** the upgrade starts; new batches build both versions; old batches are rebuilt one per turn; the switch happens inside `update`; `search` returns the same rows before, during and after.
3. **The disk guard:** when a side-by-side copy does not fit, the vault stays at v1 with a warning, and `rebuild --in-place` takes over.
4. **Crashes** (subprocess kills): `update` during a rebuild turn (staged, placed); before and after the switch; between a retirement's `_DERIVED.json` and its delete; during an in-place batch. Each recovers, and the upgrade resumes to the same files as an uninterrupted run.
5. **`gc` and the 24-hour rule:** files retired, readers fine, `verify --full` clean; the 24-hour rule with a fake clock, at writer start and at a `--follow` cycle.
6. **Mixed:** reads refused without a flag; `--parser-version` partial and flagged; `--allow-mixed` reads both; `stats` warns; `views.sql` has no `certs`; finishing makes the table complete.
7. **A new table** (test-only) backfilled while being built.
8. **`explore`:** the banner appears when `seq` changes, and `R` reloads.
9. **`verify` in every state** (complete, upgrading, mixed, retired) reports no false damage; 6A's checks learn about versions and retired files.
10. **Real data:** the canonical sample upgraded to the test v2, side by side through `update` and then in place, with timings and disk use.
11. **The gate**, then a summary as for 6A.

## 12. Decisions this amendment adds (6B)

| # | Decision |
|---|---|
| 12 | A transition runs inside `update`, in turns, with one writer and no background threads (choice A). (§8) |
| 13 | A table stays readable at N−1 while it upgrades: readable means an active version and not `mixed`. (§7) |
| 14 | Readers take table file names from `ACTIVE.json`; a new version keeps the queried columns and may add others. (§7) |
| 15 | The upgrade starts by itself when a newer binary first runs as a writer, only if the side-by-side copy fits the disk guard. (§8) |
| 16 | Old batches are rebuilt one per committed batch by default (`rebuild.batches_per_turn`), plus all idle time under `--follow`. (§8) |
| 17 | No `state/rebuild.json`: the manifests record the progress. (§8) |
| 18 | A soft stop finishes the old batch being rebuilt. (§8) |
| 19 | Retirement is recorded in `_DERIVED.json`'s `retired` list, written before the delete; `_COMMIT.json` is never rewritten. (§9) |
| 20 | `gc` retires right away; writers retire after 24 hours, checked at start and at each `--follow` cycle. (§9) |
| 21 | `explore` checks `ACTIVE.json`'s `seq` every 10 seconds and shows a reload banner. (§9) |
| 22 | While `mixed`, new batches build only N, and `views.sql` exposes `<table>_building` and `<table>_previous`, never `<table>`. (§10) |
| 23 | `--parser-version` gives a partial result and `--allow-mixed` a mixed one; both are flagged in output and exports. (§10) |

---

# Part 6C: the power-loss gate (refines spec §13.6)

Origin: the Plan 6C design discussion. The privileged part runs as one command the user starts with sudo (choice A).

## 13. How it runs, and its safety bounds

**What it proves** (spec §13.6, a release gate): after a power loss at any point where the disk confirmed a flush, recovery brings the vault back to a state that satisfies the crash suite's invariants (spec §13.5). It goes beyond the SIGKILL suites: writes the kernel had not flushed are lost too.

**How it runs:**
1. A test binary is built as the user, with the build tag `powerloss`: nothing is compiled as root.
2. The user runs it, for example in the Claude session with `! sudo /mnt/disk/ctvault/powerloss/powerloss.test -test.run TestPowerLoss -test.v`.
3. It writes `report.json` and its logs to `/mnt/disk/ctvault/powerloss/` and hands the files back to the user.

**Safety bounds:**
- **Devices:** only loop devices backed by files the run creates under `/mnt/disk/ctvault/powerloss/`. Before any format or mount, each device `losetup` returns is checked: a `/dev/loopN` backed by the run's own file.
- **Device-mapper:** one target, `ctvault-powerloss-<pid>`, and no other.
- **Cleanup:** unmount, target removal and loop detach on exit, failure or interrupt. A leftover from an earlier run is reported, not deleted.
- **Size:** a 64 MiB filesystem image and a log of up to 2 GiB.
- **Network:** none; the CT log is the in-process fake.

**The replayer is written in Go** (xfstests' `replay-log` is not installed). The run proves it with a self-check (§15).

## 14. The workload it records

The binary formats the loop device as ext4 with default options (`data=ordered`), mounts it through the log-writes target, and runs four phases against a fresh vault. Before each phase it writes a mark into the log, so every crash point in the report is attributed to its phase.

| Phase | What it writes | Primitives it exercises |
|---|---|---|
| 1. Ingest | About 480 entries in batches of 40 from the in-process fake log, with 16 KiB segments and a small dictionary sample, so it trains and installs a dictionary and rolls over segments. Each batch runs the full commit protocol: intent, vault appends and fsync, staging, canary, `_COMMIT.json`, the rename, Pebble, the intent's deletion, `ID_FLOOR`, the post-commit audit. | fsync of files and folders, atomic renames, appends, Pebble's WAL |
| 2. Upgrade | With the test `certs` v2 (A5 §11), a writer starts the upgrade; two new batches build both versions; turns rebuild every old batch until the switch. | rebuild placement, `_DERIVED.json`, the `ACTIVE.json` switch, `views.sql` |
| 3. `gc` | Retires `certs` v1 in every batch. | record-then-delete (§9) |
| 4. `repair --reindex` | Builds a new index beside the old one and exchanges them. | `renameat2(RENAME_EXCHANGE)` and the folder fsync after it |

- **The workload drives the writer in-process.** The command's volume checks need udev's by-uuid link for the filesystem, which a loop device may not get; the commit protocol and recovery are the same code.
- **In-place conversion and `repair --derived` are not recorded.** Their writes use the same primitives (a rename into place, one `_DERIVED.json` write, a delete), which the SIGKILL suites cover.
- **Small sizes on purpose:** a few hundred flush points in about 1 MiB of writes keep the replay short.

## 15. Replay and checks

**The replay:**
1. Right after `mkfs`, before the log-writes target is created, the device is copied as the starting image.
2. After the workload, the log's entries are replayed onto a working copy, in order: writes; discards zero their range; marks name the phase.
3. At each flush or FUA entry, the working copy is one possible state after a power loss. It is copied to a check image, which is mounted read-write (ext4 replays its own journal, as a reboot would), checked, unmounted and detached. The working copy itself is never mounted.
4. **Self-check:** after the last entry, the working copy must equal the final device byte for byte. Otherwise the run fails: the replayer misread the format.

Reordering unflushed writes among themselves is not explored (as in xfstests' check at each flush); that is stronger testing, at a cost that grows combinatorially.

**At every point:**
1. **Recovery succeeds:** the writer opens with recovery, then closes.
2. **`verify --full` finds nothing:** no damage, nothing left pending after recovery, and the index matches the vault.
3. **Nothing goes backwards across points** (an external record of commit times does not exist, so consistency across points stands in for one):
   - every batch committed at an earlier point is still committed, with an identical `_COMMIT.json`;
   - each `cert_id` maps to the same SHA-256 at every point;
   - `ACTIVE.json`'s `seq` never decreases.
4. **The last point equals the uninterrupted run:** the same committed batches.

Every point is checked by default; a flag checks every Nth for a quick run.

**The report:** `report.json` holds the kernel, the mount options, the log's entry count, the flush and FUA points per phase, the time taken, and each failure with its point, phase and reason; one log line per point goes beside it.

## 16. Tests and evidence (adds to spec §13.6)

1. **Without root**, before the user runs anything:
   - **the replayer:** synthetic logs with writes, flushes, FUA, discards and marks; damaged logs (wrong magic or version, cut short) are refused;
   - **the cross-point checks:** on vault folders made by the SIGKILL suite; a sequence where a later point loses a committed batch, changes a manifest or reuses a `cert_id` must fail; mutation checks on these rules;
   - **the safety checks:** the loop-device validation rejects anything that is not the run's own `/dev/loopN`; the device-mapper name.
2. **The privileged run**, by the user: the report's counts, timings and result.
3. **The gate**, then a summary as for 6A and 6B.

## 17. Decisions this amendment adds (6C)

| # | Decision |
|---|---|
| 24 | The privileged part is one command the user runs with sudo; everything else is built and tested without root. (§13) |
| 25 | The replayer is written in Go and proves itself: the full replay must equal the final device. (§13, §15) |
| 26 | Crash points are flush and FUA entries; unflushed reordering is not explored. (§15) |
| 27 | The root part is a compiled test binary, not a shell script, so its safety checks are tested Go code. (§13) |
| 28 | The workload drives the writer in-process: ingest, an upgrade with its switch, `gc`, `repair --reindex`. (§14) |
| 29 | Each check mounts a copy read-write, so ext4's journal recovery runs as on a reboot; the working copy is never mounted. (§15) |
| 30 | Consistency across points stands in for an external record of what was committed when. (§15) |
| 31 | Every point is checked by default; sampling is an option for quick runs. (§15) |

