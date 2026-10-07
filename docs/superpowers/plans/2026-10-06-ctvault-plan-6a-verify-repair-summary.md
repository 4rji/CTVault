# CTVault Plan 6A (`verify` and `repair`): Summary

Built directly in the tree, as Plans 4 and 5 were: tests first, the usual gate, real data, and this summary instead of a plan document.

**Spec:** amendment A5 Part 6A (`docs/superpowers/specs/2026-10-06-ctvault-plan6-amendment.md`), approved 2026-10-06 section by section and then as written.

## What It Adds

| Piece | Where | What it does |
|---|---|---|
| `ctvault verify` | `internal/verify`, `internal/cli/verify.go` | `--quick` (the default) checks manifests and metadata in seconds. `--full` reads every byte: checksums, records against their `certs` rows, references, Merkle trees, signed heads and the index. It takes no lock; damage exits 5. `--as-of` and `--json` are supported. |
| Recorded proofs | `internal/commit/manifest.go`, `internal/ingest/batch.go` | `_COMMIT.json` records a batch's consistency proof as `verified.proof`, so `verify` re-checks it offline. Older binaries ignore the field. |
| The streaming index check | `internal/commit/indexcheck.go` | `CheckIndex` compares an index with the vault through lookups and counts, keeping nothing per certificate. `repair --reindex` and `verify --full` share it. |
| `repair --derived` | `internal/ingest/repair.go`, `internal/cli/repair.go` | Rebuilds `certs` and `names` files that are missing or fail their recorded checksum, through `rebuild`'s staging. Each replaces the bad file only when it reproduces that checksum. `--batch` limits it to one batch. |
| Read-only helpers | `internal/lock/holder.go`, `internal/index` | `lock.Holder` tells whether a writer runs, from `/proc/locks`. `index.OpenReadOnly` reads the index without writing it. |
| Test vaults | `internal/querytest` | Test vaults pin their log, and `NewPublished` and `Ingest` let a test keep ingesting into a vault. |

## Decisions to Review

A5's 11 decisions are as approved. The implementation added these:

| # | Decision | Why |
|---|---|---|
| 1 | **`verify` finds a running writer by reading `/proc/locks`.** It doesn't take the lock to find out. | Taking the lock writes the holder's PID into `state/LOCK`. Reading `/proc/locks` writes nothing, and v1 runs on Linux only. |
| 2 | **The index phase touches two lock files and nothing else.** `state/LOCK` records `verify`'s PID while it holds the lock, as for any holder. Pebble re-creates its empty `state/pebble/LOCK`, which changes only its timestamp. | A5 §1 says `verify` "writes nothing but its spill". Avoiding even these would need a custom file layer under Pebble. |
| 3 | **While a writer runs, its work in flight is not judged:** its intent, bytes past the tail, `tmp/` leftovers, and a `views.sql` that lags a commit by a moment. The report names the writer instead. | They are its batch in flight, not leftovers. |
| 4 | **`views.sql` is compared under the root path it names.** The writer names the root as it was given. The same vault reached through a symlink is fine. A moved or copied vault keeps views over its old path until the next `update`, which is reported as recovery pending. | **Found on the 1M-entry smoke vault**, where `update` used the symlinked path and the first measurement used the resolved one. Without this, a different spelling of the same root reads as damage. |
| 5 | **The vault-tail checks always use the latest commit, even with `--as-of`.** An `--as-of` past the last commit is a usage error. | The tail is a property of the vault on disk, not of the snapshot. |
| 6 | **An unreadable intent is damage, and so are bytes past the tail that no uncommitted intent explains.** | These are recovery's own rules (spec §8.5). Recovery would stop with exit 5 on both. |
| 7 | **Records are compared with the active `certs` file, or the version being built when the batch has it.** A batch with neither is decoded and hashed only. | A5 §2.2, made concrete. |
| 8 | **After a batch whose rebuilt tree differs, later batches are judged from its recorded `merkle_after`.** | One damaged batch then gives one finding, not one for every batch after it. |
| 9 | **References use a bitset of the `cert_id`s seen so far**, one bit per ID (about 50 MB at 400M). | Entries refer only to their own batch or earlier ones, so the bitset is always complete in time. |
| 10 | **The index phase reuses `commit.CheckIndex`, which runs on one core and decodes the vault again.** | It's the function `repair --reindex` uses, so one implementation is tested. It costs most of `--full`'s time (see Known Gaps). |
| 11 | **`repair --derived` opens no writer and runs no recovery**, as `--reindex` doesn't. It lists batches without checking file sizes. | A missing or truncated derived file, which is exactly what it repairs, would stop the writer's start. |
| 12 | **`rebuild`'s per-batch staging is shared by `rebuild` and `repair --derived`.** | One path, already proven byte-identical in 3B-2. `rebuild`'s tests and crash tests pass unchanged. |
| 13 | **Within a batch, files that reproduce their checksum are replaced even if another file doesn't.** Damaged source data in a batch replaces nothing there. An index that disagrees with the vault stops the whole repair. | A partly repaired batch is safe: a rerun or `verify` reports the rest. |
| 14 | **`repair` needs exactly one of `--reindex` and `--derived`,** and `--batch` goes only with `--derived`. Anything else is exit 2, naming both repairs and suggesting `verify --full`. `repair --derived` opens the index read-only; with no index, it exits 5 and says to run `repair --reindex` first. | A5 §3.4. |
| 15 | **`query.Session.DB()` gives `verify` the reader session's database**, so its queries spill only to `tmp/duckdb-<pid>/`. `--quick` opens no session at all, so it writes nothing. | One spill rule for every reader. |
| 16 | **A fresh vault with no index folder yet is sound.** | `init` creates no index; the first `update` does. |

## Evidence (2026-10-06)

1. **Fault matrix** (`internal/verify`):
   - 37 faults, one per fresh copy: 17 for `--quick`, 12 for `--full`, and 4 that no other case isolated:
     - a vault span that doesn't follow the previous one;
     - a `certs` row with another SHA-256;
     - a `cert_id` that doesn't increase;
     - a batch rewritten consistently, with a forged `leaf_hash` and a `merkle_after` that matches it. Only the signed head disproves it, and `verify` catches it there.
   - In the "consistent but wrong" cases, the file is rewritten and its checksum updated, so the content checks are shown not to rely on checksums.
   - The writer's own index check has 8 cases of its own (`TestCheckIndex`).
2. **What isn't damage:**
   - an intent, bytes past the tail and `tmp/stage` leftovers are recovery pending, exit 0;
   - an audit failure in `health.json` is a warning;
   - with a writer holding the lock, nothing in flight is judged;
   - an index one batch behind is pending;
   - a held lock skips the index check and names the PID.
3. **Behaviour:**
   - **Read-only:** `--quick` changes no file. `--full` changes only `state/LOCK`. Beside a writer, it changes nothing.
   - **`--quick` with an unreadable data file:** it passes, and `--full` fails.
   - **Beside a writer:** `verify --full` runs while a writer under the lock commits batches 4 to 10. It checks its snapshot, passes, and skips the index, naming the PID.
   - **The same vault through a symlink** passes. A moved vault's `views.sql` is pending.
   - **An empty vault** passes in both modes.
4. **Mutation checks:**
   - Of 34 mutations, 32 were caught: each removed check makes its fault test fail, including `repair`'s checksum rule and its source check.
   - Two survive by design, because a second check still catches the fault:
     - with the `ACTIVE.json` check bypassed, the per-batch "lacks its file" check still fails;
     - with the writer check bypassed, the in-process lock is still held, so the index is still skipped.
   - The two overlapping-ID checks back each other up. Removing both is caught.
5. **`repair`:**
   - **`--derived` brings files back byte-identical:** a flipped `certs` file and a deleted `names` file, after which a second run finds nothing to do.
   - **It refuses what it can't rebuild:** an unreproducible recorded checksum, and damaged `entries`, each reported with nothing replaced.
   - **Crash tests:** subprocesses killed after staging and after the first replacement. Each damaged file is either the damaged copy or the rebuilt one, never partial or missing, and a rerun ends equal to the undamaged vault.
   - **`--reindex`'s heap stays flat:** between the first and the last of 8 batches, building and checking (`TestReindexMemoryStaysFlat`, 5 runs). Re-adding A2's map as a mutation shows 190 bytes per certificate.
6. **Real data:**
   - **The canonical sample** (100,000 entries, 10 batches): `--quick` takes 2 ms. `--full` takes 2.7 s with one decoder and 2.1 s with five, with every check passing. The sample's signed head lies past the ingested range, so all 10 recorded proofs were re-checked offline. `repair --derived` rebuilt a damaged real `certs` file byte for byte in 0.8 s.
   - **The 1,000,000-entry smoke vault**, through the dev binary: `verify` takes 0.06 s and `verify --full` 23.5 s, with no damage.
     - Stages with 5 decoders: checksums 0.55 s, records 5.5 s, index 16.7 s. With 1 decoder, records take 9.7 s.
     - Its 2 batches predate recorded proofs: `2 proved at ingest, proof not recorded`.
   - **`repair --reindex` on a copy of the smoke vault** (1,000,689 certificates):

     | | Time | Peak memory |
     |---|---|---|
     | with A2's map put back | 29.7 s | 485 MiB |
     | streaming | 26.8 s | 302 MiB |

     A2's map would need about 70 GB at today's 383M entries. The streaming check is bounded by one batch.
7. **Projection to `argon2027h1` today** (383M entries, from the 1M-entry vault, linear):
   - `--quick` stays under a second or two.
   - `--full` takes about 2.5 hours: checksums about 3.5 minutes (more on a slow disk), records about 35 minutes over 5 cores, and the index check about 1.8 hours.
   - With a writer running, the index is skipped, so `--full` takes about 40 minutes.
8. **Gate:** gofmt clean; `go vet` clean with 4 tag sets; race tests pass in production and dev builds (30 packages). The `verify` and `tui` real-data tests pass.

## Known Gaps

- **The index check dominates `--full`:** about 70% of its time on the smoke vault (decision 10). It decodes the vault a second time, on one core. Spreading it across cores, as the records stage is, or reusing the records stage's hashes, would roughly halve `--full`. That's a follow-up and changes no result.
- **Leftover temp files from an interrupted atomic write** (outside batch directories) aren't listed as recovery pending. Recovery removes them anyway.
- **The full-scale times are projected, not measured.** The real-data `repair --derived` evidence is from the sample.
- **Batches committed before 6A have no recorded proof.** Their signed heads are re-checked by the Merkle rebuild once the vault reaches their tree size. Until then they show as `proved at ingest, proof not recorded`.
