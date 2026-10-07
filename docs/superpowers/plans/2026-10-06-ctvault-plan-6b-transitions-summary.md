# CTVault Plan 6B (Version Transitions): Summary

Built directly in the tree, as 6A was: tests first, the usual gate, real data, and this summary instead of a plan document.

**Spec:** amendment A5 Part 6B (`docs/superpowers/specs/2026-10-06-ctvault-plan6-amendment.md` §7–§12), approved 2026-10-06 section by section and then as written. You chose to run transitions inside `update`, in turns (choice A).

## What It Adds

| Piece | Where | What it does |
|---|---|---|
| The version registry | `internal/derive/registry.go`, `active.go` | A binary carries each table's version N and may carry N−1. `ACTIVE.json` gains the `mixed` status and the `retiring` and `switched_at` fields; unset fields are omitted, so existing files keep their bytes. `Readable` and `BuildVersions` say which version readers use and which versions a new batch builds. |
| Readers by version | `internal/query`, `internal/dataset/views.go`, `internal/ingest/audit.go`, `internal/tui`, `internal/verify` | Every reader takes table file names from `ACTIVE.json` instead of `certs.p1` and `names.p1`. A table stays readable at N−1 while N is built. `views.sql` exposes `<table>_building` beside the active version, and `<table>_previous` while mixed. |
| The upgrade in turns | `internal/ingest/rebuild.go`, `internal/cli/update.go` | A newer binary's first writer starts the upgrade, if the disk guard allows a second copy. New batches build both versions. `update` rebuilds one old batch after each committed batch (`rebuild.batches_per_turn`), and under `--follow` between cycles. The last turn switches. `rebuild` does it all at once. |
| Retirement | `internal/commit/derived.go` (`Retire`), `internal/ingest/retire.go`, `internal/cli/gc.go` | `_DERIVED.json` gains a `retired` list, written before the files are deleted. `ctvault gc` retires at once; `update` and `rebuild` retire 24 hours after a switch, at start and at each `--follow` cycle. |
| In place | `rebuild --in-place` | Each batch is converted with one `_DERIVED.json` write that lists N and retires N−1. The table is `mixed` meanwhile, and new batches build only N. |
| Mixed reads | `query.MixedRead`, `--parser-version`, `--allow-mixed` | Readers refuse a mixed table (exit 2) unless the user chooses. A partial or mixed read is noted on stderr, and exports record it as `mixed_tables`. |
| `explore`'s banner | `internal/tui` | `explore` checks `ACTIVE.json`'s `seq` every 10 s; when it changes, the status line says what is active and to press R to reload. |
| `stats` | `internal/stats` | `stats` shows each transition's progress, and a WARNING line for each mixed table. |
| Test-only versions | `internal/derivetest` | A test `certs` v2 (one added column) and a test new table (`flags`), which tests and crash children install. |

## Decisions to Review

A5's 12 decisions (12–23) are as approved. The implementation added these:

| # | Decision | Why |
|---|---|---|
| 1 | **The side-by-side headroom estimate is the size of the active version's files**, not spec §10.1's seeds per entry. | It's measured, not guessed: the new version replaces files of about that size. |
| 2 | **A run with nothing to ingest and no `--follow` does no turn.** | A5 §8 ties turns to committed batches and to idle time under `--follow`. `rebuild` finishes at once. |
| 3 | **`_COMMIT.json`'s `builders` map records the newest version a batch built**; its `files` list both. | The map is informational: exports and readers use `ACTIVE.json`. |
| 4 | **The derived stager names its staging tables `<table>_p<N>_stage`.** | Two versions of a table stage together. The byte-equivalence of ingest and `rebuild` on real data still holds. |
| 5 | **The building warning names versions and progress**, for example "certs v2 is being built beside v1 (1 of 4 batches have it): update rebuilds old batches in turns; `ctvault rebuild` finishes it now". | It replaces "being built: run `ctvault rebuild`", which is no longer the only way. |
| 6 | **`rebuild.workers` stays in the config, unused.** | Choice A has no background workers. Removing a config key would make old config files fail to load, since unknown keys are errors. |
| 7 | **A table the binary carries and `ACTIVE.json` lacks is added by the writer at start.** It is built in turns when batches exist, complete when none do. | Spec §7.8's new tables. Until now, `Check` refused such a vault. |
| 8 | **`StartInPlace` also converts an upgrade already running side by side.** Batches that hold both versions then only retire the old one. | You can switch to in place when the disk fills mid-upgrade. |
| 9 | **One turn handles side-by-side and in-place tables together.** A batch counts once per turn, whatever it needs. | One pace setting covers both. |
| 10 | **`--allow-mixed` reads each batch's newer version when it has both**, and adds `union_by_name` only then. | The extra option costs schema reads on every query, so only mixed reads pay it. |
| 11 | **`explore` keeps the session's mixed choice across R.** | A reload shouldn't drop a choice the user made on the command line. |
| 12 | **`stats` gives no start time for a mixed table.** | `ACTIVE.json` records no time for it; the retiring state has `switched_at`. |
| 13 | **`views.sql` is regenerated after every rebuilt batch and every retirement**, not only at the switch. | **Found by the mid-transition `verify` test:** the first file of a new version must turn its `_building` view from empty to real. `WriteViews` writes only when the content changes. |
| 14 | **`verify` reports an index whose lock another holder has as skipped, not damaged.** | **Found by the real-data test**, which left a writer open: a lock conflict read as damage. |
| 15 | **`vaulttest`'s dumps and checks follow the readable version, and skip retired files.** | Otherwise the crash suite would stop comparing derived rows after a switch. |

## Evidence (2026-10-06)

1. **Unit and CLI tests:**
   - **Registry and states:** `TestRegistry`, and `TestTransitionStates` (11 states, valid and not).
   - **Readers:**
     - `TestReadersFollowTheActiveVersion`: `search` returns the same rows before, during and after an upgrade; `fetch` reads v2; the views follow.
     - `TestNotReadable`.
     - `TestMixedReads`:
       - each version's part of the rows, and the two parts together equal the whole;
       - `--allow-mixed` equals the original;
       - `fetch` by ID and by SHA-256 across both versions;
       - `mixed_tables` in exports;
       - the mixed views.
   - **Upgrades:**
     - `TestUpgradeInTurns`: the start, dual-building, one batch per turn, and the switch with `retiring`.
     - `TestUpgradeNeedsRoom`, `TestRebuildFinishesAnUpgrade`, `TestNewTableBackfilled`.
     - **Through the CLI:** `TestUpgradeThroughUpdate` is an upgrade carried by `update` alone, with `verify --full` passing at each step. `TestUpgradeInFollowIdleTime` finishes during `--follow` waits, then a SIGINT stops it.
   - **Retirement:** `TestRetire` (record, then delete; a file a crash left is deleted by recovery), `TestRetireOld` (the 24 hours, and `gc`), and `TestGCCommand` (`gc`, and `update` 25 hours later).
   - **In place:** `TestInPlace`, `TestInPlaceAfterSideBySide`, `TestRebuildInPlace` (no room, then `--in-place`), `TestMixedReadFlags` (exit 2; notes on stderr), and `TestTransitionsInStats`.
   - **`explore`:** `TestReloadBanner`.
   - **`verify` mid-transition:** `TestVerifyTransitionStates` (side by side, in place, a new table) and `TestIndexInUse`.
2. **Crashes** (`TestTransitionCrashes`, subprocesses killed with SIGKILL) at 8 points:
   - an upgrade: staged, placed, before the switch, after the switch;
   - in place: staged, placed, between the record and the delete;
   - `gc`: between the record and the delete.

   Each kill passes recovery and spec §13.5's invariants. Its rerun ends with the same vault (dump and derived checksums) as an uninterrupted run. At the record-and-delete points, a retired file is still on disk, which proves the record comes first.
3. **Mutation checks:** 10 run, 10 caught:
   - in place deleting before recording;
   - a switch without `retiring`;
   - the readable rule reverted to "complete only";
   - the 24 hours ignored;
   - `union_by_name` never added;
   - views not regenerated after a turn;
   - no disk check;
   - plus three re-checks.

   Two of them first survived, and the tests were strengthened:
   - the kill point couldn't see delete-before-record, so the test now requires a retired file still present there;
   - `search` alone didn't need `union_by_name`, so the test now also fetches by SHA-256 across both versions.
4. **Real data** (the canonical sample, 100,000 entries in 10 batches; `TestUpgradeOnRealData`):

   | Step | Result |
   |---|---|
   | Side by side, 10 turns | 6.8 s; slowest turn 0.79 s |
   | `certs` v1 / v2 | 8 MiB each; 17 MiB at the peak |
   | `gc` | 10 files retired, 8 MiB freed |
   | In place, on a second copy | 7.1 s; no v1 left |

   - `search` gives the same rows after the upgrade, and `verify --full` passes after each step.
   - A turn takes about 80 µs per entry, so about 40 s for a 500,000-entry batch (A5 §8 estimated 50 s).
   - **Regression checks:** the real-data ingest-against-rebuild byte equivalence still holds; so do the read-path test and `verify`'s and `explore`'s real-data tests.
5. **Gate:** gofmt clean; `go vet` clean with 4 tag sets; race tests pass in production and dev builds (30 packages).

## Known Gaps

- **No real v2 exists.** The machinery is proven with the test-only v2. The first real extractor change will be its first production use.
- **`stats` doesn't time a transition.** It shows batches done of the total, but no ETA: no rate is recorded.
- **A mixed table has no recorded start time.**
- **`rebuild.workers` is unused** (decision 6).
