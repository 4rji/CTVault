# CTVault Plan 3B-2 (Local Backfill and `repair --reindex`): Summary

Built directly in the tree, with the same TDD, gates and real-data checks as earlier plans, instead of a full plan document: the user chose speed ("tu decide, sigue"). This page records what was built, the decisions to review, and the evidence.

**Spec:** amendment A2 §5 (`docs/superpowers/specs/2026-10-04-ctvault-plan3-amendment.md`), approved 2026-10-05. It builds on Plan 3B-1.

## What It Adds

| Piece | Where | What it does |
|---|---|---|
| `_DERIVED.json` | `internal/commit/derived.go` | The manifest of derived files a rebuild adds to a committed batch (A2 §5.3). Deterministic and checksummed. `ListCommitted` reads it into `Manifest.Derived` and checks its files' sizes; `Manifest.Listed(name)` says whether a file belongs to the batch. |
| Recovery | `internal/commit/recover.go` | Also deletes derived files no manifest lists, the temp files of an interrupted `_DERIVED.json` write, and a leftover `state/pebble.reindex` or exchange probe (A2 §5.5). |
| `ctvault rebuild` | `internal/ingest/rebuild.go`, `internal/cli/rebuild.go` | Fills in the tables `ACTIVE.json` lists as building, batch by batch, from the vault (A2 §5.2). Then it re-lists the batches, verifies every file's checksum, and switches `ACTIVE.json` to complete (A2 §5.4). |
| `ctvault repair --reindex` | `internal/commit/reindex.go`, `internal/cli/repair.go` | Builds a new Pebble index beside the old one, verifies it, and exchanges them with `renameat2(RENAME_EXCHANGE)` (A2 §5.6). |
| The `update` warning | `internal/cli/writer.go` | On a vault still building: `warning: certs and names are being built: run ``ctvault rebuild``` (A2 §5.5). |

## Decisions to Review

These choices are **not** in the approved sections.

| # | Decision | Why |
|---|---|---|
| 1 | **A damaged `_DERIVED.json`** (checksum, format, or another batch's ID) is corruption, exit 5. It is not deleted. | It is written atomically, so damage means something else is wrong. Derived files are regenerable, but silently dropping a manifest would hide that. |
| 2 | **The checksum** is the SHA-256 of the file's indented JSON (one-space indent, trailing newline) written with `checksum` empty. | Canonical and reproducible: the same binary over the same batch writes the same bytes. |
| 3 | **Recovery deletes only unlisted files named `<table>.p<N>.parquet`** and `_DERIVED.json` temp files. Any other unknown file in a batch directory is left alone. | Only what a rebuild could have placed is ours to delete. |
| 4 | **`rebuild` checks `entries.parquet` and `chains.parquet` against `_COMMIT.json`'s checksums** before using them to cross-check kinds. | A kind decision must not rest on a damaged source file. |
| 5 | **Kind cross-checks:** a full leaf record's entries must have exactly one type (`x509` → final, `precert` → precert); a leaf-delta's entries must all be `x509`; a chain record must appear in its batch's `chains.parquet`. | A2 §5.2. Any disagreement is a dataset inconsistency, exit 5. |
| 6 | **A Pebble disagreement stops the rebuild at that batch**, exit 5, "index inconsistency (the vault is intact; run `ctvault repair --reindex`)". Files already placed stay. | A2 §5.2. The rebuild resumes after the repair. |
| 7 | **`rebuild` has no interrupt handling of its own.** Ctrl-C kills it, and that is safe: every step is crash-safe, and the next run resumes. | Fewer moving parts. The crash suite covers every boundary. |
| 8 | **`repair --reindex` never opens the old index and does not run recovery.** It reads only committed vault spans and `chains.parquet`. With no `state/pebble` at all, it renames instead of exchanging. | A broken index must not stop its own repair. The next writer start recovers as usual. |
| 9 | **Without `RENAME_EXCHANGE`, `repair --reindex` exits 1** with a message naming the missing syscall. It probes by exchanging two empty directories in `state/` before building anything. | No new exit code. The old index is untouched. |
| 10 | **`repair` without `--reindex` is a usage error** (exit 2): the rest of `repair` is Plan 6. | A2 §1. |
| 11 | **`ingest.Options.NoDerived`** writes batches without derived files, as Plan 2 did. Tests only. | A2 §5.7's byte-equivalence test needs the Plan 2 shape. |
| 12 | **A shared `openWriter` in the CLI** (lock, config, writer with recovery) serves `update` and `rebuild`. | One place for the writer's setup. |

## A Finding for Plan 3C

**Plan 2's dictionary trainer is not deterministic.** `dict.BuildZstdDict` (klauspost) gave a different dictionary in 10 of 10 retrainings on the same samples.

- **Consequence:** two vaults that ingest the same entries diverge in record bytes once they train. Derived files are then equal in content (A1/A2 "equal except internal IDs and locations") but not in bytes.
- **What this changes:** ingest-against-rebuild byte equivalence is tested without training (fake log and real data), and the rebuild crash test compares a resumed rebuild with an uninterrupted rebuild of the same vault.
- **For 3C:** the libzstd trainer replaces it, and A2 requires a pinned corpus to give an expected checksum. 3C adds a determinism test for training.

## Evidence (2026-10-05)

1. **Byte equivalence on real data:** the canonical sample (100,000 entries, 10 batches, no training) ingested with the builders off and then rebuilt gives `certs` and `names` files byte-identical to an ingest with the builders on. The rebuild took 9.4 s for 100,573 certificates and 186,756 names rows.
2. **Byte equivalence on the fake log**, two vaults: identical files, and identical `_DERIVED.json` bytes (`TestRebuildIsByteIdentical`).
3. **Crashes:**
   - `rebuild` killed during staging, after placement and before `_DERIVED.json`, and before and after the `ACTIVE.json` switch: no view exposes a partial table, recovery removes unlisted files, and the resumed rebuild ends with the same files (`TestRebuildCrashes`);
   - `repair --reindex` killed during the build, after the sync and after the exchange: the index stays usable, recovery removes `state/pebble.reindex`, and a rerun completes (`TestReindexCrashes`).
4. **Inconsistencies:** an injected Pebble key, a leaf-delta referenced by a precert entry, and a corrupted record are each reported as such (`TestRebuildReports*`). `repair --reindex` fixes the index, and the rebuild then completes.
5. **Mutations caught:**
   - a delta base written as 0: `TestRebuildIsByteIdentical`;
   - recovery skipping the unlisted-file cleanup: `TestRebuildCrashes/rebuild_placed`.
6. **Gate:** `gofmt` clean, `go vet` clean with 4 tag sets, race tests pass in production and dev builds (25 packages).
7. **Real data:**
   - end to end: 100,000 entries in 4 m 11 s;
   - recovery equivalence: 5 crashes;
   - rebuild equivalence: 10 batches in 9.5 s, byte-identical;
   - the extractor's differential check on 200,710 certificates: 0 differences.
