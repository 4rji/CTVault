# CTVault A6 (Tiled Logs): Summary

Built directly in the tree, as 6A–6C were: tests first, the usual gate, real data, and this summary instead of a plan document.

**Spec:** amendment A6 (`docs/superpowers/specs/2026-10-06-ctvault-tiled-amendment.md`), approved 2026-10-06 section by section and then as written. Its scope is choice A (everything RFC 6962 logs have) and its client is choice 1 (built in-house, with no new dependency).

**Result:** tiled (static-ct-api) logs are pinned, ingested, followed, verified and sampled like RFC 6962 logs, in the same vault.
- One fake log ingested through both protocols gives byte-identical Parquet files, vault segments, dictionary, index and recorded proofs.
- A real dev vault holds `argon2027h1` and `parcelyard2027h1` side by side, and `verify --full` finds no damage.

## What It Adds

| Piece | Where | What it does |
|---|---|---|
| Pinning | `internal/loglist`, `internal/logreg`, `internal/cli/logs.go` | `TiledLog` gains the pinning fields, and `Find`/`All` resolve both kinds; `Origin` derives the checkpoint origin. A record gains `kind`, `submission_url` and `origin`, and `CheckKind` keeps them consistent; a record without `kind` is RFC 6962. `logs list`, `add` and `info` show the kind. `logs info` verifies the live head through the factory: `get-sth` or the checkpoint. |
| The factory and shared errors | `internal/logsource/sources`, `internal/logsource/httperr.go` | `sources.Open` builds a pinned log's source from its kind. The HTTP error types moved into `logsource` (the `rfc6962` names stay as aliases), so the fetcher classifies both kinds alike. |
| The tiled source | `internal/logsource/tiled` | Covers checkpoints (A6 §2's rules, in order), tile paths, and a client that refuses redirects. Proofs and compact ranges are read from hash tiles, and a partial tile that answers 404 is read from the full tile. Data tiles are rebuilt into RFC 6962 `leaf_input`/`extra_data`, with the exact bytes kept as `TileLeaf`. The issuer cache allows at most 4 requests in flight and fetches each fingerprint once. Counters record issuers fetched and partial tiles read from full ones. |
| `leaf_index_mismatch` | `internal/leaf` | `CheckLeafIndex` checks static-ct-api's extension; the code is appended to `leaf.Codes` and to the frozen code registry. |
| Page size from the source | `internal/logsource`, `internal/fetch` | `PageSizer`: a tiled source is read one 256-entry tile per request, whatever the configured page size. |
| Commands | `internal/cli` | `update` prints the tiled counters each cycle. `stats` shows each log's kind. Quarantine lines of tiled entries carry `tile_leaf`. |
| The fake's tiled mode | `internal/ctlogtest` | `Options.Tiled` serves `checkpoint`, hash tiles, data tiles and issuers from the same tree as the RFC 6962 endpoints; every entry then carries `leaf_index`. Partial tiles exist only for published sizes and go once the full tile exists. Faults cover checkpoints, tiles, issuers, redirects, gzip and leaf indexes. |
| Tiled samples | `internal/sample/tiled.go`, `internal/cli/sample_dev.go`, `update_dev.go`, `internal/measure` | Capture records every file the real tiled source reads, through a recording transport. It adds the hash tiles of a proof from every position in the range. Verification and replay run the tiled source over the mirror. A representative sample's start state comes from hash tiles. `measure` and `--replay` take their source from the factory. |
| Real fixtures | `internal/testdata` | The probe's ParcelYard checkpoint, 5 hash tiles, live data tile and issuer, and the v93.6 log list, with their hashes pinned. |

## Decisions to Review

A6's 22 decisions are as approved; final review: a self-review (no fresh reviewer). The build added these:

| # | Decision | Why |
|---|---|---|
| 1 | **The factory is `sources.Open`, in the subpackage `logsource/sources`,** not `logsource.Open`. | Both implementations import `logsource`, so it cannot import them. |
| 2 | **Proofs read tiles through a small tile-reader function.** The test of every pair up to 600 calls it directly, in four parallel parts (7.7 s; 23 s with `-race`). The HTTP path is covered by random pairs up to 70,000 and by the fake-log tests. | Through HTTP, the test took 33 s, nearly all spent on round trips. |
| 3 | **`CompactRange` and `merkle.StateFromNodes` were built in step 2,** for the real-root fixture test. | A6 §5 needed them in step 4 anyway. |
| 4 | **A source states its page size through `PageSizer`, which overrides the configured one.** | The page is a property of the protocol, not a setting. |
| 5 | **Capture fetches proof tiles for every position, not only tile boundaries.** A mutation to boundaries only survives, because the range's level-0 tiles cover the rest. | It makes "any batch size" a guarantee rather than an argument, at under a second of arithmetic even at 512,000 entries. |
| 6 | **`sample capture` reads the log list before checking `--entries`.** | The limits depend on the log's kind. A bad count is now refused after one list fetch, not before. |
| 7 | **`TileLeaf` counts in the fetcher's buffer weight.** | It is held alongside the rebuilt pair, so the bound stays honest. |
| 8 | **`measure` gives the source the sample's own head as the last accepted one.** | `measure` never calls `Head`, and a tiled source needs a verified size to read partial tiles. |

## Findings, Fixed

1. **`TestReindexMemoryStaysFlat` (6A) failed at random under `-race`.** It predates A6.
   - **Cause:** Pebble's race builds put its memtable arenas on the Go heap in half of all processes, by a coin flip at init (`internal/manual.useGoAllocation`). A memtable and WAL rotation can also land inside the measured window. Earlier gates passed by luck.
   - **Fix (the test only):** it measures the Go heap outside Pebble, with `runtime.MemProfile` at rate 1. Then 0 of 24 fresh race runs fail, and a deliberate retention of 100 B per certificate is still caught (138 B per certificate, with and without `-race`).
2. **The first real capture failed after fetching every entry.**
   - **Cause:** the recorder kept files under the full URL path, and ParcelYard's monitoring prefix has a path (`storage.googleapis.com/<bucket>/`). It also wrote the checkpoint it read before the staging folder existed into the working directory. Test runs had left two fake checkpoints in `internal/cli` and `internal/sample`; they were removed.
   - **Fix:** the recorder strips the prefix's path and records only into the staging folder. `TestTiledSampleUnderAPathPrefix` (a proxy under `/bucket.example`, with `t.Chdir`) went RED, then GREEN.
3. **The sample summary showed "0 bytes" for tiled samples.** It read the RFC 6962 entries file; it now counts data tiles, hash tiles and issuers.
4. **Found by the final self-review: under `--follow`, the issuer cache lasted one cycle, not the run** (A6 §3.1). `update` built a new source every cycle, so each cycle fetched every issuer again (about 180 requests on ParcelYard).
   - **Fix:** `update` keeps one tiled source per log for the whole run; a tiled source holds no per-batch state. The cycle line counts only that cycle's fetches.
   - **Test:** `TestTiledFollowKeepsItsIssuers` went RED (the issuer was fetched twice over two cycles), then GREEN (once).

## Evidence (2026-10-06/07)

1. **The gate:** gofmt clean; `go vet` clean with every tag set; race tests pass in production (33 packages) and dev builds (34 packages).
2. **Mutations, 12 of 12 caught.**
   - In the tiled source, 10 rules each make a test fail when removed:
     - the rebuild of nodes below level 8;
     - the partial-to-full fallback;
     - the extension-line rule;
     - the key ID check;
     - the origin check;
     - the `leaf_index` check;
     - the issuer hash check;
     - the trailing-bytes refusal (after adding `TestParseDataTileRejects`);
     - the issuer concurrency bound;
     - the redirect refusal.
   - The equivalence test catches a dropped chain fingerprint.
   - The memory test catches a 100 B per certificate retention.
3. **Real fixtures, in the normal gate:**
   - ParcelYard's checkpoint verifies with the v93.6 key;
   - its root is recomputed from the edge tiles, the level-0 partial falling back to the full tile as it did live;
   - all 256 live entries hash to their level-0 tile, with the right `leaf_index`, 98 precerts and 52 issuers.
4. **Real data:**

   | Run | Result |
   |---|---|
   | Canonical capture of `parcelyard2027h1 [0, 51200)`, head 153,502,087 | 20 s; 112 MB; 200 data tiles, 206 hash tiles, 179 issuers (about 585 requests); 2,236 B per entry |
   | `sample verify` | 4.7 s: every entry matches its level-0 tile, and the proof from 51,200 to the head verifies |
   | `sample measure` (batches of 10,240) | 34 s; 0 leaf errors (every precert check passes with the issuers the log served, every `leaf_index` right); vault 850 B per entry with the dictionary; chain dedup 99.86% |
   | Shared dev vault: Argon's canonical `[0, 100000)` then the tiled `[0, 51200)` in 10,000-entry batches (ends inside tiles) | Argon 178 s, tiled 18 s; 6 tiled batches verified by proofs from the mirror's tiles; 179 issuers, 6 partial tiles read from full tiles; 106 certificates already vaulted by Argon were not stored again |
   | `verify --full` on that vault | No damage: 16 batches in 2 logs, both signed heads (one a checkpoint) verified, 16 proofs re-checked, 151,842 records, index sound |
   | Representative window at `parcelyard2026h2`'s head `[1588442880, 1588494080)` | Capture 68 s, 65 MB, 43 issuers, 1,227 B per entry; measure 31 s, 0 leaf errors, vault 530 B per entry with the dictionary, chain dedup 99.98% |
   | `go test -tags realdata ./...` | Every package passes, including the new `TestTiledCanonicalOnRealData` (51,200 real entries from the mirror in 15 s) |

## Known Gaps

- **A6 §9's out-of-scope items:**
  - several monitoring URLs;
  - names-only tiles;
  - witness checks;
  - waiting for full data tiles;
  - issuers kept across runs;
  - pruned logs.
- **The live smoke run (A6 §7.7) has not run yet.** It waits for your go-ahead.
- **A measurement workspace's post-commit audit warns on every batch** that the batches "are not contiguous at index 0". It predates A6: the Argon representative sample does the same. The workspace starts mid-log by design (A1 §2.6), and Plan 4's audit does not expect that. It is dev-only and changes no data. A fix would skip the audit, or tolerate the seeded start, in measurement workspaces.
- **Real-data folders:** the samples live under `~/.cache/ctvault-dev/samples/` (about 177 MB), and the shared dev vault is `~/.cache/ctvault-dev/vaults/a6mixed`.
