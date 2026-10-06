# CTVault Plan 3C (Compression, `stats`, Measurements): Summary

Built directly in the tree, with the same TDD, gates and real-data checks, and this summary instead of a full plan document ("tu decide, sigue").

**Spec:** amendment A2 §2, §6 and §7 (`docs/superpowers/specs/2026-10-04-ctvault-plan3-amendment.md`), approved 2026-10-05. It builds on Plan 3B-2.

## What It Adds

| Piece | Where | What it does |
|---|---|---|
| libzstd | `internal/vault/czstd.go` | Calls libzstd 1.5.7, compiled from source by `github.com/DataDog/zstd` v1.5.7, now a direct dependency, through its stable C API: `ZDICT_trainFromBuffer`, and level-9 compression with a content checksum. |
| Full records | `internal/vault/codec.go` | Leaf and chain records are libzstd level-9 frames. Leaf-delta records are unchanged (klauspost `SpeedDefault`), and every frame is still read with klauspost's decoders. |
| Training | `internal/vault/dict.go` | `Train` runs `ZDICT_trainFromBuffer` and writes the vault dictionary ID into the dictionary header (RFC 8878 §5). It keeps A1 §5's checks: training errors and dictionaries that do not help fall back to dictionary 0. |
| Dictionary manifest | `dict/<id>.json` | Gains `capacity`, `binding`, `api`, `implementation`, `parameters`, and `training.order` and `training.samples_sha256` (A2 §2.2). Plan 2 manifests stay valid. |
| `_COMMIT.json` counters | `internal/commit/manifest.go`, `internal/ingest/batch.go` | `fetch` (requests, 429s, retries), `parse_status` (the new certificates' mix) and `delta_saved` (approximate, from a 1-in-16 hash sample, A2 §6.1). |
| `ctvault stats [--json]` | `internal/stats`, `internal/cli/stats.go` | Shows, per log: heads, committed entries, remaining entries, ingest rate, ETA, 429 ratio and growth. For the vault: deltas and their ≈ savings, the `parse_status` mix, tables and incidents. Also disk use per volume, bytes per entry and the projected cap date, each estimate with A2 §6.3's windows. It reads only. |
| Measurements | `internal/measure` | Reports gain a `derived` section (rows, bytes per entry, names per certificate, `parse_status`, extraction time) and DataDog/zstd in the provenance. |

## Decisions to Review

| # | Decision | Why |
|---|---|---|
| 1 | **CTVault declares the libzstd prototypes it calls** instead of including `zstd.h`. DataDog/zstd is imported for its compiled C code; its Go API is not used. | DataDog's bulk API cannot enable the content checksum the vault format requires (spec §6.2). The stable API (`ZSTD_CCtx_setParameter`, `ZSTD_compress2`, `ZSTD_createCDict`, `ZDICT_trainFromBuffer`) can. |
| 2 | **Training uses `MaxDictSize` (110 KiB) as its capacity**, the same as Plan 2. | A2 §2.5's evidence used 112,640 bytes. |
| 3 | **The "does it help" check is unchanged:** the training samples must compress smaller with the dictionary than without. libzstd builds its dictionary from pieces of the samples, so even random samples pass it. The fallback test therefore checks `checkHelps` with data the dictionary was not trained on; degenerate samples still give an error. | It still catches a broken dictionary. It cannot catch an overfitted one, and neither could Plan 2's. |
| 4 | **Counters live at the top of `_COMMIT.json`**: `fetch`, `parse_status`, `delta_saved`. Batches written before 3C lack them, and `stats` says "estimated in N of M batches". | No change to `counts`, which the disk guard reads. |
| 5 | **`fetch.retries`** counts every request repeated after a 429, a 5xx, a malformed response, a network error or another HTTP status. It covers the committed attempt only. | A2 §6.1 names requests, 429s and retries. A refetched batch's first attempt is not part of its commit. |
| 6 | **`delta_saved`** compares whole records: the full record a sampled certificate would have been (libzstd, the batch's dictionary) against its leaf-delta record. With no sampled record its bytes are 0 and `sampled_records` says why. | The vault pays for records, not frames. |
| 7 | **`stats` "delta hit rate"** is the share of new certificates stored as leaf-delta records. | It needs only `_COMMIT.json`. The measurement reports keep the finer "eligible finals" rate. |
| 8 | **The projected cap date** is computed only when every vault directory shares the root's filesystem; otherwise it is unknown, with that reason. Pebble's bytes per entry are `state/pebble` over all committed entries. | One headroom figure is only meaningful for one filesystem. Multi-volume projection is Plan 6's hardening. |
| 9 | **The ingest rate** counts the entries of the window's batches after the first, over the time since the first committed. **The log growth rate** comes from the tree sizes and timestamps of the STHs the committed batches were verified against. | Both come from durable records, so `stats` needs no extra state. |
| 10 | **The disk-guard seeds are not changed.** The re-measured numbers below are a proposal for a reviewed edit (A2 §7). | A1 §8. |

## Evidence (2026-10-05)

1. **Reproducible training:** the pinned corpus (the first 2,000 certificates of the extractor's checked-in corpus) trains to `cc99954ae7ebe51a1dcef221a6c2a0ade517339fc770007b61e999b48faf2429` every time, in separate processes, with ID 1 in the header. Plan 2's trainer differed in 10 of 10 retrainings.
2. **Compatibility:**
   - C frames carry a checksum and the record's dictionary ID, and an independent klauspost decoder reads them, with and without a dictionary;
   - 50 frames written by Plan 2's encoder, half with its klauspost-trained dictionary, still decode (`testdata/plan2_frames.json`).
3. **Counters:** a 400-entry fake-log batch records fetch counters, `parse_status` summing to its new certificates, and a `delta_saved` scaled from its hash-sampled delta records (`TestBatchCounters`).
4. **`stats`:** every estimate is unknown below its window's minimum (`TestEstimatesNeedEnoughHistory`). The cap projection is checked during and after the catch-up (`TestProjectedCapDate`).
5. **Re-measurement of both samples** (10,000-entry batches, production dictionary training), against Plan 2C's of 2026-10-04:

   | | Canonical `[0, 100000)` | Representative `[397220000, 397320000)` |
   |---|---|---|
   | Vault, B/entry (with dictionary 1) | 1079 (985) → **1009 (894)** | 745 (638) → **686 (561)** |
   | Full leaf records with a dictionary | 1.58× → **1.74×** | 1.71× → **1.96×** (the spec's figure) |
   | Parquet, B/entry (now with `certs` and `names`) | 55 → 182 | 55 → 200 |
   | `certs` / `names`, B/entry | 90.6 / 36.2 | 99.2 / 45.5 |
   | Names per certificate | 1.86 | 1.93 |
   | Pebble, B/entry | 72 → 72 | 71 → 71 |
   | `leaf-delta` saving (dictionary batches) | 37.0% → 30.3% | 25.8% → 17.8% |
   | `parse_status` | ok 100,570, partial 3 | ok 100,199, partial 4 |
   | Extraction | 11.1 µs per certificate | 11.9 µs per certificate |

   - **The representative vault is 561 B/entry** with a dictionary, against the spec's budget of 765. The canonical sample, which A1 §2.1 says not to tune from, still reports a gap (894 against 765).
   - **Leaf-delta records save less in relative terms** only because full records are now smaller. Delta frames did not change.
   - **Training now takes seconds.** The real-data end-to-end ingest of 100,000 entries with production training dropped from 4 m 11 s to 32 s, and the whole real-data layer from about 15 minutes to 5.
   - **Proposed seed edit, not applied** (A1 §8):
     - vault 840, unchanged: it covers the representative 686 without a dictionary and 561 with one;
     - Parquet 175 → 210: measured 182 and 200, now including the derived tables;
     - Pebble 60 → 75: measured 71–72 on both samples.
     The proposed total is 1,125 B/entry, against 1,075.
6. **Gate:** `gofmt` clean, `go vet` clean with 4 tag sets, race tests pass in production and dev builds (26 packages). The whole real-data layer passes in 313 s:
   - end to end with production training;
   - recovery equivalence;
   - rebuild equivalence: 10 batches in 10.3 s, byte-identical;
   - both measurement reports.
