# CTVault Plan 4 (The Read Path): Summary

Built directly in the tree, with TDD, the usual gates and real data, and this summary instead of a plan document ("sigue y no pares").

**Spec:** amendment A3 (`docs/superpowers/specs/2026-10-05-ctvault-plan4-amendment.md`), approved 2026-10-05.

## What It Adds

| Piece | Where | What it does |
|---|---|---|
| Snapshots | `internal/query/snapshot.go` | `query.Open(root, asOf)`: the committed batches up to a `commit_seq`, with the files their manifests list. Never globs. Derived tables are used only while complete. |
| Reader sessions | `internal/query/session.go` | DuckDB in memory, every core, the Parquet metadata cache on. Spill goes to `tmp/duckdb-<pid>/`, removed on close; folders of dead readers are removed at start. |
| Read-only dictionaries | `vault.ReadDicts` | Readers verify dictionaries and never repair replicas. |
| `ctvault fetch` | `internal/query/fetch.go`, `dump.go`, `internal/cli/fetch.go` | By SHA-256 (bloom-pruned) or `cert_id` (`cert_id_range`), verified against the SHA-256. `pem`, `der`, `text` or `json`. `--with-chain` returns every distinct chain; `--with-entries` is an opt-in scan. |
| `ctvault search` | `internal/query/search.go`, `internal/cli/search.go` | Modes: domain, `--suffix`, `--exact`, `--ip`, `--contains`, `--regex`. Filters: issuer CN/O, `--issued-by` by relationship, key, kind, validity, time, log. Groups: names, certs, issuances. Formats: table, md, json, csv. |
| Export | `internal/query/export.go`, `format.go` | `--output` with md, json or csv (plus `.meta.json`). It carries the metadata that reproduces it, is written atomically, and is never overwritten without `--force`. |
| Post-commit audit | `internal/ingest/audit.go`, `internal/health` | After every commit, the writer runs 8 SHA-256 fetches, 8 name and 8 eTLD+1 lookups, and 1 `cert_id` fetch through the read path. The result goes to `state/health.json`, which `stats` shows. A failure never undoes the commit. |
| Benchmark | `internal/integration/readpath_bench_realdata_test.go` | A3 §7.1, on a synthetic dataset grown from the canonical sample's rows (`CTVAULT_BENCH=1`). |

## Decisions to Review

| # | Decision | Why |
|---|---|---|
| 1 | **Search prunes with the matched cert_ids.** It reads names first; then only the `certs` files of batches whose `cert_id_range` holds a match, and `entries` only from the first such batch on (an entry can only reference a certificate already vaulted). Up to 1,000 matches are inlined as a literal list; larger matches use a subquery over the same pruned files. | Found by the benchmark: the semi-join over every `certs` file dominated, not `entries`. A rare domain fell from about 26 s to about 1 s at extrapolated full scale. A 15,000-value literal list made DuckDB slower than the subquery (1.2 s against 75 ms on real data), hence the 1,000 limit. No new on-disk artifact (A3 approach 1). |
| 2 | **Bloom filters stay** (A2's `DICTIONARY_SIZE_LIMIT 122880`). | A3 §7.2 rule 1: without them, `fetch` would take about 10.5 s at full scale, failing M2's 5 s. They cost about 22 B/entry (~2%). |
| 3 | **CSV exports stream through Go's CSV writer**, not DuckDB `COPY`. | The same value rendering in every format, and still never held whole in memory (A3 §5's aim). |
| 4 | **`search --format json` to stdout writes the rows first and `meta` last**, so it streams. Export files put `meta` first, as spec §11.6 shows. | A streaming stdout cannot know `row_count` up front. JSON readers ignore key order. |
| 5 | **The audit reads through the writer's own DuckDB session**, and is skipped while the tables are being built. | A reader session would leave `tmp/duckdb-<pid>` behind after a kill during the audit, which recovery does not clean. |
| 6 | **Keyset pagination waits for `explore`** (Plan 5). Every sort already ends with a unique tie-breaker, so pagination can be added without changing results. | Only the TUI pages. |
| 7 | **`--contains` is case-insensitive**; `--regex` uses RE2 (DuckDB and Go agree), validated before running. | Predictable behaviour. Invalid patterns exit 2. |
| 8 | **`fetch` writes to stdout or `--output`**, and refuses DER to a terminal. | A3 §4.2. |

## Evidence (2026-10-05)

1. **Real data** (the canonical sample, 10 batches of 10,000), `TestReadPathOnRealData`:
   - all 10 post-commit audits passed;
   - 1,000 sampled certificates fetched byte-exact by SHA-256 (p50 7.9 ms) and by `cert_id` (p50 6.7 ms);
   - `search` results equal independent DuckDB queries over `views.sql`, for the most common domain (`on.aws`, 26,272 names, 88 ms) and a rare one (14 ms).
2. **Benchmark** (synthetic, 10, 50 and 100 batches of 500,000 entries, both writer settings), extrapolated to about 770 batches:

   | | A2 settings (kept) | DuckDB defaults |
   |---|---|---|
   | `fetch` lookup p50 at 100 batches → full shard | 79 ms → **0.27 s** | 1,373 ms → 10.5 s |
   | Absent certificate p50 at 100 batches | 28 ms | 1,373 ms |
   | Rare domain search → full shard | 163 ms → **1.1 s** | 1,186 ms → 9.1 s |
   | Exact name search → full shard | 348 ms → **2.5 s** | 1,539 ms → 11.7 s |
   | A domain present in every batch (worst case) → full shard | 7.8 s → 60 s | 8.4 s → 66 s |
   | `certs` + `names`, B/entry | 120.4 | 98.2 |

   - **The worst case** is a domain repeated in every batch at `on.aws`'s density (26% of the sample's names), so no file can be pruned. M3 targets a typical domain, which takes 1–2.5 s; the worst case is recorded, at the 60 s line.
   - **The method:** latency was taken as linear in the number of batches and checked at 10, 50 and 100. The OS page cache was warm (no root to drop it); the first lookup in each session is reported separately.
   - **The report:** `.superpowers/sdd/2026-10-05-ctvault-4/bench-report.json`.
3. **The audit at full scale** (estimated from the benchmark): about 20 s per 500,000-entry batch, mostly the 16 name and eTLD+1 lookups. That is about 2.5% of a batch, which spends roughly 13 minutes fetching at 20 requests/s.
4. **Mutations and crashes:** a kill inside the audit leaves the batch committed and `health.json` valid (`TestCrashAtEveryBoundary/post_commit_audit`). A failed audit is recorded and reported (`TestPostCommitAuditFailure`).
5. **Gate:** `gofmt` clean, `go vet` clean with 4 tag sets, race tests pass in production and dev builds (28 packages).
6. **Real-data layer:** passes, with `TestReadPathOnRealData` added; the extractor's differential check on 200,710 certificates found 0 differences.

## Known Gaps

- **`--issued-by`:** no test has a certificate whose issuer DER matches the CA's subject with no chain or key-ID relationship, so "DER is necessary but not sufficient" is not covered by a negative case.
- **The live smoke test** covered rates up to 20 requests/s; higher rates were not tried.

## Live Smoke Test and Seeds (A3 §7.3–7.4)

The user confirmed the test ("si dale"). Two real `argon2027h1` batches of 500,000 entries, `[0, 1,000,000)`, went into a dev vault on `/mnt/disk`, with the dev build:

| | Batch 1 | Batch 2 |
|---|---|---|
| `max_rps` | 5 | 20 |
| Time | 53 min | 14.4 min (about 580 entries/s; page size 32) |
| Requests, 429s, retries | 15,640, 15, 15 | 15,630, 5, 5 |
| New certificates (deltas) | 500,642 (4,596) | 500,047 (11,784) |
| Vault, B/entry | 1,295 (no dictionary) | 733 (dictionary 1) |
| `certs` / `names` / `entries`, B/entry | 88.9 / 34.9 / 53.5 | 86.3 / 32.9 / 52.8 |
| `delta_saved` (approximate) | 3.5 MB | 2.6 MB |
| Peak RSS | 1.85 GB | 2.0 GB |
| Post-commit audit | passed | passed |

- **M1:** Pebble 77 B/entry after 1,000,000 entries. Delta hit rate 1.6% of new certificates (the shard's start; A1 §2.1).
- **M2 and M3 on the real vault**, process start included: `fetch` 46 ms (156 ms in `text` with the chain); `search amazonaws.com` 542 ms; `--exact` 61 ms; `--suffix` 385 ms.
- **M4:** 20 requests/s is sustainable from one IP, with 0.03% 429s. The defaults (`max_rps` 20, 4 workers) stay.
- **Seeds, applied after approval:**
  - vault 840, unchanged: it covers 561–733 B/entry with a dictionary; a first batch without one (1,295 at the shard's start) sits just above 840 × 1.5;
  - Parquet 175 → **210** (measured 172–200);
  - Pebble 60 → **80** (measured 77 live; 3C had proposed 75).
  - `TestSeedsAreReviewed` pins them.
