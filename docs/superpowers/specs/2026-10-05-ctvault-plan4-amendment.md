# CTVault Spec Amendment A3: the read path (`query`, `search`, `fetch`, export, health, benchmarks)

- **Date:** 2026-10-05
- **Status:** Approved 2026-10-05. §2–§4 were approved in the design discussion; the written amendment, §5–§7 included, was approved with "sigue y no pares", together with building it directly in the tree.
- **Amends:**
  - `docs/superpowers/specs/2026-10-04-ctvault-design.md` ("the spec")
  - `docs/superpowers/specs/2026-10-04-ctvault-plan2-amendment.md` ("A1")
  - `docs/superpowers/specs/2026-10-04-ctvault-plan3-amendment.md` ("A2")
- **Origin:** Plan 4 design discussion, 2026-10-05.
  - The live smoke test runs at the end of Plan 4, on the dev build (choice A).
  - Issuers are matched by text and by relationship (choice A).
  - The query engine is SQL over an explicit snapshot (approach 1).
- **Scope:** Plan 4, the read path (phase 4 of spec §16).

Everything not changed here stays as in the spec, A1 and A2. **Production safety requirements are unchanged.**

---

## 0. Changes at a glance

| Spec / amendment section | Change |
|---|---|
| Spec §8.1 | Readers query an explicit snapshot of listed files, never globs. A reader removes the spill folders of processes that no longer exist. Readers load dictionaries without repairing replicas. (§2) |
| Spec §11.3 | The search modes compiled to SQL. A default-mode argument must be a registrable domain. `--ip` also matches IP-literal CNs. `--issued-by` matches issuers by relationship (A2 §3.2). Chain certificates are excluded unless asked for. (§3) |
| Spec §11.5 | `fetch` formats, every distinct chain for `--with-chain`, and an opt-in `--with-entries`. (§4) |
| Spec §11.6 | Export writes atomically, never overwrites without `--force`, and records the snapshot's committed heads. (§5) |
| Spec §8.3 P11 | The post-commit audit and `state/health.json`. (§6) |
| A2 §4.4, spec §15 M1–M4 | The bloom-filter benchmark and its decision rule; the live smoke test; the seed edit. (§7) |

---

## 1. Scope

**Plan 4 is the read path:**
- the `query` package;
- `search`, `fetch` and export;
- the post-commit audit;
- the bloom-filter benchmark;
- then the live smoke test and the seed edit.

It may be split into two plans:
- **4A:** `query`, `search`, `fetch`, export (§2–§5);
- **4B:** health, the benchmark, the smoke test and the seeds (§6–§7).

**Not in Plan 4:**
- `explore` (the TUI): Plan 5. It reuses `query` unchanged, so `search` and `explore` give identical results.
- A tiled `LogSource`: a v1 non-goal (spec §1.2).
- Version transitions, `gc`, `verify --full` and `repair` hardening: Plan 6.

---

## 2. The snapshot and the reader session (refines spec §8.1)

### 2.1 The snapshot

Every read command starts with `query.Open(root, asOf)`:

1. It lists the committed batches through `commit.ListCommitted`, which checks every `_COMMIT.json` and `_DERIVED.json` and the size of every listed file.
2. With `--as-of N` it keeps batches with `commit_seq ≤ N`. Without it, the highest `commit_seq` is pinned, and every output reports it.
3. For each table it builds the **explicit list of files a manifest lists** (`Manifest.Listed`). It never uses globs. A batch committed, or a file placed by `rebuild`, during a query does not affect it.

**Derived tables** are used only while `ACTIVE.json` marks them complete. Otherwise the command exits 1: "certs and names are being built: run `ctvault rebuild`". A partial table is never presented as complete.

### 2.2 The reader's DuckDB session

- **The session:** in memory, owned by the process.
- **Spill:** to `tmp/duckdb-<pid>/`, removed on exit. The spill limit uses spec §10.1's formula: the headroom below the cap, minus 1 GiB.
- **Caching:** the Parquet metadata cache is on.
- **Threads:** every core. Readers do not need byte-identical files, and every result order comes from an explicit `ORDER BY` with a unique tie-breaker.

### 2.3 Strictly read-only

Readers take no lock and never write to `dataset/`, `state/` or `vault/`.
- **Dictionaries:** `vault.LoadDicts` repairs missing dictionary replicas, which is a write. Readers use a new read-only loader that verifies and never writes.
- **Leftover spill folders:** at start, a reader deletes `tmp/duckdb-<pid>/` folders whose process no longer exists (`kill(pid, 0)` returns `ESRCH`). It never touches a live process's folder. Before this, nothing removed a killed reader's spill: A1 §7 lets the writer clean only `tmp/stage` and `tmp/rebuild`.
- **Checksums:** readers check file sizes only, as `ListCommitted` does. Full checksums stay `verify`'s job. `fetch` always verifies the SHA-256 of what it returns.

---

## 3. `search` (refines spec §11.3)

### 3.1 Modes

Every mode reads `names`. The argument is normalized as ingest normalizes names: ASCII lowercase, one trailing dot removed.

| Mode | Predicate | Pruning |
|---|---|---|
| `<domain>` (default) | `etld1 = <domain>` | bloom filter on `etld1` |
| `--suffix <name>` | `etld1 = etld1(<name>) AND (name = <name> OR name LIKE '%.' \|\| <name>)` | bloom filter on `etld1` |
| `--exact <name>` | `name = <name>` | bloom filter on `name` |
| `--ip <addr>` | `name = canonical(<addr>)` (RFC 5952 for IPv6) | bloom filter on `name` |
| `--contains <s>`, `--regex <re>` | a substring or a regular expression over every name, including non-DNS CN values | **full scan**, with a warning on stderr |

**Rules:**
- **The default mode needs a registrable domain:** when the argument is not its own eTLD+1 (for example `api.example.com`), `search` exits 2 and suggests `--suffix` or `--exact`. It never guesses.
- **`--ip` also matches IP-literal CNs**, which ingest stores in canonical form with `source = 'cn'`, not only `san_ip` rows. A certificate with its address only in the CN is found.

### 3.2 Filters

| Filter | Column |
|---|---|
| `--issuer <cn>` | `issuer_cn`, exact, case-insensitive |
| `--issuer-org <o>` | `issuer_o`, exact, case-insensitive |
| `--issued-by <sha256 \| cert_id>` | the relationship rule below |
| `--key-alg`, `--kind`, `--parse-status` | `certs` |
| `--valid-at <date>` | `not_before ≤ date < not_after` |
| `--wildcard` | `names.is_wildcard` |
| `--log` | `entries.log` |
| `--since`, `--until` | `entries.ct_ts`, or `certs.not_before` with `--by not-before` |

- **Kinds by default:** `precert` and `final`. Chain certificates are included only with `--kind chain`, so a domain search never mixes in intermediates.
- **`--issued-by`** first resolves the CA certificate C (by `fetch`'s lookup). A certificate counts as issued by C when two conditions hold:
  1. its `issuer_der` equals C's `subject_der`: necessary, never sufficient;
  2. at least one relationship holds:
     - the log served it with a chain whose position 0 is C;
     - or its `authority_key_id` equals C's `subject_key_id`.

  The DER is the cross-check, and the chain or the key IDs are the mechanism (A2 §3.2). Signature verification is not part of v1 search.

### 3.3 Grouping, order and output

**Grouping**, exact within the result set:

| Group | One row per | Columns |
|---|---|---|
| `names` (default) | name | first and last seen (`ct_ts`), certificate count, up to 5 issuer CNs |
| `certs` | certificate | `sha256`, kind, issuer, validity, name count, first seen, logs |
| `issuances` | `issuance_key` | precert and final of one issuance merged |

**Order:** every sort ends with a unique tie-breaker, so results are deterministic and keyset pagination works. The defaults are `last_seen desc` for names and `first_seen desc` for certs and issuances.

**Output:** `--format table|md|json|csv`, `--fields`, `--sort`, `--limit`, `--output <file>`.
- **The default limit** is 100 rows for a terminal table. Files and the `json` and `csv` formats have no limit unless `--limit` is given.

---

## 4. `fetch` (refines spec §11.5)

### 4.1 Lookup

- **The argument:** 64 hex digits are a SHA-256, and a decimal number is a `cert_id`. Anything else is a usage error (exit 2).
- **By SHA-256:** a bloom-pruned lookup on `certs.sha256` over the snapshot's `certs` files gives `cert_id`, the vault location and the delta base.
- **By `cert_id`:** each batch's `_COMMIT.json` `cert_id_range` names the single batch to read.
- **Then:** the vault record is read (resolving a leaf-delta), its **SHA-256 is verified**, and the certificate is returned.
- **Errors:** corruption exits 5. A certificate not in the snapshot exits 1, with a message that says so.

### 4.2 Formats

| `--format` | Output |
|---|---|
| `pem` (default) | PEM |
| `der` | the exact bytes; refused to a terminal (use `--output`) |
| `text` | a deterministic CTVault dump from the extractor: subject, issuer, serial, validity, key, SANs, the extensions present, `parse_status`, and every error code with its explanation. It is not `openssl x509 -text`, and it shows what the extractor reads even from certificates OpenSSL rejects. |
| `json` | the `certs` row, its `names` rows, the vault location and the DER in base64 |

### 4.3 Options

- **`--with-chain`:** follows `entries.chain_id` → `chains` → the chain's `cert_id`s, each fetched and verified the same way.
  - `pem` concatenates the leaf and the chain.
  - `json` adds a `chain` array.
  - With `der` it is a usage error.
  - When a certificate appears in several entries with different chains, **every distinct chain** is returned, in order of first appearance.
  - A chain certificate (`kind chain`) has no entries, so it has no chain of its own.
- **`--with-entries`** lists the log entries that reference the certificate (`log`, `idx`, `ct_ts`, entry type).
  - A repeated certificate can appear in any batch, so this scans the `cert_id` column of every `entries` file. It is opt-in and documented as a scan.
  - M2's target applies to a plain `fetch`.

---

## 5. Export (refines spec §11.6)

- **What can be exported:** any `search` result, through `--output <file>` with `--format md|json|csv`.
- **How each format carries the metadata** (spec §11.6):
  - `md`: a header block above the table;
  - `json`: `{"meta": …, "rows": […]}`;
  - `csv`: the metadata in a sidecar, `<file>.meta.json`.
- **The metadata:**
  - `ctvault_version`, `generated_at`;
  - the query: text, mode, every filter, group, sort, fields and limit;
  - `as_of_commit_seq`;
  - the builders: table versions, `extractor`, `psl`;
  - for each log, the STH its last batch in the snapshot was verified against (tree size, root hash, timestamp). This is the snapshot's own committed head, not the possibly newer head in `state/heads/`;
  - `row_count` and `approximate`.
- **Reproducible:** re-running the recorded query with its `--as-of` gives the same rows in the same order, so the export is byte-identical apart from `generated_at`. This is tested.
- **Safe to write:**
  - **Atomic:** the file is written to a temp file next to the destination, fsynced and renamed.
  - **No overwrites:** an existing destination is refused unless `--force`.
  - **Large exports stream:** `csv` through DuckDB `COPY`, `json` and `md` row by row. A result is never materialized whole in Go.

---

## 6. `state/health.json` and the post-commit audit (spec §8.3 P11)

- **When:** after P10, the writer runs a short audit of the batch it just committed, through the `query` package's reader path, over the full committed snapshot including the new batch.
- **What it checks:**
  1. 8 `sha256` lookups of the batch's new certificates, each fetched from the vault and verified;
  2. 8 `name` and 8 `etld1` lookups from the batch's `names` rows;
  3. 1 `cert_id` lookup through `cert_id_range`.
- **A failure** is recorded in `state/health.json`. `update` prints a warning, and **the batch stays committed**. The audit never changes the dataset, the exit code, or what was committed.
- **`state/health.json`:**
  - fields: `format`, `passes`, `last_pass_at`, and the last 100 `failures`, each with `batch_id`, `commit_seq`, `at`, `check` and `detail`;
  - written atomically by the writer, under the lock (the writer owns `state/`).
- **`stats`** shows the passes, the failure count and the last failure, replacing its "not yet" line. `verify` (Plan 6) adds the history.
- **Configuration:** `ingest.post_commit_audit`, default `true`. Its cost grows with the number of batches, through the bloom lookups, and is measured in §7.

---

## 7. Bloom filters, measurements and seeds (A2 §4.4, spec §15 M1–M4)

### 7.1 The benchmark

- **Two writer settings compared:**
  - A2's `DICTIONARY_SIZE_LIMIT 122880`, which gives bloom filters on every column;
  - DuckDB's defaults, which give no bloom filter on `sha256` or `name`.

  DuckDB cannot choose bloom filters per column (A2 §4.4).
- **The data:** a synthetic dataset grown from the real samples' rows. Each copy of a batch gets distinct names, so pruning behaves as it would at scale:
  - every `etld1` is mapped to a per-copy variant;
  - SHA-256 values are re-derived per copy.
- **Scale points:** 10, 50 and 100 batches of 500,000 entries, up to 50 million entries and about 9 GB on `/mnt/disk`.
  - Latency is expected to grow with the number of files (footers and bloom filters read).
  - A line is fitted, its linearity checked, and the result extrapolated to the full shard: about 770 batches, 385 million entries.
- **What is measured**, first run and repeated:
  - **M2:** `fetch` by SHA-256 (50 present, 10 absent, p50 and p95) and by `cert_id`;
  - **M3:** the default search for a common and a rare domain, plus `--exact` and `--suffix`;
  - bytes per entry for `certs` and `names` under both settings;
  - the post-commit audit's cost.

### 7.2 The decision rule

**Keep A2's setting if either holds**, at extrapolated full scale:
1. without it, M2 (`fetch` under 5 s) or M3 (a typical domain under 60 s) fails;
2. it speeds up `fetch` or the default search by 3× or more, and costs at most 10% of the dataset's total bytes.

**Otherwise switch to DuckDB's defaults** for `certs` and `names`.
- **What a switch costs:** no production vault exists, so v1's writer settings can still change without a version bump (A2 §4.4). Dev vaults are rebuilt.
- **If M2 fails either way:** spec §14's Pebble checkpoints for readers become the fix, and they are designed then.

### 7.3 The live smoke test (spec §13.11, M1 and M4)

- **Setup:** the dev build, on a dev vault in `/mnt/disk` (the SSD is not available yet).
- **Consent:** CTVault asks for explicit confirmation immediately before contacting Google.
- **The run:** two real `argon2027h1` batches of 500,000 entries.
  - The first runs at a low rate (`max_rps` 5).
  - The second steps the rate up while watching 429s and `Retry-After`.
- **What it measures:**
  - **M1:** bytes per entry per component, the delta hit rate, and Pebble bytes per key;
  - **M2 and M3:** on the real batches;
  - **M4:** the sustainable rate from one IP, which sets the defaults for `workers` and `max_rps`.
- **What waits for the SSD:** the figures specific to it (throughput, fsync latency, the real disk cap).

### 7.4 Seeds

The disk-guard seeds change in Plan 4 by an **explicit, reviewed edit**, combining Plan 3C's proposal with M1:
- 3C proposed vault 840 (unchanged), Parquet 175 → 210, and Pebble 60 → 75.

The edit is presented for approval and never applied automatically (A1 §8).

---

## 8. Test matrix additions

| Layer | Command | Adds |
|---|---|---|
| Unit and fake log | `go test -race ./...` | query compilation for every mode and filter; the snapshot and `--as-of`; tables still building; `--issued-by` with chains, key IDs and a DER mismatch; `fetch` formats and corruption; export reproducibility and metadata; the audit and `health.json`; read-only behaviour (no writes outside `tmp/duckdb-<pid>/`) |
| Crash suite | `go test ./internal/commit/` | a kill during the audit: the batch stays committed, and `health.json` is valid |
| Real data | `go test -tags realdata -timeout 90m ./internal/integration/` | `search` and `fetch` on the canonical sample against independent DuckDB queries; `fetch` of every sampled certificate verified |
| Benchmark | `go test -tags realdata -run TestReadPathBenchmark -timeout 6h ./internal/integration/` | §7.1, on `/mnt/disk` |
| Live (opt-in) | `ctvault-dev` smoke command, after confirmation | §7.3 |

---

## 9. Decisions this amendment adds

These are flagged for review:

| # | Decision |
|---|---|
| 1 | Readers query explicit file lists from the manifests, never globs. Derived tables must be complete. (§2.1) |
| 2 | Readers use every core; result order always comes from an explicit `ORDER BY` with a unique tie-breaker. (§2.2) |
| 3 | A reader deletes the spill folders of processes that no longer exist; readers load dictionaries read-only. (§2.3) |
| 4 | The default search mode requires a registrable domain; otherwise exit 2 with a suggestion. (§3.1) |
| 5 | `--ip` also matches IP-literal CNs. (§3.1) |
| 6 | `--issued-by`: `issuer_der` equality plus a chain or key-ID relationship. Signature verification is out of v1 search. (§3.2) |
| 7 | Chain certificates are excluded from search unless `--kind chain`. (§3.2) |
| 8 | A default limit of 100 rows for terminal tables only. (§3.3) |
| 9 | `fetch --with-chain` returns every distinct chain; `--with-entries` is an opt-in scan; `text` is CTVault's own dump. (§4) |
| 10 | Exports are atomic, never overwrite without `--force`, and record the snapshot's committed heads. (§5) |
| 11 | The post-commit audit: 8 + 8 + 8 + 1 lookups, the last 100 failures kept, on by default. (§6) |
| 12 | The bloom-filter decision rule and the synthetic scale points. (§7.1–7.2) |
| 13 | The live smoke test on the dev build, with confirmation before contacting Google. (§7.3) |
