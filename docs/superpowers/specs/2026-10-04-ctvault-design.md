# CTVault — Design Spec

- **Date:** 2026-10-04
- **Status:** Draft, awaiting review
- **Origin:** `ct_log_local_search_platform.md` (idea note) plus a brainstorming session that approved every section below
- **Next step after approval:** implementation plan (superpowers:writing-plans)

---

## 1. Purpose

CTVault turns public Certificate Transparency (CT) logs into a local, cryptographically verified research dataset of X.509 certificates.

- **Primary use:** analysis across all certificates (issuance, cryptography, names, and log behaviour) with the DuckDB CLI and Jupyter (Polars or DuckDB).
- **Secondary use:** domain reconnaissance and raw certificate retrieval through a CLI and a TUI.

### 1.1 Goals (v1)

1. Ingest Google `argon2027h1` (RFC 6962) from index 0, incrementally. Verify every batch cryptographically against a signed tree head.
2. Keep every unique certificate's raw DER, compressed and deduplicated by SHA-256, so new fields can be extracted later by re-parsing local data.
3. Answer research questions in four areas:
   - **A** issuance
   - **B** cryptography
   - **C** names
   - **E** log behaviour

   Area **D** (policies and extensions) is deferred, but must be addable without migrating existing data.
4. Keep the dataset open and portable: Parquet files plus generated DuckDB views.
5. Ship a CLI with `init`, `logs`, `update`/`ingest`, `stats`, `search`, `explore` (TUI), `fetch`, export, `rebuild`, `verify` and `repair`.
6. Never exceed 85% usage on any CTVault volume of the 4 TB external SSD, and never prune source data automatically.
7. Allow more logs, including static-ct-api tiled logs, full CT history, and D fields to be added later without re-ingesting.

### 1.2 Non-goals for v1

- D tables
- A tiled `LogSource` implementation (only the interface and a test fake exist)
- Built-in reports
- HTTP API and web UI
- Monitoring and notifications
- DNS, ASN and WHOIS enrichment
- macOS host support
- Distributed or multi-host ingestion

### 1.3 Success criteria

1. `argon2027h1` is ingested from index 0 to a pinned signed tree head (STH). Every batch passes a consistency proof, and the final root equals the STH root.
2. Any committed certificate can be fetched by SHA-256 or `cert_id`, byte-exact and SHA-256 verified.
3. The DuckDB CLI and Jupyter can query `entries`, `certs` and `names` through `views.sql` with no CTVault process running.
4. SIGKILL at any commit boundary recovers to a valid committed prefix (§13.5).
5. No CTVault volume ever exceeds the configured cap (default 85%).

---

## 2. Decision log

| # | Decision | Choice |
|---|---|---|
| D1 | Primary purpose | CT as a research dataset (option D). Domain search is secondary. |
| D2 | Coverage | Start with one shard, `argon2027h1`. Design for more logs and full history without re-ingesting. |
| D3 | v1 research areas | A, B, C and E. D is deferred, with a migration-free seam. |
| D4 | Raw retention | Every unique certificate's raw DER is kept, compressed and deduplicated by SHA-256. |
| D5 | Analysis tools | DuckDB CLI and Jupyter with Polars or DuckDB, over Parquet. Built-in reports come later and only for common analyses. |
| D6 | Hardware | One 4 TB external SSD with a hard cap of 85% usage. |
| D7 | Architecture | Two layers: an immutable source of truth plus rebuildable derived Parquet tables. |
| D8 | Language and runtime | Go, as a single binary. Embedded DuckDB through cgo is accepted. |
| D9 | Collector | A custom collector behind a `LogSource` interface. `scrape-ct-log` is not used: it supports RFC 6962 only and emits a JSON intermediate of about 7.4 KB per entry. |
| D10 | Raw intermediates | None. Data streams straight into the vault and Parquet. |
| D11 | Fingerprint index | Pebble. It is private to the writer and rebuildable from the vault. |
| D12 | Commit unit | 500,000-entry batches by default (`ingest.batch_size`). Each batch has a deterministic ID, a manifest and a commit marker. |
| D13 | Verification | A compact Merkle range per log, persisted with each commit. Every batch is verified against the pinned STH by consistency proof, and the final root is compared directly. |
| D14 | Internal identity | `cert_id` is a global, sequential, immutable `uint64` that is never reused. SHA-256 is the permanent external identity. |
| D15 | Final-cert storage | A `leaf-delta` record compresses a final certificate against its own earlier precertificate. |
| D16 | Parser | A field-level lenient extractor built on `cryptobyte`, differentially tested against `crypto/x509`. |
| D17 | Issuance counting | Whole-dataset counts use `approx_count_distinct` (HyperLogLog) and are always labelled approximate. Bounded or time-sliced queries use exact counts. |
| D18 | Readers | Readers never open Pebble. They resolve certificates through committed Parquet, using bloom-filtered hex SHA-256 and vault locations. |
| D19 | Parquet binary columns | No `BLOB` columns at all. Binary identifiers are stored as lowercase hex `VARCHAR`, because of a DuckDB bloom-filter bug (§3.6). |
| D20 | Parser upgrades | Side-by-side rebuild. The current version stays active and ingestion never stops (§7.8). |
| D21 | Filesystems | Linux with ext4 is supported and tested. Untested filesystems are rejected unless explicitly overridden. Non-durable ones are always rejected (§9.3). |

---

## 3. Ground truth measured on 2026-10-04

These are sample-based measurements taken during brainstorming. Milestone 1 re-measures them at batch scale (§15).

### 3.1 Logs

**Chrome log list:** v93.3, published 2026-10-03T13:35:24Z.

| Log | State | Tree size | Note |
|---|---|---|---|
| `argon2026h1` | not listed (closed) | 2,807,501,296 | Frozen |
| `argon2026h2` | usable, expiry Jul–Dec 2026 | 3,410,627,151 | Nearly finished |
| `argon2027h1` | usable, expiry Jan–Jun 2027 | 383,407,509 → 383,442,431 in 249 s | **About 140 entries/s, roughly 12M/day.** The v1 target. |
| `parcelyard2027h1` | tiled (static-ct-api) | about 101.1M | |

Google has **no RFC 6962 Argon shard for 2027h2.** Its 2027h2 logs (ParcelYard and PlumbersArms) are tiled only, which is why `LogSource` must support both protocols.

### 3.2 Fetching

- `get-entries` returns at most **32 entries** per request.
- A 60-second probe from one IP with 4 workers got 783 OK responses and 194 × 429. That is **about 13 OK requests/s, or about 418 entries/s**, with 0.27 s mean latency.
- Sustained fetching with backoff ran at about 237 entries/s (32,768 entries in 2m18s).
- The JSON response costs **7,409 B per entry**, because the chain is repeated inline.
- The initial catch-up of about 383M entries therefore takes **2–3 weeks** on one IP. Once caught up, keeping pace needs about a third of measured capacity.
- `get-sth-consistency` works: 383,000,000 → 383,819,928 returned a 22-node proof. The first attempt was rate-limited.

### 3.3 Certificates

| Sample | Size | Precert share | Leaf DER mean | Other |
|---|---|---|---|---|
| Spread across the log | 1,184 entries at 40 offsets | 72% | 1,514 B (median 1,449, p95 2,166) | |
| Contiguous | 32,768 entries at 380,000,000 | 68% | 1,114 B | 0 parse failures (Python `cryptography` 43), 0 duplicates, 93 issuers |

- **The issuance key links precerts to their final certs.** In the contiguous sample, 2,555 final certs matched their precert within the same window. The key is SHA-256 of the log's precert TBS, compared with the final cert's TBS with the SCT-list extension removed.
- **Final certs carry most of the vault's weight.** They are larger (1,808 B raw, because of the SCT list) and make up about 62% of vault bytes while being about 32% of entries.

### 3.4 Compression (zstd level 19)

| Method | Ratio or size |
|---|---|
| Per certificate, no dictionary | 1.21× |
| Per certificate, global 110 KB dictionary (contiguous sample) | 1.96×, **568 B/cert** |
| Same dictionary, spread sample | 1.84×, **824 B/cert** |
| Block compression of many certificates | 1.91–1.97× |
| Per-issuer dictionaries (top 7 issuers) | +0.9% only. **Rejected.** |
| Final cert against its own precert as dictionary | 1,090 → 904 B, **−17.1%** |

### 3.5 Parquet (DuckDB 1.5.6, zstd, 32,768 rows), bytes per entry

| Table | Total | Main columns |
|---|---|---|
| `entries` (naive) | 85.4 | `cert_sha` 32.5, `leaf_hash` 32.5, `issuance_key` 15.3, `ts` 2.5, `idx` 1.0, `chain_id` 0.8, `ikh` 0.7 |
| `certs` (naive) | 68.2 | `sha` 32.5, `serial` 16.9, `subject_cn` 12.4, `not_after` 2.2, `not_before` 1.9, others ≤0.6 each |
| `names` (naive) | 59.1 | `sha` 32.8, `name` 19.1, `etld1` 7.0. There are 1.95 names per certificate. |

**Cost of dictionary encoding plus bloom filters:**

| Column | Extra bytes per entry |
|---|---|
| SHA-256 as hex `VARCHAR` (vs. plain `BLOB`) | +6.5 |
| `etld1` | +0.5 |
| `name` | +6.7 |

### 3.6 DuckDB bloom-filter bug (v1.5.6)

**Equality filters with a constant on a `BLOB` column that has a bloom filter return false negatives.**

- With dictionary encoding forced on SHA-256 `BLOB`s, lookups returned 0 rows instead of 1.
- On a **default-written** file, the low-cardinality `BLOB` column `issuer_key_hash` got a bloom filter automatically, and a literal lookup returned **0 rows instead of 7,096**.
- The same values matched correctly through a join.
- Hex `VARCHAR` columns with bloom filters are correct: 2,000 of 2,000 sampled values and all literal lookups matched.

**Consequences:** CTVault never writes `BLOB` columns (D19), keeps a regression test (§13.7), and should report the bug upstream (§15).

### 3.7 Tools

- **`scrape-ct-log`:** last push 2026-06-07. Its README covers RFC 6962 only, with no tiles or static-ct-api.
- **`github.com/duckdb/duckdb-go/v2`:** the official Go driver. Its prebuilt bindings statically link the Parquet, JSON, ICU and autocomplete extensions, and it has an Appender API.
- **`github.com/klauspost/compress/dict.BuildZstdDict`:** trains zstd dictionaries in pure Go.

---

## 4. Architecture

### 4.1 Pipeline

```text
LogSource (rfc6962 in v1, tiled later)
   │ raw entries, possibly out of order
   ▼
Fetcher ── worker pool, adaptive rate limit, retries, reassembles in index order
   ▼
Merkle accumulator ── leaf hashes in strict index order, compact range
   ▼
Parser ── leaf → certificate DER, SHA-256, issuance key, extracted fields, names
   ▼
Dedup ── writer-private Pebble: SHA-256 already in the vault?
   │ new certificate              │ every entry
   ▼                              ▼
vault append                 entries row
derived rows (certs, names)
   ▼
Batch commit ── vault fsync → Merkle verify → staged Parquet → canary → _COMMIT.json
                → atomic directory rename (the commit point) → Pebble apply
```

### 4.2 Go packages

Each package has one purpose.

| Package | Responsibility |
|---|---|
| `logsource` | The `LogSource` interface and the `rfc6962` implementation. Later: `tiled`. |
| `loglist` | Parses Chrome's log list v3. Pins each log's metadata and public key when the log is added. |
| `fetch` | Worker pool, token bucket with adaptive rate, retry and backoff, in-order reassembly. |
| `merkle` | RFC 6962 leaf hashing, compact range, STH signature verification, consistency-proof verification. |
| `leaf` | `MerkleTreeLeaf` and `extra_data` decoding, leaf error classification. |
| `vault` | Segments, record codec, dictionaries, `leaf-delta`, multiple directories, scan and truncate. |
| `index` | Pebble wrapper (`c/<sha256>` keys, applied markers). Writer-private. |
| `extract` | The field-level lenient X.509 extractor built on `cryptobyte`. |
| `derive` | The registry of versioned table builders (`certs`, `names`, and later the D tables). |
| `dataset` | Parquet staging through embedded DuckDB, `ACTIVE.json`, `views.sql` generation, batch snapshots. |
| `commit` | Intents, `_COMMIT.json`, the commit protocol, recovery, `ID_FLOOR`. |
| `volume` | `VAULT_ID` and `DIR_ID`, filesystem UUID, mount-point and filesystem-type checks. |
| `diskguard` | Usage per volume, peak-space preflight, mid-batch hard checks, projections. |
| `ingest` | Orchestrates update cycles, batches, and dual building during rebuilds. |
| `query` | Search semantics, `--as-of` snapshots, keyset pagination, export. Shared by `search`, `explore`, `fetch` and `stats`. |
| `tui` | The `explore` interface in Bubble Tea. Strictly read-only. |
| `cmd/ctvault` | The CLI entry point. |

### 4.3 On-disk layout

The SSD is mounted at a configurable root, for example `/mnt/ctvault`.

```text
<root>/
├── VAULT_ID                      vault UUID, volumes with filesystem UUIDs, durability class
├── ctvault.toml                  tunables (§11.1)
├── views.sql                     generated from ACTIVE.json; used by ctvault, the DuckDB CLI and Jupyter
├── state/
│   ├── LOCK                      writer flock
│   ├── ID_FLOOR                  durable high-water mark for cert_id
│   ├── intent/<batch-id>.json    in-flight batch intent
│   ├── pebble/                   writer-private index (rebuildable)
│   ├── incidents/<ts>/           CT verification failure evidence
│   └── health.json               results of post-commit audits
├── vault/                        first vault directory (DIR_ID inside)
│   ├── DIR_ID
│   ├── dict/<id>.zdict           dictionaries, replicated into every vault directory
│   └── segments/<segment-id>.seg
├── dataset/
│   ├── ACTIVE.json               active and building version of each derived table
│   └── log=<log>/batch=<first>-<last>/      first and last index, zero-padded to 12 digits
│       ├── entries.parquet       source layer
│       ├── chains.parquet        source layer: chains first seen in this batch
│       ├── certs.p<N>.parquet    derived, table version N
│       ├── names.p<N>.parquet    derived, table version N
│       ├── quarantine.ndjson     only if a semantic leaf error occurred (§5.4)
│       └── _COMMIT.json          commit manifest
├── tmp/                          staging, rebuild scratch, DuckDB spill (counted by the disk guard)
└── logs/                         JSON-lines logs, rotated and capped at 1 GiB in total
```

---

## 5. Collector

### 5.1 The `LogSource` interface

```go
type LogSource interface {
    Info() LogInfo                                        // name, log_id, public key, URLs, temporal interval
    Head(ctx context.Context) (SignedHead, error)         // RFC 6962 get-sth | tiled: /checkpoint (signature verified)
    Fetch(ctx context.Context, start, end uint64) ([]RawEntry, error) // may return fewer than requested
    ConsistencyProof(ctx context.Context, first, second uint64) ([][32]byte, error)
    Issuer(ctx context.Context, fp [32]byte) ([]byte, error) // chain certificate DER by SHA-256
}

type RawEntry struct {
    Index         uint64
    LeafInput     []byte     // exact MerkleTreeLeaf bytes as served (source of LeafHash)
    ExtraData     []byte     // exact extra_data bytes as served
    LeafHash      [32]byte   // SHA-256(0x00 || LeafInput)
    Timestamp     uint64     // ms; decoded from LeafInput (0 on semantic leaf error)
    Type          EntryType  // X509 | Precert | Unknown
    CertDER       []byte     // final certificate, or the precertificate from extra_data
    PrecertTBS    []byte     // precert only: the log's TBS (poison removed, issuer fixed)
    IssuerKeyHash [32]byte   // precert only
    Chain         [][32]byte // chain referenced by SHA-256 fingerprint
    LeafErr       LeafErrorCode
}
```

Chain certificates are referenced by fingerprint, which is how tiled logs already work (`/issuer/<sha256>`). The RFC 6962 implementation hashes the inline chain DER and serves `Issuer` from an in-memory cache.

### 5.2 RFC 6962 implementation

- **Endpoints:** `get-sth`, `get-entries` and `get-sth-consistency`.
- **STH signatures** are verified with the log key pinned when the log was added.
- **Request alignment:** requests align to the server's current page size.
- **Short reads are authoritative only for the request they answer.** The fetcher adapts the next request size but never treats a short response as a permanent page boundary. It re-queues the remainder.
- **Indexes come from request position.** An entry's index is `request.start + position`, never derived from counts.

### 5.3 Fetcher

- **Workers:** the default is 4 (`ingest.workers`). They fill slots in the current batch's index range.
- **Rate control:** one shared token bucket, capped at `ingest.max_rps`.
  - A 429 or 5xx halves the rate and honours `Retry-After`. The failed request retries with exponential backoff plus jitter, from 1 s up to a 60 s cap.
  - Sustained success raises the rate by a fixed step.
- **Ordering:** results arrive out of order. A reorder buffer releases entries to the Merkle accumulator and the parser **strictly in index order**.
- **Stall rule:** if a batch makes no progress for `ingest.stall_timeout` (default 15 min), it is abandoned and recovered (§8.5).

### 5.4 Leaf failure classes

| Class | Detection | Behaviour |
|---|---|---|
| **Transport or framing corruption** | Invalid JSON, invalid base64, missing fields, a truncated body, or an entry count of 0 | The exact leaf bytes cannot be established, so **nothing advances**. The request is retried. If the batch cannot be completed, it is abandoned and refetched. An index is never invented or skipped. |
| **Semantic leaf error** | `leaf_input` and `extra_data` decode as bytes, but the `MerkleTreeLeaf` or `extra_data` structure cannot be interpreted | The leaf hash is still computed from the exact bytes and fed into the Merkle range. The `entries` row has a `leaf_error` code and a null `cert_id`. The raw bytes go to the batch's `quarantine.ndjson`, which commits atomically with the batch. |

If corruption in transit produces a valid-looking but wrong `leaf_input`, the batch's consistency proof fails (§5.5). The batch is then refetched.

### 5.5 Merkle verification

- **State:** each log keeps an RFC 6962 compact range covering leaves `[0, next_index)`, about 1 KB. Leaf hashes are appended in strict index order.
- **Update cycles pin one STH.** For each batch ending at `m`:
  - If `m == sth.tree_size`, the computed root must equal `sth.root_hash`.
  - Otherwise CTVault fetches `ConsistencyProof(m, sth.tree_size)` and verifies it from the computed root at `m` to the signed root.
- **Failure:** the batch is discarded and refetched once from scratch. A repeat failure is an incident (§12).
- **Persistence:** the compact range is persisted only inside `_COMMIT.json`, so the Merkle state commits atomically with the data (§8.3).
- **Starting point:** every log is ingested from index 0, which keeps the full log verifiable.

### 5.6 Update cycles

`ctvault update`, with alias `ingest`, runs one cycle:

1. Fetch and verify an STH and pin it.
2. If `tree_size` is unchanged, exit 0.
3. Ingest batches of `[start, min(start + batch_size, tree_size))` until `tree_size` is reached.
4. Each batch commits only after its verification succeeds.
5. Only then fetch a newer STH.

`--follow` repeats cycles every `ingest.follow_interval` (default 10 min). It is the mode used for the multi-week catch-up.

---

## 6. Source layer

### 6.1 Identifiers

| Identifier | Definition | Rules |
|---|---|---|
| `cert_id` | `uint64`, starting at 1, assigned at first vault append | Immutable and never reused. Gaps are allowed after a crash (§8.6). |
| SHA-256 | Hash of the exact DER | The permanent external identity. Lowercase hex in Parquet; 32 raw bytes in Pebble keys. |
| `issuance_key` | 16-byte truncation of SHA-256(precert: log TBS; final: TBS without the SCT-list extension) | Links a precert to its final cert. **Never an identity.** |
| `leaf_hash` | RFC 6962 leaf hash | Kept for later integrity checks and diagnostics. |
| `chain_id` | SHA-256 of the concatenated chain fingerprints, in order | Keys the `chains` table. |
| batch ID | `<log>/<first>-<last>`, inclusive indexes, zero-padded to 12 digits | Deterministic. |
| `commit_seq` | Global `uint64`, incremented once per committed batch | Orders commits across logs. |

### 6.2 Vault

**Segments**
- Segments are append-only files named by a global segment ID. They roll over at `vault.segment_size` (default 1 GiB).
- **Header:** magic `CTVSEG01`, format version, vault UUID, segment ID, first `cert_id`, creation time.

**Record format**

```text
uvarint body_len | u8 kind | uvarint cert_id | ref | zstd frame
  kind 1 = leaf        ref = uvarint dict_id   (0 = no dictionary)
  kind 2 = leaf-delta  ref = uvarint base_segment, uvarint base_offset
  kind 3 = chain       ref = uvarint dict_id
```

- The zstd frame has the content checksum enabled and its own dictionary ID omitted.
- SHA-256 is not stored in the record. It is recomputed on read and verified against the expected value.

**Dictionaries**
- Records written before the first dictionary exists use `dict_id 0`.
- Dictionary 1 is trained with `dict.BuildZstdDict`, using up to 110 KB, from a sample of the first batch's leaf certificates. Later batches use it.
- Dictionaries are immutable, never deleted, and replicated into every vault directory's `dict/`.
- Retraining creates a new ID. Old records keep their old dictionary.

**`leaf-delta` (D15)**
- The writer keeps an in-memory LRU of `issuance_key → (segment, offset)` for recently vaulted precerts. The default capacity is 2M entries, about 4 hours of log at about 128 MB of RAM. At startup it is warmed from the last 4 committed batches.
- A final certificate is delta-encoded only if its precert record exists **earlier in the vault**. That can include an earlier record of the same in-flight batch, because truncation always removes the newest records first.
- If no suitable precert is available, the final certificate is stored as a normal `leaf` record.
- **Decoding** reads the base record (which may itself be a `leaf`), decompresses it, and uses it as a raw-content dictionary for the delta frame. The reconstructed DER must match its expected SHA-256.
- An unresolvable base, a checksum failure or a SHA-256 mismatch is **vault corruption** and is never ignored.
- `stats` reports the link hit rate and the bytes saved.

**`vault.dirs`**
- Vault directories are an ordered list. Each has a `DIR_ID` and a filesystem UUID recorded in `VAULT_ID` (§9).
- New segments go to the first directory that passes the disk guard.
- Segments are located by scanning the directories at startup. A duplicate segment ID counts as corruption.

### 6.3 Pebble (writer-private)

| Key | Value |
|---|---|
| `c/<sha256 32B>` | `uvarint cert_id, segment, offset, len` |
| `applied/<log>` | last `commit_seq` applied |

- Pebble is used for deduplication during ingest. It holds an in-memory indexed batch until commit, which also catches duplicates within a batch.
- **It is fully rebuildable by scanning the vault** (`ctvault repair --reindex`).
- **Readers never open it** (D18).

### 6.4 The `entries` table (source layer)

`entries` has one row per log entry and is partitioned by `log=` and `batch=`.

| Column | Type | Notes |
|---|---|---|
| `idx` | `UBIGINT` | Index in the log |
| `ct_ts` | `TIMESTAMP_MS` | Timestamp from `MerkleTreeLeaf` |
| `entry_type` | `VARCHAR` | `x509`, `precert` or `unknown` (dictionary-encoded) |
| `cert_id` | `UBIGINT` | Null on a leaf error |
| `leaf_hash` | `VARCHAR` | 64 hex characters |
| `issuance_key` | `VARCHAR` | 32 hex characters; null on a leaf error |
| `issuer_key_hash` | `VARCHAR` | Hex; precerts only |
| `chain_id` | `VARCHAR` | Hex |
| `leaf_error` | `VARCHAR` | Stable error code, or null |

The estimate is about **60 B per entry**, derived from the measured 85.4 by replacing the SHA-256 column with `cert_id` and adding the hex overhead.

### 6.5 The `chains` table (source layer)

`chains.parquet` holds rows of `chain_id, position, cert_id` for chains first seen in the batch. Chain certificates are vaulted as `kind=chain` and get their own `cert_id` and `certs` rows.

---

## 7. Derived layer

### 7.1 Extractor (D16)

- The extractor is built on `golang.org/x/crypto/cryptobyte`. It reads each field independently:
  - version and serial
  - signature algorithm, issuer, validity and subject
  - SPKI, meaning the algorithm OID, parameters or curve, and the key size (RSA modulus bits)
  - extensions, as `(oid, critical, raw)`, with SAN and AKI/SKI decoded
- A malformed field adds a stable error code and extraction continues.
- `parse_status` is `ok`, `partial` or `failed`.
- **No certificate is ever dropped.** A `failed` certificate still has a `certs` row, and its DER stays in the vault.
- Error codes are stable, compact strings such as `serial_negative`, `time_bad_format` or `san_ip_bad_len`. The CLI maps codes to explanations (`ctvault explain-error <code>`).

### 7.2 Determinism and versioning

- **Determinism:** the same DER plus the same table version always produces identical rows. The rules:
  - no map-order dependence
  - no wall-clock input
  - a fixed row order: `certs` by `cert_id`; `names` by `cert_id`, then SAN order, then CN
  - fixed Parquet writer settings
- **Byte-identical files** are expected from the same binary and are tested.
- **Each derived table has a version `N`,** encoded in the file name as `certs.p<N>.parquet`.
- The version registry, compiled into the binary, maps `(table, N)` to:
  - `extractor_version`
  - `schema_sha256`
  - `psl_snapshot`, the `golang.org/x/net` module version and its embedded public-suffix list date, for tables that use eTLD+1
- This metadata is written into each file's Parquet key-value metadata (`ctvault.table`, `ctvault.version`, `ctvault.extractor`, `ctvault.schema_sha256`, `ctvault.psl`) and into `_COMMIT.json`.
- Any change to the extractor, schema or suffix list bumps `N` for every affected table.

### 7.3 The `certs` table

`certs` has one row per unique certificate: leaf, precert or chain. It lives in the batch where the certificate was first vaulted. The estimate is about **80 B per entry**.

`kind` records how the certificate was **first vaulted**:
- `precert` comes from a `precert_entry`
- `final` comes from an `x509_entry`
- `chain` comes from a chain position

`has_ct_poison` is extracted independently, so research can catch mismatches between the two.

| Group | Columns |
|---|---|
| Identity | `cert_id UBIGINT`, `sha256 VARCHAR` (hex, bloom filter), `kind VARCHAR` (`precert`, `final` or `chain`), `has_ct_poison BOOLEAN` |
| Vault | `vault_seg UINTEGER`, `vault_off UBIGINT`, `vault_len UINTEGER`, `delta_base_cert_id UBIGINT` (null unless `leaf-delta`) |
| Parse | `parse_status VARCHAR`, `parse_errors VARCHAR[]` (codes) |
| A: issuance | `serial VARCHAR` (hex of the raw INTEGER content bytes, so sign and leading zeros are preserved), `issuer_dn VARCHAR` (deterministic RFC 4514 rendering), `issuer_o`, `issuer_cn`, `authority_key_id VARCHAR` (hex), `not_before TIMESTAMP`, `not_after TIMESTAMP` |
| B: cryptography | `key_alg VARCHAR` (`rsa`, `ecdsa`, `ed25519`, `ed448`, `dsa` or `other`), `key_bits USMALLINT`, `key_curve VARCHAR`, `spki_alg_oid VARCHAR`, `sig_alg VARCHAR` (name, or the OID if unknown) |
| C: summary | `subject_cn VARCHAR`, `n_dns_names USMALLINT`, `n_ip_names USMALLINT`, `has_wildcard BOOLEAN` |
| Chain certificates only | `subject_key_id VARCHAR` (hex; null for leaves, saving about 70 GB at full shard) |

### 7.4 The `names` table and normalization

`names` has one row per name per certificate. The estimate is about **35 B per entry**, including bloom filters on `name` and `etld1`.

| Column | Type |
|---|---|
| `cert_id` | `UBIGINT` |
| `source` | `VARCHAR`: `san_dns`, `san_ip` or `cn` |
| `name` | `VARCHAR`, normalized as described below |
| `dns_valid` | `BOOLEAN` |
| `is_wildcard` | `BOOLEAN` |
| `tld` | `VARCHAR`: null unless `dns_valid` |
| `etld1` | `VARCHAR`: null unless `dns_valid` and a registrable domain exists |

**Normalization depends on the source:**
- **`san_dns` names, and CN values that are DNS names:**
  - Lowercase ASCII and strip one trailing dot.
  - A leftmost label of exactly `*` sets `is_wildcard`, and `etld1` is computed on the name without `*.`.
  - `dns_valid` is lenient: labels of 1–63 characters made of letters, digits, `-` and `_`, with a total length of at most 253.
  - A-labels (`xn--`) are kept as-is. v1 does not convert IDNA.
  - `tld` and `etld1` come from `x/net/publicsuffix`, pinned through `psl_snapshot`.
- **`san_ip`:**
  - 4 bytes are rendered as a dotted quad. 16 bytes are rendered in RFC 5952 canonical form.
  - Any other length becomes the hex of the raw bytes, with `dns_valid = false`, plus the error `san_ip_bad_len` on the certificate.
  - `tld` and `etld1` are null.
- **`cn` values that are neither a DNS name nor an IP literal:**
  - Stored exactly as decoded. Invalid UTF-8 is replaced with escape sequences deterministically.
  - `dns_valid = false`, with no public-suffix processing. They remain searchable through `--contains` and `--regex`.
  - A CN row is emitted only if its normalized value differs from every SAN of that certificate.

### 7.5 Builder registry (the D seam)

```go
type Builder interface {
    Table() string
    Version() int                       // N
    Schema() Schema                     // fixed column list; no BLOB types allowed
    Build(c *extract.Cert, ctx BuildCtx) ([]Row, error)
}
```

- Ingest runs every active builder, and every building builder during a transition (§7.8).
- `rebuild` runs whichever builders it is asked for.
- The registry keeps each table's **current version N and its previous version N−1**, so it can dual-build during a transition. Older versions are removed in a later release.
- A binary refuses to run if `ACTIVE.json` is older than N−1. The required action is to upgrade through the intermediate release.
- **Adding D** means registering new tables, each built from the vault, such as:
  - `cert_policies`
  - `cert_ekus`
  - `cert_key_usage`
  - `cert_aia`
  - `cert_crl_dps`
  - `cert_scts`

  No existing file changes.

### 7.6 Views (`views.sql`)

`views.sql` is generated from `ACTIVE.json` and replaced by atomic rename. It defines:
- `entries`, `chains`, `certs` and `names`, through `read_parquet` globs over committed batch directories with `hive_partitioning` and `union_by_name`
- `batches`, through `read_json` over `_COMMIT.json`
- `entry_certs`, joining `entries` with `certs` on `cert_id`
- `logging_delay`, defined as `ct_ts − not_before`, for E
- `<table>_building`, for tables that are still being built

The CLI and the TUI query explicit snapshots of committed batch files instead of globs (§8.1). The documentation explains that a commit landing mid-query can make glob-based joins in an external DuckDB session momentarily inconsistent.

### 7.7 Issuance counting (D17)

- **Exact:** `COUNT(DISTINCT issuance_key)` for bounded or time-sliced queries, for example one month.
- **Whole dataset:** `approx_count_distinct(issuance_key)` (HyperLogLog, about 1–2% error).
- Every CTVault output that contains an approximate value labels it: `≈` in tables, and `approximate: true` in export metadata.

### 7.8 Rebuild and `ACTIVE.json` (D20)

`ACTIVE.json` has this shape:

```json
{"seq": 41, "tables": {
  "certs": {"active": 3, "building": 4, "status": "building"},
  "names": {"active": 3, "building": null, "status": "complete"}}}
```

**Side-by-side rebuild (the default):**
1. A writer whose binary carries a newer version N sets `building = N` and starts background rebuild workers (`rebuild.workers`). This happens in `update` or in standalone `ctvault rebuild`.
2. Historical batches get `certs.pN.parquet`, staged in `tmp/rebuild/` and renamed into the committed batch directory. Views do not see these files.
3. While the rebuild is active, **new batches build both N−1 and N.** If dual building falls behind, the missing N batches are recorded in `state/rebuild.json` and caught up. **CT ingestion never stops.**
4. Once every committed batch has `pN`:
   - `ACTIVE.json` is replaced atomically with `active = N` and `seq + 1`, and `views.sql` is regenerated.
   - Readers pick up the change on their next query. A running `explore` shows a "dataset version changed — reload" banner.
5. The `pN−1` files are deleted by `ctvault gc`, or by the next writer process (`update` or `rebuild`) once 24 hours have passed since the switch. Running `explore` sessions therefore have time to reload. These are derived files, not source data.

**In-place mode (`--in-place`, explicit only):**
- It is used when the disk guard cannot fit a side-by-side copy (§10.1).
- `pN` replaces `pN−1` batch by batch, and `status` becomes `mixed`.
- `stats` shows a prominent warning.
- Reports, and any query that would mix versions, refuse to run without `--parser-version` or `--allow-mixed`.

**New tables (D):**
- A new table starts as `{active: null, building: 1}`.
- Ingest writes it for new batches while the rebuild backfills.
- It is exposed only as `<table>_building` until complete.

---

## 8. Batch commit and recovery

### 8.1 Writer lock and reader model

- **One writer process.** `update`, `rebuild`, `repair` and `gc` take an exclusive `flock` on `state/LOCK`. If the lock is held, the command exits 1 and names the PID holding it.
- **Readers take no lock and never write** to `dataset/`, `state/` or `vault/`. They may write only to their own `tmp/duckdb-<pid>/` spill directory and to export destinations the user chooses.
- **Each reader query snapshots the committed batch list.** Only directories with a valid `_COMMIT.json` are included, optionally filtered by `--as-of <commit_seq>`. The reader queries those explicit files.
- **A batch becomes visible all at once** through a single directory rename.

### 8.2 Batch identity

A batch covers `[first, last]` within one update cycle. `last = min(first + batch_size, sth.tree_size) − 1`. Its directory is `dataset/log=<log>/batch=<first>-<last>/`, with 12-digit zero padding.

### 8.3 Commit protocol

| Step | Action |
|---|---|
| P0 | **Preflight.** Writer lock held, volume checks (§9), disk-guard peak preflight (§10.1), `ID_FLOOR` loaded. |
| P1 | **Intent.** Write `state/intent/<batch-id>.json`, then fsync it and the directory. It contains the batch range, the pinned STH, the vault tail `(segment, offset)`, `next_cert_id`, the starting compact range and the builder versions. |
| P2 | **Process.** Fetch and reassemble in index order, accumulate the Merkle range, classify leaves, and extract. Append new certificates to the vault (no fsync yet). Advance `ID_FLOOR` durably before assigning any `cert_id` at or above it (§8.6). Hold Pebble writes in an in-memory indexed batch. Collect Parquet rows. Segment rollover fsyncs the old segment, creates the new segment and its header, and fsyncs both plus the directory. |
| P3 | **Vault durability.** fsync every segment touched since P1 and their directories. |
| P4 | **Merkle verification** (§5.5). On failure, abandon the batch (§8.5) and refetch it once. A second failure is an incident and exit 5. |
| P5 | **Stage Parquet.** Write the Parquet files into `tmp/stage/<batch-id>/` through embedded DuckDB `COPY` with fixed settings, then fsync them. |
| P6 | **Canary**, run against the staged files with the same `query` predicates that readers use. It checks:<br>(a) row counts against expected values;<br>(b) schemas, including that **no `BLOB` columns** exist;<br>(c) N random `sha256` lookups through the bloom-filtered path, including linked delta certificates;<br>(d) N random `name` and `etld1` lookups;<br>(e) `cert_id` range lookups;<br>(f) vault reads for sampled locations, which must decode and match SHA-256.<br>On failure, abandon the batch and retry once. A second failure is exit 5 with an incident. |
| P7 | **Write `_COMMIT.json`** into the staging directory, then fsync the file and the directory. |
| P8 | **Commit point.** `rename(tmp/stage/<batch-id>, dataset/log=…/batch=…)`, then fsync `dataset/log=…/` and `dataset/`. |
| P9 | **Apply the Pebble batch** with `Sync = true`, including `applied/<log> = commit_seq`. |
| P10 | **Delete the intent** and fsync `state/intent/`. |
| P11 | **Optional post-commit audit.** Run a few lookups through the committed views. A failure goes to `state/health.json` and appears in `stats` and `verify`. **The batch stays committed.** |

### 8.4 `_COMMIT.json`

```json
{
  "format": 1, "commit_seq": 812, "batch_id": "argon2027h1/000383000000-000383499999",
  "log": "argon2027h1", "first": 383000000, "last": 383499999,
  "sth": {"tree_size": 383819928, "timestamp": "…", "root_hash": "…", "signature": "…"},
  "merkle_after": {"size": 383500000, "compact_range": ["…hex…"]},
  "verified": {"method": "consistency_proof", "proof_nodes": 22},
  "cert_id_range": [9000001, 9412337], "next_cert_id": 9412338,
  "vault": {"start": {"segment": 311, "offset": 1024}, "end": {"segment": 312, "offset": 77311}},
  "builders": {"certs": 3, "names": 3},
  "files": {"entries.parquet": {"sha256": "…", "rows": 500000}, "certs.p3.parquet": {"…": "…"}},
  "counts": {"entries": 500000, "new_certs": 412337, "delta_records": 98112, "leaf_errors": 0},
  "ctvault_version": "0.1.0"
}
```

The **committed vault tail** is the `vault.end` of the `_COMMIT.json` with the highest `commit_seq`.

### 8.5 Recovery

Recovery runs at writer startup, under the lock and before any work.

| State found | Action |
|---|---|
| Vault data beyond the committed tail (with or without an intent) | Scan the tail records and durably raise `ID_FLOOR` above the highest `cert_id` seen. Then truncate the tail segment to the committed offset, delete newer segments, and fsync. Delta records only point backwards, so truncation cannot orphan a committed record. |
| An intent, and the batch directory is not committed (crash before P8) | Truncate as above. Delete `tmp/stage/<batch-id>` and the intent. |
| An intent, and the batch directory is committed (crash between P8 and P10) | Make sure P9 is applied (idempotent), then delete the intent. |
| `applied/<log>` behind the latest committed `commit_seq` | Re-insert Pebble keys by scanning the vault range in each missing `_COMMIT.json`, recomputing SHA-256. This is idempotent. |
| Staging or rebuild scratch directories with no intent | Delete them. Rebuild work resumes from `state/rebuild.json`. |
| A committed batch directory with a missing or invalid `_COMMIT.json`, or a file checksum mismatch | **Corruption.** Stop with exit 5 and point to `verify` and `repair`. |
| Pebble keys pointing beyond the committed tail | Flagged by `verify`. Fixed by `repair --reindex`. |

Pebble is applied after the commit point, so Pebble can only lag the dataset, never lead it. Readers never depend on Pebble.

### 8.6 `ID_FLOOR`

- `state/ID_FLOOR` is a durable high-water mark: **every `cert_id` below it may have been assigned.**
- Before assigning a `cert_id ≥ ID_FLOOR`, the writer sets `ID_FLOOR = id + reservation` (default 65,536). It writes a temp file, fsyncs it, renames it and fsyncs the directory.
- `ID_FLOOR` only increases.
- **After a clean commit,** the next batch starts at the committed `next_cert_id`. Every assigned ID is inside the commit, so unassigned reserved IDs are safe to use.
- **After recovery from a crash,** the next batch starts at `ID_FLOOR`, so IDs touched by the lost attempt are skipped forever. IDs are never reused.

### 8.7 `verify` and `repair`

**`ctvault verify --quick`** checks:
- `_COMMIT.json` checksums and contiguity per log
- that the batch ranges cover `[0, next)`
- that each `merkle_after.size` equals `last + 1`
- that each recorded STH signature verifies with the pinned log key
- that `ACTIVE.json` matches the files on disk
- the health history

**`ctvault verify --full`** additionally:
- decodes every vault record, checking zstd checksums, SHA-256 against `certs`, and delta bases
- recomputes each log's compact range from `entries.leaf_hash` in index order, and compares it with every batch's `merkle_after`
- re-verifies each batch against its recorded STH
- cross-checks Pebble against the vault
- reports `cert_id` uniqueness

**`ctvault repair --reindex`** rebuilds Pebble from the vault.

Neither command ever deletes committed data.

---

## 9. Volume safety and filesystem support

### 9.1 Identity markers

- **`ctvault init <root>`** checks the root before writing anything:
  - `<root>` must be a mount point: its `st_dev` differs from its parent's, and it appears in `/proc/self/mountinfo`.
  - It must be on a different device from `/`.
  - Its filesystem type must be supported (§9.3).
- `init` then writes `VAULT_ID`:

  ```json
  {"vault_uuid": "…", "created_at": "…", "durability": "tested",
   "volumes": [{"role": "root", "path": "/mnt/ctvault", "fs_uuid": "…", "fs_type": "ext4"},
               {"role": "vault_dir", "path": "/mnt/ctvault/vault", "dir_id": "…", "fs_uuid": "…", "fs_type": "ext4"}]}
  ```

- The filesystem UUID is found by resolving the mount's device through `/proc/self/mountinfo` and `/dev/disk/by-uuid`.
- **`ctvault vault add-dir <path>`** applies the same checks to the new directory. It writes a `DIR_ID` there and records the volume in `VAULT_ID`. Adding a disk never weakens the checks.

### 9.2 When checks run

Checks run on every command start (readers included) and at every batch preflight:
- every marker is present
- the vault UUID matches
- each path is still a mount point with the recorded filesystem UUID and type
- no path resolves to the device of `/`

Any mismatch means exit 4 and no writes. If the drive is unplugged mid-batch, the resulting I/O errors abandon the batch, and the next start recovers.

### 9.3 Filesystem support and durability assumptions

**v1 runs on Linux only.**

| Filesystem | Status |
|---|---|
| `ext4` | **Supported and tested.** The full suite in §13.5 plus a power-loss simulation are release gates. |
| `xfs`, `btrfs`, `f2fs` | **Untested.** Rejected unless `init --allow-untested-fs` is given, which records `durability: "untested"`. `stats` and every writer start then show a warning. |
| `vfat`, `exfat`, `ntfs` / `ntfs3` / `fuseblk`, any FUSE filesystem, `nfs`, `cifs`/`smb`, `tmpfs`, `overlay` | **Always rejected.** These cannot guarantee the needed rename, fsync, flock or durability semantics. |
| APFS | Needs a macOS host, which is out of scope for v1 (§14). macOS fsync semantics also need `F_FULLFSYNC`. |

**Mount options:** `nobarrier` or `barrier=0` is rejected because it disables flushes.

**Documented assumptions:**
- `rename` within a directory is atomic.
- `fsync(file)` persists data and metadata.
- `fsync(dir)` persists directory entries.
- `flock` is local and advisory.
- **The device honours cache flushes.** USB bridges with volatile write caches that ignore FLUSH can defeat any software guarantee. This cannot be tested in software. The documentation recommends UAS-capable enclosures.

---

## 10. Disk guard and storage budget

### 10.1 The guard

**Usage per volume** is `(f_blocks − f_bavail) / f_blocks`, so ext4's reserved blocks count as used. The cap is `disk.max_used_fraction`, default 0.85, enforced on each volume separately.

**Peak preflight before each batch.** The batch may start only if `used + peak` stays at or below the cap on every volume it touches. The peak is:

```text
peak_vault   = n × p95(vault B/entry) × safety            + segment rollover reserve (1 GiB)
peak_root    = n × (p95(parquet B/entry) + p95(pebble B/entry)) × safety
             + Pebble compaction reserve (max(2 GiB, 10% of Pebble size))
             + staging, intent, _COMMIT and quarantine overhead (64 MiB)
             + DuckDB canary spill limit
             + during a side-by-side rebuild: derived bytes of one more version for the in-flight batch
```

- `n` is the batch's entry count, and `safety` defaults to 1.5.
- The p95 values come from the last 20 committed batches. Until 20 exist, the seeds are vault 840, Parquet 175 and Pebble 60 B per entry (§3).
- **If the batch would cross the cap,** it does not start. `update` exits 3 with the numbers. `--follow` pauses, re-checks each cycle and logs a warning each time.

**Hard checks during a batch** run before every segment creation, every 256 MiB of vault appends, and every staged Parquet write. If actual usage would cross the cap, the batch is abandoned and recovered. **The cap is never exceeded and source data is never pruned automatically.**

**A side-by-side rebuild** first checks headroom for one full derived copy of the table, about 80 B per entry for `certs` and 35 B for `names`. If that does not fit, the rebuild refuses and suggests `--in-place`.

**DuckDB spill:** every CTVault DuckDB session, readers included, sets `temp_directory = <root>/tmp/duckdb-<pid>`. It also sets `max_temp_directory_size` to the headroom left below the cap, minus a 1 GiB margin.

**Projection:** `stats` shows usage per volume, the rolling bytes per entry for each component, and the projected date each volume reaches its cap at the current log growth rate.

### 10.2 Storage budget

These are estimates per entry, from §3.

| Component | B per entry |
|---|---|
| Vault: 568–824 measured, plus about 8 B framing, minus about 8% from `leaf-delta` at about 80% linking | ~530–765 |
| `entries` | ~60 |
| `certs` | ~80 |
| `names` | ~35 |
| Pebble (unmeasured) | ~60 |
| **Total** | **~765–1,000** |

- **Capacity:** 85% of 4 TB is about 3.4 TB, which holds **about 3.4–4.4B entries.**
- **Expected need:** `argon2027h1` is expected to end at **3.5B or more**. Each half-year shard collects about six months of issuance, and shorter validity periods increase issuance.
- **So a full shard is borderline.** The guard stops ingest cleanly, and `vault add-dir` is the expansion path. This was accepted in brainstorming.

---

## 11. CLI, search, explore, fetch and export

### 11.1 Configuration (`ctvault.toml`)

```toml
[ingest]
batch_size = 500000
workers = 4
max_rps = 20
follow_interval = "10m"
stall_timeout = "15m"
delta_lru_entries = 2000000

[vault]
segment_size = "1GiB"

[disk]
max_used_fraction = 0.85
safety_factor = 1.5

[rebuild]
workers = 2
```

Logs, with their pinned keys, and volumes are recorded through `ctvault logs add` and `ctvault vault add-dir`, not edited by hand.

### 11.2 Commands

| Command | Purpose |
|---|---|
| `init <root> [--allow-untested-fs]` | Create the vault after volume checks |
| `logs list \| add <name> \| info <name>` | Log metadata from Chrome's log list v3, with keys pinned when added |
| `vault add-dir <path>` | Add a vault volume (§9) |
| `update [--follow]` (alias `ingest`) | Pinned-head cycles (§5.6) |
| `rebuild [--table T] [--in-place]`, `gc` | Derived-table versions (§7.8) |
| `verify [--quick \| --full]`, `repair --reindex` | Integrity (§8.7) |
| `stats [--json]` | Logs and verified heads, ingest rate and 429 ratio, catch-up ETA, delta hit rate and bytes saved, `parse_status` mix, builder versions (**mixed flagged**), health failures, per-volume disk use and the projected cap date. Approximate values are marked `≈`. |
| `search <query> [flags]` | Non-interactive queries (§11.3) |
| `explore [query]` | Read-only TUI (§11.4) |
| `fetch <sha256 \| cert_id> [--format pem\|der\|text\|json] [--with-chain]` | Raw retrieval (§11.5) |
| `explain-error <code>` | Explain a parse or leaf error code |

**Exit codes:** 0 OK, 1 error, 2 usage, 3 disk cap reached, 4 volume check failed, 5 verification or corruption failure.

### 11.3 `search`

`search` and `explore` share the `query` package, so the same query gives identical results in both.

**Matching modes:**

| Mode | Semantics |
|---|---|
| default `<domain>` | `etld1 = '<domain>'`. The bloom filter on `etld1` limits the read to batches containing the domain. |
| `--suffix <name>` | `etld1 = etld1(<name>) AND (name = <name> OR name LIKE '%.' \|\| <name>)` |
| `--exact <name>` | `name = <name>`, using the bloom filter |
| `--contains <s>`, `--regex <re>` | **Full scans, flagged as slow.** These also reach non-DNS CN values. |
| `--ip <addr>` | `source = 'san_ip' AND name = canonical(<addr>)`, using the bloom filter on `name` |

**Filters:** `--issuer`, `--issuer-org`, `--key-alg`, `--since`/`--until` (on `ct_ts`, or on `not_before` with `--by not-before`), `--kind precert|final|chain`, `--log`, `--parse-status`, `--wildcard`, `--valid-at <date>`.

**Grouping:**
- `--group names` (the default): unique names with first and last seen, certificate count and issuers
- `--group certs`
- `--group issuances`: merged by `issuance_key`, exact within the result set

**Output:** `--format table|md|json|csv`, plus `--fields`, `--limit`, `--sort` and `--output <file>`.

**Reproducibility:** `--as-of <commit_seq>` restricts results to batches with that `commit_seq` or lower.

### 11.4 `explore` (TUI)

```text
┌ query: example.com issuer:"Let's Encrypt" since:2026-10 kind:final ─────────┐
│ NAME                  CERTS  FIRST SEEN   LAST SEEN    ISSUERS              │
│▸api.example.com          14  2026-10-02   2026-10-04   YE1, WE1             │
│ vpn.example.com           3  2026-10-03   2026-10-03   R12                  │
├ detail ─────────────────────────────────────────────────────────────────────┤
│ sha256 3f9a…  kind final  issuance ↔ precert 81c2…  log argon2027h1 #383…   │
│ issuer YE1 · ECDSA P-256 · 2026-10-03 → 2027-01-01 · 4 names · parse ok     │
├─────────────────────────────────────────────────────────────────────────────┤
│ 2 names · 41 ms · certs p3 ✓ · as-of commit 812   [?]help                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

- **Query bar:** uses the same syntax as the `search` flags.
- **Keys:**
  - `Tab` switches between names, certs and issuances.
  - `Enter` opens detail: all names, every log entry, the precert↔final link, and the chain.
  - `f` fetches the raw certificate as PEM or a text dump.
  - `Space` marks rows. `e` exports the marked rows, or all rows.
  - `/` filters within results. `s` sorts. `Esc` cancels the running query.
- **The precert↔final link** uses `delta_base_cert_id` first. Otherwise it looks up `issuance_key` in batches whose `ct_ts` range overlaps the 7 days before the final certificate's `ct_ts`, pruned by Parquet min/max statistics.
- **Execution:** queries run asynchronously with cancellation and keyset pagination. The Parquet metadata cache is enabled for the session, and the session pins its `as-of` snapshot.
- **Strictly read-only:** `explore` never takes the writer lock, never triggers ingestion and never writes outside `tmp/duckdb-<pid>/` and the export paths the user chooses.
- **Exports** record the exact active filters, sort, grouping and `as-of` commit that produced the displayed result.

### 11.5 `fetch`

- **`fetch <sha256>`:**
  1. A bloom-pruned lookup on `certs.sha256` across the snapshot's files gives `(cert_id, vault_seg, vault_off, vault_len, delta_base_cert_id)`.
  2. CTVault reads the record, resolving the delta base if there is one.
  3. It **verifies SHA-256** and outputs the certificate.
- **`fetch <cert_id>`:** the `cert_id_range` in each `_COMMIT.json` identifies the single batch, so only that batch's `certs` file is read.
- **`--with-chain`:** `entries.chain_id` → `chains` → chain `cert_id`s → fetched the same way.
- **Corruption** (§6.2) means exit 5.

### 11.6 Export

Formats are `md`, `json` and `csv`. Every export carries enough metadata to reproduce it:

```json
{"meta": {
  "ctvault_version": "0.1.0", "generated_at": "…",
  "query": {"text": "example.com", "mode": "etld1", "filters": {"issuer": "Let's Encrypt", "since": "2026-10"},
            "group": "names", "sort": "last_seen desc", "fields": ["…"]},
  "as_of_commit_seq": 812,
  "builders": {"certs": 3, "names": 3, "extractor": "…", "psl": "…"},
  "logs": [{"log": "argon2027h1", "verified_tree_size": 383819928, "root_hash": "…", "sth_timestamp": "…"}],
  "row_count": 2, "approximate": false},
 "rows": [ … ]}
```

How each format carries it:
- **Markdown:** the same metadata as a header block above the table
- **JSON:** the structure above
- **CSV:** the metadata goes in a sidecar file, `<file>.meta.json`, because comment lines break CSV readers

---

## 12. Error handling

**The rule: never silently drop, skip or reuse data.**

| Failure | Behaviour |
|---|---|
| 429, 5xx or timeouts | Adaptive backoff (§5.3). A stall abandons the batch, recovers and exits 1. `--follow` retries on the next cycle. |
| Transport or framing corruption | Refetch. Nothing advances (§5.4). |
| Semantic leaf error | `leaf_error` plus quarantine. The leaf hash is still accumulated (§5.4). |
| Bad STH signature, failed consistency proof, a smaller tree size, or an STH older than the committed checkpoint | Refetch once. Then exit 5 with an **incident** in `state/incidents/<ts>/` containing the STHs, the proof, our compact range and the raw responses. |
| X.509 field errors | `parse_status` plus codes. The certificate is kept (§7.1). |
| Canary failure (P6) | Not committed. Retry once, then exit 5 with an incident. |
| Post-commit audit failure (P11) | Health failure in `state/health.json`. The batch stays committed. |
| Disk cap | Exit 3 before the batch starts, or the batch is abandoned mid-way (§10.1). |
| Volume mismatch, I/O error or unplug | Exit 4 or 1. The batch is abandoned and recovered on the next start. |
| Vault corruption (checksum, SHA-256 mismatch, unresolvable delta) | Exit 5. Never skipped. |
| SIGINT or SIGTERM | The first signal finishes the current batch gracefully, showing progress. The second abandons it, and recovery runs before exit. |
| Writer lock held | Exit 1, naming the holder's PID. |
| Binary older than `ACTIVE.json`, or more than one version ahead | Refuse to write (§7.5). |

---

## 13. Testing

1. **Unit tests**, table-driven:
   - leaf decoding and classification, the issuance key, and the vault record and delta codec
   - the compact range, consistency-proof verification (RFC 6962 and RFC 9162 test vectors) and STH signatures
   - name normalization for each source
   - disk-guard arithmetic, `ID_FLOOR` and `ACTIVE.json` state transitions
2. **Golden corpus**, checked in:
   - a few thousand real `argon2027h1` entries
   - a malformed-certificate corpus: negative or oversized serials, odd time encodings, duplicate extensions, non-DNS CNs, IDNs, IP SANs of every length, unknown key algorithms, truncated extensions

   Expected rows are golden files. The **determinism test** requires identical rows, and identical files from the same binary, across runs and `GOMAXPROCS` settings.
3. **Differential tests:** every corpus certificate that both our extractor and `crypto/x509` parse must agree on serial, issuer, subject, validity, SANs, key algorithm, size and curve, and signature algorithm. **Fuzzing** (Go native) of the extractor and the leaf decoder must never panic.
4. **Fake CT log** (`httptest`), backed by a real Merkle tree and a test key:
   - short reads, injected 429s and 5xxs, latency and out-of-order completion
   - **adversarial modes:** altered entries, a forked tree, a bad STH signature, a shrinking tree, truncated or corrupt JSON, invalid base64, and valid bytes with an invalid `MerkleTreeLeaf`
   - two fake logs with overlapping certificates, to test cross-log dedup
5. **Crash and fault injection.** A test hook kills the process with SIGKILL, in a subprocess, at each named boundary:

   | Boundary |
   |---|
   | after intent fsync (P1) |
   | during a vault append (a torn record) |
   | during segment rollover (before the header, after the header, before the directory fsync) |
   | during an `ID_FLOOR` advance |
   | after vault fsync (P3) |
   | during the canary (P6) |
   | after `_COMMIT.json` (P7) |
   | immediately before and immediately after the batch rename (P8) |
   | before and after the Pebble sync (P9) |
   | before intent deletion (P10) |
   | during the `ACTIVE.json` switch and during rebuild file placement |

   There is also a **randomized kill loop** of 200 or more iterations, run nightly. After every restart, these invariants must hold:
   - committed batches are contiguous from index 0 and every file checksum matches
   - **no committed data is missing**: everything committed before the kill is still present
   - **no partial batch is ever visible**: a reader snapshot never contains a directory without `_COMMIT.json` or its files
   - **no `cert_id` is reused**: the harness records every `(cert_id, sha256)` assignment across all attempts, and each `cert_id` maps to exactly one SHA-256
   - the vault and Pebble agree after recovery
   - the Merkle state equals a fresh recomputation
   - no `tmp/` leftovers remain
6. **Filesystem tests:**
   - The crash suite runs on ext4. The test asserts the filesystem type, and CI runners provide ext4.
   - A **power-loss simulation** uses `dm-log-writes` on a loopback ext4 device. It replays every flush point and checks the invariants above. It is a privileged job and a release gate.
   - Filesystem-type and mount-option rejection is tested with fake `mountinfo` fixtures. So are volume-identity mismatches, using fake `mountinfo` and `by-uuid` data.
7. **Query tests:**
   - `search` and `explore` return identical results
   - `--as-of` snapshots work
   - each `search` mode behaves as specified
   - Markdown, JSON and CSV exports plus metadata match golden files, including TUI exports that capture filters, sort, grouping and `as-of`
   - the canary works
   - **schema tests assert that no `BLOB` column exists in any written file**
   - a **DuckDB regression test** reproduces the §3.6 bug and reports when DuckDB fixes it
8. **Rebuild tests:**
   - side-by-side p3→p4 while ingest dual-builds
   - catch-up of batches missed during dual building
   - the atomic `ACTIVE` switch
   - `mixed` flagged in `stats` and refused by queries
   - a new D-style table backfilled while building
9. **Disk guard tests:** a fake `statfs` source; preflight refusal; crossing the threshold mid-batch, which leads to abandon and recover; side-by-side headroom refusal.
10. **TUI tests:** `teatest` model tests for the key flows. `explore` also runs against a bind mount where `dataset/`, `state/` and `vault/` are read-only, to prove it never writes.
11. **Live smoke test** (opt-in, not CI): two real `argon2027h1` batches at low request rate. It measures the real bytes per entry for each component, the delta hit rate, the `fetch` and search latencies, and the sustainable request rate.

---

## 14. Future seams (not v1)

| Item | Seam already in place |
|---|---|
| Tiled (static-ct-api) logs | `LogSource` with fingerprint-referenced chains and `ConsistencyProof` computed from hash tiles. Needed for Google's 2027h2+ logs. |
| More logs and full history | Per-log partitions, global `cert_id`, cross-log dedup, a per-log Merkle state |
| D fields | Builder registry (§7.5) |
| More disk | `vault add-dir` (§9.1) |
| Built-in reports | `query` package and export metadata |
| Faster `fetch <sha256>` | Read-only Pebble checkpoints for readers, if the target in §15 is missed |
| macOS host and APFS | `volume` package abstraction; `F_FULLFSYNC` durability |
| HTTP API, web UI, monitoring, enrichment | Out of scope |

---

## 15. Plan-time checks and milestone-1 measurements

Each item has a decision rule, so none of them blocks planning.

| # | Item | Decision rule |
|---|---|---|
| V1 | Check that `klauspost/compress/zstd` supports raw-content dictionaries for encoding and decoding `leaf-delta` frames | If not, use a cgo libzstd binding (cgo is already accepted) |
| V2 | DuckDB `COPY` dictionary-limit settings at 122,880-row groups. A 100M limit tried to allocate 6 GiB in testing. | Choose the smallest limits that still produce bloom filters on `sha256`, `name` and `etld1`, measured on a full batch |
| V3 | Pin the versions of `duckdb-go/v2`, Pebble, Bubble Tea and teatest, `x/crypto` and `x/net` | Pin them in `go.mod` in the plan |
| M1 | Live smoke test (§13.11): bytes per entry per component, delta hit rate, Pebble bytes per key | Replace the disk-guard seeds; update §10.2 |
| M2 | `fetch <sha256>` latency | Target under 5 s at full-shard scale (extrapolated). If missed, add Pebble checkpoints for readers (§14). |
| M3 | Default `etld1` search latency | Recorded. No change in v1 unless it exceeds 60 s for a typical domain. |
| M4 | Sustainable request rate from one IP | Set the defaults for `workers` and `max_rps` |
| R1 | Report the §3.6 DuckDB bug upstream | Your decision. The regression test stays either way. |

---

## 16. Suggested implementation phasing

This is input for the implementation plan. Each phase ends with a working, tested slice.

1. **Foundations:**
   - `volume` and `init`, with the ext4, mount-point and filesystem-UUID checks
   - `diskguard`
   - the `loglist` and `logs add` commands
   - `merkle`, built against RFC test vectors
   - the fake CT log
2. **Source-layer ingest:**
   - `logsource/rfc6962` and `fetch`
   - `leaf` classification
   - `vault`, with dictionaries and `leaf-delta`
   - `index` (Pebble)
   - `entries` and `chains` Parquet
   - the commit protocol, recovery and `ID_FLOOR`
   - `update` and `--follow`
   - the full crash and fault-injection suite
3. **Derived layer:**
   - `extract`, with the golden, differential and fuzz tests
   - `derive` with the `certs` and `names` builders
   - versions metadata, `ACTIVE.json` and `views.sql`
   - the canary
   - `stats`
4. **Read path:** the `query` package, `search`, `fetch` and export with metadata. Then the live smoke test (M1–M4) and tuning of the guard seeds.
5. **`explore`:** the TUI.
6. **Rebuild:**
   - side-by-side and dual-build
   - `--in-place` and `mixed`
   - `gc`
   - `verify --full` and `repair --reindex` hardening
   - the `dm-log-writes` power-loss gate
