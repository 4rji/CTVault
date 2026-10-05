# CTVault Spec Amendment A2: derived layer, local backfill, libzstd compression, `stats`

- **Date:** 2026-10-04
- **Revised:** 2026-10-05, with the review's four corrections (§3.2, §4.4, §5.6, §6.1)
- **Status:** Approved 2026-10-05
- **Amends:**
  - `docs/superpowers/specs/2026-10-04-ctvault-design.md` ("the spec")
  - `docs/superpowers/specs/2026-10-04-ctvault-plan2-amendment.md` ("A1")
- **Origin:** Plan 3 design discussion. All five design sections were approved, with refinements.
- **Scope:** Plan 3, the derived layer (phase 3 of spec §16), plus three decisions carried from Plan 2:
  - the compression library (A1 §5);
  - DuckDB's dictionary limits for bloom filters (spec §15 V2);
  - the disk-guard seeds.

Everything not changed here stays as in the spec and A1. **Production safety requirements are unchanged.**

---

## 0. Changes at a glance

| Spec / A1 section | Change |
|---|---|
| Spec §16 phase 3 | Split into Plans 3A, 3B and 3C. A local backfill of v1 tables joins Plan 3. (§1) |
| A1 §5 | Dictionaries are trained by libzstd, and full records are encoded by C zstd at level 9. Decoding stays pure Go. (§2) |
| Spec §7.1 | The DER of each name is its reproducible identity, and the RFC 4514 rendering is display only. Issuer-to-chain matching uses the actual chain relationship, with name DER as a cross-check. Error-code rules are tightened. (§3) |
| Spec §7.3 | `certs` v1 gains `issuer_der` and the chain-only `subject_der`. (§4.2) |
| Spec §15 V2 | Resolved: `DICTIONARY_SIZE_LIMIT 122880` on `certs` and `names`. The bloom filters on every column it implies are provisional until Plan 4 benchmarks search. (§4.4) |
| Spec §7.6, §7.8 | `ACTIVE.json` exists from Plan 3; `views.sql` is generated from it. A Plan 2 vault starts in the "new table" state. (§4.6–4.7) |
| Spec §7.8, §8.7 | A local backfill (`ctvault rebuild`), `_DERIVED.json`, and a minimal `repair --reindex`. (§5) |
| Spec §8.4 | `_COMMIT.json` gains fetch counters, the `parse_status` mix and `delta_saved_bytes`. (§6.1) |
| Spec §11.2 | `stats`, with defined estimation windows. (§6) |
| Spec §10.1 | Seeds are re-measured; a change stays an explicit, reviewed edit. (§7) |

---

## 1. Scope and plan split

Plan 3 is three plans, each ending green:

| Plan | Contents |
|---|---|
| **3A: extractor** | The `extract` package (§3), the error-code catalog and `ctvault explain-error`, and the golden, malformed, differential and fuzz tests. Ingest does not change. |
| **3B: derived tables** | The `derive` package with the `certs` v1 and `names` v1 builders, derived files in every batch, `ACTIVE.json`, `views.sql`, the local backfill and `repair --reindex` (§4–§5). |
| **3C: compression, `stats`, measurements, docs** | The libzstd change (§2), `stats` and the new `_COMMIT.json` counters (§6), measurements and the seed proposal (§7), and the README. |

**Not in Plan 3:**
- `search`, `fetch` and export: Plan 4.
- Version transitions N−1 → N, dual-building, `--in-place` and `mixed`, `gc`, background rebuild workers, and the hardening of `verify --full` and `repair`: Plan 6.

**Plan 2 vaults remain valid source data.** They are upgraded locally (§5). Neither re-downloading CT entries nor replaying a sample is ever required.

---

## 2. Compression (amends A1 §5)

### 2.1 Decision

| Role | Implementation |
|---|---|
| Dictionary training | libzstd's `ZDICT_trainFromBuffer`, called in-process through cgo |
| Full leaf and chain records | C zstd, **level 9**, with the record's dictionary |
| `leaf-delta` records | unchanged: klauspost `SpeedDefault`, raw-content dictionary of the base |
| Every read | unchanged: klauspost decoders |

- **Dependency:** `github.com/DataDog/zstd` v1.5.7 becomes an **explicit, pinned, direct dependency** in `go.mod`. It is no longer relied on just because Pebble brings it in. It compiles libzstd 1.5.7 from source, `zdict.c` included.
- **The training API:** the trainer is reached through libzstd's stable public C API (`ZDICT_trainFromBuffer`, `ZDICT_isError`, `ZDICT_getErrorName`), resolved against the libzstd that this dependency compiles.
  - **What it runs:** in libzstd 1.5.7 (`zdict.c`), `ZDICT_trainFromBuffer` calls `ZDICT_optimizeTrainFromBuffer_fastCover` with:
    - `d = 8`, `steps = 4` and `compressionLevel = 3` (`ZSTD_CLEVEL_DEFAULT`);
    - every other parameter at 0, so `k` is searched, `f`, `accel` and `splitPoint` are libzstd's defaults, and it runs single-threaded.
  - **How it is named:** CTVault records the API it calls, not a trainer name.
- **The dictionary's own ID:** libzstd chooses the Dictionary_ID in the dictionary header itself, because `dictID = 0` means automatic.
  - Plan 2B's codec requires every frame's dictionary ID to equal the record's `dict_id`, and checks it on every read.
  - So after training, CTVault sets the header's `Dictionary_ID` field (RFC 8878 §5) to the vault dictionary ID.
  - The C encoder then writes that ID into every frame. The recorded SHA-256 covers these final bytes.
- **Deployment:** CTVault already needs cgo for embedded DuckDB, so this adds no new deployment constraint.

### 2.2 Dictionary manifest

`dict/<id>.json` records every input that determines the dictionary bytes:

| Field | Value |
|---|---|
| `library` | `libzstd 1.5.7`, read at run time from `ZSTD_versionString()` |
| `binding` | `github.com/DataDog/zstd v1.5.7` |
| `api` | `ZDICT_trainFromBuffer` |
| `implementation` | `ZDICT_optimizeTrainFromBuffer_fastCover`, which `ZDICT_trainFromBuffer` calls in libzstd 1.5.7 |
| `parameters` | Every field `ZDICT_trainFromBuffer` sets: `k` 0, `d` 8, `f` 0, `steps` 4, `nbThreads` 0, `splitPoint` 0, `accel` 0, `shrinkDict` 0, `shrinkDictMaxRegression` 0, `compressionLevel` 3, `notificationLevel` 0, `dictID` 0. A 0 means the default `zdict.h` documents for libzstd 1.5.7: `k` is searched, `f` is 20, `splitPoint` is 0.75, `accel` is 1, there is no shrinking, and the ID is automatic. |
| `dictionary_id` | The vault dictionary ID written into the header after training |
| `samples` | the count, the order (the first N full leaf records in vault order, as A1 §5 defines), and the SHA-256 of the concatenated samples |
| `capacity`, `size` | the requested and actual dictionary size in bytes |
| `sha256` | the dictionary bytes |
| `created_at` | as today |

**Rules:**
- **Reproducibility** is defined by those pinned inputs: the same samples, the same library version and the same parameters give the same dictionary bytes.
- **Dictionary IDs are immutable** and never reused for different bytes. Existing dictionaries, including klauspost-trained ones, stay valid and readable forever.
- **Readers select decompression from the vault format and the record's dictionary ID**, never from whichever compressor is current.

### 2.3 Failure behaviour

- **A training failure or an unusable dictionary** behaves as A1 §5 already defines: ingestion continues with dictionary 0, and the failure is recorded in `_COMMIT.json`.
- **A failed C encoding of a record** fails the batch attempt before anything is appended. The record is never partially written. The attempt is abandoned and recovered as for any other append error.

### 2.4 Compatibility tests

- C-produced frames decode with the klauspost decoders, with and without dictionaries.
- Frames produced by Plan 2's klauspost encoder still decode, from a checked-in fixture.
- A dictionary trained by klauspost (Plan 2) still decodes its records after the change.
- A pinned training corpus (checked-in samples), trained with the pinned library, gives the expected dictionary SHA-256, recorded in the test.
- A frame written with a libzstd-trained dictionary carries the vault dictionary ID.

### 2.5 Evidence (2026-10-04, representative sample `argon2027h1/000397220000-000397319999`)

The test trained on the first 20,000 unique leaf certificates and compressed the next 30,000 (1,115 B raw on average). Every frame decoded with the production klauspost decoder.

| Dictionary → encoder | B/cert | Ratio | Compress | Training |
|---|---|---|---|---|
| klauspost → klauspost "better" (Plan 2) | 659.7 | 1.690× | 129 µs | 3 m 29 s |
| klauspost → klauspost "best" | 645.9 | 1.726× | 9,157 µs | 3 m 29 s |
| klauspost → C zstd 9 | 622.8 | 1.790× | 34 µs | 3 m 29 s |
| libzstd → klauspost "better" | 607.4 | 1.836× | 117 µs | 1.7 s |
| **libzstd → C zstd 9** | **582.9** | **1.913×** | **31 µs** | **1.7 s** |
| libzstd → C zstd 19 | 578.5 | 1.927× | 268 µs | 1.7 s |

- **Determinism:** in-process training was deterministic across runs. The `zstd --train` CLI gave a different dictionary with the same ratio.
- **`leaf-delta`:** 3,943 pairs, 817 B with klauspost and 809 B with C zstd 19. No reason to change it.

The new pair is 11.7% smaller than Plan 2 and 2.4% from the spec's 1.96×, so under A1 §5's 10% threshold.

---

## 3. Extractor (Plan 3A; refines spec §7.1)

### 3.1 API and status

- **The call:** `extract.Parse(der []byte) *Cert` never fails and never panics.
- **The result:** the fields it could read, the error codes in the order they were found, and `parse_status`:
  - `ok`: no errors;
  - `partial`: at least one field failed;
  - `failed`: the outer `Certificate` or the `TBSCertificate` cannot be read.
- **Field independence:** each field is read independently with `golang.org/x/crypto/cryptobyte`, so a malformed field never prevents reading the others.

### 3.2 Names

- **`Name.Raw`** holds the exact DER bytes of the issuer and subject `Name`. **They are the name's reproducible identity**: two names are the same name exactly when their DER is equal.
- **Name equality is not how issuers are matched.** Matching a certificate to the certificate that issued it uses the actual relationships, where available:
  - the chain the log served with the entry (`chains`);
  - the authority key ID against the subject key ID;
  - the issuer and signature relationship, as A1 §4 already does for precerts.

  Exact name DER equality is a **cross-check** on those, never the sole mechanism. Plan 3 only stores the data; matching belongs to the read path (Plan 4).
- **The RFC 4514 rendering** is a deterministic **display and search representation only**, never an identity:
  - RDNs in reverse DER order;
  - short names for the RFC 4514 and common attribute types (`CN`, `O`, `OU`, `C`, `L`, `ST`, `STREET`, `DC`, `UID`, `serialNumber`, `emailAddress`), and dotted OIDs otherwise;
  - values of unknown string types as `#` plus hex;
  - multi-valued RDNs joined with `+` in DER order.
- **String types:** every `DirectoryString` type is decoded: UTF8, Printable, IA5, Teletex (as ISO 8859-1), BMP (UCS-2) and Universal (UCS-4).
- **Invalid content** is rendered with deterministic escapes and adds an error code.

### 3.3 Fields and codes

| Field | Notes |
|---|---|
| Serial | Hex of the raw INTEGER content bytes, so sign and leading zeros are kept. Codes `serial_negative`, `serial_zero`, `serial_too_long` (over 20 octets). |
| Signature algorithm | Name from a fixed table, or the dotted OID. |
| Validity | UTCTime and GeneralizedTime parsed strictly. A malformed time adds `time_bad_format`, and the column is null. |
| SPKI | Algorithm OID; `key_alg`; `key_bits` (the minimal bit length of the RSA modulus or the DSA `p`); `key_curve` (named curves, otherwise the OID). |
| Extensions | `(oid, critical, raw)` for every extension, in order. Decoded: SAN (dNSName and iPAddress), AKI key ID, SKI, and the CT poison. A repeated OID adds `ext_duplicate`. |

**Error codes:**
- They are stable, compact strings in a catalog compiled into the binary. Each code has an explanation, shown by `ctvault explain-error <code>`, where an unknown code exits 2.
- A checked-in list of codes, with a test, guarantees that codes are only ever added, never renamed or removed.

**Determinism:** extraction is a pure function of the DER. No map iteration order and no clock affect it.

### 3.4 Tests

- **Golden corpus:** about 2,000 leaf certificates plus every distinct chain certificate from the canonical and representative samples, checked in compressed (about 1.5 MB), with one expected output line per certificate.
- **Malformed corpus:**
  - generated with `cryptobyte` builders in the test: negative, zero and oversized serials; odd time encodings; duplicate extensions; non-DNS CNs; IDNs; IP SANs of every length; unknown key algorithms; truncated extensions;
  - golden expected outputs.
- **Differential against `crypto/x509`:**
  - **Coverage:** every certificate both parse. That is the golden corpus in the normal suite, and all of both samples' certificates (about 200,000) under `-tags realdata`.
  - **Fields that must agree:**
    - the serial;
    - the raw issuer and subject, **compared by DER**;
    - the CN and O values;
    - the validity;
    - the DNS and IP SANs;
    - the key algorithm, size and curve;
    - the signature algorithm.
- **Fuzzing:** the extractor never panics, and two calls on the same input return equal results.

---

## 4. Derived tables in ingest (Plan 3B; refines spec §7.2–7.6)

### 4.1 Builders

- **Package:** `derive` implements spec §7.5's registry with `certs` v1 and `names` v1.
- **The version registry** records `extractor_version`, `schema_sha256` and, for `names`, `psl_snapshot`: the pinned `golang.org/x/net` version and its embedded public-suffix list date. `golang.org/x/net` becomes a pinned dependency.

### 4.2 `certs` v1

It has spec §7.3's columns, plus two:

| Column | Type | Rows |
|---|---|---|
| `issuer_der` | `VARCHAR`, lowercase hex of `Name.Raw` | every row. Few distinct issuers, so dictionary encoding makes it cheap. |
| `subject_der` | `VARCHAR`, lowercase hex | **chain certificates only**, null for leaves, like `subject_key_id`. A leaf's subject DER is always available from the vault. |

These columns keep the exact names reproducible and let the read path cross-check an issuer match made through `chains`, AKI/SKI or signatures (§3.2). They are not a matching key by themselves.

**`kind`:** `precert`, `final` or `chain`, describing how the certificate was first vaulted, as in the spec.

### 4.3 In the batch

- **P2:**
  - For every certificate the batch vaults for the first time, the batch extracts the DER already in memory and builds its rows.
  - `kind` comes from the vaulting step: a chain position, a `precert_entry`, or an `x509_entry` (whose full or delta record is a final).
  - `delta_base_cert_id` comes from the delta base. The delta cache stores the base's `cert_id` with its location.
- **P5:** `certs.p1.parquet` and `names.p1.parquet` are staged with `entries` and `chains`.
  - Row order: `certs` by `cert_id`; `names` by `cert_id`, then SAN order, then the CN row.
  - DuckDB writes them with one thread, so files are byte-identical from the same binary.
- **P6:** the canary is extended (§4.5).
- **P7:** `_COMMIT.json` lists the derived files with their checksums, and `builders: {"certs": 1, "names": 1}`.

### 4.4 Parquet settings (resolves spec §15 V2)

- **Settings in Plan 3:**
  - `COMPRESSION zstd`, `ROW_GROUP_SIZE 122880`, `DICTIONARY_SIZE_LIMIT 122880`;
  - the default 1 MB string-dictionary page limit;
  - bloom filters on, at a 1% false-positive ratio.
- **The bloom filters on every column are provisional, not a permanent design decision.**
  - **The cost:** with this limit, DuckDB writes a filter for every column, at a measurable storage cost (below).
  - **Who decides:** Plan 4 benchmarks real search latency with and without them, and decides which columns justify their disk cost.
  - **What a change costs:** no production vault exists yet, so a change made before production costs nothing. After that, changing these writer settings is a table version change (spec §7.2).
- **No `BLOB` columns** in these files (D19).
- **`KV_METADATA`:** `ctvault.table`, `ctvault.version`, `ctvault.extractor`, `ctvault.schema_sha256`, `ctvault.psl`.
- **Measured** on both samples (200,710 unique certificates and 379,148 DNS names), with a prototype schema:
  - **DuckDB's defaults** write **no** bloom filter on `sha256` or `name`, and one on `etld1` in only 1 of 4 row groups.
  - **With the limit raised,** every column gets one in every row group:

    | | Defaults | `DICTIONARY_SIZE_LIMIT 122880` |
    |---|---|---|
    | `certs`, B/row | 36.6 | 44.7 |
    | `names`, B/row | 12.5 | 17.6 |

  - Literal lookups were correct, and there was no large allocation.
  - DuckDB cannot select bloom filters per column, so `cert_id` gets one too (about 1.6 B/row).
  - These measurements are kept as Plan 4's baseline.

### 4.5 Canary (P6) additions

- The exact schemas and KV metadata.
- Bloom filters present on `certs.sha256`, `names.name` and `names.etld1`, while §4.4's settings stand. No `BLOB` column in any file.
- `certs` rows equal the batch's new certificates, with matching `cert_id` and vault location.
- Literal `sha256` lookups return the right `cert_id`, and sampled `names` rows read back.

### 4.6 `ACTIVE.json`

`ACTIVE.json` uses spec §7.8's shape. In Plan 3 the versions are only 1.

| Situation | State |
|---|---|
| `init` | `certs` and `names` are `{active: 1, building: null, status: "complete"}`. |
| A vault without `ACTIVE.json` (Plan 2), first opened by a Plan 3 writer under the lock | `{active: null, building: 1, status: "building"}`, written atomically. |
| Every new batch | Builds every table whose active or building version is 1. |
| An `ACTIVE.json` naming an unknown version | Refused. |

### 4.7 `views.sql`

`views.sql` is generated from `ACTIVE.json` and replaced atomically only when it changes:
- `entries`, `chains` and `batches`, as in Plan 2.
- When `certs` and `names` are `active`: `certs`, `names`, `entry_certs` (entries joined to certs on `cert_id`) and `logging_delay` (`ct_ts − not_before`).
- While they are `building`: only `certs_building` and `names_building`. A partial table is never presented as complete.

---

## 5. Local backfill and `repair --reindex` (Plan 3B; refines spec §7.8 and §8.7)

### 5.1 Authority

**The durable authority is the vault, the committed source files (`entries`, `chains`) and the commit manifests.**
- Pebble is an acceleration index. It is rebuildable, and never an authority for derived data.

### 5.2 `ctvault rebuild` in Plan 3

- **What it does:** fills in tables in the `building` state from the local vault, under the writer lock. With nothing to do, it says so and exits 0.
- **The order:** committed batches are processed in commit order. For each batch that lacks a building table's file:
  1. **Read the batch's records** from its vault span (`_COMMIT.json` `vault.start`–`vault.end`).
     - Each record's DER is decoded and its SHA-256 **recomputed from the bytes**, which also checks the record's checksum and delta resolution.
     - A record that fails its own checks is vault corruption (exit 5).
  2. **Determine `kind`**, with the record kind first:
     - a chain record is `chain`;
     - a `leaf-delta` record is `final`;
     - a full `leaf` record is `precert` or `final`, according to the entries of this batch that reference its `cert_id`.

     **Cross-checks:**
     - The entries referencing a full `leaf` record must all have the same type, and at least one must exist.
     - A `leaf-delta` record's entries must all be `x509`.
     - A chain record must appear in this batch's `chains.parquet`.

     Any disagreement is **reported as a dataset inconsistency (exit 5)**, never resolved by whichever row comes first.
  3. **Determine the vault fields:** `vault_seg`, `vault_off` and `vault_len` from the record's location, and `delta_base_cert_id` from the base record's header.
  4. **Build** the rows with the same builders, stage them in `tmp/rebuild/<batch>/`, and run the same canary as ingest.
  5. **fsync** the files, rename them into the committed batch directory, and fsync the directory.
  6. **Write `_DERIVED.json`** (§5.3) atomically: this is the commit point of the batch's backfilled files.
- **Pebble:** `rebuild` also looks up each record in Pebble.
  - A disagreement (a missing key, another `cert_id`, another location) is reported as an **index inconsistency** (exit 5): "the vault is intact; run `ctvault repair --reindex`".
  - It is never reported as vault corruption.
  - Files already placed stay valid, because they come from the vault.

### 5.3 `_DERIVED.json`

- **Content:**
  - `format` (1);
  - the batch ID;
  - for each table: version, file name, bytes, rows, SHA-256, `extractor`, `schema_sha256` and `psl`;
  - the batch's `parse_status` mix;
  - `ctvault_version`;
  - `checksum`: the SHA-256 of the file's canonical JSON with that field empty.
- **Deterministic:** keys in a fixed order and no timestamps. The same binary over the same batch writes the same bytes.
- **Immutability of `_COMMIT.json`:** it is never rewritten. `_DERIVED.json` is the authoritative manifest of locally added derived files.
- **Readers:** they and `verify` treat a derived file as part of a batch only if `_COMMIT.json` or `_DERIVED.json` lists it, with a matching checksum.

### 5.4 Switching `ACTIVE.json`

- **Re-listing:** after the last batch, `rebuild` lists the committed batches again under the writer lock. A batch committed by an `update` run between two `rebuild` runs is therefore included; it already carries v1 files from ingest.
- **Final verification:** `rebuild` re-verifies that **every** committed batch has `certs.p1.parquet` and `names.p1.parquet` with the checksums its `_COMMIT.json` or `_DERIVED.json` records.
- **The switch:** only then is `ACTIVE.json` replaced atomically with `active: 1`, `building: null`, `status: "complete"` and `seq + 1`, and `views.sql` regenerated.

### 5.5 Crashes and concurrency

- **Recovery** (at every writer start and at `rebuild` start):
  - deletes `tmp/rebuild/*`, as A1 §7 already allows;
  - deletes derived files in batch directories that neither `_COMMIT.json` nor `_DERIVED.json` lists. They are derived and regenerable.
  - deletes a leftover `state/pebble.reindex/` from an interrupted `repair --reindex` (§5.6).
- **Resuming:** a resumed `rebuild` continues and produces identical files. It never needs CT data from the network.
- **Concurrency:** `update` and `rebuild` both take the writer lock, so they never run at the same time.
  - `update` on a vault that is still building ingests normally and warns: "certs and names are being built: run `ctvault rebuild`".
  - Plan 3 has no background workers.

### 5.6 `repair --reindex` (minimal)

**The existing index is never touched until a complete new one replaces it.** Under the writer lock:
1. **Build:** a new Pebble index is built side by side in `state/pebble.reindex/`. It re-applies every committed batch from the vault and `chains.parquet`, through recovery's catch-up path.
2. **Verify** the new index against the authority:
   - every committed vault record maps to its `cert_id` and location;
   - there is no other certificate key;
   - every chain recorded in `chains.parquet` has its key;
   - `applied/<log>` is each log's last `commit_seq`.
3. **Sync:** the new index is synced and closed, and `state/` is fsynced.
4. **Switch:** the two directories are exchanged atomically with `renameat2(RENAME_EXCHANGE)`, and `state/` is fsynced.
   - `state/pebble` is therefore always a complete index: the old one before the exchange, the new one after.
   - The previous index, now at `state/pebble.reindex/`, is then deleted.

**Crashes and failures:**
- **A crash at any point** leaves `state/pebble` usable. Recovery deletes a leftover `state/pebble.reindex/`, whichever index it holds.
- **No `RENAME_EXCHANGE`:** if the filesystem does not support it, `repair --reindex` refuses before building, and the old index is untouched.

**What stays in Plan 6:** the hardening of `verify` and `repair`.

### 5.7 Tests

- **Byte equivalence (essential):**
  - A sample is ingested with the builders off (the Plan 2 shape, a test hook) and then rebuilt.
  - Its `certs.p1.parquet` and `names.p1.parquet` must be **byte-identical** to an ingest with the builders on.
  - This runs on the fake log, and on the canonical sample under `realdata`.
- **Crash boundaries** added to the SIGKILL suite (spec §13.5):
  - during rebuild staging;
  - after file placement and before `_DERIVED.json`;
  - before and after the `ACTIVE.json` switch.

  **Invariants:**
  - no view exposes a partial table;
  - unlisted derived files are removed by recovery;
  - a resumed rebuild ends with the same files.
- **Inconsistencies:** an injected Pebble inconsistency is reported as an index inconsistency, and `repair --reindex` fixes it. An injected kind disagreement and a corrupted record are reported as described above.
- **`repair --reindex` crashes:** SIGKILLs during the build, after the sync and around the exchange each leave a usable index. The next start removes `state/pebble.reindex/`, and a rerun completes.

---

## 6. `stats` (Plan 3C; refines spec §11.2)

### 6.1 New `_COMMIT.json` counters

- **`fetch`:** requests, 429 responses and retries, from the fetcher's statistics.
- **`parse_status`:** counts of `ok`, `partial` and `failed`. Backfilled batches carry it in `_DERIVED.json`.
- **`delta_saved_bytes`** (`≈`):
  - **How it is estimated:** a deterministic sample of about **1 in 16** `leaf-delta` records is also compressed as a full record, and the measured saving is scaled to all delta records.
  - **The selection** is a stable hash, not `cert_id` order: a record is sampled when the first byte of `SHA-256("ctvault/delta-saved-sample/v1" ‖ certificate SHA-256)` is below 16.
    - It is reproducible from the certificate alone, the same in any vault and any order.
    - It is not correlated with `cert_id` assignment, batch boundaries or issuance patterns, and the domain prefix keeps it apart from every other use of the certificate hash.
  - **Cost:** about 31 µs per sampled record, on about 4% of certificates, so negligible.
  - **Labelling:** it is labelled approximate everywhere.

### 6.2 What `stats [--json]` shows

**Per log:**
- the pinned and last verified head, and the committed checkpoint;
- the entries remaining, and the catch-up ETA;
- the ingest rate and the 429 ratio.

**For the vault:**
- the `delta` hit rate and bytes saved (`≈`), and the `parse_status` mix;
- builder versions and `ACTIVE` status;
- the incident count;
- disk use per volume, rolling bytes per entry for each component, and the projected cap date.

**Not yet:** `health.json` (P11) arrives with Plan 4, and `stats` says so.

### 6.3 Estimation windows

| Estimate | Window | Shown as **unknown** when |
|---|---|---|
| Ingest rate and catch-up ETA | Batches committed in the last 24 hours | there are fewer than 3 such batches, or they span less than 10 minutes |
| Log growth rate | Signed heads in the committed batches' STHs over the last 7 days | they span less than 1 hour, or the tree did not grow |
| Bytes per entry | The last 20 committed batches, as for the disk guard | there are fewer than 5 committed batches |

**Projected cap date:**
1. While catching up, it adds the remaining entries at the current ingest rate.
2. After that, it uses the log's growth rate.

It is unknown if any of its inputs is unknown. A projection is never shown from too little history.

---

## 7. Measurements and seeds (Plan 3C)

- **`sample measure`** adds `certs` and `names`: bytes per entry, the `parse_status` mix, names per certificate and extraction time.
- **Both samples are re-measured** with the new compression.
- **The disk-guard seeds** (vault 840, Parquet 175, Pebble 60 B/entry) change only by an **explicit, reviewed edit**, proposed with the measured numbers. Measurements never change them automatically (A1 §8).
- **Measured so far** (Plan 2C): Pebble at 71–72 B/entry, against its seed of 60.

---

## 8. Test matrix additions

| Layer | Command | Adds |
|---|---|---|
| Unit and fake log | `go test -race ./...` | extractor golden, malformed and differential tests on the golden corpus; builders; canary; `ACTIVE.json`; backfill byte equivalence; compatibility of compression frames; the dictionary checksum |
| Fuzzing | `go test -run '^$' -fuzz FuzzParse ./internal/extract/` | the extractor |
| Crash suite | `go test ./internal/commit/` and `-tags nightly` | backfill and `ACTIVE.json` boundaries |
| Real data | `go test -tags realdata -timeout 90m ./internal/integration/` | differential on about 200,000 certificates; end to end with derived tables; backfill byte equivalence on the canonical sample; measurements |

---

## 9. Decisions this amendment adds

These were settled during the design and are flagged for review:

| # | Decision |
|---|---|
| 1 | `certs` v1 gains `issuer_der` (every row) and `subject_der` (chain only), as reproducible name identities and cross-checks, not as the matching mechanism. (§3.2, §4.2) |
| 2 | A minimal `repair --reindex` joins Plan 3, so the index-inconsistency message names a command that exists. It builds side by side and switches with `RENAME_EXCHANGE`. (§5.6) |
| 3 | `rebuild` in Plan 3 only fills tables in the `building` state; it has no background workers. (§5.2, §5.5) |
| 4 | `delta_saved_bytes` is estimated from a deterministic, hash-selected sample of about 1 in 16. (§6.1) |
| 5 | The `stats` estimation windows and minimums. (§6.3) |
| 6 | `DICTIONARY_SIZE_LIMIT 122880` on `certs` and `names`. The resulting bloom filters on every column are **provisional**: Plan 4 benchmarks search latency and decides. (§4.4) |
| 7 | After libzstd training, the dictionary header's `Dictionary_ID` is set to the vault dictionary ID. Verified: libzstd chose 1603103589 automatically; with the ID set to 1, C zstd frames carry 1 and klauspost decodes them. (§2.1) |
