# CTVault Spec Amendment A6: Tiled Logs (static-ct-api)

- **Date:** 2026-10-06
- **Status:** approved section by section on 2026-10-06 (§1–§7 as presented), then as written ("ok"). Built in the tree on 2026-10-06/07 (summary: `docs/superpowers/plans/2026-10-06-ctvault-tiled-summary.md`); the live smoke run (§7.7) awaits the user's go-ahead.
- **Amends:** `docs/superpowers/specs/2026-10-04-ctvault-design.md` ("the spec") §1.2, §3.1, §5.1, §5.2, §5.4, §11, §13 and §14, and amendments A1–A5.
- **Origin:** the tiled-logs design discussion, after Plan 6.
  - The scope is choice A: tiled logs get everything RFC 6962 logs have.
  - The client is choice 1: built in-house, with no new dependency.
- **Lifts:** spec §1.2's non-goal "A tiled `LogSource` implementation".

Everything not changed here stays as in the spec and A1–A5. **Production safety requirements are unchanged.** The commit protocol, recovery, the disk guard, `verify` and the incident rules apply to tiled logs exactly as they do to RFC 6962 logs.

---

## 0. At a glance

**What A6 adds**
- Tiled logs can be pinned, ingested (`update`, `--follow`, `--until`), verified and measured, in the same vault as RFC 6962 logs, with certificates deduplicated across both kinds.
- A new source, `logsource/tiled`, plugs into the existing fetcher. Every tiled entry becomes the same `RawEntry` the RFC 6962 source produces.

**References** (the C2SP editor's copies, saved under `/mnt/disk/ctvault/tiled/spec/`):
- `static-ct-api`: the CT read path, checkpoints and `TileLeaf`;
- `tlog-tiles`: tiles, partial tiles and pruning;
- `tlog-checkpoint`: the note text;
- `signed-note`: the note format, key IDs and signature types.

### Measurements behind the design (probe, 2026-10-07 04:22 UTC)

The probe made 11 read-only requests. They are recorded, with every file, in `/mnt/disk/ctvault/tiled/PROBE.md`.

| What | Measured |
|---|---|
| Chrome log list v93.6 (2026-10-06T13:36:54Z) | **43 tiled logs** (22 usable, 21 qualified) against 26 RFC 6962 logs (21 usable). All 69 CTVault names are unique. Let's Encrypt's current logs are tiled only, and Google has no RFC 6962 shard for 2027h2. |
| `parcelyard2026h2` checkpoint | Size 1,587,930,800, no extension lines, 4 signature lines. The RFC 6962 line (key ID `93a78ae0`, as the spec's formula predicts) verifies with the list's key. The other three are a 68-byte line under the log's name (probably Ed25519) and 2 witness cosignatures. |
| Root from tiles | The root recomputed from the right-edge tiles (levels 0–3) equals the checkpoint's. |
| Data tiles | In both tiles fetched, all 256 leaf hashes equal the level-0 tile, and every `leaf_index` extension equals its position. |
| Live traffic (`tile/data/x006/x202/854`) | 158 x509 and 98 precert entries; **1,840 B per entry**; chains of 2 (129 entries), 3 (120) and 4 (7); **52 distinct issuers** in 33 distinct chains. |
| Compared with RFC 6962 | Argon's raw `get-entries` JSON is 5,947 B per entry (A1 measurement), so tiles are **3.2 times smaller**. One request carries 256 entries, against Argon's 32. |
| Serving | Data tiles are sent as identity even when gzip is asked for (gzip would give 184 KB, zstd 167 KB, against 471 KB). Tiles are `immutable`; the checkpoint is `no-cache`. |
| Partial tiles | ParcelYard grows about 188 entries a second, so a level-0 tile fills in about 1.4 s. **The level-0 partial tile at the checkpoint's edge already answered 404** minutes after the checkpoint; the full tile was there. |
| Consistency proofs at ParcelYard's size (computed with `transparency-dev/merkle`) | 22 to 39 nodes from **5 to 7 hash tiles**: 6 tiles for 112,800 entries behind the head (a 10-minute cycle), 7 for 100 million behind. |

## 1. Pinning tiled logs (refines spec §3.1 and §11)

**The log list (`loglist`)**
- `TiledLog` gains the pinning fields `Log` has: `log_id`, `key`, `mmd`, `state` and `temporal_interval`.
- `Find` resolves names of both kinds, and `ErrTiledUnsupported` is removed.
  - A name that matches one log of each kind is refused as ambiguous, as two RFC 6962 matches are today.
  - A tiled log's name is `LogName(description, submission_url)`, as now.
- The key check is shared: the log ID must be the SHA-256 of the key.

**The pinned record (`logreg.Record`)**

| Field | RFC 6962 | Tiled |
|---|---|---|
| `kind` (new) | `"rfc6962"` | `"tiled"` |
| `url` (meaning unchanged: where CTVault reads) | the log URL | the **monitoring** prefix |
| `submission_url` (new) | absent | as listed |
| `origin` (new) | absent | the submission URL without its scheme or trailing slash, for example `parcelyard2026h2.prod.certificate.transparency.goog`. It is computed once, when the log is pinned. |

- **A record without `kind` is an RFC 6962 record.** Records pinned before A6 are read unchanged; nothing is migrated.
- `LogInfo` gains `Kind` and `Origin`.

**One place builds sources.** `logsource.Open(rec, …)` chooses the RFC 6962 or tiled source from `kind`. All of these build their source through it:
- `update`;
- `logs info`;
- the dev build's `sample` and `update --replay`;
- `measure`;
- the test helpers.

**Commands**
- `logs list --available` lists both kinds, with a `KIND` column.
- `logs list` and `logs info` show the kind.
- `logs add` accepts tiled names, and still reads only the log list.
- `logs info` verifies the current checkpoint, as it verifies `get-sth` today.

## 2. Signed heads from checkpoints (refines spec §5.1 and §12)

**`Head` reads `<url>checkpoint` and checks it in this order:**
1. **The note** (signed-note):
   - it is valid UTF-8, with no control characters other than newline, and ends with a newline;
   - the text is separated from the signatures by the last blank line;
   - each signature line has the form `— <name> <base64>`, and there is at least one;
   - it has **at most 64 signature lines and 1 MiB**. The spec requires accepting at least 16.
2. **The text** (tlog-checkpoint):
   - exactly three lines: the origin, the size and the root;
   - the size is decimal, with no leading zero unless it is `0`;
   - the root is canonical base64 of 32 bytes;
   - **there are no extension lines.** static-ct-api forbids them with this signature type.
3. **The origin line equals the pinned origin.**
4. **Exactly one signature line comes from the pinned key:** its name equals the origin, and its key ID equals SHA-256(origin ‖ 0x0A ‖ 0x05 ‖ log ID)[:4]. Every other line is ignored, as signed-note requires.
5. **The signature body is a `uint64` timestamp followed by a DigitallySigned value, with no bytes left over.**
   - The fields become a `merkle.SignedTreeHead`: size and root from the text, then the timestamp and the DigitallySigned bytes as the signature.
   - `merkle.VerifySTH` checks it with the pinned key, as for `get-sth`.
   - `CheckHead` then compares it with the last accepted head, unchanged.

**`SignedHead.Raw` is the checkpoint exactly as received.** The stored head, manifests, `verify`'s "sth signatures" check and incident evidence already work on the head's four fields and the raw bytes, so they apply unchanged.

**Failure semantics**

| Problem | Treated as | Result |
|---|---|---|
| A malformed note, text or signature body (steps 1, 2 and 5) | `ErrMalformed`, like an unusable `get-sth` body | retried with backoff |
| The origin differs; no line, or two lines, from the pinned key (steps 3 and 4) | a bad signature | fetched again once after 5 s, then **an incident, exit 5** |
| The signature does not verify | a bad signature | the same |
| A smaller tree, a changed root, an older timestamp | `CheckHead`, unchanged | the same |

### 2.1 HTTP rules for every tiled request

- **The error types move to `logsource`:** `HTTPError`, `ErrRateLimited` and `ErrMalformed`. The `rfc6962` names stay as aliases. The fetcher's handling of 429, 5xx, `Retry-After` and backoff therefore applies to tiles and issuers unchanged.
- **gzip:** Go's transport asks for gzip and decompresses it, so a log may send gzip without negotiation, as static-ct-api allows.
- **Redirects are refused, not followed** (tlog-tiles: "MUST NOT serve redirect responses"). A 3xx is reported with its URL, like any unexpected status: retried 3 times, then the run fails.
- **Body limits:**
  - a checkpoint, 1 MiB;
  - a hash tile, exactly 32 × W bytes;
  - a data tile, 64 MiB. The measured size is 471 KB.
- The User-Agent is `ctvault`, as for RFC 6962.

## 3. Entries from data tiles (refines spec §5.1, §5.2 and §5.4)

**`Fetch(start, end)` reads one data tile per call:** tile `n = start / 256`. It returns entries `[start, min(end, (n+1)·256))`. `Fetch` may already return fewer entries than asked, and the fetcher asks again for the rest. Which file is fetched is set out in §4.2.

**Each `TileLeaf` becomes the `RawEntry` the RFC 6962 source would produce:**

| Field | From the tile |
|---|---|
| `LeafInput` | `0x00 0x00 ‖ TimestampedEntry`. These are exactly the bytes an RFC 6962 front end would serve as `leaf_input`. Its hash enters the batch's Merkle state and is checked against the signed root at P4, as today. |
| `ExtraData` | **Rebuilt** in RFC 6962 form: the chain certificates' DER for an x509 entry; `pre_certificate` followed by the chain for a precert entry. |
| `Leaf` | `leaf.Decode(LeafInput, ExtraData)`, unchanged. The precert checks (finding the issuer, `issuer_key_hash`, the TBS) work as they do now. |
| `Chain` | The tile's fingerprints, in order. |
| `TileLeaf` (new) | The entry's bytes exactly as served. Quarantine lines for tiled logs add them as `tile_leaf` (base64). |

- `RawEntry.Size()`, the fetcher's buffer weight, counts `LeafInput`, `ExtraData` and `TileLeaf`.
- `pre_certificate` and the chain fingerprints are outside the Merkle hash, as `extra_data` is in RFC 6962.

### 3.1 Issuers

Precert checks need the chain's DER, so issuers are fetched before an entry is decoded.
- **Each tiled source keeps one issuer cache for the whole run.** It is never emptied between batches, and it is bounded at 64 MiB like the chain cache, about 44,000 certificates of 1.5 KB. Filling it fails the run with `ErrChainCacheFull`. The measured live tile referenced 52 distinct issuers.
- **An uncached fingerprint is fetched from `<url>issuer/<lowercase hex>`.** The certificate's SHA-256 must equal the fingerprint.
  - At most **4 issuer requests** are in flight per source.
  - A fingerprint requested twice at once is fetched once.
- **Issuer requests belong to the tile's `Fetch`.** A 429 or 5xx on an issuer fails that `Fetch`. The fetcher then slows down and retries the tile as usual, and issuers already fetched stay in the cache.
- **`Issuer(fp)`**, which `vaultChain` calls, answers from the same cache.
- **A restarted run fetches its issuers again,** about one request per distinct issuer.

### 3.2 The `leaf_index` extension

static-ct-api requires every entry's `TimestampedEntry` extensions to hold one `leaf_index` (type 0, 5 bytes) equal to the entry's position. The signed tree covers it.
- **If it is missing, malformed, duplicated or different, the entry gets the new leaf error `leaf_index_mismatch`.**
- The certificate is kept, as with the existing cross-check codes. A code already set by `leaf.Decode` takes precedence.
- The code is appended to the end of `leaf.Codes`, so existing codes keep their order, and `explain-error` documents it.
- RFC 6962 entries are not checked.

### 3.3 Failure semantics

| Problem | Result |
|---|---|
| A tile that cannot be parsed: the wrong number of entries for its width, bytes left over, or a chain length that is not a multiple of 32 | `ErrMalformed` for the whole tile, retried (spec §5.4: framing corruption). The entry boundaries are lost, so nothing advances. |
| An issuer whose SHA-256 is not its fingerprint | `ErrMalformed`, retried |
| An issuer that answers 404 | Like any unexpected status: retried 3 times, then the run fails and names the fingerprint |
| An entry whose bytes differ from the signed tree | The root check at P4, unchanged |
| A bad certificate or chain inside a well-formed tile | The same leaf errors as RFC 6962 |

## 4. Proofs from tiles, partial tiles, and the fetcher (refines spec §5.2 and §5.5)

### 4.1 `ConsistencyProof(first, second)`

1. The node list is `proof.Consistency(first, second).IDs` from `transparency-dev/merkle`, the library the vault already uses.
2. **Each node `(L, i)` is read from the tile at level `t = ⌊L/8⌋`.**
   - When `L` is a multiple of 8, the node is hash `i mod 256` of tile `⌊i/256⌋`.
   - Otherwise it is rebuilt with RFC 6962 node hashing from the 2^(L mod 8) consecutive hashes starting at `i · 2^(L mod 8)`, which lie in one tile. That is at most 128 hashes.
3. `Rehash` combines the nodes into the proof.
4. **The tiles are not trusted.** The proof is checked by `merkle.VerifyConsistency` against the computed root and the signed root, as today.

- Sizes 0 and equal sizes need no proof and make no request, as in RFC 6962.
- Hash tiles are not cached between proofs; a proof costs 5 to 7 small tiles.

### 4.2 Which file is fetched

The rule is the same for hash tiles and data tiles. The **reference size** is `second` for a proof, and the source's latest verified head for data.
- **A tile that is full within the reference size** is fetched at its full path.
- **The tile at the right edge** is fetched as `.p/W`, with `W = ⌊size / 256^t⌋ mod 256`. The reference size always comes from a verified checkpoint, which is when the specs let a client ask for a partial.
- **A partial that answers 404 is replaced by the full tile,** using its first `W` hashes or entries.
- **If both answer 404,** the request is retried 3 times like any unexpected status, then the run fails.
- The partial is always tried first. At a fast log's edge each proof or edge data tile therefore costs one extra request.

### 4.3 Partial data tiles: ingestion still goes to the head

static-ct-api suggests that a client following a log avoid partial data tiles. CTVault does not wait for full tiles: batches and cycles end where they do today, at the head or at `--until`. Waiting would need its own timing rule and state, and going to the head costs little:
- **ParcelYard:** the edge tile (471 KB) is downloaded again the next cycle, about **0.23%** of a 10-minute cycle's 207 MB.
- **A slow log:** at most one partial tile per cycle while it fills, so at most **68 MB a day per log**.

Batch boundaries are not aligned to tiles. At 500,000 entries per batch, one tile per batch is downloaded twice, about 0.05%.

### 4.4 Fetcher settings

- **The page size comes from the source: 256 for tiled logs,** one request per tile, and 32 for RFC 6962 as now. With the default of 32, each tile would be downloaded 8 times.
- Workers, `max_rps`, buffers and the stall timeout are unchanged. At the default 20 requests a second, that is 5,120 entries a second, 27 times ParcelYard's growth.
- Batch verification (P4) is unchanged. A batch that ends at the head compares roots; any other batch is checked with a consistency proof computed by §4.1.

**Failure semantics**

| Problem | Result |
|---|---|
| A hash tile whose length is not 32 × W | `ErrMalformed`, retried |
| Tiles that give a wrong proof | Exactly like a bad `get-sth-consistency` proof: P4's retry, then an incident in `checkTip` |

## 5. Tiled samples, replay and measurement (dev build; refines A1 §2)

**A tiled sample mirrors the log's files exactly as served.** It is not converted to `entries.ndjson.zst`.

```
samples/<log>/<start>-<count>/
  sample.json      the manifest: "protocol": "tiled", kind, log, head (raw checkpoint), start,
                   count, and every file with its SHA-256 and size
  checkpoint       the pinned head, byte for byte
  tile/data/...    the data tiles of [start, start+count), all full
  tile/0/...       the level-0 tiles of the same range
  tile/<L>/...     every higher hash tile the proofs need (below)
  issuer/<hex>     every issuer the range references
```

- **The manifest:** a manifest without `protocol` is an RFC 6962 sample, so existing samples are read unchanged.
- **Replay** serves the folder as a static site on loopback.
  - A path not in the manifest answers 404, so the partial-to-full fallback runs as it does against the real log.
  - `update --replay` and `sample measure` run the **real tiled source**, unchanged.
- **Capture:** `sample capture --log <tiled log>` fetches through the tiled source and the real fetcher, and records each file it read.
  - Each file is checked as it arrives: data tiles against their tree hashes, issuers against their fingerprints.
  - The folder appears only once complete, as today.
- **Proof tiles:** capture computes the nodes of `consistency(b, head)` for **every** tile boundary `b` in the range, and fetches the union of their tiles.
  - The boundaries share most nodes, so this is a handful of tiles per level.
  - Replay therefore accepts **any batch size that is a multiple of 256**, without A1's 5,000-entry proof points.
- **Representative samples need no inclusion proof.** The compact range at `start` is read from hash tiles: the nodes of `compact.RangeNodes(0, start)`, through `NewRange`.
- **`sample verify`** checks:
  - each file's sum and size;
  - the checkpoint against the pinned key;
  - the data tiles against the level-0 tiles;
  - the range's root against the head: equal at the head, otherwise by a consistency proof built from the sample's own tiles.
- **Size rules:** A1 §2.1's, aligned to tiles. `start` and `count` are multiples of **256**, and `count` runs from **51,200 to 512,000**.
- **Sizes on disk:** 1,840 B per entry, stored uncompressed. A 51,200-entry sample takes about **94 MB**, plus a few hundred KB of hash tiles and issuers. RFC 6962 samples take 900 B per entry (zstd JSON). The disk guard's estimate before capture stays 7,409 B per entry.
- **`measure`** takes its source from the sample, through the same factory as §1: RFC 6962 replay or the tiled static site. The page size is 256 for tiled samples.

## 6. Other commands (refines spec §11)

- **`update`:** each cycle's summary line adds, for tiled logs, the number of issuers fetched and of partial tiles replaced by full ones. Both are counters on the tiled source.
- **`stats`:** shows each log's kind. The rate, ETA and 429 figures are unchanged, and 429s on tiles and issuers count in them.
- **`verify`:** unchanged. A checkpoint yields the same head fields (§2), so heads, recorded proofs and records are checked as today.
- **`search`, `fetch`, `explore`, `export`:** unchanged. A tiled log is one more log name in the dataset.
- **`explain-error`:** gains `leaf_index_mismatch` (§3.2).
- **Configuration:** nothing new. The 4 concurrent issuer requests and the 256-entry page are fixed.
- **Documentation:**
  - the README gains a tiled-logs section;
  - spec §1.2 and §14 are noted as lifted and implemented by A6.

## 7. Tests and evidence (adds to spec §13)

1. **The fake log serves both protocols** (`ctlogtest`, a new `Options.Tiled`).
   - The RFC 6962 endpoints and the tiled files come from **one tree**: `checkpoint`, `tile/<L>/…`, `tile/data/…` and `issuer/<hex>`.
   - With `Tiled`, every entry carries a `leaf_index` extension in both protocols. RFC 6962 permits any extensions.
   - The checkpoint is signed with the fake's ECDSA key. It also carries an extra Ed25519 line and a witness line, to prove those are ignored.
   - Partial tiles exist only for published sizes, and are deleted once the full tile exists, as ParcelYard does.
   - **New faults:**
     - 429 and 503 on tiles and issuers;
     - a cut data tile;
     - an altered entry;
     - a wrong hash tile;
     - an issuer with wrong bytes, or missing;
     - a redirect;
     - gzip;
     - a wrong or missing `leaf_index`;
     - checkpoints with the wrong origin, an extension line, two lines from the pinned key, or a bad signature.
2. **Unit tests in `logsource/tiled`:**
   - **paths:** the specs' examples (`1234067` → `x001/x234/067`, and `.p/W`);
   - **checkpoints:** a table covering every rule in §2;
   - **proofs from tiles** equal the reference tree's byte for byte, for every pair `m < n` up to 600 and for random pairs up to 70,000. That size exercises level-1 and level-2 tiles. Removing the rebuild for levels that are not multiples of 8 must make the test fail;
   - **the partial-to-full fallback;**
   - **issuers:** the bound on concurrent requests, and one fetch per fingerprint.
3. **The equivalence test:** one fake log ingested into two vaults, once through RFC 6962 and once through tiles. These must be **byte-identical**:
   - the Parquet files;
   - the vault segments;
   - the Pebble index;
   - the proofs recorded in the manifests.

   The one expected difference is the tiled quarantine's `tile_leaf` field.
4. **Commands against the fake:**
   - `logs add`, `list` and `info` with tiled entries;
   - `update`, `--follow` and `--until`;
   - `verify --full` and `stats`;
   - the incidents and their exit codes.
5. **Real fixtures in the normal gate** go in `internal/testdata`, kept exactly as served, with their SHA-256 pinned in `TestFixturesAreUnchanged`:
   - from the probe: the ParcelYard checkpoint, the 5 hash tiles, the live data tile and the issuer, about 515 KB;
   - the v93.6 log list, 50 KB.

   The tests check that:
   - the checkpoint verifies with the list's key, and the other three lines are ignored;
   - the root is recomputed from the edge tiles;
   - all 256 live entries hash to the level-0 tile, each with the right `leaf_index`.
6. **Real data** (the `realdata` tag, on `/mnt/disk`):
   - **A canonical tiled sample `[0, 51200)`** of a usable tiled log with real traffic, chosen at capture time; `parcelyard2027h1` is the likely one.
     - It goes through `sample verify`, then `update --replay` into a dev vault, then `verify --full`.
     - The measurement report covers bytes per entry, delta hits, leaf errors and issuers.
   - **The same dev vault also holds the existing `argon2027h1` canonical sample.** Both kinds then share one vault, with certificates deduplicated across them, and `verify --full` passes.
   - **A representative sample near ParcelYard's head,** for measurement only.
7. **A live smoke run** (opt-in, run with the user's go-ahead at the time): a small usable tiled log is followed from 0 to its head for two cycles. This exercises live partial tiles and their 404 fallback.

**No new crash tests:** the tiled source only reads. The commit protocol, the SIGKILL suites and the power-loss gate are unchanged.

## 8. Decisions this amendment adds

| # | Decision |
|---|---|
| 1 | A tiled log's kind is written `tiled`, after the log list's `tiled_logs` key. (§1) |
| 2 | For a tiled log, `url` holds the monitoring prefix. The submission URL is kept as a record and as the source of the origin, because CTVault never submits. (§1) |
| 3 | No migration: a record without `kind` is RFC 6962, and so is a sample without `protocol`. (§1, §5) |
| 4 | A wrong origin, or no line (or two lines) from the pinned key, counts as a bad signature, so it becomes an incident. (§2) |
| 5 | Redirects are refused. (§2.1) |
| 6 | Witness cosignatures and the log's other signatures (Ed25519) are ignored: CTVault has no keys for them. (§2) |
| 7 | `extra_data` is rebuilt in RFC 6962 form so that `leaf.Decode` stays the only decoder. The exact tile bytes are kept as `TileLeaf` for quarantine. (§3) |
| 8 | A wrong or missing `leaf_index` is the leaf error `leaf_index_mismatch`, not an incident: the entry is signed and genuine, it just breaks the API's rule. (§3.2) |
| 9 | An issuer that stays missing fails the run, rather than recording the entry without a chain: static-ct-api requires every issuer to be served, and failing loses nothing. (§3.3) |
| 10 | The issuer cache lasts the whole run and is never emptied. A restart fetches the issuers again. (§3.1) |
| 11 | Ingestion goes to the head, partial data tiles included: 0.23% extra on ParcelYard, at most 68 MB a day for a slow log. (§4.3) |
| 12 | Batch boundaries are not aligned to tiles (about 0.05% extra). (§4.3) |
| 13 | The fetcher's page size comes from the source: 256 for tiled logs. (§4.4) |
| 14 | Hash tiles are not cached between proofs, and a partial tile is always tried before the full one. (§4.1, §4.2) |
| 15 | Tiled samples keep the files exactly as served, and replay goes through the tiled source. (§5) |
| 16 | Capture includes the proof tiles for every tile boundary, so replay accepts any batch size that is a multiple of 256. (§5) |
| 17 | Representative tiled samples take their start state from hash tiles instead of an inclusion proof. (§5) |
| 18 | Sample files are stored uncompressed: about twice the disk of RFC 6962 samples, in exchange for byte-exact files served as is. (§5) |
| 19 | The real-data sample has 51,200 entries (about 94 MB), the tile-aligned minimum of A1's size rules. (§5, §7) |
| 20 | The fake log gives every entry a `leaf_index` and serves both protocols from one tree, which makes the equivalence test possible. (§7) |
| 21 | About 565 KB of real fixtures join `internal/testdata`, which grows from 256 KB to about 820 KB. (§7) |
| 22 | No new crash or power-loss runs: the write path is unchanged. (§7) |

## 9. Known gaps and future work (adds to spec §14)

| Item | Why it is out, and the seam |
|---|---|
| Several monitoring URLs with failover | The log list gives one per log. The seam: a source built from a list of URL prefixes. |
| The names-only tiles extension | Unauthenticated; static-ct-api itself warns security-minded clients off it. |
| Checking witness cosignatures | The log list carries no witness keys. The checkpoint parser already reads every signature line and skips them. |
| Waiting for full data tiles | Decision 11. It would need a timing rule, for example per log, and state for it. |
| Keeping issuers across runs | Decision 10. The vault already stores every chain certificate under its SHA-256, so a lookup there could replace refetching. |
| Pruned logs (tlog-tiles' minimum index) | No CT policy allows pruning yet. A pruned log would answer 404 below its minimum index, and because vaults start at 0, ingestion would fail there with the URL named. It needs its own design. |

## 10. How it is built

As 6A–6C were: directly in the tree, tests first, then the usual gate, the real data and a summary document, with no plan document. It is one part, built in this order:

1. Pinning (`loglist`, `logreg`, the `logs` commands), the shared HTTP errors and `logsource.Open`.
2. `logsource/tiled`: checkpoints, tile paths, proofs from tiles, data tiles and issuers. The fake log's tiled mode and its faults, and the probe fixtures in `internal/testdata`.
3. `update` and the other commands on tiled logs, and the equivalence test.
4. Tiled samples: capture, verify, replay and measure.
5. Real data (the sample, the shared dev vault, the measurements), then the live smoke run once the user says go, the README and the summary.
