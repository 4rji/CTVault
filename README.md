# CTVault

A local, cryptographically verified Certificate Transparency research archive.
Design: `docs/superpowers/specs/2026-10-04-ctvault-design.md`.

**Status:** D fields (amendment A7): seven tables of certificate
policies and extensions, built from the vault. Before that, tiled logs
(amendment A6): static-ct-api logs are pinned, ingested, followed and
verified like RFC 6962 logs, in the same vault. This builds on Plan 6: 6C (the power-loss gate, passing), 6B (version transitions:
upgrades in turns, `gc`, `rebuild --in-place`) and 6A (`verify`, `repair`);
Plan 5 (`explore`, the terminal UI) and Plan 4 (the read path: `search`,
`fetch`, export, the post-commit audit).
`ctvault update` ingests pinned logs into the vault:
- Every batch is verified against a signed tree head.
- Every unique certificate is stored once, compressed with libzstd and a
  trained dictionary (a precert's final as a delta against it).
- Each batch writes Parquet:
  - `entries` and `chains`;
  - `certs`: one row per certificate, with its parsed fields;
  - `names`: one row per DNS name, IP address or CN, with its public suffix
    and registrable domain.

  `views.sql` exposes them to DuckDB, with `entry_certs` and `logging_delay`.
- No certificate is ever dropped: a malformed one is kept, with stable error
  codes (`ctvault explain-error <code>`).
- A crash at any point recovers to the last committed batch. A test suite
  proves it by killing the writer (SIGKILL) at every commit boundary and at
  random moments.
- So does a power loss: the power-loss gate records a workload through the
  kernel's `dm-log-writes`, replays it to every point where the disk had
  confirmed a flush, and checks each one (see below).

`search`, `fetch` and `explore` read a fixed snapshot of the committed
batches, take no lock and never write into the vault, so they run while
`update` ingests.

## Requirements

- Linux, with the vault on a dedicated, mounted **ext4** volume (an external
  SSD). xfs, btrfs and f2fs work only with `--allow-untested-fs`; exFAT, NTFS,
  FAT, FUSE, network filesystems and tmpfs are always rejected.
- Go 1.26.8 or newer. With the default `GOTOOLCHAIN=auto`, an older `go`
  downloads the right toolchain automatically.
- A C compiler (`gcc`) for cgo: CTVault embeds DuckDB. The DuckDB library
  makes the binary about 100 MB, and a first build takes a minute or two.

## Build and test

```bash
go build -o ctvault ./cmd/ctvault
go test -race ./...
```

| Layer | Command | Network |
|---|---|---|
| Unit tests, fake-log fault injection, crash boundaries and a 25-kill loop, production guard tests | `go test -race ./...` | none |
| Dev-build behaviour, measurements | `go test -race -tags ctvault_dev ./...` | none |
| Real-data end to end, recovery and rebuild equivalence, measurement reports, the tiled sample end to end (skip without a cached sample) | `go test -tags realdata -timeout 90m ./internal/integration/` | none (loopback replay) |
| The power-loss gate (root: loop devices, `dm-log-writes`); about 5 minutes | `go test -c -tags powerloss -o /mnt/disk/ctvault/powerloss/powerloss.test ./internal/powerloss/`, then `sudo /mnt/disk/ctvault/powerloss/powerloss.test -test.run TestPowerLoss -test.v -test.timeout 2h` | none; files under `/mnt/disk/ctvault/powerloss/` |
| Extractor against `crypto/x509` on every certificate of both samples | `go test -tags realdata ./internal/extract/` | none |
| Long crash loop (200 kills) | `go test -tags nightly -run RandomKill ./internal/commit/` | none |
| Leaf decoder fuzzing | `go test -run '^$' -fuzz FuzzDecode -fuzztime 60s ./internal/leaf/` | none |
| Certificate extractor fuzzing | `go test -run '^$' -fuzz FuzzParse -fuzztime 60s ./internal/extract/` | none |
| Live sample capture | `ctvault-dev sample capture ...` (below) | Google, opt-in |

- **The crash suite** (`internal/commit/crash_test.go`) re-runs the test
  binary as a child, kills it with SIGKILL, then checks after every recovery:
  - committed batches are intact, and nothing partial is visible;
  - nothing is left beyond the vault tail or in `tmp/`;
  - Pebble agrees with the vault;
  - no `cert_id` of a truncated record is ever committed later;
  - a finished ingest equals a clean one.

  `-short` skips it. With `-race`, the `commit` package takes about
  2.5 minutes.
- **The real-data layer runs without `-race`.** It replays 100,000 real
  entries several times; the fake-log suites run the same code under `-race`.
  The integration layer takes about 5 minutes, the extractor's about 40
  seconds.
- **Temp space:** the crash suite and the real-data tests write a few hundred
  MB under `TMPDIR`. If `/tmp` is a small tmpfs, point `TMPDIR` (and
  `GOTMPDIR`) at a disk.

## Usage

```bash
# The SSD must be mounted at /mnt/ctvault and contain nothing but lost+found.
./ctvault init /mnt/ctvault
export CTVAULT_ROOT=/mnt/ctvault

./ctvault logs list --available        # every log in Chrome's log list, with its kind
./ctvault logs add argon2027h1          # pin the log and its public key
./ctvault logs add parcelyard2027h1     # a tiled (static-ct-api) log, pinned the same way
./ctvault logs info argon2027h1         # fetch and verify the live signed tree head
./ctvault vault add-dir /mnt/disk2/ctvault-vault   # optional extra vault disk

./ctvault update                         # ingest up to the current signed head
./ctvault update --until 1000000         # stop at index 1,000,000 (exclusive)
./ctvault update --follow                # keep ingesting, one cycle every 10 minutes

./ctvault search example.com            # names under example.com, newest first
./ctvault search --suffix api.example.com --group certs
./ctvault search --exact www.example.com --format json
./ctvault search example.com --issuer R12 --since 2026-10 --format csv --output r.csv
./ctvault search --ip 192.0.2.1
./ctvault fetch <sha256>                 # PEM, verified against its SHA-256
./ctvault fetch <cert_id> --format text --with-chain
./ctvault explore example.com "issuer:Let's Encrypt" since:2026-10   # the terminal UI

./ctvault stats                          # progress, ETA, disk use, projected cap date
./ctvault verify                         # manifests, IDs, segments, sizes, tables, signed heads: seconds
./ctvault verify --full                  # also every byte: checksums, records, Merkle trees, the index
./ctvault stats --json
./ctvault explain-error san_ip_bad_len    # what a parse or leaf error code means
```

`update` (alias `ingest`):
- **Batches:** commits batches of `ingest.batch_size` entries, each verified
  by a consistency proof or the signed root.
- **Ctrl-C:** the first finishes the current batch; the second abandons it,
  and it is fetched again next time.
- **Log misbehaviour:** a shrinking log, a fork or a bad signature is an
  incident. It is refetched once, then evidence is written to
  `state/incidents/` and `update` exits 5.
- **Full disk:** at the disk cap it exits 3 before a batch starts; with
  `--follow` it waits for the next cycle instead.
- **Crashes:** the next start recovers to the last committed batch. The
  certificate IDs a lost batch may have used are skipped, never reused, so
  `cert_id` values can have gaps.
- **A batch that cannot be cleaned up** (the vault cannot be cut back) stops
  `update`, even with `--follow`. The next start recovers it.

**Tiled (static-ct-api) logs** (amendment A6) work the same way: most of
Chrome's current logs are tiled, and Google's 2027h2 logs and Let's
Encrypt's current ones are tiled only.
- **Pinning:** `logs add` records the kind, the monitoring prefix (where
  CTVault reads) and the checkpoint origin (the submission URL without its
  scheme). Records pinned earlier have no kind and stay RFC 6962.
- **Signed heads:** the `checkpoint` must name the pinned origin and carry
  exactly one RFC 6962 signature from the pinned key. Other signatures (the
  log's Ed25519 one, witnesses) are ignored. A wrong origin or a missing key
  line is an incident, like a bad signature.
- **Entries:** one 256-entry data tile per request. Each entry becomes the
  same `leaf_input` and `extra_data` an RFC 6962 log would serve, so
  decoding, dedup and the dataset are identical; a test ingests one fake log
  both ways and compares the files byte for byte. Issuers are fetched once
  per run from `issuer/<sha256>` and checked against their fingerprint.
- **Proofs:** consistency proofs are computed from hash tiles and checked
  against both roots, so a wrong tile is caught like a wrong proof.
- **Partial tiles:** `update` still ingests up to the signed head. A partial
  tile the log has already replaced is read from the full tile.
- **New leaf error:** `leaf_index_mismatch`, when an entry's `leaf_index`
  extension is missing or differs from its position. The certificate is kept.
- Each cycle reports how many issuers were fetched and how many partial tiles
  were read from full ones.

The dataset can be queried without CTVault running:

```bash
duckdb -c ".read /mnt/ctvault/views.sql" -c "SELECT count(*) FROM entries"
duckdb -c ".read /mnt/ctvault/views.sql" -c "SELECT c.issuer_cn, c.not_before FROM names n JOIN certs c USING (cert_id) WHERE n.etld1 = 'example.com'"
duckdb -c ".read /mnt/ctvault/views.sql" -c "SELECT median(logging_delay) FROM logging_delay"
```

**Policies and extensions (area D, amendment A7)** have seven tables, one or
more rows per certificate, joined on `cert_id`:

| Table | Holds |
|---|---|
| `cert_extensions` | every extension: OID, critical, length, and a `decode_error` when D could not decode it |
| `cert_policies` | policy OIDs, with `validation` (`dv`, `ov`, `iv`, `ev`) and the first CPS URI |
| `cert_ekus` | extended key usages, with short names (`server_auth`, `client_auth`, ...) |
| `cert_key_usage` | the nine keyUsage bits, `is_ca` and `path_len` |
| `cert_aia` | OCSP and caIssuers URLs |
| `cert_crl_dps` | CRL distribution point URLs |
| `cert_scts` | embedded SCTs: log ID, timestamp, algorithms |

```bash
# The share of certificates per log that still carry an OCSP URL.
duckdb -c ".read /mnt/ctvault/views.sql" -c "SELECT log, avg((EXISTS (SELECT 1 FROM cert_aia a WHERE a.cert_id = e.cert_id AND a.method = 'ocsp'))::INT) FROM entries e GROUP BY 1"
# Leaf certificates that still allow clientAuth.
duckdb -c ".read /mnt/ctvault/views.sql" -c "SELECT count(DISTINCT cert_id) FROM cert_ekus JOIN certs USING (cert_id) WHERE eku_name = 'client_auth' AND kind <> 'chain'"
```

- They add about 56 B per entry, measured on 151,200 real entries; SCTs are
  the largest part.
- An extension that does not decode gives no rows, only its code in
  `cert_extensions` (`ctvault explain-error ext_policies_malformed`).
- A vault written before them builds them in turns during `update`, or all
  at once with `ctvault rebuild`. The views show `<table>_building` until
  then.

**New table versions are built from the vault**, never downloaded again:
- **A vault written before Plan 3, or a new table:** the views show it only as
  `<table>_building` until every batch has it, and `update` says how far it is.
- **A newer binary with a new version of a table** (say `certs` v2) starts an
  upgrade side by side, if a second copy fits under the disk cap. Readers keep
  using v1 until the switch:
  - new batches build both versions;
  - `update` rebuilds one old batch after each new one
    (`rebuild.batches_per_turn`), and under `--follow` between cycles;
  - `ctvault rebuild` does the rest at once.
  - When every batch has v2, it becomes active and v1 is "retiring":
    `ctvault gc` deletes its files now, and `update` and `rebuild` do it 24 hours
    after the switch, so open `explore` sessions can reload (they show a banner;
    `R` reloads).
- **Without room for both:** `ctvault rebuild --in-place` replaces each batch's
  v1 as it goes. The table is "mixed" meanwhile, and readers refuse it unless
  given `--parser-version N` (only the batches at N, a partial result) or
  `--allow-mixed` (each batch's own version). `stats` warns while it lasts.
- **Every step can be interrupted, or killed, and resumed.**

**Search** (`ctvault search --help` lists every flag):
- **Modes:** a registrable domain (the default), `--suffix`, `--exact`, `--ip`, and `--contains` or `--regex`, which scan every name and are slow on a large vault.
- **Filters:** `--issuer`, `--issuer-org`, `--issued-by <CA sha256 or cert_id>` (by chain and key IDs, not by name), `--key-alg`, `--kind`, `--valid-at`, `--since`/`--until`, `--log`.
- **Groups:** `--group names` (the default), `certs` or `issuances`.
- **Exports:** `--output` writes `md`, `json` or `csv` with the metadata that reproduces the result: the query, the snapshot's `commit_seq` (`--as-of` re-runs it) and each log's verified head. A `csv` export puts the metadata in `<file>.meta.json`. Existing files are replaced only with `--force`.

**Explore** (`ctvault explore [query] [--as-of N]`, a terminal of at least 80×24):
- **The bar** takes search's syntax as terms: a domain, or `suffix:`, `exact:`, `ip:`, `contains:`, `regex:`, then `issuer:`, `org:`, `issued-by:`, `key:`, `kind:`, `status:`, `valid-at:`, `wildcard`, `log:`, `since:`, `until:`, `by:not-before`. Values with spaces go in double quotes.
- **Keys:** `Tab` switches names, certs and issuances; `Enter` opens a name's certificates or a certificate's detail (names, entries, chains, the precert↔final link); `f` shows the text dump or the PEM and `w` writes it (never over a file); `Space` marks rows and `e` exports the marked rows, or all, with the selection in the metadata; `/` filters the whole result; `s` sorts; `Esc` cancels or goes back; `R` re-pins the latest commit; `?` lists the keys.
- **The same rows as search:** explore runs a query once and holds its rows in the reader session (they spill to `tmp/duckdb-<pid>/` when large), then shows them 200 at a time. Pages, `s` and `/` read the held rows, not the vault. Without a terminal it exits 2 and points to `search`.

**Post-commit audit:** after every batch, `update` looks the batch up through
the read path. A failure is recorded in `state/health.json` and shown by
`stats`; the batch stays committed.

**Verify:** `ctvault verify` checks the vault without changing it and exits 5
when it finds damage. It takes no lock and never stops `update`: it checks the
batches committed when it starts.
- `--quick`, the default, reads manifests and metadata in seconds: contiguous
  batches, `cert_id` ranges and `ID_FLOOR`, vault segments and dictionaries,
  every file's size, `ACTIVE.json` and `views.sql`, and each signed head's
  signature.
- `--full` also hashes every file, decodes every vault record against its
  `certs` row, checks that every `cert_id` an entry or chain names exists,
  rebuilds each log's Merkle tree and re-verifies the signed heads, the
  consistency proofs included (recorded in `_COMMIT.json` since Plan 6A).
  When no writer holds the lock, it also checks the index.
- What a stopped writer leaves (an intent, bytes past the tail, `tmp/`
  leftovers) is reported as "recovery pending", not damage.

**Repairs:** both run under the writer lock, and neither deletes committed
data nor rewrites a manifest.
- `ctvault repair --reindex` rebuilds the Pebble index from the vault, beside
  the current one, and swaps the two atomically. Its memory does not grow
  with the vault. A `rebuild` that finds the index disagreeing with the vault
  says so and points to it.
- `ctvault repair --derived [--batch ID]` rebuilds `certs` and `names` files
  that are missing or fail their recorded checksum, and replaces each one
  only when the rebuilt file reproduces that checksum. Damaged source data
  (vault records, `entries`, `chains`) is named, and must be restored from a
  backup.

Log names are the conventional names from the log list, lowercased:
`argon2027h1`, `wyvern2027h1`, `oak2026h2`, `mammoth2026h2` and so on.
`logs list --available` shows them. Tiled (static-ct-api) logs are listed in
Chrome's log list but cannot be pinned in v1.

The vault must be a dedicated volume. `init` refuses the system disk, including
a loop image, LVM or LUKS device stored on it, as well as any disk that already
holds files other than `lost+found`.

Exit codes: 0 OK, 1 error, 2 usage, 3 disk cap reached, 4 volume check failed,
5 verification or corruption failure.

## Development build (real data on the normal disk)

Until the external SSD is available, real CT data may live on the normal disk
only through the dev build. It is a separate binary, selected at compile time;
the production binary contains none of its code and refuses its vaults.

```bash
go build -tags ctvault_dev -o ctvault-dev ./cmd/ctvault
./ctvault-dev version        # "... DEV BUILD — not for production"
```

Everything it writes lives under `~/.cache/ctvault-dev/` (home from the OS user
database, not `$HOME`):
- dev vaults in `vaults/`;
- samples in `samples/`;
- measurement reports in `reports/`;
- measurement workspaces in `tmp/`.

It keeps the same 85% disk cap, applied to the disk that holds that folder.
`~/.cache/ctvault-dev` may be a symlink to a folder on another local disk; the
dev build resolves it. A dev vault created before such a move is refused
afterwards, because its `VAULT_ID` records the old filesystem's UUID.

### Real-data samples

```bash
# Canonical sample: argon2027h1 [0, 100000). Fixed forever once captured.
./ctvault-dev sample capture --log argon2027h1 --entries 100000

# Representative sample: the newest whole window, or one starting at S.
./ctvault-dev sample capture --log argon2027h1 --start head --entries 100000
./ctvault-dev sample capture --log argon2027h1 --start 200000000 --entries 100000

# Re-check a sample at any time.
./ctvault-dev sample verify ~/.cache/ctvault-dev/samples/argon2027h1/000000000000-000000099999
```

- `--entries` is 50,000-500,000 and a multiple of 5,000; `--start` is a
  multiple of 5,000. A 100,000-entry sample takes about 76-100 MB (760-974 B
  per entry measured; the canonical `[0, 100000)` window took 97.5 MB) and
  about 4 minutes at the log's rate limit.
- A sample is published only after it verifies: the file checksums, the
  signed head with the key pinned from Chrome's log list, and the Merkle
  proofs that tie every entry's `leaf_input` (the logged certificate or
  precertificate TBS and its timestamp) to that head. It is then read-only
  and never overwritten; to capture the same range again, add
  `--suffix <name>`.
- The chains in `extra_data` are not part of a CT log's Merkle tree (RFC
  6962), so no proof covers them; in a sample they are protected by the
  checksums only. Precertificate cross-checks still flag a chain that does
  not match the logged TBS.
- An interrupted or failed capture (Ctrl-C, network loss, full disk) leaves
  nothing behind.
- Every later load verifies the sample again, so a damaged sample is refused
  (exit 5) instead of feeding wrong data.
- Representative samples are for measurements only.

**A tiled log's sample** mirrors the log's files exactly as served: the
checkpoint, the data and level-0 tiles of the range, every hash tile a
consistency proof from any position in the range needs, and every issuer it
references (amendment A6 §5).

```bash
./ctvault-dev sample capture --log parcelyard2027h1                    # [0, 51200)
./ctvault-dev sample capture --log parcelyard2026h2 --start head      # the newest whole window
```

- `--entries` is 51,200-512,000 and a multiple of 256 (the default for a
  tiled log is 51,200); `--start` is a multiple of 256.
- Measured on 2026-10-07: `parcelyard2027h1 [0, 51200)` took 20 seconds and
  112 MB (200 data tiles, 206 hash tiles, 179 issuers; 2,236 B per entry);
  a window at `parcelyard2026h2`'s head took 68 seconds and 65 MB
  (1,227 B per entry).
- `sample verify`, `measure` and `update --replay` read it through the
  tiled source over a loopback static site. A representative tiled sample
  takes its start state from hash tiles instead of an inclusion proof.

### Dev vaults and replay

A dev vault lives under `~/.cache/ctvault-dev/vaults/` and starts with
10,000-entry batches. A canonical sample feeds it over loopback through the
same client, fetcher and writer as the live log:

```bash
./ctvault-dev init ~/.cache/ctvault-dev/vaults/argon
./ctvault-dev --root ~/.cache/ctvault-dev/vaults/argon logs add argon2027h1
./ctvault-dev --root ~/.cache/ctvault-dev/vaults/argon update \
  --replay ~/.cache/ctvault-dev/samples/argon2027h1/000000000000-000000099999
```

- `--replay` refuses representative samples and samples of another log.
- With `--replay` of an RFC 6962 sample, `ingest.batch_size` and `--until`
  must be multiples of 5,000, the sample's proof boundaries. A tiled sample
  accepts any.
- A tiled sample needs the log pinned as tiled, with the same origin.
- Measured on 2026-10-05: the 100,000-entry canonical sample replays in
  about 30 seconds, including the one-time training of the compression
  dictionary (a few seconds with libzstd).
- The resulting vault holds about 1.0 KB of vault data, 182 B of Parquet
  (with `certs` and `names`) and 72 B of index per entry. The shard's first
  entries are 81% final certificates, so they compress worse than the log's
  average.

### Measurements

```bash
./ctvault-dev sample measure ~/.cache/ctvault-dev/samples/argon2027h1/000397220000-000397319999
```

- **What runs:** the sample, canonical or representative, goes through the
  production per-entry pipeline: decoding, the issuance key, dedup, the vault
  writer with dictionaries and `leaf-delta`, and Parquet staging. It commits
  batch by batch (`--batch-size`, default 10,000), as `update` does.
- **Where:** in a throwaway workspace under `~/.cache/ctvault-dev/tmp/`, which
  is deleted afterwards. It never creates or changes a vault.
- **The report** is written to
  `~/.cache/ctvault-dev/reports/<log>/<sample>/<UTC time>.json`, with a
  Markdown summary next to it, and the summary is also printed. It records:
  - the provenance: CTVault, Go and dependency versions, the sample, the time;
  - bytes per entry for the vault, Parquet and Pebble, against the
    disk-guard seeds;
  - compression by record kind, dictionary and entry type, and the gap
    against the spec's C-zstd figures (flagged when more than 10% worse);
  - the derived tables: rows, bytes per entry, names per certificate, the
    `parse_status` mix and extraction time;
  - precert→final links and delays, the `leaf-delta` hit rate, dedup, leaf
    errors, and every batch.
- **Reports change nothing.** Disk-guard seeds and defaults change only by a
  reviewed edit.

Measured on 2026-10-05 (Plan 3C), in 10,000-entry batches:

| | Canonical `[0, 100000)` | Representative `[397220000, 397320000)` |
|---|---|---|
| Vault, B/entry (with dictionary 1) | 1009 (894) | 686 (561) |
| Parquet, B/entry (`certs` / `names`) | 182 (91 / 36) | 200 (99 / 46) |
| Pebble, B/entry | 72 | 71 |
| Full leaf records with a dictionary | 1.74× | 1.96× |
| Finals linked to a precert in the window | 2.0% (1,603 of 81,052) | 9.2% (3,943 of 42,834) |
| `leaf-delta` saving (dictionary batches) | 30.3% | 17.8% |
| Names per certificate | 1.86 | 1.93 |

**Compression:** full records are libzstd level 9 with a dictionary trained
by libzstd (amendment A2 §2).
- On the representative window this reaches the spec's 1.96×.
- The representative vault, 561 B/entry, is well inside the spec's 765
  B/entry budget.
- Only 9% of final certificates there have their precert in the same window,
  so `leaf-delta` matters little; the dictionary does the work.

**Live smoke test (2026-10-05):** two real batches of 500,000 entries were ingested from `argon2027h1` into a dev vault.

| | Batch 1, 5 requests/s | Batch 2, 20 requests/s |
|---|---|---|
| Time | 53 min | 14.4 min |
| HTTP 429 responses | 15 of 15,640 (0.1%) | 5 of 15,630 (0.03%) |
| Vault, B/entry | 1,295 (no dictionary yet) | 733 (dictionary 1) |
| Parquet, B/entry | 177 | 172 |
| Peak memory | 1.85 GB | 2.0 GB |

- Pebble held 77 B/entry after 1,000,000 entries.
- On that vault, `fetch` takes 46 ms and `search amazonaws.com` 0.5 s, process start included.
- The defaults (`max_rps = 20`, 4 workers) are sustainable from one IP.

**Disk-guard seeds** (applied after review): vault 840, Parquet 210 (it now
includes `certs` and `names`), Pebble 80 B/entry.

## Pending verification

**Real-SSD smoke test: not run yet.** As of 2026-10-04 there was no access to
the external drive. Every automated test passes, but `init` and `logs` have
not yet been run end to end on the real drive and enclosure (USB/UAS, and LUKS
if used). Run it before trusting the vault with data. The drive must be
mounted at `/mnt/ctvault`, ext4, and empty apart from `lost+found`:

```bash
go build -o ctvault ./cmd/ctvault
./ctvault init /mnt/ctvault
./ctvault --root /mnt/ctvault logs add argon2027h1
./ctvault --root /mnt/ctvault logs info argon2027h1
```

Expected:
- `init` reports `durability tested`.
- `logs info` ends with `signature  verified with pinned key`, with a
  `tree_size` above 384,397,626.

Do not substitute a loop image; `init` refuses one stored on the system disk.

The other physical checks also wait for the drive. None of them blocks Plan 2:

1. The real-SSD smoke test above.
2. Filesystem UUID resolution on the real drive and enclosure (USB/UAS, and
   LUKS if used).
3. Unplugging the drive in the middle of a batch.
4. The mount disappearing, or the drive being remounted at a different path.
5. Real disk-cap behaviour on the 4 TB drive (statfs, ext4 reserved blocks,
   projections).
6. Enclosure throughput and fsync latency.
7. The `dm-log-writes` power-loss gate on ext4 (Plan 6).
