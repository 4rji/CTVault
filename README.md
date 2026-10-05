# CTVault

A local, cryptographically verified Certificate Transparency research archive.
Design: `docs/superpowers/specs/2026-10-04-ctvault-design.md`.

**Status:** Plan 2C (crash suite and measurements). `ctvault update` ingests
pinned logs into the vault:
- Every batch is verified against a signed tree head.
- Every unique certificate is stored compressed and deduplicated.
- `entries` and `chains` are written as Parquet, with `views.sql` for the
  DuckDB CLI.
- A crash at any point recovers to the last committed batch. A test suite
  proves it by killing the writer (SIGKILL) at every commit boundary and at
  random moments.

The derived `certs` and `names` tables arrive in Plan 3.

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
| Real-data end to end, recovery equivalence, measurement reports (skip without a cached sample) | `go test -tags realdata -timeout 90m ./internal/integration/` | none (loopback replay) |
| Long crash loop (200 kills) | `go test -tags nightly -run RandomKill ./internal/commit/` | none |
| Leaf decoder fuzzing | `go test -run '^$' -fuzz FuzzDecode -fuzztime 60s ./internal/leaf/` | none |
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
- **The real-data layer runs without `-race`.** Training the compression
  dictionary on 20,000 real certificates takes about 3.5 minutes, and the
  race detector multiplies that. The fake-log suites run the same code under
  `-race`. The whole layer takes about 15 minutes.
- **Temp space:** the crash suite and the real-data tests write a few hundred
  MB under `TMPDIR`. If `/tmp` is a small tmpfs, point `TMPDIR` (and
  `GOTMPDIR`) at a disk.

## Usage

```bash
# The SSD must be mounted at /mnt/ctvault and contain nothing but lost+found.
./ctvault init /mnt/ctvault
export CTVAULT_ROOT=/mnt/ctvault

./ctvault logs list --available        # RFC 6962 logs in Chrome's log list
./ctvault logs add argon2027h1          # pin the log and its public key
./ctvault logs info argon2027h1         # fetch and verify the live signed tree head
./ctvault vault add-dir /mnt/disk2/ctvault-vault   # optional extra vault disk

./ctvault update                         # ingest up to the current signed head
./ctvault update --until 1000000         # stop at index 1,000,000 (exclusive)
./ctvault update --follow                # keep ingesting, one cycle every 10 minutes
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

The dataset can be queried without CTVault running:
`duckdb -c ".read /mnt/ctvault/views.sql" -c "SELECT count(*) FROM entries"`.

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
- With `--replay`, `ingest.batch_size` and `--until` must be multiples of
  5,000, the sample's proof boundaries.
- Measured on 2026-10-04: the 100,000-entry canonical sample replays in
  about 4 minutes, including one-time training of the compression dictionary
  (about 3.5 minutes).
- The resulting vault holds about 1.1 KB of vault data, 54 B of Parquet and
  67 B of index per entry. The shard's first entries are 81% final
  certificates, so they compress worse than the log's average.

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
  - precert→final links and delays, the `leaf-delta` hit rate, dedup, leaf
    errors, and every batch.
- **Reports change nothing.** Disk-guard seeds and defaults change only by a
  reviewed edit.

Measured on 2026-10-04, in 10,000-entry batches:

| | Canonical `[0, 100000)` | Representative `[397220000, 397320000)` |
|---|---|---|
| Vault, B/entry (with dictionary 1) | 1079 (985) | 745 (638) |
| Parquet, B/entry | 55 | 55 |
| Pebble, B/entry | 72 | 71 |
| Full leaf records with a dictionary | 1.58× | 1.71× |
| Finals linked to a precert in the window | 2.0% (1,603 of 81,052) | 9.2% (3,943 of 42,834) |
| `leaf-delta` saving (dictionary batches) | 37.0% | 25.8% |

The spec's figures are 1.96× with a dictionary and a vault budget of 765
B/entry. Pure-Go zstd (klauspost) at its "better" level compresses full
records 12.7% below 1.96× on the representative window, more than amendment A1
§5's 10% threshold, so the reports flag it and Plan 3 decides. The
representative vault, 638 B/entry, still fits the 765 B/entry budget. Only 9%
of final certificates there have their precert in the same window, so
`leaf-delta` matters little; the dictionary does the work.

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
