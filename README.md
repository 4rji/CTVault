# CTVault

A local, cryptographically verified Certificate Transparency research archive.
Design: `docs/superpowers/specs/2026-10-04-ctvault-design.md`.

**Status:** Plan 2B (vault). `ctvault update` ingests pinned logs into the
vault:
- Every batch is verified against a signed tree head.
- Every unique certificate is stored compressed and deduplicated.
- `entries` and `chains` are written as Parquet, with `views.sql` for the
  DuckDB CLI.
- A crash at any point recovers to the last committed batch.

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
| Unit tests, fake-log fault injection, production guard tests | `go test -race ./...` | none |
| Dev-build behaviour | `go test -race -tags ctvault_dev ./...` | none |
| Real-data tests (skip without a cached sample) | `go test -race -tags realdata ./internal/integration/` | none (loopback replay) |
| Leaf decoder fuzzing | `go test -run '^$' -fuzz FuzzDecode -fuzztime 60s ./internal/leaf/` | none |
| Live sample capture | `ctvault-dev sample capture ...` (below) | Google, opt-in |

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
database, not `$HOME`): dev vaults in `vaults/`, samples in `samples/`. It
keeps the same 85% disk cap, applied to the normal disk.

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

## Pending verification

**Real-SSD smoke test: not run yet.** As of 2026-10-04 there was no access to
the external drive. Every automated test passes, but `init` and `logs` have not
yet been run end to end on the real drive and enclosure (USB/UAS, and LUKS if
used). Run this before starting Plan 2 if possible, and in any case before
trusting the vault with data. The drive must be mounted at `/mnt/ctvault`,
ext4, and empty apart from `lost+found`:

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
