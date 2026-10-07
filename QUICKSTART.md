# CTVault quick start

From nothing to your first search. The full reference is the
[README](README.md).

## What you need

- Linux.
- Go 1.26.8 or newer, and `gcc`.
- **A disk only for CTVault:** an external SSD, or a second virtual disk in
  a VM. CTVault refuses to write to the system disk. Size: about 0.5 TB for
  what `argon2027h1` holds today, and 3.4–4.7 TB for the whole log once it
  stops growing in mid-2027 (see [storage-setup.md](docs/storage-setup.md#how-much-space)).
- Optional: the [DuckDB CLI](https://duckdb.org), for SQL queries.

## 1. Clone and build

```bash
git clone https://github.com/4rji/ctvault.git
cd ctvault
go build -o ctvault ./cmd/ctvault        # 1–2 minutes the first time; about 100 MB
sudo install -m 755 ctvault /usr/local/bin/
ctvault version
```

## 2. Prepare the disk

The disk must be ext4, empty, and mounted on its own mount point. With the
disk at `/dev/sdX` (**this erases it**; check the name with `lsblk` first):

```bash
sudo parted --script /dev/sdX mklabel gpt mkpart ctvault ext4 0% 100%
sudo mkfs.ext4 -m 0 -L ctvault /dev/sdX1
sudo mkdir -p /mnt/ctvault
sudo mount /dev/sdX1 /mnt/ctvault
sudo chown "$USER": /mnt/ctvault
```

To partition the disk, mount it at every boot (`/etc/fstab`), or add a
virtual disk to a VM, follow **[docs/storage-setup.md](docs/storage-setup.md)**.

## 3. Create the vault

```bash
ctvault init /mnt/ctvault                # reports "durability tested"
echo 'export CTVAULT_ROOT=/mnt/ctvault' >> ~/.zshrc   # or ~/.bashrc
export CTVAULT_ROOT=/mnt/ctvault
```

From now on every command uses that vault. The other way is
`--root /mnt/ctvault` on each command.

## 4. Choose a log

```bash
ctvault logs list --available            # every log in Chrome's log list
ctvault logs add argon2027h1             # pin the log and its public key
ctvault logs info argon2027h1            # ends with "signature  verified with pinned key"
```

## 5. Download certificates

Try a small piece first, about half an hour:

```bash
ctvault update --until 1000000           # the first 1,000,000 entries
ctvault stats                            # progress, disk use, ETA
```

Then download the rest. The current size takes roughly 10 days, so run it
inside `tmux` (or `screen`) so that it survives closing the terminal:

```bash
tmux new -s ctvault
ctvault update --follow                  # catch up, then a new cycle every 10 minutes
# detach with Ctrl-b d; come back with: tmux attach -t ctvault
```

- **Stopping:** one Ctrl-C finishes the current batch and stops. A second one
  abandons the batch, which is fetched again next time.
- **Resuming:** run `ctvault update` again. It continues after the last
  committed batch, also after a crash or a power cut.
- **Full disk:** `update` stops with exit code 3 and corrupts nothing. Add
  space as in [storage-setup.md](docs/storage-setup.md#more-space-later).

## 6. Search

Searches work while `update` runs; they see the batches committed so far.

```bash
ctvault search example.com                            # names under example.com, newest first
ctvault search --exact www.example.com
ctvault search --suffix api.example.com --group certs # one row per certificate
ctvault search example.com --issuer R12 --since 2026-10
ctvault search --ip 192.0.2.1
ctvault search --help                                 # every filter
```

## 7. Look at a certificate

```bash
ctvault fetch <sha256>                         # PEM, verified against its SHA-256
ctvault fetch <cert_id> --format text --with-chain
```

## 8. Explore in the terminal

```bash
ctvault explore example.com
```

`Tab` switches names, certificates and issuances, `Enter` opens a row, `f`
shows the certificate, `e` exports, and `?` lists every key. It needs a
terminal of at least 80×24.

## 9. Export

```bash
ctvault search example.com --format csv --output example.csv
ctvault search example.com --format json --output example.json
```

The metadata saved with each export (the query, the snapshot and each log's
verified head) lets you re-run it and get the same result.

## 10. SQL with DuckDB

No CTVault process is needed:

```bash
duckdb -c ".read /mnt/ctvault/views.sql" -c "SELECT count(*) FROM entries"
duckdb -c ".read /mnt/ctvault/views.sql" \
  -c "SELECT c.issuer_cn, c.not_before FROM names n JOIN certs c USING (cert_id) WHERE n.etld1 = 'example.com'"
```

The tables are `entries`, `chains`, `certs`, `names`, and the policy and
extension tables listed in the [README](README.md).

## 11. Check the vault

```bash
ctvault verify                  # seconds: manifests, sizes, signed heads
ctvault verify --full           # reads everything: checksums, records, Merkle trees
```

Both run while `update` runs and change nothing.

## Updating CTVault

```bash
git pull
go build -o ctvault ./cmd/ctvault && sudo install -m 755 ctvault /usr/local/bin/
ctvault update
```

If the new version brings a new version of a table, `update` rebuilds one old
batch after each new one, and `ctvault rebuild` does the rest at once. If the
disk has no room for both copies, see `rebuild --in-place` in the
[README](README.md).

## When something fails

| Exit code | Meaning | What to do |
|---|---|---|
| 2 | Wrong command or flag | `ctvault <command> --help` |
| 3 | The disk reached its 85% cap | Add space ([storage-setup.md](docs/storage-setup.md#more-space-later)) |
| 4 | Volume check failed | The disk is not mounted, or a different disk is at that path |
| 5 | Verification failed or damage found | Read the message; see *Verify* and *Repairs* in the [README](README.md) |

`ctvault explain-error <code>` explains the error codes stored with
certificates that did not parse.
