# Storage setup: an external SSD or a VM disk

CTVault writes only to a disk of its own. This guide prepares one, either an
external SSD on a Linux machine (option A) or a virtual disk added to a Linux
VM (option B), then runs `ctvault init` on it.

**Status:** the volume checks are covered by automated tests, and on a VMware
VM a second virtual disk passes them (`init` refused it only because it was
not empty). Neither procedure has been run end to end yet; see *Pending
verification* in the [README](../README.md).

## What the disk must be

`ctvault init` checks the disk before writing anything, and every later
command checks it again on start. Any failure exits 4 and writes nothing.

| Requirement | Why | Refusal message |
|---|---|---|
| A separate block device, not the one holding `/` | The vault must never fill the system disk. A loop image stored on the system disk counts as the system disk. | `… is on the same device as / …` |
| The vault root is a mount point | An unmounted path is just an empty folder on `/`. | `… is not a mount point; mount the external SSD there first` |
| ext4 | The only tested filesystem. xfs, btrfs and f2fs need `--allow-untested-fs`; exFAT, NTFS, FAT, FUSE, network filesystems and tmpfs are always refused. | `… CTVault requires ext4 …` |
| Not mounted with `nobarrier` or `barrier=0` | These options disable cache flushes. | `… which disables cache flushes` |
| Empty apart from `lost+found` (only at `init`) | The disk is dedicated to the vault. | `… is not empty (found "…")` |
| The same filesystem every time (only after `init`) | `VAULT_ID` records the filesystem UUID and type. | `… is filesystem … but VAULT_ID records …` |

One thing software cannot check: **the device must honour cache flushes.**
The crash guarantees (the power-loss gate passed on ext4) assume that a
flush reaches stable storage. A USB bridge with a volatile cache, or a
hypervisor that ignores flushes, can defeat them. Option A and option B
each say what to check.

## How much space

Bytes per entry, everything included:

| | Vault | Parquet | Pebble | Total |
|---|---|---|---|---|
| Measured (representative window, 2026-10-05) | 561 | 200 | 71 | **~830** |
| Disk-guard seeds (conservative) | 840 | 210 | 80 | **~1,130** |

`argon2027h1` had 384M entries on 2026-10-04 and grows by about 12M a day.
The spec expects it to end at **3.5B or more** (spec §10.2).

| Entries | Data | Disk needed at the 85% cap |
|---|---|---|
| 400M (October 2026) | 0.33–0.45 TB | 0.39–0.53 TB |
| 1B | 0.83–1.13 TB | 0.98–1.33 TB |
| 3.5B (the expected end of `argon2027h1`) | 2.9–4.0 TB | 3.4–4.7 TB |

- **The cap counts ext4's reserved blocks as used.** With the default 5%
  reservation only about 80% of the disk holds data. The `mkfs` commands
  below use `-m 0`, which is fine for a disk that holds only data.
- **The last few GB stay free.** Before each batch, the guard keeps room for
  the batch's peak below the cap: Pebble compaction (2 GiB, or 10% of the
  Pebble size), DuckDB spill (up to 4 GiB) and the batch itself.
- **A full disk is safe.** `update` exits 3 before a batch starts and
  corrupts nothing. Add space and run it again (see *More space later*).
- **Memory:** peak 2.0 GB measured, so give a VM 4 GB of RAM or more.
- **Time:** at the default 20 requests/s a batch of 500,000 entries took
  14.4 minutes, about 50M entries a day. Catching up the current ~400M takes
  roughly 10 days, and the machine or VM must stay up while `update` runs.

## Option A: external SSD on a Linux machine

**1. Connect it.** Use a UAS-capable enclosure, and check that the disk uses
the `uas` driver, not `usb-storage`:

```bash
lsusb -t                                            # look for Driver=uas
lsblk -o NAME,SIZE,TYPE,TRAN,MODEL,MOUNTPOINTS      # find the disk: TRAN=usb
```

**2. Partition and format it.** This **erases the disk**. Check the name
with `lsblk` first; below it is `/dev/sdX`.

```bash
sudo wipefs -a /dev/sdX
sudo parted --script /dev/sdX mklabel gpt mkpart ctvault ext4 0% 100%
sudo mkfs.ext4 -m 0 -L ctvault /dev/sdX1
```

**3. Mount it by UUID.**

```bash
sudo blkid -s UUID -o value /dev/sdX1               # prints <uuid>
sudo mkdir -p /mnt/ctvault
echo 'UUID=<uuid>  /mnt/ctvault  ext4  defaults,noatime,nofail,x-systemd.device-timeout=10s  0  2' \
  | sudo tee -a /etc/fstab
sudo systemctl daemon-reload
sudo mount /mnt/ctvault
sudo chown "$USER": /mnt/ctvault
```

`nofail` lets the machine boot without the drive. If the drive is missing,
`/mnt/ctvault` is an empty folder on `/`, and CTVault refuses it with exit 4.

**4. Check it.**

```bash
findmnt -no SOURCE,FSTYPE,OPTIONS /mnt/ctvault      # /dev/sdX1 ext4 rw,noatime,...
ls -A /mnt/ctvault                                  # lost+found only
```

**5. Create the vault.** See [Create the vault](#create-the-vault).

**Unplugging:** stop `update` first (one Ctrl-C finishes the current batch),
then run `sudo umount /mnt/ctvault`. If the drive is pulled during a batch,
the batch is abandoned and the next start recovers.

**Encryption (optional):** with LUKS, format and mount
`/dev/mapper/<name>` instead of `/dev/sdX1`. CTVault resolves the
device-mapper device to the disk behind it. Filesystem UUID resolution
through LUKS has not been checked on a real drive yet.

## Option B: a Linux VM with a virtual disk

Give the VM a **second virtual disk** for the vault. Inside the guest it is
its own block device, so it passes the system-disk check, even though on
the host it is a file.

Rules for the virtual disk:

- **Preallocate it** (thick, fixed size). The cap only sees the guest
  filesystem, not the host's free space. If a thin disk cannot grow because
  the host is full, the hypervisor pauses the VM or the guest gets write
  errors. A failed batch is abandoned and recovered, but `update` cannot
  make progress until the host has room.
- **Keep it out of VM snapshots.** Reverting a snapshot rolls the vault back
  to that moment. CTVault recovers it like a crash, but everything ingested
  since is lost, and `cert_id` values handed out since are issued again.
  Exports or notebooks made in the meantime may then point at different
  certificates.
- **Do not let the hypervisor ignore flushes** (see your hypervisor below).

### Add the disk

**VMware Workstation:** *VM → Settings → Add → Hard Disk → SCSI → Create a
new virtual disk*, set the size and tick *Allocate all disk space now*.
Then select the new disk, open *Advanced* and set *Mode: Independent,
Persistent* so snapshots leave it alone. Keep the other defaults. CTVault
has not been tested on VMware's flush behaviour.

**VMware ESXi / vSphere:** *Edit settings → Add new device → Hard disk*,
with *Thick provision* and *Disk mode: Independent - persistent*.

**KVM / libvirt (QEMU):** never use `cache=unsafe` or QEMU's `-snapshot`
option, which ignore guest flushes. The default `writeback` and `none` both
honour them.

```bash
sudo qemu-img create -f raw -o preallocation=falloc /var/lib/libvirt/images/ctvault.raw <size>
sudo virsh attach-disk <vm> /var/lib/libvirt/images/ctvault.raw vdb \
  --driver qemu --subdriver raw --cache none --persistent
```

**VirtualBox:** VirtualBox **ignores guest flush requests by default**.
Turn flushing on for the vault disk; the `LUN#` number is the SATA port the
disk is attached to.

```bash
VBoxManage createmedium disk --filename ctvault.vdi --size <MiB> --variant Fixed
VBoxManage storageattach "<vm>" --storagectl "<SATA controller name>" \
  --port 1 --device 0 --type hdd --medium ctvault.vdi
VBoxManage setextradata "<vm>" "VBoxInternal/Devices/ahci/0/LUN#1/Config/IgnoreFlush" 0
```

### Inside the guest

If the disk was added while the VM was running and `lsblk` does not show it,
rescan the SCSI bus:

```bash
echo "- - -" | sudo tee /sys/class/scsi_host/host*/scan
lsblk -o NAME,SIZE,TYPE,MOUNTPOINTS                 # the new, empty disk, e.g. sdc or vdb
```

Then follow steps 2 to 4 of option A, with the new disk in place of
`/dev/sdX`, and create the vault.

## Create the vault

```bash
go build -o ctvault ./cmd/ctvault
./ctvault init /mnt/ctvault                         # reports "durability tested"
export CTVAULT_ROOT=/mnt/ctvault
./ctvault logs add argon2027h1
./ctvault logs info argon2027h1                     # ends with "signature  verified with pinned key"
./ctvault update                                    # or: update --follow
./ctvault stats                                     # disk use per volume and the projected cap date
```

The root may later be mounted at a different path: pass the new path with
`--root` or `CTVAULT_ROOT`. Its filesystem must stay the same.

## More space later

**Grow the virtual disk (option B).** Enlarge it in the hypervisor, then
grow the partition and the filesystem inside the guest. ext4 grows while
mounted, and the filesystem UUID that CTVault checks stays the same.

```bash
sudo growpart /dev/sdX 1                            # package cloud-guest-utils
sudo resize2fs /dev/sdX1
```

**Add a second disk (both options).** `ctvault vault add-dir` adds a
directory for more vault segments:

```bash
# prepare and mount the second disk at /mnt/ctvault2 as in steps 2 to 4
sudo mkdir /mnt/ctvault2/vault
sudo chown "$USER": /mnt/ctvault2/vault
./ctvault vault add-dir /mnt/ctvault2/vault
```

- The directory must be empty and on ext4, on a disk other than `/`. Unlike
  the root, it does not have to be a mount point itself.
- `VAULT_ID` records its absolute path, so it must be mounted at the same
  path every time.
- **Only vault segments move.** Parquet, Pebble, `tmp/` and the logs stay on
  the root, about 270–290 B per entry, roughly 1 TB for 3.5B entries. Size
  the root for that.
- Each batch writes its segments to the first vault directory, in the order
  they were added, where the batch fits next to the root's own needs. The
  root's `vault/` fills first, then the next one.

## Without a separate disk

The production binary always refuses the system disk. To try CTVault on the
normal disk, use the dev build (`go build -tags ctvault_dev`): its vaults live
under `~/.cache/ctvault-dev/`, are marked as dev vaults, and the production
binary refuses them. See *Development build* in the [README](../README.md).
