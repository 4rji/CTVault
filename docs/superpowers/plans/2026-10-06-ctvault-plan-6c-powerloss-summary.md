# CTVault Plan 6C (The Power-Loss Gate): Summary

Built directly in the tree, as 6A and 6B were: tests first, the usual gate, and this summary instead of a plan document. The privileged run was done by the user, as one sudo command (choice A).

**Spec:** amendment A5 Part 6C (`docs/superpowers/specs/2026-10-06-ctvault-plan6-amendment.md` §13–§17), approved 2026-10-06 section by section and then as written.

**Result:** **the gate passes.** In the full run, every one of the 948 checked crash points recovered. Each then passed `verify --full` and the checks across points. The replayer's self-check and the final state also passed.

## What It Adds

| Piece | Where | What it does |
|---|---|---|
| The replayer | `internal/powerloss/logwrites.go` | It reads a `dm-log-writes` log (the super, then each entry's header and data) and replays it onto an image file. Writes are applied, discards zero their range, and marks name the phase. A crash point is any flush or FUA entry. A log with the wrong magic or version, or cut short, is refused. |
| The checks | `internal/powerloss/check.go` | `Inspect` recovers the vault by opening its writer, then requires `verify --full` to find no damage, nothing pending and a sound index. `Tracker.Compare` checks that nothing goes backwards across points: earlier commits survive with identical manifests, each `cert_id` keeps its certificate, and `ACTIVE.json`'s `seq` never decreases. |
| The workload | `internal/powerloss/workload.go` | A fresh vault and an in-process fake log, then four phases, each preceded by a mark in the log: ingest (12 batches, a trained dictionary, rolled segments), an upgrade to the test `certs` v2 (two dual-built batches with turns, then the switch), `gc`, and `repair --reindex`. It drives the writer in-process. |
| Safety checks | `internal/powerloss/safety.go` | A loop device is used only if it is a `/dev/loopN` attached to the run's own file. The device-mapper target has its own name, and an earlier run's leftovers are listed. |
| The root run | `internal/powerloss/powerloss_test.go`, build tag `powerloss` | It sets up the image, its log and the `log-writes` target, mounts it, and records the workload. Then it replays the log, checks each point on a mounted copy, runs the self-check and the final check, and writes `report.json` and `points.log`. It releases every device on exit or interrupt, and gives the files back to the user who ran sudo. |

**Run it again:**
```
go test -c -tags powerloss -o /mnt/disk/ctvault/powerloss/powerloss.test ./internal/powerloss/
sudo /mnt/disk/ctvault/powerloss/powerloss.test -test.run TestPowerLoss -test.v -test.timeout 2h
```
`-powerloss.every N` checks every Nth point, for a quick run; `-powerloss.dir` moves the run folder.

## Decisions to Review

A5's 8 decisions (24–31) are as approved. The implementation added these:

| # | Decision | Why |
|---|---|---|
| 1 | **A `setup` phase comes first and is not checked.** It creates the vault's folders, durably, and pins the fake log. | It is `init`'s work, not the commit protocol. Its 29 points have no vault yet to recover. |
| 2 | **Recovery at each point runs as the binary that was running then:** v1 through ingest, the test v2 from the upgrade on. | A real power loss is followed by the same binary's restart. |
| 3 | **`mkfs` runs on the image file, never on a device.** The run deletes nothing, and the images stay in its folder. | It's the smallest set of root actions. Each run folder holds 204 MiB on disk (2.3 GiB apparent: the log is sparse). |
| 4 | **The images aren't fsynced per point.** | Loop devices read the copies through the page cache. |
| 5 | **A loop device that fails the safety check is never touched again, not even detached.** | A wrong device must not be acted on in any way. The report would name it. |
| 6 | **The workload pins its fake log as `logs add` does,** and its upgrade runs one turn after each new batch, as `update` does. | `verify` checks signed heads; turns interleaved with ingestion are part of what is recorded. |
| 7 | **The kernel's own `dm-log-writes-end` mark appears as an empty phase in the report.** | It's what the log holds, shown as is. |

## A Finding, Fixed

**`verify` reported recovery's abandoned intents as "recovery pending".**
- **What happens:** after a crash in the middle of a batch, recovery keeps the batch's intent, marked abandoned. That lets the next start resume at `ID_FLOOR`, so no `cert_id` is reused (spec §8.6).
- **The effect:** that is the recovered state, yet the first, quick run failed 17 of its 48 points on it. All 17 were this one false positive.
- **The fix:** `verify` now treats an abandoned intent as recovered (`TestAbandonedIntent`, RED then GREEN). The binary was rebuilt, and the full run passed.

## Evidence (2026-10-06)

1. **Without root** (in the gate):
   - `TestReplay`: writes, discards, marks, flushes, FUA, and a flush with data;
   - `TestDamagedLogs`: wrong magic or version, cut short, too small, a write past the end;
   - `TestTrackerCompare`: a lost batch, a changed manifest, a reused `cert_id`, `seq` going back. Removing each rule makes it fail (4 of 4 mutations caught);
   - `TestWorkload`: a copy of the vault taken at each mark passes `Inspect` and `Compare` in order. The final vault has a dictionary, several segments, `certs` v2 active, no v1 file, and no reindex leftover;
   - `TestCheckLoop`, `TestLeftovers`, `TestAbandonedIntent`.
2. **The full run, by the user** (kernel 6.12.107, ext4 with `rw,relatime` and the default `data=ordered`):

   | Phase | Flush | FUA | Checked |
   |---|---|---|---|
   | setup | 14 | 15 | not checked |
   | ingest | 229 | 228 | 457 |
   | upgrade | 166 | 128 | 294 |
   | gc | 58 | 58 | 116 |
   | reindex | 31 | 25 | 56 |
   | end (the unmount) | 14 | 11 | 25 |
   | **all** | | | **948 of 977, 0 failed** |

   - **Self-check:** replaying all 4,231 entries gave the final device byte for byte, so the replayer reads this kernel's format.
   - **Final check:** the replay ends with the run's 14 committed batches.
   - **Time:** 4 min 34 s, with a median of 0.30 s per point (95th percentile 0.33 s, maximum 0.56 s).
3. **Gate:** gofmt clean; `go vet` clean with 4 tag sets, plus `powerloss` checked separately; race tests pass in production and dev builds (31 packages).

## Known Gaps

- **Unflushed writes are not reordered.** Each crash point drops everything after the last flush together, as xfstests' check mode does (A5 decision 26).
- **In-place conversion and `repair --derived` are not recorded** (A5 §14). The SIGKILL suites cover their primitives.
- **One kernel, one set of mount options.** The run used `data=ordered`; `data=writeback` and `data=journal` are not tested.
- **The run folders keep their images** for inspection. Delete `/mnt/disk/ctvault/powerloss/run-*` when you no longer need them.
