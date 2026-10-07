# CTVault A7 (D Fields): Summary

Built directly in the tree, as A6 was: tests first, the usual gate, real data, and this summary instead of a plan document. Everything ran offline, on the samples already cached on `/mnt/disk`.

**Spec:** amendment A7 (`docs/superpowers/specs/2026-10-07-ctvault-d-fields-amendment.md`), approved 2026-10-07 section by section and then as written ("sigue").
- Coverage: choice A, the six decoded tables plus an extension inventory.
- Surfaces: choice A, the dataset and `views.sql` only.
- Approach: choice 1, decoders in their own package and the extractor untouched.

**Result:** research area D is in the dataset. Seven tables of certificate policies and extensions are built from the vault. On 303,148 real certificates their decoding agrees exactly with `crypto/x509`. They add 56 B of Parquet per entry and no measurable ingest time. `certs` and `names` keep every byte.

## What It Adds

| Piece | Where | What it does |
|---|---|---|
| The decoders | `internal/extdecode` | One pure function per extension: certificate policies, EKU, keyUsage, basicConstraints, AIA, CRL distribution points, the SCT list. Each takes the raw value the extractor keeps, and returns the whole extension or one of 8 stable codes. OIDs are read as `crypto/x509` reads them, arcs of any size included. `Version` is `ctvault-extdecode/1`. |
| The seven tables | `internal/derive/dtables.go` | `cert_extensions`, `cert_policies`, `cert_ekus`, `cert_key_usage`, `cert_aia`, `cert_crl_dps`, `cert_scts`, all at v1. They follow `certs` and `names` in the registry. Their files carry `ctvault.decoder`, and `certs` and `names` carry no new metadata. |
| Codes | `internal/cli/explain.go`, `testdata/error_codes.txt` | The `extdecode` family enters the frozen registry. `explain-error` reports these as certificate extension errors. |
| Disk guard | `internal/diskguard` | The Parquet seed goes from 210 to 265 B per entry. |
| Recovery | `internal/commit/recover.go` | The sweep of interrupted atomic writes now includes `dataset/` (see Findings). |
| Smaller | `extract.Display`, `cli/rebuild.go` | The extractor's display escaping is exported, with unchanged output, so URIs are escaped like DNS names. `rebuild` lists tables as a sentence. |

## Decisions to Review

A7's 12 decisions are as approved. The final review was a self-review, with no fresh reviewer. The build added these:

| # | Decision | Why |
|---|---|---|
| 1 | **Positions and counts are `UINTEGER`, not A7's `USMALLINT`.** A7 is updated to match. | A certificate may be up to 16 MB, so one could hold more than 65,535 extensions or qualifiers. Parquet encodes values, not declared widths, so the wider type costs nothing. |
| 2 | **A v1 SCT claiming a time after 9999-12-31 gets a null `timestamp`,** with its other fields kept. A7 is updated. | A `TIMESTAMP` column cannot hold it, and a build must never fail on a certificate. |
| 3 | **The corpus golden is split:** `certs` and `names` stay in their file, and the D tables get a new one. | The untouched file, still `8a3f641c…`, proves those tables' rows are unchanged. |
| 4 | **The test registries are built from the real one, with `certs` swapped.** | Test-only versions then carry the D tables, as a real binary would. |
| 5 | **Unknown keyUsage bits past `decipherOnly` are ignored, as `crypto/x509` ignores them.** | They have no defined meaning; every defined bit is still read whole. |

## Findings, Fixed

1. **Recovery did not sweep `dataset/` for an interrupted `ACTIVE.json` write.** This predates A7.
   - **How it was found:** the random kill loop, with the D tables registered, killed a writer inside `WriteActive` and left `.ACTIVE.json.tmp-*` behind.
   - **Fix:** the sweep includes `dataset/`. `TestRecoverRemovesInterruptedAtomicWrites` went RED, then GREEN.
2. **Tests that assumed only two tables** had counts and messages hard-coded: `repair --derived`'s file counts, the ACTIVE check's made-up table name, and `rebuild`'s message. They now count from the registry.

## Evidence (2026-10-07)

1. **The gate:** gofmt clean; `go vet` clean with every tag set; race tests pass in production (34 packages) and dev builds (35 packages).
2. **Decoders:**
   - round trips through `x509.CreateCertificate`;
   - hand-built qualifiers, CRL points and SCT lists;
   - the meaning-neutral cases;
   - a table of malformed inputs;
   - a 30-second fuzz run;
   - mutations, 4 of 4 caught: a missing trailing-bytes check, a CPS of any type, a negative path length, bytes after an SCT.
3. **The differential on real data,** over every certificate of the four cached samples:
   - 303,148 unique certificates, all parsed by `crypto/x509`, with **0 differences** and **0 decoding codes**;
   - 484,692 embedded SCTs, every log ID found in the v93.3 or v93.6 lists;
   - with the OCSP and caIssuers methods swapped on purpose, the test reports 295,061 differences.
4. **Builders and rollout:**
   - golden rows over the extractor's 2,710-certificate corpus;
   - `TestDRows` covers each rule: duplicates, malformed extensions, keyUsage or basicConstraints alone, a point without a URI, a non-v1 SCT, a timestamp after year 9999;
   - `TestDTablesRollout`: a vault written without D gets the tables in turns, its views switch, `certs` and `names` keep their sums, and recovery and derived checks pass;
   - the ingest-versus-rebuild equivalence tests and the crash suites loop over the registry, so they cover D.
5. **Real data:**

   | Run | Result |
   |---|---|
   | `rebuild` on the `a6mixed` dev vault (`argon2027h1` and `parcelyard2027h1`, 151,200 entries) | 16 batches in 12.2 s, all seven tables complete |
   | `verify --full` on it | No damage: 9 tables complete, 176 files match their checksums |
   | Bytes per entry | `cert_scts` 19.3, `cert_extensions` 9.0, `cert_aia` 6.8, `cert_policies` 5.9, `cert_ekus` 5.2, `cert_crl_dps` 5.0, `cert_key_usage` 4.8: **56.0 in all** (the prototype said 53–57) |
   | Ingest cost, `sample measure` of the ParcelYard window | Batch times 2.6–3.0 s per 10,240 entries, against 2.5–2.6 s without D. Parquet 211–223 B per entry against 159–165, under the 265 B seed. |
   | Queries through `views.sql` | OCSP URLs on 96% of Argon's leaves against 57.4% of ParcelYard 2027h1's; 132,284 DV, 10,993 OV, 278 EV and 1 IV certificate; most finals embed 3 SCTs; 25,858 leaves allow `clientAuth`; 0 decoding errors in 1.48 million extension rows |
   | `go test -tags realdata ./...` | All 36 packages pass, with the decoder differential and the integration tests, whose rebuild equivalence now covers the D tables |

## Known Gaps

- **A7 §6's out-of-scope items:**
  - `search`/`explore` filters and `fetch` text;
  - SCT signature checks;
  - mapping `log_id` to log names;
  - decoding more extensions (name constraints, must-staple and others), which `cert_extensions` already records.
- **The `a6mixed` dev vault now holds D.** It lives at `~/.cache/ctvault-dev/vaults/a6mixed`.
