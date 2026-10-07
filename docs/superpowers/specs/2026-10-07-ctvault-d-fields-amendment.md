# CTVault Spec Amendment A7: D Fields (Policies and Extensions)

- **Date:** 2026-10-07
- **Status:** approved section by section on 2026-10-07 (§1–§4 as presented), then as written ("sigue"). Built in the tree on 2026-10-07 (summary: `docs/superpowers/plans/2026-10-07-ctvault-d-fields-summary.md`).
- **Amends:** `docs/superpowers/specs/2026-10-04-ctvault-design.md` ("the spec") §1.1–§1.2, §7.5, §10.1 and §14, and amendments A1–A6.
- **Origin:** the D-fields design discussion, after A6.
  - Coverage, choice A: the spec's six decoded tables plus an extension inventory.
  - Surfaces, choice A: the dataset and `views.sql` only.
  - Approach, choice 1: decode in new builders and leave the extractor alone, with flat tables.
- **Lifts:** spec §1.2's non-goal "D tables". Research area **D** (spec §1.1, goal 3) joins A, B, C and E.

Everything not changed here stays as in the spec and A1–A6. **Production safety requirements are unchanged.** The commit protocol, recovery, the disk guard, `verify` and the transition rules apply to the new tables as to `certs` and `names`.

---

## 0. At a glance

**What A7 adds**
- **Seven derived tables, built from the vault** and never downloaded again: `cert_extensions`, `cert_policies`, `cert_ekus`, `cert_key_usage`, `cert_aia`, `cert_crl_dps` and `cert_scts`.
- **The decoders,** in a new package, `internal/extdecode`. They read the raw extension values the extractor already keeps.
- **Nothing existing changes:** the extractor, `ExtractorVersion`, `certs` and `names` keep their code and their bytes.

### Measurements behind the design (2026-10-07, offline, on the cached samples)

**Extension census** of leaf certificates:

| | `argon2027h1 [0, 100000)` | `parcelyard2026h2`, a window at its head |
|---|---|---|
| CA/B Forum DV policy (2.23.140.1.2.1) | 90.6% | 99.8% |
| OV policy (2.23.140.1.2.2) | 5.2% | 0.2% |
| AIA rows per certificate | 1.92 (OCSP and caIssuers) | 1.02 (caIssuers only) |
| CRL distribution points present | 94.0% | 99.3% |
| SAN marked critical | 0% | 89.2% (an empty subject) |
| Subject key ID present | 95.4% | 12.6% |
| Embedded SCT list | 79.2% of leaves, 358 B | 88.2%, 253 B |
| Extensions per certificate | about 9.8 | about 9.1 |

**Size**, from a prototype of the seven tables written with `certs`' Parquet settings (zstd, row groups of 122,880, dictionaries up to 122,880), per log entry:

| Table | Argon | ParcelYard |
|---|---|---|
| `cert_extensions` | 8.6 B | 8.0 B |
| `cert_policies` | 5.3 B | 5.0 B |
| `cert_ekus` | 5.5 B | 5.0 B |
| `cert_key_usage` | 4.9 B | 5.1 B |
| `cert_aia` | 7.0 B | 5.7 B |
| `cert_crl_dps` | 4.6 B | 6.8 B |
| `cert_scts` | 21.6 B | 17.8 B |
| **All seven** | **57.4 B** | **53.3 B** |

That is about 25% more Parquet than today's 210 B per entry, or about 21 GB for `argon2027h1`'s 390 million entries.

## 1. The tables (refines spec §7.5)

**Rules for all seven tables:**
- **Which certificates:** every unique certificate, precert, final or chain. That is the same set as `certs`, and each certificate's rows go in the batch whose `certs` row it has.
- **Row order:** by `cert_id`, then by the extension's or list's own order.
- **`cert_id`:** every table's first column, `UBIGINT`.
- **Strings from certificates** (URIs, the CPS URI) are display-escaped the way the extractor escapes DNS names: bytes outside printable ASCII are written `\XX`.
- **No BLOB columns** (D19).
- **Positions and counts are `UINTEGER`.** A certificate may be up to 16 MB, so one could hold more than 65,535 extensions or qualifiers. Parquet encodes values, not declared widths, so the wider type costs nothing (a build ruling, 2026-10-07).

| Table | One row per | Columns after `cert_id` |
|---|---|---|
| `cert_extensions` | extension, in certificate order | `position UINTEGER`, `oid VARCHAR` (dotted), `critical BOOLEAN`, `length UINTEGER` (bytes of the extnValue's content), `decode_error VARCHAR` |
| `cert_policies` | PolicyInformation | `position UINTEGER`, `policy_oid VARCHAR`, `validation VARCHAR`, `cps_uri VARCHAR`, `n_qualifiers UINTEGER` |
| `cert_ekus` | KeyPurposeId | `position UINTEGER`, `eku_oid VARCHAR`, `eku_name VARCHAR` |
| `cert_key_usage` | certificate with a decoded keyUsage or basicConstraints | `digital_signature`, `content_commitment`, `key_encipherment`, `data_encipherment`, `key_agreement`, `key_cert_sign`, `crl_sign`, `encipher_only`, `decipher_only` (all `BOOLEAN`), `is_ca BOOLEAN`, `path_len USMALLINT` |
| `cert_aia` | AccessDescription | `position UINTEGER`, `method VARCHAR`, `uri VARCHAR` |
| `cert_crl_dps` | URI in a DistributionPoint | `dp_index UINTEGER`, `uri VARCHAR`, `has_reasons BOOLEAN`, `has_crl_issuer BOOLEAN` |
| `cert_scts` | SCT in an embedded SCT list | `position UINTEGER`, `version USMALLINT`, `log_id VARCHAR` (lowercase hex), `timestamp TIMESTAMP` (ms), `hash_alg USMALLINT`, `sig_alg USMALLINT` |

**Column rules**
- **`cert_extensions.decode_error`** is null unless the extension is one of the seven types D decodes (§2) and that decoding failed, or it repeats an earlier one (`ext_duplicate`).
- **`validation`** comes from the CA/B Forum policy OIDs: `2.23.140.1.2.1` is `dv`, `2.23.140.1.2.2` `ov`, `2.23.140.1.2.3` `iv`, and `2.23.140.1.1` `ev`. Any other policy has null.
- **`cps_uri`** is the first qualifier with `id-qt-cps` (1.3.6.1.5.5.7.2.1); `n_qualifiers` counts every qualifier.
- **`eku_name`:**

  | OID | Name |
  |---|---|
  | `1.3.6.1.5.5.7.3.1` | `server_auth` |
  | `.2` | `client_auth` |
  | `.3` | `code_signing` |
  | `.4` | `email_protection` |
  | `.8` | `time_stamping` |
  | `.9` | `ocsp_signing` |
  | `2.5.29.37.0` | `any` |
  | `1.3.6.1.4.1.11129.2.4.4` | `precert_signing` |
  | anything else | null |
- **`cert_key_usage`:** the nine keyUsage columns are null when keyUsage is absent or did not decode. `is_ca` is null when basicConstraints is absent or did not decode. `path_len` is null unless pathLenConstraint is present. A certificate with neither extension decoded has no row.
- **`cert_aia.method`:** `ocsp` for `1.3.6.1.5.5.7.48.1`, `ca_issuers` for `1.3.6.1.5.5.7.48.2`, otherwise the dotted OID. `uri` is the uniformResourceIdentifier, and null for any other GeneralName type.
- **`cert_crl_dps`:**
  - one row per uniformResourceIdentifier in a point's `fullName`, with `dp_index` the point's position;
  - a point with no URI (only `nameRelativeToCRLIssuer`, only `cRLIssuer`, or other name types) gets one row with `uri` null;
  - `has_reasons` and `has_crl_issuer` say whether those fields are present.
- **`cert_scts`:**
  - from the extension `1.3.6.1.4.1.11129.2.4.2`, in whatever certificate carries it;
  - an SCT whose version is not v1 (0) has a row with `position` and `version` only;
  - a v1 SCT claiming a time after 9999-12-31 keeps its other fields with a null `timestamp`, which a `TIMESTAMP` column cannot hold (a build ruling);
  - SCT signatures and extensions are not stored, and `log_id` is not mapped to a log name (§6).

## 2. Decoding and errors (refines spec §7.1)

**Code layout**
- **`internal/extdecode`:** one pure function per decoded extension, from the raw value to items or a stable code, written with `cryptobyte`:

  | Extension | OID |
  |---|---|
  | certificatePolicies | `2.5.29.32` |
  | extKeyUsage | `2.5.29.37` |
  | keyUsage | `2.5.29.15` |
  | basicConstraints | `2.5.29.19` |
  | authorityInfoAccess | `1.3.6.1.5.5.7.1.1` |
  | cRLDistributionPoints | `2.5.29.31` |
  | the embedded SCT list | `1.3.6.1.4.1.11129.2.4.2` |

- **The builders,** in `derive`, read `extract.Cert.Extensions` and call one decoder each. A certificate the extractor could not fully parse contributes what it did read; no certificate is dropped.

**Rules**
- **All or nothing per extension:** anything malformed (a length, a tag, an unexpected type, bytes left over) gives that extension no rows in its table and sets its `cert_extensions.decode_error`. A decoder never returns part of an extension.
- **Meaning-neutral deviations are accepted:** an explicitly encoded `cA FALSE`, which DER says to omit, and trailing zero bits in keyUsage's BIT STRING. `crypto/x509` accepts both, and they change nothing about what the certificate says.
- **A decoded extension that appears twice** (RFC 5280 forbids it): the first copy is decoded, and later copies get `ext_duplicate` and no rows.
- **The SCT list** is an OCTET STRING holding a TLS `SignedCertificateTimestampList`: a 16-bit-length list of 16-bit-length SCTs. Its framing must be exact. Each v1 SCT is `version`, `log_id[32]`, `timestamp` (uint64 ms), extensions (16-bit length), then a digitally-signed value: hash, signature algorithm, and a 16-bit-length signature.

**Error codes:** new and frozen, in the registry family `extdecode`, documented by `explain-error`.

| Code | Meaning |
|---|---|
| `ext_policies_malformed` | certificatePolicies did not decode |
| `ext_eku_malformed` | extKeyUsage did not decode |
| `ext_key_usage_malformed` | keyUsage did not decode |
| `ext_basic_constraints_malformed` | basicConstraints did not decode |
| `ext_aia_malformed` | authorityInfoAccess did not decode |
| `ext_crl_dps_malformed` | cRLDistributionPoints did not decode |
| `ext_sct_list_malformed` | the embedded SCT list's framing did not decode |
| `ext_duplicate` | a second copy of an extension D decodes |

## 3. Versions, rollout, views and disk (refines spec §7.2, §7.5, §7.6, §10.1)

**Registration and metadata**
- **The registry order** becomes `certs`, `names`, `cert_extensions`, `cert_policies`, `cert_ekus`, `cert_key_usage`, `cert_aia`, `cert_crl_dps`, `cert_scts`. All seven new tables are at **v1**.
- **`ctvault.decoder`:** a new optional `Table.Decoder` adds this Parquet key to the files of tables that set it. Its value for all seven is `ctvault-extdecode/1`.
  - A change to a decoder bumps it, and with it the version of every table that decoder feeds.
  - `certs` and `names` set no decoder, so their metadata, and their bytes, stay as they are.

**Rollout, through the existing new-table path (spec §7.8, A5 §7–§8)**
- **A vault with no batches** marks the seven tables complete at once. The production vault will be such a vault, so D is there from its first batch.
- **A vault with batches** marks them `building`.
  - New batches build them, `update` rebuilds old batches in turns, and `ctvault rebuild` does it all at once.
  - `views.sql` shows `<table>_building` until every batch has the table, then `<table>`.
- `verify`, `stats`, `repair --derived` and `gc` handle the new tables through the registry, as they handle `certs` and `names`. A7 adds tests, not logic, for them.

**Views:** the seven tables are exposed through `ACTIVE.json` like any other table. There are no helper views or OID lookup tables; `validation` and `eku_name` cover the common questions.

**Disk guard:** the Parquet seed goes from 210 B per entry to **265 B**: 210 plus the measured 53–57 B, rounded up. A1 §8 requires an explicit, reviewed edit to change a seed, and this is that edit.

## 4. Tests and evidence (adds to spec §13)

1. **The decoders:**
   - **Round trips:** each extension is encoded by `x509.CreateCertificate` from templates, and decoding gives back the template's values. SCT lists are built byte by byte, including a non-v1 SCT.
   - **Malformed input:** a table of inputs (cut, wrong tag, bytes left over, wrong inner type) expects each code.
   - **Accepted deviations:** an explicit `cA FALSE`, and trailing zero bits.
   - **Fuzzing,** per decoder: no panic, and the same result twice.
2. **Differential on real data** (the `realdata` tag), on every certificate of every cached sample, about 300,000:
   - **Against `crypto/x509`:** the decoded values must equal its policies, `ExtKeyUsage` with `UnknownExtKeyUsage`, `KeyUsage`, basic constraints (`IsCA`, `MaxPathLen`, `MaxPathLenZero`), `OCSPServer`, `IssuingCertificateURL` and `CRLDistributionPoints`. There must be 0 differences wherever `x509` parses the certificate. Certificates it refuses are counted and reported.
   - **SCTs:** every `log_id` is looked up in the v93.6 log list fixture. Unknown IDs are reported, not failed, because old logs leave the list.
3. **The builders:**
   - golden rows for the extractor's fixture certificates;
   - byte-identical files from two builds;
   - ingest compared with `rebuild`, through the existing equivalence test, extended to every registered table.
4. **Rollout:**
   - a vault written without D gets the seven tables through `update` turns;
   - its views switch from `_building` to the table names;
   - `verify --full` is clean;
   - 6B's crash suite runs with D registered;
   - `certs` and `names` files are byte-identical before and after D is registered.
5. **Codes:** the 8 codes enter the frozen registry, and `TestErrorCodesAreFrozen` and `explain-error` cover them.
6. **Real data:** on the `a6mixed` dev vault (`argon2027h1` and `parcelyard2027h1`), `rebuild` builds D, then `verify --full` runs. The build measures bytes per entry per table and the build time per entry.

## 5. Decisions this amendment adds

| # | Decision |
|---|---|
| 1 | `cert_key_usage` also holds basicConstraints, one row per certificate. (§1) |
| 2 | `validation` and `eku_name` are computed when the table is built, from fixed OID lists; changing a list is a new table version. (§1) |
| 3 | SCT signatures are not stored, and `log_id` is not mapped to a log name. (§1) |
| 4 | A malformed extension gives no rows in its table, only its `decode_error` in `cert_extensions`. (§1, §2) |
| 5 | The decoders are a separate package, `internal/extdecode`. (§2) |
| 6 | Each extension decodes completely or not at all; meaning-neutral deviations are accepted. (§2) |
| 7 | For a duplicated decoded extension, the first copy counts. (§2) |
| 8 | The decoder version is recorded as `ctvault.decoder`, on D tables only; `ExtractorVersion` is unchanged. (§3) |
| 9 | No helper views or OID lookup tables. (§3) |
| 10 | The Parquet seed becomes 265 B per entry. (§3) |
| 11 | SCT log IDs are checked against the log list, reported, never failed. (§4) |
| 12 | The differential compares only where `crypto/x509` parses; refusals are reported. (§4) |

## 6. Known gaps and future work (adds to spec §14)

| Item | Why it is out, and the seam |
|---|---|
| `search`/`explore` filters such as `policy:ev` or `ocsp:none`, and `fetch --format text` decoding | Choice A: the dataset first. These only read the new tables, so they can come later without touching data. |
| Verifying SCT signatures | It needs each log's key and the rebuilt TBS; the stored hash and signature algorithms keep the door open. |
| Mapping `log_id` to log names | The log list changes over time, so the mapping is not derived from the certificate. A future view could join a pinned log table. |
| Decoding more extensions (name constraints, must-staple, policy constraints and others) | Their presence, criticality and size are in `cert_extensions` already; each can become another table later without touching existing ones. |

## 7. How it is built

As A6 was: directly in the tree, tests first, then the usual gate, the real data and a summary document, with no plan document. It is built in this order:

1. `internal/extdecode`, its fuzzing and the real-data differential.
2. The seven builders, the registry entries, `Table.Decoder` and `ctvault.decoder`, and the new seed.
3. Rollout and views, the equivalence and transition tests, and the code registry.
4. Real data on `a6mixed`, then the README and the summary.
