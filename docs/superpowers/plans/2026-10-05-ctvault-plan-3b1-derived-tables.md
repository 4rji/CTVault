# CTVault Plan 3B-1 (Derived Tables in Ingest) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every batch also writes `certs.p1.parquet` and `names.p1.parquet`, built by the Plan 3A extractor from the certificates the batch vaults for the first time. `ACTIVE.json` records which derived tables are complete, and `views.sql` exposes them, with `entry_certs` and `logging_delay`.

**Architecture:**
- **A new package, `internal/derive`:**
  - the table registry: columns, `schema_sha256`, file name and Parquet KV metadata;
  - the `certs` v1 and `names` v1 builders, with DNS-name normalization and the pinned public-suffix list;
  - `ACTIVE.json`.
- **`internal/dataset`:**
  - a `DerivedStage` per batch streams each table's rows into DuckDB as they are built, and keeps only a uniform sample for the canary;
  - it writes each file deterministically: one DuckDB thread, insertion order, A2 §4.4's settings, KV metadata;
  - it runs the derived canary;
  - `views.sql` is generated from `ACTIVE.json`.
- **`internal/ingest`:**
  - P2 parses each newly vaulted certificate once and streams every enabled builder's rows into the stage. `kind` comes from the vaulting step; `delta_base_cert_id` comes from the delta cache, which now keeps the base's `cert_id`.
  - P5 writes the files, P6 runs their canary, and P7 records `builders`.
- **Scope:** the local backfill (`ctvault rebuild`, `_DERIVED.json`), the `ACTIVE.json` switch, `repair --reindex` and the "being built" warning are Plan 3B-2 (amendment A2 §5).

**Tech Stack:** Go 1.26.8 with cgo; DuckDB through `duckdb-go` v2.10506.0 (unchanged). **One new direct dependency:** `golang.org/x/net` v0.59.0, for `publicsuffix`.

**Spec:**
- `docs/superpowers/specs/2026-10-04-ctvault-design.md` §7.2–§7.6, §7.8 ("the spec")
- **Amendment A2:** `docs/superpowers/specs/2026-10-04-ctvault-plan3-amendment.md` §4 (approved 2026-10-05)

It builds on Plan 3A as applied to the working tree.

## Global Constraints

- **Platform:** Linux only, `go 1.26.8`, cgo (unchanged).
- **One new dependency:** `golang.org/x/net v0.59.0`, direct ("`golang.org/x/net` becomes a pinned dependency", A2 §4.1). Its embedded list is git `d6c92f1bbb7433e5db7b8405c25d4035fb8ff376` (2026-02-06T07:36:33Z).
- **The version registry** "records `extractor_version`, `schema_sha256` and, for `names`, `psl_snapshot`" (A2 §4.1).
- **Parquet settings** (A2 §4.4): "`COMPRESSION zstd`, `ROW_GROUP_SIZE 122880`, `DICTIONARY_SIZE_LIMIT 122880`"; "**No `BLOB` columns** in these files"; "`KV_METADATA`: `ctvault.table`, `ctvault.version`, `ctvault.extractor`, `ctvault.schema_sha256`, `ctvault.psl`".
- **Row order** (A2 §4.3): "`certs` by `cert_id`; `names` by `cert_id`, then SAN order, then the CN row". "DuckDB writes them with one thread, so files are byte-identical from the same binary."
- **`kind`** "comes from the vaulting step: a chain position, a `precert_entry`, or an `x509_entry` (whose full or delta record is a final)" (A2 §4.3).
- **`ACTIVE.json`** (A2 §4.6): `init` writes both tables complete at version 1. A Plan 2 vault first opened by a Plan 3 writer becomes `{active: null, building: 1, status: "building"}`. "An `ACTIVE.json` naming an unknown version" is refused.
- **Views** (A2 §4.7): "A partial table is never presented as complete."
- **"No certificate is ever dropped"** (spec §7.1). No certificate's content can make a batch fail to stage.
- **Quality gates, for every task:**
  - `gofmt -l .` prints nothing;
  - `go vet` is clean with no tags and with `ctvault_dev`, `realdata` and `nightly`;
  - `go test -race ./...` and `go test -race -tags ctvault_dev ./...` pass.
- **Real data:** `go test -tags realdata -timeout 90m ./internal/integration/`, without `-race` (Plan 2C, decision 20).
- **Temp space:** on this machine, use `GOCACHE=/mnt/disk/ctvault/gocache GOTMPDIR=/mnt/disk/ctvault/gotmp TMPDIR=/mnt/disk/ctvault/tmp`.

## Review Focus

1. **A batch that vaults no new certificate** (every certificate already vaulted, or only leaf errors).
   - Expected: both files are still written, with their schema and no rows, and they pass the canary.
   - Pinned by `TestStageDerivedEmpty` (Task B3).
2. **A certificate whose names hold invalid UTF-8, a NUL, a quote or a backslash.**
   - Expected: the rows hold the extractor's rendering (valid UTF-8, with `\XX` escapes), they read back unchanged, and the batch commits.
   - Pinned by `TestStageDerivedOddNames` (Task B3) and `TestNormalizeDNS` (Task B1).
3. **A Plan 2 vault** (batches, no `ACTIVE.json`) opened by this binary.
   - Expected: `building`; new batches write both files; `views.sql` exposes only `certs_building` and `names_building`, never `certs`.
   - Pinned by `TestActiveOnOpen`, `TestDerivedViewsFollowActive` (Task B2) and `TestBatchesBuildDerivedFiles` (Task B4).
4. **A crash at any commit boundary.**
   - Expected: every committed certs row matches its vault record (location, digest, kind, delta base), and the recovered vault's derived rows equal a clean ingest's except for internal IDs.
   - Pinned by `vaulttest.CheckDerived` inside `CheckRecovered` (Task B4) and the `Content` comparison in `TestCrashAtEveryBoundary`, `TestRandomKillLoop` and `TestRecoveryEquivalenceOnRealData` (Task B5).
5. **A batch at the default size** (`batch_size = 500000`) on a machine with a few GiB of RAM.
   - Expected: a batch's derived rows are never all held in Go memory; only the canary's sample is.
   - Pinned by `TestDerivedStageHoldsNoRows` (Task B3), with the measurements below.

## Decisions This Plan Adds

These choices are **not** in the approved sections. They were settled while building and testing this plan. Review them.

| # | Decision | Why |
|---|---|---|
| 1 | **`names` rows, in order:** dNSName SANs, then iPAddress SANs (each in SAN order), then every subject CN that differs from all SANs. `source` is `san_dns`, `san_ip` or `cn`. | The extractor keeps DNS and IP SANs in separate lists. A CN equal to a SAN would only duplicate it. |
| 2 | **DNS normalization:** ASCII lowercase and one trailing dot removed. `dns_valid` is lenient: labels of 1–63 characters from `a-z 0-9 - _`, 253 characters at most. A leftmost `*` label followed by others sets `is_wildcard`. A name already holding `\XX` escapes is kept as it is and is not valid. `tld` is `publicsuffix.PublicSuffix` (ICANN or private section); `etld1` is `EffectiveTLDPlusOne`, or null. Invalid names have null `tld` and `etld1`. | Real CT data has underscores and odd names. Search needs them kept and flagged, never dropped. |
| 3 | **A CN is a DNS name only when it has a dot or is a wildcard.** A CN that parses as an IP address is stored in canonical form, `dns_valid` false. Any other CN (`R3`, `GlobalSign`) is stored exactly as decoded, `dns_valid` false. | CA and organization CNs are not host names. Treating `R3` as a DNS name would invent a TLD. |
| 4 | **iPAddress SANs:** 4 bytes as a dotted quad, 16 bytes in RFC 5952 form, any other length as lowercase hex (the certificate already carries `san_ip_bad_len`). | Deterministic, and never drops a malformed value. |
| 5 | **NULL means unknown:** a field the extractor could not read, `key_bits` 0, a non-delta `delta_base_cert_id`, and `subject_key_id`/`subject_der` on leaves are NULL, never `''` or 0. Counts (`n_dns_names`, `n_ip_names`, `key_bits`) are capped at 65,535 (`USMALLINT`). | Queries can tell "absent" from a real value. |
| 6 | **A vault without `ACTIVE.json` and without committed batches is `complete`**, not `building`. | Nothing exists to backfill. A2 §4.6's `building` row is about vaults with Plan 2 batches. |
| 7 | **The writer's DuckDB session always runs one thread and preserves insertion order** (`SET preserve_insertion_order = true`, DuckDB's default made explicit), for `entries` and `chains` as well. The derived files are written in the order rows were added, with no sort. | Byte-identical files (A2 §4.3). A sort copied the whole staging table: 1,377 against 991 MiB peak for 500,000 certificates. |
| 8 | **Rows stream into DuckDB during P2** through a `DerivedStage` (DuckDB Appenders on a connection of its own). Go keeps only a uniform reservoir sample of `CanarySamples` rows per table for the canary. A failed attempt's stage is dropped. | Collecting the rows in Go until P5 took about 4 KB of heap per certificate: a 100,000-entry batch peaked at 1,566–1,662 MiB against Plan 2's 823 MiB, and the default batch is 500,000 entries on a 7 GiB machine. |
| 9 | **Empty views carry the table's exact columns plus `batch` and `log`** (the Hive partition columns), so a query's schema does not change when the first file appears. `entry_certs` is `entries` joined to every `certs` column except `cert_id`, `batch` and `log`. `logging_delay` has `log, idx, cert_id, ct_ts, not_before, logging_delay`. Both exist only while `certs` is complete. | A2 §4.7, with the column sets made explicit. |
| 10 | **The derived canary** checks every row of the reservoir sample (distinct rows, uniform over the batch). It looks `certs` rows up by a literal `sha256` (checking `cert_id` and the vault location) and `names` rows by `cert_id` and `name`. It requires bloom filters on `certs.sha256`, `names.name` and `names.etld1` in every row group where the column holds a value. | A2 §4.5. An earlier version sampled with replacement and missed bad rows (found by `TestDerivedCanaryCatchesBadFiles`). A row group of NULLs has no filter to require. |
| 11 | **Frozen identifiers:** `extractor` `ctvault-extract/1`. `schema_sha256` is the SHA-256 of the lines `"<name> <TYPE>\n"`: `certs` v1 `ced48dafaee44fa963d3b3bda2d7fbfe781753b28440c828cc039393fc859b17`, `names` v1 `82bd317eaa88ed33cfdbd8f825743fe3f4b3ca3d9b376b5016722d5ee8eb0f96`. A test fails if either changes. | Spec §7.2: a schema change is a new table version. |
| 12 | **Recovery equivalence now covers derived rows.** `vaulttest.Dump` returns a `Content` that also holds each certificate's `certs` row (without `cert_id`, vault location and delta base) and its `names` rows, keyed by SHA-256. | A1 §7's "equal except internal IDs", extended to the new files. Whether a final is a leaf-delta depends on the delta cache, so `CheckDerived` checks the delta base against the vault instead. |
| 13 | **The "being built" warning on `update`** arrives with `rebuild` in Plan 3B-2. | It is A2 §5.5, and until 3B-2 there is no command it could point to. |
| 14 | **`TestCanonicalIngestEndToEnd` gains the derived checks:** every batch's builders, certs rows = vaulted certificates, entries joined to certs, kinds against entry types, `logging_delay`, a literal `names.name` lookup, and 1,000 sampled certificates compared with the extractor. | A2 §4 end to end on real data. |

## Evidence Behind This Plan (measured 2026-10-05)

1. **Memory, the finding that reshaped Tasks B3 and B4.** Peak RSS of one real 100,000-entry batch (canonical sample, no dictionary training):

   | Version | Peak RSS | Go heap (HeapSys) | Time |
   |---|---|---|---|
   | Plan 2 ingest (before this plan) | 823 MiB | 763 MiB | 11 s |
   | Rows collected in Go until P5 (first version) | 1,566–1,662 MiB | 1,307 MiB | 16–19 s |
   | Rows streamed, files written with `ORDER BY` | 1,404 MiB | 967 MiB | 16 s |
   | **This plan** (streamed, insertion order) | **1,332 MiB** | 959 MiB | 16 s |

   - **The split, measured with two diagnostic builds:** rows built but discarded 849 MiB (parsing is cheap); rows kept but never staged 1,236 MiB. Holding rows in Go cost about 400 MiB per 100,000 entries, about 4 KB per certificate with GC headroom (1.7 KB live on the golden corpus).
   - **At 25,000-entry batches:** Plan 2 752 MiB, this plan 1,178 MiB. The rest of the cost is DuckDB's: the staging tables (about 1.3 KB per certificate) and the Parquet writer (about 310 MiB, bounded by the row group).
   - **`DerivedStage` alone, synthetic, 500,000 certificates and 766,935 names rows:** 991 MiB peak (1,377 MiB with the sort), of which 681 MiB before `Write`. 23.4 s: parse 5.9 s, `certs` rows 3.9 s, `names` rows 2.3 s, appending 3.9 s, writing 2.6 s, canary 2.5 s.
   - **Rejected:** a DuckDB `memory_limit`. At 512 MB it saved only 60 MiB; at 256 MB the batch failed with `Out of Memory Error ... writing certs.p1.parquet`, because the Parquet writer cannot spill.
   - **For Plan 4's bloom-filter decision:** `DICTIONARY_SIZE_LIMIT 122880` adds about 90 MiB to the writer's memory at 100,000 certificates (311 against 221 MiB). Without it the canary rejects the file (no `sha256` bloom filter), as designed.
2. **Speed:** one 100,000-entry batch takes 16 s against Plan 2's 11 s. The canary's 128 literal lookups cost about 1.7 s per batch whatever its size.
3. **Real data end to end:** the canonical sample (100,000 entries, batches of 10,000, production settings) was ingested in 4 m 9 s (Plan 2C: 4 m 0 s; dictionary training dominates). It holds 100,573 `certs` rows (one per vaulted certificate), 186,756 `names` rows (185,772 `dns_valid`), and all 100,000 entries join to `certs`. Every invariant passed, including `CheckDerived`, kinds against entry types, `logging_delay`, a literal `names.name` lookup, and 1,000 sampled certificates compared with the extractor.
4. **Recovery on real data:** 5 crashes across dictionary training and leaf-delta batches; the recovered vault's entries and derived rows equal a clean ingest's except for internal IDs. 88.6 s (Plan 2C: 76 s).
5. **Determinism:**
   - the corpus rows golden file regenerates byte-identically;
   - two vaults ingesting the same entries write byte-identical `certs` and `names` files (`TestDerivedFilesAreByteIdentical`);
   - restaging the same rows in another DuckDB session is byte-identical (`TestStageDerived`).
6. **The golden corpus** (2,710 certificates) gives 2,710 `certs` rows and 4,154 `names` rows, 3,834 of them `dns_valid`.
7. **Mutations caught:**
   - a delta base off by one: `TestCrashAtEveryBoundary`, `TestRandomKillLoop` and `TestBatchesBuildDerivedFiles` (through `CheckDerived`);
   - `names` rows that depend on `cert_id`: `TestCrashAtEveryBoundary`, through the `Content` comparison;
   - a `names` file sorted by name instead of insertion order: `TestStageDerived`.
8. **Found while writing this plan:**
   - **The memory cost** (item 1). Fixed by streaming and by dropping the sort.
   - **A canary that sampled with replacement** missed bad rows (a 36% chance of missing a given row even with as many samples as rows). Now a reservoir sample of distinct rows is checked in full.
   - **A test that passed before its feature existed:** `TestDerivedFilesAreByteIdentical` compared two empty checksums. It now requires them to be present (RED in Task B4).

## Before You Start

- Work from the repository root, with Plan 3A applied.
- **Task B1's golden file** is generated by its test with `-update`. Its expected SHA-256 is `8a3f641c144f2e0638794d9782129b6f964c7a28e158a111ccc01f80d9c53dd1` (300,895 bytes); regeneration was byte-identical.
- **Task B5's real-data tests** read the cached canonical sample `~/.cache/ctvault-dev/samples/argon2027h1/000000000000-000000099999`.
- `go mod download golang.org/x/net@v0.59.0` needs the network once (Task B1).

## File Structure

```text
internal/extract/name.go          + Name.Values (every attribute of a type, in DER order)
internal/derive/table.go          ExtractorVersion, PSLSnapshot, Column, Table (File, SchemaSHA256, KV), Row, Context, Builder, Builders
internal/derive/certs.go          CertsV1 (29 columns) and the Certs builder
internal/derive/names.go          NamesV1 and the Names builder: DNS normalization, IP rendering, CN rows, eTLD+1
internal/derive/active.go         ACTIVE.json: TableState, Active, Complete, Upgrading, Check, ReadActive, WriteActive
internal/derive/testdata/         corpus_rows.golden.zst (the rows of the extractor's golden corpus)
internal/dataset/views.go         views.sql from ACTIVE.json: certs/names or *_building, entry_certs, logging_delay
internal/dataset/derived.go       DerivedStage: rows streamed into DuckDB, a reservoir sample, Write, Canary
internal/dataset/stage.go         the writer's DuckDB session runs one thread and preserves insertion order
internal/ingest/writer.go         settles ACTIVE.json at Open; Writer.Active
internal/ingest/batch.go          P2 streams rows, P5 writes the files, P6 canary, P7 builders
internal/vault/delta.go           the delta cache keeps the base's cert_id
internal/cli/vaultcmds.go         init writes ACTIVE.json
internal/vaulttest/vaulttest.go   CheckDerived; Dump returns Content with the derived rows
```

---

### Task B1: The `derive` package: registry, `certs` v1 and `names` v1

Spec §7.2–§7.5, amendment A2 §4.1 and §4.2.

**Files:**
- Create: `internal/derive/table.go`, `internal/derive/certs.go`, `internal/derive/names.go`, `internal/derive/testdata/corpus_rows.golden.zst` (generated)
- Modify: `internal/extract/name.go` (adds `Values`), `go.mod` and `go.sum` (`golang.org/x/net v0.59.0`)
- Tests: `internal/extract/name_test.go`, `internal/derive/table_test.go`, `internal/derive/certs_test.go`, `internal/derive/names_test.go`, `internal/derive/corpus_test.go`

**Interfaces:**
- Consumes: `extract.Parse`, `extract.Cert`, `(extract.Name).First`, `(extract.Name).String` (Plan 3A); `vault.Loc`.
- Produces:
  - `(extract.Name).Values(oid string) []string`;
  - `derive.ExtractorVersion`, `derive.PSLSnapshot`;
  - `derive.Column{Name, Type string}`; `derive.Table{Name string; Version int; Columns []Column; PSL string}` with `File() string`, `SchemaSHA256() string` and `KV() [][2]string`;
  - `derive.Row []any` (nil is NULL), `derive.KindPrecert`/`KindFinal`/`KindChain`;
  - `derive.Context{CertID uint64; SHA256 [32]byte; Kind string; Loc vault.Loc; DeltaBaseCertID uint64}`;
  - `derive.Builder` interface `{Table() Table; Build(*extract.Cert, Context) []Row}`, `derive.Builders = []Builder{Certs{}, Names{}}`;
  - `derive.CertsV1`, `derive.NamesV1`.

- [ ] **Step 1: Write the failing tests**

Replace `internal/extract/name_test.go` with (adds `TestNameValues`):

```go
package extract

import (
	"bytes"
	"encoding/asn1"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// atv is one attribute for building test names: an OID and a value element.
type atv struct {
	oid   asn1.ObjectIdentifier
	value []byte // a complete DER element (tag, length, content)
}

func str(tag cbasn1.Tag, content string) []byte {
	var b cryptobyte.Builder
	b.AddASN1(tag, func(b *cryptobyte.Builder) { b.AddBytes([]byte(content)) })
	return b.BytesOrPanic()
}

// buildName encodes a Name: a SEQUENCE of RDN SETs, in the given order.
func buildName(rdns ...[]atv) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, rdn := range rdns {
			b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
				for _, a := range rdn {
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1ObjectIdentifier(a.oid)
						b.AddBytes(a.value)
					})
				}
			})
		}
	})
	return b.BytesOrPanic()
}

var (
	oidCN    = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidO     = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidC     = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidUID   = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}
	oidEmail = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	oidOther = asn1.ObjectIdentifier{1, 2, 3, 4}
)

const (
	tagUTF8      = cbasn1.UTF8String
	tagPrintable = cbasn1.PrintableString
	tagIA5       = cbasn1.IA5String
	tagTeletex   = cbasn1.Tag(20)
	tagBMP       = cbasn1.Tag(30)
	tagUniversal = cbasn1.Tag(28)
)

func TestNameRendering(t *testing.T) {
	for _, c := range []struct {
		name string
		rdns [][]atv
		want string
		bad  bool
	}{
		{"reverse DER order", [][]atv{{{oidC, str(tagPrintable, "US")}}, {{oidO, str(tagUTF8, "Acme")}}, {{oidCN, str(tagUTF8, "example.com")}}},
			"CN=example.com,O=Acme,C=US", false},
		{"multi-valued RDN in DER order", [][]atv{{{oidCN, str(tagUTF8, "a")}, {oidUID, str(tagUTF8, "b")}}}, "CN=a+UID=b", false},
		{"special characters", [][]atv{{{oidCN, str(tagUTF8, `a,b+c"d\e;<>`)}}}, `CN=a\,b\+c\"d\\e\;\<\>`, false},
		{"leading hash and trailing space", [][]atv{{{oidCN, str(tagUTF8, "#x ")}}}, `CN=\#x\ `, false},
		{"leading space", [][]atv{{{oidCN, str(tagUTF8, " y")}}}, `CN=\ y`, false},
		{"control character", [][]atv{{{oidCN, str(tagUTF8, "a\x07b")}}}, `CN=a\07b`, false},
		{"emailAddress", [][]atv{{{oidEmail, str(tagIA5, "a@b.example")}}}, "emailAddress=a@b.example", false},
		{"unknown type, string value", [][]atv{{{oidOther, str(tagUTF8, "v")}}}, "1.2.3.4=v", false},
		{"non-string value", [][]atv{{{oidOther, []byte{0x02, 0x01, 0x05}}}}, "1.2.3.4=#020105", false},
		{"Teletex as ISO 8859-1", [][]atv{{{oidCN, str(tagTeletex, "caf\xe9")}}}, "CN=café", false},
		{"BMPString", [][]atv{{{oidCN, str(tagBMP, "\x00c\x00a\x00f\x00\xe9")}}}, "CN=café", false},
		{"UniversalString", [][]atv{{{oidCN, str(tagUniversal, "\x00\x00\x00c\x00\x00\x00\xe9")}}}, "CN=cé", false},
		{"invalid UTF-8", [][]atv{{{oidCN, str(tagUTF8, "a\xffb")}}}, `CN=a\FFb`, true},
		{"odd-length BMPString", [][]atv{{{oidCN, str(tagBMP, "\x00a\x00")}}}, `CN=a\00`, true},
		{"BMPString surrogate", [][]atv{{{oidCN, str(tagBMP, "\xd8\x00")}}}, `CN=\D8\00`, true},
		{"non-ASCII PrintableString", [][]atv{{{oidCN, str(tagPrintable, "a\xc3b")}}}, `CN=a\C3b`, true},
		{"empty name", nil, "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			der := buildName(c.rdns...)
			n, ok := parseName(der)
			if !ok {
				t.Fatal("did not parse")
			}
			if !bytes.Equal(n.Raw, der) {
				t.Fatal("Raw is not the exact DER")
			}
			if got := n.String(); got != c.want {
				t.Errorf("String() = %q, want %q", got, c.want)
			}
			if n.badStrings() != c.bad {
				t.Errorf("badStrings() = %v, want %v", n.badStrings(), c.bad)
			}
		})
	}
}

func TestNameFirst(t *testing.T) {
	n, _ := parseName(buildName([]atv{{oidO, str(tagUTF8, "Acme, Inc.")}}, []atv{{oidCN, str(tagUTF8, `one\two`)}}, []atv{{oidCN, str(tagUTF8, "second\xff")}}))
	if v, ok := n.First(OIDCommonName); !ok || v != `one\\two` {
		t.Errorf("First(CN) = %q, %v", v, ok)
	}
	if v, ok := n.First(OIDOrganization); !ok || v != "Acme, Inc." {
		t.Errorf("First(O) = %q, %v: display values escape only backslashes and bad bytes", v, ok)
	}
	if _, ok := n.First("2.5.4.11"); ok {
		t.Error("First of a missing attribute")
	}
	m, _ := parseName(buildName([]atv{{oidCN, str(tagUTF8, "bad\xff")}}))
	if v, _ := m.First(OIDCommonName); v != `bad\FF` {
		t.Errorf("bad bytes: %q", v)
	}
}

func TestNameUnreadable(t *testing.T) {
	notSet := func() []byte {
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {})
		})
		return b.BytesOrPanic()
	}()
	emptyRDN := buildName([]atv{})
	for name, der := range map[string][]byte{
		"not a SEQUENCE":    {0x31, 0x00},
		"RDN not a SET":     notSet,
		"empty RDN":         emptyRDN,
		"truncated":         buildName([]atv{{oidCN, str(tagUTF8, "x")}})[:5],
		"trailing in value": buildName([]atv{{oidCN, append(str(tagUTF8, "x"), 0x05, 0x00)}}),
	} {
		if n, ok := parseName(der); ok {
			t.Errorf("%s: parsed as %q", name, n.String())
		} else if !bytes.Equal(n.Raw, der) {
			t.Errorf("%s: Raw must still hold the bytes", name)
		}
	}
}

func TestNameValues(t *testing.T) {
	n, _ := parseName(buildName([]atv{{oidCN, str(tagUTF8, "first")}}, []atv{{oidO, str(tagUTF8, "Org")}}, []atv{{oidCN, str(tagUTF8, "second\xff")}}))
	if got := n.Values(OIDCommonName); len(got) != 2 || got[0] != "first" || got[1] != `second\FF` {
		t.Errorf("Values(CN) = %q", got)
	}
	if got := n.Values("2.5.4.11"); got != nil {
		t.Errorf("Values of a missing type = %q", got)
	}
}
```

Create `internal/derive/table_test.go`:

```go
package derive

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestTables(t *testing.T) {
	if CertsV1.File() != "certs.p1.parquet" || NamesV1.File() != "names.p1.parquet" {
		t.Errorf("files %s %s", CertsV1.File(), NamesV1.File())
	}
	for _, b := range Builders {
		tb := b.Table()
		for _, c := range tb.Columns {
			if strings.Contains(c.Type, "BLOB") {
				t.Errorf("%s.%s is a BLOB: bloom-filtered files never hold BLOB columns (D19)", tb.Name, c.Name)
			}
		}
		kv := map[string]string{}
		for _, p := range tb.KV() {
			kv[p[0]] = p[1]
		}
		if kv["ctvault.table"] != tb.Name || kv["ctvault.version"] != "1" || kv["ctvault.extractor"] != ExtractorVersion ||
			kv["ctvault.schema_sha256"] != tb.SchemaSHA256() || kv["ctvault.psl"] != tb.PSL {
			t.Errorf("%s KV %v", tb.Name, kv)
		}
	}
}

// TestSchemasAreFrozen: a table's columns are part of its version (spec
// §7.2): changing them without bumping the version would mix two schemas
// under one file name.
func TestSchemasAreFrozen(t *testing.T) {
	for name, want := range map[string]string{
		CertsV1.Name: "ced48dafaee44fa963d3b3bda2d7fbfe781753b28440c828cc039393fc859b17",
		NamesV1.Name: "82bd317eaa88ed33cfdbd8f825743fe3f4b3ca3d9b376b5016722d5ee8eb0f96",
	} {
		for _, b := range Builders {
			if b.Table().Name == name && b.Table().SchemaSHA256() != want {
				t.Errorf("%s schema %s changed (was %s): bump its version", name, b.Table().SchemaSHA256(), want)
			}
		}
	}
}

// TestPSLMatchesTheModule: names records the public-suffix list it was
// built with (spec §7.2 psl_snapshot). A bump of golang.org/x/net changes
// eTLD+1 results and must bump the names version too.
func TestPSLMatchesTheModule(t *testing.T) {
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Version}} {{.Dir}}", "golang.org/x/net")
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	version, dir, _ := strings.Cut(strings.TrimSpace(string(out)), " ")
	src, err := os.ReadFile(filepath.Join(dir, "publicsuffix", "table.go"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`git revision ([0-9a-f]+) \(([^)]+)\)`).FindSubmatch(src)
	if m == nil {
		t.Fatal("no list revision in publicsuffix/table.go")
	}
	want := "golang.org/x/net " + version + ", public_suffix_list.dat " + string(m[1]) + " (" + string(m[2]) + ")"
	if PSLSnapshot != want {
		t.Errorf("PSLSnapshot = %q, the module has %q: update it and bump the names version", PSLSnapshot, want)
	}
}
```

Create `internal/derive/certs_test.go`:

```go
package derive

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/extract"
	"github.com/4rji/ctvault/internal/vault"
)

var testKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

// makeCert issues a certificate with crypto/x509.
func makeCert(t *testing.T, edit func(*x509.Certificate)) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x0abc),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		Issuer:       pkix.Name{CommonName: "Test CA", Organization: []string{"Test Org"}},
		NotBefore:    time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		NotAfter:     time.Date(2026, 4, 2, 3, 4, 5, 0, time.UTC),
	}
	if edit != nil {
		edit(tmpl)
	}
	parent := &x509.Certificate{Subject: tmpl.Issuer}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, testKey.Public(), testKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// nameCert issues a certificate whose subject holds these CNs, in order.
func nameCert(t *testing.T, cns []string) []byte {
	return makeCert(t, func(c *x509.Certificate) {
		c.Subject = pkix.Name{}
		for _, cn := range cns {
			c.Subject.ExtraNames = append(c.Subject.ExtraNames, pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: cn})
		}
	})
}

// byName maps a row to its table's column names.
func byName(tb Table, r Row) map[string]any {
	m := map[string]any{}
	for i, c := range tb.Columns {
		m[c.Name] = r[i]
	}
	return m
}

func TestCertRow(t *testing.T) {
	der := makeCert(t, func(c *x509.Certificate) {
		c.DNSNames = []string{"leaf.example.com", "*.leaf.example.com"}
		c.IPAddresses = []net.IP{net.ParseIP("192.0.2.1").To4()}
		c.SubjectKeyId, c.AuthorityKeyId = []byte{1, 2}, []byte{3, 4}
	})
	sum := sha256.Sum256(der)
	ctx := Context{CertID: 5, SHA256: sum, Kind: KindFinal, Loc: vault.Loc{Segment: 2, Offset: 100, Len: 900}, DeltaBaseCertID: 3}
	rows := Certs{}.Build(extract.Parse(der), ctx)
	if len(rows) != 1 || len(rows[0]) != len(CertsV1.Columns) {
		t.Fatalf("rows %v", rows)
	}
	got := byName(CertsV1, rows[0])
	want := map[string]any{
		"cert_id": uint64(5), "sha256": hex.EncodeToString(sum[:]), "kind": "final", "has_ct_poison": false,
		"vault_seg": uint32(2), "vault_off": uint64(100), "vault_len": uint32(900), "delta_base_cert_id": uint64(3),
		"parse_status": "ok", "parse_errors": []string{}, "serial": "0abc",
		"issuer_dn": "CN=Test CA,O=Test Org", "issuer_o": "Test Org", "issuer_cn": "Test CA",
		"authority_key_id": "0304",
		"not_before":       time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), "not_after": time.Date(2026, 4, 2, 3, 4, 5, 0, time.UTC),
		"key_alg": "ecdsa", "key_bits": uint16(256), "key_curve": "P-256", "spki_alg_oid": "1.2.840.10045.2.1",
		"sig_alg": "ecdsa-with-SHA256", "subject_cn": "leaf.example.com", "n_dns_names": uint16(2), "n_ip_names": uint16(1),
		"has_wildcard": true, "subject_key_id": nil, "subject_der": nil,
	}
	ref, _ := x509.ParseCertificate(der)
	want["issuer_der"] = hex.EncodeToString(ref.RawIssuer)
	for k, v := range want {
		if !reflect.DeepEqual(got[k], v) {
			t.Errorf("%s = %#v, want %#v", k, got[k], v)
		}
	}
	if len(want) != len(CertsV1.Columns) {
		t.Errorf("the test checks %d of %d columns", len(want), len(CertsV1.Columns))
	}

	// A chain certificate also records its subject key ID and subject DER.
	ctx.Kind, ctx.DeltaBaseCertID = KindChain, 0
	chain := byName(CertsV1, Certs{}.Build(extract.Parse(der), ctx)[0])
	if chain["subject_key_id"] != "0102" || chain["subject_der"] != hex.EncodeToString(ref.RawSubject) || chain["delta_base_cert_id"] != nil {
		t.Errorf("chain columns: %v %v %v", chain["subject_key_id"], chain["subject_der"], chain["delta_base_cert_id"])
	}
}

// TestFailedCertRow: a certificate nothing can be read from still gets its
// row (spec §7.1: no certificate is ever dropped).
func TestFailedCertRow(t *testing.T) {
	sum := sha256.Sum256([]byte("garbage"))
	row := byName(CertsV1, Certs{}.Build(extract.Parse([]byte("garbage")), Context{CertID: 1, SHA256: sum, Kind: KindPrecert})[0])
	if row["parse_status"] != "failed" || !reflect.DeepEqual(row["parse_errors"], []string{"cert_unreadable"}) || row["kind"] != "precert" {
		t.Fatalf("row %v", row)
	}
	for _, col := range []string{"serial", "issuer_dn", "issuer_der", "not_before", "key_alg", "key_bits", "sig_alg", "subject_cn"} {
		if row[col] != nil {
			t.Errorf("%s = %v, want NULL", col, row[col])
		}
	}
	if row["n_dns_names"] != uint16(0) || row["has_wildcard"] != false {
		t.Errorf("summary columns %v %v", row["n_dns_names"], row["has_wildcard"])
	}
}
```

Create `internal/derive/names_test.go`:

```go
package derive

import (
	"reflect"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/extract"
)

func TestNormalizeDNS(t *testing.T) {
	for _, c := range []struct {
		in, name    string
		valid, wild bool
		tld, etld1  any // nil or string
	}{
		{"WWW.Example.COM.", "www.example.com", true, false, "com", "example.com"},
		{"*.example.co.uk", "*.example.co.uk", true, true, "co.uk", "example.co.uk"},
		{"foo_bar.example.com", "foo_bar.example.com", true, false, "com", "example.com"},
		{"xn--caf-dma.example", "xn--caf-dma.example", true, false, "example", "xn--caf-dma.example"},
		{"com", "com", true, false, "com", nil},
		{"localhost", "localhost", true, false, "localhost", nil},
		{"a..b.example", "a..b.example", false, false, nil, nil},
		{strings.Repeat("a", 64) + ".example.com", strings.Repeat("a", 64) + ".example.com", false, false, nil, nil},
		{strings.Repeat("abcdefghi.", 26) + "com", strings.Repeat("abcdefghi.", 26) + "com", false, false, nil, nil},
		{"*.*.example.com", "*.*.example.com", false, false, nil, nil},
		{"bad\\C3\\A9.example", "bad\\C3\\A9.example", false, false, nil, nil},
		{"has space.example", "has space.example", false, false, nil, nil},
	} {
		got := dnsRow(7, "san_dns", c.in)
		want := Row{uint64(7), "san_dns", c.name, c.valid, c.wild, c.tld, c.etld1}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %v, want %v", c.in, got, want)
		}
	}
}

func TestIPNames(t *testing.T) {
	for _, c := range []struct {
		in   []byte
		want string
	}{
		{[]byte{192, 0, 2, 1}, "192.0.2.1"},
		{[]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, "2001:db8::1"},
		{[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1}, "::ffff:192.0.2.1"},
		{[]byte{1, 2, 3, 4, 5}, "0102030405"},
	} {
		if got := ipRow(3, c.in); !reflect.DeepEqual(got, Row{uint64(3), "san_ip", c.want, false, false, nil, nil}) {
			t.Errorf("%x: %v", c.in, got)
		}
	}
}

// cert builds an extract.Cert with the names fields set, for the names
// builder: subject CNs and SANs.
func cert(t *testing.T, cns []string, dns []string, ips [][]byte) *extract.Cert {
	t.Helper()
	c := extract.Parse(nameCert(t, cns))
	c.DNSNames, c.IPAddresses = dns, ips
	return c
}

func TestNameRows(t *testing.T) {
	c := cert(t, []string{"www.example.com", "Example Device 42", "192.0.2.7", "R3", "WWW.example.com"},
		[]string{"www.example.com", "*.example.com"}, [][]byte{{192, 0, 2, 1}})
	got := Names{}.Build(c, Context{CertID: 9})
	want := []Row{
		{uint64(9), "san_dns", "www.example.com", true, false, "com", "example.com"},
		{uint64(9), "san_dns", "*.example.com", true, true, "com", "example.com"},
		{uint64(9), "san_ip", "192.0.2.1", false, false, nil, nil},
		{uint64(9), "cn", "Example Device 42", false, false, nil, nil},
		{uint64(9), "cn", "192.0.2.7", false, false, nil, nil},
		{uint64(9), "cn", "R3", false, false, nil, nil},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rows:\n%v\nwant\n%v", got, want)
	}
	// A CN that only repeats a SAN (after normalization) gets no row, and an
	// IP literal CN that equals an IP SAN is not repeated either.
	c = cert(t, []string{"192.0.2.1"}, nil, [][]byte{{192, 0, 2, 1}})
	if got := (Names{}).Build(c, Context{CertID: 1}); len(got) != 1 {
		t.Errorf("IP CN repeating the SAN: %v", got)
	}
	c = cert(t, []string{"Shop.Example.org"}, nil, nil)
	if got := (Names{}).Build(c, Context{CertID: 1}); !reflect.DeepEqual(got, []Row{{uint64(1), "cn", "shop.example.org", true, false, "org", "example.org"}}) {
		t.Errorf("DNS CN without SANs: %v", got)
	}
}
```

Create `internal/derive/corpus_test.go`:

```go
package derive

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/4rji/ctvault/internal/extract"
)

var update = flag.Bool("update", false, "rewrite testdata/corpus_rows.golden.zst")

// realCorpus reads the extractor's corpus of real certificates: 2,000
// leaves, then 710 chain certificates.
func realCorpus(t *testing.T) [][]byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "extract", "testdata", "corpus.bin.zst"))
	if err != nil {
		t.Fatal(err)
	}
	dec, _ := zstd.NewReader(nil)
	defer dec.Close()
	raw, err := dec.DecodeAll(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for len(raw) > 0 {
		n, k := binary.Uvarint(raw)
		out = append(out, raw[k:k+int(n)])
		raw = raw[k+int(n):]
	}
	return out
}

// TestCorpusRowsGolden: every builder's rows for the real corpus match the
// golden file, so a change to the extractor, the normalization or the
// public-suffix list shows up here and must bump a table version.
func TestCorpusRowsGolden(t *testing.T) {
	certs := realCorpus(t)
	var lines []string
	stats := map[string]int{}
	for i, der := range certs {
		c := extract.Parse(der)
		kind := KindFinal
		switch {
		case i >= 2000:
			kind = KindChain
		case c.HasCTPoison:
			kind = KindPrecert
		}
		ctx := Context{CertID: uint64(i + 1), SHA256: sha256.Sum256(der), Kind: kind}
		for _, b := range Builders {
			for _, r := range b.Build(c, ctx) {
				line, err := json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
				lines = append(lines, b.Table().Name+" "+string(line))
				stats[b.Table().Name]++
				if b.Table().Name == "names" && r[3] == true {
					stats["names dns_valid"]++
				}
			}
		}
	}
	t.Logf("%d certificates: %v", len(certs), stats)
	got := []byte(strings.Join(lines, "\n") + "\n")
	path := filepath.Join("testdata", "corpus_rows.golden.zst")
	if *update {
		enc, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression), zstd.WithEncoderConcurrency(1))
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, enc.EncodeAll(got, nil), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	dec, _ := zstd.NewReader(nil)
	defer dec.Close()
	want, err := dec.DecodeAll(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		g, w := strings.Split(string(got), "\n"), strings.Split(string(want), "\n")
		for i := range min(len(g), len(w)) {
			if g[i] != w[i] {
				t.Fatalf("line %d differs:\n got  %s\n want %s", i+1, g[i], w[i])
			}
		}
		t.Fatalf("%d lines, want %d", len(g), len(w))
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/extract/ ./internal/derive/`
Expected: FAIL with `n.Values undefined (type Name has no field or method Values)` in `internal/extract`, and `undefined: Table` (also `Row`, `Context`, `KindFinal`, `Certs`, `CertsV1`) in `internal/derive`.

- [ ] **Step 3: Implement**

Replace `internal/extract/name.go` with (adds `Values` at the end):

```go
package extract

import (
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Attribute type OIDs that columns read.
const (
	OIDCommonName   = "2.5.4.3"
	OIDOrganization = "2.5.4.10"
)

// shortNames are RFC 4514's attribute type names, plus serialNumber and
// emailAddress as OpenSSL writes them. Other types render as dotted OIDs.
var shortNames = map[string]string{
	"2.5.4.3": "CN", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.6": "C",
	"2.5.4.9": "STREET", "0.9.2342.19200300.100.1.25": "DC", "0.9.2342.19200300.100.1.1": "UID",
	"2.5.4.5": "serialNumber", "1.2.840.113549.1.9.1": "emailAddress",
}

// Name is an issuer or subject Name (amendment A2 §3.2). Raw, its exact DER
// encoding, is the name's reproducible identity; String is a deterministic
// display and search rendering only.
type Name struct {
	Raw  []byte        // the whole Name element, exactly as encoded
	RDNs [][]Attribute // in DER order
}

// Attribute is one AttributeTypeAndValue.
type Attribute struct {
	Type    string     // dotted OID
	Tag     cbasn1.Tag // the value's tag
	Value   []byte     // the value's content bytes
	Element []byte     // the whole value element
}

// parseName reads a Name. On failure Raw still holds the bytes and ok is
// false.
func parseName(der []byte) (n Name, ok bool) {
	n.Raw = der
	s := cryptobyte.String(der)
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !s.Empty() {
		return n, false
	}
	for !seq.Empty() {
		var set cryptobyte.String
		if !seq.ReadASN1(&set, cbasn1.SET) || set.Empty() {
			return Name{Raw: der}, false
		}
		var rdn []Attribute
		for !set.Empty() {
			var body cryptobyte.String
			var oid asn1.ObjectIdentifier
			var a Attribute
			var elem cryptobyte.String
			if !set.ReadASN1(&body, cbasn1.SEQUENCE) || !body.ReadASN1ObjectIdentifier(&oid) ||
				!body.ReadAnyASN1Element(&elem, &a.Tag) || !body.Empty() {
				return Name{Raw: der}, false
			}
			var content cryptobyte.String
			e := elem
			if !e.ReadAnyASN1(&content, &a.Tag) {
				return Name{Raw: der}, false
			}
			a.Type, a.Value, a.Element = oid.String(), content, elem
			rdn = append(rdn, a)
		}
		n.RDNs = append(n.RDNs, rdn)
	}
	return n, true
}

// decoded is a string value as runes, with each undecodable byte kept apart
// so it can be escaped as \XX.
type decoded struct {
	parts []piece
	bad   bool
}

type piece struct {
	r      rune
	rawHex bool // r is a raw byte to render as \XX
}

// decode reads a string-typed value. isString is false for any other type.
func decode(tag cbasn1.Tag, b []byte) (d decoded, isString bool) {
	raw := func(x byte) { d.parts = append(d.parts, piece{rune(x), true}) }
	switch tag {
	case cbasn1.UTF8String:
		for len(b) > 0 {
			r, n := utf8.DecodeRune(b)
			if r == utf8.RuneError && n <= 1 {
				raw(b[0])
				d.bad, b = true, b[1:]
				continue
			}
			d.parts = append(d.parts, piece{r: r})
			b = b[n:]
		}
	case cbasn1.PrintableString, cbasn1.IA5String, cbasn1.Tag(18), cbasn1.Tag(26): // Numeric, Visible
		for _, x := range b {
			if x >= 0x80 {
				raw(x)
				d.bad = true
				continue
			}
			d.parts = append(d.parts, piece{r: rune(x)})
		}
	case cbasn1.Tag(20): // TeletexString, read as ISO 8859-1
		for _, x := range b {
			d.parts = append(d.parts, piece{r: rune(x)})
		}
	case cbasn1.Tag(30): // BMPString, UCS-2 big-endian
		for len(b) >= 2 {
			u := rune(binary.BigEndian.Uint16(b))
			if u >= 0xD800 && u <= 0xDFFF {
				raw(b[0])
				raw(b[1])
				d.bad = true
			} else {
				d.parts = append(d.parts, piece{r: u})
			}
			b = b[2:]
		}
		for _, x := range b {
			raw(x)
			d.bad = true
		}
	case cbasn1.Tag(28): // UniversalString, UCS-4 big-endian
		for len(b) >= 4 {
			u := rune(binary.BigEndian.Uint32(b))
			if u > utf8.MaxRune || (u >= 0xD800 && u <= 0xDFFF) {
				for _, x := range b[:4] {
					raw(x)
				}
				d.bad = true
			} else {
				d.parts = append(d.parts, piece{r: u})
			}
			b = b[4:]
		}
		for _, x := range b {
			raw(x)
			d.bad = true
		}
	default:
		return d, false
	}
	return d, true
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// display renders a decoded value for a column: characters as they are,
// except that a backslash is doubled and control characters and
// undecodable bytes become \XX.
func (d decoded) display() string {
	var b strings.Builder
	for _, p := range d.parts {
		switch {
		case p.rawHex, isControl(p.r):
			fmt.Fprintf(&b, `\%02X`, p.r)
		case p.r == '\\':
			b.WriteString(`\\`)
		default:
			b.WriteRune(p.r)
		}
	}
	return b.String()
}

// rfc4514 renders a decoded value with RFC 4514 §2.4 escaping.
func (d decoded) rfc4514() string {
	var b strings.Builder
	for i, p := range d.parts {
		switch {
		case p.rawHex, isControl(p.r):
			fmt.Fprintf(&b, `\%02X`, p.r)
		case strings.ContainsRune(`"+,;<>\`, p.r),
			i == 0 && (p.r == '#' || p.r == ' '),
			i == len(d.parts)-1 && p.r == ' ':
			b.WriteByte('\\')
			b.WriteRune(p.r)
		default:
			b.WriteRune(p.r)
		}
	}
	return b.String()
}

// String renders the name as RFC 4514 does: RDNs in reverse DER order,
// multi-valued RDNs joined with "+" in DER order, and non-string values as
// "#" followed by the hex of their whole element.
func (n Name) String() string {
	var rdns []string
	for i := len(n.RDNs) - 1; i >= 0; i-- {
		var parts []string
		for _, a := range n.RDNs[i] {
			typ := a.Type
			if s, ok := shortNames[typ]; ok {
				typ = s
			}
			v := "#" + hex.EncodeToString(a.Element)
			if d, ok := decode(a.Tag, a.Value); ok {
				v = d.rfc4514()
			}
			parts = append(parts, typ+"="+v)
		}
		rdns = append(rdns, strings.Join(parts, "+"))
	}
	return strings.Join(rdns, ",")
}

// First returns the display value of the first attribute of type oid, in
// DER order. A non-string value is "#" followed by its hex.
func (n Name) First(oid string) (string, bool) {
	for _, rdn := range n.RDNs {
		for _, a := range rdn {
			if a.Type != oid {
				continue
			}
			if d, ok := decode(a.Tag, a.Value); ok {
				return d.display(), true
			}
			return "#" + hex.EncodeToString(a.Element), true
		}
	}
	return "", false
}

// Values returns the display value of every attribute of type oid, in DER
// order; nil when there is none.
func (n Name) Values(oid string) []string {
	var out []string
	for _, rdn := range n.RDNs {
		for _, a := range rdn {
			if a.Type != oid {
				continue
			}
			if d, ok := decode(a.Tag, a.Value); ok {
				out = append(out, d.display())
			} else {
				out = append(out, "#"+hex.EncodeToString(a.Element))
			}
		}
	}
	return out
}

// badStrings reports whether any string value has bytes invalid for its
// type (NameBadString).
func (n Name) badStrings() bool {
	for _, rdn := range n.RDNs {
		for _, a := range rdn {
			if d, ok := decode(a.Tag, a.Value); ok && d.bad {
				return true
			}
		}
	}
	return false
}
```

Create `internal/derive/table.go`:

```go
// Package derive builds the derived tables, certs and names, from extracted
// certificates (spec §7.2-7.5, amendment A2 §4). A row depends only on the
// certificate's DER and its vault context, so the same batch always derives
// the same rows, at ingest or in a later local rebuild.
package derive

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/4rji/ctvault/internal/extract"
	"github.com/4rji/ctvault/internal/vault"
)

// ExtractorVersion names the extractor's output. Any change to what
// extract.Parse returns bumps it, and with it every table's version (spec
// §7.2).
const ExtractorVersion = "ctvault-extract/1"

// PSLSnapshot is the public-suffix list that names' tld and etld1 come
// from: the pinned golang.org/x/net and its embedded list (spec §7.2).
const PSLSnapshot = "golang.org/x/net v0.59.0, public_suffix_list.dat d6c92f1bbb7433e5db7b8405c25d4035fb8ff376 (2026-02-06T07:36:33Z)"

// Column is one column of a derived table: a DuckDB type, never BLOB (D19:
// these files carry bloom filters).
type Column struct{ Name, Type string }

// Table is one version of a derived table.
type Table struct {
	Name    string
	Version int
	Columns []Column
	PSL     string // the public-suffix snapshot, for tables that use eTLD+1
}

// File is the table's file name in a batch directory, e.g. certs.p1.parquet.
func (t Table) File() string { return fmt.Sprintf("%s.p%d.parquet", t.Name, t.Version) }

// SchemaSHA256 hashes the column list, "name type\n" per column.
func (t Table) SchemaSHA256() string {
	h := sha256.New()
	for _, c := range t.Columns {
		fmt.Fprintf(h, "%s %s\n", c.Name, c.Type)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// KV is the Parquet key-value metadata every file of the table carries
// (spec §7.2), in a fixed order.
func (t Table) KV() [][2]string {
	return [][2]string{
		{"ctvault.table", t.Name},
		{"ctvault.version", strconv.Itoa(t.Version)},
		{"ctvault.extractor", ExtractorVersion},
		{"ctvault.schema_sha256", t.SchemaSHA256()},
		{"ctvault.psl", t.PSL},
	}
}

// Row is one row: values in the table's column order, nil for NULL.
type Row []any

// Certificate kinds: how a certificate was first vaulted (spec §7.3).
const (
	KindPrecert = "precert"
	KindFinal   = "final"
	KindChain   = "chain"
)

// Context is what a builder knows about a certificate besides its DER.
type Context struct {
	CertID          uint64
	SHA256          [32]byte
	Kind            string
	Loc             vault.Loc
	DeltaBaseCertID uint64 // 0 unless the record is a leaf-delta
}

// Builder derives one table's rows from a certificate (spec §7.5).
type Builder interface {
	Table() Table
	Build(c *extract.Cert, ctx Context) []Row
}

// Builders are this binary's builders, in a fixed order.
var Builders = []Builder{Certs{}, Names{}}
```

Create `internal/derive/certs.go`:

```go
package derive

import (
	"encoding/hex"
	"slices"
	"strings"

	"github.com/4rji/ctvault/internal/extract"
)

// CertsV1 is the certs table, version 1: spec §7.3's columns plus
// issuer_der and the chain-only subject_der (amendment A2 §4.2). One row per
// unique certificate, in the batch that first vaulted it.
var CertsV1 = Table{Name: "certs", Version: 1, Columns: []Column{
	{"cert_id", "UBIGINT"}, {"sha256", "VARCHAR"}, {"kind", "VARCHAR"}, {"has_ct_poison", "BOOLEAN"},
	{"vault_seg", "UINTEGER"}, {"vault_off", "UBIGINT"}, {"vault_len", "UINTEGER"}, {"delta_base_cert_id", "UBIGINT"},
	{"parse_status", "VARCHAR"}, {"parse_errors", "VARCHAR[]"},
	{"serial", "VARCHAR"}, {"issuer_dn", "VARCHAR"}, {"issuer_o", "VARCHAR"}, {"issuer_cn", "VARCHAR"}, {"issuer_der", "VARCHAR"},
	{"authority_key_id", "VARCHAR"}, {"not_before", "TIMESTAMP"}, {"not_after", "TIMESTAMP"},
	{"key_alg", "VARCHAR"}, {"key_bits", "USMALLINT"}, {"key_curve", "VARCHAR"}, {"spki_alg_oid", "VARCHAR"}, {"sig_alg", "VARCHAR"},
	{"subject_cn", "VARCHAR"}, {"n_dns_names", "USMALLINT"}, {"n_ip_names", "USMALLINT"}, {"has_wildcard", "BOOLEAN"},
	{"subject_key_id", "VARCHAR"}, {"subject_der", "VARCHAR"},
}}

// Certs builds certs v1.
type Certs struct{}

func (Certs) Table() Table { return CertsV1 }

// orNil returns nil for a zero value, so it is written as NULL.
func orNil[T comparable](v T) any {
	var zero T
	if v == zero {
		return nil
	}
	return v
}

func hexOrNil(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return hex.EncodeToString(b)
}

func count16(n int) uint16 { return uint16(min(n, 0xffff)) }

// Build returns the certificate's single certs row.
func (Certs) Build(c *extract.Cert, ctx Context) []Row {
	errs := make([]string, len(c.Errors))
	for i, e := range c.Errors {
		errs[i] = string(e)
	}
	var issuerDN, issuerO, issuerCN, subjectCN any
	if len(c.Issuer.RDNs) > 0 {
		issuerDN = c.Issuer.String()
	}
	if v, ok := c.Issuer.First(extract.OIDOrganization); ok {
		issuerO = v
	}
	if v, ok := c.Issuer.First(extract.OIDCommonName); ok {
		issuerCN = v
	}
	if v, ok := c.Subject.First(extract.OIDCommonName); ok {
		subjectCN = v
	}
	var notBefore, notAfter any
	if c.HasNotBefore {
		notBefore = c.NotBefore
	}
	if c.HasNotAfter {
		notAfter = c.NotAfter
	}
	var keyBits any
	if c.Key.Bits > 0 {
		keyBits = uint16(min(c.Key.Bits, 0xffff))
	}
	wildcard := slices.ContainsFunc(c.DNSNames, func(n string) bool { return strings.HasPrefix(n, "*.") })
	var subjectKeyID, subjectDER any
	if ctx.Kind == KindChain {
		subjectKeyID, subjectDER = hexOrNil(c.SubjectKeyID), hexOrNil(c.Subject.Raw)
	}
	var serial any
	if c.Serial != nil {
		serial = hex.EncodeToString(c.Serial)
	}
	return []Row{{
		ctx.CertID, hex.EncodeToString(ctx.SHA256[:]), ctx.Kind, c.HasCTPoison,
		uint32(ctx.Loc.Segment), ctx.Loc.Offset, ctx.Loc.Len, orNil(ctx.DeltaBaseCertID),
		string(c.Status), errs,
		serial, issuerDN, issuerO, issuerCN, hexOrNil(c.Issuer.Raw),
		hexOrNil(c.AuthorityKeyID), notBefore, notAfter,
		orNil(c.Key.Algorithm), keyBits, orNil(c.Key.Curve), orNil(c.Key.AlgorithmOID), orNil(c.SignatureAlgorithm),
		subjectCN, count16(len(c.DNSNames)), count16(len(c.IPAddresses)), wildcard,
		subjectKeyID, subjectDER,
	}}
}
```

Create `internal/derive/names.go`:

```go
package derive

import (
	"encoding/hex"
	"net/netip"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/4rji/ctvault/internal/extract"
)

// NamesV1 is the names table, version 1 (spec §7.4): one row per name per
// certificate, in order: dNSName SANs, then iPAddress SANs, both in SAN
// order, then the subject CNs that differ from every SAN.
var NamesV1 = Table{Name: "names", Version: 1, PSL: PSLSnapshot, Columns: []Column{
	{"cert_id", "UBIGINT"}, {"source", "VARCHAR"}, {"name", "VARCHAR"}, {"dns_valid", "BOOLEAN"},
	{"is_wildcard", "BOOLEAN"}, {"tld", "VARCHAR"}, {"etld1", "VARCHAR"},
}}

// Names builds names v1.
type Names struct{}

func (Names) Table() Table { return NamesV1 }

// Build returns the certificate's names rows.
func (Names) Build(c *extract.Cert, ctx Context) []Row {
	var rows []Row
	seen := map[string]bool{}
	for _, n := range c.DNSNames {
		r := dnsRow(ctx.CertID, "san_dns", n)
		rows = append(rows, r)
		seen[r[2].(string)] = true
	}
	for _, ip := range c.IPAddresses {
		r := ipRow(ctx.CertID, ip)
		rows = append(rows, r)
		seen[r[2].(string)] = true
	}
	for _, cn := range c.Subject.Values(extract.OIDCommonName) {
		r := cnRow(ctx.CertID, cn)
		if name := r[2].(string); !seen[name] {
			rows = append(rows, r)
			seen[name] = true
		}
	}
	return rows
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func validLabel(l string) bool {
	if len(l) < 1 || len(l) > 63 {
		return false
	}
	for i := range len(l) {
		c := l[i]
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// normalizeDNS lowercases ASCII and strips one trailing dot (spec §7.4).
// dns_valid is lenient: labels of 1-63 letters, digits, "-" and "_", at most
// 253 characters, and a leftmost "*" label sets is_wildcard. base is the
// name without "*.". A name that already carries \XX escapes (undecodable
// bytes) is kept as is and is not valid.
func normalizeDNS(s string) (name string, valid, wild bool, base string) {
	if strings.ContainsRune(s, '\\') {
		return s, false, false, ""
	}
	name = strings.TrimSuffix(lowerASCII(s), ".")
	labels := strings.Split(name, ".")
	if len(labels) > 1 && labels[0] == "*" {
		wild, labels = true, labels[1:]
	}
	valid = len(name) <= 253
	for _, l := range labels {
		valid = valid && validLabel(l)
	}
	if !valid {
		return name, false, false, ""
	}
	return name, true, wild, strings.Join(labels, ".")
}

// suffixes returns tld (the public suffix) and etld1 for a valid base name;
// etld1 is nil when the name has no registrable domain.
func suffixes(base string) (tld, etld1 any) {
	suffix, _ := publicsuffix.PublicSuffix(base)
	tld = suffix
	if d, err := publicsuffix.EffectiveTLDPlusOne(base); err == nil {
		etld1 = d
	}
	return tld, etld1
}

func dnsRow(certID uint64, source, s string) Row {
	name, valid, wild, base := normalizeDNS(s)
	if !valid {
		return Row{certID, source, name, false, false, nil, nil}
	}
	tld, etld1 := suffixes(base)
	return Row{certID, source, name, true, wild, tld, etld1}
}

// ipRow renders an iPAddress SAN: 4 bytes as a dotted quad, 16 bytes in RFC
// 5952 form, any other length as hex (the certificate carries
// san_ip_bad_len).
func ipRow(certID uint64, b []byte) Row {
	var name string
	switch len(b) {
	case 4:
		name = netip.AddrFrom4([4]byte(b)).String()
	case 16:
		name = netip.AddrFrom16([16]byte(b)).String()
	default:
		name = hex.EncodeToString(b)
	}
	return Row{certID, "san_ip", name, false, false, nil, nil}
}

// cnRow normalizes a subject CN: an IP literal in canonical form, a DNS name
// (one with a dot, or a wildcard) like a dNSName SAN, and anything else
// exactly as decoded with dns_valid false.
func cnRow(certID uint64, cn string) Row {
	if !strings.ContainsRune(cn, '\\') {
		if a, err := netip.ParseAddr(cn); err == nil {
			return Row{certID, "cn", a.String(), false, false, nil, nil}
		}
		if name, valid, wild, base := normalizeDNS(cn); valid && (wild || strings.Contains(base, ".")) {
			tld, etld1 := suffixes(base)
			return Row{certID, "cn", name, true, wild, tld, etld1}
		}
	}
	return Row{certID, "cn", cn, false, false, nil, nil}
}
```

Replace `go.mod` with:

```text
module github.com/4rji/ctvault

go 1.26.8

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/cockroachdb/pebble/v2 v2.1.7
	github.com/duckdb/duckdb-go/v2 v2.10506.0
	github.com/klauspost/compress v1.20.1
	github.com/spf13/cobra v1.10.2
	github.com/transparency-dev/merkle v0.0.2
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.59.0
	golang.org/x/sys v0.48.0
	golang.org/x/time v0.16.0
)

require (
	github.com/DataDog/zstd v1.5.7 // indirect
	github.com/RaduBerinde/axisds v0.1.0 // indirect
	github.com/RaduBerinde/btreemap v0.0.0-20250419174037-3d62b7205d54 // indirect
	github.com/apache/arrow-go/v18 v18.5.1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cockroachdb/crlib v0.0.0-20241112164430-1264a2edc35b // indirect
	github.com/cockroachdb/errors v1.11.3 // indirect
	github.com/cockroachdb/logtags v0.0.0-20230118201751-21c54148d20b // indirect
	github.com/cockroachdb/redact v1.1.5 // indirect
	github.com/cockroachdb/swiss v0.0.0-20260820225851-333444432258 // indirect
	github.com/cockroachdb/tokenbucket v0.0.0-20230807174530-cc333fc44b06 // indirect
	github.com/duckdb/duckdb-go-bindings v0.10506.0 // indirect
	github.com/duckdb/duckdb-go-bindings/lib/darwin-amd64 v0.10506.0 // indirect
	github.com/duckdb/duckdb-go-bindings/lib/darwin-arm64 v0.10506.0 // indirect
	github.com/duckdb/duckdb-go-bindings/lib/linux-amd64 v0.10506.0 // indirect
	github.com/duckdb/duckdb-go-bindings/lib/linux-arm64 v0.10506.0 // indirect
	github.com/duckdb/duckdb-go-bindings/lib/windows-amd64 v0.10506.0 // indirect
	github.com/getsentry/sentry-go v0.27.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/golang/snappy v1.0.0 // indirect
	github.com/google/flatbuffers v25.12.19+incompatible // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/minio/minlz v1.0.1-0.20250507153514-87eb42fe8882 // indirect
	github.com/pierrec/lz4/v4 v4.1.25 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_golang v1.16.0 // indirect
	github.com/prometheus/client_model v0.3.0 // indirect
	github.com/prometheus/common v0.42.0 // indirect
	github.com/prometheus/procfs v0.10.1 // indirect
	github.com/rogpeppe/go-internal v1.9.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/zeebo/xxh3 v1.1.0 // indirect
	golang.org/x/exp v0.0.0-20260112195511-716be5621a96 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/telemetry v0.0.0-20260811182544-a038080d80e5 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
```

Run: `go mod download golang.org/x/net@v0.59.0 && go mod tidy`
Expected: `go.sum` gains exactly these two lines:

```text
golang.org/x/net v0.59.0 h1:5zfYln+w5XCxwrnMMJPufRgNoXEaGxl0wo5GqPXyues=
golang.org/x/net v0.59.0/go.mod h1:2DA/G1UfVbCpQPeWTmMPGY7Cs2PkBkwu743bVX5PIVg=
```

- [ ] **Step 4: Generate the corpus rows golden file**

Run: `go test -count=1 -run TestCorpusRowsGolden ./internal/derive/ -update && sha256sum internal/derive/testdata/corpus_rows.golden.zst`
Expected: `ok`, then `8a3f641c144f2e0638794d9782129b6f964c7a28e158a111ccc01f80d9c53dd1`. It holds 2,710 `certs` rows and 4,154 `names` rows (3,834 with `dns_valid`).

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test -race -count=1 ./internal/extract/ ./internal/derive/`
Expected: PASS. `TestPSLMatchesTheModule` runs `go list -m golang.org/x/net` and reads the module's `publicsuffix/table.go`, so it needs the module in the cache (Step 3).

- [ ] **Step 6: Quality gate** (Global Constraints)

- [ ] **Step 7: Checkpoint.** Record the task in the ledger. The user commits.

---

### Task B2: `ACTIVE.json` and `views.sql` from it

Spec §7.6 and §7.8, amendment A2 §4.6 and §4.7.

**Files:**
- Create: `internal/derive/active.go`
- Modify: `internal/dataset/views.go` (views from `ACTIVE.json`), `internal/ingest/writer.go` (settles `ACTIVE.json` at Open), `internal/ingest/batch.go` (passes the state to `WriteViews`), `internal/cli/vaultcmds.go` (`init` writes `ACTIVE.json`)
- Tests: `internal/derive/active_test.go`, `internal/dataset/views_test.go`, `internal/dataset/dataset_test.go` (callers of `WriteViews`), `internal/ingest/active_test.go`, `internal/cli/active_test.go`

**Interfaces:**
- Consumes: `derive.Builders`, `(derive.Table).File()` (Task B1).
- Produces:
  - `derive.ActiveFile = "ACTIVE.json"` (under `dataset/`), `derive.StatusComplete`, `derive.StatusBuilding`;
  - `derive.TableState{Active, Building *int; Status string}`, `derive.Active{Seq uint64; Tables map[string]TableState}`;
  - `derive.Complete() Active`, `derive.Upgrading() Active`, `(Active).AllComplete() bool`, `(Active).Check() error`;
  - `derive.ReadActive(root) (Active, bool, error)`, `derive.WriteActive(root, Active) error` (atomic, sorted keys);
  - `dataset.Views(root string, committed bool, a derive.Active, present map[string]bool) []byte`;
  - `dataset.WriteViews(root string, a derive.Active) (bool, error)` (the new signature);
  - `(*ingest.Writer).Active() derive.Active`.

- [ ] **Step 1: Write the failing tests**

Create `internal/derive/active_test.go`:

```go
package derive

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestActiveStates(t *testing.T) {
	c, u := Complete(), Upgrading()
	for _, b := range Builders {
		tb := b.Table()
		if s := c.Tables[tb.Name]; s.Active == nil || *s.Active != tb.Version || s.Building != nil || s.Status != StatusComplete {
			t.Errorf("Complete %s: %+v", tb.Name, s)
		}
		if s := u.Tables[tb.Name]; s.Active != nil || s.Building == nil || *s.Building != tb.Version || s.Status != StatusBuilding {
			t.Errorf("Upgrading %s: %+v", tb.Name, s)
		}
	}
	if c.Seq != 1 || u.Seq != 1 || !c.AllComplete() || u.AllComplete() {
		t.Errorf("seq %d %d, complete %v %v", c.Seq, u.Seq, c.AllComplete(), u.AllComplete())
	}
}

func TestActiveRoundTrip(t *testing.T) {
	root := t.TempDir()
	if _, ok, err := ReadActive(root); ok || err != nil {
		t.Fatalf("missing ACTIVE.json: %v %v", ok, err)
	}
	if err := WriteActive(root, Upgrading()); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(filepath.Join(root, "dataset", ActiveFile))
	if err := WriteActive(root, Upgrading()); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(filepath.Join(root, "dataset", ActiveFile))
	if string(first) != string(second) {
		t.Fatal("ACTIVE.json is not deterministic")
	}
	a, ok, err := ReadActive(root)
	if !ok || err != nil || a.AllComplete() || *a.Tables["certs"].Building != 1 {
		t.Fatalf("read back %+v %v %v", a, ok, err)
	}
}

// TestActiveCheck: a binary refuses an ACTIVE.json it cannot honour (spec
// §7.5): a version or a table it does not know, or one it lacks.
func TestActiveCheck(t *testing.T) {
	two := 2
	for name, edit := range map[string]func(*Active){
		"unknown version": func(a *Active) { s := a.Tables["certs"]; s.Active = &two; a.Tables["certs"] = s },
		"unknown table":   func(a *Active) { a.Tables["cert_policies"] = a.Tables["certs"] },
		"missing table":   func(a *Active) { delete(a.Tables, "names") },
		"unknown status":  func(a *Active) { s := a.Tables["names"]; s.Status = "mixed"; a.Tables["names"] = s },
		"nothing active or building": func(a *Active) {
			s := a.Tables["names"]
			s.Active, s.Building = nil, nil
			a.Tables["names"] = s
		},
	} {
		a := Complete()
		edit(&a)
		if err := a.Check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := Complete().Check(); err != nil {
		t.Error(err)
	}
	if err := Upgrading().Check(); err != nil {
		t.Error(err)
	}
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "dataset"), 0o755)
	os.WriteFile(filepath.Join(root, "dataset", ActiveFile), []byte("{"), 0o644)
	if _, _, err := ReadActive(root); err == nil || !strings.Contains(err.Error(), ActiveFile) {
		t.Errorf("unreadable ACTIVE.json: %v", err)
	}
}
```

Replace `internal/dataset/views_test.go` with:

```go
package dataset

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"

	"github.com/4rji/ctvault/internal/derive"
)

func describe(t *testing.T, s *Stager, view string) string {
	t.Helper()
	rows, err := s.db.Query(`SELECT column_name, column_type FROM (DESCRIBE ` + view + `)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n, ty string
		rows.Scan(&n, &ty)
		out = append(out, n+" "+ty)
	}
	return fmt.Sprint(out)
}

func loadViews(t *testing.T, s *Stager, root string) {
	t.Helper()
	v, err := os.ReadFile(filepath.Join(root, ViewsFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(string(v)); err != nil {
		t.Fatalf("views.sql does not load: %v", err)
	}
}

// TestViewsWorkBeforeTheFirstBatch: a new vault's views.sql loads and
// shows empty tables with the committed columns; after the first batch
// commits it changes and shows the batch.
func TestViewsWorkBeforeTheFirstBatch(t *testing.T) {
	root := t.TempDir()
	if changed, err := WriteViews(root, derive.Complete()); err != nil || !changed {
		t.Fatalf("first write: %v %v", changed, err)
	}
	empty := stager(t)
	loadViews(t, empty, root)
	for _, v := range []string{"entries", "chains", "batches", "certs", "names", "entry_certs", "logging_delay"} {
		var n int
		if err := empty.db.QueryRow(`SELECT count(*) FROM ` + v).Scan(&n); err != nil || n != 0 {
			t.Fatalf("an empty vault: %s has %d rows (%v)", v, n, err)
		}
	}

	s := stager(t)
	dir := filepath.Join(root, "dataset", "log=argon2027h1", "batch=000000000000-000000000039")
	es, cs := rows(40)
	if _, err := s.Stage(ctx, dir, es, cs); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "_COMMIT.json"), []byte(`{"format":1,"commit_seq":1}`), 0o644)
	if changed, err := WriteViews(root, derive.Complete()); err != nil || !changed {
		t.Fatalf("the first commit changes views.sql: %v %v", changed, err)
	}
	full := stager(t)
	loadViews(t, full, root)
	var n int
	full.db.QueryRow(`SELECT count(*) FROM entries`).Scan(&n)
	if n != 40 {
		t.Fatalf("after the first commit: %d entries", n)
	}
	for _, v := range []string{"entries", "chains"} {
		if got, want := describe(t, empty, v), describe(t, full, v); got != want {
			t.Fatalf("%s before the first batch has columns %s\nafter: %s", v, got, want)
		}
	}
}

// TestEmptyDerivedViewsHaveTheSchema: before any batch holds a derived file,
// its view is empty but already has the table's exact columns, plus the
// hive partition columns.
func TestEmptyDerivedViewsHaveTheSchema(t *testing.T) {
	root := t.TempDir()
	if _, err := WriteViews(root, derive.Complete()); err != nil {
		t.Fatal(err)
	}
	s := stager(t)
	loadViews(t, s, root)
	for _, b := range derive.Builders {
		tb := b.Table()
		var want []string
		for _, c := range tb.Columns {
			want = append(want, c.Name+" "+c.Type)
		}
		want = append(want, "batch VARCHAR", "log VARCHAR")
		if got := describe(t, s, tb.Name); got != fmt.Sprint(want) {
			t.Errorf("%s: %s\nwant %v", tb.Name, got, want)
		}
	}
}

// TestDerivedViewsFollowActive: a table that is still being built is only
// exposed as <table>_building, never as the complete table (amendment A2
// §4.7), and the joins on it do not exist yet.
func TestDerivedViewsFollowActive(t *testing.T) {
	root := t.TempDir()
	exists := func(view string) bool {
		s := stager(t)
		loadViews(t, s, root)
		var n int
		return s.db.QueryRow(`SELECT count(*) FROM `+view).Scan(&n) == nil
	}
	if _, err := WriteViews(root, derive.Upgrading()); err != nil {
		t.Fatal(err)
	}
	for view, want := range map[string]bool{"certs_building": true, "names_building": true, "certs": false, "names": false, "entry_certs": false, "logging_delay": false} {
		if exists(view) != want {
			t.Errorf("building: view %s exists = %v", view, !want)
		}
	}
	if changed, err := WriteViews(root, derive.Complete()); err != nil || !changed {
		t.Fatalf("switching to complete must rewrite views.sql: %v %v", changed, err)
	}
	for view, want := range map[string]bool{"certs_building": false, "certs": true, "names": true, "entry_certs": true, "logging_delay": true} {
		if exists(view) != want {
			t.Errorf("complete: view %s exists = %v", view, !want)
		}
	}
}

// TestCanaryChecksCertIDRanges: spec §8.3 P6(e), cert_id range lookups
// through the reader's predicate.
func TestCanaryChecksCertIDRanges(t *testing.T) {
	s := stager(t)
	dir := filepath.Join(t.TempDir(), "b")
	es, cs := rows(40)
	if _, err := s.Stage(ctx, dir, es, cs); err != nil {
		t.Fatal(err)
	}
	if err := s.Canary(ctx, dir, es, cs, 8, rand.New(rand.NewPCG(5, 6))); err != nil {
		t.Fatal(err)
	}
	bad := append([]EntryRow(nil), es...)
	bad[4].CertID = 0 // the file holds a cert_id the batch does not
	if err := s.Canary(ctx, dir, bad, cs, 0, rand.New(rand.NewPCG(5, 6))); !errors.Is(err, ErrCanary) {
		t.Fatalf("a cert_id range that reads back a different count: %v", err)
	}
}
```

Replace `internal/dataset/dataset_test.go` with (`WriteViews` takes the state):

```go
package dataset

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/4rji/ctvault/internal/derive"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var ctx = context.Background()

func stager(t *testing.T) *Stager {
	t.Helper()
	s, err := NewStager(Options{TempDir: filepath.Join(t.TempDir(), "duckdb-1"), MaxTempBytes: 1 << 30, Threads: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// rows makes n entries covering every column state: precerts with an issuer
// key hash, x509 entries, and leaf errors with NULL certificate fields.
func rows(n int) ([]EntryRow, []ChainRow) {
	var es []EntryRow
	var cs []ChainRow
	for i := range n {
		r := EntryRow{Idx: uint64(1000 + i), CTTimestamp: 1790000000000 + uint64(i), EntryType: "x509", CertID: uint64(i + 1),
			LeafHash: sha256.Sum256([]byte{byte(i), byte(i >> 8)}), HasIssuanceKey: true, HasChainID: true}
		r.IssuanceKey[0], r.ChainID = byte(i), sha256.Sum256([]byte{byte(i % 3)})
		switch i % 4 {
		case 1:
			r.EntryType, r.HasIssuerKeyHash = "precert", true
			r.IssuerKeyHash[5] = 7
		case 3:
			r = EntryRow{Idx: r.Idx, LeafHash: r.LeafHash, EntryType: "unknown", LeafError: "leaf_bad_version"}
		}
		es = append(es, r)
	}
	for c := range 3 {
		for p := range 2 {
			cs = append(cs, ChainRow{ChainID: sha256.Sum256([]byte{byte(c)}), Position: uint16(p), CertID: uint64(500 + 10*c + p)})
		}
	}
	return es, cs
}

func TestStageAndCanary(t *testing.T) {
	s := stager(t)
	dir := filepath.Join(t.TempDir(), "stage", "b1")
	es, cs := rows(200)
	files, err := s.Stage(ctx, dir, es, cs)
	if err != nil {
		t.Fatal(err)
	}
	for name, rowsWant := range map[string]int{EntriesFile: 200, ChainsFile: 6} {
		fi := files[name]
		sum, err := Sum(filepath.Join(dir, name))
		if err != nil || fi.Rows != rowsWant || fi.Bytes == 0 || sum.SHA256 != fi.SHA256 {
			t.Fatalf("%s: %+v (recomputed %+v, %v)", name, fi, sum, err)
		}
	}
	if err := s.Canary(ctx, dir, es, cs, 1000, rand.New(rand.NewPCG(1, 2))); err != nil {
		t.Fatalf("every row must read back: %v", err)
	}
}

func TestCanaryCatchesMismatches(t *testing.T) {
	s := stager(t)
	dir := filepath.Join(t.TempDir(), "b")
	es, cs := rows(40)
	if _, err := s.Stage(ctx, dir, es, cs); err != nil {
		t.Fatal(err)
	}
	rnd := func() *rand.Rand { return rand.New(rand.NewPCG(3, 4)) }
	if err := s.Canary(ctx, dir, es[:39], cs, 5, rnd()); !errors.Is(err, ErrCanary) {
		t.Fatalf("a row count mismatch: %v", err)
	}
	bad := append([]EntryRow(nil), es...)
	for i := range bad {
		bad[i].CertID++
	}
	if err := s.Canary(ctx, dir, bad, cs, 5, rnd()); !errors.Is(err, ErrCanary) {
		t.Fatalf("a field that reads back differently: %v", err)
	}
	badChains := append([]ChainRow(nil), cs...)
	for i := range badChains {
		badChains[i].CertID++
	}
	if err := s.Canary(ctx, dir, es, badChains, 5, rnd()); !errors.Is(err, ErrCanary) {
		t.Fatalf("a chain that reads back differently: %v", err)
	}
}

func TestCanaryRefusesBloomFilters(t *testing.T) {
	s := stager(t)
	dir := filepath.Join(t.TempDir(), "b")
	es, cs := rows(40)
	if _, err := s.Stage(ctx, dir, es, cs); err != nil {
		t.Fatal(err)
	}
	// Rewrite entries.parquet the default way, which adds bloom filters.
	p := filepath.Join(dir, EntriesFile)
	if _, err := s.db.Exec(`COPY (SELECT * FROM read_parquet(` + quote(p) + `)) TO ` + quote(p+".bloom") + ` (FORMAT parquet)`); err != nil {
		t.Fatal(err)
	}
	os.Rename(p+".bloom", p)
	if err := s.Canary(ctx, dir, es, cs, 5, rand.New(rand.NewPCG(5, 6))); !errors.Is(err, ErrCanary) || !strings.Contains(err.Error(), "bloom") {
		t.Fatalf("a bloom-filtered file must fail the canary: %v", err)
	}
}

// TestDuckDBBloomFilterBugRegression reproduces spec §3.6 on the pinned
// DuckDB: a literal lookup on a bloom-filtered, low-cardinality BLOB column
// finds nothing. When DuckDB fixes it this test fails, so decision D19 (no
// bloom filters on BLOB columns) can be revisited; the writer keeps them off
// either way.
func TestDuckDBBloomFilterBugRegression(t *testing.T) {
	s := stager(t)
	dir := t.TempDir()
	const data = `SELECT unhex(sha256((i % 3)::VARCHAR)) AS ikh FROM range(2000) t(i)`
	lookup := `SELECT count(*) FROM read_parquet(?) WHERE ikh = unhex(sha256('1'))`
	bloom, plain := filepath.Join(dir, "bloom.parquet"), filepath.Join(dir, "plain.parquet")
	if _, err := s.db.Exec(`COPY (` + data + `) TO ` + quote(bloom) + ` (FORMAT parquet)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`COPY (` + data + `) TO ` + quote(plain) + ` ` + copyOptions); err != nil {
		t.Fatal(err)
	}
	var withBloom, without int
	s.db.QueryRow(lookup, bloom).Scan(&withBloom)
	s.db.QueryRow(lookup, plain).Scan(&without)
	if without != 667 {
		t.Fatalf("control: CTVault's writer settings must find all 667 rows, got %d", without)
	}
	if withBloom == 667 {
		t.Error("DuckDB no longer shows the BLOB bloom-filter bug (spec §3.6); D19 can be revisited")
	} else if withBloom != 0 {
		t.Fatalf("unexpected count %d with bloom filters", withBloom)
	}
}

func TestStagerConfinesSpill(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "duckdb-42")
	s, err := NewStager(Options{TempDir: dir, MaxTempBytes: 3 << 30})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var temp, max string
	s.db.QueryRow(`SELECT current_setting('temp_directory'), current_setting('max_temp_directory_size')`).Scan(&temp, &max)
	if temp != dir || !strings.HasPrefix(max, "3.0 GiB") {
		t.Fatalf("temp_directory %q, max_temp_directory_size %q", temp, max)
	}
}

// TestViewsSeeCommittedBatchesOnly loads views.sql into a fresh DuckDB
// session over two committed batches and a staged one.
func TestViewsSeeCommittedBatchesOnly(t *testing.T) {
	s := stager(t)
	root := t.TempDir()
	for i, b := range []string{"batch=000000000000-000000000039", "batch=000000000040-000000000079"} {
		dir := filepath.Join(root, "dataset", "log=argon2027h1", b)
		es, cs := rows(40)
		for j := range es {
			es[j].Idx = uint64(40*i + j)
		}
		if _, err := s.Stage(ctx, dir, es, cs); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, "_COMMIT.json"), []byte(fmt.Sprintf(`{"format":1,"commit_seq":%d}`, i+1)), 0o644)
	}
	es, cs := rows(40)
	if _, err := s.Stage(ctx, filepath.Join(root, "tmp", "stage", "x"), es, cs); err != nil {
		t.Fatal(err)
	}
	if changed, err := WriteViews(root, derive.Complete()); err != nil || !changed {
		t.Fatalf("first write: %v %v", changed, err)
	}
	if changed, _ := WriteViews(root, derive.Complete()); changed {
		t.Fatal("views.sql is rewritten only when it changes")
	}
	v, _ := os.ReadFile(filepath.Join(root, ViewsFile))
	if _, err := s.db.Exec(string(v)); err != nil {
		t.Fatal(err)
	}
	var n, logs, batches int
	s.db.QueryRow(`SELECT count(*), count(DISTINCT log) FROM entries`).Scan(&n, &logs)
	s.db.QueryRow(`SELECT count(*) FROM batches`).Scan(&batches)
	var chains int
	s.db.QueryRow(`SELECT count(*) FROM chains`).Scan(&chains)
	if n != 80 || logs != 1 || batches != 2 || chains != 12 {
		t.Fatalf("views: %d entries in %d logs, %d batches, %d chain rows; want 80, 1, 2, 12 (staging excluded)", n, logs, batches, chains)
	}
}
```

Create `internal/ingest/active_test.go`:

```go
package ingest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/derive"
)

// TestActiveOnOpen: the writer settles ACTIVE.json at Open (amendment A2
// §4.6). A vault without batches has nothing to backfill and is complete; a
// vault written before Plan 3, with batches but no ACTIVE.json, starts
// building; an ACTIVE.json this binary cannot honour is refused.
func TestActiveOnOpen(t *testing.T) {
	h := newHarness(t, entries(t, 20), ctlogtest.Options{})
	w := h.open()
	if a, ok, err := derive.ReadActive(h.root); !ok || err != nil || !a.AllComplete() {
		t.Fatalf("a new vault: %+v %v %v", a, ok, err)
	}
	h.ingest(w, h.head(), 0, 20, 20)
	w.Close()

	os.Remove(filepath.Join(h.root, "dataset", derive.ActiveFile)) // a vault written before Plan 3
	w = h.open()
	a, _, _ := derive.ReadActive(h.root)
	if a.AllComplete() || a.Tables["certs"].Building == nil || *a.Tables["certs"].Building != 1 {
		t.Fatalf("a Plan 2 vault with batches: %+v", a)
	}
	views, _ := os.ReadFile(filepath.Join(h.root, "views.sql"))
	if !strings.Contains(string(views), "VIEW certs_building ") || strings.Contains(string(views), "VIEW certs ") {
		t.Fatalf("views.sql of a building vault:\n%s", views)
	}
	w.Close()

	two := 2
	a.Tables["certs"] = derive.TableState{Active: &two, Status: derive.StatusComplete}
	if err := derive.WriteActive(h.root, a); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(h.opts); err == nil || !strings.Contains(err.Error(), derive.ActiveFile) {
		t.Fatalf("an ACTIVE.json naming certs v2: %v", err)
	}
}
```

Create `internal/cli/active_test.go`:

```go
package cli

import (
	"testing"

	"github.com/4rji/ctvault/internal/derive"
)

// TestInitWritesActive: a new vault's derived tables are complete from the
// start (amendment A2 §4.6).
func TestInitWritesActive(t *testing.T) {
	e := newEnv(t, nil)
	e.mustRun("init", e.root)
	if a, ok, err := derive.ReadActive(e.root); !ok || err != nil || !a.AllComplete() {
		t.Fatalf("ACTIVE.json after init: %+v %v %v", a, ok, err)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/derive/ ./internal/dataset/ ./internal/ingest/ ./internal/cli/`
Expected: FAIL with `undefined: Complete` in `internal/derive`; `too many arguments in call to WriteViews` and `undefined: derive.Complete` in `internal/dataset`; `undefined: derive.ReadActive` in `internal/ingest` and `internal/cli`.

- [ ] **Step 3: Implement**

Create `internal/derive/active.go`:

```go
package derive

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/4rji/ctvault/internal/fsutil"
)

// ActiveFile is dataset/ACTIVE.json (spec §4.3, §7.8): which version of each
// derived table is active and which is being built.
const ActiveFile = "ACTIVE.json"

// Table statuses.
const (
	StatusComplete = "complete" // every committed batch has the active version
	StatusBuilding = "building" // a version is being built; only <table>_building is exposed
)

// TableState is one table's entry in ACTIVE.json.
type TableState struct {
	Active   *int   `json:"active"`
	Building *int   `json:"building"`
	Status   string `json:"status"`
}

// Active is ACTIVE.json.
type Active struct {
	Seq    uint64                `json:"seq"`
	Tables map[string]TableState `json:"tables"`
}

func ptr(v int) *int { return &v }

// Complete is a vault whose every derived table is active at this binary's
// version: a new vault (amendment A2 §4.6).
func Complete() Active {
	a := Active{Seq: 1, Tables: map[string]TableState{}}
	for _, b := range Builders {
		a.Tables[b.Table().Name] = TableState{Active: ptr(b.Table().Version), Status: StatusComplete}
	}
	return a
}

// Upgrading is a vault written before its derived tables existed: every
// table is building at this binary's version, with nothing active yet.
func Upgrading() Active {
	a := Active{Seq: 1, Tables: map[string]TableState{}}
	for _, b := range Builders {
		a.Tables[b.Table().Name] = TableState{Building: ptr(b.Table().Version), Status: StatusBuilding}
	}
	return a
}

// AllComplete reports whether every table is complete.
func (a Active) AllComplete() bool {
	for _, s := range a.Tables {
		if s.Status != StatusComplete {
			return false
		}
	}
	return len(a.Tables) > 0
}

// Check refuses an ACTIVE.json this binary cannot honour (spec §7.5): a table
// or a version it does not know, a table it lacks, or an unknown status.
func (a Active) Check() error {
	known := map[string]Table{}
	for _, b := range Builders {
		known[b.Table().Name] = b.Table()
		if _, ok := a.Tables[b.Table().Name]; !ok {
			return fmt.Errorf("%s lacks table %s", ActiveFile, b.Table().Name)
		}
	}
	for name, s := range a.Tables {
		tb, ok := known[name]
		if !ok {
			return fmt.Errorf("%s names table %s, which this binary does not build: upgrade ctvault", ActiveFile, name)
		}
		for _, v := range []*int{s.Active, s.Building} {
			if v != nil && *v != tb.Version {
				return fmt.Errorf("%s names %s version %d; this binary builds version %d", ActiveFile, name, *v, tb.Version)
			}
		}
		switch {
		case s.Status == StatusComplete && s.Active != nil && s.Building == nil:
		case s.Status == StatusBuilding && s.Building != nil:
		default:
			return fmt.Errorf("%s: table %s has an inconsistent state %+v", ActiveFile, name, s)
		}
	}
	return nil
}

// ReadActive reads dataset/ACTIVE.json; ok is false when it does not exist.
func ReadActive(root string) (a Active, ok bool, err error) {
	b, err := os.ReadFile(filepath.Join(root, "dataset", ActiveFile))
	if errors.Is(err, fs.ErrNotExist) {
		return a, false, nil
	}
	if err != nil {
		return a, false, err
	}
	if err := json.Unmarshal(b, &a); err != nil {
		return a, false, fmt.Errorf("%s: %w", ActiveFile, err)
	}
	return a, true, nil
}

// WriteActive replaces dataset/ACTIVE.json atomically. The JSON is
// deterministic: map keys are sorted.
func WriteActive(root string, a Active) error {
	b, err := json.MarshalIndent(a, "", " ")
	if err != nil {
		return err
	}
	dir := filepath.Join(root, "dataset")
	if err := fsutil.MkdirAllSync(dir, 0o755); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(dir, ActiveFile), append(b, '\n'), 0o644)
}
```

Replace `internal/dataset/views.go` with:

```go
package dataset

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/fsutil"
)

// ViewsFile is generated at the vault root for the DuckDB CLI and Jupyter.
const ViewsFile = "views.sql"

// Views returns views.sql for a vault at root (absolute). Plan 2's minimal
// set: entries, chains and batches over committed batch directories only;
// staging lives in tmp/, never under dataset/. Until the first batch
// commits, the globs would match nothing and DuckDB would refuse to load
// the file, so the views are empty with the committed columns instead.
func baseViews(root string, committed bool) string {
	head := fmt.Sprintf(`-- Generated by ctvault; do not edit. Load with: .read %s
`, filepath.Join(root, ViewsFile))
	if !committed {
		return head + `-- No batch is committed yet: the views are empty. ctvault rewrites this
-- file when the first batch commits.
CREATE OR REPLACE VIEW entries AS
  SELECT NULL::UBIGINT AS idx, NULL::TIMESTAMP AS ct_ts, NULL::VARCHAR AS entry_type, NULL::UBIGINT AS cert_id,
    NULL::BLOB AS leaf_hash, NULL::BLOB AS issuance_key, NULL::BLOB AS issuer_key_hash, NULL::BLOB AS chain_id,
    NULL::VARCHAR AS leaf_error, NULL::VARCHAR AS batch, NULL::VARCHAR AS log
  WHERE false;
CREATE OR REPLACE VIEW chains AS
  SELECT NULL::BLOB AS chain_id, NULL::USMALLINT AS position, NULL::UBIGINT AS cert_id,
    NULL::VARCHAR AS batch, NULL::VARCHAR AS log
  WHERE false;
CREATE OR REPLACE VIEW batches AS
  SELECT NULL::UBIGINT AS commit_seq, NULL::VARCHAR AS batch_id, NULL::VARCHAR AS log,
    NULL::UBIGINT AS first, NULL::UBIGINT AS last
  WHERE false;
`
	}
	ds := filepath.Join(root, "dataset")
	glob := func(name string) string { return quote(filepath.Join(ds, "log=*", "batch=*", name)) }
	return head + fmt.Sprintf(`-- Globs see a commit at once, but a join running while a batch commits can
-- see it in one table and not yet in another (spec §7.6).
CREATE OR REPLACE VIEW entries AS
  SELECT * FROM read_parquet(%s, hive_partitioning = true, union_by_name = true);
CREATE OR REPLACE VIEW chains AS
  SELECT * FROM read_parquet(%s, hive_partitioning = true, union_by_name = true);
CREATE OR REPLACE VIEW batches AS
  SELECT * FROM read_json(%s, format = 'auto', union_by_name = true);
`, glob(EntriesFile), glob(ChainsFile), glob("_COMMIT.json"))
}

// Views returns views.sql for a vault at root (absolute): the source-layer
// views, then the derived tables as ACTIVE.json says (amendment A2 §4.7).
// A complete table is exposed under its name, with entry_certs and
// logging_delay joining certs; a table being built only as <table>_building.
// present names the derived files at least one committed batch holds; a
// view over a file no batch holds yet is empty with the table's columns.
func Views(root string, committed bool, a derive.Active, present map[string]bool) []byte {
	var b strings.Builder
	b.WriteString(baseViews(root, committed))
	glob := func(name string) string {
		return quote(filepath.Join(root, "dataset", "log=*", "batch=*", name))
	}
	for _, bl := range derive.Builders {
		tb := bl.Table()
		st := a.Tables[tb.Name]
		view, version := tb.Name, st.Active
		if st.Status != derive.StatusComplete {
			view, version = tb.Name+"_building", st.Building
		}
		if version == nil {
			continue
		}
		file := derive.Table{Name: tb.Name, Version: *version}.File()
		if present[file] {
			fmt.Fprintf(&b, "CREATE OR REPLACE VIEW %s AS\n  SELECT * FROM read_parquet(%s, hive_partitioning = true, union_by_name = true);\n", view, glob(file))
			continue
		}
		var cols []string
		for _, c := range tb.Columns {
			cols = append(cols, fmt.Sprintf("NULL::%s AS %s", c.Type, c.Name))
		}
		cols = append(cols, "NULL::VARCHAR AS batch", "NULL::VARCHAR AS log")
		fmt.Fprintf(&b, "CREATE OR REPLACE VIEW %s AS\n  SELECT %s\n  WHERE false;\n", view, strings.Join(cols, ", "))
	}
	if a.Tables[derive.CertsV1.Name].Status == derive.StatusComplete {
		b.WriteString(`CREATE OR REPLACE VIEW entry_certs AS
  SELECT e.*, c.* EXCLUDE (cert_id, batch, log) FROM entries e JOIN certs c USING (cert_id);
CREATE OR REPLACE VIEW logging_delay AS
  SELECT e.log, e.idx, e.cert_id, e.ct_ts, c.not_before, CAST(e.ct_ts AS TIMESTAMP) - c.not_before AS logging_delay
  FROM entries e JOIN certs c USING (cert_id);
`)
	}
	return []byte(b.String())
}

// WriteViews regenerates views.sql from ACTIVE.json's state a and replaces
// it atomically only when its contents change (amendment A1 §7). It reports
// whether it wrote. The writer calls it at start, after every commit and
// whenever ACTIVE.json changes.
func WriteViews(root string, a derive.Active) (bool, error) {
	done, err := filepath.Glob(filepath.Join(root, "dataset", "log=*", "batch=*", "_COMMIT.json"))
	if err != nil {
		return false, err
	}
	present := map[string]bool{}
	for _, d := range done {
		files, err := os.ReadDir(filepath.Dir(d))
		if err != nil {
			return false, err
		}
		for _, f := range files {
			present[f.Name()] = true
		}
	}
	want := Views(root, len(done) > 0, a, present)
	p := filepath.Join(root, ViewsFile)
	got, err := os.ReadFile(p)
	if err == nil && bytes.Equal(got, want) {
		return false, nil
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	return true, fsutil.WriteFileAtomic(p, want, 0o644)
}
```

Replace `internal/ingest/writer.go` with:

```go
// Package ingest runs batches: it fetches a range of a log, verifies it
// against a pinned signed tree head, vaults new certificates, stages the
// source-layer Parquet files and commits through the protocol of spec §8.3.
package ingest

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

// Options configure a Writer. The caller holds the writer lock and has run
// the volume checks.
type Options struct {
	Root      string
	VaultDirs []string // absolute, in VAULT_ID order
	VaultUUID [16]byte
	Config    config.Config
	Guard     diskguard.Guard
	Fetch     fetch.Options // workers, rate and stall timeout from Config, plus test overrides
	Version   string
	Now       func() time.Time
	Out       io.Writer    // one line per batch and recovery action
	Hook      func(string) // crash points, tests only
	// CheckVolumes repeats the volume checks (spec §9.2) at every batch
	// preflight; a failure stops the batch before anything is written.
	CheckVolumes func() error

	// DictSamples is how many leaf certificates train dictionary 1 (20,000;
	// tests use fewer). Train defaults to vault.Train.
	DictSamples int
	Train       func(samples [][]byte, id uint64) ([]byte, error)
	// CanarySamples is how many rows and vault records the canary checks
	// per batch (default 64).
	CanarySamples int
}

// Writer is the single writer of a vault.
type Writer struct {
	o      Options
	paths  commit.Paths
	idx    *index.Index
	codec  *vault.Codec
	stager *dataset.Stager
	ids    *commit.IDs
	vw     *vault.Writer
	delta  *vault.DeltaCache
	dictID uint64

	trainTried bool
	cold       bool  // the delta cache was emptied by a stopped attempt
	broken     error // an abandon failed: no more batches (ErrAbandonFailed)
	spill      string

	committed []commit.Manifest
	tips      map[string]commit.LogTip
	active    derive.Active // dataset/ACTIVE.json
}

func (w *Writer) logf(format string, args ...any) {
	if w.o.Out != nil {
		fmt.Fprintf(w.o.Out, format+"\n", args...)
	}
}

// WriterSpillDir is the writer's DuckDB spill folder under tmp/ (spec §10.1
// gives readers tmp/duckdb-<pid>; there is only ever one writer).
const WriterSpillDir = "duckdb-writer"

// Open recovers the vault (spec §8.5) and prepares the writer: index,
// dictionaries, cert_id allocator, vault tail, delta cache warm-up and
// views.sql.
func Open(o Options) (*Writer, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.DictSamples == 0 {
		o.DictSamples = vault.TrainingSamples
	}
	if o.Train == nil {
		o.Train = vault.Train
	}
	if o.CanarySamples == 0 {
		o.CanarySamples = 64
	}
	w := &Writer{o: o, paths: commit.Paths{Root: o.Root}}
	ok := false
	defer func() {
		if !ok {
			w.Close()
		}
	}()
	var err error
	if w.idx, err = index.Open(filepath.Join(o.Root, "state", "pebble")); err != nil {
		return nil, err
	}
	if w.codec, err = vault.NewCodec(); err != nil {
		return nil, err
	}
	dicts, err := vault.LoadDicts(o.VaultDirs)
	if err != nil {
		return nil, err
	}
	for _, d := range dicts {
		if err := w.codec.AddDict(d.Manifest.ID, d.Content); err != nil {
			return nil, err
		}
		w.dictID = d.Manifest.ID
	}
	// The writer's DuckDB spill folder has a fixed name: the writer lock
	// makes it ours, so a killed writer's leftover is emptied here.
	// Readers' tmp/duckdb-<pid> folders are never touched (amendment A1 §7).
	w.spill = filepath.Join(o.Root, "tmp", WriterSpillDir)
	if left, _ := os.ReadDir(w.spill); len(left) > 0 {
		w.logf("recovery: emptied the writer's leftover DuckDB spill folder tmp/%s", WriterSpillDir)
	}
	if err := os.RemoveAll(w.spill); err != nil {
		return nil, err
	}
	if w.stager, err = dataset.NewStager(dataset.Options{TempDir: w.spill, MaxTempBytes: w.spillLimit()}); err != nil {
		return nil, err
	}
	rec, err := commit.Recover(commit.RecoverOptions{Paths: w.paths, VaultDirs: o.VaultDirs, VaultUUID: o.VaultUUID, Index: w.idx,
		Codec: w.codec, ChainIDs: w.stager.ChainIDs})
	if err != nil {
		return nil, err
	}
	for _, a := range rec.Actions {
		w.logf("recovery: %s", a)
	}
	w.committed, w.tips = rec.Committed, commit.Tips(rec.Committed)
	if w.ids, err = commit.LoadIDs(w.paths.StateDir(), rec.NextCertID, o.Hook); err != nil {
		return nil, err
	}
	if w.vw, err = vault.OpenWriter(w.vaultOptions(), w.codec, rec.Tail); err != nil {
		return nil, err
	}
	if err := w.warm(); err != nil {
		return nil, err
	}
	if w.active, err = settleActive(o.Root, len(rec.Committed) > 0); err != nil {
		return nil, err
	}
	if _, err := dataset.WriteViews(o.Root, w.active); err != nil {
		return nil, err
	}
	ok = true
	return w, nil
}

func (w *Writer) vaultOptions() vault.Options {
	return vault.Options{Dirs: w.o.VaultDirs, VaultUUID: w.o.VaultUUID, SegmentSize: uint64(w.o.Config.Vault.SegmentSize),
		Check: w.o.Guard.Check, Hook: w.o.Hook, Now: w.o.Now}
}

// SpillBudget caps the writer's DuckDB spill. Spec §10.1 sets every DuckDB
// session's spill limit to the headroom below the cap minus 1 GiB, and
// amendment A1 §7 adds the limit to every batch's peak; together no batch
// could ever start. The writer therefore spills at most this budget, and
// the preflight counts it (Plan 2B decision). Plan 2's tables fit in memory.
const SpillBudget = 4 << 30

// spillLimit is the writer's max_temp_directory_size: the budget, or less
// when the headroom below the cap minus a 1 GiB margin is smaller, but at
// least 64 MiB.
func (w *Writer) spillLimit() uint64 {
	const margin, floor = 1 << 30, 64 << 20
	u, err := w.o.Guard.Stat(w.o.Root)
	if err != nil || u.Total == 0 {
		return floor
	}
	lim := uint64(w.o.Guard.Cap * float64(u.Total))
	if used := u.Used(); lim > used+margin+floor {
		return min(SpillBudget, lim-used-margin)
	}
	return floor
}

// warm refills the delta cache from the last delta.warm_batches committed
// batches (amendment A1 §5).
func (w *Writer) warm() error {
	if w.delta == nil {
		w.delta = vault.NewDeltaCache(w.o.Config.Ingest.DeltaLRUEntries)
	} else {
		w.delta.Reset() // reuse the cache's memory (207 MiB at the default size)
	}
	n := w.o.Config.Delta.WarmBatches
	var ranges []vault.Range
	for i := max(0, len(w.committed)-n); i < len(w.committed); i++ {
		ranges = append(ranges, vault.Range{Start: w.committed[i].Vault.Start, End: w.committed[i].Vault.End})
	}
	return vault.Warm(w.o.VaultDirs, w.codec, w.delta, ranges, leaf.PrecertIssuanceDigest)
}

// settleActive reads dataset/ACTIVE.json, or creates it (amendment A2 §4.6):
// complete for a vault without batches, which has nothing to backfill, and
// building for a vault written before Plan 3. A state this binary cannot
// honour is refused.
func settleActive(root string, committed bool) (derive.Active, error) {
	a, ok, err := derive.ReadActive(root)
	if err != nil {
		return a, err
	}
	if !ok {
		a = derive.Complete()
		if committed {
			a = derive.Upgrading()
		}
		if err := derive.WriteActive(root, a); err != nil {
			return a, err
		}
	}
	return a, a.Check()
}

// Active returns the vault's ACTIVE.json state.
func (w *Writer) Active() derive.Active { return w.active }

// Next returns the first index of log not yet committed.
func (w *Writer) Next(log string) uint64 { return w.tips[log].Next }

// Tip returns log's committed position and Merkle state (State is nil when
// nothing of log is committed).
func (w *Writer) Tip(log string) commit.LogTip { return w.tips[log] }

// LastCommitSeq returns the highest commit_seq.
func (w *Writer) LastCommitSeq() uint64 {
	if len(w.committed) == 0 {
		return 0
	}
	return w.committed[len(w.committed)-1].CommitSeq
}

// Close releases every resource; it never commits anything. Closing twice
// is harmless.
func (w *Writer) Close() error {
	var errs []error
	if w.vw != nil {
		errs = append(errs, w.vw.Close())
		w.vw = nil
	}
	if w.stager != nil {
		errs = append(errs, w.stager.Close(), os.RemoveAll(w.spill))
		w.stager = nil
	}
	if w.codec != nil {
		w.codec.Close()
		w.codec = nil
	}
	if w.idx != nil {
		errs = append(errs, w.idx.Close())
		w.idx = nil
	}
	return errors.Join(errs...)
}

// ErrVerification wraps a batch that failed Merkle verification or the
// canary twice: an incident (spec §12, exit 5).
var ErrVerification = errors.New("batch failed verification twice")

// errRetry marks a verification or canary failure; the batch is refetched
// once. A Merkle failure carries the evidence an incident records (spec
// §12): our compact range before the batch, the root we computed at end,
// and the proof the log served.
type errRetry struct {
	err    error
	before *merkle.State
	root   [32]byte
	end    uint64
	proof  [][32]byte
}

func (e errRetry) Error() string { return e.err.Error() }
func (e errRetry) Unwrap() error { return e.err }
```

Replace `internal/ingest/batch.go` with:

```go
package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

// Batch ingests entries [first, end) of src and commits them, verified
// against the pinned head sth (spec §8.3). A failed Merkle verification or
// canary abandons the attempt and refetches the batch once; a second
// failure writes an incident and returns ErrVerification. Any other error
// abandons the batch and is returned as is (a stall, a full disk, a second
// signal). The caller resets src's chain cache after every call.
func (w *Writer) Batch(ctx context.Context, src logsource.LogSource, sth logsource.SignedHead, first, end uint64) (commit.Manifest, error) {
	if w.broken != nil {
		return commit.Manifest{}, w.broken
	}
	m, err := w.attempt(ctx, src, sth, first, end)
	var firstTry, secondTry errRetry
	if !errors.As(err, &firstTry) {
		return m, err
	}
	w.logf("batch %s: %v; refetching it once", w.batchID(src, first, end), err)
	m, err = w.attempt(ctx, src, sth, first, end)
	if !errors.As(err, &secondTry) {
		return m, err
	}
	dir, ierr := w.incident(w.batchID(src, first, end), sth, firstTry, secondTry)
	if ierr != nil {
		return m, errors.Join(fmt.Errorf("%w: %v", ErrVerification, err), ierr)
	}
	return m, fmt.Errorf("%w: %v (incident written to %s)", ErrVerification, err, dir)
}

func (w *Writer) batchID(src logsource.LogSource, first, end uint64) commit.BatchID {
	return commit.BatchID{Log: src.Info().Name, First: first, Last: end - 1}
}

// batch is one attempt's in-memory state.
type batch struct {
	w       *Writer
	ctx     context.Context
	src     logsource.LogSource
	pb      *index.Batch
	before  *merkle.State // the compact range before the batch
	state   *merkle.State
	rows    []dataset.EntryRow
	chains  []dataset.ChainRow
	quar    bytes.Buffer
	counts  commit.Counts
	firstID uint64
	lastID  uint64
	samples *reservoir // vault records the canary reads back
}

type sample struct {
	sha [32]byte
	loc vault.Loc
}

// canaryReservoir is how many new vault records a batch keeps for the
// canary to choose from.
const canaryReservoir = 4096

// reservoir keeps a uniform random sample of a stream (Algorithm R), so the
// canary reads records from the whole batch, not only its start.
type reservoir struct {
	items []sample
	seen  int
	rnd   *rand.Rand
}

func newReservoir(n int, seed1, seed2 uint64) *reservoir {
	return &reservoir{items: make([]sample, 0, n), rnd: rand.New(rand.NewPCG(seed1, seed2))}
}

func (r *reservoir) add(s sample) {
	r.seen++
	if len(r.items) < cap(r.items) {
		r.items = append(r.items, s)
	} else if j := r.rnd.IntN(r.seen); j < len(r.items) {
		r.items[j] = s
	}
}

func (w *Writer) attempt(ctx context.Context, src logsource.LogSource, sth logsource.SignedHead, first, end uint64) (commit.Manifest, error) {
	id := w.batchID(src, first, end)
	tip := w.tips[id.Log]
	if first != tip.Next || end <= first || end > sth.TreeSize {
		return commit.Manifest{}, fmt.Errorf("batch %s: must start at %d and end within the signed tree of %d", id, tip.Next, sth.TreeSize)
	}
	state := merkle.NewState()
	if tip.State != nil {
		state = tip.State.Clone()
	}
	// P0: volume checks, the disk-guard peak preflight, then dictionary
	// training, which may take minutes and so runs only for a batch that
	// can start. A cache left cold by a stopped attempt is warmed first.
	if w.cold {
		if err := w.warm(); err != nil {
			return commit.Manifest{}, err
		}
		w.cold = false
	}
	if w.o.CheckVolumes != nil {
		if err := w.o.CheckVolumes(); err != nil {
			return commit.Manifest{}, err
		}
	}
	dir, err := w.preflight(end - first)
	if err != nil {
		return commit.Manifest{}, err
	}
	dict, err := w.maybeTrain(ctx)
	if err != nil {
		return commit.Manifest{}, err
	}
	w.vw.Prefer(dir)
	// P1
	in := commit.Intent{BatchID: id.String(), Log: id.Log, First: id.First, Last: id.Last, STH: toSTH(sth),
		VaultTail: w.vw.Tail(), NextCertID: w.ids.Peek(), MerkleBefore: state.Clone(), Builders: map[string]int{},
		StartedAt: w.o.Now().UTC()}
	if err := commit.WriteIntent(w.paths, in, w.o.Hook); err != nil {
		return commit.Manifest{}, err
	}
	b := &batch{w: w, ctx: ctx, src: src, pb: w.idx.NewBatch(), state: state, before: in.MerkleBefore,
		samples: newReservoir(canaryReservoir, first, end)}
	defer b.pb.Close()
	m, err := w.run(b, in, sth, dict)
	var after errCommitted
	if err != nil && !errors.As(err, &after) {
		if aerr := w.abandon(ctx, in); aerr != nil {
			w.broken = fmt.Errorf("%w: %s: %v", ErrAbandonFailed, id, aerr)
			return m, errors.Join(err, w.broken)
		}
	}
	return m, err
}

// ErrAbandonFailed means an attempt could not be cleaned up in process: the
// vault could not be cut back, or its intent could not be marked. The
// writer then refuses every further batch, and the next start recovers
// (spec §8.5).
var ErrAbandonFailed = errors.New("abandoning the batch failed; run update again to recover")

// run is P2-P10 of one attempt.
func (w *Writer) run(b *batch, in commit.Intent, sth logsource.SignedHead, dict commit.DictInfo) (commit.Manifest, error) {
	id := in.ID()
	// P2
	if _, err := fetch.Run(b.ctx, b.src, id.First, id.Last+1, w.o.Fetch, b.add); err != nil {
		return commit.Manifest{}, err
	}
	// P3
	if err := w.vw.Sync(); err != nil {
		return commit.Manifest{}, err
	}
	w.hook(HookAfterVaultSync)
	// P4
	verified, err := w.verify(b, sth, id.Last+1)
	if err != nil {
		return commit.Manifest{}, err
	}
	// P5
	stage := w.paths.StageDir(id)
	files, err := w.stager.Stage(b.ctx, stage, b.rows, b.chains)
	if err != nil {
		return commit.Manifest{}, err
	}
	if b.quar.Len() > 0 {
		p := filepath.Join(stage, commit.QuarantineFile)
		if err := os.WriteFile(p, b.quar.Bytes(), 0o644); err != nil {
			return commit.Manifest{}, err
		}
		fi, err := dataset.Sum(p)
		if err != nil {
			return commit.Manifest{}, err
		}
		fi.Rows = b.counts.LeafErrors
		files[commit.QuarantineFile] = fi
	}
	if err := w.o.Guard.Check(w.o.Root, 0); err != nil { // spec §10.1: a hard check after every staged write
		return commit.Manifest{}, err
	}
	// P6
	if err := w.canary(b, stage); err != nil {
		return commit.Manifest{}, err
	}
	// P7, P8
	seq := w.LastCommitSeq() + 1
	m := commit.Manifest{Format: commit.ManifestFormat, CommitSeq: seq, BatchID: id.String(), Log: id.Log,
		First: id.First, Last: id.Last, STH: toSTH(sth), MerkleAfter: b.state, Verified: verified,
		NextCertID: w.ids.Peek(), Vault: commit.Span{Start: in.VaultTail, End: w.vw.Tail()}, Builders: map[string]int{},
		Files: files, Counts: b.counts, Dictionary: dict, CTVaultVersion: w.o.Version, CommittedAt: w.o.Now().UTC()}
	m.Counts.Entries = len(b.rows)
	if b.firstID != 0 {
		m.CertIDRange = &[2]uint64{b.firstID, b.lastID}
	}
	perr := commit.Publish(w.paths, m, w.o.Hook)
	if perr != nil && !errors.Is(perr, commit.ErrPostCommit) {
		return m, perr // the rename did not happen: abandon
	}
	// From here the batch is committed; failures below are repaired by
	// recovery at the next start, never by abandoning.
	w.committed = append(w.committed, m)
	w.tips[id.Log] = commit.LogTip{Next: id.Last + 1, State: b.state}
	if perr != nil {
		return m, errCommitted{perr}
	}
	// P9
	if err := b.pb.SetApplied(id.Log, seq); err != nil {
		return m, errCommitted{err}
	}
	w.hook(HookBeforePebble)
	if err := b.pb.Commit(); err != nil {
		return m, errCommitted{err}
	}
	w.hook(HookAfterPebble)
	// P10
	if err := commit.RemoveIntent(w.paths, id, w.o.Hook); err != nil {
		return m, errCommitted{err}
	}
	if err := commit.ClearAbandoned(w.paths); err != nil {
		return m, errCommitted{err}
	}
	if _, err := dataset.WriteViews(w.o.Root, w.active); err != nil { // the first commit changes it
		return m, errCommitted{err}
	}
	w.logf("batch %s: %d entries, %d new certificates (%d deltas), %d leaf errors, %d vault bytes, verified by %s; commit_seq %d",
		id, m.Counts.Entries, m.Counts.NewCerts, m.Counts.DeltaRecords, m.Counts.LeafErrors, m.Counts.VaultBytes, verified.Method, seq)
	return m, nil
}

// Hook points of the engine's own steps, for crash tests (spec §13.5).
const (
	HookAfterVaultSync = "commit.P3.after_vault_sync"
	HookDuringCanary   = "commit.P6.during_canary" // between the Parquet and the vault checks
	HookBeforePebble   = "commit.P9.before_pebble"
	HookAfterPebble    = "commit.P9.after_pebble"
)

func (w *Writer) hook(p string) {
	if w.o.Hook != nil {
		w.o.Hook(p)
	}
}

// errCommitted wraps a failure after the commit point: the batch is
// committed, so it must not be abandoned.
type errCommitted struct{ err error }

func (e errCommitted) Error() string { return "after commit: " + e.err.Error() }
func (e errCommitted) Unwrap() error { return e.err }

// abandon discards an attempt: vault, staging and intent go, the Pebble
// batch is discarded by the caller, cert_ids skip to the floor, and the
// delta cache forgets records that no longer exist. When ctx is done the
// process is stopping: the cache is emptied and left cold instead of
// re-reading the vault, and the next attempt warms it.
func (w *Writer) abandon(ctx context.Context, in commit.Intent) error {
	if err := w.vw.Close(); err != nil {
		return err
	}
	if err := commit.Abandon(w.paths, w.o.VaultDirs, in); err != nil {
		return err
	}
	w.ids.SkipToFloor()
	var err error
	if w.vw, err = vault.OpenWriter(w.vaultOptions(), w.codec, in.VaultTail); err != nil {
		return err
	}
	if ctx.Err() != nil {
		w.delta.Reset()
		w.cold = true
		return nil
	}
	return w.warm()
}

// add handles one entry in index order (P2).
func (b *batch) add(e logsource.RawEntry) error {
	if err := b.state.Append(e.Leaf.LeafHash); err != nil {
		return err
	}
	row := dataset.EntryRow{Idx: e.Index, CTTimestamp: e.Leaf.Timestamp, EntryType: e.Leaf.Type.String(), LeafHash: e.Leaf.LeafHash}
	if k, ok := e.Leaf.IssuanceKey(); ok {
		row.IssuanceKey, row.HasIssuanceKey = k, true
	}
	if e.Leaf.HasIssuerKeyHash {
		row.IssuerKeyHash, row.HasIssuerKeyHash = e.Leaf.IssuerKeyHash, true
	}
	if e.Leaf.Code != leaf.OK {
		row.LeafError = string(e.Leaf.Code)
		b.counts.LeafErrors++
		line, _ := json.Marshal(map[string]any{"idx": e.Index, "leaf_error": e.Leaf.Code,
			"leaf_input": base64.StdEncoding.EncodeToString(e.LeafInput), "extra_data": base64.StdEncoding.EncodeToString(e.ExtraData)})
		b.quar.Write(append(line, '\n'))
	}
	if e.Leaf.CertDER != nil {
		id, err := b.vaultLeaf(e.Leaf)
		if err != nil {
			return err
		}
		row.CertID = id
	}
	if e.Chain != nil {
		chainID, err := b.vaultChain(e.Chain)
		if err != nil {
			return err
		}
		row.ChainID, row.HasChainID = chainID, true
	}
	b.rows = append(b.rows, row)
	return nil
}

func (b *batch) assign() (uint64, error) {
	id, err := b.w.ids.Next()
	if err != nil {
		return 0, err
	}
	if b.firstID == 0 {
		b.firstID = id
	}
	b.lastID = id
	return id, nil
}

func (b *batch) vaulted(sha [32]byte, ref index.Ref) error {
	b.counts.NewCerts++
	b.counts.VaultBytes += uint64(ref.Loc.Len)
	b.samples.add(sample{sha, ref.Loc})
	return b.pb.AddCert(sha, ref)
}

// vaultLeaf stores a leaf certificate unless it is already vaulted. A final
// certificate whose precert is cached becomes a leaf-delta record.
func (b *batch) vaultLeaf(l leaf.Entry) (uint64, error) {
	sha := sha256.Sum256(l.CertDER)
	if ref, ok, err := b.pb.Lookup(sha); err != nil || ok {
		return ref.CertID, err
	}
	id, err := b.assign()
	if err != nil {
		return 0, err
	}
	var loc vault.Loc
	if base, ok := b.w.delta.Get(l.IssuanceDigest); ok && l.Type == leaf.TypeX509 && l.HasIssuanceDigest {
		if loc, err = b.w.vw.AppendDelta(id, l.CertDER, base); err != nil {
			return 0, err
		}
		b.counts.DeltaRecords++
	} else if loc, err = b.w.vw.AppendCert(vault.KindLeaf, id, l.CertDER, b.w.dictID); err != nil {
		return 0, err
	}
	if l.Type == leaf.TypePrecert && l.HasIssuanceDigest {
		b.w.delta.Put(l.IssuanceDigest, loc)
	}
	return id, b.vaulted(sha, index.Ref{CertID: id, Loc: loc})
}

// vaultChain stores unseen chain certificates and returns the chain_id,
// adding chains.parquet rows the first time a chain is seen.
func (b *batch) vaultChain(fps [][32]byte) ([32]byte, error) {
	ids := make([]uint64, len(fps))
	h := sha256.New()
	for i, fp := range fps {
		h.Write(fp[:])
		ref, ok, err := b.pb.Lookup(fp)
		if err != nil {
			return [32]byte{}, err
		}
		if ok {
			ids[i] = ref.CertID
			continue
		}
		der, err := b.src.Issuer(b.ctx, fp)
		if err != nil {
			return [32]byte{}, err
		}
		if sha256.Sum256(der) != fp {
			return [32]byte{}, fmt.Errorf("chain certificate %x does not match its fingerprint", fp[:8])
		}
		if ids[i], err = b.assign(); err != nil {
			return [32]byte{}, err
		}
		loc, err := b.w.vw.AppendCert(vault.KindChain, ids[i], der, b.w.dictID)
		if err != nil {
			return [32]byte{}, err
		}
		if err := b.vaulted(fp, index.Ref{CertID: ids[i], Loc: loc}); err != nil {
			return [32]byte{}, err
		}
	}
	var chainID [32]byte
	copy(chainID[:], h.Sum(nil))
	seen, err := b.pb.HasChain(chainID)
	if err != nil || seen {
		return chainID, err
	}
	for i, id := range ids {
		b.chains = append(b.chains, dataset.ChainRow{ChainID: chainID, Position: uint16(i), CertID: id})
	}
	return chainID, b.pb.AddChain(chainID)
}

// verify is P4 (spec §5.5): the computed root at end must equal the signed
// root, or be proven a prefix of it.
func (w *Writer) verify(b *batch, sth logsource.SignedHead, end uint64) (commit.Verified, error) {
	root, err := b.state.Root()
	if err != nil {
		return commit.Verified{}, err
	}
	if end == sth.TreeSize {
		if root != sth.RootHash {
			return commit.Verified{}, errRetry{err: errors.New("the computed root differs from the signed root"),
				before: b.before, root: root, end: end}
		}
		return commit.Verified{Method: "root_equals_sth"}, nil
	}
	var proof [][32]byte
	if err := fetch.Retry(b.ctx, w.o.Fetch, func(ctx context.Context) (err error) {
		proof, err = b.src.ConsistencyProof(ctx, end, sth.TreeSize)
		return err
	}); err != nil {
		return commit.Verified{}, err
	}
	if err := merkle.VerifyConsistency(end, sth.TreeSize, root, sth.RootHash, proof); err != nil {
		return commit.Verified{}, errRetry{err: err, before: b.before, root: root, end: end, proof: proof}
	}
	return commit.Verified{Method: "consistency_proof", ProofNodes: len(proof)}, nil
}

// canary is P6: the staged files, and vault reads of sampled new records.
func (w *Writer) canary(b *batch, stage string) error {
	rnd := rand.New(rand.NewPCG(b.rows[0].Idx, uint64(len(b.rows))))
	if err := w.stager.Canary(b.ctx, stage, b.rows, b.chains, w.o.CanarySamples, rnd); err != nil {
		return errRetry{err: err}
	}
	w.hook(HookDuringCanary)
	r, err := vault.OpenReader(w.o.VaultDirs, w.codec)
	if err != nil {
		return err
	}
	defer r.Close()
	for range min(w.o.CanarySamples, len(b.samples.items)) {
		s := b.samples.items[rnd.IntN(len(b.samples.items))]
		if _, err := r.ReadVerified(s.loc, s.sha); err != nil {
			return errRetry{err: err}
		}
	}
	return nil
}

// maybeTrain trains dictionary 1 once the committed vault holds
// DictSamples leaf certificates; a training failure is recorded and
// ingestion goes on with dictionary 0 (amendment A1 §5). It is tried once
// per process. Vault corruption met while reading the samples is returned:
// corruption is never ignored (spec §12). Training takes minutes, so a
// cancelled ctx returns at once; the abandoned training finishes in the
// background and is discarded, and a later run trains again.
func (w *Writer) maybeTrain(ctx context.Context) (commit.DictInfo, error) {
	if w.dictID != 0 || w.trainTried {
		return commit.DictInfo{ID: w.dictID}, nil
	}
	samples, tr, err := vault.TrainingSet(w.o.VaultDirs, w.codec, w.vw.Tail(), w.o.DictSamples)
	if err != nil {
		return commit.DictInfo{}, fmt.Errorf("reading dictionary training samples: %w", err)
	}
	if len(samples) < w.o.DictSamples {
		return commit.DictInfo{ID: 0}, nil
	}
	w.trainTried = true
	w.logf("training dictionary 1 on %d leaf certificates", len(samples))
	type trained struct {
		content []byte
		err     error
	}
	done := make(chan trained, 1)
	go func() {
		c, err := w.o.Train(samples, 1)
		done <- trained{c, err}
	}()
	var res trained
	select {
	case res = <-done:
	case <-ctx.Done():
		w.trainTried = false
		return commit.DictInfo{}, ctx.Err()
	}
	content, err := res.content, res.err
	if err == nil {
		var d vault.Dict
		if d, err = vault.InstallDict(w.o.VaultDirs, 1, content, tr, w.o.Now()); err == nil {
			err = w.codec.AddDict(1, d.Content)
		}
	}
	if err != nil {
		w.logf("dictionary training failed; continuing without a dictionary: %v", err)
		return commit.DictInfo{ID: 0, TrainingError: err.Error()}, nil
	}
	w.dictID = 1
	return commit.DictInfo{ID: 1}, nil
}

// preflight is the spec §10.1 peak check before a batch starts. It returns
// the vault directory whose filesystem holds the vault peak; the batch's new
// segments go there.
func (w *Writer) preflight(n uint64) (string, error) {
	var vaultHist, parquetHist []float64
	for i := max(0, len(w.committed)-diskguard.MinHistory); i < len(w.committed); i++ {
		m := w.committed[i]
		if m.Counts.Entries == 0 {
			continue
		}
		var pq int64
		for _, f := range m.Files {
			pq += f.Bytes
		}
		vaultHist = append(vaultHist, float64(m.Counts.VaultBytes)/float64(m.Counts.Entries))
		parquetHist = append(parquetHist, float64(pq)/float64(m.Counts.Entries))
	}
	cfg := w.o.Config
	peak := diskguard.EstimatePeak(diskguard.PeakInput{Entries: n,
		VaultP95: diskguard.P95(vaultHist, diskguard.SeedVaultBytesPerEntry), ParquetP95: diskguard.P95(parquetHist, diskguard.SeedParquetBytesPerEntry),
		PebbleP95: diskguard.SeedPebbleBytesPerEntry, Safety: cfg.Disk.SafetyFactor,
		PebbleSize: dirSize(filepath.Join(w.o.Root, "state", "pebble")), DuckDBSpill: w.spillLimit()})
	var err error
	for _, d := range w.o.VaultDirs {
		if err = w.o.Guard.Preflight([]diskguard.Target{{Path: w.o.Root, Need: peak.Root}, {Path: d, Need: peak.Vault}}); err == nil {
			return d, nil
		}
	}
	return "", err
}

func dirSize(dir string) uint64 {
	var n uint64
	filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				n += uint64(fi.Size())
			}
		}
		return nil
	})
	return n
}

func toSTH(h logsource.SignedHead) commit.STH {
	return commit.STH{TreeSize: h.TreeSize, Timestamp: h.Timestamp, RootHash: hex.EncodeToString(h.RootHash[:]),
		Signature: base64.StdEncoding.EncodeToString(h.Signature)}
}

// incident writes the evidence of a batch that failed verification twice
// (spec §12): the pinned head as received, both attempts' causes, and for a
// Merkle failure our compact range before the batch, the root we computed
// and the proof the log served. The fetched data itself is truncated.
func (w *Writer) incident(id commit.BatchID, sth logsource.SignedHead, first, second errRetry) (string, error) {
	dir := filepath.Join(w.o.Root, "state", "incidents", w.o.Now().UTC().Format("20060102T150405Z")+"_"+id.Log+"_"+fmt.Sprint(id.First))
	if err := fsutil.MkdirAllSync(dir, 0o755); err != nil {
		return "", err
	}
	ev := map[string]any{"batch_id": id.String(), "causes": []string{first.Error(), second.Error()}, "sth": toSTH(sth),
		"sth_raw": base64.StdEncoding.EncodeToString(sth.Raw), "time": w.o.Now().UTC().Format(time.RFC3339)}
	if second.before != nil {
		proof := make([]string, len(second.proof))
		for i, n := range second.proof {
			proof[i] = hex.EncodeToString(n[:])
		}
		ev["merkle_before"], ev["computed_root"], ev["end"], ev["proof"] = second.before, hex.EncodeToString(second.root[:]), second.end, proof
	}
	b, err := json.MarshalIndent(ev, "", " ")
	if err != nil {
		return dir, err
	}
	return dir, fsutil.WriteFileAtomic(filepath.Join(dir, "incident.json"), b, 0o644)
}
```

Replace `internal/cli/vaultcmds.go` with:

```go
package cli

import (
	"fmt"
	"github.com/4rji/ctvault/internal/derive"

	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/volume"
)

// writeConfig writes a new vault's ctvault.toml; the dev build replaces it
// to use 10,000-entry batches (amendment A1 §2.5).
var writeConfig = config.WriteDefault

func newInitCmd(a *app) *cobra.Command {
	var allowUntested bool
	cmd := &cobra.Command{
		Use:   "init <root>",
		Short: "Create a vault on a dedicated, mounted ext4 volume",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(c *cobra.Command, args []string) error {
			id, err := a.d.Volumes.Init(args[0], volume.InitOptions{AllowUntestedFS: allowUntested})
			if err != nil {
				return volumeErr(err)
			}
			if err := writeConfig(args[0]); err != nil {
				return err
			}
			if err := derive.WriteActive(args[0], derive.Complete()); err != nil {
				return err
			}
			r := id.Volumes[0]
			fmt.Fprintf(c.OutOrStdout(), "Initialized CTVault %s at %s (%s, filesystem %s, durability %s)\n",
				id.VaultUUID, r.Path, r.FSType, r.FSUUID, id.Durability)
			fmt.Fprintf(c.OutOrStdout(), "Next: ctvault --root %s logs add argon2027h1\n", r.Path)
			return nil
		},
	}
	cmd.Flags().BoolVar(&allowUntested, "allow-untested-fs", false, "accept xfs, btrfs or f2fs with weaker durability guarantees")
	return cmd
}

func newVaultCmd(a *app) *cobra.Command {
	var allowUntested bool
	addDir := &cobra.Command{
		Use:   "add-dir <path>",
		Short: "Add a vault directory on another disk",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(c *cobra.Command, args []string) error {
			root, _, err := a.openVault(c)
			if err != nil {
				return err
			}
			lk, err := a.writerLock(root)
			if err != nil {
				return err
			}
			defer lk.Release()
			id, err := a.d.Volumes.AddDir(root, args[0], volume.InitOptions{AllowUntestedFS: allowUntested})
			if err != nil {
				return volumeErr(err)
			}
			v := id.Volumes[len(id.Volumes)-1]
			fmt.Fprintf(c.OutOrStdout(), "Added vault dir %s (%s, filesystem %s)\n", v.Path, v.FSType, v.FSUUID)
			return nil
		},
	}
	addDir.Flags().BoolVar(&allowUntested, "allow-untested-fs", false, "accept xfs, btrfs or f2fs with weaker durability guarantees")
	return groupCmd("vault", "Manage vault volumes", addDir)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race -count=1 ./internal/derive/ ./internal/dataset/ ./internal/ingest/ ./internal/cli/`
Expected: PASS.

- [ ] **Step 5: Quality gate**

- [ ] **Step 6: Checkpoint.**

---

### Task B3: Staging the derived files and their canary

Spec §7.2, amendment A2 §4.3–§4.5.

**Files:**
- Create: `internal/dataset/derived.go`
- Modify: `internal/dataset/stage.go` (one DuckDB thread by default; insertion order preserved)
- Test: `internal/dataset/derived_test.go`

**Interfaces:**
- Consumes: `derive.Table`, `derive.Row`, `derive.Builders`, `(Table).KV()`, `(Table).File()` (Task B1); `dataset.WriteViews` (Task B2).
- Produces:
  - `(*Stager).BeginDerived(ctx, tables []derive.Table, keep int, rnd *rand.Rand) (*DerivedStage, error)`: an empty staging table per table, on its own connection; each table keeps a uniform sample of `keep` rows;
  - `(*DerivedStage).Add(i int, rows []derive.Row) error`: appends to table `i` (the index in `tables`);
  - `(*DerivedStage).Write(ctx, dir string) (map[string]FileInfo, error)`: P5, files synced, staging tables dropped;
  - `(*DerivedStage).Canary(ctx, dir string) error`: P6, failing with `ErrCanary`;
  - `(*DerivedStage).Close() error`: drops what `Write` did not and releases the connection;
  - `dataset.Options.Threads`: 0 now means one thread.

- [ ] **Step 1: Write the failing tests**

Create `internal/dataset/derived_test.go`:

```go
package dataset

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/klauspost/compress/zstd"

	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/extract"
	"github.com/4rji/ctvault/internal/vault"
)

// corpus returns the first n real certificates of the extractor's corpus.
func corpus(t *testing.T, n int) [][]byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "extract", "testdata", "corpus.bin.zst"))
	if err != nil {
		t.Fatal(err)
	}
	dec, _ := zstd.NewReader(nil)
	defer dec.Close()
	raw, _ := dec.DecodeAll(b, nil)
	var out [][]byte
	for len(out) < n && len(raw) > 0 {
		l, k := binary.Uvarint(raw)
		out = append(out, raw[k:k+int(l)])
		raw = raw[k+int(l):]
	}
	return out
}

func tables() []derive.Table {
	var out []derive.Table
	for _, bl := range derive.Builders {
		out = append(out, bl.Table())
	}
	return out
}

// stageDerived adds every builder's rows for ders, with cert_ids 1..n, to
// a new DerivedStage that samples keep rows per table, and writes the files
// into dir.
func stageDerived(t *testing.T, s *Stager, dir string, ders [][]byte, keep int) (*DerivedStage, map[string]FileInfo) {
	t.Helper()
	d, err := s.BeginDerived(ctx, tables(), keep, rand.New(rand.NewPCG(3, 4)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	for i, der := range ders {
		c := extract.Parse(der)
		cx := derive.Context{CertID: uint64(i + 1), SHA256: sha256.Sum256(der), Kind: derive.KindFinal,
			Loc: vault.Loc{Segment: 1, Offset: uint64(64 + 1000*i), Len: 900}}
		for j, bl := range derive.Builders {
			if err := d.Add(j, bl.Build(c, cx)); err != nil {
				t.Fatal(err)
			}
		}
	}
	files, err := d.Write(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	return d, files
}

func singleThreaded(t *testing.T) *Stager {
	t.Helper()
	s, err := NewStager(Options{TempDir: filepath.Join(t.TempDir(), "duckdb-1"), MaxTempBytes: 1 << 30})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestStageDerived: the derived files carry their schema, KV metadata and
// bloom filters, pass the canary, and are byte-identical when staged again
// by another session (spec §7.2).
func TestStageDerived(t *testing.T) {
	ders := corpus(t, 400)
	s := singleThreaded(t)
	dir := filepath.Join(t.TempDir(), "b")
	d, files := stageDerived(t, s, dir, ders, 16)
	if fi := files[derive.CertsV1.File()]; fi.Rows != 400 || fi.Bytes == 0 {
		t.Fatalf("certs: %+v for 400 certificates", fi)
	}
	if fi := files[derive.NamesV1.File()]; fi.Rows < 400 || fi.Bytes == 0 {
		t.Fatalf("names: %+v for 400 certificates", fi)
	}
	if err := d.Canary(ctx, dir); err != nil {
		t.Fatal(err)
	}
	// The files keep the order the rows were added in (amendment A2 §4.3).
	var want []string
	for i, der := range ders {
		for _, r := range (derive.Names{}).Build(extract.Parse(der), derive.Context{CertID: uint64(i + 1)}) {
			want = append(want, fmt.Sprint(r[0], " ", r[2]))
		}
	}
	rs, err := s.db.Query(`SELECT cert_id, name FROM read_parquet(` + quote(filepath.Join(dir, derive.NamesV1.File())) + `, file_row_number = true) ORDER BY file_row_number`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rs.Next() {
		var id uint64
		var name string
		rs.Scan(&id, &name)
		got = append(got, fmt.Sprint(id, " ", name))
	}
	rs.Close()
	if !slices.Equal(got, want) {
		t.Fatalf("names rows are not in the order they were added: %d rows, first %v, want %d rows, first %v", len(got), got[:min(3, len(got))], len(want), want[:3])
	}
	var kv string
	s.db.QueryRow(`SELECT string_agg(decode(key) || '=' || decode(value), ',' ORDER BY key) FROM parquet_kv_metadata(` +
		quote(filepath.Join(dir, derive.CertsV1.File())) + `)`).Scan(&kv)
	if kv != "ctvault.extractor="+derive.ExtractorVersion+",ctvault.psl=,ctvault.schema_sha256="+derive.CertsV1.SchemaSHA256()+",ctvault.table=certs,ctvault.version=1" {
		t.Errorf("certs KV metadata: %s", kv)
	}

	again := filepath.Join(t.TempDir(), "b")
	stageDerived(t, singleThreaded(t), again, ders, 16)
	for _, tb := range tables() {
		a, _ := os.ReadFile(filepath.Join(dir, tb.File()))
		b, _ := os.ReadFile(filepath.Join(again, tb.File()))
		if !bytes.Equal(a, b) {
			t.Errorf("%s is not byte-identical when staged again", tb.File())
		}
	}
}

// TestDerivedSample: each table keeps a uniform sample of its rows for the
// canary: all of them when there are fewer, otherwise keep distinct rows
// drawn from the whole batch, not just its first rows.
func TestDerivedSample(t *testing.T) {
	ders := corpus(t, 200)
	s := singleThreaded(t)
	d, _ := stageDerived(t, s, filepath.Join(t.TempDir(), "all"), ders, 500)
	if got := len(d.tables[0].sample); got != 200 {
		t.Fatalf("keeping 500 of 200 rows kept %d", got)
	}
	d, _ = stageDerived(t, s, filepath.Join(t.TempDir(), "some"), ders, 20)
	seen, late := map[uint64]bool{}, 0
	for _, r := range d.tables[0].sample {
		id := r[0].(uint64)
		if seen[id] {
			t.Fatalf("cert_id %d sampled twice", id)
		}
		seen[id] = true
		if id > 20 {
			late++
		}
	}
	if len(seen) != 20 || late == 0 {
		t.Fatalf("kept %d rows, %d beyond the first 20", len(seen), late)
	}
}

// TestDerivedCanaryCatchesBadFiles: a row that reads back differently, or a
// file without its bloom filters, fails the canary.
func TestDerivedCanaryCatchesBadFiles(t *testing.T) {
	s := singleThreaded(t)
	dir := filepath.Join(t.TempDir(), "b")
	d, _ := stageDerived(t, s, dir, corpus(t, 50), 50)
	certs := d.tables[0]
	good := certs.sample[7]
	row := append(derive.Row(nil), good...)
	row[1] = "00" + row[1].(string)[2:] // another sha256 for this cert_id
	certs.sample[7] = row
	if err := d.Canary(ctx, dir); !errors.Is(err, ErrCanary) {
		t.Fatalf("a certs row that reads back differently: %v", err)
	}
	certs.sample[7] = good
	p := filepath.Join(dir, derive.CertsV1.File())
	if _, err := s.db.Exec(`COPY (SELECT * FROM read_parquet(` + quote(p) + `)) TO ` + quote(p+".nobloom") +
		` (FORMAT parquet, WRITE_BLOOM_FILTER false)`); err != nil {
		t.Fatal(err)
	}
	os.Rename(p+".nobloom", p)
	if err := d.Canary(ctx, dir); !errors.Is(err, ErrCanary) {
		t.Fatalf("certs without bloom filters: %v", err)
	}
}

// TestDerivedStageClose: closing a stage that never wrote (a failed batch
// attempt) drops its staging tables, and the next stage starts empty.
func TestDerivedStageClose(t *testing.T) {
	s := singleThreaded(t)
	d, err := s.BeginDerived(ctx, tables(), 4, rand.New(rand.NewPCG(1, 2)))
	if err != nil {
		t.Fatal(err)
	}
	der := corpus(t, 1)[0]
	if err := d.Add(0, derive.Certs{}.Build(extract.Parse(der), derive.Context{CertID: 1, SHA256: sha256.Sum256(der), Kind: derive.KindFinal})); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM duckdb_tables() WHERE table_name LIKE '%_stage'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d staging tables left after Close (%v)", n, err)
	}
	dir := filepath.Join(t.TempDir(), "b")
	_, files := stageDerived(t, s, dir, nil, 4)
	if fi := files[derive.CertsV1.File()]; fi.Rows != 0 {
		t.Fatalf("the next stage starts with %d rows", fi.Rows)
	}
}

// TestDerivedViewsOverStagedFiles: once a batch holds derived files, the
// views read them with the same columns as the empty views, and the joins
// on certs work.
func TestDerivedViewsOverStagedFiles(t *testing.T) {
	root := t.TempDir()
	if _, err := WriteViews(root, derive.Complete()); err != nil {
		t.Fatal(err)
	}
	empty := stager(t)
	loadViews(t, empty, root)

	s := singleThreaded(t)
	dir := filepath.Join(root, "dataset", "log=argon2027h1", "batch=000000001000-000000001039")
	es, cs := rows(40)
	if _, err := s.Stage(ctx, dir, es, cs); err != nil {
		t.Fatal(err)
	}
	stageDerived(t, s, dir, corpus(t, 40), 8)
	os.WriteFile(filepath.Join(dir, "_COMMIT.json"), []byte(`{"format":1,"commit_seq":1}`), 0o644)
	if _, err := WriteViews(root, derive.Complete()); err != nil {
		t.Fatal(err)
	}
	full := stager(t)
	loadViews(t, full, root)
	for _, v := range []string{"certs", "names", "entry_certs", "logging_delay"} {
		if got, want := describe(t, full, v), describe(t, empty, v); got != want {
			t.Errorf("%s over files: %s\nempty: %s", v, got, want)
		}
	}
	var certs, joined int
	full.db.QueryRow(`SELECT (SELECT count(*) FROM certs), (SELECT count(*) FROM entry_certs)`).Scan(&certs, &joined)
	if certs != 40 || joined != 30 {
		t.Errorf("certs %d rows, entry_certs %d rows (want 40, 30)", certs, joined)
	}
}

// TestStageDerivedEmpty: a batch that vaults no new certificate still writes
// both files, with their schema and no rows, and they pass the canary.
func TestStageDerivedEmpty(t *testing.T) {
	s := singleThreaded(t)
	dir := filepath.Join(t.TempDir(), "b")
	d, files := stageDerived(t, s, dir, nil, 16)
	for _, tb := range tables() {
		if fi := files[tb.File()]; fi.Rows != 0 || fi.Bytes == 0 {
			t.Fatalf("%s: %+v for no rows", tb.File(), fi)
		}
	}
	if err := d.Canary(ctx, dir); err != nil {
		t.Fatal(err)
	}
}

// TestStageDerivedOddNames: a name holding invalid UTF-8, a NUL, a quote and
// a backslash reaches the files as the extractor renders it (valid UTF-8,
// with \XX escapes) and reads back unchanged, so no certificate can make a
// batch fail to stage.
func TestStageDerivedOddNames(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cn := asn1.RawValue{Tag: asn1.TagUTF8String, Bytes: []byte("a\xff\x00b'\\c")}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), NotBefore: time.Unix(1.7e9, 0), NotAfter: time.Unix(1.8e9, 0),
		Subject: pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: cn}}}}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	s := singleThreaded(t)
	dir := filepath.Join(t.TempDir(), "b")
	d, _ := stageDerived(t, s, dir, [][]byte{der}, 16)
	if err := d.Canary(ctx, dir); err != nil {
		t.Fatal(err)
	}
	certRow, nameRow := d.tables[0].sample[0], d.tables[1].sample[0]
	subject, ok := certRow[23].(string) // subject_cn
	if !ok || !utf8.ValidString(subject) || strings.ContainsRune(subject, 0) {
		t.Fatalf("subject_cn %q is not valid UTF-8 without NUL", subject)
	}
	var gotCN, gotDN, gotName string
	if err := s.db.QueryRow(`SELECT subject_cn, issuer_dn FROM read_parquet(`+quote(filepath.Join(dir, derive.CertsV1.File()))+`)`).Scan(&gotCN, &gotDN); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT name FROM read_parquet(` + quote(filepath.Join(dir, derive.NamesV1.File())) + `)`).Scan(&gotName); err != nil {
		t.Fatal(err)
	}
	if gotCN != subject || gotDN != certRow[11] || gotName != nameRow[2] {
		t.Fatalf("read back subject_cn %q, issuer_dn %q, name %q; staged %q, %q, %q", gotCN, gotDN, gotName, subject, certRow[11], nameRow[2])
	}
	t.Logf("subject_cn %q, issuer_dn %q, parse_errors %v", subject, gotDN, certRow[9])
}

// TestDerivedStageHoldsNoRows: adding a batch's rows does not keep them in
// Go memory, only the canary's sample: at the default batch size (500,000
// entries) collected rows would take gigabytes. Collecting them measured
// about 1,700 bytes of live heap per certificate; streaming keeps well
// under 200.
func TestDerivedStageHoldsNoRows(t *testing.T) {
	ders := corpus(t, 3000)
	s := singleThreaded(t)
	d, err := s.BeginDerived(ctx, tables(), 64, rand.New(rand.NewPCG(1, 2)))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	const n = 20000
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := range n {
		der := ders[i%len(ders)]
		cx := derive.Context{CertID: uint64(i + 1), SHA256: sha256.Sum256(der), Kind: derive.KindFinal}
		c := extract.Parse(der)
		for j, bl := range derive.Builders {
			if err := d.Add(j, bl.Build(c, cx)); err != nil {
				t.Fatal(err)
			}
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if per := (int64(after.HeapAlloc) - int64(before.HeapAlloc)) / n; per > 200 {
		t.Fatalf("adding rows keeps %d bytes of Go heap per certificate", per)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/dataset/`
Expected: FAIL with `undefined: DerivedStage` and `s.BeginDerived undefined (type *Stager has no field or method BeginDerived)` in `internal/dataset`.

- [ ] **Step 3: Implement**

Create `internal/dataset/derived.go`:

```go
package dataset

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"strings"

	duckdb "github.com/duckdb/duckdb-go/v2"

	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/fsutil"
)

// DerivedStage stages one batch's derived tables (amendment A2 §4.3-4.5).
// The batch adds each new certificate's rows as it vaults it (P2), and they
// go straight into DuckDB: collecting them in Go first measured about 4 KB
// of heap per certificate (400 MiB for a batch of 100,000 real entries).
// Each table keeps a uniform sample of its rows (reservoir sampling) for
// the canary. Write stages the files (P5) and Canary checks them (P6). Not
// safe for concurrent use.
type DerivedStage struct {
	s      *Stager
	conn   driver.Conn
	rnd    *rand.Rand
	keep   int
	tables []*stagedTable
}

type stagedTable struct {
	table   derive.Table
	stage   string
	app     *duckdb.Appender
	vals    []driver.Value
	rows    int
	sample  []derive.Row
	dropped bool
}

// derivedOptions are the derived files' writer settings (amendment A2
// §4.4): dictionary encoding up to the row group size, so DuckDB writes a
// bloom filter on every column (D19: these files hold no BLOB column).
const derivedOptions = `FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 122880, DICTIONARY_SIZE_LIMIT 122880`

// bloomColumns are the columns readers look up by literal value; the canary
// requires their bloom filters (amendment A2 §4.5).
var bloomColumns = map[string][]string{"certs": {"sha256"}, "names": {"name", "etld1"}}

func kvLiteral(t derive.Table) string {
	var parts []string
	for _, p := range t.KV() {
		parts = append(parts, quote(p[0])+": "+quote(p[1]))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// BeginDerived creates an empty staging table for each table, on a
// connection of its own. Each table samples keep of its rows for the
// canary, chosen with rnd.
func (s *Stager) BeginDerived(ctx context.Context, tables []derive.Table, keep int, rnd *rand.Rand) (*DerivedStage, error) {
	conn, err := s.connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	d := &DerivedStage{s: s, conn: conn, rnd: rnd, keep: keep}
	for _, t := range tables {
		st := &stagedTable{table: t, stage: t.Name + "_stage"}
		d.tables = append(d.tables, st)
		var cols []string
		for _, c := range t.Columns {
			cols = append(cols, c.Name+" "+c.Type)
		}
		if err := d.exec(ctx, fmt.Sprintf("CREATE OR REPLACE TABLE %s (%s)", st.stage, strings.Join(cols, ", "))); err != nil {
			d.Close()
			return nil, err
		}
		if st.app, err = duckdb.NewAppenderFromConn(conn, "", st.stage); err != nil {
			d.Close()
			return nil, err
		}
	}
	return d, nil
}

func (d *DerivedStage) exec(ctx context.Context, q string) error {
	_, err := d.conn.(driver.ExecerContext).ExecContext(ctx, q, nil)
	return err
}

// Add appends rows to table i, after the rows already added.
func (d *DerivedStage) Add(i int, rows []derive.Row) error {
	st := d.tables[i]
	for _, r := range rows {
		st.vals = st.vals[:0]
		for _, v := range r {
			st.vals = append(st.vals, v)
		}
		if err := st.app.AppendRow(st.vals...); err != nil {
			return fmt.Errorf("staging %s row %d: %w", st.table.Name, st.rows, err)
		}
		// Algorithm R: the k-th row (from 0) replaces a sampled row with
		// probability keep/(k+1), so every row is kept with equal chance.
		if len(st.sample) < d.keep {
			st.sample = append(st.sample, r)
		} else if j := d.rnd.IntN(st.rows + 1); j < d.keep {
			st.sample[j] = r
		}
		st.rows++
	}
	return nil
}

// Write flushes each table, writes its file into dir (P5) and syncs it, then
// drops the staging table to free its memory. The file keeps the order the
// rows were added in: the session preserves insertion order, so no sort
// (which would copy the whole table) is needed, and its single thread makes
// the files byte-identical for the same rows (spec §7.2).
func (d *DerivedStage) Write(ctx context.Context, dir string) (map[string]FileInfo, error) {
	if err := fsutil.MkdirAllSync(dir, 0o755); err != nil {
		return nil, err
	}
	out := map[string]FileInfo{}
	for _, st := range d.tables {
		err := st.app.Close() // flushes the appended rows
		st.app = nil
		if err != nil {
			return nil, fmt.Errorf("staging %s: %w", st.table.Name, err)
		}
		var names []string
		for _, c := range st.table.Columns {
			names = append(names, c.Name)
		}
		p := filepath.Join(dir, st.table.File())
		q := fmt.Sprintf("COPY (SELECT %s FROM %s) TO %s (%s, KV_METADATA %s)",
			strings.Join(names, ", "), st.stage, quote(p), derivedOptions, kvLiteral(st.table))
		if err := d.exec(ctx, q); err != nil {
			return nil, fmt.Errorf("writing %s: %w", st.table.File(), err)
		}
		if err := d.exec(ctx, "DROP TABLE "+st.stage); err != nil {
			return nil, err
		}
		st.dropped = true
		info, err := syncAndSum(p)
		if err != nil {
			return nil, err
		}
		info.Rows = st.rows
		out[st.table.File()] = info
	}
	return out, fsutil.SyncDir(dir)
}

// Canary checks the written files against what was added (amendment A2
// §4.5): exact columns and types, the KV metadata, bloom filters on the
// lookup columns wherever they hold a value, the row count, and every
// sampled row read back through literal lookups.
func (d *DerivedStage) Canary(ctx context.Context, dir string) error {
	for _, st := range d.tables {
		p := filepath.Join(dir, st.table.File())
		if err := d.s.checkSchema(ctx, p, typed(st.table)); err != nil {
			return err
		}
		if err := d.s.checkKV(ctx, p, st.table); err != nil {
			return err
		}
		if err := d.s.checkBloom(ctx, p, bloomColumns[st.table.Name]); err != nil {
			return err
		}
		var rows int
		if err := d.s.db.QueryRowContext(ctx, `SELECT count(*) FROM read_parquet(`+quote(p)+`)`).Scan(&rows); err != nil {
			return err
		}
		if rows != st.rows {
			return canaryErr("%s has %d rows, staged %d", st.table.File(), rows, st.rows)
		}
		for _, r := range st.sample {
			if err := d.s.checkDerivedRow(ctx, p, st.table, r); err != nil {
				return err
			}
		}
	}
	return nil
}

// Close drops the staging tables Write did not and releases the
// connection. A batch attempt that fails before Write ends here.
func (d *DerivedStage) Close() error {
	var errs []error
	for _, st := range d.tables {
		if st.app != nil {
			errs = append(errs, st.app.Close())
			st.app = nil
		}
		if !st.dropped {
			errs = append(errs, d.exec(context.Background(), "DROP TABLE IF EXISTS "+st.stage))
			st.dropped = true
		}
	}
	return errors.Join(append(errs, d.conn.Close())...)
}

// typed lists "name type" per column, as checkSchema compares them.
func typed(t derive.Table) []string {
	out := make([]string, len(t.Columns))
	for i, c := range t.Columns {
		out[i] = c.Name + " " + c.Type
	}
	return out
}

func (s *Stager) checkKV(ctx context.Context, path string, t derive.Table) error {
	got := map[string]string{}
	rows, err := s.db.QueryContext(ctx, `SELECT decode(key), decode(value) FROM parquet_kv_metadata(`+quote(path)+`)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return err
		}
		got[k] = v
	}
	for _, p := range t.KV() {
		if got[p[0]] != p[1] {
			return canaryErr("%s: metadata %s is %q, want %q", filepath.Base(path), p[0], got[p[0]], p[1])
		}
	}
	return rows.Err()
}

// checkBloom requires a bloom filter in every row group where a lookup
// column holds at least one value.
func (s *Stager) checkBloom(ctx context.Context, path string, cols []string) error {
	for _, c := range cols {
		var missing int
		err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM parquet_metadata(`+quote(path)+`)
			WHERE path_in_schema = ? AND coalesce(stats_null_count, 0) < num_values AND coalesce(bloom_filter_length, 0) = 0`, c).Scan(&missing)
		if err != nil {
			return err
		}
		if missing > 0 {
			return canaryErr("%s: column %s lacks its bloom filter in %d row groups", filepath.Base(path), c, missing)
		}
	}
	return nil
}

// checkDerivedRow reads one row back by literal values: a certs row by its
// sha256 (the reader's lookup), a names row by cert_id and name.
func (s *Stager) checkDerivedRow(ctx context.Context, path string, t derive.Table, r derive.Row) error {
	switch t.Name {
	case "certs":
		var id uint64
		var seg, length uint32
		var off uint64
		err := s.db.QueryRowContext(ctx, `SELECT cert_id, vault_seg, vault_off, vault_len FROM read_parquet(`+quote(path)+`) WHERE sha256 = '`+r[1].(string)+`'`).
			Scan(&id, &seg, &off, &length)
		if err == sql.ErrNoRows || err == nil && (id != r[0].(uint64) || seg != r[4].(uint32) || off != r[5].(uint64) || length != r[6].(uint32)) {
			return canaryErr("%s: sha256 %s reads back as cert_id %d at %d:%d+%d, staged %v", filepath.Base(path), r[1], id, seg, off, length, r[:7])
		}
		return err
	case "names":
		var k int
		err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM read_parquet(`+quote(path)+`) WHERE cert_id = ? AND name = ?`, r[0], r[2]).Scan(&k)
		if err == nil && k == 0 {
			return canaryErr("%s: name %q of cert_id %d does not read back", filepath.Base(path), r[2], r[0])
		}
		return err
	}
	return nil
}
```

Replace `internal/dataset/stage.go` with:

```go
// Package dataset writes the source-layer Parquet files of a batch through
// embedded DuckDB (spec §6.4-6.5, amendment A1 §6), checks them (the canary,
// spec §8.3 P6) and generates views.sql (spec §7.6).
package dataset

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	duckdb "github.com/duckdb/duckdb-go/v2"

	"github.com/4rji/ctvault/internal/fsutil"
)

// File names in a batch directory.
const (
	EntriesFile = "entries.parquet"
	ChainsFile  = "chains.parquet"
)

// EntryRow is one entries.parquet row (amendment A1 §6). Zero-valued
// optional fields are written as NULL.
type EntryRow struct {
	Idx              uint64
	CTTimestamp      uint64 // ms since the epoch; 0 = unknown (NULL)
	EntryType        string // "x509", "precert" or "unknown"
	CertID           uint64 // 0 = no certificate (NULL)
	LeafHash         [32]byte
	IssuanceKey      [16]byte
	HasIssuanceKey   bool
	IssuerKeyHash    [32]byte
	HasIssuerKeyHash bool
	ChainID          [32]byte
	HasChainID       bool
	LeafError        string // "" = NULL
}

// ChainRow is one chains.parquet row: chains first seen in the batch.
type ChainRow struct {
	ChainID  [32]byte
	Position uint16
	CertID   uint64
}

// FileInfo describes a staged file for _COMMIT.json.
type FileInfo struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Rows   int    `json:"rows"`
}

// Options configure the embedded DuckDB session.
type Options struct {
	TempDir      string // <root>/tmp/duckdb-<pid> (spec §10.1)
	MaxTempBytes uint64 // max_temp_directory_size: headroom below the cap minus 1 GiB
	Threads      int    // 0 = 1: one thread makes staged files byte-identical for the same rows (spec §7.2)
}

// Stager owns one in-memory DuckDB session. Not safe for concurrent use.
type Stager struct {
	connector *duckdb.Connector
	db        *sql.DB
}

// NewStager opens an in-memory DuckDB session with spill confined to
// o.TempDir and capped at o.MaxTempBytes.
func NewStager(o Options) (*Stager, error) {
	if err := os.MkdirAll(o.TempDir, 0o755); err != nil {
		return nil, err
	}
	settings := []string{
		fmt.Sprintf("SET temp_directory = %s", quote(o.TempDir)),
		fmt.Sprintf("SET max_temp_directory_size = '%dB'", o.MaxTempBytes),
	}
	settings = append(settings, fmt.Sprintf("SET threads = %d", max(o.Threads, 1)),
		"SET preserve_insertion_order = true") // derived files keep the order rows were added in
	c, err := duckdb.NewConnector("", func(execer driver.ExecerContext) error {
		for _, q := range settings {
			if _, err := execer.ExecContext(context.Background(), q, nil); err != nil {
				return fmt.Errorf("duckdb %q: %w", q, err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &Stager{connector: c, db: sql.OpenDB(c)}, nil
}

// Close closes the session.
func (s *Stager) Close() error {
	err := s.db.Close()
	if cerr := s.connector.Close(); err == nil {
		err = cerr
	}
	return err
}

// quote makes a SQL string literal.
func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

const entriesDDL = `CREATE OR REPLACE TABLE entries_stage (
	idx UBIGINT, ct_ts TIMESTAMP_MS, entry_type VARCHAR, cert_id UBIGINT,
	leaf_hash BLOB, issuance_key BLOB, issuer_key_hash BLOB, chain_id BLOB, leaf_error VARCHAR)`

const chainsDDL = `CREATE OR REPLACE TABLE chains_stage (chain_id BLOB, position USMALLINT, cert_id UBIGINT)`

// copyOptions writes zstd Parquet with no bloom filter on any column:
// DuckDB 1.5.6 returns wrong answers for literal lookups on bloom-filtered
// BLOB columns (spec §3.6, amendment A1 §6).
const copyOptions = `(FORMAT parquet, COMPRESSION zstd, WRITE_BLOOM_FILTER false)`

func nullable(ok bool, v any) any {
	if !ok {
		return nil
	}
	return v
}

func entryValues(r EntryRow) []driver.Value {
	var ts, cert, lerr any
	if r.CTTimestamp != 0 {
		ts = time.UnixMilli(int64(r.CTTimestamp)).UTC()
	}
	if r.CertID != 0 {
		cert = r.CertID
	}
	if r.LeafError != "" {
		lerr = r.LeafError
	}
	return []driver.Value{r.Idx, ts, r.EntryType, cert, r.LeafHash[:],
		nullable(r.HasIssuanceKey, r.IssuanceKey[:]), nullable(r.HasIssuerKeyHash, r.IssuerKeyHash[:]),
		nullable(r.HasChainID, r.ChainID[:]), lerr}
}

// load appends rows into the temp tables of one connection.
func (s *Stager) load(ctx context.Context, conn *sql.Conn, entries []EntryRow, chains []ChainRow) error {
	for _, q := range []string{entriesDDL, chainsDDL} {
		if _, err := conn.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return conn.Raw(func(dc any) error {
		ea, err := duckdb.NewAppenderFromConn(dc.(driver.Conn), "", "entries_stage")
		if err != nil {
			return err
		}
		for _, r := range entries {
			if err := ea.AppendRow(entryValues(r)...); err != nil {
				ea.Close()
				return fmt.Errorf("staging entry %d: %w", r.Idx, err)
			}
		}
		if err := ea.Close(); err != nil {
			return err
		}
		ca, err := duckdb.NewAppenderFromConn(dc.(driver.Conn), "", "chains_stage")
		if err != nil {
			return err
		}
		for _, r := range chains {
			if err := ca.AppendRow(r.ChainID[:], r.Position, r.CertID); err != nil {
				ca.Close()
				return err
			}
		}
		return ca.Close()
	})
}

// Stage writes entries.parquet and chains.parquet into dir (tmp/stage/<batch>)
// and syncs them (spec §8.3 P5). Rows are written in index order, and chains
// by chain_id then position.
func (s *Stager) Stage(ctx context.Context, dir string, entries []EntryRow, chains []ChainRow) (map[string]FileInfo, error) {
	if err := fsutil.MkdirAllSync(dir, 0o755); err != nil {
		return nil, err
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := s.load(ctx, conn, entries, chains); err != nil {
		return nil, err
	}
	out := map[string]FileInfo{}
	for _, f := range []struct {
		name, query string
		rows        int
	}{
		{EntriesFile, `SELECT * FROM entries_stage ORDER BY idx`, len(entries)},
		{ChainsFile, `SELECT * FROM chains_stage ORDER BY chain_id, position`, len(chains)},
	} {
		p := filepath.Join(dir, f.name)
		if _, err := conn.ExecContext(ctx, fmt.Sprintf("COPY (%s) TO %s %s", f.query, quote(p), copyOptions)); err != nil {
			return nil, fmt.Errorf("writing %s: %w", f.name, err)
		}
		info, err := syncAndSum(p)
		if err != nil {
			return nil, err
		}
		info.Rows = f.rows
		out[f.name] = info
	}
	if _, err := conn.ExecContext(ctx, `DROP TABLE entries_stage; DROP TABLE chains_stage`); err != nil {
		return nil, err
	}
	return out, fsutil.SyncDir(dir)
}

// syncAndSum fsyncs a file and returns its size and SHA-256.
func syncAndSum(p string) (FileInfo, error) {
	f, err := os.Open(p)
	if err != nil {
		return FileInfo{}, err
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return FileInfo{}, err
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return FileInfo{}, err
	}
	return FileInfo{SHA256: hex.EncodeToString(h.Sum(nil)), Bytes: n}, nil
}

// Sum returns a committed file's size and SHA-256, for recovery and verify.
func Sum(p string) (FileInfo, error) { return syncAndSum(p) }

// ChainIDs reads the distinct chain_id values of a committed chains.parquet
// (recovery re-applies them to the index).
func (s *Stager) ChainIDs(path string) ([][32]byte, error) {
	rows, err := s.db.Query(`SELECT DISTINCT chain_id FROM read_parquet(` + quote(path) + `)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][32]byte
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		if len(b) != 32 {
			return nil, fmt.Errorf("%s: chain_id of %d bytes", path, len(b))
		}
		out = append(out, [32]byte(b))
	}
	return out, rows.Err()
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race -count=1 ./internal/dataset/`
Expected: PASS. `TestStageDerivedOddNames` logs `subject_cn "a\\FF\\00b'\\\\c"` and `parse_errors [name_bad_string]`.

- [ ] **Step 5: Quality gate**

- [ ] **Step 6: Checkpoint.**

---

### Task B4: Derived files in every batch

Amendment A2 §4.3 and §4.5.

**Files:**
- Modify: `internal/vault/delta.go` (the cache keeps `cert_id`), `internal/ingest/batch.go` (P2, P5, P6, P7), `internal/vaulttest/vaulttest.go` (test helper: `CheckDerived`, called by `CheckRecovered`)
- Tests: `internal/vault/delta_test.go`, `internal/vault/reset_test.go`, `internal/ingest/derived_files_test.go`

**Interfaces:**
- Consumes: `derive.Builders`, `derive.Context`, the kinds (Task B1); `(*ingest.Writer).Active()` (Task B2); `BeginDerived`, `Add`, `Write`, `Canary`, `Close` (Task B3).
- Produces:
  - `(*vault.DeltaCache).Put(digest [32]byte, loc vault.Loc, certID uint64)` and `Get(digest) (vault.Loc, uint64, bool)`;
  - `_COMMIT.json` `builders: {"certs": 1, "names": 1}` and both files in `files`, for every batch whose table is active or building at version 1;
  - the batch opens its `DerivedStage` at the start of P2 (sample seed: the batch's first and last index) and closes it when the attempt ends;
  - `(vaulttest.Vault).CheckDerived(t)`: in every batch that built `certs`, each vault record has one row, in `cert_id` order, with its location, SHA-256, a kind matching the record kind, and its delta base's `cert_id`; no `names` row of another batch's certificate.

- [ ] **Step 1: Write the failing tests and the test helper**

Replace `internal/vault/delta_test.go` with:

```go
package vault

import (
	"crypto/sha256"
	"errors"
	"os"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/leaf"
)

func pairs(t *testing.T, n int) (pres, finals [][]byte) {
	t.Helper()
	g, err := ctlogtest.NewGenerator()
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		p, f, err := g.Pair("delta.example.test", uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		pres, finals = append(pres, p.CertDER), append(finals, f.CertDER)
	}
	return pres, finals
}

func TestDeltaRoundTrip(t *testing.T) {
	dirs := vaultDirs(t, 1)
	pres, finals := pairs(t, 5)
	w := openWriter(t, dirs, 1<<20, Tail{}, nil)
	var bases, deltas, fulls []Loc
	for i := range pres {
		b, _ := w.AppendCert(KindLeaf, uint64(3*i+1), pres[i], 0)
		d, err := w.AppendDelta(uint64(3*i+2), finals[i], b) // base still unsynced: same batch
		if err != nil {
			t.Fatal(err)
		}
		f, _ := w.AppendCert(KindLeaf, uint64(3*i+3), finals[i], 0)
		bases, deltas, fulls = append(bases, b), append(deltas, d), append(fulls, f)
	}
	w.Sync()
	w.Close()
	r, _ := OpenReader(dirs, codec(t))
	defer r.Close()
	saved := 0
	for i := range finals {
		got, err := r.ReadVerified(deltas[i], sha256.Sum256(finals[i]))
		if err != nil || string(got) != string(finals[i]) {
			t.Fatalf("delta %d: %v", i, err)
		}
		saved += int(fulls[i].Len) - int(deltas[i].Len)
	}
	if saved <= 0 {
		t.Fatalf("a final certificate against its own precert must be smaller than in full (saved %d bytes)", saved)
	}
}

func TestDeltaCorruption(t *testing.T) {
	dirs := vaultDirs(t, 1)
	pres, finals := pairs(t, 1)
	w := openWriter(t, dirs, 1<<20, Tail{}, nil)
	chain, _ := w.AppendCert(KindChain, 1, pres[0], 0)
	if _, err := w.AppendDelta(2, finals[0], chain); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a delta base must be a leaf record: %v", err)
	}
	base, _ := w.AppendCert(KindLeaf, 3, pres[0], 0)
	d, _ := w.AppendDelta(4, finals[0], base)
	w.Sync()
	w.Close()

	// A record claiming a base that is not a leaf, or lies ahead, is corrupt.
	segs, _ := FindSegments(dirs)
	b, _ := os.ReadFile(segs[1])
	forged := AppendRecord(nil, Record{Kind: KindDelta, CertID: 5, BaseSeg: 1, BaseOff: chain.Offset, Frame: []byte{0x28, 0xb5}})
	ahead := AppendRecord(nil, Record{Kind: KindDelta, CertID: 6, BaseSeg: 1, BaseOff: 1 << 20, Frame: []byte{0x28, 0xb5}})
	os.WriteFile(segs[1], append(append(b, forged...), ahead...), 0o644)
	r, _ := OpenReader(dirs, codec(t))
	defer r.Close()
	if _, err := r.ReadVerified(d, sha256.Sum256(finals[0])); err != nil {
		t.Fatalf("the real delta still reads: %v", err)
	}
	fl := Loc{Segment: 1, Offset: uint64(len(b)), Len: uint32(len(forged))}
	if _, _, err := r.Read(fl); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a chain record as delta base: %v", err)
	}
	al := Loc{Segment: 1, Offset: uint64(len(b) + len(forged)), Len: uint32(len(ahead))}
	if _, _, err := r.Read(al); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a base ahead of the delta: %v", err)
	}
}

func TestDeltaCache(t *testing.T) {
	c := NewDeltaCache(3)
	for i := range 4 {
		c.Put([32]byte{byte(i + 1)}, Loc{Segment: uint64(i)}, uint64(100+i))
	}
	if _, _, ok := c.Get([32]byte{1}); ok || c.Len() != 3 {
		t.Fatalf("the oldest entry is evicted at capacity: len %d", c.Len())
	}
	if l, id, ok := c.Get([32]byte{4}); !ok || l.Segment != 3 || id != 103 {
		t.Fatal("the newest entry is cached")
	}
	c.Put([32]byte{4}, Loc{Segment: 9}, 109)
	if l, id, _ := c.Get([32]byte{4}); l.Segment != 9 || id != 109 || c.Len() != 3 {
		t.Fatal("re-putting a digest updates it in place")
	}
	off := NewDeltaCache(0)
	off.Put([32]byte{1}, Loc{}, 1)
	if _, _, ok := off.Get([32]byte{1}); ok {
		t.Fatal("capacity 0 disables the cache")
	}
}

// TestWarmFindsPrecertsInRanges: after a restart the cache is refilled from
// the last committed batches; only precerts enter it, keyed so that their
// final certificates find them.
func TestWarmFindsPrecertsInRanges(t *testing.T) {
	dirs := vaultDirs(t, 1)
	g, _ := ctlogtest.NewGenerator()
	w := openWriter(t, dirs, 4<<10, Tail{}, nil)
	var rs []Range
	var finalDigests [][32]byte
	var preLocs []Loc
	var preIDs []uint64
	id := uint64(0)
	for batch := range 3 {
		start := w.Tail()
		for i := range 3 {
			p, f, _ := g.Pair("warm.example.test", uint64(batch*10+i))
			id++
			l, _ := w.AppendCert(KindLeaf, id, p.CertDER, 0)
			id++
			w.AppendCert(KindLeaf, id, f.CertDER, 0)
			preLocs = append(preLocs, l)
			preIDs = append(preIDs, id-1)
			finalDigests = append(finalDigests, leaf.Decode(f.LeafInput, f.ExtraData).IssuanceDigest)
		}
		rs = append(rs, Range{Start: start, End: w.Tail()})
	}
	w.Sync()
	w.Close()
	c := NewDeltaCache(100)
	if err := Warm(dirs, codec(t), c, rs[1:], leaf.PrecertIssuanceDigest); err != nil {
		t.Fatal(err)
	}
	if c.Len() != 6 {
		t.Fatalf("two batches hold 6 precerts (finals are not cached): %d", c.Len())
	}
	if _, _, ok := c.Get(finalDigests[0]); ok {
		t.Fatal("the first batch was outside the warm-up window")
	}
	if l, id, ok := c.Get(finalDigests[4]); !ok || l != preLocs[4] || id != preIDs[4] {
		t.Fatalf("final 4 must find its precert and its cert_id %d: %+v %d %v", preIDs[4], l, id, ok)
	}
}

// TestDeltaCacheNeedsTheFullDigest: two digests sharing their first 16
// bytes never return each other's precert.
func TestDeltaCacheNeedsTheFullDigest(t *testing.T) {
	c := NewDeltaCache(10)
	a, b := [32]byte{7}, [32]byte{7}
	b[31] = 1
	c.Put(a, Loc{Segment: 1}, 1)
	if _, _, ok := c.Get(b); ok {
		t.Fatal("a 16-byte prefix match is not a hit")
	}
	c.Put(b, Loc{Segment: 2}, 2)
	if l, _, ok := c.Get(b); !ok || l.Segment != 2 {
		t.Fatal("the newer of two colliding digests wins")
	}
	if _, _, ok := c.Get(a); ok {
		t.Fatal("the displaced digest misses (stored in full instead)")
	}
	for i := range 20 { // wrap the ring past the displaced slot
		c.Put([32]byte{byte(100 + i)}, Loc{Segment: uint64(i)}, uint64(i))
	}
	if c.Len() != 10 {
		t.Fatalf("len %d after wrapping, want 10", c.Len())
	}
}
```

Replace `internal/vault/reset_test.go` with:

```go
package vault

import "testing"

func TestDeltaCacheReset(t *testing.T) {
	c := NewDeltaCache(4)
	c.Put([32]byte{1}, Loc{Segment: 1}, 1)
	c.Reset()
	if _, _, ok := c.Get([32]byte{1}); ok || c.Len() != 0 {
		t.Fatal("Reset empties the cache")
	}
	for i := range 6 {
		c.Put([32]byte{byte(i + 10)}, Loc{Segment: uint64(i)}, uint64(i))
	}
	if c.Len() != 4 {
		t.Fatalf("a reset cache keeps its capacity: %d", c.Len())
	}
}
```

Replace `internal/vaulttest/vaulttest.go` with (adds `CheckDerived`; `CheckRecovered` calls it last):

```go
// Package vaulttest checks a vault the way the crash suite needs (spec
// §13.5) and compares a recovered vault with a clean one (amendment A1 §7).
// It is test infrastructure: production binaries never import it.
package vaulttest

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	_ "github.com/duckdb/duckdb-go/v2" // the "duckdb" database/sql driver

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

// Vault is a vault root and its vault directories.
type Vault struct {
	Root string
	Dirs []string
	UUID [16]byte
}

// reader opens the vault's records with every dictionary loaded.
func (v Vault) reader(t testing.TB) *vault.Reader {
	t.Helper()
	c, err := vault.NewCodec()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	ds, err := vault.LoadDicts(v.Dirs)
	if err != nil {
		t.Fatalf("dictionaries: %v", err)
	}
	for _, d := range ds {
		if err := c.AddDict(d.Manifest.ID, d.Content); err != nil {
			t.Fatal(err)
		}
	}
	r, err := vault.OpenReader(v.Dirs, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

// record is a vault record with its certificate's SHA-256.
type record struct {
	loc    vault.Loc
	certID uint64
	sha    [32]byte
	kind   byte
	base   [2]uint64 // a leaf-delta's base record: segment, offset
}

// scan reads the records in [from, to), resolving each to its SHA-256. A
// torn record ends the scan when torn is allowed.
func (v Vault) scan(t testing.TB, from, to vault.Tail, torn bool) []record {
	t.Helper()
	r := v.reader(t)
	var out []record
	err := vault.Scan(v.Dirs, from, to, func(loc vault.Loc, rec vault.Record) error {
		der, _, err := r.Read(loc)
		if err != nil {
			return err
		}
		out = append(out, record{loc, rec.CertID, sha256.Sum256(der), rec.Kind, [2]uint64{rec.BaseSeg, rec.BaseOff}})
		return nil
	})
	if err != nil && !(torn && errors.Is(err, vault.ErrTorn)) {
		t.Fatalf("reading the vault: %v", err)
	}
	return out
}

// BeyondTail returns the cert_id and SHA-256 of every record past the
// committed tail, up to a torn record: what recovery will truncate.
func (v Vault) BeyondTail(t testing.TB) map[uint64][32]byte {
	t.Helper()
	ms, err := commit.ListCommitted(v.Root)
	if err != nil {
		t.Fatal(err)
	}
	var tail vault.Tail
	if len(ms) > 0 {
		tail = ms[len(ms)-1].Vault.End
	}
	segs, err := vault.FindSegments(v.Dirs)
	if err != nil {
		t.Fatal(err)
	}
	out := map[uint64][32]byte{}
	if len(segs) == 0 {
		return out
	}
	last := slices.Max(slices.Collect(maps.Keys(segs)))
	for _, rec := range v.scan(t, tail, vault.Tail{Segment: last, Offset: math.MaxInt64}, true) {
		out[rec.certID] = rec.sha
	}
	return out
}

// Assignments returns the cert_id and SHA-256 of every record in the
// segments, beyond the committed tail too, up to a torn record. Called after
// a kill and before recovery, it sees what the killed attempt assigned.
func (v Vault) Assignments(t testing.TB) map[uint64][32]byte {
	t.Helper()
	segs, err := vault.FindSegments(v.Dirs)
	if err != nil {
		t.Fatal(err)
	}
	out := map[uint64][32]byte{}
	if len(segs) == 0 {
		return out
	}
	last := slices.Max(slices.Collect(maps.Keys(segs)))
	for _, rec := range v.scan(t, vault.Tail{}, vault.Tail{Segment: last, Offset: math.MaxInt64}, true) {
		if prev, dup := out[rec.certID]; dup && prev != rec.sha {
			t.Fatalf("cert_id %d holds two different certificates in one vault", rec.certID)
		}
		out[rec.certID] = rec.sha
	}
	return out
}

func fileSHA256(t testing.TB, p string) string {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Committed is what a reader snapshot sees: every directory under
// dataset/log=*/ must be a committed batch whose files match _COMMIT.json
// byte for byte, so no partial batch is ever visible. It returns each
// batch directory's _COMMIT.json.
func (v Vault) Committed(t testing.TB) map[string][]byte {
	t.Helper()
	ms, err := commit.ListCommitted(v.Root)
	if err != nil {
		t.Fatalf("committed batches: %v", err)
	}
	paths := commit.Paths{Root: v.Root}
	out := map[string][]byte{}
	for _, m := range ms {
		dir := paths.BatchDir(m.ID())
		for name, fi := range m.Files {
			if got := fileSHA256(t, filepath.Join(dir, name)); got != fi.SHA256 {
				t.Fatalf("%s/%s does not match its checksum", dir, name)
			}
		}
		b, err := os.ReadFile(filepath.Join(dir, commit.ManifestFile))
		if err != nil {
			t.Fatal(err)
		}
		out[dir] = b
	}
	logs, _ := filepath.Glob(filepath.Join(v.Root, "dataset", "*", "*"))
	for _, d := range logs {
		if _, ok := out[d]; !ok {
			t.Fatalf("%s is visible under dataset/ but is not a committed batch", d)
		}
	}
	return out
}

// CheckRecovered asserts spec §13.5's invariants on a vault whose writer
// has opened (recovered) and closed it:
//   - committed batches are contiguous and every file matches its checksum;
//   - the vault holds nothing beyond the committed tail, and its segments
//     are intact;
//   - every committed record has a unique cert_id and a unique certificate;
//   - Pebble agrees with the vault, and applied/<log> is each log's last
//     commit_seq;
//   - each batch's Merkle state equals a recomputation from entries.parquet;
//   - only intents marked abandoned remain, for uncommitted batches, and
//     tmp/ holds only empty stage/ and rebuild/;
//   - no interrupted atomic write left its temp file anywhere.
func (v Vault) CheckRecovered(t testing.TB) {
	t.Helper()
	v.Committed(t)
	ms, _ := commit.ListCommitted(v.Root)
	var tail vault.Tail
	if len(ms) > 0 {
		tail = ms[len(ms)-1].Vault.End
	}
	if u, err := vault.InspectTail(v.Dirs, tail); err != nil || u.Bytes != 0 {
		t.Fatalf("data beyond the committed tail after recovery: %+v, %v", u, err)
	}
	if err := vault.CheckSegments(v.Dirs, v.UUID, tail); err != nil {
		t.Fatal(err)
	}
	refs := map[[32]byte]index.Ref{}
	ids := map[uint64]bool{}
	for _, rec := range v.scan(t, vault.Tail{}, tail, false) {
		if ids[rec.certID] {
			t.Fatalf("cert_id %d is committed twice", rec.certID)
		}
		if _, dup := refs[rec.sha]; dup {
			t.Fatalf("certificate %x is vaulted twice", rec.sha[:8])
		}
		ids[rec.certID], refs[rec.sha] = true, index.Ref{CertID: rec.certID, Loc: rec.loc}
	}

	idx, err := index.Open(filepath.Join(v.Root, "state", "pebble"))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	n := 0
	err = idx.EachCert(func(sha [32]byte, r index.Ref) error {
		if want, ok := refs[sha]; !ok || want != r {
			return fmt.Errorf("pebble has %x → %+v, the vault %+v (%v)", sha[:8], r, want, ok)
		}
		n++
		return nil
	})
	if err != nil || n != len(refs) {
		t.Fatalf("pebble and the vault disagree: %v (%d index entries, %d records)", err, n, len(refs))
	}
	last := map[string]uint64{}
	for _, m := range ms {
		last[m.Log] = m.CommitSeq
	}
	if applied, err := idx.AppliedLogs(); err != nil || !maps.Equal(applied, last) {
		t.Fatalf("applied %v, want %v (%v)", applied, last, err)
	}

	db := duck(t)
	states := map[string]*merkle.State{}
	paths := commit.Paths{Root: v.Root}
	for _, m := range ms {
		st, ok := states[m.Log]
		if !ok {
			st = merkle.NewState()
			states[m.Log] = st
		}
		for i, e := range entries(t, db, filepath.Join(paths.BatchDir(m.ID()), dataset.EntriesFile)) {
			if e.idx != m.First+uint64(i) {
				t.Fatalf("batch %s: row %d has index %d", m.BatchID, i, e.idx)
			}
			st.Append(e.leafHash)
		}
		want, _ := m.MerkleAfter.Root()
		if got, _ := st.Root(); got != want || st.Size() != m.Last+1 {
			t.Fatalf("batch %s: the Merkle state recomputed from entries.parquet differs from merkle_after", m.BatchID)
		}
	}

	ins, err := commit.ReadIntents(commit.Paths{Root: v.Root})
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range ins {
		if _, err := os.Stat(filepath.Join(paths.BatchDir(in.ID()), commit.ManifestFile)); !in.Abandoned || err == nil {
			t.Fatalf("intent of %s left after recovery (abandoned=%v, committed=%v)", in.BatchID, in.Abandoned, err == nil)
		}
	}
	filepath.WalkDir(v.Root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && fsutil.IsAtomicTemp(d.Name()) {
			t.Errorf("an interrupted write's temp file survived recovery: %s", p)
		}
		return nil
	})
	var tmp []string
	filepath.WalkDir(filepath.Join(v.Root, "tmp"), func(p string, d os.DirEntry, err error) error {
		if rel, _ := filepath.Rel(v.Root, p); err == nil && rel != "tmp" {
			tmp = append(tmp, rel)
		}
		return nil
	})
	if !slices.Equal(tmp, []string{"tmp/rebuild", "tmp/stage"}) {
		t.Fatalf("tmp/ after recovery: %v", tmp)
	}
	v.CheckDerived(t)
}

func duck(t testing.TB) *sql.DB {
	t.Helper()
	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

type row struct {
	idx                uint64
	ts                 sql.Null[int64]
	typ                string
	certID             sql.Null[uint64]
	leafHash           [32]byte
	ikey, ikh, chainID []byte
	leafErr            sql.Null[string]
}

func entries(t testing.TB, db *sql.DB, path string) []row {
	t.Helper()
	rs, err := db.Query(`SELECT idx, epoch_ms(ct_ts), entry_type, cert_id, leaf_hash, issuance_key, issuer_key_hash, chain_id, leaf_error
		FROM read_parquet(` + quote(path) + `) ORDER BY idx`)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	var out []row
	for rs.Next() {
		var r row
		var lh []byte
		if err := rs.Scan(&r.idx, &r.ts, &r.typ, &r.certID, &lh, &r.ikey, &r.ikh, &r.chainID, &r.leafErr); err != nil {
			t.Fatal(err)
		}
		copy(r.leafHash[:], lh)
		out = append(out, r)
	}
	if err := rs.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// Entry is one log entry's content without internal IDs: certificates and
// chains are given by SHA-256 (hex), and NULL fields are empty.
type Entry struct {
	Idx           uint64
	LeafHash      string
	Timestamp     string // milliseconds, "" when NULL
	Type          string
	IssuanceKey   string
	IssuerKeyHash string
	LeafError     string
	Cert          string
	Chain         []string
}

// Dump returns every committed entry by log, in index order. A recovered
// ingest must equal a clean one on all of it; only cert_id and chain_id may
// differ (amendment A1 §7). Dump also checks that every reference resolves:
// each cert_id to one vault record, each chain_id to positions 0..n-1
// written by exactly one batch, and every committed record is referenced.
func (v Vault) Dump(t testing.TB) map[string][]Entry {
	t.Helper()
	ms, err := commit.ListCommitted(v.Root)
	if err != nil {
		t.Fatal(err)
	}
	var tail vault.Tail
	if len(ms) > 0 {
		tail = ms[len(ms)-1].Vault.End
	}
	certs := map[uint64]string{}
	for _, rec := range v.scan(t, vault.Tail{}, tail, false) {
		certs[rec.certID] = hex.EncodeToString(rec.sha[:])
	}
	used := map[uint64]bool{}
	cert := func(id uint64) string {
		s, ok := certs[id]
		if !ok {
			t.Fatalf("cert_id %d is referenced but not in the committed vault", id)
		}
		used[id] = true
		return s
	}

	db := duck(t)
	paths := commit.Paths{Root: v.Root}
	chains := map[string][]uint64{}
	for _, m := range ms {
		rs, err := db.Query(`SELECT chain_id, position, cert_id FROM read_parquet(` + quote(filepath.Join(paths.BatchDir(m.ID()), dataset.ChainsFile)) + `) ORDER BY chain_id, position`)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for rs.Next() {
			var id []byte
			var pos uint16
			var c uint64
			if err := rs.Scan(&id, &pos, &c); err != nil {
				t.Fatal(err)
			}
			k := string(id)
			if !seen[k] && len(chains[k]) > 0 {
				t.Fatalf("chain %x is written by two batches", id[:4])
			}
			if seen[k] = true; int(pos) != len(chains[k]) {
				t.Fatalf("chain %x: position %d out of order", id[:4], pos)
			}
			chains[k] = append(chains[k], c)
		}
		rs.Close()
	}

	out := map[string][]Entry{}
	for _, m := range ms {
		for _, r := range entries(t, db, filepath.Join(paths.BatchDir(m.ID()), dataset.EntriesFile)) {
			e := Entry{Idx: r.idx, LeafHash: hex.EncodeToString(r.leafHash[:]), Type: r.typ,
				IssuanceKey: hex.EncodeToString(r.ikey), IssuerKeyHash: hex.EncodeToString(r.ikh), LeafError: r.leafErr.V}
			if r.ts.Valid {
				e.Timestamp = fmt.Sprint(r.ts.V)
			}
			if r.certID.Valid {
				e.Cert = cert(r.certID.V)
			}
			if r.chainID != nil {
				ids, ok := chains[string(r.chainID)]
				if !ok {
					t.Fatalf("entry %d: chain %x has no chains.parquet rows", r.idx, r.chainID[:4])
				}
				e.Chain = []string{}
				for _, id := range ids {
					e.Chain = append(e.Chain, cert(id))
				}
			}
			out[m.Log] = append(out[m.Log], e)
		}
	}
	for id := range certs {
		if !used[id] {
			t.Fatalf("committed record cert_id %d is referenced by no entry or chain", id)
		}
	}
	return out
}

// Diff describes the first difference between two dumps, "" if equal.
func Diff(got, want map[string][]Entry) string {
	for _, log := range slices.Sorted(maps.Keys(want)) {
		g, w := got[log], want[log]
		for i := range min(len(g), len(w)) {
			if a, b := fmt.Sprintf("%+v", g[i]), fmt.Sprintf("%+v", w[i]); a != b {
				return fmt.Sprintf("log %s entry %d:\n got  %s\n want %s", log, w[i].Idx, a, b)
			}
		}
		if len(g) != len(w) {
			return fmt.Sprintf("log %s: %d entries, want %d", log, len(g), len(w))
		}
	}
	if len(got) != len(want) {
		return fmt.Sprintf("%d logs, want %d", len(got), len(want))
	}
	return ""
}

// CheckDerived asserts amendment A2 §4's derived files. In every committed
// batch that built certs, each vault record the batch wrote has exactly
// one certs row, in order: its cert_id, location and DER SHA-256, a kind
// that matches the record (chain; precert or final for a full leaf; final
// for a leaf-delta) and, for a leaf-delta, its base record's cert_id. Every
// names row belongs to one of the batch's certificates.
func (v Vault) CheckDerived(t testing.TB) {
	t.Helper()
	ms, err := commit.ListCommitted(v.Root)
	if err != nil || len(ms) == 0 {
		return
	}
	idAt := map[[2]uint64]uint64{}
	for _, r := range v.scan(t, vault.Tail{}, ms[len(ms)-1].Vault.End, false) {
		idAt[[2]uint64{r.loc.Segment, r.loc.Offset}] = r.certID
	}
	db := duck(t)
	paths := commit.Paths{Root: v.Root}
	for _, m := range ms {
		if m.Builders[derive.CertsV1.Name] != derive.CertsV1.Version {
			continue
		}
		dir := paths.BatchDir(m.ID())
		certs := quote(filepath.Join(dir, derive.CertsV1.File()))
		rows, err := db.Query(`SELECT cert_id, sha256, kind, vault_seg, vault_off, vault_len, coalesce(delta_base_cert_id, 0) FROM read_parquet(` + certs + `) ORDER BY cert_id`)
		if err != nil {
			t.Fatal(err)
		}
		recs := v.scan(t, m.Vault.Start, m.Vault.End, false)
		i := 0
		for ; rows.Next(); i++ {
			var id, off, base uint64
			var seg, length uint32
			var sha, kind string
			if err := rows.Scan(&id, &sha, &kind, &seg, &off, &length, &base); err != nil {
				t.Fatal(err)
			}
			if i >= len(recs) {
				t.Fatalf("batch %s: certs has more rows than the %d records it vaulted", m.BatchID, len(recs))
			}
			r := recs[i]
			wantKind := map[byte][]string{vault.KindLeaf: {"precert", "final"}, vault.KindDelta: {"final"}, vault.KindChain: {"chain"}}[r.kind]
			wantBase := uint64(0)
			if r.kind == vault.KindDelta {
				wantBase = idAt[r.base]
			}
			if id != r.certID || sha != hex.EncodeToString(r.sha[:]) || uint64(seg) != r.loc.Segment || off != r.loc.Offset ||
				length != r.loc.Len || !slices.Contains(wantKind, kind) || base != wantBase {
				t.Fatalf("batch %s: certs row %d (cert_id %d, %s at %d:%d+%d, base %d) differs from vault record %+v (base %d)",
					m.BatchID, i, id, kind, seg, off, length, base, r, wantBase)
			}
		}
		rows.Close()
		if i != len(recs) {
			t.Fatalf("batch %s: %d certs rows for %d vault records", m.BatchID, i, len(recs))
		}
		var orphans int
		names := quote(filepath.Join(dir, derive.NamesV1.File()))
		if err := db.QueryRow(`SELECT count(*) FROM read_parquet(` + names + `) WHERE cert_id NOT IN (SELECT cert_id FROM read_parquet(` + certs + `))`).Scan(&orphans); err != nil || orphans > 0 {
			t.Fatalf("batch %s: %d names rows of no certificate in the batch (%v)", m.BatchID, orphans, err)
		}
	}
}
```

Create `internal/ingest/derived_files_test.go`:

```go
package ingest

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/vaulttest"
)

// TestBatchesBuildDerivedFiles: each batch commits certs and names with the
// rest (amendment A2 §4.3), listed in _COMMIT.json, and their rows agree
// with the vault. A vault upgraded to building does the same for its new
// batches.
func TestBatchesBuildDerivedFiles(t *testing.T) {
	h := newHarness(t, entries(t, 60), ctlogtest.Options{})
	w := h.open()
	ms := h.ingest(w, h.head(), 0, 30, 30)
	w.Close()
	os.Remove(filepath.Join(h.root, "dataset", derive.ActiveFile)) // as if written before Plan 3
	w = h.open()
	ms = append(ms, h.ingest(w, h.head(), 30, 60, 30)...)
	w.Close()
	for _, m := range ms {
		certs, names := m.Files[derive.CertsV1.File()], m.Files[derive.NamesV1.File()]
		if m.Builders["certs"] != 1 || m.Builders["names"] != 1 || certs.Rows != m.Counts.NewCerts || certs.SHA256 == "" || names.SHA256 == "" {
			t.Fatalf("batch %s: builders %v, certs %+v, names %+v, %d new certificates", m.BatchID, m.Builders, certs, names, m.Counts.NewCerts)
		}
	}
	vaulttest.Vault{Root: h.root, Dirs: h.opts.VaultDirs, UUID: h.opts.VaultUUID}.CheckDerived(t)
}

// TestDerivedFilesAreByteIdentical: the same entries in the same batches
// give the same derived files in two vaults (spec §7.2).
func TestDerivedFilesAreByteIdentical(t *testing.T) {
	es := entries(t, 40)
	var sums [2][]string
	for i := range sums {
		h := newHarness(t, es, ctlogtest.Options{})
		w := h.open()
		for _, m := range h.ingest(w, h.head(), 0, 40, 20) {
			sums[i] = append(sums[i], m.Files[derive.CertsV1.File()].SHA256, m.Files[derive.NamesV1.File()].SHA256)
		}
		w.Close()
	}
	if len(sums[0]) != 4 || slices.Contains(sums[0], "") || !slices.Equal(sums[0], sums[1]) {
		t.Fatalf("checksums missing or different: %v\n%v", sums[0], sums[1])
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/vault/ ./internal/ingest/`
Expected: FAIL with `too many arguments in call to c.Put` and `assignment mismatch: 3 variables but c.Get returns 2 values` in `internal/vault`; in `internal/ingest`, `TestBatchesBuildDerivedFiles` fails with `batch fakelog/000000000000-000000000029: builders map[], certs {SHA256: Bytes:0 Rows:0}, names {SHA256: Bytes:0 Rows:0}, 31 new certificates` and `TestDerivedFilesAreByteIdentical` with `checksums missing or different: [   ]`.

- [ ] **Step 3: Implement**

Replace `internal/vault/delta.go` with:

```go
package vault

// DeltaCache maps a precert's full 32-byte issuance digest to its vault
// record and cert_id (the final certificate's certs.delta_base_cert_id),
// for recently vaulted precerts (spec §6.2, amendment A1 §5). It is
// an optimization only: an eviction or a restart simply stores the final
// certificate in full. Entries are evicted oldest first, which for
// precerts inserted once and looked up once behaves like an LRU.
//
// Layout: a ring of (full digest, location) and a map from the digest's
// first 16 bytes to a ring slot. A hit requires all 32 bytes to match. On a
// 16-byte prefix collision the newer precert wins, which only costs a
// delta. The default 2M entries take 207 MiB of heap (measured 2026-10-04;
// spec §6.2 estimated about 128 MB), against 317 MiB for a map keyed by the
// full digest. Lower ingest.delta_lru_entries on small machines.
type DeltaCache struct {
	idx  map[[16]byte]int32
	ring []cacheSlot
	next int
}

type cacheSlot struct {
	digest [32]byte
	loc    Loc
	certID uint64
	used   bool
}

// NewDeltaCache holds at most capacity entries (ingest.delta_lru_entries);
// capacity 0 disables the cache.
func NewDeltaCache(capacity int) *DeltaCache {
	return &DeltaCache{idx: make(map[[16]byte]int32, capacity), ring: make([]cacheSlot, capacity)}
}

func prefix(d [32]byte) (p [16]byte) {
	copy(p[:], d[:16])
	return p
}

// Put records a precert's location and cert_id, evicting the oldest entry
// when full.
func (c *DeltaCache) Put(digest [32]byte, loc Loc, certID uint64) {
	if len(c.ring) == 0 {
		return
	}
	k := prefix(digest)
	if i, ok := c.idx[k]; ok && c.ring[i].digest == digest {
		c.ring[i].loc, c.ring[i].certID = loc, certID
		return
	}
	slot := &c.ring[c.next]
	if slot.used {
		if old := prefix(slot.digest); c.idx[old] == int32(c.next) {
			delete(c.idx, old)
		}
	}
	*slot = cacheSlot{digest: digest, loc: loc, certID: certID, used: true}
	c.idx[k] = int32(c.next)
	c.next = (c.next + 1) % len(c.ring)
}

// Get returns the precert record and cert_id for digest.
func (c *DeltaCache) Get(digest [32]byte) (Loc, uint64, bool) {
	i, ok := c.idx[prefix(digest)]
	if !ok || c.ring[i].digest != digest {
		return Loc{}, 0, false
	}
	return c.ring[i].loc, c.ring[i].certID, true
}

// Len returns the number of cached precerts.
func (c *DeltaCache) Len() int { return len(c.idx) }

// Reset empties the cache and keeps its memory for reuse.
func (c *DeltaCache) Reset() {
	clear(c.idx)
	clear(c.ring)
	c.next = 0
}

// Range is a span of the vault, [Start, End), as recorded in _COMMIT.json.
type Range struct {
	Start, End Tail
}

// Warm refills the cache from the leaf records in ranges, normally the last
// delta.warm_batches committed batches. digest returns a precert's issuance
// digest, or false for any other certificate.
func Warm(dirs []string, codec *Codec, c *DeltaCache, ranges []Range, digest func(der []byte) ([32]byte, bool)) error {
	// Consecutive batches are contiguous in the vault: scan them as one range,
	// so a segment shared by several batches is read once.
	var merged []Range
	for _, rg := range ranges {
		if n := len(merged); n > 0 && merged[n-1].End == rg.Start {
			merged[n-1].End = rg.End
			continue
		}
		merged = append(merged, rg)
	}
	for _, rg := range merged {
		err := Scan(dirs, rg.Start, rg.End, func(loc Loc, rec Record) error {
			if rec.Kind != KindLeaf {
				return nil
			}
			der, err := codec.Decompress(rec.Frame, rec.DictID)
			if err != nil {
				return err
			}
			if d, ok := digest(der); ok {
				c.Put(d, loc, rec.CertID)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}
```

Replace `internal/ingest/batch.go` with:

```go
package ingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/extract"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

// Batch ingests entries [first, end) of src and commits them, verified
// against the pinned head sth (spec §8.3). A failed Merkle verification or
// canary abandons the attempt and refetches the batch once; a second
// failure writes an incident and returns ErrVerification. Any other error
// abandons the batch and is returned as is (a stall, a full disk, a second
// signal). The caller resets src's chain cache after every call.
func (w *Writer) Batch(ctx context.Context, src logsource.LogSource, sth logsource.SignedHead, first, end uint64) (commit.Manifest, error) {
	if w.broken != nil {
		return commit.Manifest{}, w.broken
	}
	m, err := w.attempt(ctx, src, sth, first, end)
	var firstTry, secondTry errRetry
	if !errors.As(err, &firstTry) {
		return m, err
	}
	w.logf("batch %s: %v; refetching it once", w.batchID(src, first, end), err)
	m, err = w.attempt(ctx, src, sth, first, end)
	if !errors.As(err, &secondTry) {
		return m, err
	}
	dir, ierr := w.incident(w.batchID(src, first, end), sth, firstTry, secondTry)
	if ierr != nil {
		return m, errors.Join(fmt.Errorf("%w: %v", ErrVerification, err), ierr)
	}
	return m, fmt.Errorf("%w: %v (incident written to %s)", ErrVerification, err, dir)
}

func (w *Writer) batchID(src logsource.LogSource, first, end uint64) commit.BatchID {
	return commit.BatchID{Log: src.Info().Name, First: first, Last: end - 1}
}

// batch is one attempt's in-memory state.
type batch struct {
	w       *Writer
	ctx     context.Context
	src     logsource.LogSource
	pb      *index.Batch
	before  *merkle.State // the compact range before the batch
	state   *merkle.State
	rows    []dataset.EntryRow
	chains  []dataset.ChainRow
	quar    bytes.Buffer
	counts  commit.Counts
	firstID uint64
	lastID  uint64
	samples *reservoir            // vault records the canary reads back
	builds  []derive.Builder      // the builders ACTIVE.json enables (amendment A2 §4.6)
	dstage  *dataset.DerivedStage // their rows, staged as they are built (amendment A2 §4.3)
}

type sample struct {
	sha [32]byte
	loc vault.Loc
}

// canaryReservoir is how many new vault records a batch keeps for the
// canary to choose from.
const canaryReservoir = 4096

// reservoir keeps a uniform random sample of a stream (Algorithm R), so the
// canary reads records from the whole batch, not only its start.
type reservoir struct {
	items []sample
	seen  int
	rnd   *rand.Rand
}

func newReservoir(n int, seed1, seed2 uint64) *reservoir {
	return &reservoir{items: make([]sample, 0, n), rnd: rand.New(rand.NewPCG(seed1, seed2))}
}

func (r *reservoir) add(s sample) {
	r.seen++
	if len(r.items) < cap(r.items) {
		r.items = append(r.items, s)
	} else if j := r.rnd.IntN(r.seen); j < len(r.items) {
		r.items[j] = s
	}
}

func (w *Writer) attempt(ctx context.Context, src logsource.LogSource, sth logsource.SignedHead, first, end uint64) (commit.Manifest, error) {
	id := w.batchID(src, first, end)
	tip := w.tips[id.Log]
	if first != tip.Next || end <= first || end > sth.TreeSize {
		return commit.Manifest{}, fmt.Errorf("batch %s: must start at %d and end within the signed tree of %d", id, tip.Next, sth.TreeSize)
	}
	state := merkle.NewState()
	if tip.State != nil {
		state = tip.State.Clone()
	}
	// P0: volume checks, the disk-guard peak preflight, then dictionary
	// training, which may take minutes and so runs only for a batch that
	// can start. A cache left cold by a stopped attempt is warmed first.
	if w.cold {
		if err := w.warm(); err != nil {
			return commit.Manifest{}, err
		}
		w.cold = false
	}
	if w.o.CheckVolumes != nil {
		if err := w.o.CheckVolumes(); err != nil {
			return commit.Manifest{}, err
		}
	}
	dir, err := w.preflight(end - first)
	if err != nil {
		return commit.Manifest{}, err
	}
	dict, err := w.maybeTrain(ctx)
	if err != nil {
		return commit.Manifest{}, err
	}
	w.vw.Prefer(dir)
	// P1
	in := commit.Intent{BatchID: id.String(), Log: id.Log, First: id.First, Last: id.Last, STH: toSTH(sth),
		VaultTail: w.vw.Tail(), NextCertID: w.ids.Peek(), MerkleBefore: state.Clone(), Builders: map[string]int{},
		StartedAt: w.o.Now().UTC()}
	if err := commit.WriteIntent(w.paths, in, w.o.Hook); err != nil {
		return commit.Manifest{}, err
	}
	b := &batch{w: w, ctx: ctx, src: src, pb: w.idx.NewBatch(), state: state, before: in.MerkleBefore,
		samples: newReservoir(canaryReservoir, first, end)}
	b.builds = w.builders()
	defer b.pb.Close()
	m, err := w.run(b, in, sth, dict)
	var after errCommitted
	if err != nil && !errors.As(err, &after) {
		if aerr := w.abandon(ctx, in); aerr != nil {
			w.broken = fmt.Errorf("%w: %s: %v", ErrAbandonFailed, id, aerr)
			return m, errors.Join(err, w.broken)
		}
	}
	return m, err
}

// ErrAbandonFailed means an attempt could not be cleaned up in process: the
// vault could not be cut back, or its intent could not be marked. The
// writer then refuses every further batch, and the next start recovers
// (spec §8.5).
var ErrAbandonFailed = errors.New("abandoning the batch failed; run update again to recover")

// run is P2-P10 of one attempt.
func (w *Writer) run(b *batch, in commit.Intent, sth logsource.SignedHead, dict commit.DictInfo) (commit.Manifest, error) {
	id := in.ID()
	// P2
	if len(b.builds) > 0 {
		var tables []derive.Table
		for _, bl := range b.builds {
			tables = append(tables, bl.Table())
		}
		d, err := w.stager.BeginDerived(b.ctx, tables, w.o.CanarySamples, rand.New(rand.NewPCG(id.First, id.Last)))
		if err != nil {
			return commit.Manifest{}, err
		}
		defer d.Close()
		b.dstage = d
	}
	if _, err := fetch.Run(b.ctx, b.src, id.First, id.Last+1, w.o.Fetch, b.add); err != nil {
		return commit.Manifest{}, err
	}
	// P3
	if err := w.vw.Sync(); err != nil {
		return commit.Manifest{}, err
	}
	w.hook(HookAfterVaultSync)
	// P4
	verified, err := w.verify(b, sth, id.Last+1)
	if err != nil {
		return commit.Manifest{}, err
	}
	// P5
	stage := w.paths.StageDir(id)
	files, err := w.stager.Stage(b.ctx, stage, b.rows, b.chains)
	if err != nil {
		return commit.Manifest{}, err
	}
	if b.dstage != nil {
		dfiles, err := b.dstage.Write(b.ctx, stage)
		if err != nil {
			return commit.Manifest{}, err
		}
		maps.Copy(files, dfiles)
	}
	if b.quar.Len() > 0 {
		p := filepath.Join(stage, commit.QuarantineFile)
		if err := os.WriteFile(p, b.quar.Bytes(), 0o644); err != nil {
			return commit.Manifest{}, err
		}
		fi, err := dataset.Sum(p)
		if err != nil {
			return commit.Manifest{}, err
		}
		fi.Rows = b.counts.LeafErrors
		files[commit.QuarantineFile] = fi
	}
	if err := w.o.Guard.Check(w.o.Root, 0); err != nil { // spec §10.1: a hard check after every staged write
		return commit.Manifest{}, err
	}
	// P6
	if err := w.canary(b, stage); err != nil {
		return commit.Manifest{}, err
	}
	// P7, P8
	seq := w.LastCommitSeq() + 1
	m := commit.Manifest{Format: commit.ManifestFormat, CommitSeq: seq, BatchID: id.String(), Log: id.Log,
		First: id.First, Last: id.Last, STH: toSTH(sth), MerkleAfter: b.state, Verified: verified,
		NextCertID: w.ids.Peek(), Vault: commit.Span{Start: in.VaultTail, End: w.vw.Tail()}, Builders: b.tables(),
		Files: files, Counts: b.counts, Dictionary: dict, CTVaultVersion: w.o.Version, CommittedAt: w.o.Now().UTC()}
	m.Counts.Entries = len(b.rows)
	if b.firstID != 0 {
		m.CertIDRange = &[2]uint64{b.firstID, b.lastID}
	}
	perr := commit.Publish(w.paths, m, w.o.Hook)
	if perr != nil && !errors.Is(perr, commit.ErrPostCommit) {
		return m, perr // the rename did not happen: abandon
	}
	// From here the batch is committed; failures below are repaired by
	// recovery at the next start, never by abandoning.
	w.committed = append(w.committed, m)
	w.tips[id.Log] = commit.LogTip{Next: id.Last + 1, State: b.state}
	if perr != nil {
		return m, errCommitted{perr}
	}
	// P9
	if err := b.pb.SetApplied(id.Log, seq); err != nil {
		return m, errCommitted{err}
	}
	w.hook(HookBeforePebble)
	if err := b.pb.Commit(); err != nil {
		return m, errCommitted{err}
	}
	w.hook(HookAfterPebble)
	// P10
	if err := commit.RemoveIntent(w.paths, id, w.o.Hook); err != nil {
		return m, errCommitted{err}
	}
	if err := commit.ClearAbandoned(w.paths); err != nil {
		return m, errCommitted{err}
	}
	if _, err := dataset.WriteViews(w.o.Root, w.active); err != nil { // the first commit changes it
		return m, errCommitted{err}
	}
	w.logf("batch %s: %d entries, %d new certificates (%d deltas), %d leaf errors, %d vault bytes, verified by %s; commit_seq %d",
		id, m.Counts.Entries, m.Counts.NewCerts, m.Counts.DeltaRecords, m.Counts.LeafErrors, m.Counts.VaultBytes, verified.Method, seq)
	return m, nil
}

// Hook points of the engine's own steps, for crash tests (spec §13.5).
const (
	HookAfterVaultSync = "commit.P3.after_vault_sync"
	HookDuringCanary   = "commit.P6.during_canary" // between the Parquet and the vault checks
	HookBeforePebble   = "commit.P9.before_pebble"
	HookAfterPebble    = "commit.P9.after_pebble"
)

func (w *Writer) hook(p string) {
	if w.o.Hook != nil {
		w.o.Hook(p)
	}
}

// errCommitted wraps a failure after the commit point: the batch is
// committed, so it must not be abandoned.
type errCommitted struct{ err error }

func (e errCommitted) Error() string { return "after commit: " + e.err.Error() }
func (e errCommitted) Unwrap() error { return e.err }

// abandon discards an attempt: vault, staging and intent go, the Pebble
// batch is discarded by the caller, cert_ids skip to the floor, and the
// delta cache forgets records that no longer exist. When ctx is done the
// process is stopping: the cache is emptied and left cold instead of
// re-reading the vault, and the next attempt warms it.
func (w *Writer) abandon(ctx context.Context, in commit.Intent) error {
	if err := w.vw.Close(); err != nil {
		return err
	}
	if err := commit.Abandon(w.paths, w.o.VaultDirs, in); err != nil {
		return err
	}
	w.ids.SkipToFloor()
	var err error
	if w.vw, err = vault.OpenWriter(w.vaultOptions(), w.codec, in.VaultTail); err != nil {
		return err
	}
	if ctx.Err() != nil {
		w.delta.Reset()
		w.cold = true
		return nil
	}
	return w.warm()
}

// add handles one entry in index order (P2).
func (b *batch) add(e logsource.RawEntry) error {
	if err := b.state.Append(e.Leaf.LeafHash); err != nil {
		return err
	}
	row := dataset.EntryRow{Idx: e.Index, CTTimestamp: e.Leaf.Timestamp, EntryType: e.Leaf.Type.String(), LeafHash: e.Leaf.LeafHash}
	if k, ok := e.Leaf.IssuanceKey(); ok {
		row.IssuanceKey, row.HasIssuanceKey = k, true
	}
	if e.Leaf.HasIssuerKeyHash {
		row.IssuerKeyHash, row.HasIssuerKeyHash = e.Leaf.IssuerKeyHash, true
	}
	if e.Leaf.Code != leaf.OK {
		row.LeafError = string(e.Leaf.Code)
		b.counts.LeafErrors++
		line, _ := json.Marshal(map[string]any{"idx": e.Index, "leaf_error": e.Leaf.Code,
			"leaf_input": base64.StdEncoding.EncodeToString(e.LeafInput), "extra_data": base64.StdEncoding.EncodeToString(e.ExtraData)})
		b.quar.Write(append(line, '\n'))
	}
	if e.Leaf.CertDER != nil {
		id, err := b.vaultLeaf(e.Leaf)
		if err != nil {
			return err
		}
		row.CertID = id
	}
	if e.Chain != nil {
		chainID, err := b.vaultChain(e.Chain)
		if err != nil {
			return err
		}
		row.ChainID, row.HasChainID = chainID, true
	}
	b.rows = append(b.rows, row)
	return nil
}

func (b *batch) assign() (uint64, error) {
	id, err := b.w.ids.Next()
	if err != nil {
		return 0, err
	}
	if b.firstID == 0 {
		b.firstID = id
	}
	b.lastID = id
	return id, nil
}

func (b *batch) vaulted(sha [32]byte, ref index.Ref) error {
	b.counts.NewCerts++
	b.counts.VaultBytes += uint64(ref.Loc.Len)
	b.samples.add(sample{sha, ref.Loc})
	return b.pb.AddCert(sha, ref)
}

// vaultLeaf stores a leaf certificate unless it is already vaulted. A final
// certificate whose precert is cached becomes a leaf-delta record.
func (b *batch) vaultLeaf(l leaf.Entry) (uint64, error) {
	sha := sha256.Sum256(l.CertDER)
	if ref, ok, err := b.pb.Lookup(sha); err != nil || ok {
		return ref.CertID, err
	}
	id, err := b.assign()
	if err != nil {
		return 0, err
	}
	var loc vault.Loc
	var baseID uint64
	if base, bid, ok := b.w.delta.Get(l.IssuanceDigest); ok && l.Type == leaf.TypeX509 && l.HasIssuanceDigest {
		if loc, err = b.w.vw.AppendDelta(id, l.CertDER, base); err != nil {
			return 0, err
		}
		b.counts.DeltaRecords++
		baseID = bid
	} else if loc, err = b.w.vw.AppendCert(vault.KindLeaf, id, l.CertDER, b.w.dictID); err != nil {
		return 0, err
	}
	kind := derive.KindFinal
	if l.Type == leaf.TypePrecert {
		kind = derive.KindPrecert
	}
	if err := b.derive(l.CertDER, derive.Context{CertID: id, SHA256: sha, Kind: kind, Loc: loc, DeltaBaseCertID: baseID}); err != nil {
		return 0, err
	}
	if l.Type == leaf.TypePrecert && l.HasIssuanceDigest {
		b.w.delta.Put(l.IssuanceDigest, loc, id)
	}
	return id, b.vaulted(sha, index.Ref{CertID: id, Loc: loc})
}

// vaultChain stores unseen chain certificates and returns the chain_id,
// adding chains.parquet rows the first time a chain is seen.
func (b *batch) vaultChain(fps [][32]byte) ([32]byte, error) {
	ids := make([]uint64, len(fps))
	h := sha256.New()
	for i, fp := range fps {
		h.Write(fp[:])
		ref, ok, err := b.pb.Lookup(fp)
		if err != nil {
			return [32]byte{}, err
		}
		if ok {
			ids[i] = ref.CertID
			continue
		}
		der, err := b.src.Issuer(b.ctx, fp)
		if err != nil {
			return [32]byte{}, err
		}
		if sha256.Sum256(der) != fp {
			return [32]byte{}, fmt.Errorf("chain certificate %x does not match its fingerprint", fp[:8])
		}
		if ids[i], err = b.assign(); err != nil {
			return [32]byte{}, err
		}
		loc, err := b.w.vw.AppendCert(vault.KindChain, ids[i], der, b.w.dictID)
		if err != nil {
			return [32]byte{}, err
		}
		if err := b.derive(der, derive.Context{CertID: ids[i], SHA256: fp, Kind: derive.KindChain, Loc: loc}); err != nil {
			return [32]byte{}, err
		}
		if err := b.vaulted(fp, index.Ref{CertID: ids[i], Loc: loc}); err != nil {
			return [32]byte{}, err
		}
	}
	var chainID [32]byte
	copy(chainID[:], h.Sum(nil))
	seen, err := b.pb.HasChain(chainID)
	if err != nil || seen {
		return chainID, err
	}
	for i, id := range ids {
		b.chains = append(b.chains, dataset.ChainRow{ChainID: chainID, Position: uint16(i), CertID: id})
	}
	return chainID, b.pb.AddChain(chainID)
}

// verify is P4 (spec §5.5): the computed root at end must equal the signed
// root, or be proven a prefix of it.
func (w *Writer) verify(b *batch, sth logsource.SignedHead, end uint64) (commit.Verified, error) {
	root, err := b.state.Root()
	if err != nil {
		return commit.Verified{}, err
	}
	if end == sth.TreeSize {
		if root != sth.RootHash {
			return commit.Verified{}, errRetry{err: errors.New("the computed root differs from the signed root"),
				before: b.before, root: root, end: end}
		}
		return commit.Verified{Method: "root_equals_sth"}, nil
	}
	var proof [][32]byte
	if err := fetch.Retry(b.ctx, w.o.Fetch, func(ctx context.Context) (err error) {
		proof, err = b.src.ConsistencyProof(ctx, end, sth.TreeSize)
		return err
	}); err != nil {
		return commit.Verified{}, err
	}
	if err := merkle.VerifyConsistency(end, sth.TreeSize, root, sth.RootHash, proof); err != nil {
		return commit.Verified{}, errRetry{err: err, before: b.before, root: root, end: end, proof: proof}
	}
	return commit.Verified{Method: "consistency_proof", ProofNodes: len(proof)}, nil
}

// canary is P6: the staged files, and vault reads of sampled new records.
func (w *Writer) canary(b *batch, stage string) error {
	rnd := rand.New(rand.NewPCG(b.rows[0].Idx, uint64(len(b.rows))))
	if err := w.stager.Canary(b.ctx, stage, b.rows, b.chains, w.o.CanarySamples, rnd); err != nil {
		return errRetry{err: err}
	}
	if b.dstage != nil {
		if err := b.dstage.Canary(b.ctx, stage); err != nil {
			return errRetry{err: err}
		}
	}
	w.hook(HookDuringCanary)
	r, err := vault.OpenReader(w.o.VaultDirs, w.codec)
	if err != nil {
		return err
	}
	defer r.Close()
	for range min(w.o.CanarySamples, len(b.samples.items)) {
		s := b.samples.items[rnd.IntN(len(b.samples.items))]
		if _, err := r.ReadVerified(s.loc, s.sha); err != nil {
			return errRetry{err: err}
		}
	}
	return nil
}

// maybeTrain trains dictionary 1 once the committed vault holds
// DictSamples leaf certificates; a training failure is recorded and
// ingestion goes on with dictionary 0 (amendment A1 §5). It is tried once
// per process. Vault corruption met while reading the samples is returned:
// corruption is never ignored (spec §12). Training takes minutes, so a
// cancelled ctx returns at once; the abandoned training finishes in the
// background and is discarded, and a later run trains again.
func (w *Writer) maybeTrain(ctx context.Context) (commit.DictInfo, error) {
	if w.dictID != 0 || w.trainTried {
		return commit.DictInfo{ID: w.dictID}, nil
	}
	samples, tr, err := vault.TrainingSet(w.o.VaultDirs, w.codec, w.vw.Tail(), w.o.DictSamples)
	if err != nil {
		return commit.DictInfo{}, fmt.Errorf("reading dictionary training samples: %w", err)
	}
	if len(samples) < w.o.DictSamples {
		return commit.DictInfo{ID: 0}, nil
	}
	w.trainTried = true
	w.logf("training dictionary 1 on %d leaf certificates", len(samples))
	type trained struct {
		content []byte
		err     error
	}
	done := make(chan trained, 1)
	go func() {
		c, err := w.o.Train(samples, 1)
		done <- trained{c, err}
	}()
	var res trained
	select {
	case res = <-done:
	case <-ctx.Done():
		w.trainTried = false
		return commit.DictInfo{}, ctx.Err()
	}
	content, err := res.content, res.err
	if err == nil {
		var d vault.Dict
		if d, err = vault.InstallDict(w.o.VaultDirs, 1, content, tr, w.o.Now()); err == nil {
			err = w.codec.AddDict(1, d.Content)
		}
	}
	if err != nil {
		w.logf("dictionary training failed; continuing without a dictionary: %v", err)
		return commit.DictInfo{ID: 0, TrainingError: err.Error()}, nil
	}
	w.dictID = 1
	return commit.DictInfo{ID: 1}, nil
}

// preflight is the spec §10.1 peak check before a batch starts. It returns
// the vault directory whose filesystem holds the vault peak; the batch's new
// segments go there.
func (w *Writer) preflight(n uint64) (string, error) {
	var vaultHist, parquetHist []float64
	for i := max(0, len(w.committed)-diskguard.MinHistory); i < len(w.committed); i++ {
		m := w.committed[i]
		if m.Counts.Entries == 0 {
			continue
		}
		var pq int64
		for _, f := range m.Files {
			pq += f.Bytes
		}
		vaultHist = append(vaultHist, float64(m.Counts.VaultBytes)/float64(m.Counts.Entries))
		parquetHist = append(parquetHist, float64(pq)/float64(m.Counts.Entries))
	}
	cfg := w.o.Config
	peak := diskguard.EstimatePeak(diskguard.PeakInput{Entries: n,
		VaultP95: diskguard.P95(vaultHist, diskguard.SeedVaultBytesPerEntry), ParquetP95: diskguard.P95(parquetHist, diskguard.SeedParquetBytesPerEntry),
		PebbleP95: diskguard.SeedPebbleBytesPerEntry, Safety: cfg.Disk.SafetyFactor,
		PebbleSize: dirSize(filepath.Join(w.o.Root, "state", "pebble")), DuckDBSpill: w.spillLimit()})
	var err error
	for _, d := range w.o.VaultDirs {
		if err = w.o.Guard.Preflight([]diskguard.Target{{Path: w.o.Root, Need: peak.Root}, {Path: d, Need: peak.Vault}}); err == nil {
			return d, nil
		}
	}
	return "", err
}

func dirSize(dir string) uint64 {
	var n uint64
	filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				n += uint64(fi.Size())
			}
		}
		return nil
	})
	return n
}

func toSTH(h logsource.SignedHead) commit.STH {
	return commit.STH{TreeSize: h.TreeSize, Timestamp: h.Timestamp, RootHash: hex.EncodeToString(h.RootHash[:]),
		Signature: base64.StdEncoding.EncodeToString(h.Signature)}
}

// incident writes the evidence of a batch that failed verification twice
// (spec §12): the pinned head as received, both attempts' causes, and for a
// Merkle failure our compact range before the batch, the root we computed
// and the proof the log served. The fetched data itself is truncated.
func (w *Writer) incident(id commit.BatchID, sth logsource.SignedHead, first, second errRetry) (string, error) {
	dir := filepath.Join(w.o.Root, "state", "incidents", w.o.Now().UTC().Format("20060102T150405Z")+"_"+id.Log+"_"+fmt.Sprint(id.First))
	if err := fsutil.MkdirAllSync(dir, 0o755); err != nil {
		return "", err
	}
	ev := map[string]any{"batch_id": id.String(), "causes": []string{first.Error(), second.Error()}, "sth": toSTH(sth),
		"sth_raw": base64.StdEncoding.EncodeToString(sth.Raw), "time": w.o.Now().UTC().Format(time.RFC3339)}
	if second.before != nil {
		proof := make([]string, len(second.proof))
		for i, n := range second.proof {
			proof[i] = hex.EncodeToString(n[:])
		}
		ev["merkle_before"], ev["computed_root"], ev["end"], ev["proof"] = second.before, hex.EncodeToString(second.root[:]), second.end, proof
	}
	b, err := json.MarshalIndent(ev, "", " ")
	if err != nil {
		return dir, err
	}
	return dir, fsutil.WriteFileAtomic(filepath.Join(dir, "incident.json"), b, 0o644)
}

// builders are the builders whose table ACTIVE.json lists as active or
// building at this binary's version: every batch writes them (amendment A2
// §4.6).
func (w *Writer) builders() []derive.Builder {
	var out []derive.Builder
	for _, bl := range derive.Builders {
		st := w.active.Tables[bl.Table().Name]
		if v := bl.Table().Version; st.Active != nil && *st.Active == v || st.Building != nil && *st.Building == v {
			out = append(out, bl)
		}
	}
	return out
}

// derive extracts a newly vaulted certificate once and stages its rows in
// every derived table of the batch.
func (b *batch) derive(der []byte, ctx derive.Context) error {
	if b.dstage == nil {
		return nil
	}
	c := extract.Parse(der)
	for i, bl := range b.builds {
		if err := b.dstage.Add(i, bl.Build(c, ctx)); err != nil {
			return err
		}
	}
	return nil
}

// tables records the derived tables this batch built, for _COMMIT.json.
func (b *batch) tables() map[string]int {
	out := map[string]int{}
	for _, bl := range b.builds {
		out[bl.Table().Name] = bl.Table().Version
	}
	return out
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race -count=1 ./internal/vault/ ./internal/ingest/ ./internal/commit/`
Expected: PASS. The crash suite in `internal/commit` now runs `CheckDerived` after every recovery.

- [ ] **Step 5: Quality gate**

- [ ] **Step 6: Checkpoint.**

---

### Task B5: Recovery equivalence over derived rows, and real data end to end

Amendment A1 §7 and A2 §4, end to end.

**Files:**
- Modify: `internal/vaulttest/vaulttest.go` (test helper: `Content`; `Dump` and `Diff` cover the derived rows)
- Tests: `internal/commit/crash_test.go`, `internal/integration/vault_realdata_test.go`

**Interfaces:**
- Consumes: `CheckDerived` (Task B4); `derive.ReadActive`, `derive.CertsV1`, `derive.NamesV1`, `derive.Names` (Tasks B1–B2); `extract.Parse`.
- Produces:
  - `vaulttest.Content{Entries map[string][]Entry; Certs map[string]string}`;
  - `(vaulttest.Vault).Dump(t) Content`, `vaulttest.Diff(got, want Content) string`.

- [ ] **Step 1: Write the failing tests**

Replace `internal/commit/crash_test.go` with (`clean` returns a `Content` and requires derived rows for every referenced certificate):

```go
package commit_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/ingest"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/vault"
	"github.com/4rji/ctvault/internal/vaulttest"
)

// The crash suite (spec §13.5) runs the real writer in a subprocess, the
// test binary itself running TestCrashChild, and kills it with SIGKILL: at
// a named boundary, through the hook, or at a random moment. After every
// kill the parent checks what readers would see, recovers the vault the way
// the next start does, and checks the invariants again.

// childEnv names the file that tells TestCrashChild what to do. Only the
// crash tests set it, in the subprocesses they start.
const childEnv = "CTVAULT_CRASH_CHILD"

var crashUUID = [16]byte{0xc7, 0x5a, 0x01}

// crashConfig is what a crash child needs.
type crashConfig struct {
	Root      string
	LogURL    string
	PublicKey []byte // SPKI
	End       uint64
	BatchSize uint64
	KillAt    string // a hook point; "" runs to the end
	KillNth   int    // die the nth time KillAt fires
}

// options is the writer configuration of every crash test: small segments
// so batches roll over, and a small dictionary sample so a run trains.
func options(root string, hook func(string)) ingest.Options {
	cfg := config.Default()
	cfg.Ingest.DeltaLRUEntries = 1000
	cfg.Vault.SegmentSize = 16 << 10
	free := func(string) (diskguard.Usage, error) {
		return diskguard.Usage{Total: 1 << 40, Avail: 1 << 39, Dev: 1}, nil
	}
	return ingest.Options{Root: root, VaultDirs: []string{filepath.Join(root, "vault")}, VaultUUID: crashUUID, Config: cfg,
		Guard: diskguard.Guard{Cap: 0.85, Stat: free}, Version: "crash-test", Out: io.Discard, Hook: hook,
		DictSamples: 60, CanarySamples: 16,
		Fetch: fetch.Options{MaxRPS: 1000, MinBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond}}
}

// TestCrashChild is not a test of its own: in a subprocess it ingests the
// fake log into the vault, and kills itself at the configured point.
func TestCrashChild(t *testing.T) {
	p := os.Getenv(childEnv)
	if p == "" {
		t.Skip("run by the crash tests in a subprocess")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var c crashConfig
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	fired := 0
	hook := func(point string) {
		if point == c.KillAt {
			if fired++; fired == c.KillNth {
				syscall.Kill(os.Getpid(), syscall.SIGKILL)
				time.Sleep(time.Hour)
			}
		}
	}
	w, err := ingest.Open(options(c.Root, hook))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	pub, err := x509.ParsePKIXPublicKey(c.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	chains := logsource.NewChainCache(logsource.DefaultChainCacheBytes)
	src := rfc6962.NewSource(logsource.LogInfo{Name: "fakelog", LogID: sha256.Sum256(c.PublicKey), PublicKey: pub, URL: c.LogURL}, nil, chains, nil)
	ctx := context.Background()
	sth, err := src.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for first := w.Next("fakelog"); first < c.End; {
		end := min(first+c.BatchSize, c.End)
		if _, err := w.Batch(ctx, src, sth, first, end); err != nil {
			t.Fatal(err)
		}
		chains.Reset()
		first = end
	}
}

// crashRun is one vault under the crash suite.
type crashRun struct {
	t       *testing.T
	v       vaulttest.Vault
	cfg     crashConfig
	ids     map[uint64][32]byte // every cert_id assignment seen, over all attempts
	dropped map[uint64]bool     // cert_ids of records recovery truncated
	seen    map[string][]byte   // every committed batch's _COMMIT.json
}

func newCrashRun(t *testing.T, l *ctlogtest.Log, end, batch uint64) *crashRun {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"state/intent", "state/incidents", "state/logs", "vault/segments", "vault/dict", "dataset", "tmp/stage", "tmp/rebuild"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return &crashRun{t: t, v: vaulttest.Vault{Root: root, Dirs: []string{filepath.Join(root, "vault")}, UUID: crashUUID},
		cfg: crashConfig{Root: root, LogURL: l.URL, PublicKey: l.PublicKeyDER, End: end, BatchSize: batch},
		ids: map[uint64][32]byte{}, dropped: map[uint64]bool{}, seen: map[string][]byte{}}
}

// child runs a crash child. With killAt set it must die there; with after
// set it is killed after that long unless it finishes first. It reports
// whether the child was killed.
func (r *crashRun) child(killAt string, nth int, after time.Duration) bool {
	r.t.Helper()
	cfg := r.cfg
	cfg.KillAt, cfg.KillNth = killAt, nth
	b, _ := json.Marshal(cfg)
	p := filepath.Join(r.t.TempDir(), "child.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		r.t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), childEnv+"="+p)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		r.t.Fatal(err)
	}
	if after > 0 {
		timer := time.AfterFunc(after, func() { cmd.Process.Signal(syscall.SIGKILL) })
		defer timer.Stop()
	}
	err := cmd.Wait()
	var ee *exec.ExitError
	if err == nil {
		return false
	}
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() && ws.Signal() == syscall.SIGKILL {
			return true
		}
	}
	r.t.Fatalf("the crash child failed: %v\n%s", err, out.String())
	return false
}

// restart checks the vault as a kill left it (no partial batch visible,
// nothing committed lost, no cert_id reused), recovers it as the next start
// does, and checks spec §13.5's invariants on the result.
func (r *crashRun) restart() {
	t := r.t
	t.Helper()
	committed := r.v.Committed(t)
	for dir, b := range r.seen {
		if !bytes.Equal(committed[dir], b) {
			t.Fatalf("committed batch %s was lost or changed", dir)
		}
	}
	r.seen = committed
	beyond := r.v.BeyondTail(t)
	for id, sha := range r.v.Assignments(t) {
		if prev, ok := r.ids[id]; ok && prev != sha {
			t.Fatalf("cert_id %d was reused for a different certificate", id)
		}
		if _, now := beyond[id]; !now && r.dropped[id] {
			t.Fatalf("cert_id %d belonged to a record recovery truncated, and was committed later (spec §8.6: IDs are never reused)", id)
		}
		r.ids[id] = sha
	}
	for id := range beyond {
		r.dropped[id] = true
	}
	w, err := ingest.Open(options(r.v.Root, nil))
	if err != nil {
		t.Fatalf("recovery: %v", err)
	}
	w.Close()
	r.v.CheckRecovered(t)
}

// clean ingests the whole log in a child that is never killed and returns
// its content and how long the child took. The content holds derived rows
// for every certificate an entry references (amendment A2 §4), so the
// comparisons below cover the derived files too.
func clean(t *testing.T, l *ctlogtest.Log, end, batch uint64) (vaulttest.Content, time.Duration) {
	t.Helper()
	r := newCrashRun(t, l, end, batch)
	start := time.Now()
	if r.child("", 0, 0) {
		t.Fatal("the clean child was killed")
	}
	took := time.Since(start)
	r.restart()
	c := r.v.Dump(t)
	for _, es := range c.Entries {
		for _, e := range es {
			if _, ok := c.Certs[e.Cert]; e.Cert != "" && !ok {
				t.Fatalf("entry %d: certificate %s has no derived rows", e.Idx, e.Cert)
			}
		}
	}
	return c, took
}

const (
	crashEntries = 240
	crashBatch   = 40
)

// TestCrashAtEveryBoundary kills the writer at each named boundary of spec
// §13.5, mostly in the second batch, then lets a new run finish: the result
// must equal a clean ingest except for cert_id and chain_id (amendment A1
// §7). The ACTIVE.json and rebuild boundaries arrive with Plans 3 and 6.
func TestCrashAtEveryBoundary(t *testing.T) {
	if testing.Short() {
		t.Skip("starts about 40 subprocesses")
	}
	l := ctlogtest.New(t, crashEntries, ctlogtest.Options{})
	want, _ := clean(t, l, crashEntries, crashBatch)
	for _, b := range []struct {
		point string
		nth   int
	}{
		{commit.HookAfterIntent, 2},
		{vault.HookAppendMidRecord, 60},
		{vault.HookRolloverBeforeHeader, 3},
		{vault.HookRolloverAfterHeader, 3},
		{vault.HookRolloverBeforeDirSync, 3},
		{commit.HookIDFloorBeforeAdvance, 1},
		{commit.HookIDFloorAfterAdvance, 1},
		{ingest.HookAfterVaultSync, 2},
		{ingest.HookDuringCanary, 2},
		{commit.HookAfterManifest, 2},
		{commit.HookBeforeRename, 2},
		{commit.HookAfterRename, 2},
		{ingest.HookBeforePebble, 2},
		{ingest.HookAfterPebble, 2},
		{commit.HookBeforeIntentDelete, 2},
	} {
		t.Run(b.point, func(t *testing.T) {
			r := newCrashRun(t, l, crashEntries, crashBatch)
			if !r.child(b.point, b.nth, 0) {
				t.Fatalf("the child finished without reaching %s #%d", b.point, b.nth)
			}
			r.restart()
			if r.child("", 0, 0) {
				t.Fatal("the second run was killed")
			}
			r.restart()
			if d := vaulttest.Diff(r.v.Dump(t), want); d != "" {
				t.Fatalf("the recovered ingest differs from a clean one: %s", d)
			}
		})
	}
}

// TestRandomKillLoop kills the writer at random moments, killLoopRuns times
// (25 by default, 200 with -tags nightly). Each kill is followed by the
// recovery checks; every ingest that runs to the end must equal a clean one.
func TestRandomKillLoop(t *testing.T) {
	if testing.Short() {
		t.Skip("starts many subprocesses")
	}
	l := ctlogtest.New(t, crashEntries, ctlogtest.Options{})
	want, took := clean(t, l, crashEntries, crashBatch)
	seed := uint64(time.Now().UnixNano())
	t.Logf("seed %d; a clean ingest takes %v", seed, took)
	rnd := rand.New(rand.NewPCG(seed, 1))
	r := newCrashRun(t, l, crashEntries, crashBatch)
	kills, complete := 0, 0
	for range killLoopRuns {
		if r.child("", 0, time.Duration(rnd.Int64N(int64(took)))+time.Millisecond) {
			kills++
			r.restart()
			continue
		}
		r.restart()
		if d := vaulttest.Diff(r.v.Dump(t), want); d != "" {
			t.Fatalf("seed %d: an ingest that survived %d kills differs from a clean one: %s", seed, kills, d)
		}
		complete++
		r = newCrashRun(t, l, crashEntries, crashBatch)
	}
	for r.child("", 0, 0) {
	}
	r.restart()
	if d := vaulttest.Diff(r.v.Dump(t), want); d != "" {
		t.Fatalf("seed %d: the last ingest differs from a clean one: %s", seed, d)
	}
	t.Logf("%d runs: %d kills, %d ingests completed and compared", killLoopRuns, kills, complete+1)
}
```

Replace `internal/integration/vault_realdata_test.go` with (the derived checks in `TestCanonicalIngestEndToEnd`; `TestRecoveryEquivalenceOnRealData` requires derived rows):

```go
//go:build realdata

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/duckdb/duckdb-go/v2" // the "duckdb" database/sql driver

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/extract"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/ingest"
	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/measure"
	"github.com/4rji/ctvault/internal/sample"
	"github.com/4rji/ctvault/internal/sampletest"
	"github.com/4rji/ctvault/internal/vault"
	"github.com/4rji/ctvault/internal/vaulttest"
)

// realVault is a fresh vault in a temp folder, ingesting a canonical sample
// replayed over loopback through the production client, fetcher and writer.
type realVault struct {
	t      *testing.T
	s      *sample.Sample
	v      vaulttest.Vault
	opts   ingest.Options
	src    *rfc6962.Source
	chains *logsource.ChainCache
	head   logsource.SignedHead
	out    bytes.Buffer
}

func newRealVault(t *testing.T, s *sample.Sample, dictSamples int) *realVault {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"state/intent", "state/incidents", "state/logs", "vault/segments", "vault/dict", "dataset", "tmp/stage", "tmp/rebuild"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var id [16]byte
	rand.Read(id[:])
	r := &realVault{t: t, s: s, v: vaulttest.Vault{Root: root, Dirs: []string{filepath.Join(root, "vault")}, UUID: id}}
	url, stop, err := sample.Serve(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	r.chains = logsource.NewChainCache(logsource.DefaultChainCacheBytes)
	r.src = rfc6962.NewSource(s.LogInfo(url), nil, r.chains, nil)
	if r.head, err = r.src.Head(context.Background()); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	r.opts = ingest.Options{Root: root, VaultDirs: r.v.Dirs, VaultUUID: id, Config: cfg,
		Guard: diskguard.Guard{Cap: cfg.Disk.MaxUsedFraction, Stat: diskguard.Statfs}, Version: "realdata-test", Out: &r.out,
		Fetch:       fetch.Options{MaxRPS: 1000, PageSize: s.Manifest.PageSize, MinBackoff: time.Millisecond, MaxBackoff: 10 * time.Millisecond},
		DictSamples: dictSamples}
	return r
}

func (r *realVault) open() *ingest.Writer {
	r.t.Helper()
	w, err := ingest.Open(r.opts)
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { w.Close() })
	return w
}

// ingest commits [w's next index, to) in batches of size, verified against
// the sample's signed head with its stored consistency proofs.
func (r *realVault) ingest(w *ingest.Writer, to, size uint64) {
	r.t.Helper()
	log := r.s.Manifest.Log.Name
	for first := w.Next(log); first < to; first = w.Next(log) {
		if _, err := w.Batch(context.Background(), r.src, r.head, first, min(first+size, to)); err != nil {
			r.t.Fatalf("batch at %d: %v\n%s", first, err, r.out.String())
		}
		r.chains.Reset()
	}
}

// expected decodes the sample's entries [0, n) directly, for comparison.
type expected struct {
	types map[string]int
	certs map[uint64][]byte // idx → leaf certificate DER
}

func decodeSample(t *testing.T, s *sample.Sample, n uint64) expected {
	t.Helper()
	e := expected{types: map[string]int{}, certs: map[uint64][]byte{}}
	err := s.Each(func(x sample.Entry) error {
		if x.Index >= n {
			return nil
		}
		l := leaf.Decode(x.LeafInput, x.ExtraData)
		e.types[l.Type.String()]++
		if l.CertDER != nil {
			e.certs[x.Index] = l.CertDER
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func queryInt(t *testing.T, db *sql.DB, q string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// TestCanonicalIngestEndToEnd ingests the whole canonical sample into a
// vault with the production settings (dictionary 1 trains on 20,000 real
// certificates), then checks the vault's invariants, queries it through
// views.sql and reads certificates back.
func TestCanonicalIngestEndToEnd(t *testing.T) {
	s := sampletest.Canonical(t, realLog)
	n := s.Manifest.Count
	r := newRealVault(t, s, 0)
	w := r.open()
	start := time.Now()
	r.ingest(w, n, 10000)
	t.Logf("ingested %d entries in %v", n, time.Since(start).Round(time.Second))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r.v.CheckRecovered(t)

	ms, err := commit.ListCommitted(r.v.Root)
	if err != nil || uint64(len(ms)) != n/10000 {
		t.Fatalf("%d batches, %v", len(ms), err)
	}
	trained := false
	for _, m := range ms {
		if m.Verified.Method != "consistency_proof" {
			t.Fatalf("batch %s verified by %q", m.BatchID, m.Verified.Method)
		}
		trained = trained || m.Dictionary.ID == 1
	}
	ds, err := vault.LoadDicts(r.v.Dirs)
	if err != nil || !trained || len(ds) != 1 || ds[0].Manifest.Training.Records != vault.TrainingSamples {
		t.Fatalf("dictionary 1 trained on %d real certificates: %v %v", vault.TrainingSamples, ds, err)
	}

	want := decodeSample(t, s, n)
	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	views, err := os.ReadFile(filepath.Join(r.v.Root, dataset.ViewsFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(views)); err != nil {
		t.Fatalf("loading views.sql: %v", err)
	}
	if got := queryInt(t, db, `SELECT count(*) FROM entries`); got != int64(n) {
		t.Fatalf("entries: %d rows", got)
	}
	if got := queryInt(t, db, `SELECT count(DISTINCT idx) FROM entries WHERE idx BETWEEN 0 AND ?`, n-1); got != int64(n) {
		t.Fatalf("entries: %d distinct indexes in [0, %d)", got, n)
	}
	for typ, k := range want.types {
		if got := queryInt(t, db, `SELECT count(*) FROM entries WHERE entry_type = ?`, typ); got != int64(k) {
			t.Fatalf("entry_type %s: %d rows, the sample has %d", typ, got, k)
		}
	}
	if got := queryInt(t, db, `SELECT count(*) FROM batches`); got != int64(len(ms)) {
		t.Fatalf("batches view: %d rows", got)
	}
	// Every chain starts at position 0, and each entry's chain resolves.
	if a, b := queryInt(t, db, `SELECT count(*) FROM entries WHERE chain_id IS NOT NULL`),
		queryInt(t, db, `SELECT count(*) FROM entries e JOIN (SELECT DISTINCT chain_id FROM chains WHERE position = 0) c USING (chain_id)`); a != b || a == 0 {
		t.Fatalf("%d entries have a chain, %d resolve to one", a, b)
	}
	// Amendment A1 §6 on real data: a literal lookup on a BLOB column finds
	// every row (a bloom filter would have returned none).
	var ikh string
	var rows int64
	if err := db.QueryRow(`SELECT hex(issuer_key_hash), count(*) FROM entries WHERE issuer_key_hash IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 1`).Scan(&ikh, &rows); err != nil {
		t.Fatal(err)
	}
	if got := queryInt(t, db, fmt.Sprintf(`SELECT count(*) FROM entries WHERE issuer_key_hash = from_hex('%s')`, ikh)); got != rows || rows == 0 {
		t.Fatalf("literal issuer_key_hash lookup: %d rows, want %d", got, rows)
	}

	// Derived tables (amendment A2 §4): every batch built them, ACTIVE.json
	// is complete, every vaulted certificate has one certs row, every entry
	// joins its certificate, and kinds agree with the entry types.
	if a, ok, err := derive.ReadActive(r.v.Root); err != nil || !ok || !a.AllComplete() {
		t.Fatalf("ACTIVE.json: %+v %v %v", a, ok, err)
	}
	var newCerts int64
	for _, m := range ms {
		if m.Builders[derive.CertsV1.Name] != derive.CertsV1.Version || m.Builders[derive.NamesV1.Name] != derive.NamesV1.Version {
			t.Fatalf("batch %s built %v", m.BatchID, m.Builders)
		}
		newCerts += int64(m.Counts.NewCerts)
	}
	if got := queryInt(t, db, `SELECT count(*) FROM certs`); got != newCerts {
		t.Fatalf("certs: %d rows for %d vaulted certificates", got, newCerts)
	}
	if a, b := queryInt(t, db, `SELECT count(*) FROM entries WHERE cert_id IS NOT NULL`), queryInt(t, db, `SELECT count(*) FROM entry_certs`); a != b || a == 0 {
		t.Fatalf("%d entries have a certificate, %d join certs", a, b)
	}
	if got := queryInt(t, db, `SELECT count(*) FROM entry_certs
		WHERE NOT (entry_type = 'precert' AND kind = 'precert' OR entry_type = 'x509' AND kind IN ('final', 'chain'))`); got != 0 {
		t.Fatalf("%d entries disagree with their certificate's kind", got)
	}
	if got := queryInt(t, db, `SELECT count(*) FROM logging_delay WHERE logging_delay IS NOT NULL`); got == 0 {
		t.Fatal("logging_delay has no values")
	}
	// Literal lookups on the bloom-filtered columns find every row.
	var top string
	if err := db.QueryRow(`SELECT name, count(*) FROM names WHERE dns_valid GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 1`).Scan(&top, &rows); err != nil {
		t.Fatal(err)
	}
	if got := queryInt(t, db, `SELECT count(*) FROM names WHERE name = '`+top+`'`); got != rows || rows == 0 {
		t.Fatalf("literal names lookup of %s: %d rows, want %d", top, got, rows)
	}
	t.Logf("derived: %d certs rows, %d names rows (%d dns_valid), %d entries joined to certs", newCerts,
		queryInt(t, db, `SELECT count(*) FROM names`), queryInt(t, db, `SELECT count(*) FROM names WHERE dns_valid`),
		queryInt(t, db, `SELECT count(*) FROM entry_certs`))

	// Certificates read back through Pebble and the vault, verified.
	idx, err := index.Open(filepath.Join(r.v.Root, "state", "pebble"))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	codec, err := vault.NewCodec()
	if err != nil {
		t.Fatal(err)
	}
	defer codec.Close()
	for _, d := range ds {
		codec.AddDict(d.Manifest.ID, d.Content)
	}
	vr, err := vault.OpenReader(r.v.Dirs, codec)
	if err != nil {
		t.Fatal(err)
	}
	defer vr.Close()
	rnd := mrand.New(mrand.NewPCG(1, 2))
	for range 1000 {
		i := rnd.Uint64N(n)
		der, ok := want.certs[i]
		if !ok {
			continue
		}
		sha := sha256.Sum256(der)
		ref, ok, err := idx.Lookup(sha)
		if err != nil || !ok {
			t.Fatalf("entry %d: certificate %x not in the index (%v)", i, sha[:8], err)
		}
		got, err := vr.ReadVerified(ref.Loc, sha)
		if err != nil || !bytes.Equal(got, der) {
			t.Fatalf("entry %d: reading certificate %x back: %v", i, sha[:8], err)
		}
		if c := queryInt(t, db, `SELECT count(*) FROM entries WHERE idx = ? AND cert_id = ?`, i, ref.CertID); c != 1 {
			t.Fatalf("entry %d: entries.parquet does not point at cert_id %d", i, ref.CertID)
		}
		// Its derived rows, found by a literal sha256, match the extractor.
		c := extract.Parse(der)
		var status, issuer string
		var dns int64
		if err := db.QueryRow(fmt.Sprintf(`SELECT parse_status, coalesce(issuer_der, ''), n_dns_names FROM certs WHERE sha256 = '%x' AND cert_id = %d`, sha, ref.CertID)).
			Scan(&status, &issuer, &dns); err != nil || status != string(c.Status) || issuer != hex.EncodeToString(c.Issuer.Raw) || dns != int64(len(c.DNSNames)) {
			t.Fatalf("entry %d: certs row (%s, %s, %d) differs from the extractor's %+v: %v", i, status, issuer, dns, c, err)
		}
		if got, want := queryInt(t, db, `SELECT count(*) FROM names WHERE cert_id = ?`, ref.CertID), len(derive.Names{}.Build(c, derive.Context{CertID: ref.CertID})); got != int64(want) {
			t.Fatalf("entry %d: %d names rows, the builder gives %d", i, got, want)
		}
	}
}

// TestRecoveryEquivalenceOnRealData crashes an ingest of real entries at
// commit boundaries, across dictionary training and leaf-delta batches,
// recovers each time, and requires the result to equal a clean ingest on
// everything but internal IDs (amendment A1 §7).
func TestRecoveryEquivalenceOnRealData(t *testing.T) {
	s := sampletest.Canonical(t, realLog)
	const n, size, dict = 30000, 5000, 2000 // dictionary 1 trains before the second batch
	clean := newRealVault(t, s, dict)
	cw := clean.open()
	clean.ingest(cw, n, size)
	cw.Close()
	want := clean.v.Dump(t)
	if len(want.Certs) == 0 {
		t.Fatal("the clean ingest has no derived rows")
	}

	r := newRealVault(t, s, dict)
	crashes := []struct {
		at    uint64 // the batch that crashes
		point string
	}{
		{5000, commit.HookAfterIntent}, // the batch that trains dictionary 1
		{10000, vault.HookAppendMidRecord},
		{15000, ingest.HookDuringCanary},
		{20000, commit.HookBeforeRename},
		{25000, ingest.HookBeforePebble},
	}
	for _, c := range crashes {
		w := r.open()
		r.ingest(w, c.at, size)
		w.Close()
		r.opts.Hook = func(p string) {
			if p == c.point {
				panic("crash at " + p)
			}
		}
		w = r.open()
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("batch at %d: %s did not fire", c.at, c.point)
				}
			}()
			w.Batch(context.Background(), r.src, r.head, c.at, c.at+size)
		}()
		w.Close()
		r.chains.Reset()
		r.opts.Hook = nil
		w = r.open() // recovers
		w.Close()
		r.v.CheckRecovered(t)
		if !strings.Contains(r.out.String(), "recovery:") {
			t.Fatalf("crash at %s (batch %d): recovery reported nothing", c.point, c.at)
		}
	}
	w := r.open()
	r.ingest(w, n, size)
	w.Close()
	r.v.CheckRecovered(t)
	if d := vaulttest.Diff(r.v.Dump(t), want); d != "" {
		t.Fatalf("the recovered ingest differs from a clean one: %s", d)
	}
	ms, _ := commit.ListCommitted(r.v.Root)
	got, want2 := ms[len(ms)-1].NextCertID, lastNext(t, clean.v.Root)
	if got <= want2 {
		t.Fatalf("after crashes cert_ids resume at ID_FLOOR, leaving gaps: next %d, clean %d", got, want2)
	}
	t.Logf("%d crashes recovered; %d batches equal a clean ingest of %d real entries (next cert_id %d, clean %d)",
		len(crashes), len(ms), n, got, want2)
}

func lastNext(t *testing.T, root string) uint64 {
	ms, err := commit.ListCommitted(root)
	if err != nil || len(ms) == 0 {
		t.Fatal(err)
	}
	return ms[len(ms)-1].NextCertID
}

// TestMeasurementReports measures every cached sample of the log and writes
// the reports under the dev base (amendment A1 §8).
func TestMeasurementReports(t *testing.T) {
	samples := []*sample.Sample{sampletest.Canonical(t, realLog)}
	samples = append(samples, sampletest.Representatives(t, realLog)...)
	base := filepath.Dir(sampletest.Base(t))
	for _, s := range samples {
		id := s.Manifest.ID(filepath.Base(s.Dir))
		t.Run(strings.ReplaceAll(id, "/", "_"), func(t *testing.T) {
			r, p, err := measure.Run(context.Background(), s, measure.Options{Base: base, Version: "realdata-test", Stat: diskguard.Statfs,
				Dependencies: goModVersions(t)})
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Provenance.Dependencies) != 4 {
				t.Fatalf("provenance lacks dependency versions: %v", r.Provenance.Dependencies)
			}
			if r.Errors.Total != r.Errors.Committed || r.Sizes.Vault <= 0 || r.Sizes.Parquet <= 0 || r.Sizes.Pebble <= 0 {
				t.Fatalf("inconsistent report: errors %+v, sizes %+v", r.Errors, r.Sizes)
			}
			full := 0
			for _, g := range r.Compression.Groups {
				if g.Kind == "leaf" || g.Kind == "delta" {
					full += g.Records
				}
			}
			if full != r.Dedup.UniqueLeafCerts {
				t.Fatalf("%d leaf and delta records for %d unique leaf certificates", full, r.Dedup.UniqueLeafCerts)
			}
			t.Logf("report %s\n%s", p.JSON, measure.Markdown(r))
		})
	}
}

// goModVersions reads the required module versions from go.mod: a go test
// binary's build info lists no dependencies.
func goModVersions(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "require "))
		if len(f) >= 2 && strings.Contains(f[0], ".") && strings.HasPrefix(f[1], "v") {
			out[f[0]] = f[1]
		}
	}
	return out
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/commit/`
Expected: FAIL with `undefined: vaulttest.Content` (then `c.Entries undefined`, `c.Certs undefined`) in `internal/commit`. `go vet -tags realdata ./internal/integration/` fails too, with `want.Certs undefined (type map[string][]vaulttest.Entry has no field or method Certs)`.

- [ ] **Step 3: Implement**

Replace `internal/vaulttest/vaulttest.go` with:

```go
// Package vaulttest checks a vault the way the crash suite needs (spec
// §13.5) and compares a recovered vault with a clean one (amendment A1 §7).
// It is test infrastructure: production binaries never import it.
package vaulttest

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	_ "github.com/duckdb/duckdb-go/v2" // the "duckdb" database/sql driver

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/vault"
)

// Vault is a vault root and its vault directories.
type Vault struct {
	Root string
	Dirs []string
	UUID [16]byte
}

// reader opens the vault's records with every dictionary loaded.
func (v Vault) reader(t testing.TB) *vault.Reader {
	t.Helper()
	c, err := vault.NewCodec()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	ds, err := vault.LoadDicts(v.Dirs)
	if err != nil {
		t.Fatalf("dictionaries: %v", err)
	}
	for _, d := range ds {
		if err := c.AddDict(d.Manifest.ID, d.Content); err != nil {
			t.Fatal(err)
		}
	}
	r, err := vault.OpenReader(v.Dirs, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

// record is a vault record with its certificate's SHA-256.
type record struct {
	loc    vault.Loc
	certID uint64
	sha    [32]byte
	kind   byte
	base   [2]uint64 // a leaf-delta's base record: segment, offset
}

// scan reads the records in [from, to), resolving each to its SHA-256. A
// torn record ends the scan when torn is allowed.
func (v Vault) scan(t testing.TB, from, to vault.Tail, torn bool) []record {
	t.Helper()
	r := v.reader(t)
	var out []record
	err := vault.Scan(v.Dirs, from, to, func(loc vault.Loc, rec vault.Record) error {
		der, _, err := r.Read(loc)
		if err != nil {
			return err
		}
		out = append(out, record{loc, rec.CertID, sha256.Sum256(der), rec.Kind, [2]uint64{rec.BaseSeg, rec.BaseOff}})
		return nil
	})
	if err != nil && !(torn && errors.Is(err, vault.ErrTorn)) {
		t.Fatalf("reading the vault: %v", err)
	}
	return out
}

// BeyondTail returns the cert_id and SHA-256 of every record past the
// committed tail, up to a torn record: what recovery will truncate.
func (v Vault) BeyondTail(t testing.TB) map[uint64][32]byte {
	t.Helper()
	ms, err := commit.ListCommitted(v.Root)
	if err != nil {
		t.Fatal(err)
	}
	var tail vault.Tail
	if len(ms) > 0 {
		tail = ms[len(ms)-1].Vault.End
	}
	segs, err := vault.FindSegments(v.Dirs)
	if err != nil {
		t.Fatal(err)
	}
	out := map[uint64][32]byte{}
	if len(segs) == 0 {
		return out
	}
	last := slices.Max(slices.Collect(maps.Keys(segs)))
	for _, rec := range v.scan(t, tail, vault.Tail{Segment: last, Offset: math.MaxInt64}, true) {
		out[rec.certID] = rec.sha
	}
	return out
}

// Assignments returns the cert_id and SHA-256 of every record in the
// segments, beyond the committed tail too, up to a torn record. Called after
// a kill and before recovery, it sees what the killed attempt assigned.
func (v Vault) Assignments(t testing.TB) map[uint64][32]byte {
	t.Helper()
	segs, err := vault.FindSegments(v.Dirs)
	if err != nil {
		t.Fatal(err)
	}
	out := map[uint64][32]byte{}
	if len(segs) == 0 {
		return out
	}
	last := slices.Max(slices.Collect(maps.Keys(segs)))
	for _, rec := range v.scan(t, vault.Tail{}, vault.Tail{Segment: last, Offset: math.MaxInt64}, true) {
		if prev, dup := out[rec.certID]; dup && prev != rec.sha {
			t.Fatalf("cert_id %d holds two different certificates in one vault", rec.certID)
		}
		out[rec.certID] = rec.sha
	}
	return out
}

func fileSHA256(t testing.TB, p string) string {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Committed is what a reader snapshot sees: every directory under
// dataset/log=*/ must be a committed batch whose files match _COMMIT.json
// byte for byte, so no partial batch is ever visible. It returns each
// batch directory's _COMMIT.json.
func (v Vault) Committed(t testing.TB) map[string][]byte {
	t.Helper()
	ms, err := commit.ListCommitted(v.Root)
	if err != nil {
		t.Fatalf("committed batches: %v", err)
	}
	paths := commit.Paths{Root: v.Root}
	out := map[string][]byte{}
	for _, m := range ms {
		dir := paths.BatchDir(m.ID())
		for name, fi := range m.Files {
			if got := fileSHA256(t, filepath.Join(dir, name)); got != fi.SHA256 {
				t.Fatalf("%s/%s does not match its checksum", dir, name)
			}
		}
		b, err := os.ReadFile(filepath.Join(dir, commit.ManifestFile))
		if err != nil {
			t.Fatal(err)
		}
		out[dir] = b
	}
	logs, _ := filepath.Glob(filepath.Join(v.Root, "dataset", "*", "*"))
	for _, d := range logs {
		if _, ok := out[d]; !ok {
			t.Fatalf("%s is visible under dataset/ but is not a committed batch", d)
		}
	}
	return out
}

// CheckRecovered asserts spec §13.5's invariants on a vault whose writer
// has opened (recovered) and closed it:
//   - committed batches are contiguous and every file matches its checksum;
//   - the vault holds nothing beyond the committed tail, and its segments
//     are intact;
//   - every committed record has a unique cert_id and a unique certificate;
//   - Pebble agrees with the vault, and applied/<log> is each log's last
//     commit_seq;
//   - each batch's Merkle state equals a recomputation from entries.parquet;
//   - only intents marked abandoned remain, for uncommitted batches, and
//     tmp/ holds only empty stage/ and rebuild/;
//   - no interrupted atomic write left its temp file anywhere.
func (v Vault) CheckRecovered(t testing.TB) {
	t.Helper()
	v.Committed(t)
	ms, _ := commit.ListCommitted(v.Root)
	var tail vault.Tail
	if len(ms) > 0 {
		tail = ms[len(ms)-1].Vault.End
	}
	if u, err := vault.InspectTail(v.Dirs, tail); err != nil || u.Bytes != 0 {
		t.Fatalf("data beyond the committed tail after recovery: %+v, %v", u, err)
	}
	if err := vault.CheckSegments(v.Dirs, v.UUID, tail); err != nil {
		t.Fatal(err)
	}
	refs := map[[32]byte]index.Ref{}
	ids := map[uint64]bool{}
	for _, rec := range v.scan(t, vault.Tail{}, tail, false) {
		if ids[rec.certID] {
			t.Fatalf("cert_id %d is committed twice", rec.certID)
		}
		if _, dup := refs[rec.sha]; dup {
			t.Fatalf("certificate %x is vaulted twice", rec.sha[:8])
		}
		ids[rec.certID], refs[rec.sha] = true, index.Ref{CertID: rec.certID, Loc: rec.loc}
	}

	idx, err := index.Open(filepath.Join(v.Root, "state", "pebble"))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	n := 0
	err = idx.EachCert(func(sha [32]byte, r index.Ref) error {
		if want, ok := refs[sha]; !ok || want != r {
			return fmt.Errorf("pebble has %x → %+v, the vault %+v (%v)", sha[:8], r, want, ok)
		}
		n++
		return nil
	})
	if err != nil || n != len(refs) {
		t.Fatalf("pebble and the vault disagree: %v (%d index entries, %d records)", err, n, len(refs))
	}
	last := map[string]uint64{}
	for _, m := range ms {
		last[m.Log] = m.CommitSeq
	}
	if applied, err := idx.AppliedLogs(); err != nil || !maps.Equal(applied, last) {
		t.Fatalf("applied %v, want %v (%v)", applied, last, err)
	}

	db := duck(t)
	states := map[string]*merkle.State{}
	paths := commit.Paths{Root: v.Root}
	for _, m := range ms {
		st, ok := states[m.Log]
		if !ok {
			st = merkle.NewState()
			states[m.Log] = st
		}
		for i, e := range entries(t, db, filepath.Join(paths.BatchDir(m.ID()), dataset.EntriesFile)) {
			if e.idx != m.First+uint64(i) {
				t.Fatalf("batch %s: row %d has index %d", m.BatchID, i, e.idx)
			}
			st.Append(e.leafHash)
		}
		want, _ := m.MerkleAfter.Root()
		if got, _ := st.Root(); got != want || st.Size() != m.Last+1 {
			t.Fatalf("batch %s: the Merkle state recomputed from entries.parquet differs from merkle_after", m.BatchID)
		}
	}

	ins, err := commit.ReadIntents(commit.Paths{Root: v.Root})
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range ins {
		if _, err := os.Stat(filepath.Join(paths.BatchDir(in.ID()), commit.ManifestFile)); !in.Abandoned || err == nil {
			t.Fatalf("intent of %s left after recovery (abandoned=%v, committed=%v)", in.BatchID, in.Abandoned, err == nil)
		}
	}
	filepath.WalkDir(v.Root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && fsutil.IsAtomicTemp(d.Name()) {
			t.Errorf("an interrupted write's temp file survived recovery: %s", p)
		}
		return nil
	})
	var tmp []string
	filepath.WalkDir(filepath.Join(v.Root, "tmp"), func(p string, d os.DirEntry, err error) error {
		if rel, _ := filepath.Rel(v.Root, p); err == nil && rel != "tmp" {
			tmp = append(tmp, rel)
		}
		return nil
	})
	if !slices.Equal(tmp, []string{"tmp/rebuild", "tmp/stage"}) {
		t.Fatalf("tmp/ after recovery: %v", tmp)
	}
	v.CheckDerived(t)
}

func duck(t testing.TB) *sql.DB {
	t.Helper()
	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

type row struct {
	idx                uint64
	ts                 sql.Null[int64]
	typ                string
	certID             sql.Null[uint64]
	leafHash           [32]byte
	ikey, ikh, chainID []byte
	leafErr            sql.Null[string]
}

func entries(t testing.TB, db *sql.DB, path string) []row {
	t.Helper()
	rs, err := db.Query(`SELECT idx, epoch_ms(ct_ts), entry_type, cert_id, leaf_hash, issuance_key, issuer_key_hash, chain_id, leaf_error
		FROM read_parquet(` + quote(path) + `) ORDER BY idx`)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	var out []row
	for rs.Next() {
		var r row
		var lh []byte
		if err := rs.Scan(&r.idx, &r.ts, &r.typ, &r.certID, &lh, &r.ikey, &r.ikh, &r.chainID, &r.leafErr); err != nil {
			t.Fatal(err)
		}
		copy(r.leafHash[:], lh)
		out = append(out, r)
	}
	if err := rs.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// Entry is one log entry's content without internal IDs: certificates and
// chains are given by SHA-256 (hex), and NULL fields are empty.
type Entry struct {
	Idx           uint64
	LeafHash      string
	Timestamp     string // milliseconds, "" when NULL
	Type          string
	IssuanceKey   string
	IssuerKeyHash string
	LeafError     string
	Cert          string
	Chain         []string
}

// Content is a vault's committed content without internal IDs: its entries
// by log, in index order, and the derived rows of each certificate by
// SHA-256 (hex).
type Content struct {
	Entries map[string][]Entry
	Certs   map[string]string
}

// Dump returns the vault's committed content. A recovered ingest must equal
// a clean one on all of it; only cert_id, chain_id and vault locations may
// differ (amendment A1 §7, A2 §4). Dump also checks that every reference
// resolves: each cert_id to one vault record, each chain_id to positions
// 0..n-1 written by exactly one batch, and every committed record is
// referenced.
func (v Vault) Dump(t testing.TB) Content {
	t.Helper()
	ms, err := commit.ListCommitted(v.Root)
	if err != nil {
		t.Fatal(err)
	}
	var tail vault.Tail
	if len(ms) > 0 {
		tail = ms[len(ms)-1].Vault.End
	}
	certs := map[uint64]string{}
	for _, rec := range v.scan(t, vault.Tail{}, tail, false) {
		certs[rec.certID] = hex.EncodeToString(rec.sha[:])
	}
	used := map[uint64]bool{}
	cert := func(id uint64) string {
		s, ok := certs[id]
		if !ok {
			t.Fatalf("cert_id %d is referenced but not in the committed vault", id)
		}
		used[id] = true
		return s
	}

	db := duck(t)
	paths := commit.Paths{Root: v.Root}
	chains := map[string][]uint64{}
	for _, m := range ms {
		rs, err := db.Query(`SELECT chain_id, position, cert_id FROM read_parquet(` + quote(filepath.Join(paths.BatchDir(m.ID()), dataset.ChainsFile)) + `) ORDER BY chain_id, position`)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for rs.Next() {
			var id []byte
			var pos uint16
			var c uint64
			if err := rs.Scan(&id, &pos, &c); err != nil {
				t.Fatal(err)
			}
			k := string(id)
			if !seen[k] && len(chains[k]) > 0 {
				t.Fatalf("chain %x is written by two batches", id[:4])
			}
			if seen[k] = true; int(pos) != len(chains[k]) {
				t.Fatalf("chain %x: position %d out of order", id[:4], pos)
			}
			chains[k] = append(chains[k], c)
		}
		rs.Close()
	}

	out := map[string][]Entry{}
	for _, m := range ms {
		for _, r := range entries(t, db, filepath.Join(paths.BatchDir(m.ID()), dataset.EntriesFile)) {
			e := Entry{Idx: r.idx, LeafHash: hex.EncodeToString(r.leafHash[:]), Type: r.typ,
				IssuanceKey: hex.EncodeToString(r.ikey), IssuerKeyHash: hex.EncodeToString(r.ikh), LeafError: r.leafErr.V}
			if r.ts.Valid {
				e.Timestamp = fmt.Sprint(r.ts.V)
			}
			if r.certID.Valid {
				e.Cert = cert(r.certID.V)
			}
			if r.chainID != nil {
				ids, ok := chains[string(r.chainID)]
				if !ok {
					t.Fatalf("entry %d: chain %x has no chains.parquet rows", r.idx, r.chainID[:4])
				}
				e.Chain = []string{}
				for _, id := range ids {
					e.Chain = append(e.Chain, cert(id))
				}
			}
			out[m.Log] = append(out[m.Log], e)
		}
	}
	for id := range certs {
		if !used[id] {
			t.Fatalf("committed record cert_id %d is referenced by no entry or chain", id)
		}
	}
	return Content{Entries: out, Certs: v.derived(t, db, ms)}
}

// derived renders each certificate's derived rows without internal IDs: the
// batch that built them, its certs row without cert_id, vault location and
// delta base (whether a final is a leaf-delta depends on the delta cache;
// CheckDerived checks it against the vault), then its names rows in order.
func (v Vault) derived(t testing.TB, db *sql.DB, ms []commit.Manifest) map[string]string {
	t.Helper()
	internal := map[string]bool{"cert_id": true, "vault_seg": true, "vault_off": true, "vault_len": true, "delta_base_cert_id": true}
	var cols, ncols []string
	for _, c := range derive.CertsV1.Columns {
		if !internal[c.Name] {
			cols = append(cols, c.Name)
		}
	}
	for _, c := range derive.NamesV1.Columns {
		if !internal[c.Name] {
			ncols = append(ncols, c.Name)
		}
	}
	out := map[string]string{}
	paths := commit.Paths{Root: v.Root}
	for _, m := range ms {
		if m.Builders[derive.CertsV1.Name] != derive.CertsV1.Version {
			continue
		}
		dir := paths.BatchDir(m.ID())
		names := map[uint64][]string{}
		for _, r := range rendered(t, db, `SELECT cert_id, '', CAST(struct_pack(`+strings.Join(ncols, ", ")+`) AS VARCHAR) FROM read_parquet(`+
			quote(filepath.Join(dir, derive.NamesV1.File()))+`, file_row_number = true) ORDER BY file_row_number`) {
			names[r.id] = append(names[r.id], r.text)
		}
		for _, r := range rendered(t, db, `SELECT cert_id, sha256, CAST(struct_pack(`+strings.Join(cols, ", ")+`) AS VARCHAR) FROM read_parquet(`+
			quote(filepath.Join(dir, derive.CertsV1.File()))+`) ORDER BY cert_id`) {
			if _, dup := out[r.sha]; dup {
				t.Fatalf("certificate %s has certs rows in two batches", r.sha)
			}
			out[r.sha] = fmt.Sprintf("batch %s %s names [%s]", m.BatchID, r.text, strings.Join(names[r.id], "; "))
		}
	}
	return out
}

type renderedRow struct {
	id        uint64
	sha, text string
}

func rendered(t testing.TB, db *sql.DB, q string) []renderedRow {
	t.Helper()
	rs, err := db.Query(q)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	var out []renderedRow
	for rs.Next() {
		var r renderedRow
		if err := rs.Scan(&r.id, &r.sha, &r.text); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rs.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// Diff describes the first difference between two dumps, "" if equal.
func Diff(gotC, wantC Content) string {
	got, want := gotC.Entries, wantC.Entries
	for _, log := range slices.Sorted(maps.Keys(want)) {
		g, w := got[log], want[log]
		for i := range min(len(g), len(w)) {
			if a, b := fmt.Sprintf("%+v", g[i]), fmt.Sprintf("%+v", w[i]); a != b {
				return fmt.Sprintf("log %s entry %d:\n got  %s\n want %s", log, w[i].Idx, a, b)
			}
		}
		if len(g) != len(w) {
			return fmt.Sprintf("log %s: %d entries, want %d", log, len(g), len(w))
		}
	}
	if len(got) != len(want) {
		return fmt.Sprintf("%d logs, want %d", len(got), len(want))
	}
	for _, sha := range slices.Sorted(maps.Keys(wantC.Certs)) {
		if g, w := gotC.Certs[sha], wantC.Certs[sha]; g != w {
			return fmt.Sprintf("certificate %s derived rows:\n got  %s\n want %s", sha, g, w)
		}
	}
	if len(gotC.Certs) != len(wantC.Certs) {
		return fmt.Sprintf("%d certificates with derived rows, want %d", len(gotC.Certs), len(wantC.Certs))
	}
	return ""
}

// CheckDerived asserts amendment A2 §4's derived files. In every committed
// batch that built certs, each vault record the batch wrote has exactly
// one certs row, in order: its cert_id, location and DER SHA-256, a kind
// that matches the record (chain; precert or final for a full leaf; final
// for a leaf-delta) and, for a leaf-delta, its base record's cert_id. Every
// names row belongs to one of the batch's certificates.
func (v Vault) CheckDerived(t testing.TB) {
	t.Helper()
	ms, err := commit.ListCommitted(v.Root)
	if err != nil || len(ms) == 0 {
		return
	}
	idAt := map[[2]uint64]uint64{}
	for _, r := range v.scan(t, vault.Tail{}, ms[len(ms)-1].Vault.End, false) {
		idAt[[2]uint64{r.loc.Segment, r.loc.Offset}] = r.certID
	}
	db := duck(t)
	paths := commit.Paths{Root: v.Root}
	for _, m := range ms {
		if m.Builders[derive.CertsV1.Name] != derive.CertsV1.Version {
			continue
		}
		dir := paths.BatchDir(m.ID())
		certs := quote(filepath.Join(dir, derive.CertsV1.File()))
		rows, err := db.Query(`SELECT cert_id, sha256, kind, vault_seg, vault_off, vault_len, coalesce(delta_base_cert_id, 0) FROM read_parquet(` + certs + `) ORDER BY cert_id`)
		if err != nil {
			t.Fatal(err)
		}
		recs := v.scan(t, m.Vault.Start, m.Vault.End, false)
		i := 0
		for ; rows.Next(); i++ {
			var id, off, base uint64
			var seg, length uint32
			var sha, kind string
			if err := rows.Scan(&id, &sha, &kind, &seg, &off, &length, &base); err != nil {
				t.Fatal(err)
			}
			if i >= len(recs) {
				t.Fatalf("batch %s: certs has more rows than the %d records it vaulted", m.BatchID, len(recs))
			}
			r := recs[i]
			wantKind := map[byte][]string{vault.KindLeaf: {"precert", "final"}, vault.KindDelta: {"final"}, vault.KindChain: {"chain"}}[r.kind]
			wantBase := uint64(0)
			if r.kind == vault.KindDelta {
				wantBase = idAt[r.base]
			}
			if id != r.certID || sha != hex.EncodeToString(r.sha[:]) || uint64(seg) != r.loc.Segment || off != r.loc.Offset ||
				length != r.loc.Len || !slices.Contains(wantKind, kind) || base != wantBase {
				t.Fatalf("batch %s: certs row %d (cert_id %d, %s at %d:%d+%d, base %d) differs from vault record %+v (base %d)",
					m.BatchID, i, id, kind, seg, off, length, base, r, wantBase)
			}
		}
		rows.Close()
		if i != len(recs) {
			t.Fatalf("batch %s: %d certs rows for %d vault records", m.BatchID, i, len(recs))
		}
		var orphans int
		names := quote(filepath.Join(dir, derive.NamesV1.File()))
		if err := db.QueryRow(`SELECT count(*) FROM read_parquet(` + names + `) WHERE cert_id NOT IN (SELECT cert_id FROM read_parquet(` + certs + `))`).Scan(&orphans); err != nil || orphans > 0 {
			t.Fatalf("batch %s: %d names rows of no certificate in the batch (%v)", m.BatchID, orphans, err)
		}
	}
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race -count=1 ./internal/commit/`
Expected: PASS.

- [ ] **Step 5: Run the real-data layer**

Run: `go test -tags realdata -timeout 90m -count=1 -v -run 'CanonicalIngest|RecoveryEquivalence' ./internal/integration/`
Expected: PASS. `TestCanonicalIngestEndToEnd` logs `ingested 100000 entries in` about 4 minutes and `derived: 100573 certs rows, 186756 names rows (185772 dns_valid), 100000 entries joined to certs`; `TestRecoveryEquivalenceOnRealData` logs `5 crashes recovered; 6 batches equal a clean ingest of 30000 real entries`.

- [ ] **Step 6: Quality gate**

- [ ] **Step 7: Checkpoint.**
