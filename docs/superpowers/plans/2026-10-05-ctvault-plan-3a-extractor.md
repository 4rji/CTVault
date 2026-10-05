# CTVault Plan 3A (Extractor) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A lenient, deterministic X.509 field extractor that never drops a certificate. Every field is read on its own, and a malformed field adds a stable error code while the rest are still read. It comes with `ctvault explain-error`, and its tests are:
- a golden corpus of real certificates;
- a malformed corpus;
- a differential check against `crypto/x509`;
- fuzzing.

**Architecture:**
- **The package:** a new `internal/extract`. `Parse(der) *Cert` reads the certificate and TBS structure, then each field independently with `golang.org/x/crypto/cryptobyte`.
- **Names** keep their exact DER as identity. Their RFC 4514 rendering is for display only.
- **Error codes** are a catalog compiled into the binary, frozen by a test so codes are only ever added.
- **Scope:** nothing in ingest changes. The `certs` and `names` builders that use the extractor arrive in Plan 3B.

**Tech Stack:** Go 1.26.8. No new modules: `golang.org/x/crypto/cryptobyte` and `klauspost/compress` (test data only) are already pinned.

**Spec:**
- `docs/superpowers/specs/2026-10-04-ctvault-design.md` §7.1, §11.2 (`explain-error`), §13 items 2–3 ("the spec")
- **Amendment A2:** `docs/superpowers/specs/2026-10-04-ctvault-plan3-amendment.md` §3 (approved 2026-10-05)

It builds on Plan 2C as applied to the working tree.

## Global Constraints

- **Platform:** Linux only, `go 1.26.8`, cgo (unchanged).
- **No new dependencies.**
- **Production safety is unchanged.** `explain-error` is a production command and reads no environment variable.
- **"No certificate is ever dropped"** (spec §7.1). `Parse` never fails and never panics. `parse_status` is `ok`, `partial` or `failed`, and `failed` means "the outer `Certificate` or the `TBSCertificate` cannot be read" (amendment A2 §3.1).
- **Names:** "`Name.Raw` holds the exact DER bytes … They are the name's reproducible identity", and the RFC 4514 rendering is "a deterministic display and search representation only, never an identity" (amendment A2 §3.2).
- **Error codes** are "stable, compact strings in a catalog compiled into the binary … codes are only ever added, never renamed or removed" (amendment A2 §3.3).
- **Determinism:** "extraction is a pure function of the DER. No map iteration order and no clock affect it" (amendment A2 §3.3).
- **Quality gates, for every task:**
  - `gofmt -l .` prints nothing;
  - `go vet` is clean with no tags and with `ctvault_dev`, `realdata` and `nightly`;
  - `go test -race ./...` and `go test -race -tags ctvault_dev ./...` pass.
- **Temp space:** on this machine, use `GOCACHE=/mnt/disk/ctvault/gocache GOTMPDIR=/mnt/disk/ctvault/gotmp TMPDIR=/mnt/disk/ctvault/tmp`.

## Review Focus

1. **A certificate `crypto/x509` rejects** (a negative serial, a time without seconds, a duplicate extension).
   - Expected: it is still extracted, `partial`, with the precise code, and every other field read.
   - Pinned by `TestSerialChecks`, `TestValidityTimes` (Task A3), `TestExtensionProblems` (Task A4) and `TestMalformedCorpus` (Task A5).
2. **Names with undecodable or unusual strings** (invalid UTF-8, odd-length BMPString, Teletex, control characters).
   - Expected: a deterministic rendering with `\XX` escapes, `name_bad_string` when the bytes are invalid for the type, and `Raw` untouched.
   - Pinned by `TestNameRendering` (Task A2) and `TestMalformedCorpus` (Task A5).
3. **A subject with several CNs.**
   - Expected: `First` returns the first in DER order, and `String` shows them all. `crypto/x509` keeps the last, so the differential check compares CN only when there is exactly one.
   - Pinned by `TestNameFirst` (Task A2) and `compareX509` (Task A5).
4. **Arbitrary bytes** (truncated, garbage, adversarial).
   - Expected: no panic, the same result twice, and a status that agrees with the codes.
   - Pinned by `FuzzParse` (Task A5).
5. **Unknown algorithms** (signature, public key, curve).
   - Expected: reported by dotted OID, with no code and no failure.
   - Pinned by `TestSignatureAlgorithm`, `TestPublicKeys` (Task A3) and `TestMalformedCorpus` (Task A5).

## Decisions This Plan Adds

These choices are **not** in the approved sections. They were settled while building and testing this plan. Review them.

| # | Decision | Why |
|---|---|---|
| 1 | **The catalog has 28 codes**, frozen in `internal/cli/testdata/error_codes.txt` together with the 13 leaf codes. Codes beyond A2's examples: `cert_trailing_data`, `signature_unreadable`, `tbs_extra_fields`, `serial_not_minimal`, `serial_unreadable`, `sig_alg_unreadable`, `issuer_unreadable`, `subject_unreadable`, `validity_unreadable`, `spki_unreadable`, `key_unreadable`, `extensions_unreadable`, `ext_unreadable`, `san_unreadable`, `san_dns_bad_string`, `aki_unreadable` and `ski_unreadable`. | Each names exactly one field that could not be read, so a reader of `certs.parse_errors` knows which column is missing and why. |
| 2 | **`explain-error` also explains the 13 leaf codes**, labelled "(log entry error)" against "(certificate parse error)". An unknown code exits 2. | Spec §11.2: "Explain a parse or leaf error code". |
| 3 | **`failed` only when the structure is unreadable:** the outer SEQUENCE, the TBS element, or the six fixed TBS fields (counted without the optional trailing `[1]`, `[2]` and `[3]`). An unreadable outer signature is `signature_unreadable` and `partial`, and every field is still read. | The certificate's content is in the TBS. Losing the signature value must not hide it. |
| 4 | **Display values** (`First`, DNS SANs) keep characters as they are, except that a backslash is doubled and control characters and undecodable bytes become `\XX`. **The RFC 4514 rendering** adds RFC 4514 §2.4's escapes and writes non-string values as `#` plus hex. | Deterministic, unambiguous and readable. A literal `\XX` in a value can never be confused with an escape. |
| 5 | **Times accept only RFC 5280's formats** (`YYMMDDHHMMSSZ`, `YYYYMMDDHHMMSSZ`). Anything else is null plus `time_bad_format`, even forms `crypto/x509` accepts (no seconds, offsets). | A2 §3.3: "parsed strictly". The raw DER keeps the original. |
| 6 | **Extensions:** a single malformed extension is skipped (`ext_unreadable`) and the rest are read. A repeated OID is listed every time, but the first occurrence is the one decoded (`ext_duplicate`). An unreadable SAN yields no names at all. | A partial SAN list could look complete; none at all is unambiguous. |
| 7 | **Key sizes:** EC sizes come from the named curve, or from the point length for an unknown curve. Explicit curve parameters give `key_unreadable`. RSASSA-PSS keys are reported as `rsa`. DSA without parameters (inherited) has 0 bits and no code. | What `certs.key_bits` and `key_curve` need, with nothing guessed. |
| 8 | **The golden corpus** is 2,000 leaves (one in every 100 distinct per sample) plus all 710 distinct chain certificates. It is 1.9 MB compressed, against A2's "about 1.5 MB". It is generated from the cached samples by a `realdata` test and checked in; regeneration is byte-identical. | Every chain certificate keeps CA coverage. Keeping only 1 in 100 leaves holds the size down. |
| 9 | **The differential check:** CN and O are compared only when the value is plain ASCII (`crypto/x509` reads TeletexString as raw bytes), CN only when there is exactly one, and IP SANs only when their lengths are valid. A CN or O that `crypto/x509` finds and the extractor does not is always a difference. | It compares where the two parsers define the same thing, and nowhere else. |

## Evidence Behind This Plan (measured 2026-10-05)

1. **Every certificate of both cached samples**, 200,000 leaves and 710 chain certificates:
   - 200,705 are `ok` and 5 `partial`, all `serial_zero`. Those are real roots (Starfield, Go Daddy, SECOM) whose serial is 0.
   - **All 200,710 were compared with `crypto/x509`, with 0 differences**, in 38 s.
2. **The golden corpus** (2,710 certificates): stable, deterministic under concurrent runs, and with 0 differences against `crypto/x509`.
3. **The malformed corpus:** 27 deterministic cases, each producing its code.
4. **Fuzzing:** 13.8 million executions in 3 minutes, plus 60 s in the final gate, with no failure.
5. **Speed:** `Parse` takes 9.6 µs per certificate (6.2 KB, 84 allocations), about 5 s for a 500,000-certificate batch.
6. **Mutations caught:**
   - an RSA modulus one bit too long, caught by the differential check;
   - a CN that is never found, caught by the differential check;
   - an O that is never found, caught by the golden file.
7. **Found while writing this plan:**
   - **A position bug** (Task A3): with the public key missing, the extensions field was read as the key. Fixed by counting the fixed fields without the optional trailing ones.
   - **A test gap** (Task A5): the golden file lacked the CN and O values, so a broken `First` went unnoticed. It now records `issuer_cn`, `issuer_o` and `subject_cn`, and the differential check flags a missing CN or O.
   - **A field-independence bug** (Task A3, found by the final review of the native execution): an optional element after the six fixed fields whose length ran past the TBS made the whole certificate `failed`, losing fields that were readable (amendment A2 §3.1).
     - **Fix:** once the fixed fields are delimited, an unreadable tail is `extensions_unreadable` and `partial`.
     - **Pinned by** `TestParseFailsOnlyOnStructure` (RED: `failed [tbs_unreadable]` with the key lost) and by the malformed case "extensions field running past the TBS".

## Before You Start

- Work from the repository root, with Plan 2C applied.
- **Task A5's test data** comes from the cached samples:
  - `~/.cache/ctvault-dev/samples/argon2027h1/000000000000-000000099999`
  - `~/.cache/ctvault-dev/samples/argon2027h1/000397220000-000397319999`
- **Expected checksums of the generated files:**

  | File | SHA-256 |
  |---|---|
  | `internal/extract/testdata/corpus.bin.zst` | `d9f441ada7834c7d823062b05139a320e3e967aa92eb9788f0e245a61a5be089` |
  | `internal/extract/testdata/corpus.golden.zst` | `63fa5bae10fc047f2d1b718494320a0595045e63095fe2aceb67fd362b0195f1` |
  | `internal/extract/testdata/malformed.golden` | `d4c7f48d32124eba4b2d64fc5399d9dece8da045bdf50f6f96ece74d6e529e23` |

## File Structure

```text
internal/extract/codes.go     Code, the catalog (Codes) and Explain
internal/extract/name.go      Name (Raw DER, RDNs), string decoding, RFC 4514 rendering, First
internal/extract/algs.go      signature algorithm names, key algorithm OIDs, named curves
internal/extract/key.go       Key and SubjectPublicKeyInfo parsing
internal/extract/cert.go      Status, Cert and Parse: structure, version, serial, signature, names, validity
internal/extract/ext.go       Extension: the list, duplicates, SAN, AKI, SKI, CT poison
internal/extract/testdata/    corpus.bin.zst (real certificates), corpus.golden.zst, malformed.golden
internal/leaf/leaf.go         + Code.Explain for the leaf codes
internal/cli/explain.go       ctvault explain-error <code>
internal/cli/testdata/error_codes.txt   every published code (frozen)
```

---

### Task A1: The error-code catalog and `explain-error`

Spec §7.1 and §11.2, amendment A2 §3.3.

**Files:**
- Create: `internal/extract/codes.go`, `internal/cli/explain.go`, `internal/cli/testdata/error_codes.txt`
- Modify: `internal/leaf/leaf.go` (explanations), `internal/cli/cli.go` (registers the command)
- Tests: `internal/extract/codes_test.go`, `internal/leaf/explain_test.go`, `internal/cli/explain_test.go`

**Interfaces:**
- Produces:
  - `extract.Code`, the code constants, `extract.Codes []Code`, `(Code).Explain() string`;
  - `(leaf.Code).Explain() string`;
  - the command `ctvault explain-error <code>`.

- [ ] **Step 1: Write the failing tests**

Create `internal/extract/codes_test.go`:

```go
package extract

import (
	"regexp"
	"testing"
)

var codeFormat = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// TestEveryCodeIsExplained: each parse error code is listed once, is a
// compact lowercase identifier, and has an explanation for explain-error.
func TestEveryCodeIsExplained(t *testing.T) {
	seen := map[Code]bool{}
	for _, c := range Codes {
		if seen[c] {
			t.Errorf("%s is listed twice", c)
		}
		seen[c] = true
		if !codeFormat.MatchString(string(c)) {
			t.Errorf("%q is not a compact lowercase code", c)
		}
		if c.Explain() == "" {
			t.Errorf("%s has no explanation", c)
		}
	}
	if Code("no_such_code").Explain() != "" {
		t.Error("an unknown code has an explanation")
	}
}
```

Create `internal/leaf/explain_test.go`:

```go
package leaf

import "testing"

// TestEveryLeafCodeIsExplained: explain-error covers the leaf codes too
// (spec §11.2: "Explain a parse or leaf error code").
func TestEveryLeafCodeIsExplained(t *testing.T) {
	for _, c := range Codes {
		if c.Explain() == "" {
			t.Errorf("%s has no explanation", c)
		}
	}
	if Code("no_such_code").Explain() != "" || OK.Explain() != "" {
		t.Error("an unknown or empty code has an explanation")
	}
}
```

Create `internal/cli/explain_test.go`:

```go
package cli

import (
	"bufio"
	"os"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/extract"
	"github.com/4rji/ctvault/internal/leaf"
)

func TestExplainError(t *testing.T) {
	e := newEnv(t, nil)
	if out := e.mustRun("explain-error", "serial_negative"); !strings.Contains(out, "serial_negative (certificate parse error): ") {
		t.Fatalf("output: %q", out)
	}
	if out := e.mustRun("explain-error", "leaf_bad_version"); !strings.Contains(out, "leaf_bad_version (log entry error): ") {
		t.Fatalf("output: %q", out)
	}
	if code := e.run("explain-error", "no_such_code"); code != exitcode.Usage || !strings.Contains(e.stderr.String(), "unknown error code") {
		t.Fatalf("unknown code: exit %d, %s", code, e.stderr)
	}
	if code := e.run("explain-error"); code != exitcode.Usage {
		t.Fatalf("no code: exit %d", code)
	}
}

// TestErrorCodesAreFrozen: error codes are stored in datasets
// (certs.parse_errors, entries.leaf_error), so a published code is never
// renamed or removed (amendment A2 §3.3). testdata/error_codes.txt lists
// every published code; a new code is appended to it.
func TestErrorCodesAreFrozen(t *testing.T) {
	f, err := os.Open("testdata/error_codes.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	listed := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		catalog, code, ok := strings.Cut(line, " ")
		var explained bool
		switch catalog {
		case "extract":
			explained = extract.Code(code).Explain() != ""
		case "leaf":
			explained = leaf.Code(code).Explain() != ""
		}
		if !ok || !explained {
			t.Errorf("published code %q no longer exists", line)
		}
		listed[line] = true
	}
	for _, c := range extract.Codes {
		if !listed["extract "+string(c)] {
			t.Errorf("new code %s: append \"extract %s\" to testdata/error_codes.txt", c, c)
		}
	}
	for _, c := range leaf.Codes {
		if !listed["leaf "+string(c)] {
			t.Errorf("new code %s: append \"leaf %s\" to testdata/error_codes.txt", c, c)
		}
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/extract/ ./internal/leaf/ ./internal/cli/`
Expected: FAIL with `c.Explain undefined (type Code has no field or method Explain)` in `internal/leaf`, `undefined: Code` in `internal/extract`, and in `internal/cli` `no required module provides package github.com/4rji/ctvault/internal/extract`.

- [ ] **Step 3: Implement**

Create `internal/extract/codes.go`:

```go
// Package extract reads the fields of an X.509 certificate leniently (spec
// §7.1, amendment A2 §3): each field is read on its own with cryptobyte, a
// malformed field adds a stable error code and extraction goes on, and no
// certificate is ever dropped. The result depends only on the DER bytes.
package extract

// Code is a stable parse error code, stored in certs.parse_errors. Codes are
// only ever added: a published code is never renamed or removed.
type Code string

const (
	// The certificate's structure.
	CertUnreadable   Code = "cert_unreadable"
	CertTrailingData Code = "cert_trailing_data"
	TBSUnreadable    Code = "tbs_unreadable"
	VersionBad       Code = "version_bad"

	// Serial number.
	SerialUnreadable Code = "serial_unreadable"
	SerialNegative   Code = "serial_negative"
	SerialZero       Code = "serial_zero"
	SerialTooLong    Code = "serial_too_long"
	SerialNotMinimal Code = "serial_not_minimal"

	// Signature algorithm.
	SigAlgUnreadable Code = "sig_alg_unreadable"
	SigAlgMismatch   Code = "sig_alg_mismatch"

	// Names.
	IssuerUnreadable  Code = "issuer_unreadable"
	SubjectUnreadable Code = "subject_unreadable"
	NameBadString     Code = "name_bad_string"

	// Validity.
	ValidityUnreadable Code = "validity_unreadable"
	TimeBadFormat      Code = "time_bad_format"

	// Public key.
	SPKIUnreadable Code = "spki_unreadable"
	KeyUnreadable  Code = "key_unreadable"

	// Extensions.
	ExtensionsUnreadable Code = "extensions_unreadable"
	ExtUnreadable        Code = "ext_unreadable"
	ExtDuplicate         Code = "ext_duplicate"
	SANUnreadable        Code = "san_unreadable"
	SANIPBadLen          Code = "san_ip_bad_len"
	SANDNSBadString      Code = "san_dns_bad_string"
	AKIUnreadable        Code = "aki_unreadable"
	SKIUnreadable        Code = "ski_unreadable"
)

// Codes lists every code in a fixed order, for docs and explain-error.
var Codes = []Code{CertUnreadable, CertTrailingData, TBSUnreadable, VersionBad,
	SerialUnreadable, SerialNegative, SerialZero, SerialTooLong, SerialNotMinimal,
	SigAlgUnreadable, SigAlgMismatch, IssuerUnreadable, SubjectUnreadable, NameBadString,
	ValidityUnreadable, TimeBadFormat, SPKIUnreadable, KeyUnreadable,
	ExtensionsUnreadable, ExtUnreadable, ExtDuplicate, SANUnreadable, SANIPBadLen, SANDNSBadString,
	AKIUnreadable, SKIUnreadable}

var explanations = map[Code]string{
	CertUnreadable:   "The certificate is not a DER SEQUENCE of TBSCertificate, signatureAlgorithm and signature. Nothing else can be read; parse_status is failed.",
	CertTrailingData: "Bytes follow the certificate's DER encoding. They are ignored; the certificate itself is read.",
	TBSUnreadable:    "The TBSCertificate's fixed fields (serial, signature, issuer, validity, subject, subjectPublicKeyInfo) cannot be located. parse_status is failed.",
	VersionBad:       "The explicit version is not v1, v2 or v3 (0, 1 or 2), or cannot be read.",

	SerialUnreadable: "The serialNumber is not a readable INTEGER.",
	SerialNegative:   "The serialNumber is negative; RFC 5280 §4.1.2.2 requires a positive integer. Its raw content bytes are kept.",
	SerialZero:       "The serialNumber is zero; RFC 5280 §4.1.2.2 requires a positive integer.",
	SerialTooLong:    "The serialNumber has more than 20 content octets, RFC 5280's limit. Its raw content bytes are kept.",
	SerialNotMinimal: "The serialNumber INTEGER is not minimally encoded (a redundant leading 0x00 or 0xFF), which DER forbids. Its raw content bytes are kept.",

	SigAlgUnreadable: "The signature AlgorithmIdentifier cannot be read.",
	SigAlgMismatch:   "The TBSCertificate's signature algorithm differs from the outer signatureAlgorithm (RFC 5280 §4.1.1.2).",

	IssuerUnreadable:  "The issuer is not a readable Name (a SEQUENCE of RDN SETs of attribute type and value).",
	SubjectUnreadable: "The subject is not a readable Name (a SEQUENCE of RDN SETs of attribute type and value).",
	NameBadString:     "A name attribute's value is not valid for its string type (for example invalid UTF-8, or an odd-length BMPString). It is rendered with \\XX escapes for the bad bytes.",

	ValidityUnreadable: "The validity is not a SEQUENCE of two times.",
	TimeBadFormat:      "A notBefore or notAfter value is not a valid UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ) as RFC 5280 §4.1.2.5 requires. The value is left null.",

	SPKIUnreadable: "The subjectPublicKeyInfo is not a readable SEQUENCE of an AlgorithmIdentifier and a BIT STRING.",
	KeyUnreadable:  "The public key cannot be interpreted for its algorithm (for example an RSA key without a valid modulus, or an unreadable curve). The key size and curve are left empty.",

	ExtensionsUnreadable: "The extensions field cannot be read; no extension is extracted.",
	ExtUnreadable:        "One extension is malformed: it is skipped, or its value could not be decoded.",
	ExtDuplicate:         "An extension OID appears more than once; RFC 5280 §4.2 forbids it. The first occurrence is used.",
	SANUnreadable:        "The subjectAltName value cannot be parsed; no SAN is extracted.",
	SANIPBadLen:          "An iPAddress SAN is neither 4 nor 16 bytes. It is kept as hex and is not a valid address.",
	SANDNSBadString:      "A dNSName SAN contains bytes outside ASCII (IA5String). It is rendered with \\XX escapes for the bad bytes.",
	AKIUnreadable:        "The authorityKeyIdentifier extension cannot be parsed.",
	SKIUnreadable:        "The subjectKeyIdentifier extension cannot be parsed.",
}

// Explain returns the code's explanation, or "" for an unknown code.
func (c Code) Explain() string { return explanations[c] }
```

Replace `internal/leaf/leaf.go` with:

```go
// Package leaf decodes RFC 6962 log entries: the MerkleTreeLeaf in leaf_input
// and the chain in extra_data (spec §5.4, amendment A1 §4). It never guesses:
// a field that cannot be decoded safely stays empty and the entry carries a
// stable error code. The leaf hash is always computed from the exact bytes.
package leaf

import (
	"crypto/sha256"

	"golang.org/x/crypto/cryptobyte"

	"github.com/4rji/ctvault/internal/merkle"
)

// Type is the RFC 6962 LogEntryType as CTVault records it.
type Type uint8

const (
	TypeUnknown Type = iota
	TypeX509
	TypePrecert
)

// String returns the entries.entry_type value: "x509", "precert" or "unknown".
func (t Type) String() string {
	switch t {
	case TypeX509:
		return "x509"
	case TypePrecert:
		return "precert"
	}
	return "unknown"
}

// Code is a stable error code stored in entries.leaf_error. The empty code
// means the entry decoded and every check passed.
type Code string

const (
	OK Code = ""

	// Leaf structure: leaf_input cannot be interpreted; no certificate is kept.
	BadVersion       Code = "leaf_bad_version"
	BadLeafType      Code = "leaf_bad_leaf_type"
	UnknownEntryType Code = "leaf_unknown_entry_type"
	Truncated        Code = "leaf_truncated"
	TrailingBytes    Code = "leaf_trailing_bytes"

	// extra_data structure.
	ExtraTruncated     Code = "extra_truncated"
	ExtraTrailingBytes Code = "extra_trailing_bytes"
	ChainCertEmpty     Code = "chain_cert_empty"

	// Issuer identification for precertificates.
	ChainIssuerMissing   Code = "chain_issuer_missing"
	ChainIssuerAmbiguous Code = "chain_issuer_ambiguous"

	// Precertificate cross-checks.
	IssuerKeyHashMismatch  Code = "issuer_key_hash_mismatch"
	PrecertTBSMismatch     Code = "precert_tbs_mismatch"
	IssuanceKeyUnavailable Code = "issuance_key_unavailable"
)

// Codes lists every code in a fixed order, for docs and explain-error.
var Codes = []Code{BadVersion, BadLeafType, UnknownEntryType, Truncated, TrailingBytes,
	ExtraTruncated, ExtraTrailingBytes, ChainCertEmpty, ChainIssuerMissing, ChainIssuerAmbiguous,
	IssuerKeyHashMismatch, PrecertTBSMismatch, IssuanceKeyUnavailable}

var explanations = map[Code]string{
	BadVersion:       "The MerkleTreeLeaf version is not v1 (0). The entry is kept in entries with its leaf hash, but no certificate can be read from it.",
	BadLeafType:      "The MerkleTreeLeaf type is not timestamped_entry. No certificate can be read from it.",
	UnknownEntryType: "The TimestampedEntry type is neither x509_entry nor precert_entry. No certificate can be read from it.",
	Truncated:        "leaf_input ends before its fields do. No certificate can be read from it.",
	TrailingBytes:    "Bytes follow the MerkleTreeLeaf in leaf_input. No certificate is read from it.",

	ExtraTruncated:     "extra_data ends before its fields do; the chain is not recorded.",
	ExtraTrailingBytes: "Bytes follow the chain in extra_data; the chain is not recorded.",
	ChainCertEmpty:     "extra_data holds an empty chain certificate; the chain is not recorded.",

	ChainIssuerMissing:   "No certificate in the chain issued the precertificate (amendment A1 §4: subject equals issuer, and key IDs match when present).",
	ChainIssuerAmbiguous: "More than one chain certificate could have issued the precertificate.",

	IssuerKeyHashMismatch:  "The precert entry's issuer_key_hash differs from the SHA-256 of the issuer's SubjectPublicKeyInfo.",
	PrecertTBSMismatch:     "The precert entry's TBSCertificate differs from the precertificate's with the poison removed (and the issuer replaced when a precert-signing certificate is used).",
	IssuanceKeyUnavailable: "The issuance key (which links a precert to its final certificate) cannot be computed for this entry.",
}

// Explain returns the code's explanation for explain-error, or "" for OK
// or an unknown code.
func (c Code) Explain() string { return explanations[c] }

// LeafStructure reports whether c means leaf_input itself could not be
// interpreted. Such entries have no certificate (spec §5.4: null cert_id).
func (c Code) LeafStructure() bool {
	switch c {
	case BadVersion, BadLeafType, UnknownEntryType, Truncated, TrailingBytes:
		return true
	}
	return false
}

// Entry is one decoded log entry. Byte slices alias the inputs.
type Entry struct {
	LeafHash  [32]byte // RFC 6962 SHA-256(0x00 || leaf_input), always set
	Type      Type
	Timestamp uint64 // ms; 0 when the leaf version or leaf type is unknown

	// CertDER is the x509 entry's certificate or the precert entry's
	// precertificate (from extra_data). Nil when it cannot be decoded safely.
	CertDER []byte
	// PrecertTBS is the log's TBSCertificate from leaf_input, exactly as
	// logged. It is authoritative; nothing reconstructed ever replaces it.
	PrecertTBS []byte
	// IssuerKeyHash is the precert leaf's issuer_key_hash, as logged.
	IssuerKeyHash    [32]byte
	HasIssuerKeyHash bool
	// Chain holds the chain certificates in extra_data order. Nil when the
	// chain cannot be decoded.
	Chain [][]byte
	// IssuanceDigest is SHA-256 of the precert's log TBS, or of the final
	// certificate's TBS without the SCT-list extension. Equal digests link a
	// precert to its final certificate.
	IssuanceDigest    [32]byte
	HasIssuanceDigest bool

	Code Code // the first problem found, or OK
}

// IssuanceKey is the 16-byte entries.issuance_key: the digest's first half.
func (e *Entry) IssuanceKey() (k [16]byte, ok bool) {
	if !e.HasIssuanceDigest {
		return k, false
	}
	copy(k[:], e.IssuanceDigest[:16])
	return k, true
}

func (e *Entry) fail(c Code) {
	if e.Code == OK {
		e.Code = c
	}
}

// Decode interprets one entry exactly as served. It never fails: problems are
// reported in Entry.Code.
func Decode(leafInput, extraData []byte) Entry {
	e := Entry{LeafHash: merkle.LeafHash(leafInput)}
	if !e.decodeLeaf(leafInput) {
		return e
	}
	switch e.Type {
	case TypeX509:
		e.decodeX509Extra(extraData)
		e.x509IssuanceDigest()
	case TypePrecert:
		e.IssuanceDigest, e.HasIssuanceDigest = sha256.Sum256(e.PrecertTBS), true
		if e.decodePrecertExtra(extraData) {
			e.checkPrecert()
		}
	}
	return e
}

// decodeLeaf parses the MerkleTreeLeaf (RFC 6962 §3.4). It reports whether
// the leaf is fully usable.
func (e *Entry) decodeLeaf(b []byte) bool {
	s := cryptobyte.String(b)
	var version, leafType uint8
	if !s.ReadUint8(&version) {
		e.fail(Truncated)
		return false
	}
	if version != 0 {
		e.fail(BadVersion)
		return false
	}
	if !s.ReadUint8(&leafType) {
		e.fail(Truncated)
		return false
	}
	if leafType != 0 {
		e.fail(BadLeafType)
		return false
	}
	var ts uint64
	var entryType uint16
	if !s.ReadUint64(&ts) || !s.ReadUint16(&entryType) {
		e.fail(Truncated)
		return false
	}
	e.Timestamp = ts
	var signed []byte
	switch entryType {
	case 0:
		e.Type = TypeX509
		var cert cryptobyte.String
		if !s.ReadUint24LengthPrefixed(&cert) || len(cert) == 0 {
			e.fail(Truncated)
			return false
		}
		signed = cert
	case 1:
		e.Type = TypePrecert
		var ikh, tbs cryptobyte.String
		if !s.ReadBytes((*[]byte)(&ikh), 32) || !s.ReadUint24LengthPrefixed(&tbs) || len(tbs) == 0 {
			e.fail(Truncated)
			return false
		}
		copy(e.IssuerKeyHash[:], ikh)
		e.HasIssuerKeyHash = true
		signed = tbs
	default:
		e.fail(UnknownEntryType)
		return false
	}
	var exts cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&exts) {
		e.fail(Truncated)
		return false
	}
	if !s.Empty() {
		e.fail(TrailingBytes)
		return false
	}
	if e.Type == TypeX509 {
		e.CertDER = signed
	} else {
		e.PrecertTBS = signed
	}
	return true
}

// readChain reads a TLS vector<ASN.1Cert> with a 24-bit total length.
func readChain(s *cryptobyte.String) ([][]byte, Code) {
	var list cryptobyte.String
	if !s.ReadUint24LengthPrefixed(&list) {
		return nil, ExtraTruncated
	}
	var chain [][]byte
	for !list.Empty() {
		var c cryptobyte.String
		if !list.ReadUint24LengthPrefixed(&c) {
			return nil, ExtraTruncated
		}
		if len(c) == 0 {
			return nil, ChainCertEmpty
		}
		chain = append(chain, c)
	}
	if chain == nil {
		chain = [][]byte{}
	}
	return chain, OK
}

func (e *Entry) decodeX509Extra(b []byte) {
	s := cryptobyte.String(b)
	chain, code := readChain(&s)
	if code != OK {
		e.fail(code)
		return
	}
	if !s.Empty() {
		e.fail(ExtraTrailingBytes)
		return
	}
	e.Chain = chain
}

// decodePrecertExtra parses a PrecertChainEntry and reports whether the
// precertificate and its chain are usable for the cross-checks.
func (e *Entry) decodePrecertExtra(b []byte) bool {
	s := cryptobyte.String(b)
	var pre cryptobyte.String
	if !s.ReadUint24LengthPrefixed(&pre) {
		e.fail(ExtraTruncated)
		return false
	}
	if len(pre) == 0 {
		e.fail(ChainCertEmpty)
		return false
	}
	chain, code := readChain(&s)
	if code != OK {
		e.fail(code)
		return false
	}
	if !s.Empty() {
		e.fail(ExtraTrailingBytes)
		return false
	}
	e.CertDER, e.Chain = pre, chain
	return true
}

// x509IssuanceDigest hashes the final certificate's TBS without the SCT list.
func (e *Entry) x509IssuanceDigest() {
	c, err := parseCert(e.CertDER)
	if err != nil {
		e.fail(IssuanceKeyUnavailable)
		return
	}
	tbs, err := c.rebuildTBS(rewrite{drop: oidSCTList})
	if err != nil {
		e.fail(IssuanceKeyUnavailable)
		return
	}
	e.IssuanceDigest, e.HasIssuanceDigest = sha256.Sum256(tbs), true
}
```

Create `internal/cli/explain.go`:

```go
package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/extract"
	"github.com/4rji/ctvault/internal/leaf"
)

func newExplainCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "explain-error <code>",
		Short: "Explain a certificate parse error or a log entry error code",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(c *cobra.Command, args []string) error {
			code, out := args[0], c.OutOrStdout()
			if e := extract.Code(code).Explain(); e != "" {
				fmt.Fprintf(out, "%s (certificate parse error): %s\n", code, e)
				return nil
			}
			if e := leaf.Code(code).Explain(); e != "" {
				fmt.Fprintf(out, "%s (log entry error): %s\n", code, e)
				return nil
			}
			return exitcode.Withf(exitcode.Usage, "unknown error code %q", code)
		},
	}
}
```

Replace `internal/cli/cli.go` with:

```go
// Package cli implements the ctvault command line. Every dependency on the
// host (mount table, network, clock, output) comes in through Deps so the
// commands can be tested end to end without root privileges or network.
package cli

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/lock"
	"github.com/4rji/ctvault/internal/loglist"
	"github.com/4rji/ctvault/internal/volume"
)

// Volumes is the volume policy the commands use: volume.Checker in production
// builds, volume.DevProbe in ctvault_dev builds (amendment A1 §1).
type Volumes interface {
	Init(root string, opts volume.InitOptions) (volume.VaultID, error)
	Check(root string) (volume.VaultID, error)
	AddDir(root, dir string, opts volume.InitOptions) (volume.VaultID, error)
}

// Deps are the host services the commands use.
type Deps struct {
	Volumes       Volumes
	HTTP          *http.Client
	Now           func() time.Time
	Stdout        io.Writer
	Stderr        io.Writer
	Getenv        func(string) string
	Statfs        diskguard.StatFunc
	LogListSource string
	Version       string
	// DevBase is <home>/.cache/ctvault-dev in ctvault_dev builds, where dev
	// vaults and samples live; production builds leave it empty.
	DevBase string
}

// DefaultDeps wires the real host with the production volume policy.
func DefaultDeps(version string) Deps {
	return Deps{
		Volumes: volume.Checker{Probe: volume.HostProbe{}, Now: time.Now},
		HTTP:    &http.Client{Timeout: 60 * time.Second}, Now: time.Now,
		Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv, Statfs: diskguard.Statfs,
		LogListSource: loglist.DefaultURL, Version: version,
	}
}

// devBanner is printed on stderr by every command of a ctvault_dev binary.
const devBanner = "WARNING: DEV BUILD (ctvault_dev) — not for production. Vaults and samples live only under ~/.cache/ctvault-dev/."

// extraCommands lets build-tagged files add commands (the dev build's
// "sample" commands); production builds register none.
var extraCommands []func(*app) *cobra.Command

// Main runs one command and returns its exit code (spec §11.2).
func Main(args []string, d Deps) int {
	if volume.DevBuild() {
		fmt.Fprintln(d.Stderr, devBanner)
	}
	a := &app{d: d}
	cmd := newRootCmd(a)
	cmd.SetArgs(args)
	cmd.SetOut(d.Stdout)
	cmd.SetErr(d.Stderr)
	err := cmd.Execute()
	if err == nil {
		return exitcode.OK
	}
	fmt.Fprintln(d.Stderr, "ctvault:", err)
	code := exitcode.Of(err)
	if code == exitcode.Usage {
		fmt.Fprintln(d.Stderr, "Run 'ctvault --help' for usage.")
	}
	return code
}

type app struct {
	d    Deps
	root string
}

func newRootCmd(a *app) *cobra.Command {
	root := &cobra.Command{
		Use:           "ctvault",
		Short:         "A local, cryptographically verified Certificate Transparency research archive",
		Args:          usageArgs(cobra.NoArgs),
		RunE:          func(c *cobra.Command, _ []string) error { return c.Help() },
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&a.root, "root", a.d.Getenv("CTVAULT_ROOT"), "vault root (default $CTVAULT_ROOT)")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return exitcode.With(exitcode.Usage, err) })
	root.AddCommand(newVersionCmd(a), newInitCmd(a), newLogsCmd(a), newVaultCmd(a), newUpdateCmd(a), newExplainCmd(a))
	for _, extra := range extraCommands {
		root.AddCommand(extra(a))
	}
	return root
}

// usageArgs marks argument-count errors as usage errors (exit code 2).
func usageArgs(v cobra.PositionalArgs) cobra.PositionalArgs {
	return func(c *cobra.Command, args []string) error { return exitcode.With(exitcode.Usage, v(c, args)) }
}

func groupCmd(use, short string, children ...*cobra.Command) *cobra.Command {
	c := &cobra.Command{Use: use, Short: short, Args: usageArgs(cobra.NoArgs),
		RunE: func(c *cobra.Command, _ []string) error { return c.Help() }}
	c.AddCommand(children...)
	return c
}

func volumeErr(err error) error {
	if errors.Is(err, volume.ErrVolume) {
		return exitcode.With(exitcode.Volume, err)
	}
	return err
}

// openVault runs the spec §9.2 checks that precede every command on a vault.
func (a *app) openVault(c *cobra.Command) (string, volume.VaultID, error) {
	if a.root == "" {
		return "", volume.VaultID{}, exitcode.Withf(exitcode.Usage, "no vault root: pass --root or set CTVAULT_ROOT")
	}
	id, err := a.d.Volumes.Check(a.root)
	if err != nil {
		return "", id, volumeErr(err)
	}
	if id.Durability == volume.DurabilityUntested {
		fmt.Fprintln(c.ErrOrStderr(), "warning: this vault uses an untested filesystem; durability guarantees are weaker (spec §9.3)")
	}
	return a.root, id, nil
}

func (a *app) writerLock(root string) (*lock.Lock, error) {
	return lock.Acquire(filepath.Join(root, "state", "LOCK"))
}

func newVersionCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use: "version", Short: "Print the ctvault version", Args: usageArgs(cobra.NoArgs),
		RunE: func(c *cobra.Command, _ []string) error {
			if volume.DevBuild() {
				fmt.Fprintln(c.OutOrStdout(), "ctvault", a.d.Version, "DEV BUILD — not for production")
				return nil
			}
			fmt.Fprintln(c.OutOrStdout(), "ctvault", a.d.Version)
			return nil
		},
	}
}
```

Create `internal/cli/testdata/error_codes.txt`:

```text
# Every published error code, "<catalog> <code>". Codes are stored in datasets:
# never rename or remove a line; append new codes (amendment A2 §3.3).
leaf leaf_bad_version
leaf leaf_bad_leaf_type
leaf leaf_unknown_entry_type
leaf leaf_truncated
leaf leaf_trailing_bytes
leaf extra_truncated
leaf extra_trailing_bytes
leaf chain_cert_empty
leaf chain_issuer_missing
leaf chain_issuer_ambiguous
leaf issuer_key_hash_mismatch
leaf precert_tbs_mismatch
leaf issuance_key_unavailable
extract cert_unreadable
extract cert_trailing_data
extract tbs_unreadable
extract version_bad
extract serial_unreadable
extract serial_negative
extract serial_zero
extract serial_too_long
extract serial_not_minimal
extract sig_alg_unreadable
extract sig_alg_mismatch
extract issuer_unreadable
extract subject_unreadable
extract name_bad_string
extract validity_unreadable
extract time_bad_format
extract spki_unreadable
extract key_unreadable
extract extensions_unreadable
extract ext_unreadable
extract ext_duplicate
extract san_unreadable
extract san_ip_bad_len
extract san_dns_bad_string
extract aki_unreadable
extract ski_unreadable
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race ./internal/extract/ ./internal/leaf/ ./internal/cli/`
Expected: PASS.

- [ ] **Step 5: Quality gate** (Global Constraints)

- [ ] **Step 6: Checkpoint.** Record the task in the ledger. The user commits.

---

### Task A2: Names

Amendment A2 §3.2.

**Files:**
- Create: `internal/extract/name.go`
- Test: `internal/extract/name_test.go`

**Interfaces:**
- Produces:
  - `extract.Name{Raw []byte; RDNs [][]Attribute}` and `extract.Attribute{Type string; Tag cbasn1.Tag; Value, Element []byte}`;
  - `(Name).String()` (RFC 4514) and `(Name).First(oid) (string, bool)` (display value);
  - `extract.OIDCommonName` and `extract.OIDOrganization`;
  - unexported, for Task A3: `parseName(der) (Name, bool)` and `(Name).badStrings() bool`.
- Rendering rules (Decision 4):
  - RDNs in reverse DER order, joined with `,`; a multi-valued RDN joined with `+` in DER order;
  - RFC 4514 §2.4 escapes, and `\XX` for control characters and undecodable bytes;
  - non-string values as `#` plus the hex of the whole element.

- [ ] **Step 1: Write the failing tests**

Create `internal/extract/name_test.go`:

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
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/extract/`
Expected: FAIL with `undefined: parseName` (and `OIDCommonName`, `OIDOrganization`) in `internal/extract`.

- [ ] **Step 3: Implement**

Create `internal/extract/name.go`:

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

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race ./internal/extract/`
Expected: PASS.

In UCS-2, `"\x00a"` is the character `a`, so an odd-length BMPString `"\x00a\x00"` renders as `a\00`.

- [ ] **Step 5: Quality gate**

- [ ] **Step 6: Checkpoint.**

---

### Task A3: `Parse`: structure, serial, signature, validity and public key

Spec §7.1, amendment A2 §3.1 and §3.3.

**Files:**
- Create: `internal/extract/cert.go`, `internal/extract/key.go`, `internal/extract/algs.go`
- Modify: `internal/extract/codes.go` (adds `signature_unreadable` and `tbs_extra_fields`), `internal/cli/testdata/error_codes.txt` (appends both)
- Test: `internal/extract/cert_test.go`

**Interfaces:**
- Produces:
  - `extract.Status` (`StatusOK`, `StatusPartial`, `StatusFailed`);
  - `extract.Cert` with `Status`, `Errors`, `Version`, `Serial`, `SignatureAlgorithm`, `Issuer`, `Subject`, `NotBefore`, `NotAfter`, `HasNotBefore`, `HasNotAfter` and `Key`;
  - `extract.Parse(der []byte) *Cert`;
  - `extract.Key{AlgorithmOID, Algorithm string; Bits int; Curve string}`.
- **Status rule:** `failed` exactly when the codes include `cert_unreadable` or `tbs_unreadable`, `partial` when there are other codes, and `ok` otherwise. Each code appears at most once, in the order found.

- [ ] **Step 1: Write the failing tests**

Create `internal/extract/cert_test.go`:

```go
package extract

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"reflect"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var testRSA = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

// selfSigned makes a certificate with crypto/x509, the reference parser.
func selfSigned(t *testing.T, key crypto.Signer, edit func(*x509.Certificate)) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x1234567890),
		Subject:      pkix.Name{CommonName: "leaf.example.com", Organization: []string{"Example Org"}},
		Issuer:       pkix.Name{CommonName: "leaf.example.com", Organization: []string{"Example Org"}},
		NotBefore:    time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		NotAfter:     time.Date(2026, 4, 2, 3, 4, 5, 0, time.UTC),
		DNSNames:     []string{"leaf.example.com"},
	}
	if edit != nil {
		edit(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParseValidCertificates(t *testing.T) {
	ec256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ec384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	for _, c := range []struct {
		name   string
		key    crypto.Signer
		sigAlg string
		key2   Key
	}{
		{"rsa", testRSA, "sha256WithRSAEncryption", Key{AlgorithmOID: "1.2.840.113549.1.1.1", Algorithm: "rsa", Bits: 2048}},
		{"p256", ec256, "ecdsa-with-SHA256", Key{AlgorithmOID: "1.2.840.10045.2.1", Algorithm: "ecdsa", Bits: 256, Curve: "P-256"}},
		{"p384", ec384, "ecdsa-with-SHA384", Key{AlgorithmOID: "1.2.840.10045.2.1", Algorithm: "ecdsa", Bits: 384, Curve: "P-384"}},
		{"ed25519", ed, "Ed25519", Key{AlgorithmOID: "1.3.101.112", Algorithm: "ed25519", Bits: 256}},
	} {
		t.Run(c.name, func(t *testing.T) {
			der := selfSigned(t, c.key, nil)
			ref, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			got := Parse(der)
			if got.Status != StatusOK || len(got.Errors) != 0 {
				t.Fatalf("status %s, errors %v", got.Status, got.Errors)
			}
			if got.Version != 3 || !bytes.Equal(got.Serial, ref.SerialNumber.Bytes()) || got.SignatureAlgorithm != c.sigAlg {
				t.Errorf("version %d, serial %x, sig %q", got.Version, got.Serial, got.SignatureAlgorithm)
			}
			if !bytes.Equal(got.Issuer.Raw, ref.RawIssuer) || !bytes.Equal(got.Subject.Raw, ref.RawSubject) {
				t.Error("names are not the exact DER")
			}
			if cn, _ := got.Subject.First(OIDCommonName); cn != "leaf.example.com" {
				t.Errorf("subject CN %q", cn)
			}
			if !got.HasNotBefore || !got.NotBefore.Equal(ref.NotBefore) || !got.HasNotAfter || !got.NotAfter.Equal(ref.NotAfter) {
				t.Errorf("validity %v %v", got.NotBefore, got.NotAfter)
			}
			if got.Key != c.key2 {
				t.Errorf("key %+v, want %+v", got.Key, c.key2)
			}
			if again := Parse(der); !reflect.DeepEqual(got, again) {
				t.Error("two parses differ")
			}
		})
	}
}

// parts are a certificate's elements, so a test can replace one of them.
type parts struct {
	version, serial, sigAlg, issuer, validity, subject, spki []byte
	extra                                                    [][]byte
	outerSigAlg, signature                                   []byte
	trailing                                                 []byte
}

func element(tag cbasn1.Tag, content []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(tag, func(b *cryptobyte.Builder) { b.AddBytes(content) })
	return b.BytesOrPanic()
}

func seq(elems ...[]byte) []byte { return element(cbasn1.SEQUENCE, bytes.Join(elems, nil)) }

func oidElem(oid asn1.ObjectIdentifier) []byte {
	var b cryptobyte.Builder
	b.AddASN1ObjectIdentifier(oid)
	return b.BytesOrPanic()
}

func validParts(t *testing.T) parts {
	t.Helper()
	ref, _ := x509.ParseCertificate(selfSigned(t, testRSA, nil))
	s := cryptobyte.String(ref.RawTBSCertificate)
	var tbs cryptobyte.String
	s.ReadASN1(&tbs, cbasn1.SEQUENCE)
	var els [][]byte
	for !tbs.Empty() {
		var e cryptobyte.String
		var tag cbasn1.Tag
		tbs.ReadAnyASN1Element(&e, &tag)
		els = append(els, e)
	}
	sigAlg := seq(oidElem(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}), []byte{0x05, 0x00})
	return parts{version: els[0], serial: els[1], sigAlg: els[2], issuer: els[3], validity: els[4], subject: els[5], spki: els[6],
		extra: els[7:], outerSigAlg: sigAlg, signature: element(cbasn1.BIT_STRING, []byte{0x00, 0xAA})}
}

func (p parts) der() []byte {
	tbs := seq(append([][]byte{p.version, p.serial, p.sigAlg, p.issuer, p.validity, p.subject, p.spki}, p.extra...)...)
	return append(seq(tbs, p.outerSigAlg, p.signature), p.trailing...)
}

func TestParseFailsOnlyOnStructure(t *testing.T) {
	if c := Parse([]byte{0x31, 0x00}); c.Status != StatusFailed || !slices.Equal(c.Errors, []Code{CertUnreadable}) {
		t.Errorf("not a SEQUENCE: %s %v", c.Status, c.Errors)
	}
	if c := Parse(nil); c.Status != StatusFailed {
		t.Errorf("empty input: %s", c.Status)
	}
	p := validParts(t)
	p.spki = nil // five TBS fields only
	if c := Parse(p.der()); c.Status != StatusFailed || !slices.Equal(c.Errors, []Code{TBSUnreadable}) {
		t.Errorf("short TBS: %s %v", c.Status, c.Errors)
	}
	p = validParts(t)
	p.extra = append([][]byte{seq()}, p.extra...) // an unknown element before the extensions
	if c := Parse(p.der()); c.Status != StatusPartial || !slices.Equal(c.Errors, []Code{TBSExtraFields}) || c.Key.Bits != 2048 {
		t.Errorf("extra TBS field: %s %v", c.Status, c.Errors)
	}
	p = validParts(t)
	p.extra = [][]byte{{0xA3, 0x10, 0x30, 0x01}} // an extensions field whose length runs past the TBS
	if c := Parse(p.der()); c.Status != StatusPartial || !slices.Equal(c.Errors, []Code{ExtensionsUnreadable}) || c.Key.Bits != 2048 {
		t.Errorf("unreadable element after the fixed fields: %s %v %+v", c.Status, c.Errors, c.Key)
	}
	p = validParts(t)
	p.trailing = []byte{0x00}
	if c := Parse(p.der()); c.Status != StatusPartial || !slices.Equal(c.Errors, []Code{CertTrailingData}) || c.Key.Bits != 2048 {
		t.Errorf("trailing data: %s %v %+v", c.Status, c.Errors, c.Key)
	}
	p = validParts(t)
	p.signature = element(cbasn1.OCTET_STRING, []byte{1})
	if c := Parse(p.der()); c.Status != StatusPartial || !slices.Equal(c.Errors, []Code{SignatureUnreadable}) || c.Serial == nil {
		t.Errorf("bad signature value: %s %v", c.Status, c.Errors)
	}
}

func TestSerialChecks(t *testing.T) {
	long := bytes.Repeat([]byte{0x01}, 21)
	for _, c := range []struct {
		content []byte
		codes   []Code
	}{
		{[]byte{0x01}, nil},
		{[]byte{0x00, 0x80}, nil}, // minimal: the 0x00 keeps it positive
		{[]byte{0x00}, []Code{SerialZero}},
		{[]byte{0x80}, []Code{SerialNegative}},
		{[]byte{0x00, 0x01}, []Code{SerialNotMinimal}},
		{[]byte{0xFF, 0x80}, []Code{SerialNegative, SerialNotMinimal}},
		{long, []Code{SerialTooLong}},
		{[]byte{}, []Code{SerialUnreadable}},
	} {
		p := validParts(t)
		p.serial = element(cbasn1.INTEGER, c.content)
		got := Parse(p.der())
		if !slices.Equal(got.Errors, c.codes) {
			t.Errorf("serial %x: codes %v, want %v", c.content, got.Errors, c.codes)
		}
		if len(c.content) > 0 && !bytes.Equal(got.Serial, c.content) {
			t.Errorf("serial %x: kept %x, want the raw content", c.content, got.Serial)
		}
	}
	p := validParts(t)
	p.serial = element(cbasn1.OCTET_STRING, []byte{1})
	if got := Parse(p.der()); got.Serial != nil || !slices.Equal(got.Errors, []Code{SerialUnreadable}) {
		t.Errorf("wrong tag: %x %v", got.Serial, got.Errors)
	}
}

func TestVersion(t *testing.T) {
	explicit := func(v byte) []byte {
		return element(cbasn1.Tag(0).Constructed().ContextSpecific(), element(cbasn1.INTEGER, []byte{v}))
	}
	for _, c := range []struct {
		version []byte
		want    int
		codes   []Code
	}{
		{explicit(2), 3, nil},
		{explicit(0), 1, nil},
		{explicit(5), 0, []Code{VersionBad}},
	} {
		p := validParts(t)
		p.version = c.version
		if got := Parse(p.der()); got.Version != c.want || !slices.Equal(got.Errors, c.codes) {
			t.Errorf("version element %x: %d %v", c.version, got.Version, got.Errors)
		}
	}
	p := validParts(t)
	p.version = nil // absent: v1
	if got := Parse(p.der()); got.Version != 1 || len(got.Errors) != 0 || got.Key.Bits != 2048 {
		t.Errorf("absent version: %d %v", got.Version, got.Errors)
	}
}

func TestValidityTimes(t *testing.T) {
	utc := func(s string) []byte { return element(cbasn1.UTCTime, []byte(s)) }
	gen := func(s string) []byte { return element(cbasn1.GeneralizedTime, []byte(s)) }
	good := utc("260102030405Z")
	for _, c := range []struct {
		name string
		t    []byte
		want time.Time
		ok   bool
	}{
		{"UTCTime 20xx", utc("250101000000Z"), time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), true},
		{"UTCTime 19xx", utc("500101000000Z"), time.Date(1950, 1, 1, 0, 0, 0, 0, time.UTC), true},
		{"GeneralizedTime", gen("20500101000000Z"), time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC), true},
		{"no seconds", utc("2501010000Z"), time.Time{}, false},
		{"offset", utc("250101000000+0000"), time.Time{}, false},
		{"fraction", gen("20500101000000.5Z"), time.Time{}, false},
		{"month 13", utc("251301000000Z"), time.Time{}, false},
		{"February 30", utc("250230000000Z"), time.Time{}, false},
		{"not digits", utc("25010100000AZ"), time.Time{}, false},
		{"wrong tag", element(cbasn1.OCTET_STRING, []byte("250101000000Z")), time.Time{}, false},
	} {
		p := validParts(t)
		p.validity = seq(c.t, good)
		got := Parse(p.der())
		if got.HasNotBefore != c.ok || !got.NotBefore.Equal(c.want) {
			t.Errorf("%s: %v %v", c.name, got.HasNotBefore, got.NotBefore)
		}
		if c.ok == slices.Contains(got.Errors, TimeBadFormat) {
			t.Errorf("%s: codes %v", c.name, got.Errors)
		}
		if !got.HasNotAfter {
			t.Errorf("%s: notAfter lost", c.name)
		}
	}
	p := validParts(t)
	p.validity = seq(good)
	if got := Parse(p.der()); !slices.Equal(got.Errors, []Code{ValidityUnreadable}) || got.HasNotBefore || got.HasNotAfter {
		t.Errorf("one time only: %v", got.Errors)
	}
}

func TestSignatureAlgorithm(t *testing.T) {
	p := validParts(t)
	p.outerSigAlg = seq(oidElem(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}), []byte{0x05, 0x00})
	if got := Parse(p.der()); !slices.Equal(got.Errors, []Code{SigAlgMismatch}) || got.SignatureAlgorithm != "sha256WithRSAEncryption" {
		t.Errorf("mismatch: %v %q", got.Errors, got.SignatureAlgorithm)
	}
	p = validParts(t)
	p.sigAlg = seq(oidElem(asn1.ObjectIdentifier{1, 2, 3, 4}))
	p.outerSigAlg = p.sigAlg
	if got := Parse(p.der()); len(got.Errors) != 0 || got.SignatureAlgorithm != "1.2.3.4" {
		t.Errorf("unknown algorithm: %v %q", got.Errors, got.SignatureAlgorithm)
	}
	p = validParts(t)
	p.sigAlg = element(cbasn1.OCTET_STRING, nil)
	if got := Parse(p.der()); !slices.Contains(got.Errors, SigAlgUnreadable) || got.SignatureAlgorithm != "" {
		t.Errorf("unreadable: %v %q", got.Errors, got.SignatureAlgorithm)
	}
}

func TestNamesInACertificate(t *testing.T) {
	p := validParts(t)
	p.issuer = element(cbasn1.SET, nil)
	if got := Parse(p.der()); !slices.Equal(got.Errors, []Code{IssuerUnreadable}) || !bytes.Equal(got.Issuer.Raw, p.issuer) {
		t.Errorf("issuer: %v", got.Errors)
	}
	p = validParts(t)
	p.subject = buildName([]atv{{oidCN, str(tagUTF8, "bad\xff")}})
	if got := Parse(p.der()); !slices.Equal(got.Errors, []Code{NameBadString}) {
		t.Errorf("subject: %v", got.Errors)
	}
}

func spki(alg []byte, key []byte) []byte {
	return seq(alg, element(cbasn1.BIT_STRING, append([]byte{0x00}, key...)))
}

func TestPublicKeys(t *testing.T) {
	rsaKey := func(modulus []byte) []byte {
		return seq(element(cbasn1.INTEGER, modulus), element(cbasn1.INTEGER, []byte{1, 0, 1}))
	}
	rsaAlg := seq(oidElem(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}), []byte{0x05, 0x00})
	ecAlg := func(curve asn1.ObjectIdentifier) []byte {
		return seq(oidElem(asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}), oidElem(curve))
	}
	point := append([]byte{0x04}, make([]byte, 64)...)
	dsaParams := seq(element(cbasn1.INTEGER, append([]byte{0x00, 0x80}, make([]byte, 127)...)), element(cbasn1.INTEGER, []byte{1}), element(cbasn1.INTEGER, []byte{2}))
	for _, c := range []struct {
		name  string
		spki  []byte
		want  Key
		codes []Code
	}{
		{"rsa with a sign byte", spki(rsaAlg, rsaKey(append([]byte{0x00, 0xC0}, make([]byte, 255)...))),
			Key{AlgorithmOID: "1.2.840.113549.1.1.1", Algorithm: "rsa", Bits: 2048}, nil},
		{"rsa unreadable", spki(rsaAlg, []byte{0x01}), Key{AlgorithmOID: "1.2.840.113549.1.1.1", Algorithm: "rsa"}, []Code{KeyUnreadable}},
		{"secp256k1", spki(ecAlg(asn1.ObjectIdentifier{1, 3, 132, 0, 10}), point),
			Key{AlgorithmOID: "1.2.840.10045.2.1", Algorithm: "ecdsa", Bits: 256, Curve: "secp256k1"}, nil},
		{"unknown curve", spki(ecAlg(asn1.ObjectIdentifier{1, 2, 3}), point),
			Key{AlgorithmOID: "1.2.840.10045.2.1", Algorithm: "ecdsa", Bits: 256, Curve: "1.2.3"}, nil},
		{"explicit curve parameters", spki(seq(oidElem(asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}), seq()), point),
			Key{AlgorithmOID: "1.2.840.10045.2.1", Algorithm: "ecdsa", Bits: 256}, []Code{KeyUnreadable}},
		{"ed448", spki(seq(oidElem(asn1.ObjectIdentifier{1, 3, 101, 113})), make([]byte, 57)),
			Key{AlgorithmOID: "1.3.101.113", Algorithm: "ed448", Bits: 456}, nil},
		{"ed25519 wrong length", spki(seq(oidElem(asn1.ObjectIdentifier{1, 3, 101, 112})), make([]byte, 31)),
			Key{AlgorithmOID: "1.3.101.112", Algorithm: "ed25519"}, []Code{KeyUnreadable}},
		{"dsa", spki(seq(oidElem(asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}), dsaParams), element(cbasn1.INTEGER, []byte{5})),
			Key{AlgorithmOID: "1.2.840.10040.4.1", Algorithm: "dsa", Bits: 1024}, nil},
		{"other", spki(seq(oidElem(asn1.ObjectIdentifier{1, 2, 3, 4, 5})), []byte{1, 2}),
			Key{AlgorithmOID: "1.2.3.4.5", Algorithm: "other"}, nil},
		{"unreadable", element(cbasn1.OCTET_STRING, nil), Key{}, []Code{SPKIUnreadable}},
	} {
		p := validParts(t)
		p.spki = c.spki
		got := Parse(p.der())
		if got.Key != c.want || !slices.Equal(got.Errors, c.codes) {
			t.Errorf("%s: %+v %v, want %+v %v", c.name, got.Key, got.Errors, c.want, c.codes)
		}
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/extract/`
Expected: FAIL with `undefined: Key` and `undefined: Parse` in `internal/extract`.

- [ ] **Step 3: Implement**

Create `internal/extract/algs.go`:

```go
package extract

// signatureAlgorithms names signature AlgorithmIdentifier OIDs (RFC 3279,
// 4055, 5758, 8410). An unknown OID is reported in dotted form.
var signatureAlgorithms = map[string]string{
	"1.2.840.113549.1.1.2":   "md2WithRSAEncryption",
	"1.2.840.113549.1.1.4":   "md5WithRSAEncryption",
	"1.2.840.113549.1.1.5":   "sha1WithRSAEncryption",
	"1.2.840.113549.1.1.10":  "rsassaPss",
	"1.2.840.113549.1.1.11":  "sha256WithRSAEncryption",
	"1.2.840.113549.1.1.12":  "sha384WithRSAEncryption",
	"1.2.840.113549.1.1.13":  "sha512WithRSAEncryption",
	"1.2.840.113549.1.1.14":  "sha224WithRSAEncryption",
	"1.2.840.10045.4.1":      "ecdsa-with-SHA1",
	"1.2.840.10045.4.3.1":    "ecdsa-with-SHA224",
	"1.2.840.10045.4.3.2":    "ecdsa-with-SHA256",
	"1.2.840.10045.4.3.3":    "ecdsa-with-SHA384",
	"1.2.840.10045.4.3.4":    "ecdsa-with-SHA512",
	"1.2.840.10040.4.3":      "dsa-with-SHA1",
	"2.16.840.1.101.3.4.3.1": "dsa-with-SHA224",
	"2.16.840.1.101.3.4.3.2": "dsa-with-SHA256",
	"1.3.101.112":            "Ed25519",
	"1.3.101.113":            "Ed448",
}

// Public key algorithm OIDs.
const (
	oidRSA     = "1.2.840.113549.1.1.1"
	oidRSAPSS  = "1.2.840.113549.1.1.10"
	oidEC      = "1.2.840.10045.2.1"
	oidEd25519 = "1.3.101.112"
	oidEd448   = "1.3.101.113"
	oidDSA     = "1.2.840.10040.4.1"
)

// namedCurves maps namedCurve OIDs to their names and sizes in bits.
var namedCurves = map[string]struct {
	name string
	bits int
}{
	"1.2.840.10045.3.1.1": {"P-192", 192},
	"1.3.132.0.33":        {"P-224", 224},
	"1.2.840.10045.3.1.7": {"P-256", 256},
	"1.3.132.0.34":        {"P-384", 384},
	"1.3.132.0.35":        {"P-521", 521},
	"1.3.132.0.10":        {"secp256k1", 256},
}
```

Create `internal/extract/key.go`:

```go
package extract

import (
	"encoding/asn1"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Key is what certs records about the subject public key.
type Key struct {
	AlgorithmOID string // dotted; "" when the SPKI is unreadable
	Algorithm    string // rsa, ecdsa, ed25519, ed448, dsa or other
	Bits         int    // 0 when unknown
	Curve        string // named curve, or the curve's dotted OID; "" otherwise
}

// bitLen is the bit length of an unsigned big-endian integer.
func bitLen(b []byte) int {
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	if len(b) == 0 {
		return 0
	}
	n := 8 * (len(b) - 1)
	for x := b[0]; x != 0; x >>= 1 {
		n++
	}
	return n
}

// parseKey reads a SubjectPublicKeyInfo element.
func parseKey(el []byte) (Key, []Code) {
	s := cryptobyte.String(el)
	var body, alg, params cryptobyte.String
	var oid asn1.ObjectIdentifier
	var bits asn1.BitString
	if !s.ReadASN1(&body, cbasn1.SEQUENCE) || !s.Empty() || !body.ReadASN1(&alg, cbasn1.SEQUENCE) ||
		!alg.ReadASN1ObjectIdentifier(&oid) || !body.ReadASN1BitString(&bits) || !body.Empty() {
		return Key{}, []Code{SPKIUnreadable}
	}
	params = alg
	k := Key{AlgorithmOID: oid.String()}
	bad := []Code{KeyUnreadable}
	key := cryptobyte.String(bits.RightAlign())
	switch k.AlgorithmOID {
	case oidRSA, oidRSAPSS:
		k.Algorithm = "rsa"
		var rsaKey, n cryptobyte.String
		if !key.ReadASN1(&rsaKey, cbasn1.SEQUENCE) || !rsaKey.ReadASN1(&n, cbasn1.INTEGER) || len(n) == 0 || n[0]&0x80 != 0 {
			return k, bad
		}
		k.Bits = bitLen(n)
	case oidEC:
		k.Algorithm = "ecdsa"
		if len(key) > 1 {
			switch key[0] {
			case 0x04:
				k.Bits = (len(key) - 1) / 2 * 8
			case 0x02, 0x03:
				k.Bits = (len(key) - 1) * 8
			}
		}
		var curve asn1.ObjectIdentifier
		if !params.ReadASN1ObjectIdentifier(&curve) || !params.Empty() {
			return k, bad
		}
		if c, ok := namedCurves[curve.String()]; ok {
			k.Curve, k.Bits = c.name, c.bits
		} else {
			k.Curve = curve.String()
		}
	case oidEd25519, oidEd448:
		k.Algorithm, k.Bits = "ed25519", 256
		size := 32
		if k.AlgorithmOID == oidEd448 {
			k.Algorithm, k.Bits, size = "ed448", 456, 57
		}
		if len(key) != size {
			k.Bits = 0
			return k, bad
		}
	case oidDSA:
		k.Algorithm = "dsa"
		if params.Empty() {
			return k, nil // parameters inherited from the issuer (RFC 3279 §2.3.2)
		}
		var dss, p cryptobyte.String
		if !params.ReadASN1(&dss, cbasn1.SEQUENCE) || !dss.ReadASN1(&p, cbasn1.INTEGER) {
			return k, bad
		}
		k.Bits = bitLen(p)
	default:
		k.Algorithm = "other"
	}
	return k, nil
}
```

Create `internal/extract/cert.go`:

```go
package extract

import (
	"bytes"
	"encoding/asn1"
	"slices"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Status is certs.parse_status.
type Status string

const (
	StatusOK      Status = "ok"      // no error code
	StatusPartial Status = "partial" // at least one field could not be read
	StatusFailed  Status = "failed"  // the Certificate or the TBSCertificate cannot be read
)

// Cert is what the extractor read from one certificate. Byte slices alias
// the input. Fields that could not be read are zero, and Errors says why.
type Cert struct {
	Status Status
	Errors []Code // in the order found, each code at most once

	Version            int    // 1, 2 or 3; 0 when unreadable
	Serial             []byte // the raw INTEGER content bytes; nil when unreadable
	SignatureAlgorithm string // the TBSCertificate's: a name, or the dotted OID; "" when unreadable

	Issuer, Subject Name

	NotBefore, NotAfter       time.Time // UTC
	HasNotBefore, HasNotAfter bool

	Key Key
}

func (c *Cert) add(code Code) {
	if !slices.Contains(c.Errors, code) {
		c.Errors = append(c.Errors, code)
	}
}

var tagVersion = cbasn1.Tag(0).Constructed().ContextSpecific()

// Parse reads der leniently (amendment A2 §3). It never fails and never
// panics: what cannot be read stays zero and adds an error code.
func Parse(der []byte) *Cert {
	c := &Cert{}
	c.parse(der)
	switch {
	case slices.Contains(c.Errors, CertUnreadable), slices.Contains(c.Errors, TBSUnreadable):
		c.Status = StatusFailed
	case len(c.Errors) > 0:
		c.Status = StatusPartial
	default:
		c.Status = StatusOK
	}
	return c
}

func (c *Cert) parse(der []byte) {
	s := cryptobyte.String(der)
	var body, tbs cryptobyte.String
	if !s.ReadASN1(&body, cbasn1.SEQUENCE) || !body.ReadASN1(&tbs, cbasn1.SEQUENCE) {
		c.add(CertUnreadable)
		return
	}
	if !s.Empty() {
		c.add(CertTrailingData)
	}
	var outerAlg cryptobyte.String
	var sig asn1.BitString
	if !body.ReadASN1Element(&outerAlg, cbasn1.SEQUENCE) || !body.ReadASN1BitString(&sig) || !body.Empty() {
		c.add(SignatureUnreadable)
		outerAlg = nil
	}

	var els [][]byte
	var tags []cbasn1.Tag
	for !tbs.Empty() {
		var el cryptobyte.String
		var tag cbasn1.Tag
		if !tbs.ReadAnyASN1Element(&el, &tag) {
			// Past the six fixed fields only the optional ones remain: an
			// unreadable tail loses the extensions, not the certificate.
			fixedSeen := len(els)
			if len(tags) > 0 && tags[0] == tagVersion {
				fixedSeen--
			}
			if fixedSeen < 6 {
				c.add(TBSUnreadable)
				return
			}
			c.add(ExtensionsUnreadable)
			break
		}
		els, tags = append(els, el), append(tags, tag)
	}
	i := 0
	c.Version = 1
	if len(tags) > 0 && tags[0] == tagVersion {
		c.Version = parseVersion(els[0])
		if c.Version == 0 {
			c.add(VersionBad)
		}
		i = 1
	}
	// The six fixed fields come before the optional issuerUniqueID [1],
	// subjectUniqueID [2] and extensions [3].
	fixed := len(els)
	for fixed > i && isOptionalTBSField(tags[fixed-1]) {
		fixed--
	}
	if fixed < i+6 {
		c.Version = 0
		c.add(TBSUnreadable)
		return
	}
	if fixed > i+6 {
		c.add(TBSExtraFields)
	}
	c.parseSerial(els[i])
	c.parseSignatureAlgorithm(els[i+1], outerAlg)
	var ok bool
	if c.Issuer, ok = parseName(els[i+2]); !ok {
		c.add(IssuerUnreadable)
	} else if c.Issuer.badStrings() {
		c.add(NameBadString)
	}
	c.parseValidity(els[i+3])
	if c.Subject, ok = parseName(els[i+4]); !ok {
		c.add(SubjectUnreadable)
	} else if c.Subject.badStrings() {
		c.add(NameBadString)
	}
	var codes []Code
	c.Key, codes = parseKey(els[i+5])
	for _, code := range codes {
		c.add(code)
	}
}

func isOptionalTBSField(t cbasn1.Tag) bool {
	return t == cbasn1.Tag(1).ContextSpecific() || t == cbasn1.Tag(2).ContextSpecific() ||
		t == cbasn1.Tag(1).Constructed().ContextSpecific() || t == cbasn1.Tag(2).Constructed().ContextSpecific() ||
		t == cbasn1.Tag(3).Constructed().ContextSpecific()
}

// parseVersion reads [0] EXPLICIT INTEGER: 0, 1 or 2 are v1-v3; anything
// else is 0.
func parseVersion(el []byte) int {
	s := cryptobyte.String(el)
	var inner cryptobyte.String
	var v int
	if !s.ReadASN1(&inner, tagVersion) || !inner.ReadASN1Integer(&v) || !inner.Empty() || v < 0 || v > 2 {
		return 0
	}
	return v + 1
}

// parseSerial keeps the raw INTEGER content and flags what RFC 5280 and DER
// forbid.
func (c *Cert) parseSerial(el []byte) {
	s := cryptobyte.String(el)
	var v cryptobyte.String
	if !s.ReadASN1(&v, cbasn1.INTEGER) || len(v) == 0 {
		c.add(SerialUnreadable)
		return
	}
	c.Serial = v
	if v[0]&0x80 != 0 {
		c.add(SerialNegative)
	}
	if len(v) > 1 && (v[0] == 0x00 && v[1]&0x80 == 0 || v[0] == 0xFF && v[1]&0x80 != 0) {
		c.add(SerialNotMinimal)
	}
	if bytes.Count(v, []byte{0}) == len(v) {
		c.add(SerialZero)
	}
	if len(v) > 20 {
		c.add(SerialTooLong)
	}
}

// parseSignatureAlgorithm names the TBSCertificate's signature algorithm and
// checks it against the outer one (RFC 5280 §4.1.1.2).
func (c *Cert) parseSignatureAlgorithm(el, outer []byte) {
	s := cryptobyte.String(el)
	var alg cryptobyte.String
	var oid asn1.ObjectIdentifier
	if !s.ReadASN1(&alg, cbasn1.SEQUENCE) || !alg.ReadASN1ObjectIdentifier(&oid) {
		c.add(SigAlgUnreadable)
		return
	}
	c.SignatureAlgorithm = oid.String()
	if name, ok := signatureAlgorithms[c.SignatureAlgorithm]; ok {
		c.SignatureAlgorithm = name
	}
	if outer != nil && !bytes.Equal(el, outer) {
		c.add(SigAlgMismatch)
	}
}

func (c *Cert) parseValidity(el []byte) {
	s := cryptobyte.String(el)
	var v cryptobyte.String
	var nb, na cryptobyte.String
	var nbTag, naTag cbasn1.Tag
	if !s.ReadASN1(&v, cbasn1.SEQUENCE) || !v.ReadAnyASN1(&nb, &nbTag) || !v.ReadAnyASN1(&na, &naTag) || !v.Empty() {
		c.add(ValidityUnreadable)
		return
	}
	var ok bool
	if c.NotBefore, ok = parseTime(nbTag, nb); ok {
		c.HasNotBefore = true
	} else {
		c.add(TimeBadFormat)
	}
	if c.NotAfter, ok = parseTime(naTag, na); ok {
		c.HasNotAfter = true
	} else {
		c.add(TimeBadFormat)
	}
}

// parseTime reads a time as RFC 5280 §4.1.2.5 requires: UTCTime
// YYMMDDHHMMSSZ (YY below 50 is 20YY) or GeneralizedTime YYYYMMDDHHMMSSZ.
func parseTime(tag cbasn1.Tag, b []byte) (time.Time, bool) {
	var digits []byte
	switch {
	case tag == cbasn1.UTCTime && len(b) == 13 && b[12] == 'Z':
		digits = b[:12]
	case tag == cbasn1.GeneralizedTime && len(b) == 15 && b[14] == 'Z':
		digits = b[:14]
	default:
		return time.Time{}, false
	}
	n := make([]int, 0, 7)
	for i := 0; i < len(digits); i += 2 {
		if digits[i] < '0' || digits[i] > '9' || digits[i+1] < '0' || digits[i+1] > '9' {
			return time.Time{}, false
		}
		n = append(n, int(digits[i]-'0')*10+int(digits[i+1]-'0'))
	}
	var year int
	if tag == cbasn1.UTCTime {
		year = 2000 + n[0]
		if n[0] >= 50 {
			year = 1900 + n[0]
		}
		n = n[1:]
	} else {
		year, n = n[0]*100+n[1], n[2:]
	}
	t := time.Date(year, time.Month(n[0]), n[1], n[2], n[3], n[4], 0, time.UTC)
	if t.Year() != year || int(t.Month()) != n[0] || t.Day() != n[1] || t.Hour() != n[2] || t.Minute() != n[3] || t.Second() != n[4] {
		return time.Time{}, false // out of range: month 13, February 30, hour 24
	}
	return t, true
}
```

Replace `internal/extract/codes.go` with:

```go
// Package extract reads the fields of an X.509 certificate leniently (spec
// §7.1, amendment A2 §3): each field is read on its own with cryptobyte, a
// malformed field adds a stable error code and extraction goes on, and no
// certificate is ever dropped. The result depends only on the DER bytes.
package extract

// Code is a stable parse error code, stored in certs.parse_errors. Codes are
// only ever added: a published code is never renamed or removed.
type Code string

const (
	// The certificate's structure.
	CertUnreadable      Code = "cert_unreadable"
	CertTrailingData    Code = "cert_trailing_data"
	SignatureUnreadable Code = "signature_unreadable"
	TBSUnreadable       Code = "tbs_unreadable"
	TBSExtraFields      Code = "tbs_extra_fields"
	VersionBad          Code = "version_bad"

	// Serial number.
	SerialUnreadable Code = "serial_unreadable"
	SerialNegative   Code = "serial_negative"
	SerialZero       Code = "serial_zero"
	SerialTooLong    Code = "serial_too_long"
	SerialNotMinimal Code = "serial_not_minimal"

	// Signature algorithm.
	SigAlgUnreadable Code = "sig_alg_unreadable"
	SigAlgMismatch   Code = "sig_alg_mismatch"

	// Names.
	IssuerUnreadable  Code = "issuer_unreadable"
	SubjectUnreadable Code = "subject_unreadable"
	NameBadString     Code = "name_bad_string"

	// Validity.
	ValidityUnreadable Code = "validity_unreadable"
	TimeBadFormat      Code = "time_bad_format"

	// Public key.
	SPKIUnreadable Code = "spki_unreadable"
	KeyUnreadable  Code = "key_unreadable"

	// Extensions.
	ExtensionsUnreadable Code = "extensions_unreadable"
	ExtUnreadable        Code = "ext_unreadable"
	ExtDuplicate         Code = "ext_duplicate"
	SANUnreadable        Code = "san_unreadable"
	SANIPBadLen          Code = "san_ip_bad_len"
	SANDNSBadString      Code = "san_dns_bad_string"
	AKIUnreadable        Code = "aki_unreadable"
	SKIUnreadable        Code = "ski_unreadable"
)

// Codes lists every code in a fixed order, for docs and explain-error.
var Codes = []Code{CertUnreadable, CertTrailingData, SignatureUnreadable, TBSUnreadable, TBSExtraFields, VersionBad,
	SerialUnreadable, SerialNegative, SerialZero, SerialTooLong, SerialNotMinimal,
	SigAlgUnreadable, SigAlgMismatch, IssuerUnreadable, SubjectUnreadable, NameBadString,
	ValidityUnreadable, TimeBadFormat, SPKIUnreadable, KeyUnreadable,
	ExtensionsUnreadable, ExtUnreadable, ExtDuplicate, SANUnreadable, SANIPBadLen, SANDNSBadString,
	AKIUnreadable, SKIUnreadable}

var explanations = map[Code]string{
	CertUnreadable:      "The certificate is not a DER SEQUENCE of TBSCertificate, signatureAlgorithm and signature. Nothing else can be read; parse_status is failed.",
	CertTrailingData:    "Bytes follow the certificate's DER encoding. They are ignored; the certificate itself is read.",
	SignatureUnreadable: "The outer signatureAlgorithm or signatureValue cannot be read. The TBSCertificate's fields are still extracted.",
	TBSUnreadable:       "The TBSCertificate's fixed fields (serial, signature, issuer, validity, subject, subjectPublicKeyInfo) cannot be located. parse_status is failed.",
	TBSExtraFields:      "The TBSCertificate has elements besides RFC 5280's fields. They are ignored; the other fields are read.",
	VersionBad:          "The explicit version is not v1, v2 or v3 (0, 1 or 2), or cannot be read.",

	SerialUnreadable: "The serialNumber is not a readable INTEGER.",
	SerialNegative:   "The serialNumber is negative; RFC 5280 §4.1.2.2 requires a positive integer. Its raw content bytes are kept.",
	SerialZero:       "The serialNumber is zero; RFC 5280 §4.1.2.2 requires a positive integer.",
	SerialTooLong:    "The serialNumber has more than 20 content octets, RFC 5280's limit. Its raw content bytes are kept.",
	SerialNotMinimal: "The serialNumber INTEGER is not minimally encoded (a redundant leading 0x00 or 0xFF), which DER forbids. Its raw content bytes are kept.",

	SigAlgUnreadable: "The signature AlgorithmIdentifier cannot be read.",
	SigAlgMismatch:   "The TBSCertificate's signature algorithm differs from the outer signatureAlgorithm (RFC 5280 §4.1.1.2).",

	IssuerUnreadable:  "The issuer is not a readable Name (a SEQUENCE of RDN SETs of attribute type and value).",
	SubjectUnreadable: "The subject is not a readable Name (a SEQUENCE of RDN SETs of attribute type and value).",
	NameBadString:     "A name attribute's value is not valid for its string type (for example invalid UTF-8, or an odd-length BMPString). It is rendered with \\XX escapes for the bad bytes.",

	ValidityUnreadable: "The validity is not a SEQUENCE of two times.",
	TimeBadFormat:      "A notBefore or notAfter value is not a valid UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ) as RFC 5280 §4.1.2.5 requires. The value is left null.",

	SPKIUnreadable: "The subjectPublicKeyInfo is not a readable SEQUENCE of an AlgorithmIdentifier and a BIT STRING.",
	KeyUnreadable:  "The public key cannot be interpreted for its algorithm (for example an RSA key without a valid modulus, or an unreadable curve). The key size and curve are left empty.",

	ExtensionsUnreadable: "The extensions field cannot be read; no extension is extracted.",
	ExtUnreadable:        "One extension is malformed: it is skipped, or its value could not be decoded.",
	ExtDuplicate:         "An extension OID appears more than once; RFC 5280 §4.2 forbids it. The first occurrence is used.",
	SANUnreadable:        "The subjectAltName value cannot be parsed; no SAN is extracted.",
	SANIPBadLen:          "An iPAddress SAN is neither 4 nor 16 bytes. It is kept as hex and is not a valid address.",
	SANDNSBadString:      "A dNSName SAN contains bytes outside ASCII (IA5String). It is rendered with \\XX escapes for the bad bytes.",
	AKIUnreadable:        "The authorityKeyIdentifier extension cannot be parsed.",
	SKIUnreadable:        "The subjectKeyIdentifier extension cannot be parsed.",
}

// Explain returns the code's explanation, or "" for an unknown code.
func (c Code) Explain() string { return explanations[c] }
```

Replace `internal/cli/testdata/error_codes.txt` with:

```text
# Every published error code, "<catalog> <code>". Codes are stored in datasets:
# never rename or remove a line; append new codes (amendment A2 §3.3).
leaf leaf_bad_version
leaf leaf_bad_leaf_type
leaf leaf_unknown_entry_type
leaf leaf_truncated
leaf leaf_trailing_bytes
leaf extra_truncated
leaf extra_trailing_bytes
leaf chain_cert_empty
leaf chain_issuer_missing
leaf chain_issuer_ambiguous
leaf issuer_key_hash_mismatch
leaf precert_tbs_mismatch
leaf issuance_key_unavailable
extract cert_unreadable
extract cert_trailing_data
extract tbs_unreadable
extract version_bad
extract serial_unreadable
extract serial_negative
extract serial_zero
extract serial_too_long
extract serial_not_minimal
extract sig_alg_unreadable
extract sig_alg_mismatch
extract issuer_unreadable
extract subject_unreadable
extract name_bad_string
extract validity_unreadable
extract time_bad_format
extract spki_unreadable
extract key_unreadable
extract extensions_unreadable
extract ext_unreadable
extract ext_duplicate
extract san_unreadable
extract san_ip_bad_len
extract san_dns_bad_string
extract aki_unreadable
extract ski_unreadable
extract signature_unreadable
extract tbs_extra_fields
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race ./internal/extract/ ./internal/cli/`
Expected: PASS.

`TestParseFailsOnlyOnStructure` is the test that found the position bug (Evidence 7). Without the optional trailing fields removed before counting, a TBS that lacks its public key reads the extensions as the key and reports `partial [spki_unreadable]` instead of `failed [tbs_unreadable]`.

- [ ] **Step 5: Quality gate**

- [ ] **Step 6: Checkpoint.**

---

### Task A4: Extensions

Amendment A2 §3.3, and spec §7.4 (`san_ip_bad_len`).

**Files:**
- Create: `internal/extract/ext.go`
- Modify: `internal/extract/cert.go` (adds the extension fields and calls `parseExtensions`)
- Test: `internal/extract/ext_test.go`

**Interfaces:**
- Produces:
  - `extract.Extension{OID string; Critical bool; Value []byte}`;
  - new `Cert` fields: `Extensions`, `DNSNames` (display-escaped), `IPAddresses` (raw, any length), `AuthorityKeyID`, `SubjectKeyID` and `HasCTPoison`.

- [ ] **Step 1: Write the failing tests**

Create `internal/extract/ext_test.go`:

```go
package extract

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"net"
	"slices"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidSAN    = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidSKIx   = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidAKIx   = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidPoison = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
)

// ext encodes one Extension.
func ext(oid asn1.ObjectIdentifier, critical bool, value []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
		if critical {
			b.AddASN1Boolean(true)
		}
		b.AddASN1OctetString(value)
	})
	return b.BytesOrPanic()
}

// extsField is the TBSCertificate's [3] extensions field.
func extsField(exts ...[]byte) []byte {
	return element(cbasn1.Tag(3).Constructed().ContextSpecific(), seq(exts...))
}

func san(names ...[]byte) []byte { return seq(names...) }
func dnsName(s string) []byte    { return element(cbasn1.Tag(2).ContextSpecific(), []byte(s)) }
func ipName(b []byte) []byte     { return element(cbasn1.Tag(7).ContextSpecific(), b) }

func withExtensions(t *testing.T, exts ...[]byte) *Cert {
	t.Helper()
	p := validParts(t)
	p.extra = [][]byte{extsField(exts...)}
	return Parse(p.der())
}

func TestExtensionsFromX509(t *testing.T) {
	der := selfSigned(t, testRSA, func(c *x509.Certificate) {
		c.DNSNames = []string{"a.example", "*.b.example"}
		c.IPAddresses = []net.IP{net.ParseIP("192.0.2.1").To4(), net.ParseIP("2001:db8::1")}
		c.SubjectKeyId = []byte{1, 2, 3}
		c.AuthorityKeyId = []byte{4, 5, 6}
	})
	ref, _ := x509.ParseCertificate(der)
	got := Parse(der)
	if got.Status != StatusOK {
		t.Fatalf("%s %v", got.Status, got.Errors)
	}
	if !slices.Equal(got.DNSNames, ref.DNSNames) || len(got.IPAddresses) != 2 ||
		!net.IP(got.IPAddresses[0]).Equal(ref.IPAddresses[0]) || !net.IP(got.IPAddresses[1]).Equal(ref.IPAddresses[1]) {
		t.Errorf("SANs %v %x", got.DNSNames, got.IPAddresses)
	}
	if !bytes.Equal(got.SubjectKeyID, ref.SubjectKeyId) || !bytes.Equal(got.AuthorityKeyID, ref.AuthorityKeyId) {
		t.Errorf("key IDs %x %x", got.SubjectKeyID, got.AuthorityKeyID)
	}
	if len(got.Extensions) != len(ref.Extensions) {
		t.Fatalf("%d extensions, want %d", len(got.Extensions), len(ref.Extensions))
	}
	for i, e := range ref.Extensions {
		if g := got.Extensions[i]; g.OID != e.Id.String() || g.Critical != e.Critical || !bytes.Equal(g.Value, e.Value) {
			t.Errorf("extension %d: %+v, want %s %v", i, g, e.Id, e.Critical)
		}
	}
}

func TestExtensionProblems(t *testing.T) {
	good := ext(oidSAN, false, san(dnsName("first.example")))
	for _, c := range []struct {
		name  string
		exts  [][]byte
		codes []Code
		check func(*Cert) bool
	}{
		{"duplicate: the first is used", [][]byte{good, ext(oidSAN, false, san(dnsName("second.example")))}, []Code{ExtDuplicate},
			func(c *Cert) bool {
				return slices.Equal(c.DNSNames, []string{"first.example"}) && len(c.Extensions) == 2
			}},
		{"one malformed extension is skipped", [][]byte{seq(oidElem(oidSAN)), good}, []Code{ExtUnreadable},
			func(c *Cert) bool {
				return slices.Equal(c.DNSNames, []string{"first.example"}) && len(c.Extensions) == 1
			}},
		{"IP SAN of 5 bytes is kept", [][]byte{ext(oidSAN, false, san(ipName([]byte{1, 2, 3, 4, 5})))}, []Code{SANIPBadLen},
			func(c *Cert) bool { return len(c.IPAddresses) == 1 && len(c.IPAddresses[0]) == 5 }},
		{"non-ASCII dNSName", [][]byte{ext(oidSAN, false, san(dnsName("caf\xc3\xa9.example")))}, []Code{SANDNSBadString},
			func(c *Cert) bool { return slices.Equal(c.DNSNames, []string{`caf\C3\A9.example`}) }},
		{"an unreadable SAN yields no names", [][]byte{ext(oidSAN, false, append(san(dnsName("x.example")), 0xff))}, []Code{SANUnreadable},
			func(c *Cert) bool { return len(c.DNSNames) == 0 }},
		{"other GeneralNames are skipped", [][]byte{ext(oidSAN, false, san(element(cbasn1.Tag(1).ContextSpecific(), []byte("a@b")), dnsName("y.example")))}, nil,
			func(c *Cert) bool { return slices.Equal(c.DNSNames, []string{"y.example"}) }},
		{"unreadable AKI", [][]byte{ext(oidAKIx, false, []byte{0x04, 0x01, 0x00})}, []Code{AKIUnreadable},
			func(c *Cert) bool { return c.AuthorityKeyID == nil }},
		{"unreadable SKI", [][]byte{ext(oidSKIx, false, []byte{0x30, 0x00})}, []Code{SKIUnreadable},
			func(c *Cert) bool { return c.SubjectKeyID == nil }},
		{"CT poison", [][]byte{ext(oidPoison, true, []byte{0x05, 0x00})}, nil,
			func(c *Cert) bool { return c.HasCTPoison && c.Extensions[0].Critical }},
		{"CT poison that is not NULL", [][]byte{ext(oidPoison, true, []byte{0x04, 0x00})}, []Code{ExtUnreadable},
			func(c *Cert) bool { return c.HasCTPoison }},
	} {
		got := withExtensions(t, c.exts...)
		if !slices.Equal(got.Errors, c.codes) || !c.check(got) {
			t.Errorf("%s: codes %v, DNS %q, IPs %x, %d extensions", c.name, got.Errors, got.DNSNames, got.IPAddresses, len(got.Extensions))
		}
	}
	p := validParts(t)
	p.extra = [][]byte{element(cbasn1.Tag(3).Constructed().ContextSpecific(), []byte{0x05, 0x00})}
	if got := Parse(p.der()); !slices.Equal(got.Errors, []Code{ExtensionsUnreadable}) || got.Extensions != nil {
		t.Errorf("unreadable extensions field: %v", got.Errors)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/extract/`
Expected: FAIL with `got.DNSNames undefined (type *Cert has no field or method DNSNames)` in `internal/extract`.

- [ ] **Step 3: Implement**

Create `internal/extract/ext.go`:

```go
package extract

import (
	"encoding/asn1"
	"fmt"
	"strings"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Extension is one extension as encoded.
type Extension struct {
	OID      string // dotted
	Critical bool
	Value    []byte // the extnValue OCTET STRING's content
}

// Extension OIDs the extractor decodes.
const (
	oidSubjectAltName = "2.5.29.17"
	oidSubjectKeyID   = "2.5.29.14"
	oidAuthorityKeyID = "2.5.29.35"
	oidCTPoison       = "1.3.6.1.4.1.11129.2.4.3"
)

var (
	tagExtensions = cbasn1.Tag(3).Constructed().ContextSpecific()
	tagDNSName    = cbasn1.Tag(2).ContextSpecific()
	tagIPAddress  = cbasn1.Tag(7).ContextSpecific()
	tagKeyID      = cbasn1.Tag(0).ContextSpecific()
)

// parseExtensions reads the TBSCertificate's optional trailing fields and
// decodes the extensions in the [3] field. Every extension is listed; the
// decoded fields come from the first occurrence of each OID.
func (c *Cert) parseExtensions(optional [][]byte) {
	var field []byte
	for _, el := range optional {
		if len(el) > 0 && cbasn1.Tag(el[0]) == tagExtensions {
			field = el
		}
	}
	if field == nil {
		return
	}
	s := cryptobyte.String(field)
	var wrapped, list cryptobyte.String
	if !s.ReadASN1(&wrapped, tagExtensions) || !wrapped.ReadASN1(&list, cbasn1.SEQUENCE) || !wrapped.Empty() {
		c.add(ExtensionsUnreadable)
		return
	}
	seen := map[string]bool{}
	for !list.Empty() {
		var el cryptobyte.String
		if !list.ReadASN1(&el, cbasn1.SEQUENCE) {
			c.add(ExtensionsUnreadable)
			return
		}
		var oid asn1.ObjectIdentifier
		var e Extension
		var value cryptobyte.String
		if !el.ReadASN1ObjectIdentifier(&oid) ||
			el.PeekASN1Tag(cbasn1.BOOLEAN) && !el.ReadASN1Boolean(&e.Critical) ||
			!el.ReadASN1(&value, cbasn1.OCTET_STRING) || !el.Empty() {
			c.add(ExtUnreadable)
			continue
		}
		e.OID, e.Value = oid.String(), value
		c.Extensions = append(c.Extensions, e)
		if seen[e.OID] {
			c.add(ExtDuplicate)
			continue
		}
		seen[e.OID] = true
		c.decodeExtension(e)
	}
}

func (c *Cert) decodeExtension(e Extension) {
	v := cryptobyte.String(e.Value)
	switch e.OID {
	case oidSubjectAltName:
		c.parseSAN(v)
	case oidSubjectKeyID:
		var id cryptobyte.String
		if !v.ReadASN1(&id, cbasn1.OCTET_STRING) || !v.Empty() {
			c.add(SKIUnreadable)
			return
		}
		c.SubjectKeyID = id
	case oidAuthorityKeyID:
		var seq, id cryptobyte.String
		var present bool
		if !v.ReadASN1(&seq, cbasn1.SEQUENCE) || !v.Empty() || !seq.ReadOptionalASN1(&id, &present, tagKeyID) {
			c.add(AKIUnreadable)
			return
		}
		if present {
			c.AuthorityKeyID = id
		}
	case oidCTPoison:
		c.HasCTPoison = true
		if string(e.Value) != "\x05\x00" { // RFC 6962 §3.1: an ASN.1 NULL
			c.add(ExtUnreadable)
		}
	}
}

// parseSAN reads dNSName and iPAddress GeneralNames; other kinds are
// skipped. An unreadable SAN yields no names at all.
func (c *Cert) parseSAN(v cryptobyte.String) {
	var names cryptobyte.String
	if !v.ReadASN1(&names, cbasn1.SEQUENCE) || !v.Empty() {
		c.add(SANUnreadable)
		return
	}
	var dns []string
	var ips [][]byte
	var codes []Code
	for !names.Empty() {
		var gn cryptobyte.String
		var tag cbasn1.Tag
		if !names.ReadAnyASN1(&gn, &tag) {
			c.add(SANUnreadable)
			return
		}
		switch tag {
		case tagDNSName:
			name, ok := asciiDisplay(gn)
			if !ok {
				codes = append(codes, SANDNSBadString)
			}
			dns = append(dns, name)
		case tagIPAddress:
			if len(gn) != 4 && len(gn) != 16 {
				codes = append(codes, SANIPBadLen)
			}
			ips = append(ips, gn)
		}
	}
	c.DNSNames, c.IPAddresses = dns, ips
	for _, code := range codes {
		c.add(code)
	}
}

// asciiDisplay renders an IA5String: bytes outside ASCII and control
// characters become \XX, and a backslash is doubled. ok is false when a
// byte is outside ASCII.
func asciiDisplay(b []byte) (string, bool) {
	ok := true
	var s strings.Builder
	for _, x := range b {
		switch {
		case x >= 0x80:
			ok = false
			fmt.Fprintf(&s, `\%02X`, x)
		case x < 0x20 || x == 0x7f:
			fmt.Fprintf(&s, `\%02X`, x)
		case x == '\\':
			s.WriteString(`\\`)
		default:
			s.WriteByte(x)
		}
	}
	return s.String(), ok
}
```

Replace `internal/extract/cert.go` with:

```go
package extract

import (
	"bytes"
	"encoding/asn1"
	"slices"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Status is certs.parse_status.
type Status string

const (
	StatusOK      Status = "ok"      // no error code
	StatusPartial Status = "partial" // at least one field could not be read
	StatusFailed  Status = "failed"  // the Certificate or the TBSCertificate cannot be read
)

// Cert is what the extractor read from one certificate. Byte slices alias
// the input. Fields that could not be read are zero, and Errors says why.
type Cert struct {
	Status Status
	Errors []Code // in the order found, each code at most once

	Version            int    // 1, 2 or 3; 0 when unreadable
	Serial             []byte // the raw INTEGER content bytes; nil when unreadable
	SignatureAlgorithm string // the TBSCertificate's: a name, or the dotted OID; "" when unreadable

	Issuer, Subject Name

	NotBefore, NotAfter       time.Time // UTC
	HasNotBefore, HasNotAfter bool

	Key Key

	Extensions     []Extension // every extension, in order
	DNSNames       []string    // dNSName SANs, display-escaped (bytes outside ASCII as \XX)
	IPAddresses    [][]byte    // iPAddress SANs, raw; 4 or 16 bytes when valid
	AuthorityKeyID []byte      // the AKI's keyIdentifier
	SubjectKeyID   []byte
	HasCTPoison    bool // the RFC 6962 precertificate poison extension is present
}

func (c *Cert) add(code Code) {
	if !slices.Contains(c.Errors, code) {
		c.Errors = append(c.Errors, code)
	}
}

var tagVersion = cbasn1.Tag(0).Constructed().ContextSpecific()

// Parse reads der leniently (amendment A2 §3). It never fails and never
// panics: what cannot be read stays zero and adds an error code.
func Parse(der []byte) *Cert {
	c := &Cert{}
	c.parse(der)
	switch {
	case slices.Contains(c.Errors, CertUnreadable), slices.Contains(c.Errors, TBSUnreadable):
		c.Status = StatusFailed
	case len(c.Errors) > 0:
		c.Status = StatusPartial
	default:
		c.Status = StatusOK
	}
	return c
}

func (c *Cert) parse(der []byte) {
	s := cryptobyte.String(der)
	var body, tbs cryptobyte.String
	if !s.ReadASN1(&body, cbasn1.SEQUENCE) || !body.ReadASN1(&tbs, cbasn1.SEQUENCE) {
		c.add(CertUnreadable)
		return
	}
	if !s.Empty() {
		c.add(CertTrailingData)
	}
	var outerAlg cryptobyte.String
	var sig asn1.BitString
	if !body.ReadASN1Element(&outerAlg, cbasn1.SEQUENCE) || !body.ReadASN1BitString(&sig) || !body.Empty() {
		c.add(SignatureUnreadable)
		outerAlg = nil
	}

	var els [][]byte
	var tags []cbasn1.Tag
	for !tbs.Empty() {
		var el cryptobyte.String
		var tag cbasn1.Tag
		if !tbs.ReadAnyASN1Element(&el, &tag) {
			// Past the six fixed fields only the optional ones remain: an
			// unreadable tail loses the extensions, not the certificate.
			fixedSeen := len(els)
			if len(tags) > 0 && tags[0] == tagVersion {
				fixedSeen--
			}
			if fixedSeen < 6 {
				c.add(TBSUnreadable)
				return
			}
			c.add(ExtensionsUnreadable)
			break
		}
		els, tags = append(els, el), append(tags, tag)
	}
	i := 0
	c.Version = 1
	if len(tags) > 0 && tags[0] == tagVersion {
		c.Version = parseVersion(els[0])
		if c.Version == 0 {
			c.add(VersionBad)
		}
		i = 1
	}
	// The six fixed fields come before the optional issuerUniqueID [1],
	// subjectUniqueID [2] and extensions [3].
	fixed := len(els)
	for fixed > i && isOptionalTBSField(tags[fixed-1]) {
		fixed--
	}
	if fixed < i+6 {
		c.Version = 0
		c.add(TBSUnreadable)
		return
	}
	if fixed > i+6 {
		c.add(TBSExtraFields)
	}
	c.parseSerial(els[i])
	c.parseSignatureAlgorithm(els[i+1], outerAlg)
	var ok bool
	if c.Issuer, ok = parseName(els[i+2]); !ok {
		c.add(IssuerUnreadable)
	} else if c.Issuer.badStrings() {
		c.add(NameBadString)
	}
	c.parseValidity(els[i+3])
	if c.Subject, ok = parseName(els[i+4]); !ok {
		c.add(SubjectUnreadable)
	} else if c.Subject.badStrings() {
		c.add(NameBadString)
	}
	var codes []Code
	c.Key, codes = parseKey(els[i+5])
	for _, code := range codes {
		c.add(code)
	}
	c.parseExtensions(els[fixed:])
}

func isOptionalTBSField(t cbasn1.Tag) bool {
	return t == cbasn1.Tag(1).ContextSpecific() || t == cbasn1.Tag(2).ContextSpecific() ||
		t == cbasn1.Tag(1).Constructed().ContextSpecific() || t == cbasn1.Tag(2).Constructed().ContextSpecific() ||
		t == cbasn1.Tag(3).Constructed().ContextSpecific()
}

// parseVersion reads [0] EXPLICIT INTEGER: 0, 1 or 2 are v1-v3; anything
// else is 0.
func parseVersion(el []byte) int {
	s := cryptobyte.String(el)
	var inner cryptobyte.String
	var v int
	if !s.ReadASN1(&inner, tagVersion) || !inner.ReadASN1Integer(&v) || !inner.Empty() || v < 0 || v > 2 {
		return 0
	}
	return v + 1
}

// parseSerial keeps the raw INTEGER content and flags what RFC 5280 and DER
// forbid.
func (c *Cert) parseSerial(el []byte) {
	s := cryptobyte.String(el)
	var v cryptobyte.String
	if !s.ReadASN1(&v, cbasn1.INTEGER) || len(v) == 0 {
		c.add(SerialUnreadable)
		return
	}
	c.Serial = v
	if v[0]&0x80 != 0 {
		c.add(SerialNegative)
	}
	if len(v) > 1 && (v[0] == 0x00 && v[1]&0x80 == 0 || v[0] == 0xFF && v[1]&0x80 != 0) {
		c.add(SerialNotMinimal)
	}
	if bytes.Count(v, []byte{0}) == len(v) {
		c.add(SerialZero)
	}
	if len(v) > 20 {
		c.add(SerialTooLong)
	}
}

// parseSignatureAlgorithm names the TBSCertificate's signature algorithm and
// checks it against the outer one (RFC 5280 §4.1.1.2).
func (c *Cert) parseSignatureAlgorithm(el, outer []byte) {
	s := cryptobyte.String(el)
	var alg cryptobyte.String
	var oid asn1.ObjectIdentifier
	if !s.ReadASN1(&alg, cbasn1.SEQUENCE) || !alg.ReadASN1ObjectIdentifier(&oid) {
		c.add(SigAlgUnreadable)
		return
	}
	c.SignatureAlgorithm = oid.String()
	if name, ok := signatureAlgorithms[c.SignatureAlgorithm]; ok {
		c.SignatureAlgorithm = name
	}
	if outer != nil && !bytes.Equal(el, outer) {
		c.add(SigAlgMismatch)
	}
}

func (c *Cert) parseValidity(el []byte) {
	s := cryptobyte.String(el)
	var v cryptobyte.String
	var nb, na cryptobyte.String
	var nbTag, naTag cbasn1.Tag
	if !s.ReadASN1(&v, cbasn1.SEQUENCE) || !v.ReadAnyASN1(&nb, &nbTag) || !v.ReadAnyASN1(&na, &naTag) || !v.Empty() {
		c.add(ValidityUnreadable)
		return
	}
	var ok bool
	if c.NotBefore, ok = parseTime(nbTag, nb); ok {
		c.HasNotBefore = true
	} else {
		c.add(TimeBadFormat)
	}
	if c.NotAfter, ok = parseTime(naTag, na); ok {
		c.HasNotAfter = true
	} else {
		c.add(TimeBadFormat)
	}
}

// parseTime reads a time as RFC 5280 §4.1.2.5 requires: UTCTime
// YYMMDDHHMMSSZ (YY below 50 is 20YY) or GeneralizedTime YYYYMMDDHHMMSSZ.
func parseTime(tag cbasn1.Tag, b []byte) (time.Time, bool) {
	var digits []byte
	switch {
	case tag == cbasn1.UTCTime && len(b) == 13 && b[12] == 'Z':
		digits = b[:12]
	case tag == cbasn1.GeneralizedTime && len(b) == 15 && b[14] == 'Z':
		digits = b[:14]
	default:
		return time.Time{}, false
	}
	n := make([]int, 0, 7)
	for i := 0; i < len(digits); i += 2 {
		if digits[i] < '0' || digits[i] > '9' || digits[i+1] < '0' || digits[i+1] > '9' {
			return time.Time{}, false
		}
		n = append(n, int(digits[i]-'0')*10+int(digits[i+1]-'0'))
	}
	var year int
	if tag == cbasn1.UTCTime {
		year = 2000 + n[0]
		if n[0] >= 50 {
			year = 1900 + n[0]
		}
		n = n[1:]
	} else {
		year, n = n[0]*100+n[1], n[2:]
	}
	t := time.Date(year, time.Month(n[0]), n[1], n[2], n[3], n[4], 0, time.UTC)
	if t.Year() != year || int(t.Month()) != n[0] || t.Day() != n[1] || t.Hour() != n[2] || t.Minute() != n[3] || t.Second() != n[4] {
		return time.Time{}, false // out of range: month 13, February 30, hour 24
	}
	return t, true
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -race ./internal/extract/`
Expected: PASS.

- [ ] **Step 5: Quality gate**

- [ ] **Step 6: Checkpoint.**

---

### Task A5: The real corpus, the malformed corpus, the differential check and fuzzing

Spec §13 items 2–3, amendment A2 §3.4.

**Files:**
- Create tests:
  - `internal/extract/golden_test.go`
  - `internal/extract/differential_test.go`
  - `internal/extract/malformed_test.go`
  - `internal/extract/fuzz_test.go`
  - `internal/extract/corpus_realdata_test.go` (`//go:build realdata`)
- Create test data: `internal/extract/testdata/corpus.bin.zst`, `corpus.golden.zst` (generated in Steps 2–3) and `malformed.golden`

**What each test checks:**
- `TestGoldenCorpus`: each real certificate extracts to its golden line, including `issuer_cn`, `issuer_o` and `subject_cn`.
- `TestDeterminism`: identical results under concurrent runs.
- `TestDifferentialCorpus`: no difference with `crypto/x509` (Decision 9).
- `TestMalformedCorpus`: 27 deterministic cases, each asserting its code, plus a golden.
- `FuzzParse`: no panic, two equal results, status consistent with codes, codes known and unique.
- Under `realdata`:
  - `TestWriteGoldenCorpus` writes the corpus with `-write-corpus`;
  - `TestDifferentialRealSamples` compares every certificate of both samples.

- [ ] **Step 1: Write the tests**

Create `internal/extract/golden_test.go`:

```go
package extract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/")

// corpus reads testdata/corpus.bin.zst: real certificates from the cached
// samples (written by TestWriteGoldenCorpus under -tags realdata).
func corpus(t testing.TB) [][]byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "corpus.bin.zst"))
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
		if k <= 0 || uint64(len(raw)-k) < n {
			t.Fatal("corrupt corpus")
		}
		out = append(out, raw[k:k+int(n)])
		raw = raw[k+int(n):]
	}
	return out
}

// row is one golden line: everything Parse returns, compactly.
type row struct {
	SHA256      string   `json:"sha256"`
	Status      Status   `json:"status"`
	Errors      []Code   `json:"errors,omitempty"`
	Version     int      `json:"version"`
	Serial      string   `json:"serial"`
	SigAlg      string   `json:"sig_alg"`
	Issuer      string   `json:"issuer"`
	IssuerCN    string   `json:"issuer_cn,omitempty"`
	IssuerO     string   `json:"issuer_o,omitempty"`
	SubjectCN   string   `json:"subject_cn,omitempty"`
	IssuerRaw   string   `json:"issuer_raw_sha256"`
	Subject     string   `json:"subject"`
	SubjectRaw  string   `json:"subject_raw_sha256"`
	NotBefore   string   `json:"not_before,omitempty"`
	NotAfter    string   `json:"not_after,omitempty"`
	Key         Key      `json:"key"`
	Extensions  []string `json:"extensions,omitempty"` // "oid" or "oid!" when critical
	DNSNames    []string `json:"dns,omitempty"`
	IPAddresses []string `json:"ips,omitempty"`
	AKI         string   `json:"aki,omitempty"`
	SKI         string   `json:"ski,omitempty"`
	Poison      bool     `json:"poison,omitempty"`
}

func shaHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func summarize(der []byte) row {
	c := Parse(der)
	r := row{SHA256: shaHex(der), Status: c.Status, Errors: c.Errors, Version: c.Version, Serial: hex.EncodeToString(c.Serial),
		SigAlg: c.SignatureAlgorithm, Issuer: c.Issuer.String(), IssuerRaw: shaHex(c.Issuer.Raw), Subject: c.Subject.String(),
		SubjectRaw: shaHex(c.Subject.Raw), Key: c.Key, DNSNames: c.DNSNames, AKI: hex.EncodeToString(c.AuthorityKeyID),
		SKI: hex.EncodeToString(c.SubjectKeyID), Poison: c.HasCTPoison}
	r.IssuerCN, _ = c.Issuer.First(OIDCommonName)
	r.IssuerO, _ = c.Issuer.First(OIDOrganization)
	r.SubjectCN, _ = c.Subject.First(OIDCommonName)
	if c.HasNotBefore {
		r.NotBefore = c.NotBefore.Format(time.RFC3339)
	}
	if c.HasNotAfter {
		r.NotAfter = c.NotAfter.Format(time.RFC3339)
	}
	for _, e := range c.Extensions {
		s := e.OID
		if e.Critical {
			s += "!"
		}
		r.Extensions = append(r.Extensions, s)
	}
	for _, ip := range c.IPAddresses {
		r.IPAddresses = append(r.IPAddresses, hex.EncodeToString(ip))
	}
	return r
}

// checkGolden compares lines with the golden file, or rewrites it with
// -update. compressed files are zstd frames.
func checkGolden(t *testing.T, name string, lines []string, compressed bool) {
	t.Helper()
	got := []byte(strings.Join(lines, "\n") + "\n")
	path := filepath.Join("testdata", name)
	if *update {
		out := got
		if compressed {
			enc, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression), zstd.WithEncoderConcurrency(1))
			out = enc.EncodeAll(got, nil)
		}
		if err := os.WriteFile(path, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if compressed {
		dec, _ := zstd.NewReader(nil)
		defer dec.Close()
		if want, err = dec.DecodeAll(want, nil); err != nil {
			t.Fatal(err)
		}
	}
	if bytes.Equal(got, want) {
		return
	}
	g, w := strings.Split(string(got), "\n"), strings.Split(string(want), "\n")
	for i := range min(len(g), len(w)) {
		if g[i] != w[i] {
			t.Fatalf("%s line %d differs:\n got  %s\n want %s", name, i+1, g[i], w[i])
		}
	}
	t.Fatalf("%s: %d lines, want %d", name, len(g), len(w))
}

func jsonLine(t *testing.T, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestGoldenCorpus: every real certificate in the corpus extracts to its
// golden line. A change to any extracted value shows up here first.
func TestGoldenCorpus(t *testing.T) {
	var lines []string
	statuses := map[Status]int{}
	for _, der := range corpus(t) {
		r := summarize(der)
		statuses[r.Status]++
		lines = append(lines, jsonLine(t, r))
	}
	t.Logf("%d certificates: %v", len(lines), statuses)
	checkGolden(t, "corpus.golden.zst", lines, true)
}

// TestDeterminism: the same DER gives the same result every time, whatever
// GOMAXPROCS is (spec §7.2).
func TestDeterminism(t *testing.T) {
	certs := corpus(t)
	first := make([]string, len(certs))
	for i, der := range certs {
		first[i] = fmt.Sprintf("%+v", *Parse(der))
	}
	done := make(chan bool)
	for range 4 {
		go func() {
			for i, der := range certs {
				if fmt.Sprintf("%+v", *Parse(der)) != first[i] {
					t.Errorf("certificate %d extracts differently on another run", i)
				}
			}
			done <- true
		}()
	}
	for range 4 {
		<-done
	}
}

func BenchmarkParse(b *testing.B) {
	certs := corpus(b)
	b.ResetTimer()
	for i := range b.N {
		Parse(certs[i%len(certs)])
	}
}
```

Create `internal/extract/differential_test.go`:

```go
package extract

import (
	"bytes"
	"crypto/dsa" //nolint:staticcheck // the reference parser still returns DSA keys
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
)

// x509SigAlgs maps crypto/x509's signature algorithms to the extractor's
// names.
var x509SigAlgs = map[x509.SignatureAlgorithm]string{
	x509.MD2WithRSA: "md2WithRSAEncryption", x509.MD5WithRSA: "md5WithRSAEncryption",
	x509.SHA1WithRSA: "sha1WithRSAEncryption", x509.SHA256WithRSA: "sha256WithRSAEncryption",
	x509.SHA384WithRSA: "sha384WithRSAEncryption", x509.SHA512WithRSA: "sha512WithRSAEncryption",
	x509.SHA256WithRSAPSS: "rsassaPss", x509.SHA384WithRSAPSS: "rsassaPss", x509.SHA512WithRSAPSS: "rsassaPss",
	x509.DSAWithSHA1: "dsa-with-SHA1", x509.DSAWithSHA256: "dsa-with-SHA256",
	x509.ECDSAWithSHA1: "ecdsa-with-SHA1", x509.ECDSAWithSHA256: "ecdsa-with-SHA256",
	x509.ECDSAWithSHA384: "ecdsa-with-SHA384", x509.ECDSAWithSHA512: "ecdsa-with-SHA512",
	x509.PureEd25519: "Ed25519",
}

// plainASCII reports whether a display value is plain ASCII with no escape,
// so it can be compared with crypto/x509's string as is.
func plainASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= 0x80 || s[i] < 0x20 || s[i] == '\\' {
			return false
		}
	}
	return true
}

// count is how many attributes of type oid the name has.
func count(n Name, oid string) int {
	k := 0
	for _, rdn := range n.RDNs {
		for _, a := range rdn {
			if a.Type == oid {
				k++
			}
		}
	}
	return k
}

// compareX509 checks the extractor against crypto/x509 on a certificate both
// parse (amendment A2 §3.4). compared is false when either one fails.
func compareX509(der []byte) (compared bool, diffs []string) {
	ref, err := x509.ParseCertificate(der)
	c := Parse(der)
	if err != nil || c.Status == StatusFailed {
		return false, nil
	}
	diff := func(field string, got, want any) {
		diffs = append(diffs, fmt.Sprintf("%s: %v, crypto/x509 %v", field, got, want))
	}
	if c.Serial != nil && !slices.Contains(c.Errors, SerialNegative) && new(big.Int).SetBytes(c.Serial).Cmp(ref.SerialNumber) != 0 {
		diff("serial", fmt.Sprintf("%x", c.Serial), ref.SerialNumber)
	}
	if !bytes.Equal(c.Issuer.Raw, ref.RawIssuer) {
		diff("issuer DER", fmt.Sprintf("%x", c.Issuer.Raw), fmt.Sprintf("%x", ref.RawIssuer))
	}
	if !bytes.Equal(c.Subject.Raw, ref.RawSubject) {
		diff("subject DER", fmt.Sprintf("%x", c.Subject.Raw), fmt.Sprintf("%x", ref.RawSubject))
	}
	names := []struct {
		field string
		n     Name
		oid   string
		want  []string
	}{
		{"subject CN", c.Subject, OIDCommonName, []string{ref.Subject.CommonName}},
		{"subject O", c.Subject, OIDOrganization, ref.Subject.Organization},
		{"issuer CN", c.Issuer, OIDCommonName, []string{ref.Issuer.CommonName}},
		{"issuer O", c.Issuer, OIDOrganization, ref.Issuer.Organization},
	}
	for _, n := range names {
		want := ""
		if len(n.want) > 0 {
			want = n.want[0]
		}
		if n.oid == OIDCommonName && count(n.n, n.oid) > 1 {
			continue // crypto/x509 keeps the last CN; the extractor reports the first
		}
		switch got, ok := n.n.First(n.oid); {
		case !ok && want != "":
			diff(n.field, "(none)", want)
		case ok && plainASCII(got) && want != "" && got != want:
			diff(n.field, got, want)
		}
	}
	if c.HasNotBefore && !c.NotBefore.Equal(ref.NotBefore) {
		diff("not_before", c.NotBefore, ref.NotBefore)
	}
	if c.HasNotAfter && !c.NotAfter.Equal(ref.NotAfter) {
		diff("not_after", c.NotAfter, ref.NotAfter)
	}
	if !slices.Contains(c.Errors, SANUnreadable) && !slices.Contains(c.Errors, SANDNSBadString) &&
		!slices.ContainsFunc(c.DNSNames, func(s string) bool { return strings.Contains(s, `\`) }) && !slices.Equal(c.DNSNames, ref.DNSNames) {
		diff("DNS SANs", c.DNSNames, ref.DNSNames)
	}
	if !slices.Contains(c.Errors, SANIPBadLen) {
		var ips []net.IP
		for _, ip := range c.IPAddresses {
			ips = append(ips, ip)
		}
		if !slices.EqualFunc(ips, ref.IPAddresses, func(a, b net.IP) bool { return a.Equal(b) }) {
			diff("IP SANs", ips, ref.IPAddresses)
		}
	}
	if want, ok := x509SigAlgs[ref.SignatureAlgorithm]; ok && c.SignatureAlgorithm != want {
		diff("signature algorithm", c.SignatureAlgorithm, want)
	}
	var want Key
	switch pk := ref.PublicKey.(type) {
	case *rsa.PublicKey:
		want = Key{Algorithm: "rsa", Bits: pk.N.BitLen()}
	case *ecdsa.PublicKey:
		want = Key{Algorithm: "ecdsa", Bits: pk.Curve.Params().BitSize, Curve: pk.Curve.Params().Name}
	case ed25519.PublicKey:
		want = Key{Algorithm: "ed25519", Bits: 256}
	case *dsa.PublicKey:
		want = Key{Algorithm: "dsa", Bits: pk.P.BitLen()}
	}
	if want.Algorithm != "" {
		if got := (Key{Algorithm: c.Key.Algorithm, Bits: c.Key.Bits, Curve: c.Key.Curve}); got != want {
			diff("key", got, want)
		}
	}
	if !slices.Contains(c.Errors, SKIUnreadable) && !bytes.Equal(c.SubjectKeyID, ref.SubjectKeyId) {
		diff("SKI", fmt.Sprintf("%x", c.SubjectKeyID), fmt.Sprintf("%x", ref.SubjectKeyId))
	}
	if !slices.Contains(c.Errors, AKIUnreadable) && !bytes.Equal(c.AuthorityKeyID, ref.AuthorityKeyId) {
		diff("AKI", fmt.Sprintf("%x", c.AuthorityKeyID), fmt.Sprintf("%x", ref.AuthorityKeyId))
	}
	return true, diffs
}

// TestDifferentialCorpus: on every corpus certificate that both parse, the
// extractor agrees with crypto/x509.
func TestDifferentialCorpus(t *testing.T) {
	compared := 0
	for i, der := range corpus(t) {
		ok, diffs := compareX509(der)
		if ok {
			compared++
		}
		for _, d := range diffs {
			t.Errorf("certificate %d (%s): %s", i, shaHex(der)[:16], d)
		}
	}
	t.Logf("compared %d certificates with crypto/x509", compared)
	if compared == 0 {
		t.Fatal("nothing was compared")
	}
}
```

Create `internal/extract/malformed_test.go`:

```go
package extract

import (
	"bytes"
	"encoding/asn1"
	"slices"
	"testing"

	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// fixedParts is a well-formed certificate built from fixed bytes, so the
// malformed corpus derived from it is deterministic.
func fixedParts() parts {
	pattern := func(n int, seed byte) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = seed + byte(i*7)
		}
		return b
	}
	sha256RSA := seq(oidElem(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}), []byte{0x05, 0x00})
	modulus := append([]byte{0x00, 0xC5}, pattern(255, 3)...)
	rsaKey := seq(element(cbasn1.INTEGER, modulus), element(cbasn1.INTEGER, []byte{1, 0, 1}))
	return parts{
		version:     element(cbasn1.Tag(0).Constructed().ContextSpecific(), element(cbasn1.INTEGER, []byte{2})),
		serial:      element(cbasn1.INTEGER, []byte{0x01, 0x23, 0x45}),
		sigAlg:      sha256RSA,
		issuer:      buildName([]atv{{oidC, str(tagPrintable, "US")}}, []atv{{oidO, str(tagUTF8, "CTVault Test")}}, []atv{{oidCN, str(tagUTF8, "CTVault Test CA")}}),
		validity:    seq(element(cbasn1.UTCTime, []byte("260101000000Z")), element(cbasn1.UTCTime, []byte("260401000000Z"))),
		subject:     buildName([]atv{{oidCN, str(tagUTF8, "leaf.example")}}),
		spki:        spki(seq(oidElem(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}), []byte{0x05, 0x00}), rsaKey),
		extra:       [][]byte{extsField(ext(oidSAN, false, san(dnsName("leaf.example"))))},
		outerSigAlg: sha256RSA,
		signature:   element(cbasn1.BIT_STRING, append([]byte{0x00}, pattern(256, 9)...)),
	}
}

type malformed struct {
	name  string
	der   []byte
	codes []Code // codes the case must produce (the golden holds the full result)
}

// malformedCorpus is one well-formed certificate and one variant per
// malformation the lenient extractor must handle (amendment A2 §3.4).
func malformedCorpus() []malformed {
	with := func(edit func(*parts)) []byte {
		p := fixedParts()
		edit(&p)
		return p.der()
	}
	serial := func(b ...byte) []byte { return with(func(p *parts) { p.serial = element(cbasn1.INTEGER, b) }) }
	notBefore := func(tag cbasn1.Tag, s string) []byte {
		return with(func(p *parts) {
			p.validity = seq(element(tag, []byte(s)), element(cbasn1.UTCTime, []byte("260401000000Z")))
		})
	}
	sanExt := func(names ...[]byte) []byte {
		return with(func(p *parts) { p.extra = [][]byte{extsField(ext(oidSAN, false, san(names...)))} })
	}
	unknownAlg := seq(oidElem(asn1.ObjectIdentifier{1, 2, 3, 4, 5}))
	return []malformed{
		{"well-formed", with(func(*parts) {}), nil},

		{"serial negative", serial(0x80, 0x01), []Code{SerialNegative}},
		{"serial zero", serial(0x00), []Code{SerialZero}},
		{"serial of 21 octets", serial(bytes.Repeat([]byte{0x01}, 21)...), []Code{SerialTooLong}},
		{"serial not minimal", serial(0x00, 0x01), []Code{SerialNotMinimal}},

		{"UTCTime without seconds", notBefore(cbasn1.UTCTime, "2601010000Z"), []Code{TimeBadFormat}},
		{"UTCTime with an offset", notBefore(cbasn1.UTCTime, "260101000000+0100"), []Code{TimeBadFormat}},
		{"GeneralizedTime with a fraction", notBefore(cbasn1.GeneralizedTime, "20260101000000.5Z"), []Code{TimeBadFormat}},
		{"GeneralizedTime month 13", notBefore(cbasn1.GeneralizedTime, "20261301000000Z"), []Code{TimeBadFormat}},

		{"duplicate SAN extension", with(func(p *parts) {
			p.extra = [][]byte{extsField(ext(oidSAN, false, san(dnsName("first.example"))), ext(oidSAN, false, san(dnsName("second.example"))))}
		}), []Code{ExtDuplicate}},
		{"truncated extension list", with(func(p *parts) {
			p.extra = [][]byte{element(cbasn1.Tag(3).Constructed().ContextSpecific(),
				element(cbasn1.SEQUENCE, append(ext(oidSKIx, false, element(cbasn1.OCTET_STRING, []byte{1})), 0x30, 0x0a, 0x06, 0x03)))}
		}), []Code{ExtensionsUnreadable}},
		{"extensions field running past the TBS", with(func(p *parts) {
			p.extra = [][]byte{{0xA3, 0x10, 0x30, 0x01}}
		}), []Code{ExtensionsUnreadable}},
		{"truncated SAN", with(func(p *parts) {
			p.extra = [][]byte{extsField(ext(oidSAN, false, []byte{0x30, 0x10, 0x82, 0x03, 'a', '.', 'b'}))}
		}), []Code{SANUnreadable}},

		{"CN that is not a DNS name, no SAN", with(func(p *parts) {
			p.subject = buildName([]atv{{oidCN, str(tagUTF8, "Example Device 42")}})
			p.extra = nil
		}), nil},
		{"CN that is an IP literal", with(func(p *parts) {
			p.subject = buildName([]atv{{oidCN, str(tagUTF8, "192.0.2.7")}})
		}), nil},

		{"IP SANs of every odd length", sanExt(ipName(nil), ipName([]byte{1}), ipName([]byte{192, 0, 2, 1}), ipName([]byte{1, 2, 3, 4, 5}),
			ipName(make([]byte, 8)), ipName(make([]byte, 16)), ipName(make([]byte, 17))), []Code{SANIPBadLen}},

		{"unknown signature algorithm", with(func(p *parts) { p.sigAlg, p.outerSigAlg = unknownAlg, unknownAlg }), nil},
		{"signature algorithm mismatch", with(func(p *parts) {
			p.outerSigAlg = seq(oidElem(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}), []byte{0x05, 0x00})
		}), []Code{SigAlgMismatch}},
		{"unknown SPKI algorithm", with(func(p *parts) {
			p.spki = spki(seq(oidElem(asn1.ObjectIdentifier{1, 2, 3, 4, 6})), []byte{0xAA, 0xBB})
		}), nil},

		{"issuer CN with invalid UTF-8", with(func(p *parts) {
			p.issuer = buildName([]atv{{oidCN, str(tagUTF8, "Bad\xffIssuer")}})
		}), []Code{NameBadString}},
		{"subject CN as odd-length BMPString", with(func(p *parts) {
			p.subject = buildName([]atv{{oidCN, str(tagBMP, "\x00l\x00e\x00")}})
		}), []Code{NameBadString}},
		{"subject CN PrintableString with a non-ASCII byte", with(func(p *parts) {
			p.subject = buildName([]atv{{oidCN, str(tagPrintable, "caf\xe9")}})
		}), []Code{NameBadString}},
		{"issuer that is a SET", with(func(p *parts) { p.issuer = element(cbasn1.SET, nil) }), []Code{IssuerUnreadable}},

		{"trailing data after the certificate", with(func(p *parts) { p.trailing = []byte{0x00, 0x00} }), []Code{CertTrailingData}},
		{"extra TBS field", with(func(p *parts) { p.extra = append([][]byte{seq()}, p.extra...) }), []Code{TBSExtraFields}},
		{"TBS without a public key", with(func(p *parts) { p.spki = nil }), []Code{TBSUnreadable}},
		{"not a certificate", element(cbasn1.OCTET_STRING, []byte("not a certificate")), []Code{CertUnreadable}},
	}
}

// TestMalformedCorpus: each malformation produces its code, and the whole
// result matches testdata/malformed.golden.
func TestMalformedCorpus(t *testing.T) {
	var lines []string
	for _, m := range malformedCorpus() {
		c := Parse(m.der)
		for _, code := range m.codes {
			if !slices.Contains(c.Errors, code) {
				t.Errorf("%s: codes %v lack %s", m.name, c.Errors, code)
			}
		}
		if m.codes == nil && len(c.Errors) > 0 {
			t.Errorf("%s: unexpected codes %v", m.name, c.Errors)
		}
		lines = append(lines, m.name+"\t"+jsonLine(t, summarize(m.der)))
	}
	checkGolden(t, "malformed.golden", lines, false)
}
```

Create `internal/extract/fuzz_test.go`:

```go
package extract

import (
	"reflect"
	"slices"
	"testing"
)

// FuzzParse: the extractor never panics, gives the same result twice, and
// its status always agrees with its codes (amendment A2 §3.4).
func FuzzParse(f *testing.F) {
	for _, m := range malformedCorpus() {
		f.Add(m.der)
	}
	for _, der := range corpus(f)[:50] {
		f.Add(der)
	}
	f.Fuzz(func(t *testing.T, der []byte) {
		c := Parse(der)
		if again := Parse(der); !reflect.DeepEqual(c, again) {
			t.Fatal("two parses of the same bytes differ")
		}
		failed := slices.Contains(c.Errors, CertUnreadable) || slices.Contains(c.Errors, TBSUnreadable)
		switch {
		case failed && c.Status != StatusFailed,
			!failed && len(c.Errors) > 0 && c.Status != StatusPartial,
			len(c.Errors) == 0 && c.Status != StatusOK:
			t.Fatalf("status %s with codes %v", c.Status, c.Errors)
		}
		seen := map[Code]bool{}
		for _, code := range c.Errors {
			if seen[code] || code.Explain() == "" {
				t.Fatalf("code %q repeated or unknown in %v", code, c.Errors)
			}
			seen[code] = true
		}
		_ = c.Issuer.String()
		_ = c.Subject.String()
	})
}
```

Create `internal/extract/corpus_realdata_test.go`:

```go
//go:build realdata

package extract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/4rji/ctvault/internal/leaf"
	"github.com/4rji/ctvault/internal/sample"
	"github.com/4rji/ctvault/internal/sampletest"
)

var writeCorpus = flag.Bool("write-corpus", false, "rewrite testdata/corpus.bin.zst from the cached samples")

// realCerts returns the cached samples' certificates: every leaf certificate
// (precert or final) and every chain certificate, each once.
func realCerts(t *testing.T) (leaves [][]byte, chains [][]byte, leafEvery100 [][]byte) {
	t.Helper()
	samples := append([]*sample.Sample{sampletest.Canonical(t, "argon2027h1")}, sampletest.Representatives(t, "argon2027h1")...)
	seen := map[[32]byte]bool{}
	for _, s := range samples {
		n := 0
		err := s.Each(func(e sample.Entry) error {
			l := leaf.Decode(e.LeafInput, e.ExtraData)
			if l.CertDER != nil && !seen[sha256.Sum256(l.CertDER)] {
				seen[sha256.Sum256(l.CertDER)] = true
				leaves = append(leaves, l.CertDER)
				if n%100 == 0 {
					leafEvery100 = append(leafEvery100, l.CertDER)
				}
				n++
			}
			for _, c := range l.Chain {
				if !seen[sha256.Sum256(c)] {
					seen[sha256.Sum256(c)] = true
					chains = append(chains, c)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return leaves, chains, leafEvery100
}

// TestWriteGoldenCorpus writes testdata/corpus.bin.zst: one leaf
// certificate in every 100 distinct ones of each cached sample, then every
// distinct chain certificate in SHA-256 order. Run it once with
// -write-corpus; the file is checked in.
func TestWriteGoldenCorpus(t *testing.T) {
	if !*writeCorpus {
		t.Skip("run with -args -write-corpus to rewrite testdata/corpus.bin.zst")
	}
	_, chains, every100 := realCerts(t)
	slices.SortFunc(chains, func(a, b []byte) int {
		ha, hb := sha256.Sum256(a), sha256.Sum256(b)
		return bytes.Compare(ha[:], hb[:])
	})
	var raw []byte
	for _, c := range append(every100, chains...) {
		raw = binary.AppendUvarint(raw, uint64(len(c)))
		raw = append(raw, c...)
	}
	enc, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression), zstd.WithEncoderConcurrency(1))
	out := enc.EncodeAll(raw, nil)
	if err := os.WriteFile(filepath.Join("testdata", "corpus.bin.zst"), out, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d leaf + %d chain certificates, %d bytes raw, %d compressed", len(every100), len(chains), len(raw), len(out))
}

// TestDifferentialRealSamples compares the extractor with crypto/x509 on
// every certificate of the cached samples, leaf and chain (amendment A2
// §3.4).
func TestDifferentialRealSamples(t *testing.T) {
	leaves, chains, _ := realCerts(t)
	statuses := map[Status]int{}
	codes := map[Code]int{}
	compared, failures := 0, 0
	for _, der := range append(leaves, chains...) {
		c := Parse(der)
		statuses[c.Status]++
		for _, code := range c.Errors {
			codes[code]++
		}
		ok, diffs := compareX509(der)
		if ok {
			compared++
		}
		for _, d := range diffs {
			if failures++; failures <= 20 {
				t.Errorf("%s: %s", shaHex(der)[:16], d)
			}
		}
	}
	t.Logf("%d leaf + %d chain certificates; statuses %v; codes %v; %d compared with crypto/x509, %d differences",
		len(leaves), len(chains), statuses, codes, compared, failures)
}
```

Create `internal/extract/testdata/malformed.golden`:

```text
well-formed	{"sha256":"e18b64288c51c9b29f55760d179aec8828d5d78d44135e650a6769cde34eed5b","status":"ok","version":3,"serial":"012345","sig_alg":"sha256WithRSAEncryption","issuer":"CN=CTVault Test CA,O=CTVault Test,C=US","issuer_cn":"CTVault Test CA","issuer_o":"CTVault Test","subject_cn":"leaf.example","issuer_raw_sha256":"2956288db15649e2310279d6d26c6475861566029728c4432bdfaa80311ae9d7","subject":"CN=leaf.example","subject_raw_sha256":"121d8fb8d22d66959d77765b89e37de29cc6dfd1640e5374dc8cd3e53057cfbe","not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","key":{"AlgorithmOID":"1.2.840.113549.1.1.1","Algorithm":"rsa","Bits":2048,"Curve":""},"extensions":["2.5.29.17"],"dns":["leaf.example"]}
serial negative	{"sha256":"6b3d762dcf7b89ef48d9e4d65bd3bdf690c31329d4aaa6067cbbe6fb6efa81de","status":"partial","errors":["serial_negative"],"version":3,"serial":"8001","sig_alg":"sha256WithRSAEncryption","issuer":"CN=CTVault Test CA,O=CTVault Test,C=US","issuer_cn":"CTVault Test CA","issuer_o":"CTVault Test","subject_cn":"leaf.example","issuer_raw_sha256":"2956288db15649e2310279d6d26c6475861566029728c4432bdfaa80311ae9d7","subject":"CN=leaf.example","subject_raw_sha256":"121d8fb8d22d66959d77765b89e37de29cc6dfd1640e5374dc8cd3e53057cfbe","not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","key":{"AlgorithmOID":"1.2.840.113549.1.1.1","Algorithm":"rsa","Bits":2048,"Curve":""},"extensions":["2.5.29.17"],"dns":["leaf.example"]}
serial zero	{"sha256":"a5c591d267412b21c66116efa30b5603db5c5c1b4ce573d2796e8d73aa15ee48","status":"partial","errors":["serial_zero"],"version":3,"serial":"00","sig_alg":"sha256WithRSAEncryption","issuer":"CN=CTVault Test CA,O=CTVault Test,C=US","issuer_cn":"CTVault Test CA","issuer_o":"CTVault Test","subject_cn":"leaf.example","issuer_raw_sha256":"2956288db15649e2310279d6d26c6475861566029728c4432bdfaa80311ae9d7","subject":"CN=leaf.example","subject_raw_sha256":"121d8fb8d22d66959d77765b89e37de29cc6dfd1640e5374dc8cd3e53057cfbe","not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","key":{"AlgorithmOID":"1.2.840.113549.1.1.1","Algorithm":"rsa","Bits":2048,"Curve":""},"extensions":["2.5.29.17"],"dns":["leaf.example"]}
serial of 21 octets	{"sha256":"e6bc352e6ddbdf2dcb42c6eafdfd574def70ce38daab51e0641480c61ccec193","status":"partial","errors":["serial_too_long"],"version":3,"serial":"010101010101010101010101010101010101010101","sig_alg":"sha256WithRSAEncryption","issuer":"CN=CTVault Test CA,O=CTVault Test,C=US","issuer_cn":"CTVault Test CA","issuer_o":"CTVault Test","subject_cn":"leaf.example","issuer_raw_sha256":"2956288db15649e2310279d6d26c6475861566029728c4432bdfaa80311ae9d7","subject":"CN=leaf.example","subject_raw_sha256":"121d8fb8d22d66959d77765b89e37de29cc6dfd1640e5374dc8cd3e53057cfbe","not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","key":{"AlgorithmOID":"1.2.840.113549.1.1.1","Algorithm":"rsa","Bits":2048,"Curve":""},"extensions":["2.5.29.17"],"dns":["leaf.example"]}
serial not minimal	{"sha256":"fa897a9bf6f1f84fa79e507f14c9e2cd892ed21079b2aafa3e436d5614b9af78","status":"partial","errors":["serial_not_minimal"],"version":3,"serial":"0001","sig_alg":"sha256WithRSAEncryption","issuer":"CN=CTVault Test CA,O=CTVault Test,C=US","issuer_cn":"CTVault Test CA","issuer_o":"CTVault Test","subject_cn":"leaf.example","issuer_raw_sha256":"2956288db15649e2310279d6d26c6475861566029728c4432bdfaa80311ae9d7","subject":"CN=leaf.example","subject_raw_sha256":"121d8fb8d22d66959d77765b89e37de29cc6dfd1640e5374dc8cd3e53057cfbe","not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","key":{"AlgorithmOID":"1.2.840.113549.1.1.1","Algorithm":"rsa","Bits":2048,"Curve":""},"extensions":["2.5.29.17"],"dns":["leaf.example"]}
UTCTime without seconds	{"sha256":"45217c453aaf0f263bd8034e0befc539acfeaa488464b9c7ac0a90b6902f5c28","status":"partial","errors":["time_bad_format"],"version":3,"serial":"012345","sig_alg":"sha256WithRSAEncryption","issuer":"CN=CTVault Test CA,O=CTVault Test,C=US","issuer_cn":"CTVault Test CA","issuer_o":"CTVault Test","subject_cn":"leaf.example","issuer_raw_sha256":"2956288db15649e2310279d6d26c6475861566029728c4432bdfaa80311ae9d7","subject":"CN=leaf.example","subject_raw_sha256":"121d8fb8d22d66959d77765b89e37de29cc6dfd1640e5374dc8cd3e53057cfbe","not_after":"2026-04-01T00:00:00Z","key":{"AlgorithmOID":"1.2.840.113549.1.1.1","Algorithm":"rsa","Bits":2048,"Curve":""},"extensions":["2.5.29.17"],"dns":["leaf.example"]}
UTCTime with an offset	{"sha256":"bd6fa419fb8ee70c9ef4f42325f1d9ae1ce07f1b6a903bcf2816136b28ee67d0","status":"partial","errors":["time_bad_format"],"version":3,"serial":"012345","sig_alg":"sha256WithRSAEncryption","issuer":"CN=CTVault Test CA,O=CTVault Test,C=US","issuer_cn":"CTVault Test CA","issuer_o":"CTVault Test","subject_cn":"leaf.example","issuer_raw_sha256":"2956288db15649e2310279d6d26c6475861566029728c4432bdfaa80311ae9d7","subject":"CN=leaf.example","subject_raw_sha256":"121d8fb8d22d66959d77765b89e37de29cc6dfd1640e5374dc8cd3e53057cfbe","not_after":"2026-04-01T00:00:00Z","key":{"AlgorithmOID":"1.2.840.113549.1.1.1","Algorithm":"rsa","Bits":2048,"Curve":""},"extensions":["2.5.29.17"],"dns":["leaf.example"]}
GeneralizedTime with a fraction	{"sha256":"94c066e4933a1e222724771ca71280a897aaa001db1ded32508b7b23a1a66466","status":"partial","errors":["time_bad_format"],"version":3,"serial":"012345","sig_alg":"sha256WithRSAEncryption","issuer":"CN=CTVault Test CA,O=CTVault Test,C=US","issuer_cn":"CTVault Test CA","issuer_o":"CTVault Test","subject_cn":"leaf.example","issuer_raw_sha256":"2956288db15649e2310279d6d26c6475861566029728c4432bdfaa80311ae9d7","subject":"CN=leaf.example","subject_raw_sha256":"121d8fb8d22d66959d77765b89e37de29cc6dfd1640e5374dc8cd3e53057cfbe","not_after":"2026-04-01T00:00:00Z","key":{"AlgorithmOID":"1.2.840.113549.1.1.1","Algorithm":"rsa","Bits":2048,"Curve":""},"extensions":["2.5.29.17"],"dns":["leaf.example"]}
GeneralizedTime month 13	{"sha256":"3b9336e3e18b2f49298d4fc31b0e79c83c216b1ab9424a498c8934572b85588c","status":"partial","errors":["time_bad_format"],"version":3,"serial":"012345","sig_alg":"sha256WithRSAEncryption","issuer":"CN=CTVault Test CA,O=CTVault Test,C=US","issuer_cn":"CTVault Test CA","issuer_o":"CTVault Test","subject_cn":"leaf.example","issuer_raw_sha256":"2956288db15649e2310279d6d26c6475861566029728c4432bdfaa80311ae9d7","subject":"CN=leaf.example","subject_raw_sha256":"121d8fb8d22d66959d77765b89e37de29cc6dfd1640e5374dc8cd3e53057cfbe","not_after":"2026-04-01T00:00:00Z","key":{"AlgorithmOID":"1.2.840.113549.1.1.1","Algorithm":"rsa","Bits":2048,"Curve":""},"extensions":["2.5.29.17"],"dns":["leaf.example"]}
duplicate SAN extension	{"sha256":"78a20620d60acc1eb7c1c19eeb12e1ce3c662a6f5e2816f3cf4dcbe33247cbfc","status":"partial","errors":["ext_duplicate"],"version":3,"serial":"012345","sig_alg":"sha256WithRSAEncryption","issuer":"CN=CTVault Test CA,O=CTVault Test,C=US","issuer_cn":"CTVault Test CA","issuer_o":"CTVault Test","subject_cn":"leaf.example","issuer_raw_sha256":"2956288db15649e2310279d6d26c6475861566029728c4432bdfaa80311ae9d7","subject":"CN=leaf.example","subject_raw_sha256":"121d8fb8d22d66959d77765b89e37de29cc6dfd1640e5374dc8cd3e53057cfbe","not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","key":{"AlgorithmOID":"1.2.840.113549.1.1.1","Algorithm":"rsa","Bits":2048,"Curve":""},"extensions":["2.5.29.17","2.5.29.17"],"dns":["first.example"]}
truncated extension list	{"sha256":"ff60a8e9bf30ce0a06bbc225353db78c3a43deb257d0a6d95e92c7f6f20e3a3f","status":"partial","errors":["extensions_unreadable"],"version":3,"serial":"012345","sig_alg":"sha256WithRSAEncryption","issuer":"CN=CTVault Test CA,O=CTVault Test,C=US","issuer_cn":"CTVault Test CA","issuer_o":"CTVault Test","subject_cn":"leaf.example","issuer_raw_sha256":"2956288db15649e2310279d6d26c6475861566029728c4432bdfaa80311ae9d7","subject":"CN=leaf.example","subject_raw_sha256":"121d8fb8d22d66959d77765b89e37de29cc6dfd1640e5374dc8cd3e53057cfbe","not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","key":{"AlgorithmOID":"1.2.840.113549.1.1.1","Algorithm":"rsa","Bits":2048,"Curve":""},"extensions":["2.5.29.14"],"ski":"01"}
extensions field running past the TBS	{"sha256":"bdd599e2d862f2fb774d249a8da0d6f5792b66a68f14cecb5cf37cec073dd582","status":"partial","errors":["extensions_unreadable"],"version":3,"serial":"012345","sig_alg":"sha256WithRSAEncryption","issuer":"CN=CTVault Test CA,O=CTVault Test,C=US","issuer_cn":"CTVault Test CA","issuer_o":"CTVault Test","subject_cn":"leaf.example","issuer_raw_sha256":"2956288db15649e2310279d6d26c6475861566029728c4432bdfaa80311ae9d7","subject":"CN=leaf.example","subject_raw_sha256":"121d8fb8d22d66959d77765b89e37de29cc6dfd1640e5374dc8cd3e53057cfbe","not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","key":{"AlgorithmOID":"1.2.840.113549.1.1.1","Algorithm":"rsa","Bits":2048,"Curve":""}}
truncated SAN	{"sha256":"ba08a12e8c3de52d0f6ab2d9b33949c29ce591dbdaba376771ffee850758f948","status":"partial","errors":["san_unreadable"],"version":3,"serial":"012345","sig_alg":"sha256WithRSAEncryption","issuer":"CN=CTVault Test CA,O=CTVault Test,C=US","issuer_cn":"CTVault Test CA","issuer_o":"CTVault Test","subject_cn":"leaf.example","issuer_raw_sha256":"2956288db15649e2310279d6d26c6475861566029728c4432bdfaa80311ae9d7","subject":"CN=leaf.example","subject_raw_sha256":"121d8fb8d22d66959d77765b89e37de29cc6dfd1640e5374dc8cd3e53057cfbe","not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","key":{"AlgorithmOID":"1.2.840.113549.1.1.1","Algorithm":"rsa","Bits":2048,"Curve":""},"extensions":["2.5.29.17"]}
CN that is not a DNS name, no SAN	{"sha256":"6dae5ef25b761d8e5a2aa5905dc408c7681a42d001f47a2648b12c5af09a3e1a","status":"ok","version":3,"serial":"012345","sig_alg":"sha256WithRSAEncryption","issuer":"CN=CTVault Test CA,O=CTVault Test,C=US","issuer_cn":"CTVault Test CA","issuer_o":"CTVault Test","subject_cn":"Example Device 42","issuer_raw_sha256":"2956288db15649e2310279d6d26c6475861566029728c4432bdfaa80311ae9d7","subject":"CN=Example Device 42","subject_raw_sha256":"b93b6c8e0786cbaa3e0312294c3e2c3680bbddc9232f80e993eb2c19b1ff33cf","not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","key":{"AlgorithmOID":"1.2.840.113549.1.1.1","Algorithm":"rsa","Bits":2048,"Curve":""}}
CN that is an IP literal	{"sha256":"7fb388e0d519858c3488f53bcf8779a98c95d2578af5fbbac62c70d632e5dd11","status":"ok","version":3,"serial":"012345","sig_alg":"sha256WithRSAEncryption","issuer":"CN=CTVault Test CA,O=CTVault Test,C=US","issuer_cn":"CTVault Test CA","issuer_o":"CTVault Test","subject_cn":"192.0.2.7","issuer_raw_sha256":"2956288db15649e2310279d6d26c6475861566029728c4432bdfaa80311ae9d7","subject":"CN=192.0.2.7","subject_raw_sha256":"fe452670d546d4c57f528a2217b1d92a197eea3331929db3a3b25a5653cc39cf","not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","key":{"AlgorithmOID":"1.2.840.113549.1.1.1","Algorithm":"rsa","Bits":2048,"Curve":""},"extensions":["2.5.29.17"],"dns":["leaf.example"]}
IP SANs of every odd length	{"sha256":"4d61396721c6b1b66d71261b9affeaea2dfb11ff48829047f2d8fbb43b3a83c7","status":"partial","errors":["san_ip_bad_len"],"version":3,"serial":"012345","sig_alg":"sha256WithRSAEncryption","issuer":"CN=CTVault Test CA,O=CTVault Test,C=US","issuer_cn":"CTVault Test CA","issuer_o":"CTVault Test","subject_cn":"leaf.example","issuer_raw_sha256":"2956288db15649e2310279d6d26c6475861566029728c4432bdfaa80311ae9d7","subject":"CN=leaf.example","subject_raw_sha256":"121d8fb8d22d66959d77765b89e37de29cc6dfd1640e5374dc8cd3e53057cfbe","not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","key":{"AlgorithmOID":"1.2.840.113549.1.1.1","Algorithm":"rsa","Bits":2048,"Curve":""},"extensions":["2.5.29.17"],"ips":["","01","c0000201","0102030405","0000000000000000","00000000000000000000000000000000","0000000000000000000000000000000000"]}
unknown signature algorithm	{"sha256":"fc7e2cfb7f2cfc8e9cc15dc27d7cf57fa153ccf3ea80a3fcfb7ce596d2be8f2e","status":"ok","version":3,"serial":"012345","sig_alg":"1.2.3.4.5","issuer":"CN=CTVault Test CA,O=CTVault Test,C=US","issuer_cn":"CTVault Test CA","issuer_o":"CTVault Test","subject_cn":"leaf.example","issuer_raw_sha256":"2956288db15649e2310279d6d26c6475861566029728c4432bdfaa80311ae9d7","subject":"CN=leaf.example","subject_raw_sha256":"121d8fb8d22d66959d77765b89e37de29cc6dfd1640e5374dc8cd3e53057cfbe","not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","key":{"AlgorithmOID":"1.2.840.113549.1.1.1","Algorithm":"rsa","Bits":2048,"Curve":""},"extensions":["2.5.29.17"],"dns":["leaf.example"]}
signature algorithm mismatch	{"sha256":"71dab3d6c20484d46b45003c551166f38d48949f9bc8015940fae225a0e1e45c","status":"partial","errors":["sig_alg_mismatch"],"version":3,"serial":"012345","sig_alg":"sha256WithRSAEncryption","issuer":"CN=CTVault Test CA,O=CTVault Test,C=US","issuer_cn":"CTVault Test CA","issuer_o":"CTVault Test","subject_cn":"leaf.example","issuer_raw_sha256":"2956288db15649e2310279d6d26c6475861566029728c4432bdfaa80311ae9d7","subject":"CN=leaf.example","subject_raw_sha256":"121d8fb8d22d66959d77765b89e37de29cc6dfd1640e5374dc8cd3e53057cfbe","not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","key":{"AlgorithmOID":"1.2.840.113549.1.1.1","Algorithm":"rsa","Bits":2048,"Curve":""},"extensions":["2.5.29.17"],"dns":["leaf.example"]}
unknown SPKI algorithm	{"sha256":"625bc8ab77fbd6ddf01e846afd944c78554eef735ccfa30bd235b27c87b92d69","status":"ok","version":3,"serial":"012345","sig_alg":"sha256WithRSAEncryption","issuer":"CN=CTVault Test CA,O=CTVault Test,C=US","issuer_cn":"CTVault Test CA","issuer_o":"CTVault Test","subject_cn":"leaf.example","issuer_raw_sha256":"2956288db15649e2310279d6d26c6475861566029728c4432bdfaa80311ae9d7","subject":"CN=leaf.example","subject_raw_sha256":"121d8fb8d22d66959d77765b89e37de29cc6dfd1640e5374dc8cd3e53057cfbe","not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","key":{"AlgorithmOID":"1.2.3.4.6","Algorithm":"other","Bits":0,"Curve":""},"extensions":["2.5.29.17"],"dns":["leaf.example"]}
issuer CN with invalid UTF-8	{"sha256":"430490541b59f475226e44e6647db0dd8eaf2de9a28d0c4b389e21412e24e5e8","status":"partial","errors":["name_bad_string"],"version":3,"serial":"012345","sig_alg":"sha256WithRSAEncryption","issuer":"CN=Bad\\FFIssuer","issuer_cn":"Bad\\FFIssuer","subject_cn":"leaf.example","issuer_raw_sha256":"2c9263514c25c5e1b1dff9b9495b95e38b22ea7b6c82d70da676ce335c658151","subject":"CN=leaf.example","subject_raw_sha256":"121d8fb8d22d66959d77765b89e37de29cc6dfd1640e5374dc8cd3e53057cfbe","not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","key":{"AlgorithmOID":"1.2.840.113549.1.1.1","Algorithm":"rsa","Bits":2048,"Curve":""},"extensions":["2.5.29.17"],"dns":["leaf.example"]}
subject CN as odd-length BMPString	{"sha256":"599a3b7a9b522771d69c3ab2fd9df8f609e35651430ba063e0b9ecf9019e56ed","status":"partial","errors":["name_bad_string"],"version":3,"serial":"012345","sig_alg":"sha256WithRSAEncryption","issuer":"CN=CTVault Test CA,O=CTVault Test,C=US","issuer_cn":"CTVault Test CA","issuer_o":"CTVault Test","subject_cn":"le\\00","issuer_raw_sha256":"2956288db15649e2310279d6d26c6475861566029728c4432bdfaa80311ae9d7","subject":"CN=le\\00","subject_raw_sha256":"27870ce6bb981a7c60db5be522df8e7c7def4817bf439764bef5d3d9188e7bab","not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","key":{"AlgorithmOID":"1.2.840.113549.1.1.1","Algorithm":"rsa","Bits":2048,"Curve":""},"extensions":["2.5.29.17"],"dns":["leaf.example"]}
subject CN PrintableString with a non-ASCII byte	{"sha256":"999674bdcad50556a7ef2d839d61215e669f42bb3b686c478ac6145d850f715e","status":"partial","errors":["name_bad_string"],"version":3,"serial":"012345","sig_alg":"sha256WithRSAEncryption","issuer":"CN=CTVault Test CA,O=CTVault Test,C=US","issuer_cn":"CTVault Test CA","issuer_o":"CTVault Test","subject_cn":"caf\\E9","issuer_raw_sha256":"2956288db15649e2310279d6d26c6475861566029728c4432bdfaa80311ae9d7","subject":"CN=caf\\E9","subject_raw_sha256":"61f191aaff69ff69015912573c30b3a420c5223fe02c407dd2b399783e5b2ac0","not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","key":{"AlgorithmOID":"1.2.840.113549.1.1.1","Algorithm":"rsa","Bits":2048,"Curve":""},"extensions":["2.5.29.17"],"dns":["leaf.example"]}
issuer that is a SET	{"sha256":"52d95300a12d907ede99d9aeafeab82a67439f51a574ee6c790476b858e04416","status":"partial","errors":["issuer_unreadable"],"version":3,"serial":"012345","sig_alg":"sha256WithRSAEncryption","issuer":"","subject_cn":"leaf.example","issuer_raw_sha256":"e79e418e48623569d75e2a7b09ae88ed9b77b126a445b9ff9dc6989a08efa079","subject":"CN=leaf.example","subject_raw_sha256":"121d8fb8d22d66959d77765b89e37de29cc6dfd1640e5374dc8cd3e53057cfbe","not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","key":{"AlgorithmOID":"1.2.840.113549.1.1.1","Algorithm":"rsa","Bits":2048,"Curve":""},"extensions":["2.5.29.17"],"dns":["leaf.example"]}
trailing data after the certificate	{"sha256":"886d1b83d9c5b29d3ed86c45eb8bb7056587711b140c2f52cd8e0e65c7d458a6","status":"partial","errors":["cert_trailing_data"],"version":3,"serial":"012345","sig_alg":"sha256WithRSAEncryption","issuer":"CN=CTVault Test CA,O=CTVault Test,C=US","issuer_cn":"CTVault Test CA","issuer_o":"CTVault Test","subject_cn":"leaf.example","issuer_raw_sha256":"2956288db15649e2310279d6d26c6475861566029728c4432bdfaa80311ae9d7","subject":"CN=leaf.example","subject_raw_sha256":"121d8fb8d22d66959d77765b89e37de29cc6dfd1640e5374dc8cd3e53057cfbe","not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","key":{"AlgorithmOID":"1.2.840.113549.1.1.1","Algorithm":"rsa","Bits":2048,"Curve":""},"extensions":["2.5.29.17"],"dns":["leaf.example"]}
extra TBS field	{"sha256":"adcbb19645f9ff94e4f6d228650794499fc25c1a84390528547ab3f236ba6de2","status":"partial","errors":["tbs_extra_fields"],"version":3,"serial":"012345","sig_alg":"sha256WithRSAEncryption","issuer":"CN=CTVault Test CA,O=CTVault Test,C=US","issuer_cn":"CTVault Test CA","issuer_o":"CTVault Test","subject_cn":"leaf.example","issuer_raw_sha256":"2956288db15649e2310279d6d26c6475861566029728c4432bdfaa80311ae9d7","subject":"CN=leaf.example","subject_raw_sha256":"121d8fb8d22d66959d77765b89e37de29cc6dfd1640e5374dc8cd3e53057cfbe","not_before":"2026-01-01T00:00:00Z","not_after":"2026-04-01T00:00:00Z","key":{"AlgorithmOID":"1.2.840.113549.1.1.1","Algorithm":"rsa","Bits":2048,"Curve":""},"extensions":["2.5.29.17"],"dns":["leaf.example"]}
TBS without a public key	{"sha256":"af501a53414dada2f04c09317045a4512599d9b8ebf2fe4ae1a350c2c7d9e079","status":"failed","errors":["tbs_unreadable"],"version":0,"serial":"","sig_alg":"","issuer":"","issuer_raw_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","subject":"","subject_raw_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","key":{"AlgorithmOID":"","Algorithm":"","Bits":0,"Curve":""}}
not a certificate	{"sha256":"0972d1754ce277434118d81041c594d1cb8cbf27a25ea0639adb45556398d2b5","status":"failed","errors":["cert_unreadable"],"version":0,"serial":"","sig_alg":"","issuer":"","issuer_raw_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","subject":"","subject_raw_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","key":{"AlgorithmOID":"","Algorithm":"","Bits":0,"Curve":""}}
```

- [ ] **Step 2: Generate the real corpus from the cached samples**

Run: `go test -count=1 -tags realdata -run TestWriteGoldenCorpus ./internal/extract/ -args -write-corpus`
Expected: `2000 leaf + 710 chain certificates, 3518029 bytes raw, 1911747 compressed`. `sha256sum internal/extract/testdata/corpus.bin.zst` must print the value in Before You Start.

- [ ] **Step 3: Generate the real corpus's golden file**

Run: `go test -count=1 -run TestGoldenCorpus ./internal/extract/ -args -update`
Then `sha256sum internal/extract/testdata/corpus.golden.zst` must print the value in Before You Start. Check `malformed.golden` against its value too.

- [ ] **Step 4: Run the tests**

Run: `go test -race -v -run 'Golden|Determinism|Differential|Malformed|FuzzParse' ./internal/extract/`
Expected: PASS, with `2710 certificates: map[ok:2705 partial:5]` and `compared 2710 certificates with crypto/x509`.

**Check that the tests can fail.** In a scratch copy, each mutation must fail:
- the bit length one too long in `key.go` (`n := 8*(len(b)-1) + 1`): the differential check reports `key: { rsa 2049 }, crypto/x509 { rsa 2048 }`;
- `First` never finding a CN (`if a.Type != oid || a.Type == OIDCommonName`): the differential check reports `issuer CN: (none), crypto/x509 Merge Delay Intermediate 1`;
- `First` never finding an O: `TestGoldenCorpus` reports `corpus.golden.zst line 1 differs`.

- [ ] **Step 5: Fuzz**

Run: `go test -run '^$' -fuzz FuzzParse -fuzztime 180s ./internal/extract/`
Expected: PASS. 13.8 million executions were measured in 3 minutes on this machine.

- [ ] **Step 6: The real-data differential check**

Run: `go test -count=1 -tags realdata -v -run TestDifferentialRealSamples ./internal/extract/`
Expected: PASS: `200000 leaf + 710 chain certificates; statuses map[ok:200705 partial:5]; codes map[serial_zero:5]; 200710 compared with crypto/x509, 0 differences`, in about 40 s.

- [ ] **Step 7: Quality gate**

- [ ] **Step 8: Checkpoint.**

---

## Final Verification

- The quality gate on the finished tree.
- `go test -count=1 -tags realdata -run 'Differential|Golden|Malformed' ./internal/extract/`
- `go test -run '^$' -fuzz FuzzParse -fuzztime 60s ./internal/extract/`
- A review of the whole change, with the Review Focus above.
