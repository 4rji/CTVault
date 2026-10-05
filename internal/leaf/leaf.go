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
