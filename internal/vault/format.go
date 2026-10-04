// Package vault stores every unique certificate's DER, compressed, in
// append-only segment files (spec §6.2, amendment A1 §5). Records are
// located by (segment, offset); SHA-256 is never stored and is verified on
// every read.
package vault

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"time"
)

// Record kinds (spec §6.2).
const (
	KindLeaf  = 1 // ref: uvarint dict_id (0 = no dictionary)
	KindDelta = 2 // ref: uvarint base_segment, uvarint base_offset
	KindChain = 3 // ref: uvarint dict_id
)

// Segment header (spec §6.2): magic, format version, vault UUID, segment ID,
// first cert_id and creation time, fixed at 64 bytes and closed by a CRC32C
// so a header torn during rollover is detected.
const (
	Magic         = "CTVSEG01"
	FormatVersion = 1
	HeaderSize    = 64
)

var (
	// ErrCorrupt means committed vault data failed a check: a bad header, a
	// checksum or SHA-256 mismatch, an unresolvable delta base. It is never
	// ignored (spec §12: exit 5).
	ErrCorrupt = errors.New("vault corruption")
	// ErrTorn means a record ends past the end of its segment: a write that
	// a crash interrupted. Only data beyond the committed tail may be torn.
	ErrTorn = errors.New("torn vault record")
)

func corrupt(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(format, args...))
}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// Header is a segment's first 64 bytes.
type Header struct {
	Version     uint16
	VaultUUID   [16]byte
	Segment     uint64
	FirstCertID uint64
	Created     time.Time
}

// Encode lays the header out as magic(8) version(2) uuid(16) segment(8)
// first_cert_id(8) created_unix_ns(8) zero(10) crc32c(4).
func (h Header) Encode() []byte {
	b := make([]byte, HeaderSize)
	copy(b, Magic)
	binary.BigEndian.PutUint16(b[8:], h.Version)
	copy(b[10:26], h.VaultUUID[:])
	binary.BigEndian.PutUint64(b[26:], h.Segment)
	binary.BigEndian.PutUint64(b[34:], h.FirstCertID)
	binary.BigEndian.PutUint64(b[42:], uint64(h.Created.UnixNano()))
	binary.BigEndian.PutUint32(b[60:], crc32.Checksum(b[:60], castagnoli))
	return b
}

// DecodeHeader parses and checks a segment header.
func DecodeHeader(b []byte) (Header, error) {
	if len(b) < HeaderSize {
		return Header{}, fmt.Errorf("%w: segment header is %d bytes", ErrTorn, len(b))
	}
	if string(b[:8]) != Magic {
		return Header{}, corrupt("bad segment magic %q", b[:8])
	}
	if crc32.Checksum(b[:60], castagnoli) != binary.BigEndian.Uint32(b[60:64]) {
		return Header{}, corrupt("segment header checksum mismatch")
	}
	h := Header{Version: binary.BigEndian.Uint16(b[8:]), Segment: binary.BigEndian.Uint64(b[26:]),
		FirstCertID: binary.BigEndian.Uint64(b[34:]), Created: time.Unix(0, int64(binary.BigEndian.Uint64(b[42:]))).UTC()}
	copy(h.VaultUUID[:], b[10:26])
	if h.Version != FormatVersion {
		return h, corrupt("unsupported segment format %d", h.Version)
	}
	return h, nil
}

// ParseUUID turns a VAULT_ID uuid ("xxxxxxxx-xxxx-...") into 16 bytes.
func ParseUUID(s string) ([16]byte, error) {
	var out [16]byte
	hex := make([]byte, 0, 32)
	for i := 0; i < len(s); i++ {
		if s[i] != '-' {
			hex = append(hex, s[i])
		}
	}
	if len(hex) != 32 {
		return out, fmt.Errorf("vault: bad vault UUID %q", s)
	}
	for i := range out {
		hi, ok1 := unhex(hex[2*i])
		lo, ok2 := unhex(hex[2*i+1])
		if !ok1 || !ok2 {
			return out, fmt.Errorf("vault: bad vault UUID %q", s)
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// Loc locates a record: its segment, the offset of its first byte and its
// total length. Pebble stores it as "uvarint cert_id, segment, offset, len".
type Loc struct {
	Segment uint64
	Offset  uint64
	Len     uint32
}

// Tail is the end of the vault: the next record goes to Segment at Offset.
// The zero Tail is an empty vault.
type Tail struct {
	Segment uint64 `json:"segment"`
	Offset  uint64 `json:"offset"`
}

// Before reports whether t is strictly before u in vault order.
func (t Tail) Before(u Tail) bool {
	return t.Segment < u.Segment || (t.Segment == u.Segment && t.Offset < u.Offset)
}

// Record is one decoded record header plus its compressed frame.
type Record struct {
	Kind     byte
	CertID   uint64
	DictID   uint64 // KindLeaf, KindChain
	BaseSeg  uint64 // KindDelta
	BaseOff  uint64 // KindDelta
	Frame    []byte
	TotalLen int // bytes the record occupies, length prefix included
}

// AppendRecord appends "uvarint body_len | u8 kind | uvarint cert_id | ref |
// frame" to dst.
func AppendRecord(dst []byte, r Record) []byte {
	body := []byte{r.Kind}
	body = binary.AppendUvarint(body, r.CertID)
	switch r.Kind {
	case KindDelta:
		body = binary.AppendUvarint(body, r.BaseSeg)
		body = binary.AppendUvarint(body, r.BaseOff)
	default:
		body = binary.AppendUvarint(body, r.DictID)
	}
	body = append(body, r.Frame...)
	dst = binary.AppendUvarint(dst, uint64(len(body)))
	return append(dst, body...)
}

// ParseRecord reads one record from the start of b. A record that runs past
// the end of b is ErrTorn; one that cannot be interpreted is ErrCorrupt.
func ParseRecord(b []byte) (Record, error) {
	n, k := binary.Uvarint(b)
	if k == 0 {
		return Record{}, ErrTorn
	}
	if k < 0 || n == 0 || n > 1<<30 {
		return Record{}, corrupt("bad record length")
	}
	if uint64(len(b)-k) < n {
		return Record{}, ErrTorn
	}
	body := b[k : k+int(n)]
	r := Record{Kind: body[0], TotalLen: k + int(n)}
	p := 1
	next := func() (uint64, bool) {
		v, m := binary.Uvarint(body[p:])
		if m <= 0 {
			return 0, false
		}
		p += m
		return v, true
	}
	var ok bool
	if r.CertID, ok = next(); !ok {
		return r, corrupt("bad record cert_id")
	}
	switch r.Kind {
	case KindLeaf, KindChain:
		if r.DictID, ok = next(); !ok {
			return r, corrupt("bad record dict_id")
		}
	case KindDelta:
		var ok2 bool
		r.BaseSeg, ok = next()
		r.BaseOff, ok2 = next()
		if !ok || !ok2 {
			return r, corrupt("bad delta base")
		}
	default:
		return r, corrupt("unknown record kind %d", r.Kind)
	}
	r.Frame = body[p:]
	return r, nil
}
