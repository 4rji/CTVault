package tiled

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/merkle"
)

// Checkpoint limits (amendment A6 §2): signed-note asks verifiers to accept at
// least 16 signatures, and post-quantum ones approach 5 KB.
const (
	MaxCheckpointBytes = 1 << 20
	MaxSignatureLines  = 64
)

// rfc6962NoteType is the signed-note signature type of an RFC 6962
// TreeHeadSignature (signed-note, "Signature types").
const rfc6962NoteType = 0x05

// KeyID is the note key ID of a static-ct-api log: the first four bytes of
// SHA-256(origin || 0x0A || 0x05 || log ID).
func KeyID(origin string, logID [32]byte) [4]byte {
	h := sha256.New()
	h.Write([]byte(origin))
	h.Write([]byte{'\n', rfc6962NoteType})
	h.Write(logID[:])
	return [4]byte(h.Sum(nil))
}

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: checkpoint: %s", logsource.ErrMalformed, fmt.Sprintf(format, args...))
}

func badSignature(format string, args ...any) error {
	return fmt.Errorf("%w: checkpoint: %s", merkle.ErrBadSignature, fmt.Sprintf(format, args...))
}

// decodeCanonical decodes standard padded base64 and refuses any encoding
// that does not re-encode to itself (tlog-checkpoint, signed-note).
func decodeCanonical(s string) ([]byte, bool) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != s {
		return nil, false
	}
	return b, true
}

// ParseCheckpoint reads a static-ct-api checkpoint for the log with origin
// and logID, and returns its signed tree head without verifying the
// signature (the caller does, with merkle.VerifySTH). A note that cannot be
// read is logsource.ErrMalformed; one that is readable but carries no single
// signature line from the pinned key, or names another origin, is
// merkle.ErrBadSignature (amendment A6 §2).
func ParseCheckpoint(b []byte, origin string, logID [32]byte) (merkle.SignedTreeHead, error) {
	var sth merkle.SignedTreeHead
	// 1. The note.
	if len(b) > MaxCheckpointBytes {
		return sth, malformed("%d bytes, more than %d", len(b), MaxCheckpointBytes)
	}
	if !utf8.Valid(b) {
		return sth, malformed("not valid UTF-8")
	}
	for _, c := range b {
		if c < 0x20 && c != '\n' {
			return sth, malformed("control character 0x%02x", c)
		}
	}
	if len(b) == 0 || b[len(b)-1] != '\n' {
		return sth, malformed("does not end with a newline")
	}
	i := bytes.LastIndex(b, []byte("\n\n"))
	if i < 0 {
		return sth, malformed("no blank line before the signatures")
	}
	text, sigs := string(b[:i+1]), string(b[i+2:])
	if sigs == "" {
		return sth, malformed("no signature lines")
	}
	lines := strings.Split(strings.TrimSuffix(sigs, "\n"), "\n")
	if len(lines) > MaxSignatureLines {
		return sth, malformed("%d signature lines, more than %d", len(lines), MaxSignatureLines)
	}
	type sigLine struct {
		name string
		sig  []byte
	}
	parsed := make([]sigLine, len(lines))
	for k, l := range lines {
		rest, ok := strings.CutPrefix(l, "— ")
		name, enc, ok2 := strings.Cut(rest, " ")
		if !ok || !ok2 || name == "" || strings.ContainsAny(name, " +") {
			return sth, malformed("signature line %d is not \"— <name> <signature>\"", k+1)
		}
		sig, ok := decodeCanonical(enc)
		if !ok || len(sig) < 5 {
			return sth, malformed("signature line %d is not canonical base64 of a key ID and a signature", k+1)
		}
		parsed[k] = sigLine{name, sig}
	}

	// 2. The text: origin, size and root, and nothing more.
	tl := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(tl) < 3 {
		return sth, malformed("%d text lines, want origin, size and root", len(tl))
	}
	if len(tl) > 3 {
		return sth, malformed("%d extension lines; static-ct-api checkpoints have none", len(tl)-3)
	}
	if tl[0] == "" || len(tl[0]) > 255 {
		return sth, malformed("origin line is empty or longer than 255 bytes")
	}
	size, err := strconv.ParseUint(tl[1], 10, 64)
	if err != nil || (len(tl[1]) > 1 && tl[1][0] == '0') {
		return sth, malformed("tree size %q is not a decimal without leading zeros", tl[1])
	}
	root, ok := decodeCanonical(tl[2])
	if !ok || len(root) != 32 {
		return sth, malformed("root hash is not canonical base64 of 32 bytes")
	}

	// 3. The origin, and 4. exactly one line from the pinned key.
	if tl[0] != origin {
		return sth, badSignature("origin %q is not the pinned %q", tl[0], origin)
	}
	id := KeyID(origin, logID)
	var body []byte
	for _, s := range parsed {
		if s.name != origin || !bytes.Equal(s.sig[:4], id[:]) {
			continue // another key or a witness: ignored (signed-note)
		}
		if body != nil {
			return sth, badSignature("two signature lines from the pinned key")
		}
		body = s.sig[4:]
	}
	if body == nil {
		return sth, badSignature("no signature line from the pinned key (name %q, key ID %x)", origin, id)
	}

	// 5. RFC6962NoteSignature: a timestamp, then a DigitallySigned that ends
	// the body.
	if len(body) < 8+4 {
		return sth, malformed("signature body of %d bytes is too short", len(body))
	}
	ds := body[8:]
	if n := int(binary.BigEndian.Uint16(ds[2:4])); 4+n != len(ds) {
		return sth, malformed("signature of %d bytes in a body of %d", n, len(ds)-4)
	}
	sth.TreeSize = size
	sth.Timestamp = binary.BigEndian.Uint64(body[:8])
	copy(sth.RootHash[:], root)
	sth.Signature = append([]byte(nil), ds...)
	return sth, nil
}
