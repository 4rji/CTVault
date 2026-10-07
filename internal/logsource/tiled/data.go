package tiled

import (
	"fmt"

	"golang.org/x/crypto/cryptobyte"

	"github.com/4rji/ctvault/internal/logsource"
)

// tileLeaf is one TileLeaf of a data tile (static-ct-api, "Log entries"),
// its parts aliasing the tile's bytes.
type tileLeaf struct {
	raw            []byte // the whole TileLeaf, exactly as served
	entry          []byte // TimestampedEntry
	extensions     []byte // its CtExtensions body
	precert        bool
	preCertificate []byte // precert entries only
	chain          [][32]byte
}

// parseDataTile splits a data tile into its TileLeafs. The tile must hold
// exactly want entries and nothing after them; anything else means the
// entry boundaries are lost, so the whole tile is logsource.ErrMalformed
// (amendment A6 §3.3).
func parseDataTile(b []byte, want int, path string) ([]tileLeaf, error) {
	bad := func(i int, what string) error {
		return fmt.Errorf("%w: data tile %s: entry %d: %s", logsource.ErrMalformed, path, i, what)
	}
	s := cryptobyte.String(b)
	out := make([]tileLeaf, 0, want)
	for i := 0; !s.Empty(); i++ {
		if i == want {
			return nil, bad(i, fmt.Sprintf("bytes follow the %d entries", want))
		}
		start := len(b) - len(s)
		var ts uint64
		var typ uint16
		if !s.ReadUint64(&ts) || !s.ReadUint16(&typ) {
			return nil, bad(i, "truncated TimestampedEntry")
		}
		var l tileLeaf
		var signed, exts cryptobyte.String
		switch typ {
		case 0:
			if !s.ReadUint24LengthPrefixed(&signed) {
				return nil, bad(i, "truncated certificate")
			}
		case 1:
			l.precert = true
			if !s.Skip(32) || !s.ReadUint24LengthPrefixed(&signed) {
				return nil, bad(i, "truncated precert TBS")
			}
		default:
			return nil, bad(i, fmt.Sprintf("unknown entry type %d", typ))
		}
		if !s.ReadUint16LengthPrefixed(&exts) {
			return nil, bad(i, "truncated extensions")
		}
		l.entry = b[start : len(b)-len(s)]
		l.extensions = exts
		if l.precert {
			var pre cryptobyte.String
			if !s.ReadUint24LengthPrefixed(&pre) {
				return nil, bad(i, "truncated pre_certificate")
			}
			l.preCertificate = pre
		}
		var fps cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&fps) || len(fps)%32 != 0 {
			return nil, bad(i, "chain fingerprints are truncated or not a multiple of 32 bytes")
		}
		l.chain = make([][32]byte, len(fps)/32)
		for k := range l.chain {
			copy(l.chain[k][:], fps[32*k:])
		}
		l.raw = b[start : len(b)-len(s)]
		out = append(out, l)
	}
	if len(out) != want {
		return nil, fmt.Errorf("%w: data tile %s: %d entries, want %d", logsource.ErrMalformed, path, len(out), want)
	}
	return out, nil
}

func appendU24(b, data []byte) []byte {
	n := len(data)
	return append(append(b, byte(n>>16), byte(n>>8), byte(n)), data...)
}

// leafInput is the RFC 6962 leaf_input of a TileLeaf: version v1 and
// timestamped_entry, then the TimestampedEntry.
func (l *tileLeaf) leafInput() []byte {
	return append([]byte{0, 0}, l.entry...)
}

// extraData rebuilds the RFC 6962 extra_data from the issuers' DER: the
// chain for an x509 entry, the precertificate then the chain for a precert
// entry (amendment A6 §3).
func (l *tileLeaf) extraData(chain [][]byte) []byte {
	var list []byte
	for _, c := range chain {
		list = appendU24(list, c)
	}
	var out []byte
	if l.precert {
		out = appendU24(out, l.preCertificate)
	}
	return appendU24(out, list)
}
