package ctlogtest

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// The tiled read path (static-ct-api, amendment A6 §7): with Options.Tiled
// the fake serves /checkpoint, /tile/<L>/<N>[.p/<W>], /tile/data/<N>[.p/<W>]
// and /issuer/<hex> from the same tree as its RFC 6962 endpoints, so one log
// can be read through either protocol.

// Checkpoint faults (Options.CheckpointFault).
const (
	WrongOrigin   = "wrong-origin"   // the origin line names another log
	ExtensionLine = "extension-line" // a fourth text line
	TwoKeyLines   = "two-key-lines"  // the pinned key signs twice
	NoKeyLine     = "no-key-line"    // only the extra Ed25519 and witness lines
)

// DefaultOrigin is the fake's checkpoint origin unless Options.Origin is set.
const DefaultOrigin = "ct.example.test/fakelog"

const tileWidth = 256

// withLeafIndex rewrites each entry's empty CtExtensions into a leaf_index
// extension equal to its position (static-ct-api), unless bad or none says
// otherwise for that index. It returns copies.
func withLeafIndex(entries []Entry, bad, none map[uint64]bool) []Entry {
	out := make([]Entry, len(entries))
	for i, e := range entries {
		idx := uint64(i)
		leaf := append([]byte(nil), e.LeafInput[:len(e.LeafInput)-2]...)
		if !none[idx] {
			if bad[idx] {
				idx++
			}
			ext := []byte{0, 0, 5, byte(idx >> 32), byte(idx >> 24), byte(idx >> 16), byte(idx >> 8), byte(idx)}
			leaf = binary.BigEndian.AppendUint16(leaf, uint16(len(ext)))
			leaf = append(leaf, ext...)
		} else {
			leaf = binary.BigEndian.AppendUint16(leaf, 0)
		}
		e.LeafInput = leaf
		out[i] = e
	}
	return out
}

func readU24(b []byte) ([]byte, []byte, bool) {
	if len(b) < 3 {
		return nil, nil, false
	}
	n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	if len(b) < 3+n {
		return nil, nil, false
	}
	return b[3 : 3+n], b[3+n:], true
}

// splitExtra reads an RFC 6962 extra_data back into its precertificate (for
// precert entries) and chain.
func splitExtra(e Entry) (pre []byte, chain [][]byte, ok bool) {
	rest := e.ExtraData
	if e.Type == PrecertEntry {
		if pre, rest, ok = readU24(rest); !ok {
			return nil, nil, false
		}
	}
	list, rest, ok := readU24(rest)
	if !ok || len(rest) != 0 {
		return nil, nil, false
	}
	for len(list) > 0 {
		var c []byte
		if c, list, ok = readU24(list); !ok {
			return nil, nil, false
		}
		chain = append(chain, c)
	}
	return pre, chain, true
}

// TileLeaf encodes one data-tile entry from an RFC 6962 leaf_input and the
// entry's extra_data parts (static-ct-api, "Log entries").
func TileLeaf(leafInput []byte, typ EntryType, pre []byte, chain [][32]byte) []byte {
	b := append([]byte(nil), leafInput[2:]...)
	if typ == PrecertEntry {
		b = appendU24(b, pre)
	}
	b = binary.BigEndian.AppendUint16(b, uint16(32*len(chain)))
	for _, fp := range chain {
		b = append(b, fp[:]...)
	}
	return b
}

func pow256(k int) uint64 { return 1 << (8 * k) }

// widthIn is the width of tile n at level in a tree of size: 256 when full,
// the partial width at the right edge, 0 beyond.
func widthIn(level int, n, size uint64) int {
	span := pow256(level + 1)
	switch {
	case n < size/span:
		return tileWidth
	case n == size/span:
		return int(size / pow256(level) % tileWidth)
	}
	return 0
}

func hashChildren(l, r [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(l[:])
	h.Write(r[:])
	return [32]byte(h.Sum(nil))
}

// SubtreeHash is the RFC 6962 hash of the perfect subtree of 256^level
// leaves starting at leaf index*256^level, from leafHash.
func SubtreeHash(leafHash func(uint64) [32]byte, level int, index uint64) [32]byte {
	if level == 0 {
		return leafHash(index)
	}
	hs := make([][32]byte, tileWidth)
	for i := range hs {
		hs[i] = SubtreeHash(leafHash, level-1, index*tileWidth+uint64(i))
	}
	for len(hs) > 1 {
		next := hs[:len(hs)/2]
		for i := range next {
			next[i] = hashChildren(hs[2*i], hs[2*i+1])
		}
		hs = next
	}
	return hs[0]
}

// HashTile is the hash tile n at level of width w over leafHash, as
// tlog-tiles defines it.
func HashTile(leafHash func(uint64) [32]byte, level int, n uint64, w int) []byte {
	b := make([]byte, 0, 32*w)
	for i := 0; i < w; i++ {
		h := SubtreeHash(leafHash, level, n*tileWidth+uint64(i))
		b = append(b, h[:]...)
	}
	return b
}

// ParseTilePath reads "<L>/<N>[.p/<W>]" or "data/<N>[.p/<W>]"; level is -1
// for data tiles.
func ParseTilePath(p string) (level int, n uint64, w int, ok bool) {
	w = tileWidth
	if i := strings.Index(p, ".p/"); i >= 0 {
		x, err := strconv.Atoi(p[i+3:])
		if err != nil || x < 1 || x > 255 || strconv.Itoa(x) != p[i+3:] {
			return 0, 0, 0, false
		}
		w, p = x, p[:i]
	}
	parts := strings.Split(p, "/")
	if len(parts) < 2 {
		return 0, 0, 0, false
	}
	if parts[0] == "data" {
		level = -1
	} else {
		x, err := strconv.Atoi(parts[0])
		if err != nil || x < 0 || x > 5 || strconv.Itoa(x) != parts[0] {
			return 0, 0, 0, false
		}
		level = x
	}
	for k, el := range parts[1:] {
		last := k == len(parts)-2
		if !last {
			if !strings.HasPrefix(el, "x") {
				return 0, 0, 0, false
			}
			el = el[1:]
		}
		d, err := strconv.ParseUint(el, 10, 64)
		if err != nil || len(el) != 3 {
			return 0, 0, 0, false
		}
		n = n*1000 + d
	}
	return level, n, w, true
}

// tileExists reports whether tile n at level of width w is served now: the
// full tile once the published tree holds it, a partial only for a size a
// checkpoint was produced at, and only until the full tile exists unless
// KeepPartials (static-ct-api, "Partial Tiles").
func (l *Log) tileExists(level int, n uint64, w int) bool {
	full := widthIn(level, n, l.published) == tileWidth
	if w == tileWidth {
		return full
	}
	if full && !l.opts.KeepPartials {
		return false
	}
	for s := range l.checkpoints {
		if widthIn(level, n, s) == w {
			return true
		}
	}
	return false
}

func (l *Log) leafHash(i uint64) [32]byte { return [32]byte(l.tree.LeafHash(i)) }

func (l *Log) serveTile(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	p := strings.TrimPrefix(r.URL.Path, "/tile/")
	endpoint := "tile"
	if strings.HasPrefix(p, "data/") {
		endpoint = "data"
	}
	count, ok := l.begin(w, endpoint)
	if !ok {
		return
	}
	if l.opts.Missing != nil && l.opts.Missing(r.URL.Path) {
		http.NotFound(w, r)
		return
	}
	if l.opts.RedirectTiles {
		http.Redirect(w, r, r.URL.Path+"?moved", http.StatusFound)
		return
	}
	level, n, width, ok := ParseTilePath(p)
	if !ok || !l.tileExists(max(level, 0), n, width) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	if level >= 0 {
		b := HashTile(l.leafHash, level, n, width)
		if l.opts.BadHashTile {
			b[0] ^= 0xff
		}
		w.Write(b)
		return
	}
	var body []byte
	for i := n * tileWidth; i < n*tileWidth+uint64(width); i++ {
		e := l.Entries[i]
		leaf := e.LeafInput
		if l.altered[i] {
			leaf = flip(leaf)
		}
		body = append(body, l.tileLeaf(e, leaf)...)
	}
	if every(l.opts.CutDataTileEvery, count) {
		body = body[:len(body)/2]
	}
	if l.opts.GzipData {
		var z bytes.Buffer
		zw := gzip.NewWriter(&z)
		zw.Write(body)
		zw.Close()
		w.Header().Set("Content-Encoding", "gzip")
		body = z.Bytes()
	}
	w.Write(body)
}

func (l *Log) tileLeaf(e Entry, leaf []byte) []byte {
	pre, chain, ok := splitExtra(e)
	if !ok {
		l.t.Errorf("ctlogtest: entry with unreadable extra_data cannot be tiled")
	}
	fps := make([][32]byte, len(chain))
	for i, c := range chain {
		fps[i] = sha256.Sum256(c)
	}
	return TileLeaf(leaf, e.Type, pre, fps)
}

func (l *Log) serveIssuer(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.begin(w, "issuer"); !ok {
		return
	}
	if l.opts.Missing != nil && l.opts.Missing(r.URL.Path) {
		http.NotFound(w, r)
		return
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(r.URL.Path, "/issuer/"))
	if err != nil || len(raw) != 32 || strings.ToLower(r.URL.Path) != r.URL.Path {
		http.NotFound(w, r)
		return
	}
	der, ok := l.issuers[[32]byte(raw)]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if l.opts.IssuerWrongBytes {
		der = append(append([]byte(nil), der...), 0)
	}
	w.Header().Set("Content-Type", "application/pkix-cert")
	w.Write(der)
}

// KeyID is the checkpoint signature's key ID (static-ct-api).
func KeyID(origin string, logID [32]byte) [4]byte {
	h := sha256.New()
	h.Write([]byte(origin))
	h.Write([]byte{'\n', 0x05})
	h.Write(logID[:])
	return [4]byte(h.Sum(nil))
}

func (l *Log) serveCheckpoint(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.begin(w, "checkpoint"); !ok {
		return
	}
	size := l.published
	ts, ds, err := l.treeHeadSignature(size)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	origin := l.Origin
	text := origin
	if l.opts.CheckpointFault == WrongOrigin {
		text = origin + "-other"
	}
	text += fmt.Sprintf("\n%d\n%s\n", size, base64.StdEncoding.EncodeToString(l.rootAt(size)))
	if l.opts.CheckpointFault == ExtensionLine {
		text += "extension\n"
	}
	id := KeyID(origin, l.LogID)
	body := binary.BigEndian.AppendUint64(append([]byte(nil), id[:]...), ts)
	body = append(body, ds...)
	line := func(name string, sig []byte) string {
		return "— " + name + " " + base64.StdEncoding.EncodeToString(sig) + "\n"
	}
	// The log's other signature and a witness, which readers must ignore.
	other := make([]byte, 4+64)
	rand.Read(other)
	witness := make([]byte, 4+72)
	rand.Read(witness)
	sigs := line(origin, other) + line("witness.example.test/w1", witness)
	switch l.opts.CheckpointFault {
	case NoKeyLine:
	case TwoKeyLines:
		sigs = line(origin, body) + sigs + line(origin, body)
	default:
		sigs = line(origin, body) + sigs
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(text + "\n" + sigs))
}

// treeHeadSignature signs the RFC 6962 TreeHeadSignature for size, as
// get-sth does, and returns the timestamp and DigitallySigned bytes.
func (l *Log) treeHeadSignature(size uint64) (uint64, []byte, error) {
	ts := uint64(1790000000000) + size
	in := []byte{0, 1}
	in = binary.BigEndian.AppendUint64(in, ts)
	in = binary.BigEndian.AppendUint64(in, size)
	in = append(in, l.rootAt(size)...)
	digest := sha256.Sum256(in)
	sig, err := ecdsa.SignASN1(rand.Reader, l.key, digest[:])
	if err != nil {
		return 0, nil, err
	}
	if l.opts.BadSTHSignature {
		sig[len(sig)-1] ^= 0xff
	}
	ds := []byte{4, 3}
	ds = binary.BigEndian.AppendUint16(ds, uint16(len(sig)))
	return ts, append(ds, sig...), nil
}
