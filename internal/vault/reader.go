package vault

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// Reader reads committed records. It is not safe for concurrent use.
type Reader struct {
	codec *Codec
	segs  map[uint64]string
	files map[uint64]*os.File
}

// OpenReader indexes the segments of the vault directories.
func OpenReader(dirs []string, codec *Codec) (*Reader, error) {
	segs, err := FindSegments(dirs)
	if err != nil {
		return nil, err
	}
	return &Reader{codec: codec, segs: segs, files: map[uint64]*os.File{}}, nil
}

func (r *Reader) file(id uint64) (*os.File, error) {
	if f, ok := r.files[id]; ok {
		return f, nil
	}
	p, ok := r.segs[id]
	if !ok {
		return nil, corrupt("segment %d does not exist", id)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	r.files[id] = f
	return f, nil
}

// recordAt reads the record that starts at (segment, offset), whose length
// is taken from its own prefix: delta references carry no length.
func (r *Reader) recordAt(seg, off uint64) (Record, Loc, error) {
	f, err := r.file(seg)
	if err != nil {
		return Record{}, Loc{}, err
	}
	var prefix [binary.MaxVarintLen64]byte
	n, err := f.ReadAt(prefix[:], int64(off))
	if err != nil && !errors.Is(err, io.EOF) {
		return Record{}, Loc{}, err
	}
	body, k := binary.Uvarint(prefix[:n])
	if k <= 0 || body > 1<<30 {
		return Record{}, Loc{}, corrupt("no record at %d:%d", seg, off)
	}
	loc := Loc{Segment: seg, Offset: off, Len: uint32(uint64(k) + body)}
	rec, err := r.record(loc)
	return rec, loc, err
}

// RecordAt reads the record that starts at (segment, offset), such as a
// leaf-delta's base, whose reference carries no length.
func (r *Reader) RecordAt(seg, off uint64) (Record, Loc, error) { return r.recordAt(seg, off) }

// record reads and parses the record at loc.
func (r *Reader) record(loc Loc) (Record, error) {
	f, err := r.file(loc.Segment)
	if err != nil {
		return Record{}, err
	}
	b := make([]byte, loc.Len)
	if _, err := f.ReadAt(b, int64(loc.Offset)); err != nil {
		if errors.Is(err, io.EOF) {
			return Record{}, corrupt("record %d:%d runs past the end of its segment", loc.Segment, loc.Offset)
		}
		return Record{}, err
	}
	rec, err := ParseRecord(b)
	if err != nil {
		return rec, corrupt("record %d:%d: %v", loc.Segment, loc.Offset, err)
	}
	if rec.TotalLen != int(loc.Len) {
		return rec, corrupt("record %d:%d is %d bytes, location says %d", loc.Segment, loc.Offset, rec.TotalLen, loc.Len)
	}
	return rec, nil
}

// Read returns the certificate DER of the record at loc, and its record.
func (r *Reader) Read(loc Loc) ([]byte, Record, error) {
	rec, err := r.record(loc)
	if err != nil {
		return nil, rec, err
	}
	switch rec.Kind {
	case KindLeaf, KindChain:
		der, err := r.codec.Decompress(rec.Frame, rec.DictID)
		return der, rec, err
	case KindDelta:
		if rec.BaseSeg > loc.Segment || (rec.BaseSeg == loc.Segment && rec.BaseOff >= loc.Offset) {
			return nil, rec, corrupt("delta %d:%d points forward to %d:%d", loc.Segment, loc.Offset, rec.BaseSeg, rec.BaseOff)
		}
		base, _, err := r.recordAt(rec.BaseSeg, rec.BaseOff)
		if err != nil {
			return nil, rec, corrupt("delta %d:%d: unresolvable base: %v", loc.Segment, loc.Offset, err)
		}
		if base.Kind != KindLeaf {
			return nil, rec, corrupt("delta %d:%d: base is a kind %d record", loc.Segment, loc.Offset, base.Kind)
		}
		baseDER, err := r.codec.Decompress(base.Frame, base.DictID)
		if err != nil {
			return nil, rec, err
		}
		der, err := r.codec.DecompressDelta(rec.Frame, baseDER)
		return der, rec, err
	}
	return nil, rec, corrupt("record %d:%d has kind %d", loc.Segment, loc.Offset, rec.Kind)
}

// ReadVerified reads the record at loc and checks its SHA-256. A mismatch is
// corruption (spec §6.2: "SHA-256 is recomputed on read and verified").
func (r *Reader) ReadVerified(loc Loc, want [32]byte) ([]byte, error) {
	der, _, err := r.Read(loc)
	if err != nil {
		return nil, err
	}
	if sha256.Sum256(der) != want {
		return nil, corrupt("record %d:%d does not match its SHA-256", loc.Segment, loc.Offset)
	}
	return der, nil
}

// Close closes the open segment files.
func (r *Reader) Close() {
	for _, f := range r.files {
		f.Close()
	}
	r.files = map[uint64]*os.File{}
}

// Scan calls fn for every record from position from up to (excluding) to,
// in vault order. Records are streamed; a segment is never loaded whole. A
// record cut short at the end of the range is ErrTorn; anything else
// malformed is ErrCorrupt.
func Scan(dirs []string, from, to Tail, fn func(Loc, Record) error) error {
	segs, err := FindSegments(dirs)
	if err != nil {
		return err
	}
	for id := max(from.Segment, 1); id <= to.Segment; id++ {
		p, ok := segs[id]
		if !ok {
			return corrupt("segment %d is missing", id)
		}
		start, end := uint64(HeaderSize), uint64(1<<63)
		if id == from.Segment {
			start = max(start, from.Offset)
		}
		if id == to.Segment {
			end = to.Offset
		}
		if err := scanSegment(id, p, start, end, fn); err != nil {
			return err
		}
	}
	return nil
}

// scanSegment checks a segment's header and streams its records in
// [start, min(end, size)).
func scanSegment(id uint64, p string, start, end uint64, fn func(Loc, Record) error) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	var hdr [HeaderSize]byte
	if n, err := f.ReadAt(hdr[:], 0); err != nil && !(errors.Is(err, io.EOF) && n == HeaderSize) {
		if _, herr := DecodeHeader(hdr[:n]); herr != nil {
			return fmt.Errorf("segment %d: %w", id, herr)
		}
		return err
	}
	if _, err := DecodeHeader(hdr[:]); err != nil {
		return fmt.Errorf("segment %d: %w", id, err)
	}
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	return eachRecord(f, id, start, min(end, uint64(fi.Size())), fn)
}

// eachRecord streams the records of f in [start, end).
func eachRecord(f *os.File, id, start, end uint64, fn func(Loc, Record) error) error {
	if start >= end {
		return nil
	}
	br := bufio.NewReaderSize(io.NewSectionReader(f, int64(start), int64(end-start)), 1<<20)
	for off := start; off < end; {
		rec, err := readRecord(br)
		if err != nil {
			return fmt.Errorf("segment %d offset %d: %w", id, off, err)
		}
		if err := fn(Loc{Segment: id, Offset: off, Len: uint32(rec.TotalLen)}, rec); err != nil {
			return err
		}
		off += uint64(rec.TotalLen)
	}
	return nil
}

// readRecord reads one record from a stream.
func readRecord(br *bufio.Reader) (Record, error) {
	n, err := binary.ReadUvarint(br)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return Record{}, ErrTorn
	}
	if err != nil || n == 0 || n > 1<<30 {
		return Record{}, corrupt("bad record length")
	}
	buf := binary.AppendUvarint(make([]byte, 0, n+binary.MaxVarintLen64), n)
	k := len(buf)
	buf = buf[:k+int(n)]
	if _, err := io.ReadFull(br, buf[k:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return Record{}, ErrTorn
		}
		return Record{}, err
	}
	return ParseRecord(buf)
}
