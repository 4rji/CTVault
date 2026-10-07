// Package powerloss is the power-loss gate (spec §13.6, amendment A5 Part
// 6C): it records a vault workload through the kernel's dm-log-writes
// target, replays the log onto a copy of the starting device, and checks
// the vault at every point where the disk had confirmed a flush. Only the
// root-only test (build tag powerloss) touches devices; the format, the
// replay, the checks and the workload here are plain code, tested without
// root.
package powerloss

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// The dm-log-writes on-disk format (drivers/md/dm-log-writes.c): the super
// in the first sector, then for each entry a header in a sector of its own,
// followed by the data it wrote.
const (
	logMagic   = 0x6a736677736872
	logVersion = 1

	flagFlush    = 1 << 0
	flagFUA      = 1 << 1
	flagDiscard  = 1 << 2
	flagMark     = 1 << 3
	flagMetadata = 1 << 4
)

// ErrLog means the log is not a dm-log-writes log this replayer reads.
var ErrLog = errors.New("not a dm-log-writes log")

// Entry is one logged request.
type Entry struct {
	Index      uint64 // 0-based, in log order
	Sector     uint64 // in the log's sector size
	Sectors    uint64
	Flags      uint64
	Mark       string // for a mark entry
	Phase      string // the last mark before or at this entry
	Data       []byte // what a write wrote; nil otherwise
	SectorSize int
}

// CrashPoint reports whether the disk had confirmed a flush once this entry
// completed: a flush, or a write with FUA (amendment A5 §15).
func (e Entry) CrashPoint() bool { return e.Flags&(flagFlush|flagFUA) != 0 }

// Discard reports whether the entry discards its range.
func (e Entry) Discard() bool { return e.Flags&flagDiscard != 0 }

// IsMark reports whether the entry is a mark.
func (e Entry) IsMark() bool { return e.Flags&flagMark != 0 }

// Log is an open dm-log-writes log.
type Log struct {
	f          *os.File
	Entries    uint64
	SectorSize int
}

// OpenLog reads a log's super.
func OpenLog(path string) (*Log, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	var sup [28]byte
	if _, err := io.ReadFull(f, sup[:]); err != nil {
		f.Close()
		return nil, fmt.Errorf("%w: %s: no super: %v", ErrLog, path, err)
	}
	magic, version := binary.LittleEndian.Uint64(sup[0:]), binary.LittleEndian.Uint64(sup[8:])
	l := &Log{f: f, Entries: binary.LittleEndian.Uint64(sup[16:]), SectorSize: int(binary.LittleEndian.Uint32(sup[24:]))}
	switch {
	case magic != logMagic:
		f.Close()
		return nil, fmt.Errorf("%w: %s: magic %#x", ErrLog, path, magic)
	case version != logVersion:
		f.Close()
		return nil, fmt.Errorf("%w: %s: version %d", ErrLog, path, version)
	case l.SectorSize < 512 || l.SectorSize > 64<<10 || l.SectorSize&(l.SectorSize-1) != 0:
		f.Close()
		return nil, fmt.Errorf("%w: %s: sector size %d", ErrLog, path, l.SectorSize)
	}
	return l, nil
}

// Close closes the log.
func (l *Log) Close() error { return l.f.Close() }

// Each calls fn for every entry the super counts, in order. A log cut short
// is refused.
func (l *Log) Each(fn func(Entry) error) error {
	ss := int64(l.SectorSize)
	off := ss
	header := make([]byte, ss)
	phase := ""
	for i := uint64(0); i < l.Entries; i++ {
		if _, err := l.f.ReadAt(header, off); err != nil {
			return fmt.Errorf("%w: entry %d of %d: its header is cut short: %v", ErrLog, i, l.Entries, err)
		}
		off += ss
		e := Entry{Index: i, Sector: binary.LittleEndian.Uint64(header[0:]), Sectors: binary.LittleEndian.Uint64(header[8:]),
			Flags: binary.LittleEndian.Uint64(header[16:]), SectorSize: l.SectorSize}
		dataLen := binary.LittleEndian.Uint64(header[24:])
		switch {
		case e.IsMark():
			if dataLen > uint64(ss-32) {
				return fmt.Errorf("%w: entry %d: a mark of %d bytes", ErrLog, i, dataLen)
			}
			e.Mark = string(header[32 : 32+dataLen])
			phase = e.Mark
		case e.Discard():
		case e.Sectors > 0:
			if e.Sectors > 1<<24 {
				return fmt.Errorf("%w: entry %d: %d sectors", ErrLog, i, e.Sectors)
			}
			e.Data = make([]byte, e.Sectors*uint64(ss))
			if _, err := l.f.ReadAt(e.Data, off); err != nil {
				return fmt.Errorf("%w: entry %d: its data is cut short: %v", ErrLog, i, err)
			}
			off += int64(len(e.Data))
		}
		e.Phase = phase
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

// Replayer applies entries to an image file.
type Replayer struct {
	f    *os.File
	size int64
}

// NewReplayer opens an image to replay onto.
func NewReplayer(path string) (*Replayer, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &Replayer{f: f, size: st.Size()}, nil
}

// Apply replays one entry: a write writes its data, a discard zeroes its
// range, flushes and marks change nothing.
func (r *Replayer) Apply(e Entry) error {
	ss := int64(e.SectorSize)
	off, n := int64(e.Sector)*ss, int64(e.Sectors)*ss
	if (e.Data != nil || e.Discard()) && off+n > r.size {
		return fmt.Errorf("entry %d writes [%d, %d), past the image's end %d", e.Index, off, off+n, r.size)
	}
	switch {
	case e.Data != nil:
		_, err := r.f.WriteAt(e.Data, off)
		return err
	case e.Discard():
		_, err := r.f.WriteAt(make([]byte, n), off)
		return err
	}
	return nil
}

// Sync flushes the image to its file.
func (r *Replayer) Sync() error { return r.f.Sync() }

// Close closes the image.
func (r *Replayer) Close() error { return r.f.Close() }
