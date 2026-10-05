package vault

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"

	"github.com/4rji/ctvault/internal/fsutil"
)

// Uncommitted describes vault data beyond the committed tail.
type Uncommitted struct {
	Bytes     uint64 // bytes beyond the tail
	MaxCertID uint64 // highest cert_id in an intact record there, 0 if none
}

// InspectTail measures the data beyond the committed tail (spec §8.5): the
// highest cert_id seen there must be lifted into ID_FLOOR before Truncate
// discards it. Torn records at the end are expected and tolerated. Records
// are streamed, and a segment that ends exactly at the tail is not read.
func InspectTail(dirs []string, tail Tail) (Uncommitted, error) {
	segs, err := FindSegments(dirs)
	if err != nil {
		return Uncommitted{}, err
	}
	var u Uncommitted
	for id, p := range segs {
		if id < tail.Segment {
			continue
		}
		fi, err := os.Stat(p)
		if err != nil {
			return u, err
		}
		size := uint64(fi.Size())
		start := uint64(HeaderSize) // records follow the header even if it is torn or damaged
		if id == tail.Segment {
			if size < tail.Offset {
				return u, corrupt("segment %d is %d bytes, shorter than the committed tail %d", id, size, tail.Offset)
			}
			u.Bytes += size - tail.Offset
			start = tail.Offset
		} else {
			u.Bytes += size
		}
		if start >= size {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			return u, err
		}
		// A torn or garbage record ends the scan: that is the crash point.
		_ = eachRecord(f, id, start, size, func(_ Loc, rec Record) error {
			u.MaxCertID = max(u.MaxCertID, rec.CertID)
			return nil
		})
		f.Close()
	}
	return u, nil
}

// Truncate removes everything beyond the committed tail: the tail segment is
// cut back to tail.Offset, later segments are deleted, and both are synced.
// Delta records only point backwards, so no committed record loses its base.
// A tail segment that is missing or shorter than tail.Offset is corruption:
// truncating would extend it with zeros.
func Truncate(dirs []string, tail Tail) error {
	segs, err := FindSegments(dirs)
	if err != nil {
		return err
	}
	if tail.Segment > 0 {
		p, ok := segs[tail.Segment]
		if !ok {
			return corrupt("tail segment %d is missing", tail.Segment)
		}
		fi, err := os.Stat(p)
		if err != nil {
			return err
		}
		if uint64(fi.Size()) < tail.Offset {
			return corrupt("segment %d is %d bytes, shorter than the tail %d it would be cut to", tail.Segment, fi.Size(), tail.Offset)
		}
	}
	for id, p := range segs {
		switch {
		case id > tail.Segment:
			if err := os.Remove(p); err != nil {
				return err
			}
			if err := fsutil.SyncDir(filepath.Dir(p)); err != nil {
				return err
			}
		case id == tail.Segment:
			f, err := os.OpenFile(p, os.O_RDWR, 0)
			if err != nil {
				return err
			}
			if tail.Offset > math.MaxInt64 {
				f.Close()
				return errors.New("vault: tail offset out of range")
			}
			err = f.Truncate(int64(tail.Offset))
			if err == nil {
				err = f.Sync()
			}
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return fmt.Errorf("truncating segment %d: %w", id, err)
			}
		}
	}
	return nil
}
