package vault

import (
	"errors"
	"io"
	"os"
)

// CheckSegments verifies the committed vault's segment files (spec §6.2):
// segments 1 to tail.Segment all exist, none lies beyond the tail, and every
// header is intact and names its own segment and this vault's UUID. A
// missing segment, or one restored from another vault, is corruption.
func CheckSegments(dirs []string, uuid [16]byte, tail Tail) error {
	segs, err := FindSegments(dirs)
	if err != nil {
		return err
	}
	for id := range segs {
		if id > tail.Segment {
			return corrupt("segment %d lies beyond the committed tail %d", id, tail.Segment)
		}
	}
	for id := uint64(1); id <= tail.Segment; id++ {
		p, ok := segs[id]
		if !ok {
			return corrupt("segment %d is missing", id)
		}
		if err := checkHeader(p, id, uuid); err != nil {
			return err
		}
	}
	return nil
}

func checkHeader(p string, id uint64, uuid [16]byte) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	b := make([]byte, HeaderSize)
	n, err := f.ReadAt(b, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	h, err := DecodeHeader(b[:n])
	if err != nil {
		return corrupt("segment %d: %v", id, err)
	}
	if h.Segment != id {
		return corrupt("segment file %d holds segment %d", id, h.Segment)
	}
	if h.VaultUUID != uuid {
		return corrupt("segment %d belongs to another vault (UUID %x)", id, h.VaultUUID)
	}
	return nil
}
