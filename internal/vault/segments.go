package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// SegmentsDir and DictDir are the subfolders of every vault directory.
const (
	SegmentsDir = "segments"
	DictDir     = "dict"
)

// SegmentName is a segment's file name: its ID, zero-padded to 10 digits.
func SegmentName(id uint64) string { return fmt.Sprintf("%010d.seg", id) }

// FindSegments lists every segment file in the vault directories, by ID.
// The same ID in two places is corruption (spec §6.2).
func FindSegments(dirs []string) (map[uint64]string, error) {
	out := map[uint64]string{}
	for _, d := range dirs {
		names, err := os.ReadDir(filepath.Join(d, SegmentsDir))
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			base, ok := strings.CutSuffix(n.Name(), ".seg")
			if !ok || n.IsDir() {
				continue
			}
			id, err := strconv.ParseUint(base, 10, 64)
			if err != nil || SegmentName(id) != n.Name() {
				return nil, corrupt("unexpected file %s in %s", n.Name(), d)
			}
			p := filepath.Join(d, SegmentsDir, n.Name())
			if prev, dup := out[id]; dup {
				return nil, corrupt("segment %d exists twice: %s and %s", id, prev, p)
			}
			out[id] = p
		}
	}
	return out, nil
}
