package vault

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/4rji/ctvault/internal/fsutil"
)

// CheckEvery is how often, in bytes appended, the writer re-checks the disk
// cap by default (spec §10.1: "every 256 MiB of vault appends").
const CheckEvery = 256 << 20

// Options configure a Writer.
type Options struct {
	Dirs        []string // vault directories, in VAULT_ID order (absolute paths)
	VaultUUID   [16]byte
	SegmentSize uint64 // vault.segment_size
	// Check is the disk guard: it returns an error if writing need more
	// bytes in dir would cross the cap.
	Check func(dir string, need uint64) error
	// CheckEvery overrides the 256 MiB re-check interval (tests use less).
	CheckEvery uint64
	// Hook, if set, is called at named crash points (tests only).
	Hook func(point string)
	Now  func() time.Time
}

// Hook points the writer passes to Options.Hook.
const (
	HookRolloverBeforeHeader  = "vault.rollover.before_header"
	HookRolloverAfterHeader   = "vault.rollover.after_header"
	HookRolloverBeforeDirSync = "vault.rollover.before_dir_sync"
)

// Writer appends records after the committed tail. It is used by one
// goroutine, the batch writer.
type Writer struct {
	o         Options
	codec     *Codec
	segs      map[uint64]string
	f         *os.File
	seg       uint64
	off       uint64
	sinceChk  uint64
	unsynced  bool
	dirOfSeg  string
	preferred string // vault directory the current batch reserved space on
	forceRoll bool   // the current segment is elsewhere: roll over first
}

// OpenWriter positions a writer at the committed tail. The tail segment must
// end exactly at tail.Offset: recovery truncates anything beyond it first.
func OpenWriter(o Options, codec *Codec, tail Tail) (*Writer, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.CheckEvery == 0 {
		o.CheckEvery = CheckEvery
	}
	segs, err := FindSegments(o.Dirs)
	if err != nil {
		return nil, err
	}
	w := &Writer{o: o, codec: codec, segs: segs, seg: tail.Segment, off: tail.Offset}
	for id := range segs {
		if id > tail.Segment {
			return nil, fmt.Errorf("vault: segment %d lies beyond the committed tail %d; run recovery first", id, tail.Segment)
		}
	}
	if tail.Segment == 0 {
		return w, nil
	}
	p, ok := segs[tail.Segment]
	if !ok {
		return nil, corrupt("tail segment %d is missing", tail.Segment)
	}
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if uint64(fi.Size()) != tail.Offset {
		f.Close()
		return nil, fmt.Errorf("vault: segment %d is %d bytes but the committed tail is %d; run recovery first", tail.Segment, fi.Size(), tail.Offset)
	}
	w.f, w.dirOfSeg = f, filepath.Dir(filepath.Dir(p)) // the vault directory, as rollover records it
	return w, nil
}

// Prefer makes new segments go to dir first: the directory the batch
// preflight reserved the vault peak on. If the current segment lives
// elsewhere, the next append starts a new segment in dir.
func (w *Writer) Prefer(dir string) {
	w.preferred = dir
	w.forceRoll = w.f != nil && w.dirOfSeg != dir
}

// Tail returns the position the next record will take.
func (w *Writer) Tail() Tail { return Tail{Segment: w.seg, Offset: w.off} }

func (w *Writer) hook(p string) {
	if w.o.Hook != nil {
		w.o.Hook(p)
	}
}

// rollover syncs the current segment and creates the next one in the first
// vault directory that passes the disk guard.
func (w *Writer) rollover(firstCertID uint64) error {
	if w.f != nil {
		if err := w.f.Sync(); err != nil {
			return err
		}
		if err := w.f.Close(); err != nil {
			return err
		}
		w.f = nil
	}
	var dir string
	var refusals []error
	order := w.o.Dirs
	if w.preferred != "" {
		order = append([]string{w.preferred}, w.o.Dirs...)
	}
	for _, d := range order {
		if w.o.Check == nil {
			dir = d
			break
		}
		err := w.o.Check(d, w.o.SegmentSize)
		if err == nil {
			dir = d
			break
		}
		refusals = append(refusals, err)
	}
	if dir == "" {
		return fmt.Errorf("vault: no vault directory has room for a new segment: %w", refusals[len(refusals)-1])
	}
	id := w.seg + 1
	p := filepath.Join(dir, SegmentsDir, SegmentName(id))
	w.hook(HookRolloverBeforeHeader)
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	h := Header{Version: FormatVersion, VaultUUID: w.o.VaultUUID, Segment: id, FirstCertID: firstCertID, Created: w.o.Now()}
	if _, err := f.WriteAt(h.Encode(), 0); err != nil {
		f.Close()
		return err
	}
	w.hook(HookRolloverAfterHeader)
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	w.hook(HookRolloverBeforeDirSync)
	if err := fsutil.SyncDir(filepath.Dir(p)); err != nil {
		f.Close()
		return err
	}
	w.f, w.seg, w.off, w.dirOfSeg = f, id, HeaderSize, dir
	w.segs[id] = p
	return nil
}

// append writes one record, rolling over first when it would not fit.
func (w *Writer) append(r Record) (Loc, error) {
	rec := AppendRecord(nil, r)
	if w.f == nil || w.forceRoll || w.off+uint64(len(rec)) > w.o.SegmentSize {
		if err := w.rollover(r.CertID); err != nil {
			return Loc{}, err
		}
		w.forceRoll = false
	}
	if w.o.Check != nil {
		w.sinceChk += uint64(len(rec))
		if w.sinceChk >= w.o.CheckEvery {
			if err := w.o.Check(w.dirOfSeg, w.o.CheckEvery); err != nil {
				return Loc{}, err
			}
			w.sinceChk = 0
		}
	}
	// Write at the tracked offset: a reopened segment's file position is 0.
	if _, err := w.f.WriteAt(rec, int64(w.off)); err != nil {
		return Loc{}, err
	}
	loc := Loc{Segment: w.seg, Offset: w.off, Len: uint32(len(rec))}
	w.off += uint64(len(rec))
	w.unsynced = true
	return loc, nil
}

// AppendCert vaults der as a leaf (KindLeaf) or chain (KindChain) record
// compressed with dictionary dictID.
func (w *Writer) AppendCert(kind byte, certID uint64, der []byte, dictID uint64) (Loc, error) {
	if kind != KindLeaf && kind != KindChain {
		return Loc{}, fmt.Errorf("vault: AppendCert with kind %d", kind)
	}
	frame, err := w.codec.Compress(der, dictID)
	if err != nil {
		return Loc{}, err
	}
	return w.append(Record{Kind: kind, CertID: certID, DictID: dictID, Frame: frame})
}

// AppendDelta vaults der as a leaf-delta record against the leaf record at
// base, which must lie earlier in the vault: a committed record, or one of
// the in-flight batch (truncation always removes the newest records first).
func (w *Writer) AppendDelta(certID uint64, der []byte, base Loc) (Loc, error) {
	baseDER, err := w.readLeaf(base)
	if err != nil {
		return Loc{}, err
	}
	frame, err := w.codec.CompressDelta(der, baseDER)
	if err != nil {
		return Loc{}, err
	}
	return w.append(Record{Kind: KindDelta, CertID: certID, BaseSeg: base.Segment, BaseOff: base.Offset, Frame: frame})
}

// readLeaf decodes the leaf record at loc, which may still be unsynced.
func (w *Writer) readLeaf(loc Loc) ([]byte, error) {
	b, err := w.readAt(loc.Segment, loc.Offset, int(loc.Len))
	if err != nil {
		return nil, err
	}
	rec, err := ParseRecord(b)
	if err != nil || rec.TotalLen != int(loc.Len) || rec.Kind != KindLeaf {
		return nil, corrupt("delta base %d:%d is not a leaf record", loc.Segment, loc.Offset)
	}
	return w.codec.Decompress(rec.Frame, rec.DictID)
}

// Sync makes every appended record durable (commit step P3).
func (w *Writer) Sync() error {
	if w.f == nil || !w.unsynced {
		return nil
	}
	if err := w.f.Sync(); err != nil {
		return err
	}
	w.unsynced = false
	return nil
}

// readAt reads n bytes of segment id at off, including unsynced data.
func (w *Writer) readAt(id, off uint64, n int) ([]byte, error) {
	p, ok := w.segs[id]
	if !ok {
		return nil, corrupt("segment %d does not exist", id)
	}
	f := w.f
	if id != w.seg || f == nil {
		var err error
		if f, err = os.Open(p); err != nil {
			return nil, err
		}
		defer f.Close()
	}
	b := make([]byte, n)
	if _, err := f.ReadAt(b, int64(off)); err != nil && err != io.EOF {
		return nil, err
	}
	return b, nil
}

// Close closes the current segment without syncing it.
func (w *Writer) Close() error {
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
