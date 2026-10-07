package powerloss

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// logBuilder writes a dm-log-writes log as the kernel does: the super in
// sector 0, then each entry's header in a sector of its own followed by its
// data.
type logBuilder struct {
	sector  int
	entries [][]byte
}

func (b *logBuilder) entry(sector, nrSectors, flags uint64, mark string, data []byte) {
	h := make([]byte, b.sector)
	binary.LittleEndian.PutUint64(h[0:], sector)
	binary.LittleEndian.PutUint64(h[8:], nrSectors)
	binary.LittleEndian.PutUint64(h[16:], flags)
	binary.LittleEndian.PutUint64(h[24:], uint64(len(mark)))
	copy(h[32:], mark)
	b.entries = append(b.entries, append(h, data...))
}

func (b *logBuilder) bytes(magic, version uint64) []byte {
	sup := make([]byte, b.sector)
	binary.LittleEndian.PutUint64(sup[0:], magic)
	binary.LittleEndian.PutUint64(sup[8:], version)
	binary.LittleEndian.PutUint64(sup[16:], uint64(len(b.entries)))
	binary.LittleEndian.PutUint32(sup[24:], uint32(b.sector))
	out := sup
	for _, e := range b.entries {
		out = append(out, e...)
	}
	return out
}

func fill(n int, c byte) []byte { return bytes.Repeat([]byte{c}, n) }

func writeFile(t *testing.T, p string, b []byte) string {
	t.Helper()
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestReplay: entries are read in order; writes land at their sector; a
// discard zeroes its range; marks name the phase; every flush and FUA entry
// is a crash point, after the entry is applied (amendment A5 §15).
func TestReplay(t *testing.T) {
	dir := t.TempDir()
	b := &logBuilder{sector: 512}
	b.entry(0, 0, flagMark, "ingest", nil)
	b.entry(2, 1, 0, "", fill(512, 'a'))
	b.entry(0, 0, flagFlush, "", nil) // crash point 1: sector 2 is 'a'
	b.entry(3, 2, flagFUA, "", fill(1024, 'b'))
	b.entry(0, 0, flagMark, "gc", nil)
	b.entry(2, 1, flagDiscard, "", nil)
	b.entry(5, 1, flagFlush, "", fill(512, 'c')) // a flush with data: crash point 3
	logPath := writeFile(t, filepath.Join(dir, "log"), b.bytes(logMagic, logVersion))
	img := writeFile(t, filepath.Join(dir, "img"), fill(8*512, 'z'))

	l, err := OpenLog(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if l.Entries != 7 || l.SectorSize != 512 {
		t.Fatalf("super: %d entries, sector %d", l.Entries, l.SectorSize)
	}
	r, err := NewReplayer(img)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var points []string
	err = l.Each(func(e Entry) error {
		if err := r.Apply(e); err != nil {
			return err
		}
		if e.CrashPoint() {
			b, _ := os.ReadFile(img)
			points = append(points, e.Phase+":"+string(b[2*512])+string(b[3*512])+string(b[4*512])+string(b[5*512]))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ingest:azzz", "ingest:abbz", "gc:\x00bbc"}
	if strings.Join(points, " ") != strings.Join(want, " ") {
		t.Fatalf("crash points %q, want %q", points, want)
	}
}

// TestDamagedLogs: a log with another magic or version, fewer entries than
// its super says, or an entry running past the end is refused.
func TestDamagedLogs(t *testing.T) {
	dir := t.TempDir()
	good := &logBuilder{sector: 512}
	good.entry(1, 2, 0, "", fill(1024, 'x'))
	cases := map[string][]byte{
		"magic":   good.bytes(logMagic+1, logVersion),
		"version": good.bytes(logMagic, logVersion+1),
		"short":   good.bytes(logMagic, logVersion)[:512+512+100],
		"tiny":    []byte("x"),
	}
	for name, b := range cases {
		p := writeFile(t, filepath.Join(dir, name), b)
		l, err := OpenLog(p)
		if err == nil {
			err = l.Each(func(Entry) error { return nil })
			l.Close()
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A write past the image's end is refused too.
	p := writeFile(t, filepath.Join(dir, "far"), good.bytes(logMagic, logVersion))
	img := writeFile(t, filepath.Join(dir, "img"), fill(1024, 0))
	l, _ := OpenLog(p)
	defer l.Close()
	r, _ := NewReplayer(img)
	defer r.Close()
	if err := l.Each(r.Apply); err == nil {
		t.Fatal("a write past the image's end is applied")
	}
}
