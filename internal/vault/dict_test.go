package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"strings"
	"testing"
)

func trainOn(t *testing.T, n int) ([][]byte, []byte) {
	t.Helper()
	cs := certs(t, n)
	content, err := Train(cs, 1)
	if err != nil {
		t.Fatal(err)
	}
	return cs, content
}

func TestTrainInstallLoadAndUse(t *testing.T) {
	cs, content := trainOn(t, 120)
	dirs := vaultDirs(t, 2)
	tr := Training{Records: 120, FirstCertID: 1, LastCertID: 120}
	if _, err := InstallDict(dirs, 1, content, tr, fixedNow()); err != nil {
		t.Fatal(err)
	}
	ds, err := LoadDicts(dirs)
	if err != nil || len(ds) != 1 {
		t.Fatalf("LoadDicts: %d dictionaries, %v", len(ds), err)
	}
	m := ds[0].Manifest
	if m.ID != 1 || m.Training != tr || m.Bytes != len(content) || !strings.HasPrefix(m.Library, "github.com/klauspost/compress") {
		t.Fatalf("manifest %+v", m)
	}
	c := codec(t)
	if err := c.AddDict(1, ds[0].Content); err != nil {
		t.Fatal(err)
	}
	w, err := OpenWriter(Options{Dirs: dirs, VaultUUID: testUUID, SegmentSize: 1 << 20, Now: fixedNow}, c, Tail{})
	if err != nil {
		t.Fatal(err)
	}
	var with, without int
	for i, der := range cs[:20] {
		a, _ := w.AppendCert(KindLeaf, uint64(2*i+1), der, 1)
		b, _ := w.AppendCert(KindLeaf, uint64(2*i+2), der, 0)
		with, without = with+int(a.Len), without+int(b.Len)
		r, _ := OpenReader(dirs, c)
		if got, err := r.ReadVerified(a, sha256.Sum256(der)); err != nil || string(got) != string(der) {
			t.Fatalf("dictionary record %d: %v", i, err)
		}
		r.Close()
	}
	w.Close()
	if with >= without {
		t.Fatalf("the trained dictionary must shrink records: %d vs %d bytes", with, without)
	}
	frame, _ := c.Compress(cs[0], 1)
	if _, err := c.Decompress(frame, 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a dictionary-1 frame in a record claiming no dictionary is corrupt: %v", err)
	}
}

func TestDictsAreImmutableAndReplicated(t *testing.T) {
	_, content := trainOn(t, 80)
	dirs := vaultDirs(t, 2)
	if _, err := InstallDict(dirs, 1, content, Training{}, fixedNow()); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallDict(dirs, 1, content, Training{}, fixedNow()); err == nil {
		t.Fatal("a dictionary ID is never reused")
	}
	cp, mp := dictFiles(dirs[1], 1)
	os.Remove(mp)
	os.Remove(cp)
	if _, err := LoadDicts(dirs); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(mp); err != nil {
		t.Fatal("LoadDicts must restore a replica an interrupted install left missing")
	}
	cp0, _ := dictFiles(dirs[0], 1)
	os.Chmod(cp0, 0o644)
	b, _ := os.ReadFile(cp0)
	b[10] ^= 1
	os.WriteFile(cp0, b, 0o644)
	if _, err := LoadDicts(dirs); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a dictionary that no longer matches its manifest is corruption: %v", err)
	}
}

// TestTrainFailureFallsBack: ingestion continues with dictionary 0 when
// training fails (amendment A1 §5), including when the library panics.
func TestTrainFailureFallsBack(t *testing.T) {
	if _, err := Train([][]byte{[]byte("a"), []byte("b")}, 1); err == nil {
		t.Fatal("degenerate samples (the library divides by zero on them) must give an error, not a panic")
	}
	noise := make([][]byte, 60)
	for i := range noise {
		noise[i] = make([]byte, 1500)
		rand.Read(noise[i])
	}
	if _, err := Train(noise, 1); err == nil {
		t.Fatal("a dictionary that does not shrink its own samples is unusable")
	}
}

func TestTrainingSetReadsCommittedLeaves(t *testing.T) {
	dirs := vaultDirs(t, 1)
	cs := certs(t, 10)
	w := openWriter(t, dirs, 1<<20, Tail{}, nil)
	w.AppendCert(KindChain, 1, cs[0], 0)
	for i := 1; i < 10; i++ {
		w.AppendCert(KindLeaf, uint64(i+1), cs[i], 0)
	}
	w.Sync()
	tail := w.Tail()
	w.AppendCert(KindLeaf, 11, cs[0], 0) // beyond the committed tail
	w.Close()
	got, tr, err := TrainingSet(dirs, codec(t), tail, 5)
	if err != nil || len(got) != 5 || string(got[0]) != string(cs[1]) || tr != (Training{Records: 5, FirstCertID: 2, LastCertID: 6}) {
		t.Fatalf("the first 5 leaf records (chains skipped): %d, %+v, %v", len(got), tr, err)
	}
	all, tr, _ := TrainingSet(dirs, codec(t), tail, 100)
	if len(all) != 9 || tr.LastCertID != 10 {
		t.Fatalf("never past the committed tail: %d records, %+v", len(all), tr)
	}
}
