//go:build ctvault_dev || realdata

package ingest

import (
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/merkle"
)

// TestSeedStartsAMeasurementMidLog: a seeded writer commits a window that
// starts mid-log, verified against the real head, and the workspace can
// never be reopened as a vault.
func TestSeedStartsAMeasurementMidLog(t *testing.T) {
	h := newHarness(t, entries(t, 40), ctlogtest.Options{})
	w := h.open()
	st := merkle.NewState()
	for _, e := range h.log.Entries[:16] {
		if err := st.Append(merkle.LeafHash(e.LeafInput)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Seed("fakelog", st); err != nil {
		t.Fatal(err)
	}
	ms := h.ingest(w, h.head(), 16, 40, 12)
	if ms[0].First != 16 || ms[1].Last != 39 || ms[1].Verified.Method != "root_equals_sth" {
		t.Fatalf("manifests: %+v / %+v", ms[0], ms[1])
	}
	if got := w.Committed(); len(got) != 2 || got[1].CommitSeq != 2 {
		t.Fatalf("Committed() = %d manifests", len(got))
	}
	if err := w.Seed("fakelog", merkle.NewState()); err == nil {
		t.Fatal("Seed accepted a log that already has committed batches")
	}
	w.Close()
	if _, err := Open(h.opts); err == nil || !strings.Contains(err.Error(), "not contiguous at index 0") {
		t.Fatalf("reopening a seeded workspace: %v, want the contiguity refusal", err)
	}
}

// TestSeedWithAWrongStateFailsVerification: the seed is not trusted; a
// batch whose compact range is wrong fails Merkle verification.
func TestSeedWithAWrongStateFailsVerification(t *testing.T) {
	h := newHarness(t, entries(t, 40), ctlogtest.Options{})
	w := h.open()
	st := merkle.NewState()
	for _, e := range h.log.Entries[1:17] { // shifted by one: the wrong range
		st.Append(merkle.LeafHash(e.LeafInput))
	}
	if err := w.Seed("fakelog", st); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Batch(ctx, h.src, h.head(), 16, 40); err == nil {
		t.Fatal("a batch over a wrong seed committed")
	}
}
