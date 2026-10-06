package health

import (
	"fmt"
	"testing"
	"time"
)

// TestRecordKeepsTheLast100Failures: passes are counted, failures kept up
// to MaxFailures, newest last, and the file round-trips.
func TestRecordKeepsTheLast100Failures(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	if err := Record(dir, "a/1", 1, nil, at); err != nil {
		t.Fatal(err)
	}
	for i := range 105 {
		if err := Record(dir, fmt.Sprintf("a/%d", i+2), uint64(i+2), []Failure{{Check: "sha256", Detail: "x"}}, at); err != nil {
			t.Fatal(err)
		}
	}
	h, ok, err := Read(dir)
	if err != nil || !ok || h.Passes != 1 || h.FailedAudits != 105 || len(h.Failures) != MaxFailures || h.Failures[MaxFailures-1].CommitSeq != 106 ||
		h.Failures[0].BatchID != "a/7" || h.LastPassAt == nil {
		t.Fatalf("%+v %v %v", h, ok, err)
	}
}
