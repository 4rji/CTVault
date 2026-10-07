package cli

import (
	"bytes"
	"testing"
	"time"
)

// TestProgress: a long check reports at most every interval, and always its
// last step.
func TestProgress(t *testing.T) {
	var out bytes.Buffer
	now := time.Unix(0, 0)
	p := progress(&out, "checking the new index", "batches", 10*time.Second, func() time.Time { return now })
	for done := 1; done <= 5; done++ {
		if done == 3 {
			now = now.Add(11 * time.Second)
		}
		p(done, 5)
	}
	want := "checking the new index: 3 of 5 batches\nchecking the new index: 5 of 5 batches\n"
	if out.String() != want {
		t.Fatalf("progress:\n%q\nwant\n%q", out.String(), want)
	}
}
