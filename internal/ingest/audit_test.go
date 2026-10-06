package ingest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/health"
)

// TestPostCommitAudit: after every commit the writer looks the batch up
// through the read path and records the result in state/health.json
// (amendment A3 §6).
func TestPostCommitAudit(t *testing.T) {
	h := newHarness(t, entries(t, 60), ctlogtest.Options{})
	w := h.open()
	h.ingest(w, h.head(), 0, 60, 20)
	w.Close()
	hs, ok, err := health.Read(filepath.Join(h.root, "state"))
	if err != nil || !ok || hs.Passes != 3 || len(hs.Failures) != 0 || hs.LastPassAt == nil {
		t.Fatalf("health after 3 clean batches: %+v %v %v", hs, ok, err)
	}
}

// TestPostCommitAuditFailure: a failed audit is recorded and reported, and
// the batch stays committed.
func TestPostCommitAuditFailure(t *testing.T) {
	h := newHarness(t, entries(t, 20), ctlogtest.Options{})
	h.opts.Hook = func(p string) {
		if p != HookDuringAudit {
			return
		}
		// Make the batch's names unreadable to the audit's name lookups.
		ms, _ := commit.ListCommitted(h.root)
		names := filepath.Join(commit.Paths{Root: h.root}.BatchDir(ms[0].ID()), derive.NamesV1.File())
		os.WriteFile(names, []byte("not parquet"), 0o644)
	}
	w := h.open()
	ms := h.ingest(w, h.head(), 0, 20, 20)
	w.Close()
	if len(ms) != 1 || ms[0].CommitSeq != 1 {
		t.Fatal("the batch was not committed")
	}
	hs, _, err := health.Read(filepath.Join(h.root, "state"))
	if err != nil || hs.Passes != 0 || len(hs.Failures) == 0 || hs.Failures[0].BatchID != ms[0].BatchID || hs.Failures[0].Check != "name" {
		t.Fatalf("health after a failed audit: %+v %v", hs, err)
	}
	if !strings.Contains(h.out.String(), "post-commit audit") {
		t.Fatalf("no warning in the output:\n%s", h.out.String())
	}
}

// TestPostCommitAuditOff: ingest.post_commit_audit = false writes no health
// record.
func TestPostCommitAuditOff(t *testing.T) {
	h := newHarness(t, entries(t, 20), ctlogtest.Options{})
	h.opts.Config.Ingest.PostCommitAudit = false
	w := h.open()
	h.ingest(w, h.head(), 0, 20, 20)
	w.Close()
	if _, ok, _ := health.Read(filepath.Join(h.root, "state")); ok {
		t.Fatal("an audit ran while turned off")
	}
}
