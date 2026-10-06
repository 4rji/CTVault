// Package health keeps state/health.json, the results of the post-commit
// audit (spec §8.3 P11, amendment A3 §6). A failure never undoes a commit;
// it is recorded here and shown by stats.
package health

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/4rji/ctvault/internal/fsutil"
)

// File is state/health.json.
const File = "health.json"

// MaxFailures is how many failures the file keeps, newest last.
const MaxFailures = 100

// Failure is one failed audit check.
type Failure struct {
	BatchID   string    `json:"batch_id"`
	CommitSeq uint64    `json:"commit_seq"`
	At        time.Time `json:"at"`
	Check     string    `json:"check"` // sha256, name, etld1, cert_id or snapshot
	Detail    string    `json:"detail"`
}

// Health is state/health.json.
type Health struct {
	Format       int        `json:"format"`
	Passes       int        `json:"passes"`        // audits with no failure
	FailedAudits int        `json:"failed_audits"` // audits with at least one failure
	LastPassAt   *time.Time `json:"last_pass_at"`
	Failures     []Failure  `json:"failures"`
}

// Read returns state/health.json; ok is false when there is none.
func Read(stateDir string) (h Health, ok bool, err error) {
	b, err := os.ReadFile(filepath.Join(stateDir, File))
	if errors.Is(err, fs.ErrNotExist) {
		return h, false, nil
	}
	if err != nil {
		return h, false, err
	}
	if err := json.Unmarshal(b, &h); err != nil {
		return h, false, err
	}
	return h, true, nil
}

// Record adds one audit's outcome and rewrites the file atomically. Only
// the writer calls it, under the writer lock. An unreadable file is
// replaced: the record is advisory.
func Record(stateDir, batchID string, seq uint64, failures []Failure, at time.Time) error {
	h, _, err := Read(stateDir)
	if err != nil {
		h = Health{}
	}
	h.Format = 1
	at = at.UTC()
	if len(failures) == 0 {
		h.Passes++
		h.LastPassAt = &at
	} else {
		h.FailedAudits++
		for _, f := range failures {
			f.BatchID, f.CommitSeq, f.At = batchID, seq, at
			h.Failures = append(h.Failures, f)
		}
		if n := len(h.Failures); n > MaxFailures {
			h.Failures = h.Failures[n-MaxFailures:]
		}
	}
	b, err := json.MarshalIndent(h, "", " ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(stateDir, File), append(b, '\n'), 0o644)
}
