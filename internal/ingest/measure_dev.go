//go:build ctvault_dev || realdata

package ingest

import (
	"fmt"
	"slices"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/merkle"
)

// Seed makes log start at state's size, with state as the compact range
// before it, in a measurement workspace (amendment A1 §2.6): a
// representative sample begins mid-log. The seed is not trusted: every
// batch is still Merkle-verified from it. Vaults always ingest from index 0
// (spec §5.5) and never call Seed: this file is not part of production
// builds, and a workspace whose first batch does not start at 0 cannot be
// reopened, because loading the manifests refuses the gap.
func (w *Writer) Seed(log string, state *merkle.State) error {
	if _, ok := w.tips[log]; ok {
		return fmt.Errorf("seed: log %s already has committed batches", log)
	}
	w.tips[log] = commit.LogTip{Next: state.Size(), State: state.Clone()}
	return nil
}

// Committed returns the committed batches' manifests in commit order.
func (w *Writer) Committed() []commit.Manifest { return slices.Clone(w.committed) }
