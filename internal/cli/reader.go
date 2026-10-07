package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/query"
	"github.com/4rji/ctvault/internal/vault"
)

// reader is a read command's snapshot and DuckDB session. Readers take no
// lock and never write outside tmp/duckdb-<pid>/ and the outputs the user
// names (amendment A3 §2).
type reader struct {
	root string
	dirs []string
	cfg  config.Config
	snap *query.Snapshot
	sess *query.Session
}

func (a *app) openReader(c *cobra.Command, asOf uint64, mixed query.MixedRead) (*reader, error) {
	if mixed.ParserVersion != 0 && mixed.Allow {
		return nil, usagef("--parser-version and --allow-mixed exclude each other")
	}
	root, id, err := a.openVault(c)
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(root)
	if err != nil {
		return nil, exitcode.With(exitcode.Usage, err)
	}
	snap, err := query.Open(root, asOf)
	if err != nil {
		return nil, readErr(err)
	}
	snap.Mixed = mixed
	for _, n := range snap.MixedNotes() {
		fmt.Fprintln(c.ErrOrStderr(), "note: "+n)
	}
	sess, err := query.NewSession(root, diskguard.Guard{Cap: cfg.Disk.MaxUsedFraction, Stat: a.d.Statfs})
	if err != nil {
		return nil, err
	}
	return &reader{root: root, dirs: vaultDirs(root, id), cfg: cfg, snap: snap, sess: sess}, nil
}

func (r *reader) close() { r.sess.Close() }

// readErr maps read-path errors to exit codes: corruption is 5, everything
// else keeps ingestErr's mapping or 1.
func readErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, vault.ErrCorrupt), errors.Is(err, commit.ErrCorrupt):
		return exitcode.With(exitcode.Verification, err)
	case errors.Is(err, query.ErrMixed):
		return exitcode.With(exitcode.Usage, err)
	}
	return ingestErr(err)
}

// mixedFlags are --parser-version and --allow-mixed, for readers of a
// mixed table (amendment A5 §10).
func mixedFlags(cmd *cobra.Command, m *query.MixedRead) {
	cmd.Flags().IntVar(&m.ParserVersion, "parser-version", 0, "read only the batches at this version of a mixed table (a partial result)")
	cmd.Flags().BoolVar(&m.Allow, "allow-mixed", false, "read each batch's own version of a mixed table")
}

// isTerminal reports whether w is a terminal, where binary output is refused.
func isTerminal(w any) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func usagef(format string, args ...any) error {
	return exitcode.Withf(exitcode.Usage, format, args...)
}
