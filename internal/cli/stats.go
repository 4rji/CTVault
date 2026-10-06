package cli

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/health"
	"github.com/4rji/ctvault/internal/logreg"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/stats"
)

// newStatsCmd is ctvault stats (spec §11.2, amendment A2 §6). It only
// reads: no writer lock, nothing changes.
func newStatsCmd(a *app) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "stats [--json]",
		Short: "Show ingest progress, estimates, the vault's contents and disk use",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(c *cobra.Command, _ []string) error {
			root, id, err := a.openVault(c)
			if err != nil {
				return err
			}
			cfg, err := config.Load(root)
			if err != nil {
				return exitcode.With(exitcode.Usage, err)
			}
			in, err := statsInput(a, root, vaultDirs(root, id), cfg)
			if err != nil {
				return err
			}
			r := stats.Compute(in)
			if asJSON {
				b, err := json.MarshalIndent(r, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}
			fmt.Fprint(c.OutOrStdout(), stats.Text(r))
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the report as JSON")
	return cmd
}

func statsInput(a *app, root string, dirs []string, cfg config.Config) (stats.Input, error) {
	in := stats.Input{Now: a.d.Now(), Cap: cfg.Disk.MaxUsedFraction}
	state := filepath.Join(root, "state")
	recs, err := logreg.List(root)
	if err != nil {
		return in, err
	}
	for _, rec := range recs {
		info, err := logsource.InfoFromRecord(rec)
		if err != nil {
			return in, exitcode.With(exitcode.Verification, err)
		}
		head, err := logsource.LoadHead(state, rec.Name, info)
		if err != nil {
			return in, exitcode.With(exitcode.Verification, err)
		}
		l := stats.LogInput{Name: rec.Name, State: rec.State, PinnedAt: rec.PinnedAt}
		if head != nil {
			l.Head = &stats.Head{TreeSize: head.TreeSize, Timestamp: time.UnixMilli(int64(head.Timestamp)).UTC()}
		}
		in.Logs = append(in.Logs, l)
	}
	if in.Committed, err = commit.ListCommitted(root); err != nil {
		return in, ingestErr(err)
	}
	if in.Active, _, err = derive.ReadActive(root); err != nil {
		return in, err
	}
	if h, ok, err := health.Read(state); err == nil && ok {
		in.Health = &h
	}
	if es, err := os.ReadDir(filepath.Join(state, "incidents")); err == nil {
		in.Incidents = len(es)
	}
	paths := append([]string{root}, dirs...)
	for i, p := range paths {
		u, err := a.d.Statfs(p)
		if err != nil {
			return in, err
		}
		role := "root"
		if i > 0 {
			role = "vault"
		}
		in.Volumes = append(in.Volumes, stats.Volume{Path: p, Role: role, Usage: u})
	}
	filepath.WalkDir(filepath.Join(state, "pebble"), func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				in.PebbleBytes += uint64(fi.Size())
			}
		}
		return nil
	})
	return in, nil
}
