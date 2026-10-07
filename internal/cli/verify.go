package cli

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/query"
	"github.com/4rji/ctvault/internal/vault"
	"github.com/4rji/ctvault/internal/verify"
)

// newVerifyCmd is ctvault verify (spec §8.7, amendment A5 §1-§2).
func newVerifyCmd(a *app) *cobra.Command {
	var full, quick, asJSON bool
	var asOf uint64
	cmd := &cobra.Command{
		Use:   "verify [--quick | --full]",
		Short: "Check the vault without changing it; exit 5 when damage is found",
		Long: `Check the vault without changing it. --quick (the default) checks the
batch manifests, IDs, vault segments, files' sizes, tables and signed heads
in seconds. --full also hashes every file, decodes every vault record, rebuilds
each log's Merkle tree and re-verifies the signed heads; when no writer holds
the lock it also checks the index. verify takes no lock and never stops
update: it checks the batches committed when it starts.`,
		Args: usageArgs(cobra.NoArgs),
		RunE: func(c *cobra.Command, _ []string) error {
			if full && quick {
				return usagef("verify: --quick and --full exclude each other")
			}
			root, id, err := a.openVault(c)
			if err != nil {
				return err
			}
			uuid, err := vault.ParseUUID(id.VaultUUID)
			if err != nil {
				return exitcode.With(exitcode.Verification, err)
			}
			o := verify.Options{Root: root, VaultDirs: vaultDirs(root, id), VaultUUID: uuid, AsOf: asOf, Full: full}
			if full {
				cfg, err := config.Load(root)
				if err != nil {
					return exitcode.With(exitcode.Usage, err)
				}
				sess, err := query.NewSession(root, diskguard.Guard{Cap: cfg.Disk.MaxUsedFraction, Stat: a.d.Statfs})
				if err != nil {
					return err
				}
				defer sess.Close()
				o.Session = sess
				stages := map[string]func(int, int){}
				o.Progress = func(stage string, done, total int) {
					p, ok := stages[stage]
					if !ok {
						p = progress(c.ErrOrStderr(), "verify: "+stage, "batches", 10*time.Second, a.d.Now)
						stages[stage] = p
					}
					p(done, total)
				}
			}
			rep, err := verify.Run(c.Context(), o)
			switch {
			case errors.Is(err, verify.ErrUsage):
				return exitcode.With(exitcode.Usage, err)
			case err != nil:
				return readErr(err)
			}
			out := c.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(rep); err != nil {
					return err
				}
			} else {
				rep.WriteText(out)
			}
			if rep.Damaged() {
				return exitcode.Withf(exitcode.Verification, "verify found damage; see the report")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&quick, "quick", false, "check manifests and metadata only (the default)")
	cmd.Flags().BoolVar(&full, "full", false, "also hash every file, decode every record, rebuild the Merkle trees and check the index")
	cmd.Flags().Uint64Var(&asOf, "as-of", 0, "check the batches up to this commit_seq (default: all)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "write the report as JSON")
	return cmd
}
