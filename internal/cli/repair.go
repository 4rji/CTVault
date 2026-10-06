package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/ingest"
	"github.com/4rji/ctvault/internal/vault"
)

// newRepairCmd is ctvault repair. Plan 3 has only --reindex, the minimal
// repair of amendment A2 §5.6; the rest of repair is Plan 6.
func newRepairCmd(a *app) *cobra.Command {
	var reindex bool
	cmd := &cobra.Command{
		Use:   "repair --reindex",
		Short: "Rebuild the index from the vault, beside the current one, and replace it atomically",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(c *cobra.Command, _ []string) error {
			if !reindex {
				return exitcode.Withf(exitcode.Usage, "repair: only --reindex exists in this version")
			}
			root, id, err := a.openVault(c)
			if err != nil {
				return err
			}
			lk, err := a.writerLock(root)
			if err != nil {
				return err
			}
			defer lk.Release()
			dirs := vaultDirs(root, id)
			codec, err := vault.NewCodec()
			if err != nil {
				return err
			}
			defer codec.Close()
			dicts, err := vault.LoadDicts(dirs)
			if err != nil {
				return ingestErr(err)
			}
			for _, d := range dicts {
				if err := codec.AddDict(d.Manifest.ID, d.Content); err != nil {
					return err
				}
			}
			// The writer lock makes the writer's DuckDB folder ours.
			spill := filepath.Join(root, "tmp", ingest.WriterSpillDir)
			if err := os.RemoveAll(spill); err != nil {
				return err
			}
			stager, err := dataset.NewStager(dataset.Options{TempDir: spill, MaxTempBytes: 1 << 30})
			if err != nil {
				return err
			}
			defer func() {
				stager.Close()
				os.RemoveAll(spill)
			}()
			rep, err := commit.Reindex(commit.ReindexOptions{Paths: commit.Paths{Root: root}, VaultDirs: dirs, Codec: codec,
				ChainIDs: stager.ChainIDs})
			if err != nil {
				return ingestErr(err)
			}
			fmt.Fprintf(c.OutOrStdout(), "rebuilt the index from %d batches: %d certificates, %d chains; it replaced the previous index\n",
				rep.Batches, rep.Certs, rep.Chains)
			return nil
		},
	}
	cmd.Flags().BoolVar(&reindex, "reindex", false, "rebuild the Pebble index from the vault and chains.parquet")
	return cmd
}
