package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/index"
	"github.com/4rji/ctvault/internal/ingest"
	"github.com/4rji/ctvault/internal/vault"
)

// newRepairCmd is ctvault repair: --reindex rebuilds the index (amendment
// A2 §5.6, A5 §3.1); --derived rebuilds damaged derived files (A5 §3.2).
// Neither deletes committed data nor rewrites a manifest.
func newRepairCmd(a *app) *cobra.Command {
	var reindex, derived bool
	var batch string
	cmd := &cobra.Command{
		Use:   "repair --reindex | --derived [--batch ID]",
		Short: "Rebuild the index, or damaged derived files, from the vault",
		Long: `Rebuild what the vault can rebuild. --reindex builds a new index beside the
current one and replaces it atomically. --derived rebuilds every certs or
names file that is missing or fails its recorded checksum, and replaces it
only when the rebuilt file reproduces that checksum. Damaged source data
(vault records, entries, chains) cannot be rebuilt: repair names it, and the
batch must be restored from a backup. Run ` + "`ctvault verify --full`" + ` first to see what
is damaged.`,
		Args: usageArgs(cobra.NoArgs),
		RunE: func(c *cobra.Command, _ []string) error {
			switch {
			case reindex == derived:
				return usagef("repair: name what to rebuild: --reindex (the index) or --derived (certs and names files); run `ctvault verify --full` first to see what is damaged")
			case batch != "" && !derived:
				return usagef("repair: --batch goes with --derived")
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
			if derived {
				return a.repairDerived(c, root, dirs, codec, stager, batch)
			}
			rep, err := commit.Reindex(commit.ReindexOptions{Paths: commit.Paths{Root: root}, VaultDirs: dirs, Codec: codec,
				ChainIDs: stager.ChainIDs, Progress: progress(c.ErrOrStderr(), "checking the new index", "batches", 10*time.Second, a.d.Now)})
			if err != nil {
				return ingestErr(err)
			}
			fmt.Fprintf(c.OutOrStdout(), "rebuilt the index from %d batches: %d certificates, %d chains; it replaced the previous index\n",
				rep.Batches, rep.Certs, rep.Chains)
			return nil
		},
	}
	cmd.Flags().BoolVar(&reindex, "reindex", false, "rebuild the Pebble index from the vault and chains.parquet")
	cmd.Flags().BoolVar(&derived, "derived", false, "rebuild certs and names files that are missing or fail their recorded checksum")
	cmd.Flags().StringVar(&batch, "batch", "", "with --derived: only this batch (log/first-last, as verify names it)")
	return cmd
}

// repairDerived is repair --derived, under the writer lock.
func (a *app) repairDerived(c *cobra.Command, root string, dirs []string, codec *vault.Codec, stager *dataset.Stager, batch string) error {
	x, err := index.OpenReadOnly(filepath.Join(root, "state", "pebble"))
	if err != nil {
		return exitcode.Withf(exitcode.Verification, "%v: run `ctvault repair --reindex` first", err)
	}
	defer x.Close()
	rep, err := ingest.RepairDerived(c.Context(), ingest.RepairOptions{Root: root, VaultDirs: dirs, Codec: codec, Stager: stager, Index: x,
		CanarySamples: 64, Batch: batch, Progress: progress(c.ErrOrStderr(), "repair --derived", "batches", 10*time.Second, a.d.Now)})
	switch {
	case errors.Is(err, ingest.ErrUnknownBatch):
		return exitcode.With(exitcode.Usage, err)
	case err != nil:
		return ingestErr(err)
	}
	out := c.OutOrStdout()
	for _, r := range rep.Replaced {
		fmt.Fprintf(out, "replaced %s with a rebuilt copy that matches its recorded checksum\n", r)
	}
	for _, d := range rep.Damaged {
		fmt.Fprintf(out, "cannot repair: %s\n", d)
	}
	fmt.Fprintf(out, "checked %d derived files in %d batches; replaced %d\n", rep.Checked, rep.Batches, len(rep.Replaced))
	if len(rep.Damaged) > 0 {
		return exitcode.Withf(exitcode.Verification, "repair --derived could not repair %d problems; see above", len(rep.Damaged))
	}
	return nil
}
