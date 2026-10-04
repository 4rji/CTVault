package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/volume"
)

func newInitCmd(a *app) *cobra.Command {
	var allowUntested bool
	cmd := &cobra.Command{
		Use:   "init <root>",
		Short: "Create a vault on a dedicated, mounted ext4 volume",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(c *cobra.Command, args []string) error {
			id, err := a.d.Volumes.Init(args[0], volume.InitOptions{AllowUntestedFS: allowUntested})
			if err != nil {
				return volumeErr(err)
			}
			if err := config.WriteDefault(args[0]); err != nil {
				return err
			}
			r := id.Volumes[0]
			fmt.Fprintf(c.OutOrStdout(), "Initialized CTVault %s at %s (%s, filesystem %s, durability %s)\n",
				id.VaultUUID, r.Path, r.FSType, r.FSUUID, id.Durability)
			fmt.Fprintf(c.OutOrStdout(), "Next: ctvault --root %s logs add argon2027h1\n", r.Path)
			return nil
		},
	}
	cmd.Flags().BoolVar(&allowUntested, "allow-untested-fs", false, "accept xfs, btrfs or f2fs with weaker durability guarantees")
	return cmd
}

func newVaultCmd(a *app) *cobra.Command {
	var allowUntested bool
	addDir := &cobra.Command{
		Use:   "add-dir <path>",
		Short: "Add a vault directory on another disk",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(c *cobra.Command, args []string) error {
			root, _, err := a.openVault(c)
			if err != nil {
				return err
			}
			lk, err := a.writerLock(root)
			if err != nil {
				return err
			}
			defer lk.Release()
			id, err := a.d.Volumes.AddDir(root, args[0], volume.InitOptions{AllowUntestedFS: allowUntested})
			if err != nil {
				return volumeErr(err)
			}
			v := id.Volumes[len(id.Volumes)-1]
			fmt.Fprintf(c.OutOrStdout(), "Added vault dir %s (%s, filesystem %s)\n", v.Path, v.FSType, v.FSUUID)
			return nil
		},
	}
	addDir.Flags().BoolVar(&allowUntested, "allow-untested-fs", false, "accept xfs, btrfs or f2fs with weaker durability guarantees")
	return groupCmd("vault", "Manage vault volumes", addDir)
}
