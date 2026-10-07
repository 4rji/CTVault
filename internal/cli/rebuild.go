package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// newRebuildCmd is ctvault rebuild (amendment A2 §5.2, A5 §8, §10): it
// builds every table version being built from the local vault, all at once,
// then switches them; with --in-place it first turns the pending upgrades
// into in-place conversions. Killed or interrupted, it resumes where it
// stopped.
func newRebuildCmd(a *app) *cobra.Command {
	var inPlace bool
	cmd := &cobra.Command{
		Use:   "rebuild [--in-place]",
		Short: "Build the derived table versions that are being built, from the local vault",
		Long: `Build the derived table versions that are being built, from the local vault,
all at once (update builds them in turns), then switch to them. --in-place
replaces each batch's old version as it goes, when the disk cannot hold both:
the table is mixed meanwhile, and readers need --parser-version or
--allow-mixed until it is complete.`,
		Args: usageArgs(cobra.NoArgs),
		RunE: func(c *cobra.Command, _ []string) error {
			ow, err := a.openWriter(c, nil)
			if err != nil {
				return err
			}
			defer ow.close()
			if inPlace {
				if err := ow.w.StartInPlace(); err != nil {
					return ingestErr(err)
				}
			} else {
				for _, x := range ow.w.Warnings() {
					fmt.Fprintln(c.ErrOrStderr(), "warning: "+x)
				}
			}
			var tables []string
			for _, u := range ow.w.Upgrades() {
				tables = append(tables, u.Table)
			}
			st, err := ow.w.Rebuild(c.Context())
			if err != nil {
				return ingestErr(err)
			}
			out := c.OutOrStdout()
			if !st.Switched {
				fmt.Fprintln(out, "nothing to rebuild: every derived table is complete")
				return nil
			}
			fmt.Fprintf(out, "rebuilt %d batches; %s %s complete\n", st.Batches, andList(tables), isAre(len(tables)))
			return nil
		},
	}
	cmd.Flags().BoolVar(&inPlace, "in-place", false, "replace each batch's old version as it goes, when the disk cannot hold both")
	return cmd
}

// andList joins words as a sentence does: "a", "a and b", "a, b and c".
func andList(w []string) string {
	if len(w) <= 1 {
		return strings.Join(w, "")
	}
	return strings.Join(w[:len(w)-1], ", ") + " and " + w[len(w)-1]
}
