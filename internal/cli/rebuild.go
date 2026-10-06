package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// newRebuildCmd is ctvault rebuild (amendment A2 §5.2): it fills in the
// derived tables that are being built from the local vault, then switches
// them to complete. Killed or interrupted, it resumes where it stopped.
func newRebuildCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "rebuild",
		Short: "Build the derived tables that are being built, from the local vault",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(c *cobra.Command, _ []string) error {
			ow, err := a.openWriter(c, nil)
			if err != nil {
				return err
			}
			defer ow.close()
			tables := building(ow.w.Active())
			st, err := ow.w.Rebuild(c.Context())
			if err != nil {
				return ingestErr(err)
			}
			out := c.OutOrStdout()
			if !st.Switched {
				fmt.Fprintln(out, "nothing to rebuild: every derived table is complete")
				return nil
			}
			fmt.Fprintf(out, "rebuilt %d batches; %s %s complete\n", st.Batches, strings.Join(tables, " and "), isAre(len(tables)))
			return nil
		},
	}
}
