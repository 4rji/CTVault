package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newGCCmd is ctvault gc (spec §7.8, amendment A5 §9): it retires the files
// of derived table versions that are neither active nor being built, at
// once. update and rebuild do it by themselves 24 hours after a switch.
func newGCCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "gc",
		Short: "Delete the files of derived table versions that are neither active nor being built",
		Long: `Delete the files of derived table versions that are neither active nor being
built, such as certs v1 after an upgrade to v2. Each batch's _DERIVED.json
records the retirement before the files are deleted. update and rebuild do this
by themselves 24 hours after a switch, so that running explore sessions have
time to reload; gc does it now.`,
		Args: usageArgs(cobra.NoArgs),
		RunE: func(c *cobra.Command, _ []string) error {
			ow, err := a.openWriter(c, nil)
			if err != nil {
				return err
			}
			defer ow.close()
			st, err := ow.w.RetireOld(true)
			if err != nil {
				return ingestErr(err)
			}
			if st.Files == 0 {
				fmt.Fprintln(c.OutOrStdout(), "nothing to retire")
			}
			return nil
		},
	}
}
