package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/extdecode"
	"github.com/4rji/ctvault/internal/extract"
	"github.com/4rji/ctvault/internal/leaf"
)

func newExplainCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "explain-error <code>",
		Short: "Explain a certificate parse, extension or log entry error code",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(c *cobra.Command, args []string) error {
			code, out := args[0], c.OutOrStdout()
			if e := extract.Code(code).Explain(); e != "" {
				fmt.Fprintf(out, "%s (certificate parse error): %s\n", code, e)
				return nil
			}
			if e := leaf.Code(code).Explain(); e != "" {
				fmt.Fprintf(out, "%s (log entry error): %s\n", code, e)
				return nil
			}
			if e := extdecode.Code(code).Explain(); e != "" {
				fmt.Fprintf(out, "%s (certificate extension error): %s\n", code, e)
				return nil
			}
			return exitcode.Withf(exitcode.Usage, "unknown error code %q", code)
		},
	}
}
