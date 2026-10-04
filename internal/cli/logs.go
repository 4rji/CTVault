package cli

import (
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/loglist"
	"github.com/4rji/ctvault/internal/logreg"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/merkle"
)

func newLogsCmd(a *app) *cobra.Command {
	src := new(string)
	cmd := groupCmd("logs", "Manage the CT logs this vault follows",
		logsListCmd(a, src), logsAddCmd(a, src), logsInfoCmd(a))
	cmd.PersistentFlags().StringVar(src, "log-list", a.d.LogListSource, "log list URL or file")
	return cmd
}

func logsListCmd(a *app, src *string) *cobra.Command {
	var available bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List pinned logs, or all RFC 6962 logs in the log list with --available",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(c *cobra.Command, _ []string) error {
			root, _, err := a.openVault(c)
			if err != nil {
				return err
			}
			pinned, err := logreg.List(root)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
			defer tw.Flush()
			if !available {
				fmt.Fprintln(tw, "NAME\tSTATE AT PIN\tPINNED AT\tURL")
				for _, r := range pinned {
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.Name, r.State, r.PinnedAt.Format(time.RFC3339), r.URL)
				}
				return nil
			}
			list, err := loglist.Fetch(c.Context(), a.d.HTTP, *src)
			if err != nil {
				return err
			}
			isPinned := map[string]bool{}
			for _, r := range pinned {
				isPinned[r.Name] = true
			}
			fmt.Fprintln(tw, "NAME\tSTATE\tOPERATOR\tPINNED\tURL")
			for _, r := range list.RFC6962Logs() {
				mark := ""
				if isPinned[r.Name] {
					mark = "yes"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.Name, r.Log.CurrentState(), r.Operator, mark, r.Log.URL)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&available, "available", false, "list every RFC 6962 log in the log list")
	return cmd
}

func logsAddCmd(a *app, src *string) *cobra.Command {
	return &cobra.Command{
		Use:   "add <name>",
		Short: "Pin a log from Chrome's log list (for example argon2027h1)",
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
			list, err := loglist.Fetch(c.Context(), a.d.HTTP, *src)
			if err != nil {
				return err
			}
			r, err := list.Find(args[0])
			if err != nil {
				return err
			}
			rec := logreg.FromList(list, r, a.d.Now())
			if err := logreg.Add(root, rec); err != nil {
				return err
			}
			out := c.OutOrStdout()
			fmt.Fprintf(out, "Pinned %s: %s (%s, %s)\n", rec.Name, rec.Description, rec.Operator, rec.State)
			if ti := rec.TemporalInterval; ti != nil {
				fmt.Fprintf(out, "  accepts certificates expiring %s to %s\n", ti.StartInclusive.Format("2006-01-02"), ti.EndExclusive.Format("2006-01-02"))
			}
			fmt.Fprintf(out, "  url     %s\n  log_id  %s\n  from log list %s (%s)\n", rec.URL, rec.LogID, rec.LogListVersion, rec.LogListTimestamp)
			return nil
		},
	}
}

func logsInfoCmd(a *app) *cobra.Command {
	var offline bool
	cmd := &cobra.Command{
		Use:   "info <name>",
		Short: "Show a pinned log and verify its current signed tree head",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(c *cobra.Command, args []string) error {
			root, _, err := a.openVault(c)
			if err != nil {
				return err
			}
			rec, err := logreg.Get(root, args[0])
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			fmt.Fprintf(out, "name       %s\ndescription %s\noperator   %s\nurl        %s\nlog_id     %s\nstate      %s (at pin)\npinned_at  %s\n",
				rec.Name, rec.Description, rec.Operator, rec.URL, rec.LogID, rec.State, rec.PinnedAt.Format(time.RFC3339))
			if offline {
				return nil
			}
			pub, err := rec.PublicKey()
			if err != nil {
				return exitcode.With(exitcode.Verification, fmt.Errorf("pinned record for %s is corrupt: %w", rec.Name, err))
			}
			sth, err := rfc6962.New(rec.URL, a.d.HTTP).GetSTH(c.Context())
			if err != nil {
				return err
			}
			if err := merkle.VerifySTH(pub, sth); err != nil {
				return exitcode.With(exitcode.Verification, fmt.Errorf("signed tree head from %s does not verify with the pinned key: %w", rec.URL, err))
			}
			fmt.Fprintf(out, "tree_size  %d\nsth_time   %s\nroot_hash  %x\nsignature  verified with pinned key\n",
				sth.TreeSize, time.UnixMilli(int64(sth.Timestamp)).UTC().Format(time.RFC3339), sth.RootHash)
			return nil
		},
	}
	cmd.Flags().BoolVar(&offline, "offline", false, "show pinned metadata only; do not contact the log")
	return cmd
}
