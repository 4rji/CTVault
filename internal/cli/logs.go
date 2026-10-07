package cli

import (
	"errors"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/loglist"
	"github.com/4rji/ctvault/internal/logreg"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/sources"
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
		Short: "List pinned logs, or every log in the log list with --available",
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
				fmt.Fprintln(tw, "NAME\tKIND\tSTATE AT PIN\tPINNED AT\tURL")
				for _, r := range pinned {
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.Name, r.LogKind(), r.State, r.PinnedAt.Format(time.RFC3339), r.URL)
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
			fmt.Fprintln(tw, "NAME\tKIND\tSTATE\tOPERATOR\tPINNED\tURL")
			for _, r := range list.All() {
				mark := ""
				if isPinned[r.Name] {
					mark = "yes"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Name, r.Kind, r.Log.CurrentState(), r.Operator, mark, r.Log.URL)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&available, "available", false, "list every log in the log list, RFC 6962 and tiled")
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
			if rec.LogKind() == loglist.KindTiled {
				fmt.Fprintf(out, "  kind    tiled (static-ct-api)\n  url     %s (monitoring)\n  origin  %s\n", rec.URL, rec.Origin)
			} else {
				fmt.Fprintf(out, "  kind    rfc6962\n  url     %s\n", rec.URL)
			}
			fmt.Fprintf(out, "  log_id  %s\n  from log list %s (%s)\n", rec.LogID, rec.LogListVersion, rec.LogListTimestamp)
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
			fmt.Fprintf(out, "name       %s\nkind       %s\ndescription %s\noperator   %s\nurl        %s\n",
				rec.Name, rec.LogKind(), rec.Description, rec.Operator, rec.URL)
			if rec.LogKind() == loglist.KindTiled {
				fmt.Fprintf(out, "submission %s\norigin     %s\n", rec.SubmissionURL, rec.Origin)
			}
			fmt.Fprintf(out, "log_id     %s\nstate      %s (at pin)\npinned_at  %s\n", rec.LogID, rec.State, rec.PinnedAt.Format(time.RFC3339))
			if offline {
				return nil
			}
			info, err := logsource.InfoFromRecord(rec)
			if err != nil {
				return exitcode.With(exitcode.Verification, fmt.Errorf("pinned record for %s is corrupt: %w", rec.Name, err))
			}
			// get-sth or the checkpoint, by the log's kind (amendment A6 §1).
			src, err := sources.Open(info, a.d.HTTP, logsource.NewChainCache(1), nil)
			if err != nil {
				return err
			}
			sth, err := src.Head(c.Context())
			if errors.Is(err, merkle.ErrBadSignature) {
				return exitcode.With(exitcode.Verification, fmt.Errorf("signed tree head from %s does not verify with the pinned key: %w", rec.URL, err))
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "tree_size  %d\nsth_time   %s\nroot_hash  %x\nsignature  verified with pinned key\n",
				sth.TreeSize, time.UnixMilli(int64(sth.Timestamp)).UTC().Format(time.RFC3339), sth.RootHash)
			return nil
		},
	}
	cmd.Flags().BoolVar(&offline, "offline", false, "show pinned metadata only; do not contact the log")
	return cmd
}
