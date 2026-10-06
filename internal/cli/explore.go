package cli

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/query"
	"github.com/4rji/ctvault/internal/tui"
)

// newExploreCmd is `ctvault explore` (spec §11.4, amendment A4): the
// read-only terminal UI. It takes no lock.
func newExploreCmd(a *app) *cobra.Command {
	var asOf uint64
	cmd := &cobra.Command{
		Use:   "explore [query]",
		Short: "Browse the committed snapshot in a terminal UI (read-only)",
		Long: `Browse the committed snapshot in a terminal UI. The query bar takes search's
syntax: a domain, or suffix:, exact:, ip:, contains: or regex:, then filters
such as issuer:"Let's Encrypt" since:2026-10 kind:final. Press ? for the keys.
The session stays on its commit until R re-pins the latest.`,
		RunE: func(c *cobra.Command, args []string) error {
			in, out := c.InOrStdin(), c.OutOrStdout()
			if !isTerminal(in) || !isTerminal(out) {
				return usagef("explore needs a terminal; use `ctvault search` in scripts and pipes")
			}
			r, err := a.openReader(c, asOf)
			if err != nil {
				return err
			}
			defer r.close()
			m := tui.New(tui.Options{Root: r.root, Dirs: r.dirs, Snapshot: r.snap, Session: r.sess, Query: barArgs(args), Version: a.d.Version, Now: a.d.Now})
			defer m.Close()
			_, err = tea.NewProgram(m, tea.WithContext(c.Context()), tea.WithInput(in), tea.WithOutput(out)).Run()
			return err
		},
	}
	cmd.Flags().Uint64Var(&asOf, "as-of", 0, "browse as of an earlier commit_seq (default: the latest)")
	return cmd
}

// barArgs joins explore's arguments into the bar's text. A key:value
// argument whose value has spaces lost its quotes to the shell, so the
// value is quoted again; any other argument is kept as written, so one
// argument can hold the whole bar.
func barArgs(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = a
		k, v, ok := strings.Cut(a, ":")
		if ok && query.IsBarKey(k) && strings.ContainsAny(v, " \t") && !strings.Contains(v, `"`) {
			out[i] = k + `:"` + strings.ReplaceAll(v, `\`, `\\`) + `"`
		}
	}
	return strings.Join(out, " ")
}
