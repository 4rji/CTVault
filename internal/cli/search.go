package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/query"
)

// searchFlags are search's query flags; query builds the same Query that
// explore's bar does (amendment A4 §2.1).
type searchFlags struct {
	q                                                         query.Query
	suffix, exact, ip, contains, regex, since, until, validAt string
	by                                                        string
	kinds, fields                                             []string
}

func (sf *searchFlags) query(args []string) (query.Query, error) {
	q := sf.q
	modes := map[query.Mode]string{query.ModeSuffix: sf.suffix, query.ModeExact: sf.exact, query.ModeIP: sf.ip,
		query.ModeContains: sf.contains, query.ModeRegex: sf.regex}
	if len(args) == 1 {
		modes[query.ModeDomain] = args[0]
	}
	set := 0
	for m, v := range modes {
		if v != "" {
			q.Mode, q.Text = m, v
			set++
		}
	}
	if set != 1 {
		return q, usagef("search: give exactly one of <domain>, --suffix, --exact, --ip, --contains or --regex")
	}
	for _, p := range []struct {
		in  string
		out **time.Time
		fl  string
	}{{sf.since, &q.Since, "--since"}, {sf.until, &q.Until, "--until"}, {sf.validAt, &q.ValidAt, "--valid-at"}} {
		if p.in == "" {
			continue
		}
		t, err := query.ParseWhen(p.in)
		if err != nil {
			return q, usagef("search: %s %q: use YYYY, YYYY-MM, YYYY-MM-DD or RFC 3339", p.fl, p.in)
		}
		*p.out = &t
	}
	switch sf.by {
	case "ct-ts":
	case "not-before":
		q.ByNotBefore = true
	default:
		return q, usagef("search: --by %q (ct-ts or not-before)", sf.by)
	}
	q.Kinds, q.Fields = splitList(sf.kinds), splitList(sf.fields)
	return q, nil
}

// newSearchCmd is ctvault search (spec §11.3, amendment A3 §3, §5).
func newSearchCmd(a *app) *cobra.Command {
	cmd, _ := newSearchCommand(a)
	return cmd
}

func newSearchCommand(a *app) (*cobra.Command, *searchFlags) {
	sf := &searchFlags{}
	var format, output string
	var force bool
	cmd := &cobra.Command{
		Use:   "search [<domain>] [--suffix N | --exact N | --ip A | --contains S | --regex R] [filters]",
		Short: "Search names, certificates and issuances in the committed snapshot",
		Args:  usageArgs(cobra.MaximumNArgs(1)),
		RunE: func(c *cobra.Command, args []string) error {
			q, err := sf.query(args)
			if err != nil {
				return err
			}
			if !map[string]bool{"table": true, "md": true, "json": true, "csv": true}[format] {
				return usagef("search: unknown format %q (table, md, json or csv)", format)
			}
			if output != "" && format == "table" {
				return usagef("search: --output needs --format md, json or csv")
			}
			if !c.Flags().Changed("limit") && format == "table" && output == "" {
				q.Limit = 100
			}
			r, err := a.openReader(c, q.AsOf)
			if err != nil {
				return err
			}
			defer r.close()
			if q.FullScan() {
				fmt.Fprintln(c.ErrOrStderr(), "warning: --contains and --regex do a full scan of every names file; this is slow on a large vault")
			}
			if output != "" {
				err := query.Export(c.Context(), r.snap, r.sess, r.dirs, q, query.ExportOptions{Path: output, Format: format, Force: force,
					Version: a.d.Version, Now: a.d.Now})
				if err != nil {
					return searchErr(err)
				}
				fmt.Fprintf(c.OutOrStdout(), "wrote %s (as of commit_seq %d)\n", output, r.snap.AsOf)
				return nil
			}
			return searchErr(printSearch(c, a, r, q, format))
		},
	}
	q := &sf.q
	f := cmd.Flags()
	f.StringVar(&sf.suffix, "suffix", "", "a name and every name under it")
	f.StringVar(&sf.exact, "exact", "", "exactly this name")
	f.StringVar(&sf.ip, "ip", "", "an IP address (SAN or CN)")
	f.StringVar(&sf.contains, "contains", "", "names containing this text, any case (full scan)")
	f.StringVar(&sf.regex, "regex", "", "names matching this RE2 expression (full scan)")
	f.StringVar(&q.Issuer, "issuer", "", "the issuer's CN, exact, any case")
	f.StringVar(&q.IssuerOrg, "issuer-org", "", "the issuer's O, exact, any case")
	f.StringVar(&q.IssuedBy, "issued-by", "", "certificates issued by this CA certificate (SHA-256 or cert_id)")
	f.StringVar(&q.KeyAlg, "key-alg", "", "rsa, ecdsa, ed25519, ed448, dsa or other")
	f.StringSliceVar(&sf.kinds, "kind", nil, "precert, final, chain (default precert,final)")
	f.StringVar(&q.ParseStatus, "parse-status", "", "ok, partial or failed")
	f.StringVar(&sf.validAt, "valid-at", "", "certificates valid at this time")
	f.BoolVar(&q.Wildcard, "wildcard", false, "wildcard names only")
	f.StringVar(&q.Log, "log", "", "entries of this log only")
	f.StringVar(&sf.since, "since", "", "from this time (inclusive)")
	f.StringVar(&sf.until, "until", "", "before this time (exclusive)")
	f.StringVar(&sf.by, "by", "ct-ts", "the time --since and --until compare: ct-ts or not-before")
	f.StringVar(&q.Group, "group", "names", "names, certs or issuances")
	f.StringVar(&q.Sort, "sort", "", "a column, then asc or desc")
	f.StringSliceVar(&sf.fields, "fields", nil, "the columns to show, in order")
	f.IntVar(&q.Limit, "limit", 0, "at most this many rows (0: all; a terminal table shows 100 by default)")
	f.StringVar(&format, "format", "table", "table, md, json or csv")
	f.StringVar(&output, "output", "", "export to this file, with the metadata that reproduces it")
	f.BoolVar(&force, "force", false, "replace an existing --output file")
	f.Uint64Var(&q.AsOf, "as-of", 0, "search the committed snapshot as of this commit_seq")
	return cmd, sf
}

func splitList(in []string) []string {
	var out []string
	for _, s := range in {
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

// printSearch writes the result to stdout. JSON carries the metadata after
// the rows, so it streams; the other formats print a summary on stderr.
func printSearch(c *cobra.Command, a *app, r *reader, q query.Query, format string) error {
	out := c.OutOrStdout()
	var cols []string
	rows := 0
	if format == "json" {
		io.WriteString(out, "{\"rows\": [\n")
	}
	rw := query.NewRowWriter(format, out)
	err := query.SearchEach(c.Context(), r.snap, r.sess, r.dirs, &q, func(cs []string, row []any) error {
		if cols == nil {
			cols = cs
			if err := rw.Header(cs); err != nil {
				return err
			}
		}
		rows++
		return rw.Row(row)
	})
	if err != nil {
		return err
	}
	if cols == nil {
		cols = q.Columns()
		if err := rw.Header(cols); err != nil {
			return err
		}
	}
	if err := rw.End(); err != nil {
		return err
	}
	if format == "json" {
		meta := query.NewMeta(r.snap, q, a.d.Version, a.d.Now(), rows)
		b, err := json.MarshalIndent(meta, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "\n],\n\"meta\": %s}\n", b)
		return nil
	}
	note := ""
	if q.Limit > 0 && rows == q.Limit {
		note = fmt.Sprintf(" (the first %d; --limit 0 shows all)", q.Limit)
	}
	fmt.Fprintf(c.ErrOrStderr(), "%d rows%s · as of commit_seq %d\n", rows, note, r.snap.AsOf)
	return nil
}

func searchErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, query.ErrUsage):
		return exitcode.With(exitcode.Usage, err)
	case errors.Is(err, os.ErrExist):
		return exitcode.With(exitcode.Error, err)
	}
	return readErr(err)
}
