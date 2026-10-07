package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/query"
)

var sha256Arg = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

var fetchFormats = map[string]bool{"pem": true, "der": true, "text": true, "json": true}

// newFetchCmd is ctvault fetch (spec §11.5, amendment A3 §4).
func newFetchCmd(a *app) *cobra.Command {
	var format string
	var withChain, withEntries, force bool
	var asOf uint64
	var mixed query.MixedRead
	var output string
	cmd := &cobra.Command{
		Use:   "fetch <sha256 | cert_id> [--format pem|der|text|json] [--with-chain] [--with-entries]",
		Short: "Print a certificate from the vault, verified against its SHA-256",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(c *cobra.Command, args []string) error {
			if !fetchFormats[format] {
				return usagef("fetch: unknown format %q (pem, der, text or json)", format)
			}
			if format == "der" && (withChain || withEntries) {
				return usagef("fetch: --format der holds one certificate; use pem or json with --with-chain")
			}
			if withEntries && format == "pem" {
				return usagef("fetch: --with-entries needs --format text or json")
			}
			out := c.OutOrStdout()
			if format == "der" && output == "" && isTerminal(out) {
				return usagef("fetch: refusing to write DER to a terminal; use --output")
			}
			if output != "" && !force {
				if _, err := os.Stat(output); err == nil {
					return exitcode.Withf(exitcode.Error, "fetch: %s exists (use --force to replace it)", output)
				}
			}
			arg := args[0]
			var id uint64
			isSHA := sha256Arg.MatchString(arg)
			if !isSHA {
				n, err := strconv.ParseUint(arg, 10, 64)
				if err != nil {
					return usagef("fetch: %q is neither a SHA-256 (64 hex digits) nor a cert_id", arg)
				}
				id = n
			}
			r, err := a.openReader(c, asOf, mixed)
			if err != nil {
				return err
			}
			defer r.close()
			f, err := query.NewFetcher(r.snap, r.sess, r.dirs)
			if err != nil {
				return readErr(err)
			}
			defer f.Close()
			ctx := c.Context()
			var cert *query.Cert
			if isSHA {
				var sha [32]byte
				b, _ := hex.DecodeString(strings.ToLower(arg))
				copy(sha[:], b)
				cert, err = f.BySHA256(ctx, sha)
			} else {
				cert, err = f.ByCertID(ctx, id)
			}
			if err != nil {
				return readErr(fmt.Errorf("%s: %w", arg, err))
			}
			var chains [][]*query.Cert
			if withChain {
				if chains, err = fetchChains(ctx, f, cert.CertID); err != nil {
					return readErr(err)
				}
			}
			var entries []query.Entry
			if withEntries {
				if entries, err = f.Entries(ctx, cert.CertID); err != nil {
					return readErr(err)
				}
			}
			if output == "" {
				return writeFetched(ctx, out, f, format, cert, chains, entries, r.snap.AsOf)
			}
			var buf bytes.Buffer
			if err := writeFetched(ctx, &buf, f, format, cert, chains, entries, r.snap.AsOf); err != nil {
				return err
			}
			return fsutil.WriteFileAtomic(output, buf.Bytes(), 0o644)
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&format, "format", "pem", "pem, der, text or json")
	fl.BoolVar(&withChain, "with-chain", false, "also print every distinct chain the log served with it")
	fl.BoolVar(&withEntries, "with-entries", false, "list the log entries that reference it (scans every batch's entries)")
	fl.Uint64Var(&asOf, "as-of", 0, "read the committed snapshot as of this commit_seq")
	fl.StringVar(&output, "output", "", "write to this file instead of stdout (atomically)")
	fl.BoolVar(&force, "force", false, "replace an existing --output file")
	mixedFlags(cmd, &mixed)
	return cmd
}

func fetchChains(ctx context.Context, f *query.Fetcher, certID uint64) ([][]*query.Cert, error) {
	ids, err := f.Chains(ctx, certID)
	if err != nil {
		return nil, err
	}
	var out [][]*query.Cert
	for _, chain := range ids {
		var cs []*query.Cert
		for _, id := range chain {
			c, err := f.ByCertID(ctx, id)
			if err != nil {
				return nil, err
			}
			cs = append(cs, c)
		}
		out = append(out, cs)
	}
	return out, nil
}

func writeFetched(ctx context.Context, w io.Writer, f *query.Fetcher, format string, cert *query.Cert, chains [][]*query.Cert, entries []query.Entry, asOf uint64) error {
	switch format {
	case "der":
		_, err := w.Write(cert.DER)
		return err
	case "pem":
		if err := pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: cert.DER}); err != nil {
			return err
		}
		for i, chain := range chains {
			fmt.Fprintf(w, "# chain %d of %d\n", i+1, len(chains))
			for _, c := range chain {
				if err := pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: c.DER}); err != nil {
					return err
				}
			}
		}
		return nil
	case "text":
		fmt.Fprint(w, query.Dump(cert))
		for i, chain := range chains {
			for j, c := range chain {
				fmt.Fprintf(w, "\n# chain %d of %d, position %d\n", i+1, len(chains), j)
				fmt.Fprint(w, query.Dump(c))
			}
		}
		for _, e := range entries {
			fmt.Fprintf(w, "%-11s %s #%d at %s (%s)\n", "entry:", e.Log, e.Idx, e.CTTime.Format(time.RFC3339), e.EntryType)
		}
		return nil
	}
	names, err := f.Names(ctx, cert)
	if err != nil {
		return err
	}
	doc := map[string]any{"as_of_commit_seq": asOf}
	for k, v := range certJSON(cert) {
		doc[k] = v
	}
	doc["names"] = jsonRows(names)
	if chains != nil {
		var cs [][]map[string]any
		for _, chain := range chains {
			var one []map[string]any
			for _, c := range chain {
				one = append(one, certJSON(c))
			}
			cs = append(cs, one)
		}
		doc["chains"] = cs
	}
	if entries != nil {
		doc["entries"] = entries
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func certJSON(c *query.Cert) map[string]any {
	return map[string]any{"cert_id": c.CertID, "sha256": hex.EncodeToString(c.SHA256[:]), "kind": c.Row["kind"], "batch": c.Batch,
		"certs": jsonValue(c.Row), "vault": map[string]any{"segment": c.Loc.Segment, "offset": c.Loc.Offset, "length": c.Loc.Len},
		"der_base64": c.DER}
}

// jsonValue makes a DuckDB value JSON-friendly: times in RFC 3339 UTC.
func jsonValue(v any) any {
	switch x := v.(type) {
	case time.Time:
		return x.UTC().Format(time.RFC3339)
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			out[k] = jsonValue(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = jsonValue(e)
		}
		return out
	}
	return v
}

func jsonRows(rows []map[string]any) []any {
	out := make([]any, len(rows))
	for i, r := range rows {
		out[i] = jsonValue(r)
	}
	return out
}
