//go:build ctvault_dev

package cli

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/loglist"
	"github.com/4rji/ctvault/internal/logreg"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/measure"
	"github.com/4rji/ctvault/internal/sample"
	"github.com/4rji/ctvault/internal/stop"
)

func init() { extraCommands = append(extraCommands, newSampleCmd) }

// sampleLimits are amendment A1 §2.1's rules; tests in this package shrink
// them. There is no flag or environment variable for them.
var sampleLimits = sample.DefaultLimits

// sampleTiledLimits are the same rules aligned to tiles, for tiled logs
// (amendment A6 §5); tests shrink them too.
var sampleTiledLimits = sample.TiledLimits

func newSampleCmd(a *app) *cobra.Command {
	return groupCmd("sample", "Capture, verify and measure real-data samples (dev build only)",
		sampleCaptureCmd(a), sampleVerifyCmd(a), sampleMeasureCmd(a))
}

// sampleErr maps sample errors to exit codes: a failed verification is 5, a
// full disk 3.
func sampleErr(err error) error {
	switch {
	case errors.Is(err, sample.ErrCorrupt):
		return exitcode.With(exitcode.Verification, err)
	case errors.Is(err, diskguard.ErrCap):
		return exitcode.With(exitcode.DiskCap, err)
	}
	return err
}

func sampleCaptureCmd(a *app) *cobra.Command {
	var logName, start, suffix, logList string
	var count uint64
	o := config.Default()
	cmd := &cobra.Command{
		Use:   "capture --log <name> --entries N [--start S|head] [--suffix X]",
		Short: "Capture a sample: canonical [0, N) by default, representative with --start",
		Args:  usageArgs(cobra.NoArgs),
		RunE: func(c *cobra.Command, _ []string) error {
			if a.d.DevBase == "" {
				return errors.New("no dev base folder")
			}
			if logName == "" {
				return exitcode.Withf(exitcode.Usage, "--log is required (for example --log argon2027h1)")
			}
			opts := sample.CaptureOptions{Kind: sample.Canonical, Count: count, Suffix: suffix, Limits: sampleLimits,
				Version: a.d.Version, Now: a.d.Now,
				Fetch: fetch.Options{Workers: o.Ingest.Workers, MaxRPS: o.Ingest.MaxRPS, StallTimeout: o.Ingest.StallTimeout.Duration,
					MaxBufferedEntries: o.Fetch.MaxBufferedEntries, MaxBufferedBytes: int(o.Fetch.MaxBufferedBytes)}}
			switch start {
			case "":
			case "head":
				opts.Kind, opts.StartAtHead = sample.Representative, true
			default:
				s, err := strconv.ParseUint(start, 10, 64)
				if err != nil {
					return exitcode.Withf(exitcode.Usage, "--start must be an index or \"head\", got %q", start)
				}
				opts.Kind, opts.Start = sample.Representative, s
			}
			list, err := loglist.Fetch(c.Context(), a.d.HTTP, logList)
			if err != nil {
				return err
			}
			r, err := list.Find(logName)
			if err != nil {
				return err
			}
			rec := logreg.FromList(list, r, a.d.Now())
			info, err := logsource.InfoFromRecord(rec)
			if err != nil {
				return exitcode.With(exitcode.Verification, err)
			}
			tiledLog := info.Kind == loglist.KindTiled
			if tiledLog { // whole tiles (amendment A6 §5)
				opts.Limits = sampleTiledLimits
				if !c.Flags().Changed("entries") {
					count, opts.Count = sampleTiledLimits.Min, sampleTiledLimits.Min
				}
			}
			if err := opts.Limits.Check(opts.Kind, 0, count); err != nil {
				return exitcode.With(exitcode.Usage, err)
			}
			opts.Key, opts.LogListVersion = rec.Key, rec.LogListVersion

			// On a fresh machine the dev base does not exist yet; create the
			// samples folder (inside the base) so the disk check can stat it.
			samples := filepath.Join(a.d.DevBase, "samples")
			if err := fsutil.MkdirAllSync(samples, 0o700); err != nil {
				return err
			}
			guard := diskguard.Guard{Cap: o.Disk.MaxUsedFraction, Stat: a.d.Statfs}
			opts.Check = func(need int64) error { return guard.Check(samples, uint64(need)) }
			errOut := c.ErrOrStderr()
			opts.Progress = func(done, total uint64) { fmt.Fprintf(errOut, "fetched %d / %d entries\n", done, total) }

			stops := stop.OnSignals(c.Context(), func() {
				fmt.Fprintln(errOut, "interrupted: stopping the capture; no sample will be written")
			}, nil)
			defer stops.Close()
			var s *sample.Sample
			if tiledLog {
				s, err = sample.CaptureTiled(stops.Soft, samples, info, a.d.HTTP, opts)
			} else {
				src := rfc6962.NewSource(info, a.d.HTTP, logsource.NewChainCache(logsource.DefaultChainCacheBytes), nil)
				s, err = sample.Capture(stops.Soft, samples, src, opts)
			}
			if err != nil {
				return sampleErr(err)
			}
			printSample(c, s, "captured and verified")
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&logName, "log", "", "log name from Chrome's log list (for example argon2027h1)")
	f.Uint64Var(&count, "entries", 100000, "number of entries (50,000-500,000, a multiple of 5,000; for a tiled log 51,200-512,000, a multiple of 256, default 51,200)")
	f.StringVar(&start, "start", "", "first index of a representative window, or \"head\" for the newest whole window")
	f.StringVar(&suffix, "suffix", "", "folder suffix, to capture an existing range again")
	f.StringVar(&logList, "log-list", a.d.LogListSource, "log list URL or file")
	return cmd
}

func sampleVerifyCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "verify <sample dir>",
		Short: "Verify a sample's checksums, signed head and Merkle proofs",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(c *cobra.Command, args []string) error {
			s, err := sample.Open(args[0])
			if err != nil {
				return sampleErr(err)
			}
			printSample(c, s, "verified")
			return nil
		},
	}
}

func sampleMeasureCmd(a *app) *cobra.Command {
	var batch uint64
	cmd := &cobra.Command{
		Use:   "measure <sample dir> [--batch-size N]",
		Short: "Run a sample through the per-entry pipeline in a throwaway workspace and write a measurement report",
		Args:  usageArgs(cobra.ExactArgs(1)),
		RunE: func(c *cobra.Command, args []string) error {
			if a.d.DevBase == "" {
				return errors.New("no dev base folder")
			}
			if batch == 0 || batch > 500000 {
				return exitcode.Withf(exitcode.Usage, "--batch-size must be 1-500,000, got %d", batch)
			}
			s, err := sample.Open(args[0])
			if err != nil {
				return sampleErr(err)
			}
			errOut := c.ErrOrStderr()
			stops := stop.OnSignals(c.Context(), func() {
				fmt.Fprintln(errOut, "interrupted: stopping the measurement; no report will be written")
			}, nil)
			defer stops.Close()
			r, p, err := measure.Run(stops.Soft, s, measure.Options{Base: a.d.DevBase, Version: a.d.Version, Now: a.d.Now,
				Stat: a.d.Statfs, Out: errOut, BatchSize: batch})
			if err != nil {
				return ingestErr(sampleErr(err))
			}
			out := c.OutOrStdout()
			fmt.Fprint(out, measure.Markdown(r))
			fmt.Fprintf(out, "\nreport: %s\nsummary: %s\n", p.JSON, p.Markdown)
			return nil
		},
	}
	cmd.Flags().Uint64Var(&batch, "batch-size", measure.DefaultBatchSize, "entries per committed batch")
	return cmd
}

func printSample(c *cobra.Command, s *sample.Sample, verb string) {
	m := s.Manifest
	out := c.OutOrStdout()
	entries := m.Files[sample.EntriesFile]
	fmt.Fprintf(out, "%s %s sample %s\n", verb, m.Kind, m.ID(filepath.Base(s.Dir)))
	fmt.Fprintf(out, "  folder     %s\n  entries    [%d, %d) of %s\n  head       tree_size %d, signature verified\n",
		s.Dir, m.Start, m.Start+m.Count, m.Log.Name, m.Head.TreeSize)
	if s.Tiled() { // the files as served (amendment A6 §5)
		var data, hash, issuers int
		var total, dataBytes int64
		for p, f := range m.Files {
			total += f.Bytes
			switch {
			case strings.HasPrefix(p, "tile/data/"):
				data++
				dataBytes += f.Bytes
			case strings.HasPrefix(p, "tile/"):
				hash++
			case strings.HasPrefix(p, "issuer/"):
				issuers++
			}
		}
		fmt.Fprintf(out, "  files      %d data tiles, %d hash tiles, %d issuers\n  page size  %d\n  size       %d bytes (%d B per entry in data tiles)\n",
			data, hash, issuers, m.PageSize, total, dataBytes/int64(m.Count))
		return
	}
	fmt.Fprintf(out, "  proofs     %d consistency", len(s.Proofs.Consistency))
	if s.Proofs.Inclusion != nil {
		fmt.Fprintf(out, ", 1 inclusion")
	}
	fmt.Fprintf(out, "\n  page size  %d\n  size       %d bytes (%d B per entry)\n", m.PageSize, entries.Bytes, entries.Bytes/int64(m.Count))
}
