//go:build ctvault_dev

package cli

import (
	"errors"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/sources"
	"github.com/4rji/ctvault/internal/sample"
)

// DevBatchSize is the dev build's default ingest.batch_size (amendment A1
// §2.5).
const DevBatchSize = 10000

func init() {
	updateHooks = append(updateHooks, addReplay)
	writeConfig = func(root string) error { return config.WriteDefaultBatch(root, DevBatchSize) }
}

// addReplay gives update --replay <canonical sample>: the sample is served
// over loopback and ingested by the unchanged client, fetcher and writer.
func addReplay(cmd *cobra.Command, u *updateRun) {
	var dir string
	var s *sample.Sample
	cmd.Flags().StringVar(&dir, "replay", "", "ingest a cached canonical sample over loopback instead of the live log (dev build only)")
	live := u.source
	u.prepare = func(c *cobra.Command) error {
		if dir == "" {
			return nil
		}
		var err error
		if s, err = sample.Open(dir); err != nil {
			if errors.Is(err, sample.ErrCorrupt) {
				return exitcode.With(exitcode.Verification, err)
			}
			return err
		}
		m := s.Manifest
		if m.Kind != sample.Canonical {
			return exitcode.Withf(exitcode.Usage, "--replay needs a canonical sample; representative samples are for measurements only")
		}
		if u.logName == "" {
			u.logName = m.Log.Name
		} else if u.logName != m.Log.Name {
			return exitcode.Withf(exitcode.Usage, "the sample is of log %s, not %s", m.Log.Name, u.logName)
		}
		if u.untilSet && u.until > m.Start+m.Count {
			return exitcode.Withf(exitcode.Usage, "with --replay, --until must be within the sample's %d entries", m.Count)
		}
		// A tiled sample holds the tiles of a proof from any position in it
		// (amendment A6 §5); an RFC 6962 sample only its boundaries'.
		if u.untilSet && !s.Tiled() && u.until%m.Boundary != 0 {
			return exitcode.Withf(exitcode.Usage, "with --replay, --until must be a multiple of %d within the sample's %d entries", m.Boundary, m.Count)
		}
		return nil
	}
	u.check = func(cfg config.Config, next uint64) error {
		if s == nil || s.Tiled() {
			return nil
		}
		b := s.Manifest.Boundary
		if uint64(cfg.Ingest.BatchSize)%b != 0 || next%b != 0 {
			return exitcode.Withf(exitcode.Usage, "with --replay, ingest.batch_size (%d) and the vault's position (%d) must be multiples of %d: the sample has proofs only there", cfg.Ingest.BatchSize, next, b)
		}
		return nil
	}
	u.source = func(c *cobra.Command, info logsource.LogInfo, chains *logsource.ChainCache, last *logsource.SignedHead) (logsource.LogSource, uint64, func(), error) {
		if s == nil {
			return live(c, info, chains, last)
		}
		if s.LogIDBytes() != info.LogID {
			return nil, 0, nil, exitcode.Withf(exitcode.Usage, "the sample's log ID differs from the pinned log %s", info.Name)
		}
		if si := s.LogInfo(""); si.Kind != info.Kind || si.Origin != info.Origin {
			return nil, 0, nil, exitcode.Withf(exitcode.Usage, "the sample is of a %s log (origin %q), but %s is pinned as %s (origin %q)",
				si.Kind, si.Origin, info.Name, info.Kind, info.Origin)
		}
		url, stopFn, err := sample.Serve(c.Context(), s)
		if err != nil {
			return nil, 0, nil, err
		}
		info.URL = url
		src, err := sources.Open(info, &http.Client{Timeout: 60 * time.Second}, chains, last)
		if err != nil {
			stopFn()
			return nil, 0, nil, err
		}
		return src, s.Manifest.Start + s.Manifest.Count, stopFn, nil
	}
}
