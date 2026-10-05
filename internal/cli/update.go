package cli

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/fsutil"
	"github.com/4rji/ctvault/internal/ingest"
	"github.com/4rji/ctvault/internal/logreg"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/merkle"
	"github.com/4rji/ctvault/internal/stop"
	"github.com/4rji/ctvault/internal/vault"
	"github.com/4rji/ctvault/internal/volume"
)

// headRetryDelay is how long update waits before refetching a signed head
// that failed its checks (spec §12: refetch once). A lagging frontend gets
// time to catch up. Tests shorten it.
var headRetryDelay = 5 * time.Second

// updateRun is one invocation of update. Build-tagged files may add flags
// and replace the log source (the dev build's --replay).
type updateRun struct {
	a        *app
	follow   bool
	until    uint64
	untilSet bool
	logName  string
	// source opens a log; maxEnd > 0 bounds what it can serve.
	source func(c *cobra.Command, info logsource.LogInfo, chains *logsource.ChainCache, last *logsource.SignedHead) (src logsource.LogSource, maxEnd uint64, closeFn func(), err error)
	// prepare runs before anything else, check once config and the log's
	// position are known (the dev build's replay rules); both nil in
	// production.
	prepare func(c *cobra.Command) error
	check   func(cfg config.Config, next uint64) error
}

// updateHooks let build-tagged files extend update; production has none.
var updateHooks []func(*cobra.Command, *updateRun)

func newUpdateCmd(a *app) *cobra.Command {
	u := &updateRun{a: a}
	u.source = func(_ *cobra.Command, info logsource.LogInfo, chains *logsource.ChainCache, last *logsource.SignedHead) (logsource.LogSource, uint64, func(), error) {
		return rfc6962.NewSource(info, a.d.HTTP, chains, last), 0, func() {}, nil
	}
	cmd := &cobra.Command{
		Use:     "update [--follow] [--until N] [--log NAME]",
		Aliases: []string{"ingest"},
		Short:   "Ingest pinned logs up to their current signed tree head",
		Args:    usageArgs(cobra.NoArgs),
		RunE: func(c *cobra.Command, _ []string) error {
			u.untilSet = c.Flags().Changed("until")
			return u.run(c)
		},
	}
	f := cmd.Flags()
	f.BoolVar(&u.follow, "follow", false, "keep ingesting, one cycle every ingest.follow_interval")
	f.Uint64Var(&u.until, "until", 0, "stop at index N (exclusive); never changes the stored head")
	f.StringVar(&u.logName, "log", "", "ingest only this pinned log")
	for _, h := range updateHooks {
		h(cmd, u)
	}
	return cmd
}

func (u *updateRun) run(c *cobra.Command) error {
	a := u.a
	if u.prepare != nil {
		if err := u.prepare(c); err != nil {
			return err
		}
	}
	root, id, err := a.openVault(c)
	if err != nil {
		return err
	}
	lk, err := a.writerLock(root)
	if err != nil {
		return err
	}
	defer lk.Release()
	cfg, err := config.Load(root)
	if err != nil {
		return exitcode.With(exitcode.Usage, err)
	}
	recs, err := u.logs(root)
	if err != nil {
		return err
	}
	uuid, err := vault.ParseUUID(id.VaultUUID)
	if err != nil {
		return exitcode.With(exitcode.Verification, err)
	}
	out := c.OutOrStdout()
	w, err := ingest.Open(ingest.Options{Root: root, VaultDirs: vaultDirs(root, id), VaultUUID: uuid, Config: cfg,
		Guard: diskguard.Guard{Cap: cfg.Disk.MaxUsedFraction, Stat: a.d.Statfs}, Version: a.d.Version, Now: a.d.Now, Out: out,
		CheckVolumes: func() error {
			_, err := a.d.Volumes.Check(root)
			return err
		},
		Fetch: fetch.Options{Workers: cfg.Ingest.Workers, MaxRPS: cfg.Ingest.MaxRPS, StallTimeout: cfg.Ingest.StallTimeout.Duration,
			MaxBufferedEntries: cfg.Fetch.MaxBufferedEntries, MaxBufferedBytes: int(cfg.Fetch.MaxBufferedBytes)}})
	if err != nil {
		return ingestErr(err)
	}
	defer w.Close()
	stops := stop.OnSignals(c.Context(), func() {
		fmt.Fprintln(c.ErrOrStderr(), "interrupt: finishing the current batch, then stopping; press Ctrl-C again to abandon it")
	}, func() {
		fmt.Fprintln(c.ErrOrStderr(), "interrupt: abandoning the current batch; it will be fetched again next time")
	})
	defer stops.Close()
	for {
		for _, rec := range recs {
			warning, err := afterCycle(u.cycle(c, stops, w, rec, cfg, root), u.follow, stops.Hard.Err() != nil)
			if err != nil {
				return err
			}
			if warning != "" {
				fmt.Fprintln(c.ErrOrStderr(), warning)
			}
			if stops.Soft.Err() != nil {
				fmt.Fprintln(out, "stopped after the last committed batch; run update again to continue")
				return nil
			}
		}
		if !u.follow {
			return nil
		}
		select {
		case <-stops.Soft.Done():
			fmt.Fprintln(out, "stopped between cycles")
			return nil
		case <-time.After(cfg.Ingest.FollowInterval.Duration):
		}
	}
}

// afterCycle decides what update does after a cycle: a nil error goes on;
// under --follow a full disk or a stall is a warning and waits for the next
// cycle; anything else ends the run with its exit code (spec §11.2). A
// writer whose abandon failed always ends the run. After a second interrupt
// an error keeps its own exit code (an incident stays 5), and only an error
// without one becomes "stopped" with exit 1.
func afterCycle(err error, follow, hardStopped bool) (warning string, stop error) {
	switch {
	case err == nil:
		return "", nil
	case errors.Is(err, ingest.ErrAbandonFailed):
		return "", ingestErr(err)
	case hardStopped:
		if coded := ingestErr(err); exitcode.Of(coded) != exitcode.Error {
			return "", coded
		}
		return "", exitcode.Withf(exitcode.Error, "stopped by a second interrupt; the batch in progress was abandoned")
	case follow && errors.Is(err, diskguard.ErrCap):
		return fmt.Sprintf("warning: %v; pausing until the next cycle", err), nil
	case follow && errors.Is(err, fetch.ErrStalled):
		return fmt.Sprintf("warning: %v; retrying next cycle", err), nil
	}
	return "", ingestErr(err)
}

func (u *updateRun) logs(root string) ([]logreg.Record, error) {
	if u.logName != "" {
		r, err := logreg.Get(root, u.logName)
		return []logreg.Record{r}, err
	}
	recs, err := logreg.List(root)
	if err == nil && len(recs) == 0 {
		err = errors.New("no logs are pinned; run: ctvault logs add <name>")
	}
	return recs, err
}

// vaultDirs lists the vault directories recorded in VAULT_ID, absolute.
func vaultDirs(root string, id volume.VaultID) []string {
	var out []string
	for _, v := range id.Volumes {
		if v.Role != volume.RoleVaultDir {
			continue
		}
		p := v.Path
		if !filepath.IsAbs(p) {
			p = filepath.Join(root, p)
		}
		out = append(out, p)
	}
	return out
}

// cycle is one update cycle for one log (spec §5.6, amendment A1 §3).
func (u *updateRun) cycle(c *cobra.Command, stops *stop.Contexts, w *ingest.Writer, rec logreg.Record, cfg config.Config, root string) error {
	out := c.OutOrStdout()
	next := w.Next(rec.Name)
	if u.untilSet && next >= u.until {
		fmt.Fprintf(out, "%s: already at index %d (--until %d); nothing to do\n", rec.Name, next, u.until)
		return nil
	}
	if u.check != nil {
		if err := u.check(cfg, next); err != nil {
			return err
		}
	}
	info, err := logsource.InfoFromRecord(rec)
	if err != nil {
		return exitcode.With(exitcode.Verification, err)
	}
	state := filepath.Join(root, "state")
	last, err := logsource.LoadHead(state, rec.Name, info)
	if err != nil {
		return exitcode.With(exitcode.Verification, err)
	}
	chains := logsource.NewChainCache(logsource.DefaultChainCacheBytes)
	src, maxEnd, closeSrc, err := u.source(c, info, chains, last)
	if err != nil {
		return err
	}
	defer closeSrc()
	head, err := u.head(stops.Hard, src, rec.Name, last, w.Tip(rec.Name), state)
	if err != nil {
		return err
	}
	if err := logsource.SaveHead(state, rec.Name, head, u.a.d.Now()); err != nil {
		return err
	}
	end := head.TreeSize
	if maxEnd > 0 {
		end = min(end, maxEnd)
	}
	if u.untilSet {
		if u.until > end {
			return exitcode.Withf(exitcode.Error, "%s: --until %d is beyond the log, which currently has only %d entries", rec.Name, u.until, end)
		}
		end = u.until
	}
	if next >= end {
		fmt.Fprintf(out, "%s: up to date at index %d (signed tree size %d)\n", rec.Name, next, head.TreeSize)
		return nil
	}
	size := uint64(cfg.Ingest.BatchSize)
	fmt.Fprintf(out, "%s: signed tree size %d verified; ingesting [%d, %d) in batches of up to %d\n", rec.Name, head.TreeSize, next, end, size)
	for first := next; first < end; {
		if stops.Soft.Err() != nil {
			return nil
		}
		last := min(first+size, end)
		_, err := w.Batch(stops.Hard, src, head, first, last)
		chains.Reset()
		if err != nil {
			return err
		}
		first = last
	}
	return nil
}

// head fetches and checks the signed head, against the last accepted head
// (by src) and against the committed tip (checkTip); a bad signature or an
// incident is refetched once after headRetryDelay, then written as an
// incident.
func (u *updateRun) head(ctx context.Context, src logsource.LogSource, log string, last *logsource.SignedHead, tip commit.LogTip, state string) (logsource.SignedHead, error) {
	get := func() (h logsource.SignedHead, err error) {
		err = fetch.Retry(ctx, fetch.Options{}, func(ctx context.Context) (err error) {
			h, err = src.Head(ctx)
			return err
		})
		if err == nil {
			err = checkTip(ctx, src, tip, h)
		}
		return h, err
	}
	h, err := get()
	if err == nil || !(errors.Is(err, logsource.ErrIncident) || errors.Is(err, merkle.ErrBadSignature)) {
		return h, err
	}
	select {
	case <-ctx.Done():
		return h, ctx.Err()
	case <-time.After(headRetryDelay):
	}
	h2, err2 := get()
	if err2 == nil {
		return h2, nil
	}
	dir := filepath.Join(state, "incidents", u.a.d.Now().UTC().Format("20060102T150405Z")+"_"+log+"_head")
	ev := map[string]any{"log": log, "first_error": err.Error(), "second_error": err2.Error(),
		"got_raw": base64.StdEncoding.EncodeToString(h2.Raw)}
	if last != nil {
		ev["last_accepted_raw"] = base64.StdEncoding.EncodeToString(last.Raw)
	}
	if tip.State != nil {
		root, _ := tip.State.Root()
		ev["committed_size"], ev["committed_root"] = tip.Next, hex.EncodeToString(root[:])
	}
	if werr := writeIncident(dir, ev); werr != nil {
		return h2, exitcode.With(exitcode.Verification, fmt.Errorf("%s: %w (the incident could not be written to %s: %v)", log, err2, dir, werr))
	}
	return h2, exitcode.With(exitcode.Verification, fmt.Errorf("%s: %w (incident written to %s)", log, err2, dir))
}

func writeIncident(dir string, ev map[string]any) error {
	b, err := json.MarshalIndent(ev, "", " ")
	if err != nil {
		return err
	}
	if err := fsutil.MkdirAllSync(dir, 0o755); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(dir, "incident.json"), b, 0o644)
}

// checkTip refuses a signed head that contradicts what is committed: fewer
// entries than the committed checkpoint, or a tree that does not extend the
// committed Merkle state (proven by a consistency proof). It runs on every
// head, so a vault without a stored head, or with nothing left to ingest,
// is still protected.
func checkTip(ctx context.Context, src logsource.LogSource, tip commit.LogTip, h logsource.SignedHead) error {
	if tip.State == nil {
		return nil
	}
	root, err := tip.State.Root()
	if err != nil {
		return err
	}
	switch {
	case h.TreeSize < tip.Next:
		return fmt.Errorf("%w: the signed head has %d entries, fewer than the %d already committed", logsource.ErrIncident, h.TreeSize, tip.Next)
	case h.TreeSize == tip.Next:
		if root != h.RootHash {
			return fmt.Errorf("%w: the signed head's root differs from the committed tree of %d entries", logsource.ErrIncident, tip.Next)
		}
		return nil
	}
	var proof [][32]byte
	if err := fetch.Retry(ctx, fetch.Options{}, func(ctx context.Context) (err error) {
		proof, err = src.ConsistencyProof(ctx, tip.Next, h.TreeSize)
		return err
	}); err != nil {
		return err
	}
	if err := merkle.VerifyConsistency(tip.Next, h.TreeSize, root, h.RootHash, proof); err != nil {
		return fmt.Errorf("%w: the signed head does not extend the committed tree of %d entries: %v", logsource.ErrIncident, tip.Next, err)
	}
	return nil
}

// ingestErr maps ingestion failures to spec §11.2 exit codes.
func ingestErr(err error) error {
	switch {
	case exitcode.Of(err) != exitcode.Error:
		return err
	case errors.Is(err, diskguard.ErrCap):
		return exitcode.With(exitcode.DiskCap, err)
	case errors.Is(err, volume.ErrVolume):
		return exitcode.With(exitcode.Volume, err)
	case errors.Is(err, ingest.ErrVerification), errors.Is(err, logsource.ErrIncident), errors.Is(err, merkle.ErrBadSignature),
		errors.Is(err, vault.ErrCorrupt), errors.Is(err, commit.ErrCorrupt), errors.Is(err, logsource.ErrBadHeadFile):
		return exitcode.With(exitcode.Verification, err)
	}
	return err
}
