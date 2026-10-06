package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/config"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/fetch"
	"github.com/4rji/ctvault/internal/ingest"
	"github.com/4rji/ctvault/internal/lock"
	"github.com/4rji/ctvault/internal/vault"
)

// openedWriter is the vault's single writer, opened under the writer lock.
type openedWriter struct {
	w    *ingest.Writer
	cfg  config.Config
	root string
	lk   *lock.Lock
}

func (o *openedWriter) close() {
	o.w.Close()
	o.lk.Release()
}

// openWriter checks the vault, takes the writer lock, loads ctvault.toml,
// runs before (if any) and opens the writer, which recovers the vault first
// (spec §8.5).
func (a *app) openWriter(c *cobra.Command, before func(root string) error) (*openedWriter, error) {
	root, id, err := a.openVault(c)
	if err != nil {
		return nil, err
	}
	lk, err := a.writerLock(root)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			lk.Release()
		}
	}()
	cfg, err := config.Load(root)
	if err != nil {
		return nil, exitcode.With(exitcode.Usage, err)
	}
	if before != nil {
		if err := before(root); err != nil {
			return nil, err
		}
	}
	uuid, err := vault.ParseUUID(id.VaultUUID)
	if err != nil {
		return nil, exitcode.With(exitcode.Verification, err)
	}
	w, err := ingest.Open(ingest.Options{Root: root, VaultDirs: vaultDirs(root, id), VaultUUID: uuid, Config: cfg,
		Guard: diskguard.Guard{Cap: cfg.Disk.MaxUsedFraction, Stat: a.d.Statfs}, Version: a.d.Version, Now: a.d.Now, Out: c.OutOrStdout(),
		CheckVolumes: func() error {
			_, err := a.d.Volumes.Check(root)
			return err
		},
		Fetch: fetch.Options{Workers: cfg.Ingest.Workers, MaxRPS: cfg.Ingest.MaxRPS, StallTimeout: cfg.Ingest.StallTimeout.Duration,
			MaxBufferedEntries: cfg.Fetch.MaxBufferedEntries, MaxBufferedBytes: int(cfg.Fetch.MaxBufferedBytes)}})
	if err != nil {
		return nil, ingestErr(err)
	}
	ok = true
	return &openedWriter{w: w, cfg: cfg, root: root, lk: lk}, nil
}

// building names the derived tables ACTIVE.json lists as being built.
func building(a derive.Active) []string {
	var out []string
	for name, s := range a.Tables {
		if s.Status == derive.StatusBuilding {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// warnBuilding tells the user that some derived tables are only exposed as
// <table>_building until a rebuild (amendment A2 §5.5).
func warnBuilding(c *cobra.Command, w *ingest.Writer) {
	if b := building(w.Active()); len(b) > 0 {
		fmt.Fprintf(c.ErrOrStderr(), "warning: %s %s being built: run `ctvault rebuild`\n", strings.Join(b, " and "), isAre(len(b)))
	}
}

func isAre(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}
