// Package cli implements the ctvault command line. Every dependency on the
// host (mount table, network, clock, output) comes in through Deps so the
// commands can be tested end to end without root privileges or network.
package cli

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/4rji/ctvault/internal/diskguard"
	"github.com/4rji/ctvault/internal/exitcode"
	"github.com/4rji/ctvault/internal/lock"
	"github.com/4rji/ctvault/internal/loglist"
	"github.com/4rji/ctvault/internal/volume"
)

// Volumes is the volume policy the commands use: volume.Checker in production
// builds, volume.DevProbe in ctvault_dev builds (amendment A1 §1).
type Volumes interface {
	Init(root string, opts volume.InitOptions) (volume.VaultID, error)
	Check(root string) (volume.VaultID, error)
	AddDir(root, dir string, opts volume.InitOptions) (volume.VaultID, error)
}

// Deps are the host services the commands use.
type Deps struct {
	Volumes       Volumes
	HTTP          *http.Client
	Now           func() time.Time
	Stdout        io.Writer
	Stderr        io.Writer
	Getenv        func(string) string
	Statfs        diskguard.StatFunc
	LogListSource string
	Version       string
	// DevBase is <home>/.cache/ctvault-dev in ctvault_dev builds, where dev
	// vaults and samples live; production builds leave it empty.
	DevBase string
}

// DefaultDeps wires the real host with the production volume policy.
func DefaultDeps(version string) Deps {
	return Deps{
		Volumes: volume.Checker{Probe: volume.HostProbe{}, Now: time.Now},
		HTTP:    &http.Client{Timeout: 60 * time.Second}, Now: time.Now,
		Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv, Statfs: diskguard.Statfs,
		LogListSource: loglist.DefaultURL, Version: version,
	}
}

// devBanner is printed on stderr by every command of a ctvault_dev binary.
const devBanner = "WARNING: DEV BUILD (ctvault_dev) — not for production. Vaults and samples live only under ~/.cache/ctvault-dev/."

// extraCommands lets build-tagged files add commands (the dev build's
// "sample" commands); production builds register none.
var extraCommands []func(*app) *cobra.Command

// Main runs one command and returns its exit code (spec §11.2).
func Main(args []string, d Deps) int {
	if volume.DevBuild() {
		fmt.Fprintln(d.Stderr, devBanner)
	}
	a := &app{d: d}
	cmd := newRootCmd(a)
	cmd.SetArgs(args)
	cmd.SetOut(d.Stdout)
	cmd.SetErr(d.Stderr)
	err := cmd.Execute()
	if err == nil {
		return exitcode.OK
	}
	fmt.Fprintln(d.Stderr, "ctvault:", err)
	code := exitcode.Of(err)
	if code == exitcode.Usage {
		fmt.Fprintln(d.Stderr, "Run 'ctvault --help' for usage.")
	}
	return code
}

type app struct {
	d    Deps
	root string
}

func newRootCmd(a *app) *cobra.Command {
	root := &cobra.Command{
		Use:           "ctvault",
		Short:         "A local, cryptographically verified Certificate Transparency research archive",
		Args:          usageArgs(cobra.NoArgs),
		RunE:          func(c *cobra.Command, _ []string) error { return c.Help() },
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&a.root, "root", a.d.Getenv("CTVAULT_ROOT"), "vault root (default $CTVAULT_ROOT)")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return exitcode.With(exitcode.Usage, err) })
	root.AddCommand(newVersionCmd(a), newInitCmd(a), newLogsCmd(a), newVaultCmd(a))
	for _, extra := range extraCommands {
		root.AddCommand(extra(a))
	}
	return root
}

// usageArgs marks argument-count errors as usage errors (exit code 2).
func usageArgs(v cobra.PositionalArgs) cobra.PositionalArgs {
	return func(c *cobra.Command, args []string) error { return exitcode.With(exitcode.Usage, v(c, args)) }
}

func groupCmd(use, short string, children ...*cobra.Command) *cobra.Command {
	c := &cobra.Command{Use: use, Short: short, Args: usageArgs(cobra.NoArgs),
		RunE: func(c *cobra.Command, _ []string) error { return c.Help() }}
	c.AddCommand(children...)
	return c
}

func volumeErr(err error) error {
	if errors.Is(err, volume.ErrVolume) {
		return exitcode.With(exitcode.Volume, err)
	}
	return err
}

// openVault runs the spec §9.2 checks that precede every command on a vault.
func (a *app) openVault(c *cobra.Command) (string, volume.VaultID, error) {
	if a.root == "" {
		return "", volume.VaultID{}, exitcode.Withf(exitcode.Usage, "no vault root: pass --root or set CTVAULT_ROOT")
	}
	id, err := a.d.Volumes.Check(a.root)
	if err != nil {
		return "", id, volumeErr(err)
	}
	if id.Durability == volume.DurabilityUntested {
		fmt.Fprintln(c.ErrOrStderr(), "warning: this vault uses an untested filesystem; durability guarantees are weaker (spec §9.3)")
	}
	return a.root, id, nil
}

func (a *app) writerLock(root string) (*lock.Lock, error) {
	return lock.Acquire(filepath.Join(root, "state", "LOCK"))
}

func newVersionCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use: "version", Short: "Print the ctvault version", Args: usageArgs(cobra.NoArgs),
		RunE: func(c *cobra.Command, _ []string) error {
			if volume.DevBuild() {
				fmt.Fprintln(c.OutOrStdout(), "ctvault", a.d.Version, "DEV BUILD — not for production")
				return nil
			}
			fmt.Fprintln(c.OutOrStdout(), "ctvault", a.d.Version)
			return nil
		},
	}
}
