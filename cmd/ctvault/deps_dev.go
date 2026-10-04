//go:build ctvault_dev

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/4rji/ctvault/internal/cli"
	"github.com/4rji/ctvault/internal/volume"
)

// deps wires the dev volume policy (amendment A1 §1): dev vaults only under
// ~/.cache/ctvault-dev/vaults/, samples under ~/.cache/ctvault-dev/samples/.
func deps(version string) cli.Deps {
	d := cli.DefaultDeps(version)
	base, err := volume.DefaultDevBase()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ctvault-dev:", err)
		os.Exit(1)
	}
	d.DevBase = base
	d.Volumes = volume.DevProbe{Base: filepath.Join(base, "vaults"), Probe: volume.HostProbe{}, Now: time.Now}
	return d
}
