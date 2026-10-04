//go:build !ctvault_dev

package main

import "github.com/4rji/ctvault/internal/cli"

// deps wires the production volume policy (spec §9).
func deps(version string) cli.Deps { return cli.DefaultDeps(version) }
