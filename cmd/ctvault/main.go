// Command ctvault is a local, cryptographically verified Certificate
// Transparency research archive. See docs/superpowers/specs/.
package main

import (
	"os"

	"github.com/4rji/ctvault/internal/cli"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(cli.Main(os.Args[1:], cli.DefaultDeps(version)))
}
