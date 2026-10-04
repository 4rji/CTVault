//go:build !ctvault_dev

package volume

// devBuild is false in production builds, so every dev-only branch compiles
// away (amendment A1 §1).
const devBuild = false

// DevBuild reports whether this binary was built with -tags ctvault_dev.
func DevBuild() bool { return devBuild }
