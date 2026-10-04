//go:build ctvault_dev

package volume

// devBuild is true only in binaries built with -tags ctvault_dev.
const devBuild = true

// DevBuild reports whether this binary was built with -tags ctvault_dev.
func DevBuild() bool { return devBuild }
