// Package sources builds a pinned log's LogSource from its kind (amendment
// A6 §1). It is the one place that chooses between the RFC 6962 and tiled
// implementations; it sits beside them because both import logsource.
package sources

import (
	"fmt"
	"net/http"

	"github.com/4rji/ctvault/internal/loglist"
	"github.com/4rji/ctvault/internal/logsource"
	"github.com/4rji/ctvault/internal/logsource/rfc6962"
	"github.com/4rji/ctvault/internal/logsource/tiled"
)

// Open returns the source for info. last is the last head accepted for the
// log (nil if none); chains is the per-batch chain cache.
func Open(info logsource.LogInfo, hc *http.Client, chains *logsource.ChainCache, last *logsource.SignedHead) (logsource.LogSource, error) {
	switch info.Kind {
	case loglist.KindRFC6962, "":
		return rfc6962.NewSource(info, hc, chains, last), nil
	case loglist.KindTiled:
		return tiled.NewSource(info, hc, last), nil // its issuer cache lasts the run (A6 §3.1)
	default:
		return nil, fmt.Errorf("log %s: no source for kind %q", info.Name, info.Kind)
	}
}
