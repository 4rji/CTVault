package cli

import (
	"fmt"
	"io"
	"time"
)

// progress reports a long check's steps to w ("<what>: 3 of 5 <unit>"), at
// most once per interval and always at the last step.
func progress(w io.Writer, what, unit string, every time.Duration, now func() time.Time) func(done, total int) {
	last := now()
	return func(done, total int) {
		if t := now(); done == total || t.Sub(last) >= every {
			last = t
			fmt.Fprintf(w, "%s: %d of %d %s\n", what, done, total, unit)
		}
	}
}
