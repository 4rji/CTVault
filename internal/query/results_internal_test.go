package query

import (
	"testing"
	"time"

	"github.com/4rji/ctvault/internal/diskguard"
)

// TestCloseDuringAScan: Close returns at once while a read of the rows
// runs, as explore's UI goroutine needs; the rows are dropped when the
// read ends.
func TestCloseDuringAScan(t *testing.T) {
	ctx := t.Context()
	sess, err := NewSession(t.TempDir(), diskguard.Guard{Cap: 0.85, Stat: freeDiskInternal})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	h, err := sess.hold(ctx, `SELECT name, NULL::TIMESTAMP AS first_seen, TIMESTAMP '2026-10-01' AS last_seen, 1::BIGINT AS certs, ['CA'] AS issuers,
       row_number() OVER (ORDER BY name) AS __ctv_row FROM (VALUES ('a.test'), ('b.test')) AS v(name)`, "name asc")
	if err != nil {
		t.Fatal(err)
	}
	r := &Results{q: Query{Group: "names", Sort: "name asc"}, base: h, table: h.name, n: h.n}

	reading, release, done := make(chan struct{}), make(chan struct{}), make(chan error)
	go func() {
		first := true
		done <- r.scan(ctx, "", func([]string, []any, Cursor) error {
			if first {
				first = false
				close(reading)
				<-release
			}
			return nil
		})
	}()
	<-reading
	closed := make(chan struct{})
	go func() { r.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("Close waits for a read to end")
	}
	if n, _ := sess.Held(ctx); n != 1 {
		t.Fatalf("%d held tables while a read runs", n)
	}
	if _, err := r.Page(ctx, 0, 1); err == nil {
		t.Fatal("a closed result gives a page")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("the read: %v", err)
	}
	if n, _ := sess.Held(ctx); n != 0 {
		t.Fatalf("%d held tables after the read ended", n)
	}
}
