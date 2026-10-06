package query

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/diskguard"
)

func freeDiskInternal(string) (diskguard.Usage, error) {
	return diskguard.Usage{Total: 1 << 40, Avail: 1 << 39, Dev: 1}, nil
}

// TestReaderSessionSpill: a session spills only into tmp/duckdb-<pid>/,
// removes it on close, and removes the folders of readers that no longer
// run, never a live one's (amendment A3 §2.2-2.3).
func TestReaderSessionSpill(t *testing.T) {
	root := t.TempDir()
	dead := filepath.Join(root, "tmp", "duckdb-999999999")
	live := filepath.Join(root, "tmp", "duckdb-1") // init
	writer := filepath.Join(root, "tmp", "duckdb-writer")
	for _, d := range []string{dead, live, writer} {
		os.MkdirAll(d, 0o755)
	}
	sess, err := NewSession(root, diskguard.Guard{Cap: 0.85, Stat: freeDiskInternal})
	if err != nil {
		t.Fatal(err)
	}
	mine := filepath.Join(root, "tmp", "duckdb-"+strconv.Itoa(os.Getpid()))
	if _, err := os.Stat(mine); err != nil {
		t.Fatalf("no spill folder of its own: %v", err)
	}
	if _, err := os.Stat(dead); err == nil {
		t.Fatal("a dead reader's spill folder survived")
	}
	for _, d := range []string{live, writer} {
		if _, err := os.Stat(d); err != nil {
			t.Fatalf("%s was removed", d)
		}
	}
	var spill string
	sess.db.QueryRow(`SELECT current_setting('temp_directory')`).Scan(&spill)
	if spill != mine {
		t.Fatalf("temp_directory %q, want %q", spill, mine)
	}
	sess.Close()
	if _, err := os.Stat(mine); err == nil {
		t.Fatal("the spill folder survived Close")
	}
}

// TestSearchIPPredicate: --ip compares the canonical address and also finds
// IP-literal CNs (amendment A3 §3.1).
func TestSearchIPPredicate(t *testing.T) {
	for in, want := range map[string]string{"192.0.2.1": "'192.0.2.1'", "2001:DB8:0:0::1": "'2001:db8::1'"} {
		q := Query{Mode: ModeIP, Text: in}
		pred, err := q.namePredicate()
		if err != nil || !strings.Contains(pred, "name = "+want) || !strings.Contains(pred, "'san_ip', 'cn'") {
			t.Errorf("%s: %s %v", in, pred, err)
		}
	}
}
