package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/stats"
)

// TestStatsCommand: stats shows each log's progress and the vault's
// contents, and estimates stay unknown with too little history (amendment
// A2 §6.2-6.3); --json gives the same report as JSON.
func TestStatsCommand(t *testing.T) {
	e, _ := updateEnv(t, 120, ctlogtest.Options{})
	e.mustRun("--root", e.root, "update")
	out := e.mustRun("--root", e.root, "stats")
	for _, s := range []string{"log fakelog", "committed: 120 entries", "remaining: 0 entries", "ingest rate: unknown",
		"vault: 3 batches, 120 entries", "certs v1 complete", "projected disk cap: unknown", "health: 3 post-commit audits passed, 0 failed"} {
		if !strings.Contains(out, s) {
			t.Errorf("stats lacks %q:\n%s", s, out)
		}
	}
	var r stats.Report
	if err := json.Unmarshal([]byte(e.mustRun("--root", e.root, "stats", "--json")), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Logs) != 1 || r.Logs[0].CommittedEntries != 120 || r.Logs[0].Remaining == nil || *r.Logs[0].Remaining != 0 ||
		r.Vault.Batches != 3 || r.Vault.ParseStatus["ok"] == 0 || r.Logs[0].IngestRate != nil || len(r.Volumes) == 0 {
		t.Fatalf("stats --json: %+v", r)
	}
}
