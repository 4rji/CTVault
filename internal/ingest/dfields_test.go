package ingest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/4rji/ctvault/internal/commit"
	"github.com/4rji/ctvault/internal/ctlogtest"
	"github.com/4rji/ctvault/internal/dataset"
	"github.com/4rji/ctvault/internal/derive"
	"github.com/4rji/ctvault/internal/vaulttest"
)

// dTables are the D tables' names (amendment A7).
var dTables = []string{"cert_extensions", "cert_policies", "cert_ekus", "cert_key_usage", "cert_aia", "cert_crl_dps", "cert_scts"}

// TestDTablesRollout is amendment A7 §4.4: a vault written by a binary
// without the D tables gets them through update's turns, its views switch
// from <table>_building to the tables' names, and certs and names keep every
// byte.
func TestDTablesRollout(t *testing.T) {
	h := newHarness(t, entries(t, 150), ctlogtest.Options{})
	restore := derive.SetRegistry([]derive.Versions{{Current: derive.Certs{}}, {Current: derive.Names{}}}) // the binary before A7
	w := h.open()
	h.ingest(w, h.head(), 0, 150, 50)
	w.Close()
	before, _ := commit.ListCommitted(h.root)
	restore()

	w = h.open()
	for _, name := range dTables {
		if s := w.Active().Tables[name]; s.Active != nil || s.Building == nil || s.Status != derive.StatusBuilding {
			t.Fatalf("%s on a vault with batches: %+v", name, s)
		}
	}
	views, _ := os.ReadFile(filepath.Join(h.root, dataset.ViewsFile))
	if !strings.Contains(string(views), "VIEW cert_scts_building AS") || strings.Contains(string(views), "VIEW cert_scts AS") {
		t.Fatalf("while building, D shows only as <table>_building:\n%s", views)
	}
	st, pending, err := w.RebuildTurn(ctx, 10)
	if err != nil || pending || st.Batches != 3 || !st.Switched {
		t.Fatalf("backfilling: %+v %v %v", st, pending, err)
	}
	if !w.Active().AllComplete() {
		t.Fatalf("after the turns: %+v", w.Active())
	}
	w.Close()
	views, _ = os.ReadFile(filepath.Join(h.root, dataset.ViewsFile))
	for _, name := range dTables {
		if !strings.Contains(string(views), "VIEW "+name+" AS") || strings.Contains(string(views), name+"_building") {
			t.Fatalf("%s did not switch:\n%s", name, views)
		}
	}
	after, _ := commit.ListCommitted(h.root)
	for i, m := range after {
		for _, f := range []string{"certs.p1.parquet", "names.p1.parquet"} {
			if m.Files[f] != before[i].Files[f] {
				t.Fatalf("batch %s: %s changed", m.BatchID, f)
			}
		}
		for _, name := range dTables {
			if _, ok := m.Listed(name + ".p1.parquet"); !ok {
				t.Fatalf("batch %s lacks %s", m.BatchID, name)
			}
		}
	}
	v := vaulttest.Vault{Root: h.root, Dirs: h.vaultDirs()}
	v.CheckRecovered(t)
	v.CheckDerived(t)
}
