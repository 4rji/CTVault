package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultTOMLMatchesDefault(t *testing.T) {
	root := t.TempDir()
	if err := WriteDefault(root); err != nil {
		t.Fatal(err)
	}
	got, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if got != Default() {
		t.Fatalf("DefaultTOML decodes to %+v, want %+v", got, Default())
	}
}

func TestLoadMissingFileGivesDefaults(t *testing.T) {
	got, err := Load(t.TempDir())
	if err != nil || got != Default() {
		t.Fatalf("Load without file = %+v, %v", got, err)
	}
}

func TestLoadOverridesAndUnits(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, FileName), []byte(`
[ingest]
batch_size = 1000
follow_interval = "30s"
[vault]
segment_size = "256MiB"
`), 0o644)
	got, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if got.Ingest.BatchSize != 1000 || got.Ingest.FollowInterval.Duration != 30*time.Second || got.Vault.SegmentSize != 256<<20 {
		t.Fatalf("overrides not applied: %+v", got)
	}
	if got.Ingest.Workers != 4 {
		t.Fatal("unset keys must keep defaults")
	}
}

func TestLoadRejectsUnknownKeysAndBadValues(t *testing.T) {
	for name, body := range map[string]string{
		"typo":         "[ingest]\nbatchsize = 10\n",
		"cap too high": "[disk]\nmax_used_fraction = 0.99\n",
		"bad size":     "[vault]\nsegment_size = \"lots\"\n",
		"tiny segment": "[vault]\nsegment_size = \"4KiB\"\n",
		"zero workers": "[ingest]\nworkers = 0\n",
	} {
		root := t.TempDir()
		os.WriteFile(filepath.Join(root, FileName), []byte(body), 0o644)
		if _, err := Load(root); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestWriteDefaultKeepsExistingFile(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, FileName)
	os.WriteFile(p, []byte("[ingest]\nworkers = 8\n"), 0o644)
	if err := WriteDefault(root); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "workers = 8") {
		t.Fatal("WriteDefault overwrote an existing config")
	}
}
