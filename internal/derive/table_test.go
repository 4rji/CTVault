package derive

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestTables(t *testing.T) {
	if CertsV1.File() != "certs.p1.parquet" || NamesV1.File() != "names.p1.parquet" {
		t.Errorf("files %s %s", CertsV1.File(), NamesV1.File())
	}
	for _, b := range Builders {
		tb := b.Table()
		for _, c := range tb.Columns {
			if strings.Contains(c.Type, "BLOB") {
				t.Errorf("%s.%s is a BLOB: bloom-filtered files never hold BLOB columns (D19)", tb.Name, c.Name)
			}
		}
		kv := map[string]string{}
		for _, p := range tb.KV() {
			kv[p[0]] = p[1]
		}
		if kv["ctvault.table"] != tb.Name || kv["ctvault.version"] != "1" || kv["ctvault.extractor"] != ExtractorVersion ||
			kv["ctvault.schema_sha256"] != tb.SchemaSHA256() || kv["ctvault.psl"] != tb.PSL {
			t.Errorf("%s KV %v", tb.Name, kv)
		}
	}
}

// TestSchemasAreFrozen: a table's columns are part of its version (spec
// §7.2): changing them without bumping the version would mix two schemas
// under one file name.
func TestSchemasAreFrozen(t *testing.T) {
	for name, want := range map[string]string{
		CertsV1.Name: "ced48dafaee44fa963d3b3bda2d7fbfe781753b28440c828cc039393fc859b17",
		NamesV1.Name: "82bd317eaa88ed33cfdbd8f825743fe3f4b3ca3d9b376b5016722d5ee8eb0f96",
	} {
		for _, b := range Builders {
			if b.Table().Name == name && b.Table().SchemaSHA256() != want {
				t.Errorf("%s schema %s changed (was %s): bump its version", name, b.Table().SchemaSHA256(), want)
			}
		}
	}
}

// TestPSLMatchesTheModule: names records the public-suffix list it was
// built with (spec §7.2 psl_snapshot). A bump of golang.org/x/net changes
// eTLD+1 results and must bump the names version too.
func TestPSLMatchesTheModule(t *testing.T) {
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Version}} {{.Dir}}", "golang.org/x/net")
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	version, dir, _ := strings.Cut(strings.TrimSpace(string(out)), " ")
	src, err := os.ReadFile(filepath.Join(dir, "publicsuffix", "table.go"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`git revision ([0-9a-f]+) \(([^)]+)\)`).FindSubmatch(src)
	if m == nil {
		t.Fatal("no list revision in publicsuffix/table.go")
	}
	want := "golang.org/x/net " + version + ", public_suffix_list.dat " + string(m[1]) + " (" + string(m[2]) + ")"
	if PSLSnapshot != want {
		t.Errorf("PSLSnapshot = %q, the module has %q: update it and bump the names version", PSLSnapshot, want)
	}
}
