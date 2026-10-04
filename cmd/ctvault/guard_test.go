package main

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// goCmd runs the go tool with GOFLAGS cleared, so a developer's environment
// cannot sneak build tags into the production checks.
func goCmd(t *testing.T, args ...string) []byte {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not in PATH")
	}
	cmd := exec.Command(goBin, args...)
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("go %v: %v\n%s", args, err, ee.Stderr)
		}
		t.Fatalf("go %v: %v", args, err)
	}
	return out
}

// TestProductionBinaryExcludesDevCode proves amendment A1 §1: production
// builds contain no dev probe, no dev-only file and no test-only package.
func TestProductionBinaryExcludesDevCode(t *testing.T) {
	if testing.Short() {
		t.Skip("builds two binaries")
	}
	banned := []string{"/internal/volume/volumetest", "/internal/ctlogtest", "/internal/sampletest", "/internal/sample"}
	dec := json.NewDecoder(bytes.NewReader(goCmd(t, "list", "-deps", "-json", ".")))
	for dec.More() {
		var p struct {
			ImportPath string
			GoFiles    []string
		}
		if err := dec.Decode(&p); err != nil {
			t.Fatal(err)
		}
		for _, b := range banned {
			if strings.HasSuffix(p.ImportPath, b) {
				t.Errorf("production binary depends on test/dev-only package %s", p.ImportPath)
			}
		}
		// The _dev.go naming rule is CTVault's own; third-party packages
		// (prometheus/procfs's net_dev.go, via Pebble) may use the suffix.
		if !strings.HasPrefix(p.ImportPath, "github.com/4rji/ctvault/") {
			continue
		}
		for _, f := range p.GoFiles {
			if f == "devprobe.go" || strings.HasSuffix(f, "_dev.go") {
				t.Errorf("production build of %s compiles dev-only file %s", p.ImportPath, f)
			}
		}
	}

	dir := t.TempDir()
	prod, dev := filepath.Join(dir, "ctvault"), filepath.Join(dir, "ctvault-dev")
	goCmd(t, "build", "-o", prod, ".")
	goCmd(t, "build", "-tags", "ctvault_dev", "-o", dev, ".")
	if syms := goCmd(t, "tool", "nm", prod); bytes.Contains(syms, []byte("volume.DevProbe")) {
		t.Error("production binary contains the DevProbe symbol")
	}
	// Positive control: the same check finds DevProbe in a dev build, so the
	// assertion above can actually fail.
	if syms := goCmd(t, "tool", "nm", dev); !bytes.Contains(syms, []byte("volume.DevProbe")) {
		t.Error("dev binary lacks DevProbe; the symbol check is not meaningful")
	}
}

// productionFile reports whether a non-test Go file is compiled into
// production builds: its //go:build line, if any, must hold without ctvault_dev.
func productionFile(src []byte) bool {
	for _, line := range strings.Split(string(src), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "package ") {
			return true
		}
		if constraint.IsGoBuild(line) {
			expr, err := constraint.Parse(line)
			if err != nil {
				return true
			}
			return expr.Eval(func(tag string) bool { return tag != "ctvault_dev" })
		}
	}
	return true
}

// TestOnlyRootEnvVarIsRead proves amendment A1 §1: no environment variable
// can change production behaviour except CTVAULT_ROOT, which selects a path.
// os.Getenv may be referenced only where it is injected (cli.DefaultDeps), and
// every Getenv call must name CTVAULT_ROOT literally.
func TestOnlyRootEnvVarIsRead(t *testing.T) {
	root := filepath.Join("..", "..")
	envFuncs := map[string]bool{"Getenv": true, "LookupEnv": true, "Environ": true, "ExpandEnv": true}
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !productionFile(src) {
			return nil
		}
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if id, ok := x.X.(*ast.Ident); ok && (id.Name == "os" || id.Name == "syscall") && envFuncs[x.Sel.Name] {
					if rel != filepath.Join("internal", "cli", "cli.go") || x.Sel.Name != "Getenv" {
						t.Errorf("%s: %s.%s outside the single injection point", fset.Position(x.Pos()), id.Name, x.Sel.Name)
					}
				}
			case *ast.CallExpr:
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Getenv" || len(x.Args) != 1 {
					return true
				}
				lit, ok := x.Args[0].(*ast.BasicLit)
				if !ok || lit.Value != `"CTVAULT_ROOT"` {
					t.Errorf("%s: Getenv must read only \"CTVAULT_ROOT\"", fset.Position(x.Pos()))
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
