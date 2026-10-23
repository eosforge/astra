// Verify the complete owned wrapper's numerical boundary with real Go types and independently prescribed counterexamples.
package command

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// exports binds the importer to actual exports from the selected offline Go toolchain, including project-local installations.
func exports(t *testing.T, directory string) types.Importer {
	t.Helper()
	context, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(context, "go", "list", "-deps", "-export", "-json", "errors", "flag")
	command.Dir = directory
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOWORK=off", "GOFLAGS=-mod=readonly")
	data, err := command.Output()
	if err != nil {
		t.Fatalf("cannot obtain native standard-library exports: %v", err)
	}
	paths := make(map[string]string)
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var item struct {
			ImportPath string
			Export     string
		}
		if err := decoder.Decode(&item); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("invalid native export inventory: %v", err)
		}
		paths[item.ImportPath] = item.Export
	}
	return importer.ForCompiler(token.NewFileSet(), "gc", func(path string) (io.ReadCloser, error) {
		if paths[path] == "" {
			return nil, fmt.Errorf("missing native export for %q", path)
		}
		return os.Open(paths[path])
	})
}

// numerics inspects owned expressions and declared bindings, without traversing the borrowed standard-library implementation.
func numerics(source []byte, imports types.Importer) (int, []string, error) {
	positions := token.NewFileSet()
	file, err := parser.ParseFile(positions, "flags.go", source, 0)
	if err != nil {
		return 0, nil, err
	}
	facts := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}}
	checker := types.Config{Importer: imports}
	if _, err := checker.Check("command", positions, []*ast.File{file}, facts); err != nil {
		return 0, nil, err
	}
	var numeric []string
	inspect := func(node ast.Node, kind string, value types.Type) {
		if basic, ok := value.Underlying().(*types.Basic); ok && basic.Info()&types.IsNumeric != 0 {
			numeric = append(numeric, fmt.Sprintf("%s:%s:%s", positions.Position(node.Pos()), kind, value))
		}
	}
	for node, value := range facts.Types {
		inspect(node, "expression", value.Type)
	}
	for node, value := range facts.Defs {
		if value != nil {
			inspect(node, "binding", value.Type())
		}
	}
	sort.Strings(numeric)
	return len(facts.Types) + len(facts.Defs), numeric, nil
}

// TestNumeric establishes absence of owned numeric semantics, then challenges the type-based oracle with valid numeric source.
func TestNumeric(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("missing source location")
	}
	directory := filepath.Dir(filename)
	var owned []string
	if err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			name, relative := filepath.Rel(directory, path)
			if relative != nil {
				return relative
			}
			owned = append(owned, filepath.ToSlash(name))
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(owned) != 1 || owned[0] != "flags.go" {
		t.Fatalf("unclassified command sources: %v", owned)
	}
	source, err := os.ReadFile(filepath.Join(directory, "flags.go"))
	if err != nil {
		t.Fatal(err)
	}
	// Reuse the native export importer across checks; no substitute declarations stand in for real flag/error types.
	imports := exports(t, directory)
	scanned, numeric, err := numerics(source, imports)
	if err != nil || scanned == 0 || len(numeric) != 0 {
		t.Fatalf("owned numeric boundary changed: %d %v %v", scanned, numeric, err)
	}
	// Types, aliases, implicit integer results and numeric constants must be detected even without arithmetic syntax.
	controls := []struct {
		before string
		after  string
	}{
		{"set bool", "set bool; count uint64"},
		{"set bool", "set bool; count *int"},
		{"set bool", "set bool; count [1]string"},
		{"set bool", "set bool; count map[int]string"},
		{"type once struct", "type count = rune\ntype once struct"},
		{"type once struct", "type count flag.ErrorHandling\ntype once struct"},
		{"type once struct", "const count uint64 = 18446744073709551615\ntype once struct"},
		{"type once struct", "const count int64 = -9223372036854775808\ntype once struct"},
		{"type once struct", "const count = 1e300\ntype once struct"},
		{"type once struct", "const count = 1i\ntype once struct"},
		{"value.set = true", "value.set = true; _ = len(text)"},
		{"return flags.Parse(arguments)", "for index := range arguments { _ = index }; return flags.Parse(arguments)"},
		{"value.set = true", "value.set = true; _ = float64(len(text))"},
		{"value.set = true", "value.set = true; count := len(text); count /= 1; _ = count"},
		{"value.set = true", "value.set = true; _ = complex(1.0, 2.0)"},
		{"value.set = true", "value.set = true; _ = uintptr(len(text))"},
		{"value.set = true", "value.set = true; _ = uint8(len(text))"},
		{"value.set = true", "value.set = true; _ = flag.ContinueOnError"},
	}
	for index, control := range controls {
		if strings.Count(string(source), control.before) != 1 {
			t.Fatalf("numeric control anchor changed: %q", control.before)
		}
		changed := strings.Replace(string(source), control.before, control.after, 1)
		checked, numeric, err := numerics([]byte(changed), imports)
		if err != nil || checked == 0 || len(numeric) == 0 {
			t.Fatalf("valid numeric control %d escaped or failed type checking: %d %v %v", index, checked, numeric, err)
		}
		t.Logf("COMMAND-NUMERIC-CONTROL %d %v", index, numeric)
	}
	// Bool/string data are not numerical merely because their physical representation uses machine words.
	positive := strings.Replace(string(source), "value.set = true", "value.set = true; text = text + \"\"", 1)
	if checked, numeric, err := numerics([]byte(positive), imports); err != nil || checked == 0 || len(numeric) != 0 {
		t.Fatalf("non-numeric string control rejected: %d %v %v", checked, numeric, err)
	}
	t.Logf(`ASTRA-CONTRACT {"contract":"COMMAND-NUMERIC","hits":%d}`, 1)
	t.Logf(`ASTRA-CONTRACT {"contract":"COMMAND-NUMERIC-CONTROLS","hits":%d}`, len(controls)+1)
	t.Logf("COMMAND-NUMERIC-SOURCE typed_nodes=%d numeric_nodes=0", scanned)
}
