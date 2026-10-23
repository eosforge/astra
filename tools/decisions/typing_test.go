// Challenge typed overlays with independent value/type expectations and native compiler export inputs.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// typedFixture owns one source file, its syntax inventory and explicit metadata used only by tool self-checks.
func typedFixture(t *testing.T, input string) (string, report, []byte) {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "unit"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "unit/state.go"), []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	item, err := scan("unit/state.go", []byte(input))
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := json.Marshal(exported{ImportPath: "fixture/unit", Dir: filepath.Join(root, "unit"), Name: "main", GoFiles: []string{"state.go"}})
	if err != nil {
		t.Fatal(err)
	}
	return root, report{SourceSHA256: strings.Repeat("a", 64), Files: []inventory{item}}, metadata
}

// TestTyping executes actual rewritten named-Boolean stores, fields, arguments and returns; constants stay constant.
func TestTyping(t *testing.T) {
	input := `package main
type Flag bool
type Value struct{ Allowed Flag }
const Constant = 1 < 2
var last Flag
func accept(value Flag) Flag { return value }
func compute(a,b Flag) Flag {
 last = a != b
 value := Value{Allowed: a == b}
 return accept(a && b) && value.Allowed
}
`
	root, collection, metadata := typedFixture(t, input)
	checked, err := annotate(root, "unit", metadata, collection)
	if err != nil || len(checked.Files) != 1 || len(checked.Inactive) != 0 || len(checked.Constants) != 1 || len(checked.Results) != 4 || len(checked.Exports) != 0 {
		t.Fatalf("typed root inventory changed: %+v %v", checked, err)
	}
	for _, spelling := range checked.Results {
		if spelling != "Flag" {
			t.Fatalf("named Boolean context was lost: %s", spelling)
		}
	}
	output := filepath.Join(root, "overlay")
	if err := typedTrace(root, "unit", output, collection, &checked); err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Version  int      `json:"version"`  // Typed records cannot masquerade as old syntax-only evidence.
		Observed []string `json:"observed"` // Constants remain in the denominator but not runtime traces.
		Typing   typing   `json:"typing"`   // Exact checked input facts.
	}
	data, err := os.ReadFile(filepath.Join(output, "trace.json"))
	if err != nil || json.Unmarshal(data, &manifest) != nil || manifest.Version != 2 || len(manifest.Observed) != 4 || manifest.Typing.MetadataSHA256 != checked.MetadataSHA256 {
		t.Fatal("typed trace binding changed", err)
	}
	// The harness stays outside the overlay and defines expected values independently of the instrumenter.
	harness := `package main
import "reflect"
func main() {
 for _,item := range []struct{a,b,want,last Flag}{
 {false,false,false,false}, {false,true,false,true}, {true,false,false,true}, {true,true,true,false},
 } {
  value := compute(item.a,item.b)
  if value != item.want || last != item.last || reflect.TypeOf(value) != reflect.TypeOf(Flag(false)) || !Constant { panic("typed evaluation changed") }
 }
 astraProbeFinish(0)
}
`
	if err := os.WriteFile(filepath.Join(output, "main.go"), []byte(harness), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(output, "go.mod"), []byte("module fixture\ngo 1.25\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Generated TestMain is not needed for go run; the explicit harness owns the terminal record.
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "run", "-race", ".")
	command.Dir = output
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOWORK=off", "GOFLAGS=-mod=readonly")
	command.WaitDelay = time.Second
	native, err := command.CombinedOutput()
	if err != nil || ctx.Err() != nil || !bytes.HasPrefix(native, []byte("GO-DECISIONS ")) {
		t.Fatalf("typed native evaluation failed: %v %s", err, native)
	}
	var receipt struct {
		Code int `json:"code"` // Native harness exit after all independent value/type checks.
		Rows []struct {
			ID     string `json:"id"`     // Source-bound original decision.
			Values string `json:"values"` // Actual short-circuit vector.
			Result bool   `json:"result"` // Completed evaluation result.
			Hits   uint64 `json:"hits"`   // Actual calls, not expected counts from metadata.
		} `json:"rows"`
	}
	if err := json.Unmarshal(native[len("GO-DECISIONS "):], &receipt); err != nil || receipt.Code != 0 {
		t.Fatal("invalid typed native receipt", err)
	}
	counts := map[string]uint64{}
	for _, row := range receipt.Rows {
		if row.Hits == 0 || checked.Results[row.ID] == "" || row.ID == checked.Constants[0] {
			t.Fatal("unowned or fabricated typed observation")
		}
		counts[row.ID] += row.Hits
	}
	if len(counts) != 4 {
		t.Fatal("typed root was not executed")
	}
	for _, hits := range counts {
		if hits != 4 {
			t.Fatal("typed expression was reevaluated or skipped")
		}
	}
}

// TestTypingInactive retains native rootless platform stubs and rejects inactive decisions or an incomplete partition.
func TestTypingInactive(t *testing.T) {
	root, collection, metadata := typedFixture(t, "package main\nfunc F(a,b bool)bool{return a&&b}\n")
	var selected exported
	if err := json.Unmarshal(metadata, &selected); err != nil {
		t.Fatal(err)
	}
	selected.IgnoredGoFiles = []string{"other.go", "other_test.go"}
	data, err := json.Marshal(selected)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{
		"//go:build !linux\npackage main\nfunc Other()error{return nil}\n",
		"//go:build !linux\npackage main\nfunc Other(a bool)bool{return a}\n",
		"//go:build !linux\npackage main\nfunc Other(){defer F(false,false)}\n",
	} {
		if err := os.WriteFile(filepath.Join(root, "unit/other.go"), []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		item, err := scan("unit/other.go", []byte(input))
		if err != nil {
			t.Fatal(err)
		}
		candidate := collection
		candidate.Files = append(append([]inventory{}, collection.Files...), item)
		checked, err := annotate(root, "unit", data, candidate)
		if len(item.Decisions) == 0 && len(item.Controls) == 0 {
			if err != nil || len(checked.Files) != 1 || len(checked.Inactive) != 1 || checked.Inactive[0] != item.File || len(checked.Results) != 1 {
				t.Fatal("rootless inactive source lost its explicit identity", err)
			}
			if _, err := annotate(root, "unit", data, collection); err == nil {
				t.Fatal("native inactive input disappeared from the owned inventory")
			}
		} else if err == nil || !strings.Contains(err.Error(), "typing-inactive-decisions") {
			t.Fatal("inactive decisions or controls were silently accepted", err)
		}
	}
}

// TestTypingRejection preserves failed/inactive/changed sources and refuses missing type information.
func TestTypingRejection(t *testing.T) {
	input := "package main\nfunc Check(a,b bool)bool { v:=a&&b; return v }\n"
	root, collection, metadata := typedFixture(t, input)
	var selected exported
	if err := json.Unmarshal(metadata, &selected); err != nil {
		t.Fatal(err)
	}
	for _, value := range []exported{
		{ImportPath: selected.ImportPath, Dir: selected.Dir, Name: selected.Name, Incomplete: true, GoFiles: selected.GoFiles},
		{ImportPath: selected.ImportPath, Dir: selected.Dir, Name: selected.Name, Error: json.RawMessage(`{"Err":"failed"}`), GoFiles: selected.GoFiles},
		{ImportPath: selected.ImportPath, Dir: selected.Dir, Name: selected.Name, DepsErrors: []json.RawMessage{json.RawMessage(`{"Err":"failed"}`)}, GoFiles: selected.GoFiles},
		{ImportPath: selected.ImportPath, Dir: selected.Dir, Name: selected.Name, GoFiles: []string{"state.go", "state.go"}},
		{ImportPath: selected.ImportPath, Dir: selected.Dir, Name: selected.Name, GoFiles: []string{"../state.go"}},
		{ImportPath: selected.ImportPath, Dir: selected.Dir, Name: selected.Name, GoFiles: []string{"state.go"}, CgoFiles: []string{"cgo.go"}},
		{ImportPath: selected.ImportPath, Dir: selected.Dir, Name: selected.Name},
	} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := annotate(root, "unit", data, collection); err == nil {
			t.Fatalf("unsupported typed metadata accepted: %+v", value)
		}
	}
	for _, data := range [][]byte{nil, []byte("{"), append(append([]byte{}, metadata...), metadata...)} {
		if _, err := annotate(root, "unit", data, collection); err == nil {
			t.Fatal("empty, malformed or duplicate package metadata accepted")
		}
	}
	if err := os.WriteFile(filepath.Join(root, "unit/state.go"), []byte(input+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := annotate(root, "unit", metadata, collection); err == nil {
		t.Fatal("source drift accepted")
	}
	if _, _, err := rewrite("unit/state.go", []byte(input), map[string]string{}); err == nil {
		t.Fatal("mandatory control/return roots lost their types")
	}
	for _, input := range []string{
		"package main\ntype bool = bool\nfunc F(value bool)bool{return value}\n",
		"package main\nfunc F()bool{return missing}\n",
	} {
		root, collection, metadata := typedFixture(t, input)
		if _, err := annotate(root, "unit", metadata, collection); err == nil {
			t.Fatal("shadowed builtin or failed type checking accepted")
		}
	}
}

// TestTypingImports binds a real gc archive and rejects missing, changed or out-of-cache dependency inputs.
func TestTypingImports(t *testing.T) {
	root, collection, metadata := typedFixture(t, "package main\nimport alias \"fixture/dependency\"\nfunc F(a,b alias.Flag)alias.Flag{return a&&b}\n")
	directory := filepath.Join(root, "build", "cache", "go")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(directory, "dependency.a")
	input := filepath.Join(root, "dependency.go")
	compile := func(definition string) {
		t.Helper()
		if err := os.WriteFile(input, []byte("package dependency\n// Flag preserves the declared Boolean representation.\ntype Flag "+definition+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "go", "tool", "compile", "-p", "fixture/dependency", "-pack", "-o", output, input)
		command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOWORK=off")
		command.WaitDelay = time.Second
		if data, err := command.CombinedOutput(); err != nil || ctx.Err() != nil {
			t.Fatalf("native fixture export failed: %v %s", err, data)
		}
	}
	compile("bool")
	dependency := exported{ImportPath: "fixture/dependency", Dir: root, Name: "dependency", Export: output}
	bind := func(value exported) []byte {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return append(append(append([]byte{}, metadata...), '\n'), data...)
	}
	checked, err := annotate(root, "unit", bind(dependency), collection)
	if err != nil || len(checked.Exports) != 1 || len(checked.Results) != 1 {
		t.Fatal("native typed import failed", err)
	}
	for _, spelling := range checked.Results {
		if spelling != "alias.Flag" {
			t.Fatal("source import alias was not preserved")
		}
	}
	bound := checked.Exports[dependency.ImportPath]
	actual, err := os.ReadFile(output)
	if err != nil || bound.Path != output || bound.Bytes != len(actual) || bound.SHA256 == "" {
		t.Fatal("native export content was not bound", err)
	}
	if _, err := annotate(root, "unit", metadata, collection); err == nil {
		t.Fatal("missing dependency metadata accepted")
	}
	for _, path := range []string{"", "relative.a", filepath.Join(root, "outside.a")} {
		value := dependency
		value.Export = path
		if _, err := annotate(root, "unit", bind(value), collection); err == nil {
			t.Fatal("missing or out-of-cache export accepted")
		}
	}
	compile("uint8")
	if _, err := annotate(root, "unit", bind(dependency), collection); err == nil {
		t.Fatal("changed non-Boolean dependency accepted")
	}
	if err := os.WriteFile(output, []byte("not a gc archive"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := annotate(root, "unit", bind(dependency), collection); err == nil {
		t.Fatal("malformed dependency archive accepted")
	}
}
