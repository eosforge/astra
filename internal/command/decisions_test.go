// Bind the complete flag-wrapper decision inventory to independently observed dispatch and short-circuit cases.
package command

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// operand exposes delegate calls without deriving expected results from the wrapper implementation.
type operand struct {
	reads  int
	writes int
	err    error
}

// String makes delegation distinguishable from the zero-value fallback.
func (value *operand) String() string {
	value.reads++
	return "visible"
}

// Set records the call even when the registered value rejects it.
func (value *operand) Set(string) error {
	value.writes++
	return value.err
}

// boolean declares the optional flag interface independently of its returned value.
type boolean struct {
	operand
	result bool
	calls  int
}

// IsBoolFlag counts actual evaluation, including the explicit false-interface case.
func (value *boolean) IsBoolFlag() bool {
	value.calls++
	return value.result
}

// decisions refuses new files, callables or branch forms until their verification domain is updated.
func decisions(source []byte) ([]string, error) {
	positions := token.NewFileSet()
	file, err := parser.ParseFile(positions, "flags.go", source, 0)
	if err != nil {
		return nil, err
	}
	var found []string
	show := func(node ast.Node) string {
		var text bytes.Buffer
		if err := format.Node(&text, positions, node); err != nil {
			panic(err)
		}
		return text.String()
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.FuncDecl:
			name := value.Name.Name
			if value.Recv != nil {
				name = show(value.Recv.List[0].Type) + "." + name
			}
			found = append(found, "function:"+name)
		case *ast.FuncLit:
			found = append(found, "closure:"+show(value.Type))
		case *ast.IfStmt:
			found = append(found, "if:"+show(value.Cond))
		case *ast.BinaryExpr:
			found = append(found, "binary:"+show(value))
		case *ast.UnaryExpr:
			if value.Op == token.NOT {
				found = append(found, "not:"+show(value))
			}
		case *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt, *ast.GoStmt, *ast.DeferStmt, *ast.BranchStmt:
			found = append(found, fmt.Sprintf("unsupported:%T", value))
		}
		return true
	})
	sort.Strings(found)
	return found, nil
}

// isolation rejects undeclared effects while leaving the registered flag implementation at the caller boundary.
func isolation(source []byte) error {
	positions := token.NewFileSet()
	file, err := parser.ParseFile(positions, "flags.go", source, parser.ParseComments)
	if err != nil {
		return err
	}
	imports := []string{}
	for _, spec := range file.Imports {
		if spec.Name != nil {
			return errors.New("import alias")
		}
		imports = append(imports, spec.Path.Value)
	}
	sort.Strings(imports)
	if !reflect.DeepEqual(imports, []string{`"errors"`, `"flag"`}) {
		return errors.New("dependency boundary")
	}
	for _, group := range file.Comments {
		for _, comment := range group.List {
			if strings.HasPrefix(comment.Text, "//go:") || strings.HasPrefix(comment.Text, "// +build") {
				return errors.New("compiler directive")
			}
		}
	}
	for _, declaration := range file.Decls {
		if value, ok := declaration.(*ast.GenDecl); ok && value.Tok == token.VAR {
			return errors.New("global state")
		}
		if value, ok := declaration.(*ast.FuncDecl); ok && value.Name.Name == "init" {
			return errors.New("initialization effect")
		}
	}
	var calls []string
	ast.Inspect(file, func(node ast.Node) bool {
		if err != nil {
			return false
		}
		switch value := node.(type) {
		case *ast.GoStmt, *ast.DeferStmt, *ast.ChanType, *ast.SendStmt, *ast.SelectStmt:
			err = errors.New("task or channel ownership")
		case *ast.UnaryExpr:
			if value.Op == token.ARROW {
				err = errors.New("channel receive")
			}
		case *ast.CallExpr:
			var text bytes.Buffer
			if err = format.Node(&text, positions, value.Fun); err == nil {
				calls = append(calls, text.String())
			}
		}
		return err == nil
	})
	if err != nil {
		return err
	}
	sort.Strings(calls)
	// Calls outside the borrowed FlagSet/Value interfaces are restricted to constructing a local error value.
	if !reflect.DeepEqual(calls, []string{"boolean.IsBoolFlag", "errors.New", "flags.Parse", "flags.VisitAll", "value.Value.Set", "value.Value.String"}) {
		return errors.New("undeclared call")
	}
	return nil
}

// TestDecisionInventory binds every owned callable and decision expression; edits cannot silently retain the old denominator.
func TestDecisionInventory(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("missing source location")
	}
	directory := filepath.Dir(filename)
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var owned []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".go") && !strings.HasSuffix(entry.Name(), "_test.go") {
			owned = append(owned, entry.Name())
		}
	}
	if !reflect.DeepEqual(owned, []string{"flags.go"}) {
		t.Fatalf("unclassified command sources: %v", owned)
	}
	source, err := os.ReadFile(filepath.Join(directory, "flags.go"))
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"binary:ok && boolean.IsBoolFlag()", "binary:value.Value == nil", "closure:func(option *flag.Flag)",
		"function:*once.IsBoolFlag", "function:*once.Set", "function:*once.String", "function:Parse",
		"if:value.Value == nil", "if:value.set",
	}
	actual, err := decisions(source)
	if err != nil || !reflect.DeepEqual(actual, expected) {
		t.Fatalf("decision inventory drift: %v %v", actual, err)
	}
	// The denominator checker must reject changed expressions, a new branch, and a new callable before claiming completeness.
	for _, changed := range []string{
		strings.Replace(string(source), "ok && boolean.IsBoolFlag()", "ok || boolean.IsBoolFlag()", 1),
		strings.Replace(string(source), "return flags.Parse(arguments)", "if len(arguments) == 0 { return nil }; return flags.Parse(arguments)", 1),
		string(source) + "\nfunc extra() bool { return true }\n",
	} {
		observed, err := decisions([]byte(changed))
		if err != nil || reflect.DeepEqual(observed, expected) {
			t.Fatalf("inventory negative control did not detect a valid source change: %v", err)
		}
	}
	if err := isolation(source); err != nil {
		t.Fatalf("owned effect boundary changed: %v", err)
	}
	// Each syntactically valid perturbation must be rejected by its own boundary, not a parser error.
	controls := []struct {
		before string
		after  string
		reason string
	}{
		{`"errors"`, `"errors"; "time"`, "dependency boundary"},
		{`"flag"`, `"flag"; _ "net/http"`, "import alias"},
		{`"flag"`, `flags "flag"`, "import alias"},
		{"type once struct", "var shared bool\ntype once struct", "global state"},
		{"type once struct", "func init() {}\ntype once struct", "initialization effect"},
		{"type once struct", "//go:build linux\ntype once struct", "compiler directive"},
		{"return flags.Parse(arguments)", "go flags.Parse(arguments); return nil", "task or channel ownership"},
		{"return flags.Parse(arguments)", "defer flags.Parse(arguments); return nil", "task or channel ownership"},
		{"return flags.Parse(arguments)", "select {}; return nil", "task or channel ownership"},
		{"set bool", "set bool; pending chan int", "task or channel ownership"},
		{"return flags.Parse(arguments)", "pending <- 1; return nil", "task or channel ownership"},
		{"return flags.Parse(arguments)", "<-pending; return nil", "channel receive"},
		{"return flags.Parse(arguments)", "panic(arguments)", "undeclared call"},
		{"return flags.Parse(arguments)", "return indirect(arguments)", "undeclared call"},
		{"return flags.Parse(arguments)", "flags.Parse(arguments); return flags.Parse(arguments)", "undeclared call"},
	}
	for _, control := range controls {
		if strings.Count(string(source), control.before) != 1 {
			t.Fatalf("effect control anchor changed: %q", control.before)
		}
		changed := strings.Replace(string(source), control.before, control.after, 1)
		if _, err := parser.ParseFile(token.NewFileSet(), "flags.go", changed, 0); err != nil {
			t.Fatalf("invalid effect control: %v", err)
		}
		if err := isolation([]byte(changed)); err == nil || err.Error() != control.reason {
			t.Fatalf("effect control %q escaped or failed for another reason: %v", control.reason, err)
		}
	}
	t.Logf(`ASTRA-CONTRACT {"contract":"COMMAND-ISOLATION","hits":%d}`, len(controls)+1)
	t.Logf(`ASTRA-CONTRACT {"contract":"COMMAND-DECISION-INVENTORY","hits":%d}`, len(actual)+3)
	// Structural qualification additionally requires the runner's complete native statement profile.
	t.Logf(`ASTRA-CONTRACT {"contract":"COMMAND-ASSURANCE","hits":%d}`, len(actual)+3)
}

// TestDecisions exercises both one-condition decisions and all three feasible rows of the optional-boolean conjunction.
func TestDecisions(t *testing.T) {
	hits := 0
	check := func(condition bool) {
		t.Helper()
		if !condition {
			t.Fatal("command decision contract violated")
		}
		hits++
	}
	// Rows contain observed inputs/results. Pair indices declare the independently fixed witnesses, not fabricated counters.
	report := func(id string, rows []map[string]any, pairs [][2]int, conditions []string, outcome string) {
		t.Helper()
		for index, pair := range pairs {
			left, right := rows[pair[0]], rows[pair[1]]
			target := conditions[index%len(conditions)]
			independent := left[target] != right[target] && left[outcome] != right[outcome]
			for _, other := range conditions {
				if other != target && left[other] != right[other] {
					// Only the absent optional interface may mask evaluation of its delegated boolean.
					independent = independent && id == "boolean" && other == "value" &&
						(left[other] == nil && left["interface"] == false || right[other] == nil && right["interface"] == false)
				}
			}
			check(independent)
		}
		encoded, err := json.Marshal(map[string]any{"id": id, "conditions": conditions, "outcome": outcome, "rows": rows, "pairs": pairs, "mode": "short-circuit-masking"})
		if err != nil {
			t.Fatal(err)
		}
		t.Log("COMMAND-DECISION " + string(encoded))
	}
	// String's nil condition changes the selected result and delegate count; an empty delegate string would be a weak oracle.
	plain := &operand{}
	var rows []map[string]any
	for index, input := range []flag.Value{nil, plain} {
		wrapped := &once{Value: input}
		missing := wrapped.Value == nil
		result := wrapped.String()
		check(result == []string{"", "visible"}[index] && plain.reads == index)
		rows = append(rows, map[string]any{"nil": missing, "fallback": result == ""})
	}
	report("string", rows, [][2]int{{0, 1}}, []string{"nil"}, "fallback")
	// Set's consumed condition changes admission. Underlying failure consumes the same single attempt and retains error identity.
	rejected := errors.New("registered value rejected input")
	rows = nil
	for _, failure := range []error{nil, rejected} {
		target := &operand{err: failure}
		wrapped := &once{Value: target}
		consumed := wrapped.set
		result := wrapped.Set("first")
		check(result == failure && target.writes == 1 && wrapped.set)
		rows = append(rows, map[string]any{"consumed": consumed, "blocked": target.writes == 0})
		consumed = wrapped.set
		before := target.writes
		result = wrapped.Set("second")
		check(result != nil && target.writes == 1 && wrapped.set)
		rows = append(rows, map[string]any{"consumed": consumed, "blocked": target.writes == before})
	}
	report("set", rows, [][2]int{{0, 1}, {2, 3}}, []string{"consumed"}, "blocked")
	// A absent/B unevaluated, A present/B false, A present/B true. The first pair uses B masked by short-circuiting.
	result := (&once{Value: plain}).IsBoolFlag()
	check(!result)
	rows = []map[string]any{{"interface": false, "value": nil, "result": result}}
	for _, enabled := range []bool{false, true} {
		target := &boolean{result: enabled}
		result := (&once{Value: target}).IsBoolFlag()
		check(result == enabled && target.calls == 1)
		rows = append(rows, map[string]any{"interface": true, "value": target.result, "result": result, "calls": target.calls})
	}
	report("boolean", rows, [][2]int{{0, 2}, {1, 2}}, []string{"interface", "value"}, "result")
	check(hits == 14)
	t.Logf(`ASTRA-CONTRACT {"contract":"COMMAND-MCDC","hits":%d}`, hits)
}
