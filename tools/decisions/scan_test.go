// Verify native Go decision enumeration against explicit syntax, ownership and malformed-input counterexamples.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestTree freezes source-order atoms and nested short-circuit structure independently of scanner traversal.
func TestTree(t *testing.T) {
	source := []byte("package example\nfunc Allowed(a,b,c bool) bool { if (a && !b) || c { return true }; return false }\n")
	actual, err := scan("state.go", source)
	if err != nil || len(actual.Functions) != 1 || len(actual.Decisions) != 3 || len(actual.Controls) != 0 {
		t.Fatalf("inventory mismatch: %+v %v", actual, err)
	}
	root := actual.Decisions[0]
	var texts []string
	for _, item := range root.Atoms {
		texts = append(texts, item.Text)
		if string(source[item.Begin.Offset:item.End.Offset]) != item.Text {
			t.Fatal("atom source identity lost")
		}
	}
	if root.Kind != "if" || root.Text != "(a && !b) || c" || !reflect.DeepEqual(texts, []string{"a", "b", "c"}) {
		t.Fatalf("ordered atom mismatch: %+v", root)
	}
	first, second, third := 0, 1, 2
	expected := []expression{{Kind: "atom", Atom: &first}, {Kind: "atom", Atom: &second}, {Kind: "not", Children: []int{1}},
		{Kind: "and", Children: []int{0, 2}}, {Kind: "atom", Atom: &third}, {Kind: "or", Children: []int{3, 4}}}
	if root.Root != 5 || !reflect.DeepEqual(root.Tree, expected) || root.ID != fmt.Sprintf("state.go:%d", bytes.Index(source, []byte("(a &&"))) {
		t.Fatal("Boolean structure/source identity mismatch")
	}
	if actual.Decisions[1].Kind != "return" || actual.Decisions[1].Text != "true" || actual.Decisions[2].Text != "false" {
		t.Fatal("constant returns disappeared")
	}
}

// TestFlatTree retains a long compound decision while remaining below the existing gate's JSON nesting limit.
func TestFlatTree(t *testing.T) {
	operands := make([]string, 64)
	for index := range operands {
		operands[index] = "value"
	}
	actual, err := scan("long.go", []byte("package example\nfunc Check(value bool)bool { return "+strings.Join(operands, " && ")+" }\n"))
	if err != nil || len(actual.Decisions) != 1 {
		t.Fatalf("long source rejected: %v", err)
	}
	root := actual.Decisions[0]
	if len(root.Atoms) != 64 || len(root.Tree) != 127 || root.Root != 126 {
		t.Fatal("long tree was truncated")
	}
	for index, node := range root.Tree {
		for _, child := range node.Children {
			if child < 0 || child >= index {
				t.Fatal("flat tree is not postorder")
			}
		}
	}
	encoded, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	var value any
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
	var depth func(any) int
	depth = func(value any) int {
		maximum := 0
		switch children := value.(type) {
		case map[string]any:
			for _, child := range children {
				maximum = max(maximum, depth(child))
			}
		case []any:
			for _, child := range children {
				maximum = max(maximum, depth(child))
			}
		default:
			return 0
		}
		return maximum + 1
	}
	if depth(value) > 32 {
		t.Fatal("native report exceeds the fixed gate JSON depth")
	}
}

// TestControls retains every explicitly unsupported branch/lifecycle form rather than excluding it from the report.
func TestControls(t *testing.T) {
	input := []byte(`package example
func Work(value any, channel chan int, values []int) {
for { break }
for index:=0; index<3; index++ {}
for range values {}
switch value { case nil: }
switch value.(type) { case int: }
switch { case len(values)>0 && value!=nil: }
select { case <-channel: default: }
go func(){ if value!=nil {} }()
defer func(){}()
}`)
	actual, err := scan("control.go", input)
	if err != nil {
		t.Fatal(err)
	}
	var controls, decisions []string
	for _, item := range actual.Controls {
		controls = append(controls, item.Kind)
	}
	for _, item := range actual.Decisions {
		decisions = append(decisions, item.Kind+":"+item.Text)
	}
	if !reflect.DeepEqual(controls, []string{"loop", "range", "switch", "type-switch", "switch", "select", "go", "defer"}) {
		t.Fatalf("control inventory mismatch: %v", controls)
	}
	if !reflect.DeepEqual(decisions, []string{"for:index < 3", "case:len(values) > 0 && value != nil", "if:value != nil"}) || len(actual.Functions) != 3 {
		t.Fatalf("decision/function inventory mismatch: %v %+v", decisions, actual.Functions)
	}
}

// TestExpressions distinguishes Boolean arguments, repeated/coupled atoms, receivers and closure execution domains.
func TestExpressions(t *testing.T) {
	input := []byte(`package example
type Value struct{}
func (*Value) Check(a,b bool, call func(bool)bool) bool {
x:=a && a
if call(a!=b) && func()bool { if a { return b }; return false }() { return x }
return !x
}`)
	actual, err := scan("expressions.go", input)
	if err != nil {
		t.Fatal(err)
	}
	if actual.Functions[0].Name != "*Value.Check" || len(actual.Functions) != 2 {
		t.Fatal("receiver or closure lost")
	}
	var texts []string
	for _, item := range actual.Decisions {
		texts = append(texts, item.Kind+":"+item.Text)
	}
	expected := []string{"boolean:a && a", "if:call(a != b) && func() bool {\n\tif a {\n\t\treturn b\n\t}\n\treturn false\n}()", "boolean:a != b", "if:a", "return:b", "return:false", "return:x", "return:!x"}
	if !reflect.DeepEqual(texts, expected) || actual.Decisions[0].Atoms[0].Text != "a" || actual.Decisions[0].Atoms[1].Text != "a" {
		t.Fatalf("independent expression roots changed: %q", texts)
	}
	changed, err := scan("expressions.go", bytes.Replace(input, []byte("a && a"), []byte("a || a"), 1))
	if err != nil || changed.SHA256 == actual.SHA256 || reflect.DeepEqual(changed.Decisions[0].Tree, actual.Decisions[0].Tree) {
		t.Fatal("source/operator drift undetected")
	}
	if _, err := scan("bad.go", []byte("package example\nfunc Broken( {")); err == nil {
		t.Fatal("malformed source accepted")
	}
}

// fixture binds actual temporary files, including inactive-platform code and an intentionally misplaced generated marker.
func fixture(t *testing.T) (string, []byte) {
	t.Helper()
	root := t.TempDir()
	contents := map[string]string{
		"state.go":         "package example\nfunc Check(a bool)bool { if a { return true }; return false }\n",
		"state_windows.go": "//go:build windows\npackage example\nfunc Other()bool { return true }\n",
		"state_test.go":    "package example\n",
		"generated.go":     "// Code generated fixture. DO NOT EDIT.\npackage example\n",
		"marker.go":        "package example\n// Code generated misplaced. DO NOT EDIT.\nfunc Visible()bool { return false }\n",
	}
	manifest := source{Files: []input{}}
	for name, content := range contents {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte(content))
		encoded := hex.EncodeToString(digest[:])
		manifest.Files = append(manifest.Files, input{Path: name, SHA256: &encoded})
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return root, data
}

// TestManifest checks complete ownership, inactive platforms, exact bytes and strict duplicate/missing fields.
func TestManifest(t *testing.T) {
	root, data := fixture(t)
	actual, err := collect(root, data)
	if err != nil || len(actual.Files) != 3 || !reflect.DeepEqual(actual.Generated, []string{"generated.go"}) || !reflect.DeepEqual(actual.Tests, []string{"state_test.go"}) {
		t.Fatalf("ownership inventory mismatch: %+v %v", actual, err)
	}
	if actual.Files[0].File != "marker.go" || actual.Files[2].File != "state_windows.go" || actual.Qualification != "not-evaluated" {
		t.Fatal("owned source hidden or false qualification")
	}
	// A duplicate-key negative must otherwise be a valid nonempty manifest, so another rejection cannot hide a broken guard.
	duplicate := bytes.Replace(data, []byte(`"status":""`), []byte(`"status":"","status":""`), 1)
	if bytes.Equal(duplicate, data) {
		t.Fatal("duplicate-key fixture did not reach the intended field")
	}
	if _, err := collect(root, duplicate); err == nil || err.Error() != "duplicate-key" {
		t.Fatalf("duplicate guard did not reject the actual repeated field: %v", err)
	}
	for _, invalid := range []string{
		`{"commit":null,"status":"","files":[],"status":""}`,
		`{"commit":null,"status":"","files":[],"extra":1}`,
		`{"commit":null,"status":""}`,
		`{"commit":null,"status":"","files":[{"path":"state.go"}]}`,
		`{"commit":null,"status":"","files":[{"path":"state.go","sha256":null,"extra":1}]}`,
		`{"commit":null,"status":"","files":[]} trailing`,
		`{"commit":null,"status":"","files":[]}`,
		`{"commit":null,"status":"","files":` + strings.Repeat("[", 66) + strings.Repeat("]", 66) + `}`,
	} {
		if _, err := collect(root, []byte(invalid)); err == nil {
			t.Fatalf("invalid manifest accepted: %s", invalid)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "state.go"), []byte("package changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := collect(root, data); err == nil || !strings.Contains(err.Error(), "source-drift") {
		t.Fatalf("source drift accepted: %v", err)
	}
}

// TestBoundary rejects traversal/aliases, dangling links, oversized inputs and unrequested CLI arguments.
func TestBoundary(t *testing.T) {
	root, data := fixture(t)
	for _, name := range []string{"", "../state.go", "/state.go", "state.go/../state.go", "./state.go", "state.go//child", "state.go\\child", "a:state.go", "missing.go"} {
		if _, err := inside(root, name); err == nil {
			t.Fatalf("unsafe path accepted: %s", name)
		}
	}
	if _, err := read(filepath.Join(root, "state.go"), 2); err == nil {
		t.Fatal("size limit ignored")
	}
	manifest := filepath.Join(root, "source.json")
	if err := os.WriteFile(manifest, data, 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run([]string{"--root", root, "--source", manifest}, &stdout, &stderr); err != nil || !bytes.Contains(stdout.Bytes(), []byte(`"qualification":"not-evaluated"`)) {
		t.Fatalf("native collection rejected: %v", err)
	}
	for _, arguments := range [][]string{{"--root", ".", "--source", manifest}, {"--root", root, "--source", manifest, "extra"}, {"--unknown"}} {
		stdout.Reset()
		if err := run(arguments, &stdout, &stderr); err == nil || stdout.Len() != 0 {
			t.Fatal("invalid CLI produced success output")
		}
	}
	// Linux native verification must exercise the actual symlink boundary; Windows without link privilege fails explicitly.
	link := filepath.Join(root, "alias.go")
	if err := os.Symlink(filepath.Join(root, "state.go"), link); err != nil {
		t.Fatal(err)
	}
	if _, err := inside(root, "alias.go"); err == nil || err.Error() != "path-symlink" {
		t.Fatalf("symlink consumed: %v", err)
	}
}
