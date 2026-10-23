// Enumerate owned numerical expressions and implicit arithmetic from authenticated native Go types.
package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"runtime"
	"sort"
)

// number identifies a typed numerical use or an operation whose bounds require a domain proof.
type number struct {
	File   string `json:"file"`   // Root-relative owned source.
	Line   int    `json:"line"`   // One-based source line.
	Column int    `json:"column"` // One-based byte column.
	Begin  int    `json:"begin"`  // UTF-8 byte offset inclusive.
	End    int    `json:"end"`    // UTF-8 byte offset exclusive.
	Scope  string `json:"scope"`  // Named owning function, or package declarations.
	Kind   string `json:"kind"`   // Expression/binding or explicit implicit-operation class.
	Type   string `json:"type"`   // Native Go type spelling; no inferred numerical width.
	Text   string `json:"text"`   // Exact original bytes at the stated range.
}

// numerical retains compiler inputs separately from any qualification or range conclusion.
type numerical struct {
	Version       int      `json:"version"`       // Native inventory format.
	SourceSHA256  string   `json:"source_sha256"` // Consumed source manifest digest.
	OS            string   `json:"os"`            // Host running this native collector.
	Architecture  string   `json:"architecture"`  // Host ABI used by go/types sizes.
	Runtime       string   `json:"runtime"`       // Actual Go runtime version.
	Typing        typing   `json:"typing"`        // Complete active/inactive inputs and consumed exports.
	Scanned       int      `json:"scanned"`       // All expression and binding objects examined.
	Nodes         []number `json:"nodes"`         // Sorted typed uses and implicit operations.
	Qualification string   `json:"qualification"` // Always not-evaluated; requires an independent domain proof.
}

// numeric classifies named/aliased basic numerical types without guessing from source spelling.
func numeric(value types.Type) bool {
	if value == nil {
		return false
	}
	basic, ok := value.Underlying().(*types.Basic)
	return ok && basic.Info()&types.IsNumeric != 0
}

// numbers includes comparisons, compound stores, increments, range indices and slices that have no numerical result node.
func numbers(root, directory string, metadata []byte, collection report) (numerical, error) {
	result := numerical{Version: 1, SourceSHA256: collection.SourceSHA256, OS: runtime.GOOS, Architecture: runtime.GOARCH, Runtime: runtime.Version(), Nodes: []number{}, Qualification: "not-evaluated"}
	checked, err := inspectTypes(root, directory, metadata, collection, false, func(positions *token.FileSet, parsed map[string]*ast.File, facts *types.Info) error {
		result.Scanned = len(facts.Types) + len(facts.Defs)
		if result.Scanned == 0 {
			return errors.New("numeric-empty-types")
		}
		originals := map[string][]byte{}
		for name := range parsed {
			data, err := read(filepath.Join(root, filepath.FromSlash(name)), 32<<20)
			if err != nil {
				return err
			}
			originals[name] = data
		}
		appendNode := func(node ast.Node, kind string, value types.Type) {
			begin, end := positions.PositionFor(node.Pos(), false), positions.PositionFor(node.End(), false)
			owner := "<package>"
			for _, declaration := range parsed[begin.Filename].Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || node.Pos() < function.Pos() || node.End() > function.End() {
					continue
				}
				owner = function.Name.Name
				if function.Recv != nil {
					receiver := function.Recv.List[0].Type
					if pointer, ok := receiver.(*ast.StarExpr); ok {
						receiver = pointer.X
					}
					if name, ok := receiver.(*ast.Ident); ok {
						owner = name.Name + "." + owner
					}
				}
				break
			}
			result.Nodes = append(result.Nodes, number{begin.Filename, begin.Line, begin.Column, begin.Offset, end.Offset, owner, kind, value.String(), string(originals[begin.Filename][begin.Offset:end.Offset])})
		}
		for node, value := range facts.Types {
			if numeric(value.Type) {
				appendNode(node, fmt.Sprintf("%T", node), value.Type)
			}
		}
		for node, object := range facts.Defs {
			if object != nil && numeric(object.Type()) {
				appendNode(node, "binding", object.Type())
			}
		}
		for _, file := range parsed {
			ast.Inspect(file, func(node ast.Node) bool {
				switch value := node.(type) {
				case *ast.BinaryExpr:
					if !numeric(facts.TypeOf(value)) && (numeric(facts.TypeOf(value.X)) || numeric(facts.TypeOf(value.Y))) {
						appendNode(value, "comparison", facts.TypeOf(value))
					}
				case *ast.AssignStmt:
					if value.Tok != token.ASSIGN && value.Tok != token.DEFINE && len(value.Lhs) == 1 && numeric(facts.TypeOf(value.Lhs[0])) {
						appendNode(value, "assignment:"+value.Tok.String(), facts.TypeOf(value.Lhs[0]))
					}
				case *ast.IncDecStmt:
					if numeric(facts.TypeOf(value.X)) {
						appendNode(value, "increment:"+value.Tok.String(), facts.TypeOf(value.X))
					}
				case *ast.RangeStmt:
					for _, field := range []ast.Expr{value.Key, value.Value} {
						if field != nil && numeric(facts.TypeOf(field)) {
							appendNode(field, "range", facts.TypeOf(field))
						}
					}
				case *ast.SliceExpr:
					appendNode(value, "slice", facts.TypeOf(value))
				case *ast.IndexExpr:
					if !numeric(facts.TypeOf(value)) && numeric(facts.TypeOf(value.Index)) {
						appendNode(value, "index", facts.TypeOf(value))
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		return numerical{}, err
	}
	result.Typing = checked
	sort.Slice(result.Nodes, func(left, right int) bool {
		a, b := result.Nodes[left], result.Nodes[right]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Begin != b.Begin {
			return a.Begin < b.Begin
		}
		if a.End != b.End {
			return a.End < b.End
		}
		return a.Kind < b.Kind
	})
	return result, nil
}
