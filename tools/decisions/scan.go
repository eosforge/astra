// Enumerate owned Go source decisions and control forms without inferring coverage from test counts.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"sort"
	"strings"
)

// position binds an expression to native byte offsets and human-readable source coordinates.
type position struct {
	Offset int `json:"offset"` // Byte offset in the original UTF-8 source.
	Line   int `json:"line"`   // One-based line.
	Column int `json:"column"` // One-based byte column.
}

// expression describes Boolean structure; leaves retain their original independently evaluated atom.
type expression struct {
	Kind     string `json:"kind"`               // atom, and, or, or not.
	Atom     *int   `json:"atom,omitempty"`     // Index in the containing decision's ordered atom list.
	Children []int  `json:"children,omitempty"` // Earlier node indices in source order; no recursive JSON nesting.
}

// atom identifies one syntactic operand, retaining repeated expressions as separate occurrences.
type atom struct {
	Text  string   `json:"text"`  // Native Go formatting of the operand.
	Begin position `json:"begin"` // Inclusive location.
	End   position `json:"end"`   // Exclusive location.
}

// decision binds each Boolean root to its short-circuit tree without manufacturing observed outcomes.
type decision struct {
	ID    string       `json:"id"`    // File and byte offset form a source-version-specific identity.
	Kind  string       `json:"kind"`  // if, for, case, boolean, or return.
	Text  string       `json:"text"`  // Canonical expression, preserving operand order.
	Begin position     `json:"begin"` // Inclusive location.
	End   position     `json:"end"`   // Exclusive location.
	Tree  []expression `json:"tree"`  // Flat postorder structure used by later observed-pair verification.
	Root  int          `json:"root"`  // Final node in the flat tree.
	Atoms []atom       `json:"atoms"` // Every syntactic occurrence, including coupled operands.
}

// control retains non-Boolean choices that need a separate branch, lifecycle, or progress oracle.
type control struct {
	Kind  string   `json:"kind"`  // switch, type-switch, select, range, loop, go, or defer.
	Begin position `json:"begin"` // Source span start.
	End   position `json:"end"`   // Source span end.
}

// callable includes declarations and closures even when tests never reach them.
type callable struct {
	Name  string   `json:"name"`  // Declared symbol or position-bound closure.
	Begin position `json:"begin"` // Source span start.
	End   position `json:"end"`   // Source span end.
}

// inventory is a syntactic denominator, not a typed all-path or MC/DC report.
type inventory struct {
	File      string     `json:"file"`      // Root-relative original input path.
	SHA256    string     `json:"sha256"`    // Digest of bytes actually parsed.
	Functions []callable `json:"functions"` // Native callable inventory.
	Decisions []decision `json:"decisions"` // Boolean roots selected by the declared syntax rules.
	Controls  []control  `json:"controls"`  // Other control forms remain explicitly unsupported by Boolean pairs.
}

// scan parses one exact source input, deduplicating overlapping roots without removing repeated atoms.
func scan(name string, data []byte) (inventory, error) {
	positions := token.NewFileSet()
	file, err := parser.ParseFile(positions, name, data, parser.AllErrors)
	if err != nil {
		return inventory{}, err
	}
	digest := sha256.Sum256(data)
	result := inventory{File: name, SHA256: hex.EncodeToString(digest[:]), Functions: []callable{}, Decisions: []decision{}, Controls: []control{}}
	locate := func(offset token.Pos) position {
		actual := positions.PositionFor(offset, false)
		return position{Offset: actual.Offset, Line: actual.Line, Column: actual.Column}
	}
	show := func(node ast.Node) string {
		var buffer bytes.Buffer
		if err := format.Node(&buffer, positions, node); err != nil {
			panic(err) // A parsed, unmodified AST must remain printable.
		}
		return buffer.String()
	}
	var tree func(ast.Expr, *[]atom, *[]expression) int
	tree = func(value ast.Expr, atoms *[]atom, nodes *[]expression) int {
		appendNode := func(node expression) int {
			index := len(*nodes)
			*nodes = append(*nodes, node)
			return index
		}
		switch node := value.(type) {
		case *ast.ParenExpr:
			return tree(node.X, atoms, nodes)
		case *ast.BinaryExpr:
			if node.Op == token.LAND || node.Op == token.LOR {
				kind := "and"
				if node.Op == token.LOR {
					kind = "or"
				}
				return appendNode(expression{Kind: kind, Children: []int{tree(node.X, atoms, nodes), tree(node.Y, atoms, nodes)}})
			}
		case *ast.UnaryExpr:
			if node.Op == token.NOT {
				return appendNode(expression{Kind: "not", Children: []int{tree(node.X, atoms, nodes)}})
			}
		}
		index := len(*atoms)
		*atoms = append(*atoms, atom{Text: show(value), Begin: locate(value.Pos()), End: locate(value.End())})
		return appendNode(expression{Kind: "atom", Atom: &index})
	}
	// Explicit branch roots take precedence over nested logical/comparison nodes.
	covered := map[ast.Expr]bool{}
	add := func(kind string, value ast.Expr) {
		if value == nil || covered[value] {
			return
		}
		atoms := []atom{}
		nodes := []expression{}
		root := tree(value, &atoms, &nodes)
		begin, end := locate(value.Pos()), locate(value.End())
		result.Decisions = append(result.Decisions, decision{ID: fmt.Sprintf("%s:%d", name, begin.Offset), Kind: kind, Text: show(value), Begin: begin, End: end, Tree: nodes, Root: root, Atoms: atoms})
		// Mark only the logical tree and its atomic roots. Boolean call arguments and closure bodies remain independent roots.
		var mark func(ast.Expr)
		mark = func(expression ast.Expr) {
			covered[expression] = true
			switch node := expression.(type) {
			case *ast.ParenExpr:
				mark(node.X)
			case *ast.BinaryExpr:
				if node.Op == token.LAND || node.Op == token.LOR {
					mark(node.X)
					mark(node.Y)
				}
			case *ast.UnaryExpr:
				if node.Op == token.NOT {
					mark(node.X)
				}
			}
		}
		mark(value)
	}
	retain := func(kind string, value ast.Node) {
		result.Controls = append(result.Controls, control{Kind: kind, Begin: locate(value.Pos()), End: locate(value.End())})
	}
	returns := func(body *ast.BlockStmt, result *ast.FieldList) {
		if body == nil || result == nil || len(result.List) != 1 {
			return
		}
		declared, ok := result.List[0].Type.(*ast.Ident)
		if !ok || declared.Name != "bool" {
			return
		}
		ast.Inspect(body, func(inner ast.Node) bool {
			if _, closure := inner.(*ast.FuncLit); closure {
				return false
			}
			if returned, ok := inner.(*ast.ReturnStmt); ok && len(returned.Results) == 1 {
				add("return", returned.Results[0])
			}
			return true
		})
	}
	ast.Inspect(file, func(value ast.Node) bool {
		switch node := value.(type) {
		case *ast.FuncDecl:
			name := node.Name.Name
			if node.Recv != nil {
				name = show(node.Recv.List[0].Type) + "." + name
			}
			result.Functions = append(result.Functions, callable{Name: name, Begin: locate(node.Pos()), End: locate(node.End())})
			// A literal bool result supplies type information without importing or executing dependencies.
			returns(node.Body, node.Type.Results)
		case *ast.FuncLit:
			result.Functions = append(result.Functions, callable{Name: fmt.Sprintf("closure@%d", locate(node.Pos()).Offset), Begin: locate(node.Pos()), End: locate(node.End())})
			returns(node.Body, node.Type.Results)
		case *ast.IfStmt:
			add("if", node.Cond)
		case *ast.ForStmt:
			if node.Cond == nil {
				retain("loop", node)
			} else {
				add("for", node.Cond)
			}
		case *ast.SwitchStmt:
			// Every switch owns its explicit arms, including the default of a tagless Boolean switch.
			retain("switch", node)
			if node.Tag == nil {
				for _, statement := range node.Body.List {
					for _, condition := range statement.(*ast.CaseClause).List {
						add("case", condition)
					}
				}
			}
		case *ast.TypeSwitchStmt:
			retain("type-switch", node)
		case *ast.SelectStmt:
			retain("select", node)
		case *ast.RangeStmt:
			retain("range", node)
		case *ast.GoStmt:
			retain("go", node)
		case *ast.DeferStmt:
			retain("defer", node)
		}
		return true
	})
	// Native preorder chooses each outer Boolean expression before its covered subexpressions.
	ast.Inspect(file, func(value ast.Node) bool {
		expression, ok := value.(ast.Expr)
		if !ok || covered[expression] {
			return true
		}
		switch node := expression.(type) {
		case *ast.BinaryExpr:
			if strings.Contains(" == != < > <= >= && || ", " "+node.Op.String()+" ") {
				add("boolean", expression)
			}
		case *ast.UnaryExpr:
			if node.Op == token.NOT {
				add("boolean", expression)
			}
		}
		return true
	})
	sort.Slice(result.Decisions, func(left, right int) bool {
		return result.Decisions[left].Begin.Offset < result.Decisions[right].Begin.Offset
	})
	sort.Slice(result.Functions, func(left, right int) bool {
		return result.Functions[left].Begin.Offset < result.Functions[right].Begin.Offset
	})
	sort.Slice(result.Controls, func(left, right int) bool {
		return result.Controls[left].Begin.Offset < result.Controls[right].Begin.Offset
	})
	return result, nil
}
