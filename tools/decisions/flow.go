// Observe loop entry/exhaustion and selected communication arms in a separate diagnostic overlay.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
)

// edge identifies a loop or communication arm in the original, uninstrumented source.
type edge struct {
	ID     string   `json:"id"`     // Source file and original byte offset.
	Kind   string   `json:"kind"`   // range, for, loop, or select-arm.
	Parent string   `json:"parent"` // Containing control identity; a loop is its own parent.
	Begin  position `json:"begin"`  // Original start coordinate.
	End    position `json:"end"`    // Original end coordinate.
}

// flow leaves expressions and channel operations intact; diagnostic defers observe local loop completion.
// Unlabeled breaks retain their actual target; switches require an explicit default for complete arm accounting.
func flow(name string, data []byte) ([]byte, []edge, error) {
	positions := token.NewFileSet()
	file, err := parser.ParseFile(positions, name, data, parser.AllErrors)
	if err != nil {
		return nil, nil, err
	}
	unsafe := false
	parents := []ast.Node{}
	breaks := map[ast.Node][]token.Pos{}
	ast.Inspect(file, func(node ast.Node) bool {
		if node == nil {
			parents = parents[:len(parents)-1]
			return false
		}
		switch value := node.(type) {
		case *ast.Ident:
			unsafe = unsafe || strings.HasPrefix(value.Name, "astraProbe") || value.Name == "recover"
		case *ast.LabeledStmt:
			unsafe = true
		case *ast.SwitchStmt:
			unsafe = unsafe || !fallback(value.Body)
		case *ast.TypeSwitchStmt:
			unsafe = unsafe || !fallback(value.Body)
		case *ast.SelectStmt:
			unsafe = unsafe || len(value.Body.List) == 0
		case *ast.BranchStmt:
			unsafe = unsafe || value.Tok != token.CONTINUE && value.Tok != token.BREAK || value.Label != nil
			if value.Tok == token.BREAK && value.Label == nil {
				found := false
				for index := len(parents) - 1; index >= 0; index-- {
					switch parent := parents[index].(type) {
					case *ast.ForStmt, *ast.RangeStmt:
						breaks[parent] = append(breaks[parent], value.Pos())
						found = true
					case *ast.SelectStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt:
						found = true
					case *ast.FuncDecl, *ast.FuncLit:
						index = 0
					}
					if found {
						break
					}
				}
				unsafe = unsafe || !found
			}
		}
		parents = append(parents, node)
		return true
	})
	if unsafe {
		return nil, nil, errors.New("flow-unsupported-control")
	}
	locate := func(value token.Pos) position {
		point := positions.PositionFor(value, false)
		return position{point.Offset, point.Line, point.Column}
	}
	insertions, edges := map[int]string{}, []edge{}
	insert := func(point token.Pos, text string) { insertions[locate(point).Offset] += text }
	loop := func(kind string, node ast.Node, body *ast.BlockStmt) {
		begin, end := locate(node.Pos()), locate(node.End())
		id, state := fmt.Sprintf("%s:%d", name, begin.Offset), fmt.Sprintf("astraProbeLoop%d", begin.Offset)
		edges = append(edges, edge{id, kind, id, begin, end})
		// A fresh lexical scope gives each dynamic nested invocation its own state captured by its defer.
		initial, view, finish := "[2]byte{1,1}", "[:]", state+"[1]=2;"
		if kind != "loop" && len(breaks[node]) != 0 {
			initial, view, finish = "[3]byte{1,1,1}", "[:2]", "if "+state+"[2]==1 {"+state+"[1]=2};"
			for _, point := range breaks[node] {
				insert(point, state+"[2]=0; ")
			}
		}
		insert(node.Pos(), fmt.Sprintf("{ %s := %s; defer func(){ astraProbeRecord(%s,%s%s,%s[1]==2) }(); ", state, initial, strconv.Quote(id), state, view, state))
		insert(body.Lbrace+1, state+"[0]=2;\n")
		if kind == "loop" {
			// Keep an unconditional loop terminating in Go's control-flow grammar; it cannot exhaust.
			insert(node.End(), " }")
		} else {
			insert(node.End(), "; "+finish+" }")
		}
	}
	branch := func(kind string, node ast.Node, body *ast.BlockStmt) {
		parent := fmt.Sprintf("%s:%d", name, locate(node.Pos()).Offset)
		for _, statement := range body.List {
			arm := statement.(*ast.CaseClause)
			begin, end := locate(arm.Pos()), locate(arm.End())
			id := fmt.Sprintf("%s:%d", name, begin.Offset)
			edges = append(edges, edge{id, kind, parent, begin, end})
			insert(arm.Colon+1, "astraProbeRecord("+strconv.Quote(id)+",[]byte{2},true);\n")
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.RangeStmt:
			loop("range", value, value.Body)
		case *ast.ForStmt:
			kind := "for"
			if value.Cond == nil {
				kind = "loop"
			}
			loop(kind, value, value.Body)
		case *ast.SelectStmt:
			parent := fmt.Sprintf("%s:%d", name, locate(value.Pos()).Offset)
			for _, statement := range value.Body.List {
				arm := statement.(*ast.CommClause)
				begin, end := locate(arm.Pos()), locate(arm.End())
				id := fmt.Sprintf("%s:%d", name, begin.Offset)
				edges = append(edges, edge{id, "select-arm", parent, begin, end})
				insert(arm.Colon+1, "astraProbeRecord("+strconv.Quote(id)+",[]byte{2},true);\n")
			}
		case *ast.SwitchStmt:
			branch("switch-arm", value, value.Body)
		case *ast.TypeSwitchStmt:
			branch("type-arm", value, value.Body)
		}
		return true
	})
	sort.Slice(edges, func(a, b int) bool { return edges[a].Begin.Offset < edges[b].Begin.Offset })
	points := make([]int, 0, len(insertions))
	for point := range insertions {
		points = append(points, point)
	}
	sort.Ints(points)
	var output bytes.Buffer
	cursor := 0
	for _, point := range points {
		output.Write(data[cursor:point])
		output.WriteString(insertions[point])
		cursor = point
	}
	output.Write(data[cursor:])
	formatted, err := format.Source(output.Bytes())
	return formatted, edges, err
}

// fallback rejects an implicit unmatched path until that path has a separate native observation contract.
func fallback(body *ast.BlockStmt) bool {
	for _, statement := range body.List {
		if len(statement.(*ast.CaseClause).List) == 0 {
			return true
		}
	}
	return false
}
