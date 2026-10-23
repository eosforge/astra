// Verify the five pure input-validation decisions with independent condition witnesses and an explicit source denominator.
//go:build linux && cgo

package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// decision records immutable input predicates and the result obtained from the production validator.
type decision struct {
	Name   string `json:"name"`   // Stable case identity within one decision.
	Values []any  `json:"values"` // Semantic input predicates; nil denotes only Scan's unreachable length check.
	Result bool   `json:"result"` // Actual validator result, or Scan's rejection result.
	Input  any    `json:"input"`  // Exact source inputs; invalid text is represented as bytes.
}

// decisions checks fixed independent witnesses; it never derives expected results from production output.
func decisions(t *testing.T, id string, conditions []string, rows []decision, pairs [][2]int) {
	t.Helper()
	if len(conditions) != len(pairs) || len(rows) == 0 {
		t.Fatal("missing condition witnesses")
	}
	for index, pair := range pairs {
		left, right := rows[pair[0]], rows[pair[1]]
		if len(left.Values) != len(conditions) || len(right.Values) != len(conditions) || left.Values[index] == right.Values[index] || left.Result == right.Result {
			t.Fatalf("condition %s has no independent result change", conditions[index])
		}
		for other := range conditions {
			if other == index || left.Values[other] == right.Values[other] {
				continue
			}
			// A failed type assertion prevents evaluating len(bytes); the zero-value slice is not a second observed condition.
			masked := id == "scan" && index == 0 && other == 1 &&
				(left.Values[0] == true && left.Values[1] == nil || right.Values[0] == true && right.Values[1] == nil)
			if !masked {
				t.Fatalf("witness for %s changes another unmasked predicate", conditions[index])
			}
		}
	}
	encoded, err := json.Marshal(map[string]any{"id": id, "conditions": conditions, "rows": rows, "pairs": pairs, "basis": "immutable semantic inputs; scan type/length uses short-circuit masking"})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("STORAGE-DECISION " + string(encoded))
}

// TestDecisions covers each declared validator condition without SQLite, sleeps, random input or a replacement state machine.
func TestDecisions(t *testing.T) {
	t.Run("text", func(t *testing.T) {
		inputs := []string{"ok", "", "abcde", "x\x00y", "\xff"}
		conditions := []string{"nonempty", "bounded", "nul-free", "utf8"}
		rows := make([]decision, 0, len(inputs))
		for index, input := range inputs {
			values := []any{true, true, true, true}
			if index != 0 {
				values[index-1] = false
			}
			result := text(input, 4)
			if result != (index == 0) {
				t.Fatalf("text boundary %d accepted/rejected incorrectly", index)
			}
			rows = append(rows, decision{fmt.Sprint(index), values, result, map[string]any{"bytes": hex.EncodeToString([]byte(input)), "maximum": 4}})
		}
		decisions(t, "text", conditions, rows, [][2]int{{0, 1}, {0, 2}, {0, 3}, {0, 4}})
	})
	t.Run("scope", func(t *testing.T) {
		inputs := []Scope{{"sector", "spectrum"}, {"", "spectrum"}, {"sector", ""}}
		var rows []decision
		for index, input := range inputs {
			values := []any{true, true}
			if index != 0 {
				values[index-1] = false
			}
			result := input.Valid()
			if result != (index == 0) {
				t.Fatalf("scope boundary %d accepted/rejected incorrectly", index)
			}
			rows = append(rows, decision{fmt.Sprint(index), values, result, input})
		}
		decisions(t, "scope", []string{"sector", "spectrum"}, rows, [][2]int{{0, 1}, {0, 2}})
	})
	t.Run("limits", func(t *testing.T) {
		// Configuration caps are resource-admission bounds, distinct from the absence of a protocol-wide batch cap.
		cases := []struct {
			name   string        // Predicate identity fixed before execution.
			valid  func(*Limits) // Place this field at its admissible boundary.
			refuse func(*Limits) // Cross only the named predicate's boundary.
		}{
			{"scopes-positive", func(value *Limits) { value.Scopes = 1 }, func(value *Limits) { value.Scopes = 0 }},
			{"scopes-bounded", func(value *Limits) { value.Scopes = 16384 }, func(value *Limits) { value.Scopes++ }},
			{"records-positive", func(value *Limits) { value.Records = 1 }, func(value *Limits) { value.Records = 0 }},
			{"records-bounded", func(value *Limits) { value.Records = 1 << 20 }, func(value *Limits) { value.Records++ }},
			{"bytes-positive", func(value *Limits) { value.Bytes = 1 }, func(value *Limits) { value.Bytes = 0 }},
			{"bytes-bounded", func(value *Limits) { value.Bytes, value.Total = 1<<30, 4<<30 }, func(value *Limits) { value.Bytes++ }},
			{"total-covers-scope", func(value *Limits) { value.Total = value.Bytes }, func(value *Limits) { value.Total-- }},
			{"total-bounded", func(value *Limits) { value.Total = 4 << 30 }, func(value *Limits) { value.Total++ }},
			{"history-nonnegative", func(value *Limits) { value.History = 0 }, func(value *Limits) { value.History = -1 }},
			{"history-bounded", func(value *Limits) { value.History = 65536 }, func(value *Limits) { value.History++ }},
			{"backlog-nonnegative", func(value *Limits) { value.Backlog = 0 }, func(value *Limits) { value.Backlog = -1 }},
			{"backlog-bounded", func(value *Limits) { value.Backlog = 64 << 20 }, func(value *Limits) { value.Backlog++ }},
			{"timeout-positive", func(value *Limits) { value.Timeout = time.Nanosecond }, func(value *Limits) { value.Timeout = 0 }},
			{"timeout-bounded", func(value *Limits) { value.Timeout = 30 * time.Second }, func(value *Limits) { value.Timeout++ }},
			{"wal-minimum", func(value *Limits) { value.WAL = 1 << 20 }, func(value *Limits) { value.WAL-- }},
			{"wal-bounded", func(value *Limits) { value.WAL = 4 << 30 }, func(value *Limits) { value.WAL++ }},
		}
		var conditions []string
		var rows []decision
		var pairs [][2]int
		for index, item := range cases {
			input := Default()
			item.valid(&input)
			values := make([]any, len(cases))
			for condition := range values {
				values[condition] = true
			}
			result := input.valid()
			if !result {
				t.Fatalf("valid configuration boundary %s refused", item.name)
			}
			rows = append(rows, decision{item.name + "/valid", values, result, input})
			item.refuse(&input)
			values = append([]any(nil), values...)
			values[index] = false
			result = input.valid()
			if result {
				t.Fatalf("configuration boundary %s accepted", item.name)
			}
			rows = append(rows, decision{item.name + "/refused", values, result, input})
			conditions = append(conditions, item.name)
			pairs = append(pairs, [2]int{2 * index, 2*index + 1})
		}
		decisions(t, "limits", conditions, rows, pairs)
	})
	t.Run("scan", func(t *testing.T) {
		inputs := []any{"12345678", []byte{1, 2, 3, 4, 5, 6, 7}, []byte{0, 0, 0, 0, 0, 0, 0, 7}}
		values := [][]any{{true, nil}, {false, true}, {false, false}}
		var rows []decision
		for index, input := range inputs {
			version := Version(91)
			err := version.Scan(input)
			if index == 2 {
				if err != nil || version != 7 {
					t.Fatal("valid BLOB did not replace the exact full-width version", version, err)
				}
			} else if !errors.Is(err, ErrCorrupt) || version != 91 {
				t.Fatal("rejected BLOB changed the prior version or stable error", version, err)
			}
			rows = append(rows, decision{fmt.Sprint(index), values[index], err != nil, input})
		}
		decisions(t, "scan", []string{"wrong-type", "wrong-size"}, rows, [][2]int{{0, 2}, {1, 2}})
	})
	t.Run("change", func(t *testing.T) {
		inputs := []Change{{Key: "key", Value: []byte("v")}, {Value: []byte("v")}, {Key: "key", Value: make([]byte, (1<<20)+1)}, {Key: "key", Value: []byte("v"), Erase: true}, {Key: "key", Erase: true}}
		values := [][]any{{true, true, true, false}, {false, true, true, false}, {true, false, true, false}, {true, true, false, false}, {true, true, false, true}}
		var rows []decision
		for index, input := range inputs {
			result := validChange(input)
			if result != (index == 0 || index == 4) {
				t.Fatalf("change boundary %d accepted/rejected incorrectly", index)
			}
			rows = append(rows, decision{fmt.Sprint(index), values[index], result, map[string]any{"key": input.Key, "bytes": len(input.Value), "erase": input.Erase}})
		}
		decisions(t, "change", []string{"key", "payload-bounded", "set", "empty"}, rows, [][2]int{{0, 1}, {0, 2}, {0, 3}, {3, 4}})
	})
}

// predicates inventories every decision root within the five named validators, retaining unsupported control forms as errors.
func predicates(source []byte) (map[string][]string, error) {
	positions := token.NewFileSet()
	file, err := parser.ParseFile(positions, "input.go", source, 0)
	if err != nil {
		return nil, err
	}
	selected := map[string]string{"text": "text", "Scope.Valid": "scope", "Limits.valid": "limits", "*Version.Scan": "scan", "validChange": "change"}
	result := make(map[string][]string)
	show := func(node ast.Node) string {
		var output bytes.Buffer
		if err := format.Node(&output, positions, node); err != nil {
			panic(err)
		}
		return output.String()
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := function.Name.Name
		if function.Recv != nil {
			name = show(function.Recv.List[0].Type) + "." + name
		}
		id, selected := selected[name]
		if !selected {
			continue
		}
		if _, duplicate := result[id]; duplicate {
			return nil, fmt.Errorf("duplicate validator %s", id)
		}
		result[id] = nil
		ast.Inspect(function.Body, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.IfStmt:
				result[id] = append(result[id], show(value.Cond))
			case *ast.ReturnStmt:
				if len(value.Results) == 1 {
					if _, ok := value.Results[0].(*ast.BinaryExpr); ok {
						result[id] = append(result[id], show(value.Results[0]))
					}
				}
			case *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt, *ast.GoStmt, *ast.DeferStmt:
				result[id] = append(result[id], fmt.Sprintf("unsupported:%T", value))
			}
			return true
		})
	}
	return result, nil
}

// atoms counts independently changeable leaves of this declared AND/OR predicate grammar.
func atoms(value ast.Expr) int {
	switch expression := value.(type) {
	case *ast.ParenExpr:
		return atoms(expression.X)
	case *ast.BinaryExpr:
		if expression.Op == token.LAND || expression.Op == token.LOR {
			return atoms(expression.X) + atoms(expression.Y)
		}
	}
	return 1
}

// TestDecisionInventory freezes this finite validation denominator rather than claiming every Storage decision is covered.
func TestDecisionInventory(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("missing validation source location")
	}
	directory := filepath.Dir(filename)
	expected := map[string][]string{
		"text":   {"len(value) > 0 && len(value) <= maximum && !strings.ContainsRune(value, 0) && utf8.ValidString(value)"},
		"scope":  {"text(scope.Sector, 128) && text(scope.Spectrum, 128)"},
		"limits": {"limits.Scopes > 0 && limits.Scopes <= 16384 && limits.Records > 0 && limits.Records <= 1<<20 && limits.Bytes > 0 && limits.Bytes <= 1<<30 && limits.Total >= limits.Bytes && limits.Total <= 4<<30 && limits.History >= 0 && limits.History <= 65536 && limits.Backlog >= 0 && limits.Backlog <= 64<<20 && limits.Timeout > 0 && limits.Timeout <= 30*time.Second && limits.WAL >= 1<<20 && limits.WAL <= 4<<30"},
		"scan":   {"!ok || len(bytes) != 8"},
		"change": {"text(change.Key, 1024) && len(change.Value) <= 1<<20 && (!change.Erase || len(change.Value) == 0)"},
	}
	actual := make(map[string][]string)
	identities := make(map[string]string)
	total := 0
	for _, name := range []string{"model.go", "batch.go"} {
		source, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		found, err := predicates(source)
		if err != nil {
			t.Fatal(err)
		}
		for id, roots := range found {
			if _, duplicate := actual[id]; duplicate {
				t.Fatal("duplicate validator identity", id)
			}
			actual[id] = roots
			if len(roots) != 1 {
				t.Fatal("validator contains an unclassified decision", id)
			}
			expression, err := parser.ParseExpr(roots[0])
			if err != nil {
				t.Fatal(err)
			}
			total += atoms(expression)
			// Changing a Boolean operator must invalidate the old decision denominator, independently of behavioral tests.
			before := roots[0]
			after := strings.Replace(before, "&&", "||", 1)
			if after == before {
				after = strings.Replace(before, "||", "&&", 1)
			}
			modified, err := predicates(bytes.Replace(source, []byte(before), []byte(after), 1))
			if err != nil || reflect.DeepEqual(modified[id], roots) {
				t.Fatal("valid predicate drift escaped the inventory", id, err)
			}
		}
		identities[name] = fmt.Sprintf("%x", sha256.Sum256(source))
	}
	if !reflect.DeepEqual(actual, expected) || total != 28 {
		t.Fatalf("unclassified validation predicate: %v", actual)
	}
	encoded, err := json.Marshal(map[string]any{"decisions": actual, "sources": identities, "conditions": total, "scope": "five named pure validators only"})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("STORAGE-DECISION-INVENTORY " + string(encoded))
}
