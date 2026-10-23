// Compare complete bounded callback histories with an independent first-attempt admission model.
package command

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"reflect"
	"testing"
)

// register exposes callback effects even when the callback returns an error or panics after modifying its state.
type register struct {
	reads   int
	writes  int
	queries int
	mode    int
	text    string
	nested  string
	wrapped *once
}

var rejected = errors.New("model delegate rejected")

// String preserves the last attempted payload while independently counting reads.
func (value *register) String() string {
	value.reads++
	return value.text
}

// Set makes partial callback effects visible and bounds a deliberately adversarial recursive write.
func (value *register) Set(text string) error {
	value.writes++
	value.text = text
	if value.mode == 5 && value.writes == 1 {
		value.nested = invoke(value.wrapped, 2, "nested")
	}
	if value.mode == 3 {
		return rejected
	}
	if value.mode == 4 {
		panic(rejected)
	}
	return nil
}

// switcher provides the optional boolean interface separately from its configured true/false result.
type switcher struct {
	*register
	result bool
}

// IsBoolFlag counts optional-interface evaluation; an absent interface must never call it.
func (value *switcher) IsBoolFlag() bool {
	value.queries++
	return value.result
}

// invoke observes public results without recovering or repairing the production object's state.
func invoke(value *once, action int, text string) (result string) {
	result = "panic"
	defer func() { _ = recover() }()
	switch action {
	case 0:
		return "string:" + value.String()
	case 1:
		return fmt.Sprint("bool:", value.IsBoolFlag())
	default:
		if err := value.Set(text); err != nil {
			if err == rejected {
				return "rejected"
			}
			return err.Error()
		}
		return "ok"
	}
}

// payload fixes two distinguishable exact byte strings; forwarding is not normalized or decoded.
func payload(index int) string {
	return []string{"", "\x00µ🙂"}[index%2]
}

// history derives results from the earliest attempted write and prefix counts, without executing wrapper control flow.
func history(actions []int, kind int) [][]any {
	states := make([][]any, 0, len(actions))
	first := len(actions)
	for index, action := range actions {
		if action >= 2 {
			first = index
			break
		}
	}
	reads, queries := 0, 0
	for index, action := range actions {
		consumed := first <= index
		writes, text, nested := 0, "", ""
		if consumed && kind != 0 {
			writes, text = 1, payload(first)
			if actions[first] == 5 {
				nested = "duplicate option"
			}
		}
		var result string
		switch action {
		case 0:
			if kind != 0 {
				reads++
			}
			result = "string:" + text
		case 1:
			if kind >= 2 {
				queries++
			}
			result = fmt.Sprint("bool:", kind == 3)
		default:
			result = "duplicate option"
			if index == first {
				result = "ok"
				if kind == 0 || action == 4 {
					result = "panic"
				} else if action == 3 {
					result = "rejected"
				}
			}
		}
		states = append(states, []any{result, reads, writes, queries, consumed, text, nested})
	}
	return states
}

// TestModel covers all prefixes through four events over six operations and four delegate/interface classes.
func TestModel(t *testing.T) {
	histories, transitions := 0, 0
	for kind := 0; kind < 4; kind++ {
		var visit func([]int)
		visit = func(actions []int) {
			delegate := &register{}
			var value flag.Value
			if kind == 1 {
				value = delegate
			} else if kind >= 2 {
				value = &switcher{register: delegate, result: kind == 3}
			}
			wrapped := &once{Value: value}
			delegate.wrapped = wrapped
			actual := make([][]any, 0, len(actions))
			for index, action := range actions {
				delegate.mode = action
				result := invoke(wrapped, action, payload(index))
				actual = append(actual, []any{result, delegate.reads, delegate.writes, delegate.queries, wrapped.set, delegate.text, delegate.nested})
			}
			if expected := history(actions, kind); !reflect.DeepEqual(actual, expected) {
				t.Fatalf("model kind=%d history=%v actual=%v expected=%v", kind, actions, actual, expected)
			}
			encoded, err := json.Marshal(map[string]any{"kind": kind, "history": actions, "states": actual})
			if err != nil {
				t.Fatal(err)
			}
			t.Log("ASTRA-COMMAND-MODEL " + string(encoded))
			histories++
			transitions += len(actions)
			if len(actions) < 4 {
				for action := 0; action < 6; action++ {
					next := append(append([]int{}, actions...), action)
					visit(next)
				}
			}
		}
		visit([]int{})
	}
	if histories != 6220 || transitions != 23640 {
		t.Fatalf("incomplete finite domain: %d histories / %d transitions", histories, transitions)
	}
	t.Logf("COMMAND-MODEL-DOMAIN histories=%d transitions=%d", histories, transitions)
	t.Logf(`ASTRA-CONTRACT {"contract":"COMMAND-MODEL","hits":%d}`, histories)
}

// TestModelOracle anchors the reference calculation to manually prescribed public outcomes, including failure and reentry.
func TestModelOracle(t *testing.T) {
	vectors := []struct {
		kind    int
		actions []int
		states  [][]any
	}{
		{0, []int{0}, [][]any{{"string:", 0, 0, 0, false, "", ""}}},
		{1, []int{0}, [][]any{{"string:", 1, 0, 0, false, "", ""}}},
		{2, []int{1}, [][]any{{"bool:false", 0, 0, 1, false, "", ""}}},
		{3, []int{1}, [][]any{{"bool:true", 0, 0, 1, false, "", ""}}},
		{1, []int{3}, [][]any{{"rejected", 0, 1, 0, true, "", ""}}},
		{1, []int{4}, [][]any{{"panic", 0, 1, 0, true, "", ""}}},
		{0, []int{2}, [][]any{{"panic", 0, 0, 0, true, "", ""}}},
		{1, []int{5}, [][]any{{"ok", 0, 1, 0, true, "", "duplicate option"}}},
		{1, []int{2, 2}, [][]any{{"ok", 0, 1, 0, true, "", ""}, {"duplicate option", 0, 1, 0, true, "", ""}}},
		{3, []int{1, 2}, [][]any{{"bool:true", 0, 0, 1, false, "", ""}, {"ok", 0, 1, 1, true, "\x00µ🙂", ""}}},
	}
	for index, vector := range vectors {
		if actual := history(vector.actions, vector.kind); !reflect.DeepEqual(actual, vector.states) {
			t.Fatalf("reference vector %d: actual=%v expected=%v", index, actual, vector.states)
		}
	}
	t.Logf(`ASTRA-CONTRACT {"contract":"COMMAND-MODEL-CONTROLS","hits":%d}`, len(vectors))
}
