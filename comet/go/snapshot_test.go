// Compare copy-on-write roots with an independent mutable dictionary oracle.
package comet

import (
	"maps"
	"math/rand/v2"
	"strings"
	"testing"
)

// TestMapIteration keeps callback mutation, early return and panics outside
// immutable storage; visiting a retained root never traverses a later draft.
func TestMapIteration(t *testing.T) {
	t.Parallel()
	expected := map[string]string{"a": "one", "b": "", "c": "three"}
	base := newDraft(emptyTable())
	for key, data := range expected {
		base.set(key, &row{data: NewValue([]byte(data))})
	}
	values := Map{root: &snapshot{data: base.data}}
	next := newDraft(base.data)
	next.set("a", &row{data: NewValue([]byte("replacement"))})
	next.set("c", nil)
	next.set("d", &row{data: NewValue([]byte("new"))})
	visited := make(map[string]string)
	values.Range(func(key string, value Value) bool {
		if _, duplicate := visited[key]; duplicate {
			t.Fatal("iteration duplicated a key")
		}
		visited[key] = value.String()
		if data := value.Bytes(); len(data) != 0 {
			data[0] = 'x'
		}
		return true
	})
	if !maps.Equal(visited, expected) || values.Len() != 3 {
		t.Fatal("iteration included another root or changed retained content")
	}
	calls := 0
	values.Range(func(string, Value) bool { calls++; return false })
	if calls != 1 {
		t.Fatal("false return did not stop iteration")
	}
	values.Range(nil)
	if _, present := values.Get("d"); present {
		t.Fatal("a later insertion appeared in a retained map")
	}
	for key, want := range expected {
		if value, present := values.Get(key); !present || value.String() != want {
			t.Fatal("caller byte mutation changed a retained value")
		}
	}
	marker := &struct{ value int }{1}
	func() {
		defer func() {
			if recover() != marker {
				t.Error("synchronous iteration did not propagate the caller panic")
			}
		}()
		values.Range(func(string, Value) bool { panic(marker) })
	}()
}

// TestPersistentTableHistory compares successive immutable roots with an independent map oracle.
func TestPersistentTableHistory(t *testing.T) {
	t.Parallel()
	random := rand.New(rand.NewPCG(11, 29))
	current, expected := emptyTable(), make(map[string]string)
	for turn := range 300 {
		old := current
		oldCount := len(expected)
		key := string(rune('a' + random.IntN(90)))
		before := old.find(key)
		candidate := newDraft(current)
		if random.IntN(3) == 0 {
			candidate.set(key, nil)
			delete(expected, key)
		} else {
			data := strings.Repeat("v", turn%31)
			candidate.set(key, &row{data: NewValue([]byte(data))})
			expected[key] = data
		}
		current = candidate.data
		if old.count != oldCount || old.find(key) != before || current.count != len(expected) {
			t.Fatalf("root mutation at turn %d", turn)
		}
		for name, want := range expected {
			if got := current.find(name); got == nil || got.data.String() != want {
				t.Fatalf("map oracle mismatch at turn %d key %q", turn, name)
			}
		}
	}
}
