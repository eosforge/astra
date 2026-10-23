// Compare directory publication with an independent finite membership model.
package admission

import (
	"fmt"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/internal/generated/orbit"
)

// operation describes a complete list or an already-verified handshake over two principals.
type operation struct {
	a, b    int
	observe bool
	invalid int
}

// domain fixes the operation alphabet independently of the implementation's branches.
func domain() []operation {
	return []operation{
		{}, {a: 1}, {a: 2}, {b: 1}, {b: 2},
		{a: 1, b: 1}, {a: 1, b: 2}, {a: 2, b: 1}, {a: 2, b: 2},
		{a: 1, observe: true}, {a: 2, observe: true}, {b: 1, observe: true}, {b: 2, observe: true},
		{invalid: 1}, {invalid: 2}, {invalid: 3}, {invalid: 4}, {invalid: 5},
	}
}

// transition uses only two epoch registers: lists merge maxima, while stale handshakes fail.
// Malformed lists fail atomically. A full directory admits replacement but no third slot.
func transition(state [2]int, action operation, capacity int) ([2]int, bool) {
	if action.invalid != 0 {
		return state, false
	}
	next := state
	for index, epoch := range [2]int{action.a, action.b} {
		if epoch == 0 {
			continue
		}
		if action.observe && epoch < state[index] {
			return state, false
		}
		next[index] = max(state[index], epoch)
	}
	count := 0
	for _, epoch := range next {
		if epoch != 0 {
			count++
		}
	}
	if count > capacity {
		return state, false
	}
	return next, true
}

// apply builds wire objects without sharing validation, equality, or merge helpers with the model.
func apply(directory *Directory, action operation) error {
	members := []*orbit.Member{}
	for index, epoch := range [2]int{action.a, action.b} {
		if epoch != 0 {
			members = append(members, member(index+1, epoch, orbit.Role_ROLE_STAR))
		}
	}
	switch action.invalid {
	case 1:
		members = []*orbit.Member{member(1, 1, orbit.Role_ROLE_STAR), member(1, 1, orbit.Role_ROLE_STAR)}
	case 2:
		members = []*orbit.Member{member(2, 1, orbit.Role_ROLE_STAR), member(1, 1, orbit.Role_ROLE_STAR)}
	case 3:
		members = []*orbit.Member{nil}
	case 4:
		members = []*orbit.Member{member(1, 1, orbit.Role_ROLE_STAR)}
		members[0].Galaxy = "foreign"
	case 5:
		members = []*orbit.Member{member(1, 1, orbit.Role_ROLE_PLANET)}
	}
	if action.observe {
		return directory.observe(members[0])
	}
	return directory.Install(members)
}

// observation checks complete public snapshots and current-identity predicates against two registers.
func observation(t *testing.T, directory *Directory, state [2]int, check func(bool, string)) {
	t.Helper()
	view := directory.Members()
	expected := []*orbit.Member{}
	for index, epoch := range state {
		if epoch != 0 {
			expected = append(expected, member(index+1, epoch, orbit.Role_ROLE_STAR))
		}
		for candidate := 1; candidate <= 2; candidate++ {
			check(directory.Current(member(index+1, candidate, orbit.Role_ROLE_STAR)) == (epoch == candidate), "current identity must match the register")
		}
	}
	check(len(view) == len(expected), "directory cardinality")
	for index := range view {
		check(proto.Equal(view[index], expected[index]), "snapshot membership, order, and fields")
		view[index].Group = "caller-owned"
	}
	copy := directory.Members()
	for index := range copy {
		check(proto.Equal(copy[index], expected[index]), "reader mutation cannot alter the directory")
	}
}

// counter emits executed assertions, never a precomputed coverage percentage.
func counter(t *testing.T, contracts ...string) func(bool, string) {
	t.Helper()
	hits := 0
	t.Cleanup(func() {
		for _, contract := range contracts {
			t.Logf("ASTRA-CONTRACT {\"contract\":%q,\"hits\":%d}", contract, hits)
		}
	})
	return func(ok bool, why string) {
		t.Helper()
		hits++
		if !ok {
			t.Fatal(why)
		}
	}
}

// TestDirectoryModel enumerates all 18^3 sequences for capacities one and two, without pruning.
// Identity cryptography, arbitrary members, internal lock schedules, and durable storage are outside this domain.
func TestDirectoryModel(t *testing.T) {
	check := counter(t, "ADMISSION-FINITE", "ADMISSION-ASSURANCE")
	actions := domain()
	check(len(actions) == 18, "fixed operation alphabet")
	sequences, transitions := 0, 0
	for capacity := 1; capacity <= 2; capacity++ {
		for first := range actions {
			for second := range actions {
				for third := range actions {
					value, err := NewDirectory(&Identity{}, "alpha", orbit.Role_ROLE_POLARIS, capacity)
					check(err == nil, "valid isolated directory")
					state := [2]int{}
					var receipts []any
					for step, selected := range []int{first, second, third} {
						next, accepted := transition(state, actions[selected], capacity)
						err = apply(value, actions[selected])
						check((err == nil) == accepted, fmt.Sprintf("capacity=%d sequence=%v step=%d error=%v", capacity, []int{first, second, third}, step, err))
						if err != nil {
							check(err == ErrIdentity || status.Code(err) == codes.ResourceExhausted, "bounded validation failure")
						}
						observation(t, value, next, check)
						receipts = append(receipts, map[string]any{"accepted": err == nil, "members": value.Members()})
						state = next
						transitions++
					}
					witness(t, "directory", map[string]any{"capacity": capacity, "sequence": first*324 + second*18 + third, "receipts": receipts})
					sequences++
				}
			}
		}
	}
	check(sequences == 11664 && transitions == 34992, "complete finite domain")
	t.Logf("directory-model version=1 principals=2 epochs=2 capacities=2 operations=18 depth=3 sequences=%d transitions=%d pruning=none", sequences, transitions)
}

// TestDirectorySchedules checks every pair against both legal serializations from five starting states.
// A start barrier introduces overlap; it does not claim exhaustive internal or weak-memory schedules.
func TestDirectorySchedules(t *testing.T) {
	check := counter(t, "ADMISSION-SCHEDULE")
	actions := domain()
	histories := 0
	for capacity := 1; capacity <= 2; capacity++ {
		for _, initial := range [][2]int{{}, {1, 0}, {2, 0}, {0, 1}, {0, 2}} {
			for firstIndex, first := range actions {
				for secondIndex, second := range actions {
					value, err := NewDirectory(&Identity{}, "alpha", orbit.Role_ROLE_POLARIS, capacity)
					check(err == nil && apply(value, operation{a: initial[0], b: initial[1]}) == nil, "initial directory")
					accepted := [2]bool{}
					start := make(chan struct{})
					var workers sync.WaitGroup
					for index, action := range [2]operation{first, second} {
						workers.Go(func() {
							<-start
							accepted[index] = apply(value, action) == nil
						})
					}
					close(start)
					workers.Wait()
					state := [2]int{}
					for _, record := range value.Members() {
						check(len(record.Principal) == 32 && record.Principal[31] >= 1 && record.Principal[31] <= 2, "known principal domain")
						state[int(record.Principal[31])-1] = int(record.Epoch)
					}
					left, a := transition(initial, first, capacity)
					left, b := transition(left, second, capacity)
					right, c := transition(initial, second, capacity)
					right, d := transition(right, first, capacity)
					check(state == left && accepted == [2]bool{a, b} || state == right && accepted == [2]bool{d, c}, "history must have a legal serial commit order")
					observation(t, value, state, check)
					witness(t, "pair", map[string]any{"capacity": capacity, "initial": initial, "first": firstIndex, "second": secondIndex, "accepted": accepted, "members": value.Members()})
					histories++
				}
			}
		}
	}
	check(histories == 3240, "complete pair and starting-state domain")
	t.Logf("directory-schedules version=1 histories=%d serializations=2 controlled-start=true internal-schedule-exhaustive=false", histories)
}

// TestDirectoryOracle anchors the model to fixed protocol examples, separately from production observations.
func TestDirectoryOracle(t *testing.T) {
	for _, example := range []struct {
		before, after [2]int
		action        operation
		capacity      int
		accepted      bool
	}{
		{[2]int{2, 1}, [2]int{2, 1}, operation{a: 1}, 2, true},
		{[2]int{2, 0}, [2]int{2, 0}, operation{a: 1, observe: true}, 2, false},
		{[2]int{1, 0}, [2]int{2, 0}, operation{a: 2, observe: true}, 1, true},
		{[2]int{1, 0}, [2]int{1, 0}, operation{b: 1}, 1, false},
		{[2]int{1, 2}, [2]int{1, 2}, operation{}, 2, true},
		{[2]int{}, [2]int{}, operation{invalid: 1}, 2, false},
		{[2]int{}, [2]int{1, 2}, operation{a: 1, b: 2}, 2, true},
	} {
		state, accepted := transition(example.before, example.action, example.capacity)
		if state != example.after || accepted != example.accepted {
			t.Fatalf("protocol model example %+v: state=%v accepted=%t", example, state, accepted)
		}
	}
}

// TestDirectoryOwnership retains identities independently of both input and output message storage.
func TestDirectoryOwnership(t *testing.T) {
	check := counter(t, "ADMISSION-OWNERSHIP")
	for _, handshake := range []bool{false, true} {
		value, err := NewDirectory(&Identity{}, "alpha", orbit.Role_ROLE_POLARIS, 2)
		check(err == nil, "valid isolated directory")
		input := member(1, 1, orbit.Role_ROLE_STAR)
		expected := proto.Clone(input).(*orbit.Member)
		if handshake {
			err = value.observe(input)
		} else {
			err = value.Install([]*orbit.Member{input})
		}
		check(err == nil, "valid input accepted")
		input.Id[0] ^= 1
		input.Principal[0] ^= 1
		input.Group = "mutated"
		input.Epoch = 999
		check(value.Current(expected) && !value.Current(input), "caller retains only its own input message")
		view := value.Members()
		check(len(view) == 1 && proto.Equal(view[0], expected), "original fields remain intact")
		view[0].Id[0] ^= 1
		view[0].Principal[0] ^= 1
		check(value.Current(expected), "reader cannot mutate stored identity bytes")
	}
}
