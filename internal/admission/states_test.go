// Enumerate Node publication and replacement histories against a literal protocol state table.
package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/internal/generated/orbit"
)

// witness emits actual public observations for independent reconstruction after the native test ends.
func witness(t *testing.T, kind string, value any) {
	t.Helper()
	data, err := json.Marshal(struct {
		Kind  string `json:"kind"`  // Fixed finite-domain identity.
		Value any    `json:"value"` // Actual input identity, receipts and public state.
	}{kind, value})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("ADMISSION-MODEL " + string(data))
}

// receipt states one protocol outcome independently of transport and production validation helpers.
type receipt struct {
	state  int // Next state: pending empty/current/newer, or admitted current/newer.
	result int // Result: success, unavailable, invalid identity, or replaced identity.
}

// lifecycle fixes all five reachable states and nine public-operation outcomes.
// Columns: healthy/refused/invalid registration, healthy/refused/absent/invalid refresh, newer/older verification.
// Rows retain original process credentials after replacement; only the host may create a new process instance.
var lifecycle = [5][9]receipt{
	{{3, 0}, {0, 1}, {0, 2}, {0, 1}, {0, 1}, {0, 1}, {0, 1}, {2, 0}, {1, 0}},
	{{3, 0}, {1, 1}, {1, 2}, {1, 1}, {1, 1}, {1, 1}, {1, 1}, {2, 0}, {1, 0}},
	{{2, 2}, {2, 1}, {2, 2}, {2, 1}, {2, 1}, {2, 1}, {2, 1}, {2, 0}, {2, 3}},
	{{3, 0}, {3, 0}, {3, 0}, {3, 0}, {3, 1}, {3, 3}, {3, 2}, {4, 0}, {3, 0}},
	{{4, 0}, {4, 0}, {4, 0}, {4, 3}, {4, 1}, {4, 3}, {4, 2}, {4, 0}, {4, 3}},
}

// TestNodeTransitionsOracle anchors exact admission, replacement, no-replay and refusal histories without Node calls.
func TestNodeTransitionsOracle(t *testing.T) {
	for _, example := range []struct {
		input []int     // Literal public-operation history.
		want  []receipt // Independently stated state and result after every operation.
	}{
		{[]int{3, 0, 1}, []receipt{{0, 1}, {3, 0}, {3, 0}}},
		{[]int{7, 0, 8}, []receipt{{2, 0}, {2, 2}, {2, 3}}},
		{[]int{8, 2, 0}, []receipt{{1, 0}, {1, 2}, {3, 0}}},
		{[]int{0, 7, 3}, []receipt{{3, 0}, {4, 0}, {4, 3}}},
		{[]int{0, 7, 0}, []receipt{{3, 0}, {4, 0}, {4, 0}}},
		{[]int{0, 6, 3}, []receipt{{3, 0}, {3, 2}, {3, 0}}},
		{[]int{0, 5, 4}, []receipt{{3, 0}, {3, 3}, {3, 1}}},
	} {
		state := 0
		for step, action := range example.input {
			got := lifecycle[state][action]
			if got != example.want[step] {
				t.Fatalf("lifecycle example input=%v step=%d: got %+v, want %+v", example.input, step, got, example.want[step])
			}
			state = got.state
		}
	}
}

// TestNodeTransitions checks every length-three history over the whole operation alphabet, for both supported roles.
// RPC receipts are controlled; real signature verification, directory publication and Node locks remain in use.
func TestNodeTransitions(t *testing.T) {
	check := counter(t, "ADMISSION-NODE-TRANSITIONS")
	identity := identity(t)
	trials, steps, requests := 0, 0, 0
	for _, role := range []orbit.Role{orbit.Role_ROLE_POLARIS, orbit.Role_ROLE_ASTROLABE} {
		local := &orbit.Member{Galaxy: "alpha", Id: []byte("local"), Principal: identity.Principal("alpha", "127.0.0.1:7443"), Advertise: "127.0.0.1:7443", Epoch: 1, Role: role, Group: "default"}
		newer := proto.Clone(local).(*orbit.Member)
		newer.Id, newer.Epoch = []byte("newer"), 2
		original, replacement := response(t, local), response(t, newer)
		invalid := proto.Clone(original).(*orbit.RegistrationResponse)
		invalid.Signature = make([]byte, 64)
		for sequence := range 729 {
			input := []int{sequence / 81, sequence / 9 % 9, sequence % 9}
			func() {
				value, err := Open(identity, "127.0.0.1:1", "alpha", "127.0.0.1:7443", "default", role)
				check(err == nil && value != nil, "finite lifecycle could not acquire its channel")
				defer func() { check(value.Close() == nil, "finite lifecycle channel did not close") }()
				request := proto.Clone(value.request).(*orbit.RegistrationRequest)
				state := 0
				for step, action := range input {
					want := lifecycle[state][action]
					registers, lists := 0, 0
					value.client = &transport{
						register: func(_ context.Context, current *orbit.RegistrationRequest) (*orbit.RegistrationResponse, error) {
							registers++
							check(proto.Equal(current, request) && action < 3, "registration changed its startup request or crossed operation ownership")
							if action == 1 {
								return nil, status.Error(codes.Unavailable, "Controlled registration refusal")
							}
							if action == 2 {
								return invalid, nil
							}
							return original, nil
						},
						list: func(ctx context.Context, current *orbit.DirectoryRequest) (*orbit.DirectoryResponse, error) {
							lists++
							fields, _ := metadata.FromOutgoingContext(ctx)
							check(action >= 3 && action <= 6 && proto.Equal(current, &orbit.DirectoryRequest{}) && len(fields.Get("astra-admission-bin")) == 1 && fields.Get("astra-admission-bin")[0] == string(original.Admission) && len(fields.Get("astra-signature-bin")) == 1 && fields.Get("astra-signature-bin")[0] == string(original.Signature), "refresh request changed its process credentials or operation ownership")
							if action == 4 {
								return nil, status.Error(codes.Unavailable, "Controlled refresh refusal")
							}
							members := []*orbit.Member{local}
							if action == 5 {
								members = nil
							} else if action == 6 {
								members = append(members, nil)
							}
							return &orbit.DirectoryResponse{Members: members}, nil
						},
					}
					switch {
					case action < 3:
						err = value.Register(context.Background())
					case action < 7:
						err = value.Refresh(context.Background())
					default:
						message := original
						if action == 7 {
							message = replacement
						}
						_, err = value.Directory().Verify(message.Admission, message.Signature, role)
					}
					label := fmt.Sprintf("role=%s sequence=%d step=%d state=%d action=%d", role, sequence, step, state, action)
					outcome := -1
					switch {
					case err == nil:
						outcome = 0
					case errors.Is(err, ErrIdentity):
						outcome = 2
					case status.Code(err) == codes.Unavailable:
						outcome = 1
					case status.Code(err) == codes.Unauthenticated:
						outcome = 3
					}
					check(outcome == want.result, "lifecycle result: "+label)
					expectedRegisters, expectedLists := 0, 0
					if state < 3 && action < 3 {
						expectedRegisters = 1
					}
					if state >= 3 && action >= 3 && action < 7 {
						expectedLists = 1
					}
					check(registers == expectedRegisters && lists == expectedLists, "lifecycle external request count: "+label)
					state = want.state
					ready := state >= 3
					member, hello := value.Member(), value.Hello()
					check(ready && proto.Equal(member, local) || !ready && member == nil, "lifecycle process identity: "+label)
					check(ready && hello != nil && hello.ProtocolMajor == 1 && hello.MaxFrameBytes == 8<<20 && bytes.Equal(hello.Admission, original.Admission) && bytes.Equal(hello.AdmissionSignature, original.Signature) || !ready && hello == nil, "lifecycle credential publication: "+label)
					ctx, failure := value.Context(context.Background())
					if ready {
						fields, _ := metadata.FromOutgoingContext(ctx)
						check(failure == nil && len(fields.Get("astra-admission-bin")) == 1 && fields.Get("astra-admission-bin")[0] == string(original.Admission) && len(fields.Get("astra-signature-bin")) == 1 && fields.Get("astra-signature-bin")[0] == string(original.Signature), "lifecycle context credentials: "+label)
					} else {
						check(ctx == nil && status.Code(failure) == codes.Unavailable, "pending lifecycle context: "+label)
					}
					epoch := []int{0, 1, 2, 1, 2}[state]
					members := value.Directory().Members()
					expected := local
					if epoch == 2 {
						expected = newer
					}
					check(epoch == 0 && len(members) == 0 || epoch != 0 && len(members) == 1 && proto.Equal(members[0], expected), "lifecycle complete directory: "+label)
					check(value.Directory().Current(local) == (epoch == 1) && value.Directory().Current(newer) == (epoch == 2), "lifecycle current process predicates: "+label)
					check(len(value.gate) == 0 && proto.Equal(value.request, request), "lifecycle admission and startup ownership: "+label)
					witness(t, "publication", map[string]any{
						"role": role, "sequence": sequence, "step": step, "result": outcome,
						"registers": registers, "lists": lists, "member": member, "directory": members,
						"hello": hello != nil, "context": ctx != nil,
						"current": []bool{value.Directory().Current(local), value.Directory().Current(newer)},
					})
					requests += registers + lists
					steps++
				}
			}()
			trials++
		}
	}
	check(trials == 1458 && steps == 4374, "complete lifecycle role and operation domain")
	t.Logf("node-transitions version=1 roles=2 states=5 operations=9 depth=3 trials=%d steps=%d requests=%d pruning=none", trials, steps, requests)
}
