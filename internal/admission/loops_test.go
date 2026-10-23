// Enumerate bounded Node retry histories against independent finite transition tables.
package admission

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/internal/generated/orbit"
)

// retry is the observation history specified by the finite protocol model.
type retry struct {
	calls     int             // Number of transport requests before termination.
	delays    []time.Duration // Requested logical waits, including a cancelled final wait.
	callbacks []codes.Code    // Refresh receipts delivered before termination.
	result    codes.Code      // Stable terminal result; Canceled denotes the finite input boundary.
	admitted  bool            // Whether this history publishes or retains process credentials.
}

// predict uses literal states and transitions, independently of Node's exponential arithmetic and fatal helper.
// Input symbols are transient refusal, success and permanent refusal. Exhausted input cancels waiting.
func predict(refresh bool, input []int) retry {
	delays := []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second}
	next := []int{1, 2, 3, 4, 5, 6, 6}
	if refresh {
		delays = []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute}
		next = []int{1, 2, 2}
	}
	result := retry{result: codes.Canceled, admitted: refresh}
	state := 0
	for _, symbol := range input {
		if refresh {
			result.delays = append(result.delays, delays[state])
		}
		result.calls++
		if refresh {
			result.callbacks = append(result.callbacks, []codes.Code{codes.Unavailable, codes.OK, codes.PermissionDenied}[symbol])
		}
		switch symbol {
		case 0:
			if !refresh {
				result.delays = append(result.delays, delays[state])
			}
			state = next[state]
		case 1:
			if !refresh {
				result.result, result.admitted = codes.OK, true
				return result
			}
			state = 0
		case 2:
			result.result = codes.PermissionDenied
			return result
		default:
			panic("Invalid finite retry symbol")
		}
	}
	if refresh {
		result.delays = append(result.delays, delays[state])
	}
	return result
}

// TestNodeOracle anchors the model independently of production, including saturation and success reset.
func TestNodeOracle(t *testing.T) {
	for _, example := range []struct {
		refresh bool  // Select the recurring refresh state machine.
		input   []int // Fixed protocol receipts.
		want    retry // Independently stated complete observation history.
	}{
		{false, []int{1, 2}, retry{calls: 1, result: codes.OK, admitted: true}},
		{false, []int{2, 1}, retry{calls: 1, result: codes.PermissionDenied}},
		{false, []int{0, 1}, retry{calls: 2, delays: []time.Duration{500 * time.Millisecond}, result: codes.OK, admitted: true}},
		{false, []int{0, 0, 0, 0, 0, 0, 0, 0}, retry{calls: 8, delays: []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second}, result: codes.Canceled}},
		{true, []int{2, 1}, retry{calls: 1, delays: []time.Duration{30 * time.Second}, callbacks: []codes.Code{codes.PermissionDenied}, result: codes.PermissionDenied, admitted: true}},
		{true, []int{0, 0, 0}, retry{calls: 3, delays: []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 2 * time.Minute}, callbacks: []codes.Code{codes.Unavailable, codes.Unavailable, codes.Unavailable}, result: codes.Canceled, admitted: true}},
		{true, []int{0, 1, 0}, retry{calls: 3, delays: []time.Duration{30 * time.Second, time.Minute, 30 * time.Second, time.Minute}, callbacks: []codes.Code{codes.Unavailable, codes.OK, codes.Unavailable}, result: codes.Canceled, admitted: true}},
	} {
		got := predict(example.refresh, example.input)
		if got.calls != example.want.calls || got.result != example.want.result || got.admitted != example.want.admitted || !slices.Equal(got.delays, example.want.delays) || !slices.Equal(got.callbacks, example.want.callbacks) {
			t.Fatalf("model example refresh=%t input=%v: got %+v, want %+v", example.refresh, example.input, got, example.want)
		}
	}
}

// TestNodeModel covers every three-receipt suffix after each reachable backoff state, for both supported roles.
// It executes real Node transitions with controlled transport/wait receipts; native scheduling remains a separate check.
func TestNodeModel(t *testing.T) {
	check := counter(t, "ADMISSION-NODE-FINITE")
	identity := identity(t)
	trials, calls, waits := 0, 0, 0
	for _, role := range []orbit.Role{orbit.Role_ROLE_POLARIS, orbit.Role_ROLE_ASTROLABE} {
		local := &orbit.Member{Galaxy: "alpha", Id: []byte("local"), Principal: identity.Principal("alpha", "127.0.0.1:7443"), Advertise: "127.0.0.1:7443", Epoch: 1, Role: role, Group: "default"}
		reply := response(t, local)
		for _, refresh := range []bool{false, true} {
			prefixes := 8
			if refresh {
				prefixes = 3
			}
			for prefix := range prefixes {
				for suffix := range 27 {
					input := append(make([]int, prefix), suffix/9, suffix/3%3, suffix%3)
					want := predict(refresh, input)
					func() {
						value, err := Open(identity, "127.0.0.1:1", "alpha", "127.0.0.1:7443", "default", role)
						check(err == nil && value != nil, "finite Node could not acquire its channel")
						defer func() { check(value.Close() == nil, "finite Node channel did not close") }()
						if refresh {
							value.client = &transport{register: func(context.Context, *orbit.RegistrationRequest) (*orbit.RegistrationResponse, error) {
								return reply, nil
							}}
							check(value.Register(context.Background()) == nil, "finite refresh could not establish its initial state")
						}
						request := proto.Clone(value.request).(*orbit.RegistrationRequest)
						got := retry{}
						step := func() error {
							check(got.calls < len(input), "loop consumed a receipt beyond its finite input")
							symbol := input[got.calls]
							got.calls++
							switch symbol {
							case 0:
								return status.Error(codes.Unavailable, "Controlled transient refusal")
							case 1:
								return nil
							default:
								return status.Error(codes.PermissionDenied, "Controlled permanent refusal")
							}
						}
						value.client = &transport{
							register: func(_ context.Context, current *orbit.RegistrationRequest) (*orbit.RegistrationResponse, error) {
								check(!refresh && proto.Equal(current, request), "registration changed its request or crossed loop ownership")
								if err := step(); err != nil {
									return nil, err
								}
								return reply, nil
							},
							list: func(context.Context, *orbit.DirectoryRequest) (*orbit.DirectoryResponse, error) {
								check(refresh, "Join performed a refresh operation")
								if err := step(); err != nil {
									return nil, err
								}
								return &orbit.DirectoryResponse{Members: []*orbit.Member{local}}, nil
							},
						}
						wait := func(_ context.Context, delay time.Duration) error {
							got.delays = append(got.delays, delay)
							check(len(got.delays) <= len(input)+1 && len(value.gate) == 0, "waiting retained admission or exceeded the finite schedule")
							if got.calls == len(input) {
								return context.Canceled
							}
							return nil
						}
						if refresh {
							err = value.run(context.Background(), func(err error) {
								check(len(value.gate) == 0 && got.calls == len(got.callbacks)+1, "callback ran before request completion or with retained admission")
								got.callbacks = append(got.callbacks, status.Code(err))
							}, wait)
						} else {
							err = value.join(context.Background(), wait)
						}
						got.result = status.Code(err)
						if errors.Is(err, context.Canceled) {
							got.result = codes.Canceled
						}
						got.admitted = value.Member() != nil
						label := fmt.Sprintf("role=%s refresh=%t prefix=%d suffix=%d", role, refresh, prefix, suffix)
						check(got.calls == want.calls && got.result == want.result, "terminal receipt or request count: "+label)
						check(slices.Equal(got.delays, want.delays), "complete delay history: "+label)
						check(slices.Equal(got.callbacks, want.callbacks), "complete callback history: "+label)
						check(got.admitted == want.admitted && (value.Hello() != nil) == want.admitted, "process publication: "+label)
						check(len(value.gate) == 0 && proto.Equal(value.request, request), "final admission or request ownership: "+label)
						if want.admitted {
							check(proto.Equal(value.Member(), local) && value.directory.Current(local), "complete current process identity: "+label)
						} else {
							check(len(value.directory.Members()) == 0, "failed pending loop changed its directory: "+label)
						}
						calls += got.calls
						waits += len(got.delays)
						witness(t, "retry", map[string]any{
							"role": role, "refresh": refresh, "prefix": prefix, "suffix": suffix,
							"calls": got.calls, "delays": got.delays, "callbacks": got.callbacks,
							"result": got.result, "admitted": got.admitted,
						})
					}()
					trials++
				}
			}
		}
	}
	check(trials == 594, "complete role, backoff-state and three-receipt domain")
	t.Logf("node-model version=1 roles=2 join-prefixes=8 refresh-prefixes=3 alphabet=3 depth=3 trials=%d calls=%d waits=%d pruning=none", trials, calls, waits)
}
