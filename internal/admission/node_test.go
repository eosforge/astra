// Verify Node publication, retry transitions, cancellation and native TLS transport.
package admission

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/internal/generated/orbit"
)

// transport exposes controlled RPC receipts without substituting Node synchronization.
type transport struct {
	register func(context.Context, *orbit.RegistrationRequest) (*orbit.RegistrationResponse, error) // Registration receipt.
	list     func(context.Context, *orbit.DirectoryRequest) (*orbit.DirectoryResponse, error)       // Directory receipt.
}

// Register rejects unexpected calls rather than providing a default successful response.
func (transport *transport) Register(ctx context.Context, request *orbit.RegistrationRequest, _ ...grpc.CallOption) (*orbit.RegistrationResponse, error) {
	if transport.register == nil {
		return nil, status.Error(codes.Internal, "Unexpected test registration")
	}
	return transport.register(ctx, request)
}

// List preserves the caller's context for the independently controlled refresh operation.
func (transport *transport) List(ctx context.Context, request *orbit.DirectoryRequest, _ ...grpc.CallOption) (*orbit.DirectoryResponse, error) {
	if transport.list == nil {
		return nil, status.Error(codes.Internal, "Unexpected test refresh")
	}
	return transport.list(ctx, request)
}

// node owns a real unopened gRPC channel and uses only public repository credentials.
func node(t *testing.T) (*Node, *orbit.Member) {
	t.Helper()
	value, err := Open(identity(t), "127.0.0.1:1", "alpha", "127.0.0.1:7443", "default", orbit.Role_ROLE_POLARIS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := value.Close(); err != nil {
			t.Error(err)
		}
	})
	member := &orbit.Member{Galaxy: "alpha", Id: []byte("local"), Principal: value.identity.Principal("alpha", "127.0.0.1:7443"), Advertise: "127.0.0.1:7443", Epoch: 1, Role: orbit.Role_ROLE_POLARIS, Group: "default"}
	return value, member
}

// response signs explicit fixture fields independently of the Node's response validation.
func response(t *testing.T, member *orbit.Member) *orbit.RegistrationResponse {
	t.Helper()
	data, err := proto.Marshal(member)
	if err != nil {
		t.Fatal(err)
	}
	return &orbit.RegistrationResponse{Admission: data, Signature: sign(t, data, "proto.orbit.v1.admission\x00"), Members: []*orbit.Member{proto.Clone(member).(*orbit.Member)}}
}

// ready publishes a healthy response through Register, keeping the initial request unchanged.
func ready(t *testing.T, value *Node, member *orbit.Member) {
	t.Helper()
	reply := response(t, member)
	value.client = &transport{register: func(context.Context, *orbit.RegistrationRequest) (*orbit.RegistrationResponse, error) {
		return reply, nil
	}}
	if err := value.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestNodeOpen checks both supported roles and each public argument rejection.
func TestNodeOpen(t *testing.T) {
	if os.Getenv("ASTRA_ADMISSION_RESOLVER") == "unregistered" {
		resolverFault(t)
		return
	}
	check := counter(t, "ADMISSION-NODE-OPEN")
	identity := identity(t)
	for _, role := range []orbit.Role{orbit.Role_ROLE_POLARIS, orbit.Role_ROLE_ASTROLABE} {
		value, err := Open(identity, "127.0.0.1:1", "alpha", "127.0.0.1:7443", "default", role)
		check(err == nil && value != nil, "valid Node constructor rejected")
		check(value.Directory() == value.directory && len(value.request.RequestId) == 32 && cap(value.gate) == 1, "constructor ownership or startup request changed")
		check(value.request.Role == role && value.request.Username == identity.username && value.request.Password == identity.password, "constructor registration fields changed")
		check(value.Close() == nil, "unopened channel did not close")
	}
	for index := range 7 {
		local, super, galaxy, advertise, group, role := identity, "127.0.0.1:1", "alpha", "127.0.0.1:7443", "default", orbit.Role_ROLE_POLARIS
		switch index {
		case 0:
			super = "localhost:1"
		case 1:
			advertise = "0.0.0.0:7443"
		case 2:
			local = nil
		case 3:
			galaxy = ""
		case 4:
			group = ""
		case 5:
			role = orbit.Role_ROLE_STAR
		case 6:
			role = orbit.Role_ROLE_PLANET
		}
		value, err := Open(local, super, galaxy, advertise, group, role)
		check(value == nil && errors.Is(err, ErrIdentity), "invalid Node input acquired a channel")
	}
	resolverChild(t, check)
}

// resolverFault changes only this child's public registry, then restores it before checking recovery.
func resolverFault(t *testing.T) {
	check := counter(t, "ADMISSION-NODE-RESOLVER")
	identity := identity(t)
	before := resolver.GetDefaultScheme()
	defer resolver.SetDefaultScheme(before)
	const missing = "astra-admission-unregistered"
	resolver.SetDefaultScheme(missing)
	check(resolver.GetDefaultScheme() == missing, "resolver fault was not armed")
	for range 2 {
		value, err := Open(identity, "127.0.0.1:1", "alpha", "127.0.0.1:7443", "default", orbit.Role_ROLE_POLARIS)
		if value != nil {
			defer value.Close()
		}
		check(value == nil && err != nil, "client construction failure published a partial Node")
		check(err.Error() == `could not get resolver for default scheme: "astra-admission-unregistered"`, "client construction failure lost its dependency error")
	}
	resolver.SetDefaultScheme(before)
	check(resolver.GetDefaultScheme() == before, "resolver registry did not recover")
	value, err := Open(identity, "127.0.0.1:1", "alpha", "127.0.0.1:7443", "default", orbit.Role_ROLE_POLARIS)
	if value != nil {
		t.Cleanup(func() {
			if value != nil {
				_ = value.Close()
			}
		})
	}
	check(value != nil && err == nil, "disarmed client construction did not recover")
	check(value.Close() == nil, "recovered client channel did not close")
	value = nil
}

// resolverChild owns and joins the isolated test process, retaining its native counters without changing this registry.
func resolverChild(t *testing.T, check func(bool, string)) {
	t.Helper()
	before := resolver.GetDefaultScheme()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	args := []string{"-test.run=^TestNodeOpen$", "-test.timeout=15s", "-test.v"}
	profile := ""
	if testing.CoverMode() != "" {
		profile = filepath.Join(t.TempDir(), "resolver.profile")
		args = append(args, "-test.coverprofile="+profile)
	}
	command := exec.CommandContext(ctx, os.Args[0], args...)
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "ASTRA_ADMISSION_RESOLVER=") {
			command.Env = append(command.Env, value)
		}
	}
	command.Env = append(command.Env, "ASTRA_ADMISSION_RESOLVER=unregistered")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated resolver check failed: %v; child: %s", err, output)
	}
	check(ctx.Err() == nil && command.ProcessState.Exited(), "resolver child did not complete within its owner budget")
	check(strings.Count(string(output), `ASTRA-CONTRACT {"contract":"ADMISSION-NODE-RESOLVER","hits":8}`) == 1, "resolver child omitted its completed assertion receipt")
	for _, line := range strings.Split(string(output), "\n") {
		for _, marker := range []string{"ASTRA-CONTRACT ", "GO-DECISIONS ", "GO-CONTROLS "} {
			if offset := strings.Index(line, marker); offset >= 0 {
				t.Log(line[offset:])
			}
		}
	}
	check(resolver.GetDefaultScheme() == before, "child registry mutation escaped its process")
	if profile != "" {
		data, err := os.ReadFile(profile)
		check(err == nil && len(data) > 0 && len(data) <= 1<<20, "resolver child omitted its bounded native profile")
		t.Log("ADMISSION-RESOLVER-PROFILE " + base64.StdEncoding.EncodeToString(data))
	}
}

// TestNodeState checks pending state, defensive message copies and outgoing metadata ownership.
func TestNodeState(t *testing.T) {
	check := counter(t, "ADMISSION-NODE-STATE")
	value, member := node(t)
	check(value.Member() == nil && value.Hello() == nil, "pending Node published credentials")
	ctx, err := value.Context(context.Background())
	check(ctx == nil && status.Code(err) == codes.Unavailable, "pending Node created an authenticated context")
	ready(t, value, member)
	check(proto.Equal(value.Member(), member) && value.directory.Current(member), "registered member was not current")
	hello := value.Hello()
	check(hello.ProtocolMajor == 1 && hello.MaxFrameBytes == 8<<20, "public hello protocol fields changed")
	copy := value.Member()
	copy.Id[0] ^= 1
	hello.Admission[0] ^= 1
	hello.AdmissionSignature[0] ^= 1
	check(proto.Equal(value.Member(), member) && !bytes.Equal(value.Hello().Admission, hello.Admission), "returned message modified Node ownership")
	original := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("retained", "value"))
	ctx, err = value.Context(original)
	check(err == nil, "ready Node rejected a fresh context")
	actual, _ := metadata.FromOutgoingContext(ctx)
	previous, _ := metadata.FromOutgoingContext(original)
	check(slices.Equal(actual.Get("retained"), []string{"value"}) && len(previous.Get("astra-admission-bin")) == 0, "context metadata aliased its input")
	check(slices.Equal(actual.Get("astra-admission-bin"), []string{string(value.Hello().Admission)}) && slices.Equal(actual.Get("astra-signature-bin"), []string{string(value.Hello().AdmissionSignature)}), "outgoing credentials changed")
	for _, key := range []string{"astra-admission-bin", "astra-signature-bin"} {
		ctx, err = value.Context(metadata.NewOutgoingContext(context.Background(), metadata.Pairs(key, "existing")))
		check(ctx == nil && errors.Is(err, ErrIdentity), "existing admission metadata was overwritten")
	}
}

// TestNodeRegistration rejects every response boundary twice without partial publication or nonce replacement.
func TestNodeRegistration(t *testing.T) {
	check := counter(t, "ADMISSION-NODE-REGISTER")
	for scenario := range 13 {
		value, local := node(t)
		request := proto.Clone(value.request).(*orbit.RegistrationRequest)
		candidate := proto.Clone(local).(*orbit.Member)
		want := codes.Unknown
		switch scenario {
		case 4:
			candidate.Galaxy = "other"
		case 5:
			candidate.Role = orbit.Role_ROLE_STAR
		case 6:
			candidate.Group = "other"
		case 7:
			candidate.Advertise = "127.0.0.1:7555"
		case 8:
			candidate.Principal[0] ^= 1
		case 11:
			newer := proto.Clone(local).(*orbit.Member)
			newer.Epoch, newer.Id = 2, []byte("newer")
			check(value.directory.Install([]*orbit.Member{newer}) == nil, "superseded fixture could not install")
		}
		reply := response(t, candidate)
		switch scenario {
		case 1:
			reply.Admission = nil
		case 2:
			reply.Signature = make([]byte, 64)
		case 3:
			reply.Admission = []byte{0xff}
			reply.Signature = sign(t, reply.Admission, "proto.orbit.v1.admission\x00")
		case 9:
			reply.Members = nil
		case 10:
			reply.Members = append(reply.Members, nil)
		case 12:
			reply.Members = []*orbit.Member{member(2, 1, orbit.Role_ROLE_STAR)}
		}
		before := value.directory.Members()
		calls := 0
		value.client = &transport{register: func(_ context.Context, current *orbit.RegistrationRequest) (*orbit.RegistrationResponse, error) {
			calls++
			check(proto.Equal(request, current), "failed registration replaced its startup request")
			if scenario == 0 {
				return nil, status.Error(codes.Unavailable, "Controlled refusal")
			}
			return reply, nil
		}}
		if scenario == 0 {
			want = codes.Unavailable
		}
		for range 2 {
			err := value.Register(context.Background())
			check(err != nil && status.Code(err) == want, "response boundary returned the wrong failure")
			check(value.Member() == nil && value.Hello() == nil && len(value.gate) == 0, "failed registration published state or retained its slot")
			check(slices.EqualFunc(before, value.directory.Members(), func(a, b *orbit.Member) bool { return proto.Equal(a, b) }), "rejected response changed the directory")
			check(proto.Equal(value.request, request), "rejected response changed retry identity")
		}
		check(calls == 2, "registration failure was hidden by an unexpected retry")
		local.Epoch, local.Id = 3, []byte("recovered")
		ready(t, value, local)
		check(proto.Equal(value.Member(), local) && value.directory.Current(local) && len(value.gate) == 0, "healthy registration did not recover the same Node")
		value.client = &transport{}
		check(value.Register(context.Background()) == nil && proto.Equal(value.request, request), "ready Node registered its password again")
	}
}

// TestNodeRefresh checks pending state, transport refusal, complete-list validation and process replacement.
func TestNodeRefresh(t *testing.T) {
	check := counter(t, "ADMISSION-NODE-REFRESH")
	value, local := node(t)
	check(status.Code(value.Refresh(context.Background())) == codes.Unavailable && len(value.gate) == 0, "pending refresh acquired credentials or retained its slot")
	ready(t, value, local)
	before := value.Hello()
	for scenario := range 5 {
		members := []*orbit.Member{proto.Clone(local).(*orbit.Member)}
		want := codes.Unknown
		if scenario == 1 {
			members = nil
			want = codes.Unauthenticated
		}
		if scenario == 2 {
			members = append(members, nil)
		}
		if scenario == 3 {
			newer := proto.Clone(local).(*orbit.Member)
			newer.Epoch, newer.Id = 2, []byte("newer")
			check(value.directory.Install([]*orbit.Member{newer}) == nil, "replacement fixture could not install")
			want = codes.Unauthenticated
		}
		value.client = &transport{list: func(context.Context, *orbit.DirectoryRequest) (*orbit.DirectoryResponse, error) {
			if scenario == 0 {
				return nil, status.Error(codes.Unavailable, "Controlled refusal")
			}
			return &orbit.DirectoryResponse{Members: members}, nil
		}}
		if scenario == 0 {
			want = codes.Unavailable
		}
		ctx := context.Background()
		if scenario == 4 {
			ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("astra-signature-bin", "existing"))
		}
		err := value.Refresh(ctx)
		check(err != nil && status.Code(err) == want && len(value.gate) == 0, "failed refresh returned the wrong result or retained its slot")
		check(proto.Equal(value.Member(), local) && proto.Equal(value.Hello(), before), "refresh silently replaced the process credential")
	}
	value, local = node(t)
	ready(t, value, local)
	value.client = &transport{list: func(context.Context, *orbit.DirectoryRequest) (*orbit.DirectoryResponse, error) {
		return &orbit.DirectoryResponse{Members: []*orbit.Member{local}}, nil
	}}
	check(value.Refresh(context.Background()) == nil && value.directory.Current(local) && len(value.gate) == 0, "healthy refresh did not retain current admission")
}

// TestNodeSerialization constructs overlap with latches, cancels blocked operations and joins the actual worker.
func TestNodeSerialization(t *testing.T) {
	check := counter(t, "ADMISSION-NODE-SCHEDULE")
	value, local := node(t)
	reply := response(t, local)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	var once sync.Once
	var calls atomic.Int32
	value.client = &transport{register: func(ctx context.Context, _ *orbit.RegistrationRequest) (*orbit.RegistrationResponse, error) {
		calls.Add(1)
		close(entered)
		select {
		case <-release:
			return reply, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	t.Cleanup(func() {
		cancel()
		once.Do(func() { close(release) })
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			t.Error("registration worker did not drain")
		}
	})
	go func() { result <- value.Register(ctx); close(finished) }()
	select {
	case <-entered:
		check(true, "registration entered")
	case <-ctx.Done():
		t.Fatal("registration did not enter")
	}
	check(value.Member() == nil && value.Hello() == nil && len(value.gate) == 1, "in-flight request published partial state")
	blocked, stop := context.WithCancel(context.Background())
	stop()
	check(errors.Is(value.Register(blocked), context.Canceled), "blocked registration ignored cancellation")
	check(errors.Is(value.Refresh(blocked), context.Canceled), "blocked refresh ignored cancellation")
	check(calls.Load() == 1 && len(value.gate) == 1, "blocked operation entered transport or released another owner's slot")
	once.Do(func() { close(release) })
	select {
	case err := <-result:
		check(err == nil, "released registration failed")
	case <-ctx.Done():
		t.Fatal("released registration did not finish")
	}
	check(proto.Equal(value.Member(), local) && value.directory.Current(local) && len(value.gate) == 0, "completed registration did not publish atomically")
	check(value.Register(ctx) == nil && calls.Load() == 1, "completed registration repeated its external operation")
}

// TestNodeJoin steps retry time explicitly, retaining the same request through the fixed exponential cap.
func TestNodeJoin(t *testing.T) {
	check := counter(t, "ADMISSION-NODE-RETRY")
	value, local := node(t)
	reply, request := response(t, local), proto.Clone(value.request).(*orbit.RegistrationRequest)
	calls := 0
	value.client = &transport{register: func(_ context.Context, current *orbit.RegistrationRequest) (*orbit.RegistrationResponse, error) {
		check(proto.Equal(request, current), "Join replaced retry identity")
		calls++
		if calls <= 9 {
			return nil, status.Error(codes.Unavailable, "Controlled transient failure")
		}
		return reply, nil
	}}
	var delays []time.Duration
	err := value.join(context.Background(), func(_ context.Context, delay time.Duration) error {
		delays = append(delays, delay)
		if len(delays) > 12 {
			return context.Canceled
		}
		return nil
	})
	check(err == nil && calls == 10, "Join did not stop at healthy registration")
	check(slices.Equal(delays, []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second}), "Join retry sequence or cap changed")
	check(value.Join(context.Background()) == nil && calls == 10, "public Join repeated a completed operation")
	value, _ = node(t)
	value.client = &transport{register: func(context.Context, *orbit.RegistrationRequest) (*orbit.RegistrationResponse, error) {
		return nil, status.Error(codes.PermissionDenied, "Controlled permanent refusal")
	}}
	check(status.Code(value.join(context.Background(), func(context.Context, time.Duration) error { t.Fatal("permanent refusal waited"); return nil })) == codes.PermissionDenied, "permanent refusal was hidden")
	value.client = &transport{register: func(context.Context, *orbit.RegistrationRequest) (*orbit.RegistrationResponse, error) {
		return nil, status.Error(codes.Unavailable, "Controlled transient refusal")
	}}
	check(errors.Is(value.join(context.Background(), func(context.Context, time.Duration) error { return context.Canceled }), context.Canceled), "Join swallowed waiting cancellation")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	value.gate <- struct{}{}
	check(errors.Is(value.Join(ctx), context.Canceled), "public Join did not cancel blocked admission")
	<-value.gate
}

// TestNodeCancellation distinguishes owner cancellation from refusal, successful admission and remote cancellation.
func TestNodeCancellation(t *testing.T) {
	for _, name := range []string{"cancelled", "unavailable", "refused", "identity", "committed", "remote"} {
		t.Run(name, func(t *testing.T) {
			value, local := node(t)
			reply := response(t, local)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls, waits := 0, 0
			value.client = &transport{register: func(context.Context, *orbit.RegistrationRequest) (*orbit.RegistrationResponse, error) {
				calls++
				if name != "remote" {
					cancel()
				}
				switch name {
				case "committed":
					return reply, nil
				case "identity":
					return &orbit.RegistrationResponse{}, nil
				case "refused":
					return nil, status.Error(codes.PermissionDenied, "Controlled permanent refusal")
				case "unavailable":
					return nil, status.Error(codes.Unavailable, "Controlled interrupted transport")
				default:
					return nil, status.Error(codes.Canceled, "Controlled cancelled RPC")
				}
			}}
			waiting := errors.New("controlled retry boundary")
			err := value.join(ctx, func(context.Context, time.Duration) error {
				waits++
				return waiting
			})
			switch name {
			case "committed":
				if err != nil || !proto.Equal(value.Member(), local) || !value.directory.Current(local) {
					t.Fatal("owner cancellation hid completed admission", err)
				}
			case "refused":
				if status.Code(err) != codes.PermissionDenied {
					t.Fatal("owner cancellation hid permanent refusal", err)
				}
			case "identity":
				if !errors.Is(err, ErrIdentity) {
					t.Fatal("owner cancellation hid invalid identity", err)
				}
			case "remote":
				if err != waiting || ctx.Err() != nil || waits != 1 {
					t.Fatal("remote cancellation was mistaken for owner cancellation", err, waits)
				}
			default:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("interrupted admission lost its owner cancellation cause", err)
				}
			}
			if calls != 1 || len(value.gate) != 0 || name != "remote" && waits != 0 || name != "committed" && value.Member() != nil {
				t.Fatal("join retried a terminal outcome, retained admission ownership or published rejected state", calls, waits)
			}
		})
	}
}

// TestNodeRun specifies callback order, transient backoff, reset, permanent refusal and cancellation.
func TestNodeRun(t *testing.T) {
	check := counter(t, "ADMISSION-NODE-RUN")
	value, local := node(t)
	ready(t, value, local)
	calls := 0
	value.client = &transport{list: func(context.Context, *orbit.DirectoryRequest) (*orbit.DirectoryResponse, error) {
		calls++
		if calls < 4 {
			return nil, status.Error(codes.Unavailable, "Controlled transient refusal")
		}
		if calls > 4 {
			return nil, status.Error(codes.Aborted, "Controlled permanent refusal")
		}
		return &orbit.DirectoryResponse{Members: []*orbit.Member{local}}, nil
	}}
	var delays []time.Duration
	var callbacks []codes.Code
	err := value.run(context.Background(), func(err error) { callbacks = append(callbacks, status.Code(err)) }, func(_ context.Context, delay time.Duration) error {
		delays = append(delays, delay)
		if len(delays) > 6 {
			return context.Canceled
		}
		return nil
	})
	check(status.Code(err) == codes.Aborted && calls == 5, "Run did not stop at permanent refusal")
	check(slices.Equal(delays, []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 2 * time.Minute, 30 * time.Second}), "Run retry cap or healthy reset changed")
	check(slices.Equal(callbacks, []codes.Code{codes.Unavailable, codes.Unavailable, codes.Unavailable, codes.OK, codes.Aborted}), "Run callback order changed")
	check(errors.Is(value.run(context.Background(), nil, func(context.Context, time.Duration) error { return context.Canceled }), context.Canceled) && calls == 5, "cancelled wait refreshed admission")
	ctx, cancel := context.WithCancel(context.Background())
	value.client = &transport{list: func(context.Context, *orbit.DirectoryRequest) (*orbit.DirectoryResponse, error) {
		return &orbit.DirectoryResponse{Members: []*orbit.Member{local}}, nil
	}}
	check(errors.Is(value.run(ctx, func(error) { cancel() }, func(context.Context, time.Duration) error { return nil }), context.Canceled), "callback cancellation was swallowed")
	check(errors.Is(value.Run(ctx, nil), context.Canceled), "public Run did not cancel its real timer")
	check(proto.Equal(value.Member(), local) && value.directory.Current(local) && len(value.gate) == 0, "stopped refresh loop changed admission or retained its slot")
	refreshes := 0
	value.client = &transport{list: func(context.Context, *orbit.DirectoryRequest) (*orbit.DirectoryResponse, error) {
		refreshes++
		return &orbit.DirectoryResponse{Members: []*orbit.Member{local}}, nil
	}}
	err = value.run(context.Background(), nil, func(context.Context, time.Duration) error {
		if refreshes == 1 {
			return context.Canceled
		}
		return nil
	})
	check(errors.Is(err, context.Canceled) && refreshes == 1, "absent callback prevented one complete refresh or ignored cancellation")
	check(proto.Equal(value.Member(), local) && value.directory.Current(local) && len(value.gate) == 0, "callback-free refresh changed admission or retained its slot")
}

// TestNodePause exercises the actual timer's immediately ready and cancelled branches without sleep.
func TestNodePause(t *testing.T) {
	check := counter(t, "ADMISSION-NODE-PAUSE")
	check(pause(context.Background(), 0) == nil, "ready timer did not finish")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	check(errors.Is(pause(ctx, time.Hour), context.Canceled), "real timer ignored cancellation")
	for _, err := range []error{nil, errors.New("Transient fixture"), status.Error(codes.Unavailable, "Transient fixture")} {
		check(!fatal(err), "transient result became permanent")
	}
	for _, err := range []error{ErrIdentity, status.Error(codes.Unauthenticated, "Permanent fixture"), status.Error(codes.PermissionDenied, "Permanent fixture"), status.Error(codes.InvalidArgument, "Permanent fixture"), status.Error(codes.Aborted, "Permanent fixture")} {
		check(fatal(err), "permanent result became retryable")
	}
}

// authority supplies real generated gRPC replies over a repository-fixture TLS connection.
type authority struct {
	orbit.UnimplementedAdmissionServer
	reply         *orbit.RegistrationResponse // Immutable signed fixture.
	registrations atomic.Int32                // Actual server calls.
	refreshes     atomic.Int32                // Successfully authenticated refreshes.
}

// Register requires one complete startup token and returns an independently signed member.
func (authority *authority) Register(_ context.Context, request *orbit.RegistrationRequest) (*orbit.RegistrationResponse, error) {
	authority.registrations.Add(1)
	if len(request.RequestId) != 32 || request.Galaxy != "alpha" || request.Role != orbit.Role_ROLE_POLARIS || request.Advertise != "127.0.0.1:7443" {
		return nil, status.Error(codes.InvalidArgument, "Unexpected fixture request")
	}
	return proto.Clone(authority.reply).(*orbit.RegistrationResponse), nil
}

// List verifies the exact credentials transported by the public Node context.
func (authority *authority) List(ctx context.Context, _ *orbit.DirectoryRequest) (*orbit.DirectoryResponse, error) {
	values, _ := metadata.FromIncomingContext(ctx)
	if !slices.Equal(values.Get("astra-admission-bin"), []string{string(authority.reply.Admission)}) || !slices.Equal(values.Get("astra-signature-bin"), []string{string(authority.reply.Signature)}) {
		return nil, status.Error(codes.Unauthenticated, "Unexpected fixture admission")
	}
	authority.refreshes.Add(1)
	return &orbit.DirectoryResponse{Members: []*orbit.Member{proto.Clone(authority.reply.Members[0]).(*orbit.Member)}}, nil
}

// TestNodeTransport consumes public Join/Refresh with real TLS, generated RPCs and joined server ownership.
func TestNodeTransport(t *testing.T) {
	check := counter(t, "ADMISSION-NODE-TRANSPORT")
	identity := identity(t)
	local := &orbit.Member{Galaxy: "alpha", Id: []byte("native"), Principal: identity.Principal("alpha", "127.0.0.1:7443"), Advertise: "127.0.0.1:7443", Epoch: 1, Role: orbit.Role_ROLE_POLARIS, Group: "default"}
	service := &authority{reply: response(t, local)}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	})
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(identity.Server())))
	orbit.RegisterAdmissionServer(server, service)
	finished := make(chan error, 1)
	go func() { finished <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		select {
		case err := <-finished:
			if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("fixture RPC server did not drain")
		}
	})
	value, err := Open(identity, listener.Addr().String(), "alpha", "127.0.0.1:7443", "default", orbit.Role_ROLE_POLARIS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := value.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	check(value.Join(ctx) == nil, "native TLS registration failed")
	check(value.Join(ctx) == nil && service.registrations.Load() == 1, "native completed Join registered twice")
	check(value.Refresh(ctx) == nil && service.refreshes.Load() == 1, "native authenticated refresh failed")
	check(proto.Equal(value.Member(), local) && value.directory.Current(local), "native transport published wrong admission")
}
