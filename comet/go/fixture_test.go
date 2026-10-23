// Provide local wire-level fault fixtures with explicit channels and no service downloads.
package comet

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// fixtureHandlers are immutable after server start; tests synchronize captured state.
type fixtureHandlers struct {
	session   func(*protocol.SessionRequest, grpc.ServerStreamingServer[protocol.SessionReply]) error      // Authentication history.
	query     func(context.Context, *protocol.CatalogQueryRequest) (*protocol.CatalogQueryReply, error)    // Fixed version watermark oracle.
	publish   func(context.Context, *protocol.PublishRequest) (*protocol.PublishReply, error)              // Commit or lost-receipt script.
	create    func(context.Context, *protocol.CreateRequest) (*protocol.CreateReply, error)                // Initial/recovery registration script.
	update    func(context.Context, *protocol.UpdateRequest) (*protocol.UpdateReply, error)                // Complete Data update script.
	renew     func(context.Context, *protocol.RenewRequest) (*protocol.RenewReply, error)                  // Independent renewal sequence script.
	remove    func(context.Context, *protocol.RemoveRequest) (*protocol.Empty, error)                      // Bounded cleanup observation.
	catalog   func(*protocol.WatchRequest, grpc.ServerStreamingServer[protocol.CatalogWatchReply]) error   // Catalog page script.
	almanac   func(*protocol.WatchRequest, grpc.ServerStreamingServer[protocol.AlmanacWatchReply]) error   // Authority floor script.
	ephemeris func(*protocol.WatchRequest, grpc.ServerStreamingServer[protocol.EphemerisWatchReply]) error // Record/Data-only script.
}

// fixture is a TCP gRPC endpoint whose server resources belong only to this test.
type fixture struct {
	address  string          // OS-assigned loopback port, isolated from other cases.
	server   *grpc.Server    // Stop cancels every owned server stream.
	handlers fixtureHandlers // Fixed operations, with explicit defaults below.
}

// newFixture starts the exact private generated services; cleanup joins Serve.
func newFixture(t *testing.T, handlers fixtureHandlers, options ...grpc.ServerOption) *fixture {
	t.Helper()
	listener, cause := net.Listen("tcp", "127.0.0.1:0")
	if cause != nil {
		t.Fatal(cause)
	}
	// Stop must join fixture handlers as well as Serve, so no assertion/event
	// producer can survive the owning test's cleanup boundary.
	options = append([]grpc.ServerOption{grpc.WaitForHandlers(true)}, options...)
	fixture := &fixture{address: listener.Addr().String(), server: grpc.NewServer(options...), handlers: handlers}
	protocol.RegisterGatewayServer(fixture.server, &gatewayFixture{fixture: fixture})
	protocol.RegisterCatalogServer(fixture.server, &catalogFixture{fixture: fixture})
	protocol.RegisterAlmanacServer(fixture.server, &almanacFixture{fixture: fixture})
	protocol.RegisterEphemerisServer(fixture.server, &ephemerisFixture{fixture: fixture})
	done := make(chan struct{})
	go func() { defer close(done); _ = fixture.server.Serve(listener) }()
	t.Cleanup(func() { fixture.server.Stop(); _ = listener.Close(); <-done })
	return fixture
}

// fixtureClient owns a real SDK Client and drains it before its server is stopped.
func fixtureClient(t *testing.T, fixture *fixture, options ...Options) *Client {
	t.Helper()
	settings := Options{Anonymous: true, Plaintext: true}
	if len(options) != 0 {
		settings = options[0]
	}
	settings.Endpoints = []string{fixture.address}
	client, cause := New(settings)
	if cause != nil {
		t.Fatal(cause)
	}
	t.Cleanup(func() {
		client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if cause := client.Wait(ctx); cause != nil {
			t.Errorf("client did not drain: %v", cause)
		}
		if used := client.used.Load(); used != 0 {
			t.Errorf("retained %d controlled bytes after drain", used)
		}
	})
	return client
}

// gatewayFixture supplies authentication independently of unary fixture behavior.
type gatewayFixture struct {
	protocol.UnimplementedGatewayServer
	fixture *fixture // Server and immutable handler configuration.
}

// Session defaults to one confirmation followed by a live Session stream.
func (server *gatewayFixture) Session(request *protocol.SessionRequest, stream grpc.ServerStreamingServer[protocol.SessionReply]) error {
	if handler := server.fixture.handlers.session; handler != nil {
		return handler(request, stream)
	}
	if cause := stream.Send(&protocol.SessionReply{Instance: []byte("star-a"), Session: make([]byte, 32)}); cause != nil {
		return cause
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

// catalogFixture exposes explicit Query/Publish histories and optional Watch faults.
type catalogFixture struct {
	protocol.UnimplementedCatalogServer
	fixture *fixture // Server and immutable handler configuration.
}

// Query defaults to a complete same-order zero watermark response.
func (server *catalogFixture) Query(ctx context.Context, request *protocol.CatalogQueryRequest) (*protocol.CatalogQueryReply, error) {
	if handler := server.fixture.handlers.query; handler != nil {
		return handler(ctx, request)
	}
	reply := &protocol.CatalogQueryReply{Instance: []byte("star-a")}
	for _, key := range request.Keys {
		reply.Entries = append(reply.Entries, &protocol.CatalogQueryReply_Entry{Key: key})
	}
	return reply, nil
}

// Publish defaults to acknowledging the exact submitted instance and version.
func (server *catalogFixture) Publish(ctx context.Context, request *protocol.PublishRequest) (*protocol.PublishReply, error) {
	if handler := server.fixture.handlers.publish; handler != nil {
		return handler(ctx, request)
	}
	return &protocol.PublishReply{Instance: request.Instance, Version: request.Version}, nil
}

// Watch requires an explicit stream script so an unintended call is visible.
func (server *catalogFixture) Watch(request *protocol.WatchRequest, stream grpc.ServerStreamingServer[protocol.CatalogWatchReply]) error {
	if handler := server.fixture.handlers.catalog; handler != nil {
		return handler(request, stream)
	}
	return status.Error(codes.Unimplemented, "fixture has no Catalog stream")
}

// almanacFixture owns authority-floor stream scripts.
type almanacFixture struct {
	protocol.UnimplementedAlmanacServer
	fixture *fixture // Server and immutable handler configuration.
}

// Watch requires a test-authored authority sequence.
func (server *almanacFixture) Watch(request *protocol.WatchRequest, stream grpc.ServerStreamingServer[protocol.AlmanacWatchReply]) error {
	if handler := server.fixture.handlers.almanac; handler != nil {
		return handler(request, stream)
	}
	return status.Error(codes.Unimplemented, "fixture has no Almanac stream")
}

// ephemerisFixture owns registration operations and optional observation scripts.
type ephemerisFixture struct {
	protocol.UnimplementedEphemerisServer
	fixture *fixture // Server and immutable handler configuration.
}

// fixtureID is a valid binary UUIDv4 used only as deterministic protocol input.
func fixtureID() []byte { return []byte{1, 2, 3, 4, 5, 6, 0x47, 8, 0x89, 10, 11, 12, 13, 14, 15, 16} }

// Create issues a fixed test capability and otherwise echoes registration fields.
func (server *ephemerisFixture) Create(ctx context.Context, request *protocol.CreateRequest) (*protocol.CreateReply, error) {
	if handler := server.fixture.handlers.create; handler != nil {
		return handler(ctx, request)
	}
	return &protocol.CreateReply{Instance: []byte("star-a"), Uuid: fixtureID(), Capability: make([]byte, 32),
		Generation: request.Generation, TtlMs: request.TtlMs, Order: request.Order, Data: request.Data}, nil
}

// Update defaults to acknowledging the exact order with no automatic application retry.
func (server *ephemerisFixture) Update(ctx context.Context, request *protocol.UpdateRequest) (*protocol.UpdateReply, error) {
	if handler := server.fixture.handlers.update; handler != nil {
		return handler(ctx, request)
	}
	return &protocol.UpdateReply{Order: request.Order}, nil
}

// Renew exposes its independent order sequence to tests that override the default.
func (server *ephemerisFixture) Renew(ctx context.Context, request *protocol.RenewRequest) (*protocol.RenewReply, error) {
	if handler := server.fixture.handlers.renew; handler != nil {
		return handler(ctx, request)
	}
	return &protocol.RenewReply{Order: request.Order}, nil
}

// Remove acknowledges one best-effort unregister, unless a case injects a fault.
func (server *ephemerisFixture) Remove(ctx context.Context, request *protocol.RemoveRequest) (*protocol.Empty, error) {
	if handler := server.fixture.handlers.remove; handler != nil {
		return handler(ctx, request)
	}
	return &protocol.Empty{}, nil
}

// Watch requires an explicit full-record/Data-only history.
func (server *ephemerisFixture) Watch(request *protocol.WatchRequest, stream grpc.ServerStreamingServer[protocol.EphemerisWatchReply]) error {
	if handler := server.fixture.handlers.ephemeris; handler != nil {
		return handler(request, stream)
	}
	return status.Error(codes.Unimplemented, "fixture has no Ephemeris stream")
}

// rejected writes a valid bounded precommit detail; message text stays deliberately untrusted.
func rejected(ctx context.Context, reason protocol.Reason) error {
	body, cause := proto.Marshal(&protocol.Failure{Reason: reason, Effect: protocol.Effect_EFFECT_UNAPPLIED, Message: "untrusted private server detail"})
	if cause != nil {
		return cause
	}
	if cause := grpc.SetTrailer(ctx, metadata.Pairs("comet-error-bin", string(body))); cause != nil {
		return cause
	}
	return status.Error(codes.FailedPrecondition, "untrusted private status text")
}

// receiveTest bounds a test synchronization wait; no fixed sleep proves behavior.
func receiveTest[T any](t *testing.T, values <-chan T) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for fixture event")
		var zero T
		return zero
	}
}

// requireCode checks a public structured failure rather than error-string matching.
func requireCode(t *testing.T, cause error, code Code, effect Effect) {
	t.Helper()
	var failure *Error
	if !errors.As(cause, &failure) || failure.Code != code || failure.Effect != effect {
		t.Fatalf("failure = %#v; want code %d effect %d", cause, code, effect)
	}
}

// oracle counts successful assertions in one test goroutine for the native
// gate adapter; failed assertions still fail the owning Go test immediately.
func oracle(t *testing.T, contract string) func(bool, string) {
	t.Helper()
	hits := 0
	t.Cleanup(func() { t.Logf(`ASTRA-CONTRACT {"contract":%q,"hits":%d}`, contract, hits) })
	return func(condition bool, message string) {
		t.Helper()
		if !condition {
			t.Fatal(message)
		}
		hits++
	}
}

// testScope returns a public byte-exact scope shared only within local fixtures.
func testScope() Scope { return Scope{Sector: "test", Spectrum: "native-go"} }

// recordTest records bounded fixture events without allowing an unexpected
// repeat to block RPC/Client cleanup and hide the actual assertion failure.
func recordTest[T any](t *testing.T, events chan<- T, value T) {
	t.Helper()
	select {
	case events <- value:
	default:
		t.Error("fixture event exceeded its declared capacity")
	}
}

// testContext bounds explicit test waits and is canceled by the owning test.
func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// awaitCondition waits for an observed state transition, not a fixed elapsed-time guess.
func awaitCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for !condition() {
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("expected state transition did not occur")
		}
	}
}
