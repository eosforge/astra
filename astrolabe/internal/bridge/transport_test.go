// Exercise the production bridge over real TLS and signed admission with controlled authority responses.
package bridge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eosforge/astra/internal/admission"
	"github.com/eosforge/astra/internal/generated/comet"
	"github.com/eosforge/astra/internal/generated/orbit"
	"github.com/eosforge/astra/internal/generated/polaris"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// registration returns one independently signed fixture identity without modifying admission internals.
type registration struct {
	orbit.UnimplementedAdmissionServer
	response *orbit.RegistrationResponse
}

// Register returns an independent copy of the configured admission response.
func (service *registration) Register(context.Context, *orbit.RegistrationRequest) (*orbit.RegistrationResponse, error) {
	return proto.Clone(service.response).(*orbit.RegistrationResponse), nil
}

// authority owns immutable per-test handlers; counters record actual transport calls, including rejected calls.
type authority struct {
	polaris.UnimplementedAuthorityServer
	identity *admission.Identity
	member   *orbit.Member
	commits  atomic.Int32
	batches  atomic.Int32
	loads    atomic.Int32
	lists    atomic.Int32
	commit   func(context.Context, *polaris.CommitRequest) (*polaris.Position, error)
	batch    func(grpc.ClientStreamingServer[polaris.BatchRequest, polaris.Position]) error
	load     func(*comet.Scope, grpc.ServerStreamingServer[polaris.Snapshot]) error
}

// authenticate requires the actual Node-provided bearer and its fixture signature on every authority operation.
func (service *authority) authenticate(ctx context.Context) error {
	values, ok := metadata.FromIncomingContext(ctx)
	if !ok || len(values.Get("astra-admission-bin")) != 1 || len(values.Get("astra-signature-bin")) != 1 {
		return status.Error(codes.Unauthenticated, "missing fixture admission")
	}
	member, err := service.identity.Verify([]byte(values.Get("astra-admission-bin")[0]), []byte(values.Get("astra-signature-bin")[0]))
	if err != nil || !proto.Equal(member, service.member) {
		return status.Error(codes.Unauthenticated, "invalid fixture admission")
	}
	return nil
}

// Commit counts the request and authenticates it before invoking the configured handler.
func (service *authority) Commit(ctx context.Context, request *polaris.CommitRequest) (*polaris.Position, error) {
	service.commits.Add(1)
	if err := service.authenticate(ctx); err != nil {
		return nil, err
	}
	return service.commit(ctx, request)
}

// Batch counts the stream and authenticates it before invoking the configured handler.
func (service *authority) Batch(stream grpc.ClientStreamingServer[polaris.BatchRequest, polaris.Position]) error {
	service.batches.Add(1)
	if err := service.authenticate(stream.Context()); err != nil {
		return err
	}
	return service.batch(stream)
}

// Load counts the stream and authenticates it before invoking the configured snapshot handler.
func (service *authority) Load(scope *comet.Scope, stream grpc.ServerStreamingServer[polaris.Snapshot]) error {
	service.loads.Add(1)
	if err := service.authenticate(stream.Context()); err != nil {
		return err
	}
	return service.load(scope, stream)
}

// List counts and authenticates the request before returning the fixed complete inventory.
func (service *authority) List(ctx context.Context, _ *comet.Empty) (*polaris.Inventory, error) {
	service.lists.Add(1)
	if err := service.authenticate(ctx); err != nil {
		return nil, err
	}
	return &polaris.Inventory{Complete: true, Positions: []*polaris.Position{{Scope: &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}, Version: 7}}}, nil
}

// transport starts one isolated TLS peer, registers a real Node, and drains all owned resources on cleanup.
func transport(t *testing.T, service *authority) (*Backend, *admission.Node, *orbit.Member) {
	t.Helper()
	fixtures := filepath.Join("..", "..", "..", "tests", "fixtures")
	identity, err := admission.Load(filepath.Join(fixtures, "star-a"), "127.0.0.1:7447")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	local := &orbit.Member{Id: []byte("manager"), Galaxy: "alpha", Group: "default", Advertise: "127.0.0.1:7447", Role: orbit.Role_ROLE_ASTROLABE, Epoch: 1, Principal: identity.Principal("alpha", "127.0.0.1:7447")}
	member := &orbit.Member{Id: []byte("polaris"), Galaxy: "alpha", Group: "default", Advertise: listener.Addr().String(), Role: orbit.Role_ROLE_POLARIS, Epoch: 1, Principal: identity.Principal("alpha", listener.Addr().String())}
	data, err := proto.Marshal(local)
	if err != nil {
		t.Fatal(err)
	}
	material, err := os.ReadFile(filepath.Join(fixtures, "pulsar", "admission.key"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(material)
	if block == nil {
		t.Fatal("missing public fixture key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("unexpected fixture key type")
	}
	service.identity, service.member = identity, local
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(identity.Server())))
	orbit.RegisterAdmissionServer(server, &registration{response: &orbit.RegistrationResponse{Admission: data, Signature: ed25519.Sign(key, append([]byte("proto.orbit.v1.admission\x00"), data...)), Members: []*orbit.Member{local, member}}})
	polaris.RegisterAuthorityServer(server, service)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		if err := <-done; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Error(err)
		}
	})
	node, err := admission.Open(identity, listener.Addr().String(), "alpha", local.Advertise, "default", orbit.Role_ROLE_ASTROLABE)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := node.Register(ctx); err != nil {
		t.Fatal(err)
	}
	backend := New(node, identity)
	t.Cleanup(backend.Close)
	backend.Update(nil)
	return backend, node, member
}

// TestTransport verifies admitted forwarding, unary result ambiguity, and exact large-batch transport boundaries.
func TestTransport(t *testing.T) {
	hits := 0
	t.Cleanup(func() { t.Logf(`ASTRA-CONTRACT {"contract":"ASTROLABE-TRANSPORT","hits":%d}`, hits) })
	scope := &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}
	if t.Run("unary", func(t *testing.T) {
		request := &polaris.CommitRequest{Scope: scope, Version: 8, Change: &comet.AlmanacChange{Key: "key", Action: &comet.AlmanacChange_Value{Value: []byte("value")}}}
		service := &authority{load: func(*comet.Scope, grpc.ServerStreamingServer[polaris.Snapshot]) error {
			return status.Error(codes.Internal, "cancelled load reached peer")
		}, commit: func(_ context.Context, received *polaris.CommitRequest) (*polaris.Position, error) {
			if !proto.Equal(received, request) {
				return nil, status.Error(codes.InvalidArgument, "changed request")
			}
			return nil, status.Error(codes.Unavailable, "committed but receipt lost")
		}}
		backend, _, _ := transport(t, service)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		inventory, err := backend.List(ctx)
		if err != nil || !inventory.Complete || len(inventory.Positions) != 1 || inventory.Positions[0].Version != 7 {
			t.Fatal("inventory forwarding", inventory, err)
		}
		cancelled, stop := context.WithCancel(ctx)
		stop()
		if err := backend.Load(cancelled, scope, func(*polaris.Snapshot) error { return errors.New("unexpected page") }); status.Code(err) != codes.Canceled || service.loads.Load() != 0 {
			t.Fatal("pre-cancelled load was sent", err)
		}
		if _, err := backend.Commit(cancelled, &polaris.CommitRequest{Scope: scope, Version: 8, Changes: []*comet.AlmanacChange{request.Change}}); status.Code(err) != codes.Canceled || service.batches.Load() != 0 {
			t.Fatal("pre-cancelled batch was sent", err)
		}
		position, err := backend.Commit(ctx, request)
		if position != nil || status.Code(err) != codes.Unavailable || service.commits.Load() != 1 || service.batches.Load() != 0 {
			t.Fatal("ambiguous write was retried or rerouted", position, err)
		}
		contaminated := metadata.AppendToOutgoingContext(ctx, "astra-admission-bin", "untrusted")
		if _, err := backend.List(contaminated); !errors.Is(err, admission.ErrIdentity) || service.lists.Load() != 1 {
			t.Fatal("caller metadata reached the authority", err)
		}
	}) {
		hits++
	}
	for _, size := range []struct {
		name                string
		count, bytes, pages int
	}{{"many-keys", 129, 1, 1}, {"split", 3, 150 << 10, 3}, {"large-total", 9, 300 << 10, 9}} {
		if t.Run(size.name, func(t *testing.T) {
			request := &polaris.CommitRequest{Scope: scope, Version: 8}
			for index := range size.count {
				request.Changes = append(request.Changes, &comet.AlmanacChange{Key: fmt.Sprint(index), Action: &comet.AlmanacChange_Value{Value: bytes.Repeat([]byte{byte(index)}, size.bytes)}})
			}
			service := &authority{batch: func(stream grpc.ClientStreamingServer[polaris.BatchRequest, polaris.Position]) error {
				var changes []*comet.AlmanacChange
				pages := 0
				complete := false
				for {
					page, err := stream.Recv()
					if errors.Is(err, io.EOF) {
						break
					}
					if err != nil {
						return err
					}
					if complete || !proto.Equal(page.Scope, scope) || page.Version != request.Version || len(page.Changes) == 0 {
						return status.Error(codes.InvalidArgument, "invalid transport page")
					}
					changes = append(changes, page.Changes...)
					complete = page.Complete
					pages++
				}
				if !complete || pages != size.pages || !proto.Equal(&polaris.CommitRequest{Scope: scope, Version: request.Version, Changes: changes}, request) {
					return status.Error(codes.DataLoss, "partial or altered batch")
				}
				return stream.SendAndClose(&polaris.Position{Scope: scope, Version: request.Version})
			}}
			backend, _, _ := transport(t, service)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			position, err := backend.Commit(ctx, request)
			if err != nil || !proto.Equal(position, &polaris.Position{Scope: scope, Version: 8}) || service.batches.Load() != 1 || service.commits.Load() != 0 {
				t.Fatal("batch forwarding", position, err)
			}
		}) {
			hits++
		}
	}
}

// TestTransportLoad proves page order, error preservation and server-observed cancellation after consumer failure.
func TestTransportLoad(t *testing.T) {
	hits := 0
	t.Cleanup(func() { t.Logf(`ASTRA-CONTRACT {"contract":"ASTROLABE-LOAD","hits":%d}`, hits) })
	scope := &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}
	for _, mode := range []string{"complete", "rpc-error", "consumer-error"} {
		if t.Run(mode, func(t *testing.T) {
			drained := make(chan struct{})
			service := &authority{load: func(received *comet.Scope, stream grpc.ServerStreamingServer[polaris.Snapshot]) error {
				defer close(drained)
				if !proto.Equal(received, scope) {
					return status.Error(codes.InvalidArgument, "changed scope")
				}
				if err := stream.Send(&polaris.Snapshot{Scope: scope, Version: proto.Uint64(7)}); err != nil {
					return err
				}
				if mode == "rpc-error" {
					return status.Error(codes.DataLoss, "fixture read failure")
				}
				if mode == "consumer-error" {
					<-stream.Context().Done()
					return stream.Context().Err()
				}
				return stream.Send(&polaris.Snapshot{Scope: scope, Version: proto.Uint64(7), Complete: true})
			}}
			backend, _, _ := transport(t, service)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			failure := errors.New("consumer stopped")
			pages := 0
			err := backend.Load(ctx, scope, func(page *polaris.Snapshot) error {
				pages++
				if !proto.Equal(page.Scope, scope) || page.GetVersion() != 7 || page.Complete != (pages == 2) {
					return errors.New("changed snapshot")
				}
				if mode == "consumer-error" {
					return failure
				}
				return nil
			})
			if mode == "complete" && (err != nil || pages != 2) || mode == "rpc-error" && (status.Code(err) != codes.DataLoss || pages != 1) || mode == "consumer-error" && (!errors.Is(err, failure) || pages != 1) {
				t.Fatal("snapshot termination", pages, err)
			}
			select {
			case <-drained:
			case <-ctx.Done():
				t.Fatal("server stream did not drain")
			}
			if ctx.Err() != nil {
				t.Fatal("parent deadline cannot substitute for consumer cancellation")
			}
			if service.loads.Load() != 1 {
				t.Fatal("load was retried")
			}
		}) {
			hits++
		}
	}
}

// TestTransportReplacement rejects stale authority instances and drains an in-flight stream before closing its resources.
func TestTransportReplacement(t *testing.T) {
	entered, drained := make(chan struct{}), make(chan struct{})
	service := &authority{load: func(_ *comet.Scope, stream grpc.ServerStreamingServer[polaris.Snapshot]) error {
		close(entered)
		defer close(drained)
		<-stream.Context().Done()
		return stream.Context().Err()
	}}
	backend, node, member := transport(t, service)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	old := backend.target
	backend.Update(errors.New("directory temporarily unavailable"))
	if backend.target != old || !backend.stale {
		t.Fatal("failed observation discarded target")
	}
	backend.Update(nil)
	if backend.target != old || backend.stale {
		t.Fatal("unchanged observation replaced channel")
	}
	result := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		result <- backend.Load(ctx, &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}, func(*polaris.Snapshot) error { return nil })
	}()
	t.Cleanup(func() {
		cancel()
		backend.Close()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("owned load worker did not drain")
		}
	})
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("load never entered")
	}
	newer := proto.Clone(member).(*orbit.Member)
	newer.Id, newer.Epoch = []byte("polaris-next"), member.Epoch+1
	if err := node.Directory().Install([]*orbit.Member{node.Member(), newer}); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.List(ctx); status.Code(err) != codes.Unavailable || service.lists.Load() != 0 {
		t.Fatal("stale instance was used", err)
	}
	backend.Update(nil)
	if backend.target == old || old.channel.GetState() != connectivity.Shutdown {
		t.Fatal("old channel retained after replacement")
	}
	select {
	case err := <-result:
		if status.Code(err) != codes.Canceled && status.Code(err) != codes.Unavailable {
			t.Fatal("replaced request result", err)
		}
	case <-ctx.Done():
		t.Fatal("replaced client did not drain")
	}
	select {
	case <-drained:
	case <-ctx.Done():
		t.Fatal("replaced server did not drain")
	}
	if _, err := backend.List(ctx); err != nil {
		t.Fatal("new target unavailable", err)
	}
	extra := proto.Clone(newer).(*orbit.Member)
	extra.Id, extra.Principal, extra.Advertise = []byte("second"), bytes.Repeat([]byte{42}, 32), "127.0.0.1:65534"
	if err := node.Directory().Install([]*orbit.Member{node.Member(), newer, extra}); err != nil {
		t.Fatal(err)
	}
	backend.Update(nil)
	if _, err := backend.List(ctx); status.Code(err) != codes.Unavailable || backend.target != nil || service.lists.Load() != 1 {
		t.Fatal("selected one of multiple authorities", err)
	}
	backend.Close()
	backend.Close()
	backend.Update(nil)
	late, err := grpc.NewClient("passthrough:///"+member.Advertise, grpc.WithTransportCredentials(credentials.NewTLS(backend.identity.Client())))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = late.Close() })
	backend.replace(&target{member: member, channel: late, client: polaris.NewAuthorityClient(late)})
	// Observe immediately: a later cleanup must not conceal an illegal intermediate publication.
	if backend.target != nil || late.GetState() != connectivity.Shutdown {
		t.Fatal("late connection was published after close")
	}
	backend.replace(nil)
	if backend.target != nil || late.GetState() != connectivity.Shutdown {
		t.Fatal("late connection escaped closed backend")
	}
	if _, err := backend.Commit(ctx, &polaris.CommitRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatal("closed backend admitted commit", err)
	}
	if err := backend.Load(ctx, &comet.Scope{}, func(*polaris.Snapshot) error { t.Fatal("closed backend delivered page"); return nil }); status.Code(err) != codes.Unavailable {
		t.Fatal("closed backend admitted load", err)
	}
	if service.loads.Load() != 1 {
		t.Fatal("in-flight load was replayed after replacement")
	}
	t.Log(`ASTRA-CONTRACT {"contract":"ASTROLABE-TARGET","hits":1}`)
}

// failedStream injects exact client-transport failures without changing production control flow or synchronization.
type failedStream struct {
	grpc.ClientStream
	err    error
	at     int
	sends  int
	closes int
}

// Send counts attempts and returns the configured error at the selected send boundary.
func (stream *failedStream) Send(*polaris.BatchRequest) error {
	stream.sends++
	if stream.sends == stream.at {
		return stream.err
	}
	return nil
}

// CloseAndRecv counts completion attempts and returns the configured receipt failure.
func (stream *failedStream) CloseAndRecv() (*polaris.Position, error) {
	stream.closes++
	return nil, stream.err
}

// failedClient substitutes only the Batch boundary while retaining the actual admitted Node and other client methods.
type failedClient struct {
	polaris.AuthorityClient
	err    error
	stream *failedStream
	opens  int
}

// Batch counts open attempts and returns the configured stream and opening error.
func (client *failedClient) Batch(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[polaris.BatchRequest, polaris.Position], error) {
	client.opens++
	return client.stream, client.err
}

// TestTransportFailures preserves original errors and forbids subsequent sends, completion or retry after a transport failure.
func TestTransportFailures(t *testing.T) {
	hits := 0
	t.Cleanup(func() { t.Logf(`ASTRA-CONTRACT {"contract":"ASTROLABE-SEND","hits":%d}`, hits) })
	for _, item := range []struct {
		name                       string
		changes, at, sends, closes int
	}{{"open", 1, 0, 0, 0}, {"prefix", 2, 1, 1, 0}, {"final", 1, 1, 1, 0}, {"receipt", 1, 0, 1, 1}} {
		if t.Run(item.name, func(t *testing.T) {
			backend, _, _ := transport(t, &authority{})
			failure := errors.New("controlled transport failure")
			stream := &failedStream{err: failure, at: item.at}
			client := &failedClient{AuthorityClient: backend.target.client, stream: stream}
			if item.name == "open" {
				client.err = failure
			}
			backend.target.client = client
			request := &polaris.CommitRequest{Scope: &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}, Version: 8}
			for index := range item.changes {
				request.Changes = append(request.Changes, &comet.AlmanacChange{Key: fmt.Sprint(index), Action: &comet.AlmanacChange_Value{Value: bytes.Repeat([]byte{1}, 150<<10)}})
			}
			position, err := backend.Commit(t.Context(), request)
			if !errors.Is(err, failure) || position != nil || client.opens != 1 || stream.sends != item.sends || stream.closes != item.closes {
				t.Fatal("transport failure was altered, ignored or retried", position, err, client.opens, stream.sends, stream.closes)
			}
		}) {
			hits++
		}
	}
}
