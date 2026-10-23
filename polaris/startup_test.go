// Verify native startup rollback and cancellation through real SQLite, TLS and gRPC boundaries.
//go:build linux && cgo

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/internal/admission"
	"github.com/eosforge/astra/internal/generated/orbit"
	"github.com/eosforge/astra/polaris/internal/storage"
)

// registrar supplies one signed local member or an explicit permanent admission refusal.
type registrar struct {
	orbit.UnimplementedAdmissionServer
	reply *orbit.RegistrationResponse // Independently encoded public fixture reply.
	deny  bool                        // Permanent failure, with no retry timing dependency.
	calls atomic.Int32                // Actual registration attempts across RPC goroutines.
}

// Register checks the deployment request before returning the fixed test outcome.
func (service *registrar) Register(_ context.Context, request *orbit.RegistrationRequest) (*orbit.RegistrationResponse, error) {
	service.calls.Add(1)
	member := service.reply.Members[0]
	if request.Advertise != member.Advertise || request.Galaxy != member.Galaxy || request.Group != member.Group || request.Role != member.Role || len(request.RequestId) != 32 {
		return nil, status.Error(codes.InvalidArgument, "Unexpected fixture registration")
	}
	if service.deny {
		return nil, status.Error(codes.PermissionDenied, "Fixture refusal")
	}
	return proto.Clone(service.reply).(*orbit.RegistrationResponse), nil
}

// launch owns an isolated admission server; all cryptographic material is the repository's public fixture.
func launch(t *testing.T, config *options, identity *admission.Identity, deny bool, settings ...grpc.ServerOption) *registrar {
	t.Helper()
	member := &orbit.Member{Galaxy: config.galaxy, Id: []byte("entry-test"), Principal: identity.Principal(config.galaxy, config.advertise), Advertise: config.advertise, Epoch: 1, Role: orbit.Role_ROLE_POLARIS, Group: config.group}
	data, err := proto.Marshal(member)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join("..", "tests", "fixtures", "pulsar", "admission.key"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(key)
	if block == nil {
		t.Fatal("missing public fixture signing key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	signer, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("public fixture key has the wrong algorithm")
	}
	service := &registrar{reply: &orbit.RegistrationResponse{Admission: data, Signature: ed25519.Sign(signer, append([]byte("proto.orbit.v1.admission\x00"), data...)), Members: []*orbit.Member{member}}, deny: deny}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	config.super = listener.Addr().String()
	rpc := grpc.NewServer(append(settings, grpc.Creds(credentials.NewTLS(identity.Server())))...)
	orbit.RegisterAdmissionServer(rpc, service)
	done := make(chan error, 1)
	go func() { done <- rpc.Serve(listener) }()
	t.Cleanup(func() {
		rpc.Stop()
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("fixture admission server did not drain")
		}
	})
	return service
}

// TestStartup keeps each failure local and proves that owned database locks and listeners are reusable.
func TestStartup(t *testing.T) {
	for _, name := range []string{"identity", "storage", "credentials", "node", "listener", "admission", "budget", "cancel"} {
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			endpoint := listener.Addr().String()
			config := options{listen: endpoint, advertise: endpoint, galaxy: "entry", group: "default", identity: filepath.Join("..", "tests", "fixtures", "star-a"), state: filepath.Join(t.TempDir(), "authority.db"), snapshots: 256 << 20}
			identity, err := admission.Load(config.identity, endpoint)
			if err != nil {
				t.Fatal(err)
			}
			binding := storage.Binding{Galaxy: config.galaxy, Username: identity.Username(), Advertise: endpoint}
			if name != "identity" && name != "storage" {
				store, err := storage.Open(t.Context(), config.state, binding, storage.Default(), true)
				if err != nil {
					t.Fatal(err)
				}
				if name == "credentials" {
					_, err = store.Commit(t.Context(), storage.Scope{Sector: "__auth", Spectrum: "comet"}, storage.Change{Version: 1, Key: "client", Value: []byte{0xff}})
				}
				closed := store.Close()
				if err != nil || closed != nil {
					t.Fatal("fixture database preparation failed", err, closed)
				}
			}
			service := launch(t, &config, identity, name == "admission")
			want := error(nil)
			switch name {
			case "identity":
				config.identity = t.TempDir()
				want = admission.ErrIdentity
			case "storage":
				want = storage.ErrUnavailable
			case "credentials":
				want = storage.ErrCorrupt
			case "node":
				config.super = "localhost:1"
				want = admission.ErrIdentity
			case "budget":
				config.snapshots = 1
				want = storage.ErrInput
			}
			if name != "listener" {
				if err := listener.Close(); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			if name == "cancel" {
				done := make(chan error, 1)
				go func() { done <- run(ctx, config) }()
				channel, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(credentials.NewTLS(identity.Client())), grpc.WithDisableRetry())
				if err != nil {
					cancel()
					<-done
					t.Fatal(err)
				}
				health, observed := grpc_health_v1.NewHealthClient(channel).Check(ctx, &grpc_health_v1.HealthCheckRequest{}, grpc.WaitForReady(true))
				cancel()
				err = <-done
				closed := channel.Close()
				if observed != nil || health.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING || err != nil || closed != nil {
					t.Fatal("ready service failed to cancel and drain", observed, err, closed)
				}
			} else {
				err := run(ctx, config)
				if err == nil || want != nil && !errors.Is(err, want) || name == "admission" && status.Code(err) != codes.PermissionDenied {
					t.Fatal("startup did not preserve the expected refusal", err)
				}
			}
			calls := int32(0)
			if name == "admission" || name == "budget" || name == "cancel" {
				calls = 1
			}
			if service.calls.Load() != calls {
				t.Fatal("startup performed admission before local validation or retried a permanent result")
			}
			if name == "listener" {
				if err := listener.Close(); err != nil {
					t.Fatal(err)
				}
			}
			rebound, err := net.Listen("tcp", endpoint)
			if err != nil {
				t.Fatal("startup retained its listener after returning", err)
			}
			if err := rebound.Close(); err != nil {
				t.Fatal(err)
			}
			missing := name == "identity" || name == "storage"
			if _, err := os.Stat(config.state); missing && !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed startup unexpectedly initialized a database", err)
			}
			store, err := storage.Open(t.Context(), config.state, binding, storage.Default(), missing)
			if err != nil {
				t.Fatal("startup retained its exclusive database lock", err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestRefresh observes one healthy directory refresh before a permanent refusal stops the actual service.
func TestRefresh(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	endpoint := listener.Addr().String()
	config := options{listen: endpoint, advertise: endpoint, galaxy: "entry", group: "default", identity: filepath.Join("..", "tests", "fixtures", "star-a"), state: filepath.Join(t.TempDir(), "authority.db"), snapshots: 256 << 20, initialize: true}
	identity, err := admission.Load(config.identity, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	member := &orbit.Member{Galaxy: config.galaxy, Id: []byte("entry-test"), Principal: identity.Principal(config.galaxy, endpoint), Advertise: endpoint, Epoch: 1, Role: orbit.Role_ROLE_POLARIS, Group: config.group}
	var refreshes atomic.Int32
	service := launch(t, &config, identity, false, grpc.UnaryInterceptor(func(ctx context.Context, request any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		if info.FullMethod != orbit.Admission_List_FullMethodName {
			return next(ctx, request)
		}
		if refreshes.Add(1) == 1 {
			return &orbit.DirectoryResponse{Members: []*orbit.Member{proto.Clone(member).(*orbit.Member)}}, nil
		}
		return nil, status.Error(codes.PermissionDenied, "Controlled admission revocation")
	}))
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	// Two production refresh periods fit this budget; no injected clock or shortened service timer is used.
	ctx, cancel := context.WithTimeout(t.Context(), 85*time.Second)
	defer cancel()
	err = run(ctx, config)
	if status.Code(err) != codes.PermissionDenied || ctx.Err() != nil || service.calls.Load() != 1 || refreshes.Load() != 2 {
		t.Fatal("service lost its directory refusal, retried permanent admission or failed to drain", err, ctx.Err(), service.calls.Load(), refreshes.Load())
	}
	rebound, err := net.Listen("tcp", endpoint)
	if err != nil {
		t.Fatal("revoked service retained its listener", err)
	}
	if err := rebound.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(t.Context(), config.state, storage.Binding{Galaxy: config.galaxy, Username: identity.Username(), Advertise: endpoint}, storage.Default(), false)
	if err != nil {
		t.Fatal("revoked service retained its database or damaged durable state", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}
