// Verify Astrolabe entry rollback, local readiness and cancellation over real TLS admission.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/internal/admission"
	"github.com/eosforge/astra/internal/generated/orbit"
)

// counter records only assertions actually reached by this named entry scenario.
func counter(t *testing.T) func(bool, string) {
	t.Helper()
	hits := 0
	t.Cleanup(func() { t.Logf(`ASTRA-CONTRACT {"contract":"ASTROLABE-ENTRY","hits":%d}`, hits) })
	return func(ok bool, message string) {
		t.Helper()
		hits++
		if !ok {
			t.Fatal(message)
		}
	}
}

// deployment reserves a unique endpoint and prepares only public, non-login fixture material.
func deployment(t *testing.T) (options, net.Listener, *admission.Identity) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	config := options{listen: listener.Addr().String(), advertise: listener.Addr().String(), super: "127.0.0.1:1", galaxy: "entry", group: "default", identity: filepath.Join("..", "tests", "fixtures", "star-a"), account: filepath.Join(t.TempDir(), "account.json"), public: "https://admin.example", sessions: 1, plain: true}
	data := []byte(`{"username":"entry","salt":"00000000000000000000000000000000","hash":"0000000000000000000000000000000000000000000000000000000000000000"}`)
	if err := os.WriteFile(config.account, data, 0600); err != nil {
		t.Fatal(err)
	}
	identity, err := admission.Load(config.identity, config.advertise)
	if err != nil {
		t.Fatal(err)
	}
	return config, listener, identity
}

// registrar exposes a latched in-flight RPC, a permanent refusal or a signed successful admission.
type registrar struct {
	orbit.UnimplementedAdmissionServer
	reply   *orbit.RegistrationResponse // Immutable public signed fixture.
	mode    string                      // Fixed scenario, never modified after Serve starts.
	entered chan struct{}               // First request reached the real service.
	exited  chan struct{}               // First handler finished using its request.
	calls   atomic.Int32                // A terminal outcome must not be retried.
}

// Register validates the requested identity before supplying the independently selected outcome.
func (service *registrar) Register(ctx context.Context, request *orbit.RegistrationRequest) (*orbit.RegistrationResponse, error) {
	if service.calls.Add(1) != 1 {
		return nil, status.Error(codes.Aborted, "Unexpected repeated admission")
	}
	close(service.entered)
	defer close(service.exited)
	member := service.reply.Members[0]
	if request.Advertise != member.Advertise || request.Galaxy != member.Galaxy || request.Group != member.Group || request.Role != member.Role || len(request.RequestId) != 32 {
		return nil, status.Error(codes.InvalidArgument, "Unexpected entry identity")
	}
	if service.mode == "cancel" {
		<-ctx.Done()
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	if service.mode == "refusal" {
		return nil, status.Error(codes.PermissionDenied, "Fixture refusal")
	}
	return proto.Clone(service.reply).(*orbit.RegistrationResponse), nil
}

// launch owns the TLS listener and serving goroutine; cleanup joins them even after a failed assertion.
func launch(t *testing.T, config *options, identity *admission.Identity, mode string) *registrar {
	t.Helper()
	member := &orbit.Member{Galaxy: config.galaxy, Id: []byte("astrolabe-entry"), Principal: identity.Principal(config.galaxy, config.advertise), Advertise: config.advertise, Epoch: 1, Role: orbit.Role_ROLE_ASTROLABE, Group: config.group}
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
		t.Fatal("unexpected fixture signing algorithm")
	}
	service := &registrar{mode: mode, entered: make(chan struct{}), exited: make(chan struct{}), reply: &orbit.RegistrationResponse{Admission: data, Signature: ed25519.Sign(signer, append([]byte("proto.orbit.v1.admission\x00"), data...)), Members: []*orbit.Member{member}}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	config.super = listener.Addr().String()
	rpc := grpc.NewServer(grpc.Creds(credentials.NewTLS(identity.Server())))
	orbit.RegisterAdmissionServer(rpc, service)
	done := make(chan error, 1)
	go func() { done <- rpc.Serve(listener) }()
	t.Cleanup(func() {
		rpc.Stop()
		_ = listener.Close()
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

// TestStartup rejects each preparation failure before any registration and releases the management endpoint.
func TestStartup(t *testing.T) {
	for _, name := range []string{"metrics", "identity", "account", "node", "handler", "listener"} {
		t.Run(name, func(t *testing.T) {
			check := counter(t)
			config, listener, identity := deployment(t)
			service := launch(t, &config, identity, "refusal")
			switch name {
			case "metrics":
				config.metrics = filepath.Join(t.TempDir(), "missing.json")
			case "identity":
				config.identity = t.TempDir()
			case "account":
				config.account = filepath.Join(t.TempDir(), "missing.json")
			case "node":
				config.super = "localhost:1"
			case "handler":
				config.sessions = 0
			}
			if name != "listener" {
				check(listener.Close() == nil, "fixture did not release its reservation")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			err := run(ctx, config)
			check(err != nil && !errors.Is(err, context.DeadlineExceeded), "startup hid a preparation refusal")
			if name == "identity" || name == "node" {
				check(errors.Is(err, admission.ErrIdentity), "startup changed the identity refusal")
			}
			check(service.calls.Load() == 0, "startup contacted admission before local preparation completed")
			if name == "listener" {
				check(listener.Close() == nil, "fixture reservation was closed by failed startup")
			}
			rebound, err := net.Listen("tcp", config.listen)
			check(err == nil, "startup retained its management endpoint")
			check(rebound.Close() == nil, "rebound listener failed to close")
		})
	}
}

// TestLifecycle distinguishes admission refusal from cancellation and keeps local HTTP usable during admission.
func TestLifecycle(t *testing.T) {
	for _, name := range []string{"http", "https", "cancel", "refusal"} {
		t.Run(name, func(t *testing.T) {
			check := counter(t)
			config, listener, identity := deployment(t)
			config.plain = name != "https"
			service := launch(t, &config, identity, name)
			check(listener.Close() == nil, "fixture did not release its reservation")
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			done := make(chan error, 1)
			go func() { done <- run(ctx, config) }()
			joined := false
			t.Cleanup(func() {
				cancel()
				if !joined {
					select {
					case <-done:
					case <-time.After(6 * time.Second):
						t.Error("entry owner did not drain")
					}
				}
			})
			select {
			case <-service.entered:
			case <-ctx.Done():
				t.Fatal("entry did not reach admission")
			}
			if name != "refusal" {
				transport := &http.Transport{TLSClientConfig: identity.Client(), Proxy: nil}
				defer transport.CloseIdleConnections()
				client := &http.Client{Transport: transport}
				scheme := "http://"
				if !config.plain {
					scheme = "https://"
				}
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+config.listen+"/api/nodes", nil)
				check(err == nil, "invalid native readiness request")
				// The admission RPC starts after Listen; the OS backlog waits for Serve without a polling sleep.
				response, err := client.Do(request)
				check(err == nil, "local management was unavailable while admission was in flight")
				body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
				closed := response.Body.Close()
				check(err == nil && closed == nil && len(body) > 0 && len(body) < 1024, "readiness response was incomplete")
				check(response.StatusCode == http.StatusUnauthorized && response.Header.Get("Cache-Control") == "no-store", "pending admission bypassed local HTTP authentication")
				cancel()
			}
			select {
			case err := <-done:
				joined = true
				if name == "refusal" {
					check(status.Code(err) == codes.PermissionDenied, "entry swallowed permanent admission refusal")
				} else {
					check(err == nil, "owner cancellation became a failed entry exit")
				}
			case <-time.After(6 * time.Second):
				t.Fatal("entry did not return within its shutdown budget")
			}
			select {
			case <-service.exited:
			case <-time.After(5 * time.Second):
				t.Fatal("cancelled admission handler did not retire")
			}
			check(service.calls.Load() == 1, "terminal admission outcome was retried")
			rebound, err := net.Listen("tcp", config.listen)
			check(err == nil, "completed entry retained its management listener")
			check(rebound.Close() == nil, "rebound listener failed to close")
		})
	}
}
