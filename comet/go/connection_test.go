// Verify explicit credential recovery, real TLS validation and bounded client admission.
package comet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// TestAuthenticationRequiresExplicitSecretRecovery distinguishes rejected login from automatic reauthentication.
func TestAuthenticationRequiresExplicitSecretRecovery(t *testing.T) {
	logins := atomic.Int32{}
	queries := atomic.Int32{}
	fixture := newFixture(t, fixtureHandlers{
		session: func(request *protocol.SessionRequest, stream grpc.ServerStreamingServer[protocol.SessionReply]) error {
			logins.Add(1)
			if request.Key != "key" || string(request.Secret) != "good" {
				return status.Error(codes.Unauthenticated, "private rejected credential")
			}
			if cause := stream.Send(&protocol.SessionReply{Instance: []byte("star-a"), Session: []byte(strings.Repeat("s", 32))}); cause != nil {
				return cause
			}
			<-stream.Context().Done()
			return stream.Context().Err()
		},
		query: func(ctx context.Context, request *protocol.CatalogQueryRequest) (*protocol.CatalogQueryReply, error) {
			queries.Add(1)
			incoming, _ := metadata.FromIncomingContext(ctx)
			values := incoming.Get("comet-session-bin")
			if len(values) != 1 || values[0] != strings.Repeat("s", 32) {
				return nil, status.Error(codes.Unauthenticated, "missing session")
			}
			return &protocol.CatalogQueryReply{Instance: []byte("star-a"), Entries: []*protocol.CatalogQueryReply_Entry{{Key: request.Keys[0]}}}, nil
		},
	})
	client := fixtureClient(t, fixture, Options{Plaintext: true, Key: "key", Secret: []byte("bad")})
	publisher, cause := client.Publisher(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	_, cause = publisher.Update(context.Background(), []Entry{{Key: "k"}}, time.Second)
	requireCode(t, cause, CodeSession, Unapplied)
	if queries.Load() != 0 || logins.Load() != 1 {
		t.Fatal("rejected authentication admitted a business query")
	}
	if cause := client.Secret([]byte("good")); cause != nil {
		t.Fatal(cause)
	}
	// Application metadata must not substitute its own SDK authentication token.
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("comet-session-bin", "forged"))
	if _, cause := publisher.Update(ctx, []Entry{{Key: "k"}}, time.Second); cause != nil {
		t.Fatal(cause)
	}
	if logins.Load() != 2 || queries.Load() != 1 {
		t.Fatal("credential recovery was not shared and explicit")
	}
}

// TestInvalidatedSessionRelogsWithoutReplayingWrite pauses no future business calls after establishment.
func TestInvalidatedSessionRelogsWithoutReplayingWrite(t *testing.T) {
	logins, writes := atomic.Int32{}, atomic.Int32{}
	fixture := newFixture(t, fixtureHandlers{
		session: func(_ *protocol.SessionRequest, stream grpc.ServerStreamingServer[protocol.SessionReply]) error {
			logins.Add(1)
			if cause := stream.Send(&protocol.SessionReply{Instance: []byte("star-a"), Session: make([]byte, 32)}); cause != nil {
				return cause
			}
			<-stream.Context().Done()
			return stream.Context().Err()
		},
		publish: func(ctx context.Context, request *protocol.PublishRequest) (*protocol.PublishReply, error) {
			if writes.Add(1) == 1 {
				return nil, rejected(ctx, protocol.Reason_REASON_SESSION)
			}
			return &protocol.PublishReply{Instance: request.Instance, Version: request.Version}, nil
		},
	})
	client := fixtureClient(t, fixture, Options{Plaintext: true, Key: "key", Secret: []byte("secret")})
	publisher, cause := client.Publisher(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	_, cause = publisher.Update(context.Background(), []Entry{{Key: "k", Data: []byte("first")}}, time.Second)
	requireCode(t, cause, CodeSession, Unapplied)
	if _, cause := publisher.Update(context.Background(), []Entry{{Key: "k", Data: []byte("second")}}, time.Second); cause != nil {
		t.Fatal(cause)
	}
	if logins.Load() != 2 || writes.Load() != 2 {
		t.Fatal("Session invalidation paused authentication or replayed business data")
	}
}

// fixtureCertificate creates a temporary in-memory loopback trust root and leaf.
func fixtureCertificate(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, cause := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if cause != nil {
		t.Fatal(cause)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Comet test endpoint"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, cause := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if cause != nil {
		t.Fatal(cause)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestVerifiedTLSAndSession exercises both secure defaults against a real TLS gRPC endpoint.
func TestVerifiedTLSAndSession(t *testing.T) {
	certificate, ca := fixtureCertificate(t)
	fixture := newFixture(t, fixtureHandlers{}, grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}})))
	client := fixtureClient(t, fixture, Options{Key: "key", Secret: []byte("secret"), CA: ca})
	publisher, cause := client.Publisher(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	if _, cause := publisher.Update(context.Background(), []Entry{{Key: "secure"}}, time.Second); cause != nil {
		t.Fatalf("verified TLS/session failed: %v", cause)
	}
}

// TestTLSRejectsUnrelatedTrust uses a second certificate to prove verification is enabled.
func TestTLSRejectsUnrelatedTrust(t *testing.T) {
	certificate, _ := fixtureCertificate(t)
	_, unrelated := fixtureCertificate(t)
	fixture := newFixture(t, fixtureHandlers{}, grpc.Creds(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}})))
	client := fixtureClient(t, fixture, Options{Key: "key", Secret: []byte("secret"), CA: unrelated, Timeout: 100 * time.Millisecond})
	publisher, cause := client.Publisher(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	_, cause = publisher.Update(context.Background(), []Entry{{Key: "must-not-commit"}}, time.Second)
	if cause == nil {
		t.Fatal("unrelated root authorized the server certificate")
	}
	var structured *Error
	if !errors.As(cause, &structured) || structured.Effect != Unapplied {
		t.Fatalf("TLS failure was treated as a submitted write: %v", cause)
	}
}

// TestControlledBytesAndClosure bounds fixed Publisher ownership before any connection succeeds.
func TestControlledBytesAndClosure(t *testing.T) {
	fixture := newFixture(t, fixtureHandlers{})
	client := fixtureClient(t, fixture, Options{Anonymous: true, Plaintext: true, Bytes: 16384})
	owners := make([]*Publisher, 0, 8)
	for range 8 {
		owner, cause := client.Publisher(testScope())
		if cause != nil {
			t.Fatal(cause)
		}
		owners = append(owners, owner)
	}
	if _, cause := client.Publisher(testScope()); cause == nil {
		t.Fatal("fixed owner metadata bypassed the Client byte budget")
	}
	for _, owner := range owners {
		owner.Close()
		if cause := owner.Wait(testContext(t)); cause != nil {
			t.Fatal(cause)
		}
	}
	if client.used.Load() != 0 {
		t.Fatal("closed Publishers retained controlled bytes")
	}
	client.Close()
	if cause := client.Secret([]byte("secret")); cause == nil {
		t.Fatal("closed client accepted credential mutation")
	}
}

// TestDeadlineGuardCannotResurrectExpiry forces the timer/confirmation boundary explicitly.
func TestDeadlineGuardCannotResurrectExpiry(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := newDeadline(cancel)
	defer guard.stop()
	guard.arm(time.Nanosecond)
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("guard did not expire")
	}
	if guard.disarm() || !guard.expired() {
		t.Fatal("late confirmation erased an actual deadline")
	}
}
