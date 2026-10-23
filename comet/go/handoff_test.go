// Verify authenticated handoff, confirmed Beacon history and cancellation at the actual wire boundary.
package comet

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// TestDuplicateSessionRequiresExplicitRecovery rejects a second confirmation without replaying business data.
func TestDuplicateSessionRequiresExplicitRecovery(t *testing.T) {
	duplicate := make(chan struct{})
	logins, writes := atomic.Int32{}, atomic.Int32{}
	fixture := newFixture(t, fixtureHandlers{
		session: func(_ *protocol.SessionRequest, stream grpc.ServerStreamingServer[protocol.SessionReply]) error {
			number := logins.Add(1)
			reply := &protocol.SessionReply{Instance: []byte("star-a"), Session: []byte(strings.Repeat("s", 32))}
			if cause := stream.Send(reply); cause != nil {
				return cause
			}
			if number == 1 {
				select {
				case <-duplicate:
					if cause := stream.Send(reply); cause != nil {
						return cause
					}
				case <-stream.Context().Done():
					return stream.Context().Err()
				}
			}
			<-stream.Context().Done()
			return stream.Context().Err()
		},
		publish: func(_ context.Context, request *protocol.PublishRequest) (*protocol.PublishReply, error) {
			writes.Add(1)
			return &protocol.PublishReply{Instance: request.Instance, Version: request.Version}, nil
		},
	})
	client := fixtureClient(t, fixture, Options{Plaintext: true, Key: "key", Secret: []byte("secret")})
	publisher, cause := client.Publisher(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	if _, cause := publisher.Update(testContext(t), []Entry{{Key: "k", Data: []byte("before")}}, time.Second); cause != nil {
		t.Fatal(cause)
	}
	close(duplicate)
	awaitCondition(t, func() bool { client.mu.Lock(); defer client.mu.Unlock(); return client.blocked != nil })
	_, cause = publisher.Update(testContext(t), []Entry{{Key: "k", Data: []byte("rejected")}}, time.Second)
	requireCode(t, cause, CodeProtocol, Unapplied)
	if logins.Load() != 1 || writes.Load() != 1 {
		t.Fatal("malformed established Session admitted or replayed a business write")
	}
	if cause := client.Secret([]byte("secret")); cause != nil {
		t.Fatal(cause)
	}
	if receipt, cause := publisher.Update(testContext(t), []Entry{{Key: "k", Data: []byte("fresh")}}, time.Second); cause != nil || receipt.Version != 2 {
		t.Fatalf("explicit recovery lost the consumed version: %#v %v", receipt, cause)
	}
	if logins.Load() != 2 || writes.Load() != 2 {
		t.Fatal("explicit recovery did not preserve the caller-owned write history")
	}
}

// TestSecretReplacementFencesRejectedLogin makes an in-flight old rejection unable to pause newer credentials.
func TestSecretReplacementFencesRejectedLogin(t *testing.T) {
	entered, reject := make(chan struct{}), make(chan struct{})
	logins := atomic.Int32{}
	fixture := newFixture(t, fixtureHandlers{session: func(request *protocol.SessionRequest, stream grpc.ServerStreamingServer[protocol.SessionReply]) error {
		number := logins.Add(1)
		if number == 1 {
			if string(request.Secret) != "old" {
				t.Error("initial credential changed before explicit replacement")
			}
			close(entered)
			select {
			case <-reject:
				return status.Error(codes.Unauthenticated, "private old-login rejection")
			case <-stream.Context().Done():
				return stream.Context().Err()
			}
		}
		if number != 2 || string(request.Secret) != "new" {
			t.Error("recovery did not use exactly one new credential generation")
		}
		if cause := stream.Send(&protocol.SessionReply{Instance: []byte("star-a"), Session: make([]byte, 32)}); cause != nil {
			return cause
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}})
	client := fixtureClient(t, fixture, Options{Plaintext: true, Key: "key", Secret: []byte("old")})
	receiveTest(t, entered)
	if cause := client.Secret([]byte("new")); cause != nil {
		t.Fatal(cause)
	}
	close(reject)
	publisher, cause := client.Publisher(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	if receipt, cause := publisher.Update(testContext(t), []Entry{{Key: "k"}}, time.Second); cause != nil || receipt.Version != 1 {
		t.Fatalf("old rejection blocked newer credentials: %#v %v", receipt, cause)
	}
	if logins.Load() != 2 {
		t.Fatal("credential replacement retried an obsolete login")
	}
}

// TestBeaconSessionRenewalRetainsRegistration reauthenticates the same target without creating another logical Beacon.
func TestBeaconSessionRenewalRetainsRegistration(t *testing.T) {
	invalidate := make(chan struct{})
	logins, creates := atomic.Int32{}, atomic.Int32{}
	beats := make(chan *protocol.RenewRequest, 1)
	fixture := newFixture(t, fixtureHandlers{
		session: func(_ *protocol.SessionRequest, stream grpc.ServerStreamingServer[protocol.SessionReply]) error {
			number := logins.Add(1)
			if cause := stream.Send(&protocol.SessionReply{Instance: []byte("star-a"), Session: []byte(strings.Repeat(string(rune('a'+number)), 32))}); cause != nil {
				return cause
			}
			if number == 1 {
				select {
				case <-invalidate:
					return status.Error(codes.Unauthenticated, "expired Session")
				case <-stream.Context().Done():
					return stream.Context().Err()
				}
			}
			<-stream.Context().Done()
			return stream.Context().Err()
		},
		create: func(_ context.Context, request *protocol.CreateRequest) (*protocol.CreateReply, error) {
			creates.Add(1)
			return &protocol.CreateReply{Instance: []byte("star-a"), Uuid: fixtureID(), Capability: make([]byte, 32), Generation: request.Generation,
				TtlMs: request.TtlMs, Order: request.Order, Data: request.Data}, nil
		},
		renew: func(ctx context.Context, request *protocol.RenewRequest) (*protocol.RenewReply, error) {
			incoming, _ := metadata.FromIncomingContext(ctx)
			if values := incoming.Get("comet-session-bin"); len(values) == 1 && values[0] == strings.Repeat("c", 32) {
				select {
				case beats <- request:
				default:
				}
			}
			return &protocol.RenewReply{Order: request.Order}, nil
		},
	})
	client := fixtureClient(t, fixture, Options{Plaintext: true, Key: "key", Secret: []byte("secret")})
	beacon, cause := client.Beacon(testContext(t), testScope(), []byte("fixed"), []byte("initial"), 10*time.Second, 50*time.Millisecond)
	if cause != nil {
		t.Fatal(cause)
	}
	identity := beacon.State().Identity
	close(invalidate)
	request := receiveTest(t, beats)
	if request.Generation != 1 || string(request.Uuid) != identity.ID || creates.Load() != 1 || logins.Load() != 2 {
		t.Fatal("same-target Session renewal recreated the logical registration")
	}
	if receipt, cause := beacon.Update(testContext(t), []byte("fresh")); cause != nil || receipt.Order != 1 || receipt.Identity != identity {
		t.Fatalf("Session renewal damaged the existing Beacon: %#v %v", receipt, cause)
	}
}

// TestBeaconRecoveryOrderOverflow rejects wraparound after a valid server-confirmed maximum order.
func TestBeaconRecoveryOrderOverflow(t *testing.T) {
	creates, updates := atomic.Int32{}, atomic.Int32{}
	fixture := newFixture(t, fixtureHandlers{
		create: func(_ context.Context, request *protocol.CreateRequest) (*protocol.CreateReply, error) {
			reply := &protocol.CreateReply{Instance: []byte("star-a"), Uuid: fixtureID(), Capability: make([]byte, 32), Generation: request.Generation,
				TtlMs: request.TtlMs, Order: request.Order, Data: request.Data}
			if creates.Add(1) == 2 {
				reply.Order, reply.Data = ^uint64(0), []byte("confirmed-maximum")
			}
			return reply, nil
		},
		update: func(ctx context.Context, _ *protocol.UpdateRequest) (*protocol.UpdateReply, error) {
			updates.Add(1)
			return nil, rejected(ctx, protocol.Reason_REASON_ENDED)
		},
	})
	client := fixtureClient(t, fixture)
	beacon, cause := client.Beacon(testContext(t), testScope(), nil, []byte("initial"), 10*time.Second, time.Second)
	if cause != nil {
		t.Fatal(cause)
	}
	_, cause = beacon.Update(testContext(t), []byte("not-replayed"))
	requireCode(t, cause, CodeEnded, Unapplied)
	awaitCondition(t, func() bool { return creates.Load() == 2 && beacon.State().Phase == Ready })
	_, cause = beacon.Update(testContext(t), []byte("must-not-wrap"))
	requireCode(t, cause, CodeLimit, Unapplied)
	state := beacon.State()
	if state.Phase != Failed || !state.HasIdentity || state.Identity.ID != string(fixtureID()) || updates.Load() != 1 {
		t.Fatal("maximum confirmed order wrapped, sent another update or lost its identity")
	}
}

// TestBeaconDestroyCancelsSubmittedUpdate retains unknown effect while waiting for the actual canceled RPC to drain.
func TestBeaconDestroyCancelsSubmittedUpdate(t *testing.T) {
	entered, canceled := make(chan struct{}), make(chan struct{})
	fixture := newFixture(t, fixtureHandlers{update: func(ctx context.Context, _ *protocol.UpdateRequest) (*protocol.UpdateReply, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		return nil, ctx.Err()
	}})
	client := fixtureClient(t, fixture)
	beacon, cause := client.Beacon(testContext(t), testScope(), nil, nil, 10*time.Second, time.Second)
	if cause != nil {
		t.Fatal(cause)
	}
	finished := make(chan error, 1)
	go func() { _, cause := beacon.Update(context.Background(), []byte("submitted")); finished <- cause }()
	receiveTest(t, entered)
	beacon.Destroy()
	requireCode(t, receiveTest(t, finished), CodeClosed, Unknown)
	receiveTest(t, canceled)
	if cause := beacon.Wait(testContext(t)); cause != nil || beacon.State().Phase != Closed {
		t.Fatalf("destroy did not drain the submitted update: %v", cause)
	}
}

// TestBeaconRenewalFailurePreservesData retries maintenance without issuing a Data update or recreating the owner.
func TestBeaconRenewalFailurePreservesData(t *testing.T) {
	creates, updates, renewals := atomic.Int32{}, atomic.Int32{}, atomic.Int32{}
	fixture := newFixture(t, fixtureHandlers{
		create: func(_ context.Context, request *protocol.CreateRequest) (*protocol.CreateReply, error) {
			creates.Add(1)
			return &protocol.CreateReply{Instance: []byte("star-a"), Uuid: fixtureID(), Capability: make([]byte, 32), Generation: request.Generation,
				TtlMs: request.TtlMs, Order: request.Order, Data: request.Data}, nil
		},
		update: func(_ context.Context, request *protocol.UpdateRequest) (*protocol.UpdateReply, error) {
			updates.Add(1)
			return &protocol.UpdateReply{Order: request.Order}, nil
		},
		renew: func(ctx context.Context, request *protocol.RenewRequest) (*protocol.RenewReply, error) {
			if number := renewals.Add(1); number == 1 {
				return nil, rejected(ctx, protocol.Reason_REASON_BUSY)
			} else if request.Order != uint64(number) {
				t.Error("maintenance reused a consumed renewal order")
			}
			return &protocol.RenewReply{Order: request.Order}, nil
		},
	})
	client := fixtureClient(t, fixture)
	beacon, cause := client.Beacon(testContext(t), testScope(), nil, []byte("confirmed"), time.Second, 50*time.Millisecond)
	if cause != nil {
		t.Fatal(cause)
	}
	awaitCondition(t, func() bool {
		return renewals.Load() >= 2 && beacon.State().Phase == Ready && beacon.State().Error == nil
	})
	if creates.Load() != 1 || updates.Load() != 0 {
		t.Fatal("renewal failure recreated the owner or replayed Data")
	}
	if receipt, cause := beacon.Update(testContext(t), []byte("fresh")); cause != nil || receipt.Order != 1 || updates.Load() != 1 {
		t.Fatalf("renewal failure consumed the independent Data order: %#v %v", receipt, cause)
	}
}
