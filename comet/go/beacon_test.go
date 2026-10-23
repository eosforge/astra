// Verify Beacon ownership, recovery history, independent beat and late-sample fencing.
package comet

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// TestBeaconFactoryContextAndDestroy makes a successful factory independent of its caller Context.
func TestBeaconFactoryContextAndDestroy(t *testing.T) {
	removed := make(chan *protocol.RemoveRequest, 1)
	fixture := newFixture(t, fixtureHandlers{remove: func(_ context.Context, request *protocol.RemoveRequest) (*protocol.Empty, error) {
		recordTest(t, removed, request)
		return &protocol.Empty{}, nil
	}})
	client := fixtureClient(t, fixture)
	ctx, cancel := context.WithCancel(context.Background())
	beacon, cause := client.Beacon(ctx, testScope(), []byte("fixed"), nil, 10*time.Second, time.Second)
	cancel()
	if cause != nil {
		t.Fatal(cause)
	}
	receipt, cause := beacon.Update(context.Background(), []byte("new"))
	if cause != nil || receipt.Order != 1 || receipt.Identity.ID != string(fixtureID()) || !beacon.State().HasIdentity {
		t.Fatalf("factory Context became a lifetime: %#v %v", receipt, cause)
	}
	beacon.Destroy()
	beacon.Destroy()
	if beacon.State().Phase != Closed {
		t.Fatal("Destroy did not close synchronously")
	}
	if cause := beacon.Wait(testContext(t)); cause != nil {
		t.Fatal(cause)
	}
	request := receiveTest(t, removed)
	if request.Generation != 1 || string(request.Uuid) != receipt.Identity.ID || len(request.Capability) != 32 {
		t.Fatal("cleanup lost its registration identity")
	}
	_, cause = beacon.Update(context.Background(), nil)
	requireCode(t, cause, CodeClosed, Unapplied)
}

// TestBeaconRecoveryAdoptsConfirmedServerData fixes the lost-receipt history without replaying its payload.
func TestBeaconRecoveryAdoptsConfirmedServerData(t *testing.T) {
	creates, updates := atomic.Int32{}, atomic.Int32{}
	restored := make(chan *protocol.CreateRequest, 1)
	fixture := newFixture(t, fixtureHandlers{
		create: func(_ context.Context, request *protocol.CreateRequest) (*protocol.CreateReply, error) {
			reply := &protocol.CreateReply{Instance: []byte("star-a"), Uuid: fixtureID(), Capability: make([]byte, 32),
				Generation: request.Generation, TtlMs: request.TtlMs, Order: request.Order, Data: request.Data}
			if creates.Add(1) > 1 {
				recordTest(t, restored, request)
				reply.Instance, reply.Order, reply.Data = []byte("star-b"), 1, []byte("server-confirmed")
			}
			return reply, nil
		},
		update: func(_ context.Context, request *protocol.UpdateRequest) (*protocol.UpdateReply, error) {
			if updates.Add(1) == 1 {
				return nil, status.Error(codes.Unavailable, "write may have committed")
			}
			return &protocol.UpdateReply{Order: request.Order}, nil
		},
	})
	client := fixtureClient(t, fixture)
	beacon, cause := client.Beacon(context.Background(), testScope(), []byte("fixed"), []byte("initial"), 10*time.Second, time.Second)
	if cause != nil {
		t.Fatal(cause)
	}
	_, cause = beacon.Update(context.Background(), []byte("unknown-caller-data"))
	requireCode(t, cause, CodeTransport, Unknown)
	request := receiveTest(t, restored)
	if request.Generation != 2 || request.Order != 0 || string(request.Data) != "initial" || string(request.Uuid) != string(fixtureID()) || len(request.Capability) != 32 {
		t.Fatal("recovery replayed unknown Data or replaced the logical ID")
	}
	awaitCondition(t, func() bool {
		state := beacon.State()
		return state.Phase == Ready && state.Identity.Instance == "star-b"
	})
	beacon.mu.Lock()
	confirmed := beacon.data.String()
	beacon.mu.Unlock()
	if confirmed != "server-confirmed" {
		t.Fatal("recovery failed to adopt a newer server-confirmed order")
	}
	receipt, cause := beacon.Update(context.Background(), []byte("explicit-next"))
	if cause != nil || receipt.Order != 2 || receipt.Identity.Instance != "star-b" || updates.Load() != 2 {
		t.Fatalf("recovery changed explicit update history: %#v %v", receipt, cause)
	}
}

// TestBeaconSlowTickDoesNotBlockBeatAndManualUpdate fences a queued sample after explicit admission.
func TestBeaconSlowTickDoesNotBlockBeatAndManualUpdate(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	once := sync.Once{}
	writes := make(chan string, 4)
	beats := make(chan uint64, 16)
	fixture := newFixture(t, fixtureHandlers{
		update: func(_ context.Context, request *protocol.UpdateRequest) (*protocol.UpdateReply, error) {
			recordTest(t, writes, string(request.Data))
			return &protocol.UpdateReply{Order: request.Order}, nil
		},
		renew: func(_ context.Context, request *protocol.RenewRequest) (*protocol.RenewReply, error) {
			select {
			case beats <- request.Order:
			default:
			}
			return &protocol.RenewReply{Order: request.Order}, nil
		},
	})
	client := fixtureClient(t, fixture)
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	beacon, cause := client.Beacon(context.Background(), testScope(), nil, nil, time.Second, 50*time.Millisecond)
	if cause != nil {
		t.Fatal(cause)
	}
	if cause := beacon.Tick(time.Hour, func() ([]byte, error) { close(entered); <-release; return []byte("obsolete-sample"), nil }); cause != nil {
		t.Fatal(cause)
	}
	// Move only the local test deadline: production time is never replaced or slept forward.
	beacon.mu.Lock()
	beacon.nextTick = time.Now()
	beacon.mu.Unlock()
	beacon.wake()
	receiveTest(t, entered)
	if order := receiveTest(t, beats); order == 0 {
		t.Fatal("renewal order was not positive while Tick blocked")
	}
	if receipt, cause := beacon.Update(context.Background(), []byte("manual")); cause != nil || receipt.Order != 1 {
		t.Fatalf("slow Tick blocked manual Update: %#v %v", receipt, cause)
	}
	once.Do(func() { close(release) })
	awaitCondition(t, func() bool { beacon.mu.Lock(); defer beacon.mu.Unlock(); return !beacon.sampling })
	if receiveTest(t, writes) != "manual" {
		t.Fatal("manual payload changed")
	}
	select {
	case payload := <-writes:
		t.Fatalf("late sample escaped its epoch: %q", payload)
	default:
	}
}

// TestBeaconTickPanicSkipsDataAndPreservesBeat observes continued renewal after disabling a bad sampler.
func TestBeaconTickPanicSkipsDataAndPreservesBeat(t *testing.T) {
	writes, renewals := atomic.Int32{}, atomic.Int32{}
	fixture := newFixture(t, fixtureHandlers{
		update: func(_ context.Context, request *protocol.UpdateRequest) (*protocol.UpdateReply, error) {
			writes.Add(1)
			return &protocol.UpdateReply{Order: request.Order}, nil
		},
		renew: func(_ context.Context, request *protocol.RenewRequest) (*protocol.RenewReply, error) {
			renewals.Add(1)
			return &protocol.RenewReply{Order: request.Order}, nil
		},
	})
	client := fixtureClient(t, fixture)
	beacon, cause := client.Beacon(context.Background(), testScope(), nil, []byte("keep"), time.Second, 20*time.Millisecond)
	if cause != nil {
		t.Fatal(cause)
	}
	if cause := beacon.Tick(time.Millisecond, func() ([]byte, error) { panic("secret panic value") }); cause != nil {
		t.Fatal(cause)
	}
	awaitCondition(t, func() bool { return client.Panics() == 1 })
	before := renewals.Load()
	awaitCondition(t, func() bool { return renewals.Load() > before })
	if writes.Load() != 0 || client.Panics() != 1 {
		t.Fatal("failed Tick submitted empty data or remained active")
	}
	beacon.mu.Lock()
	retained, disabled := beacon.data.String(), beacon.tick == nil
	beacon.mu.Unlock()
	if retained != "keep" || !disabled {
		t.Fatal("panic replaced recovery data or failed to disable sampling")
	}
}

// TestBeaconWaitIncludesActualCallbackCompletion keeps lifetime quota until a blocked callback exits.
func TestBeaconWaitIncludesActualCallbackCompletion(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	once := sync.Once{}
	fixture := newFixture(t, fixtureHandlers{})
	client := fixtureClient(t, fixture)
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	beacon, cause := client.Beacon(context.Background(), testScope(), nil, nil, time.Second, 100*time.Millisecond)
	if cause != nil {
		t.Fatal(cause)
	}
	if cause := beacon.Changed(func(BeaconState) { close(entered); <-release }); cause != nil {
		t.Fatal(cause)
	}
	receiveTest(t, entered)
	beacon.Destroy()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if cause := beacon.Wait(ctx); !errors.Is(cause, context.Canceled) {
		t.Fatalf("Wait reclaimed a running callback: %v", cause)
	}
	once.Do(func() { close(release) })
	if cause := beacon.Wait(testContext(t)); cause != nil {
		t.Fatal(cause)
	}
}

// TestBeaconRejectsMalformedCreate preserves possible-commit uncertainty without a usable handle.
func TestBeaconRejectsMalformedCreate(t *testing.T) {
	// These independent wire mutations violate the shared Create reply contract.
	cases := []struct {
		name   string                      // The malformed protocol field under test.
		change func(*protocol.CreateReply) // Mutate one otherwise legal initial receipt.
	}{
		{"uuid-length", func(reply *protocol.CreateReply) { reply.Uuid = []byte("invalid") }},
		{"uuid-version", func(reply *protocol.CreateReply) { reply.Uuid[6] = 0x57 }},
		{"uuid-variant", func(reply *protocol.CreateReply) { reply.Uuid[8] = 0x09 }},
		{"instance-empty", func(reply *protocol.CreateReply) { reply.Instance = nil }},
		{"instance-mismatch", func(reply *protocol.CreateReply) { reply.Instance = []byte("other-star") }},
		{"generation", func(reply *protocol.CreateReply) { reply.Generation = 2 }},
		{"ttl", func(reply *protocol.CreateReply) { reply.TtlMs = 2000 }},
		{"capability-short", func(reply *protocol.CreateReply) { reply.Capability = make([]byte, 31) }},
		{"capability-long", func(reply *protocol.CreateReply) { reply.Capability = make([]byte, 33) }},
		{"initial-order", func(reply *protocol.CreateReply) { reply.Order = 1 }},
		{"unconfirmed-data", func(reply *protocol.CreateReply) { reply.Data = []byte("altered") }},
		{"data-limit", func(reply *protocol.CreateReply) { reply.Data = make([]byte, maxPayload+1) }},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			calls := atomic.Int32{}
			fixture := newFixture(t, fixtureHandlers{create: func(_ context.Context, request *protocol.CreateRequest) (*protocol.CreateReply, error) {
				calls.Add(1)
				if request.Generation != 1 || request.Order != 0 || len(request.Uuid) != 0 || len(request.Capability) != 0 || string(request.Data) != "initial" {
					t.Error("initial request violated the fixed registration history")
				}
				reply := &protocol.CreateReply{Instance: []byte("star-a"), Uuid: fixtureID(), Capability: make([]byte, 32),
					Generation: 1, TtlMs: 1000, Order: 0, Data: []byte("initial")}
				item.change(reply)
				return reply, nil
			}})
			client := fixtureClient(t, fixture, Options{Plaintext: true, Key: "key", Secret: []byte("secret")})
			beacon, cause := client.Beacon(context.Background(), testScope(), nil, []byte("initial"), time.Second, 100*time.Millisecond)
			requireCode(t, cause, CodeProtocol, Unknown)
			if beacon != nil {
				t.Fatal("malformed registration returned an active handle")
			}
			client.Close()
			if cause := client.Wait(testContext(t)); cause != nil || calls.Load() != 1 {
				t.Fatalf("uncertain initial registration was replayed or not drained: calls=%d error=%v", calls.Load(), cause)
			}
		})
	}
}

// TestBeaconRejectsMalformedUpdate preserves the consumed order and acknowledged Data after a bad receipt.
func TestBeaconRejectsMalformedUpdate(t *testing.T) {
	// Both a stale and a future acknowledgment leave the sent operation uncertain.
	for _, item := range []struct {
		name  string // Relation to the consumed first update order.
		order uint64 // Deliberately mismatched wire acknowledgment.
	}{{"older", 0}, {"future", 2}} {
		t.Run(item.name, func(t *testing.T) {
			calls := atomic.Int32{}
			fixture := newFixture(t, fixtureHandlers{update: func(_ context.Context, request *protocol.UpdateRequest) (*protocol.UpdateReply, error) {
				calls.Add(1)
				if request.Order != 1 || request.Generation != 1 || string(request.Data) != "unconfirmed" {
					t.Error("explicit update did not preserve its first consumed order and complete payload")
				}
				return &protocol.UpdateReply{Order: item.order}, nil
			}})
			client := fixtureClient(t, fixture)
			beacon, cause := client.Beacon(context.Background(), testScope(), nil, []byte("confirmed"), 10*time.Second, time.Second)
			if cause != nil {
				t.Fatal(cause)
			}
			receipt, cause := beacon.Update(context.Background(), []byte("unconfirmed"))
			requireCode(t, cause, CodeProtocol, Unknown)
			if receipt != (BeaconReceipt{}) || beacon.State().Phase != Failed || !beacon.State().HasIdentity {
				t.Fatalf("invalid receipt produced success or discarded the prior identity: %#v %#v", receipt, beacon.State())
			}
			beacon.mu.Lock()
			confirmed, issued, data := beacon.confirmed, beacon.issued, beacon.data.String()
			beacon.mu.Unlock()
			if confirmed != 0 || issued != 1 || data != "confirmed" {
				t.Fatalf("unknown outcome changed acknowledged history: confirmed=%d issued=%d data=%q", confirmed, issued, data)
			}
			_, cause = beacon.Update(context.Background(), []byte("later"))
			requireCode(t, cause, CodeBusy, Unapplied)
			beacon.Destroy()
			if cause := beacon.Wait(testContext(t)); cause != nil || calls.Load() != 1 {
				t.Fatalf("failed update was replayed or not drained: calls=%d error=%v", calls.Load(), cause)
			}
		})
	}
}

// TestBeaconRejectsMalformedRecovery keeps its last acknowledged history when restoration contradicts it.
func TestBeaconRejectsMalformedRecovery(t *testing.T) {
	// An established identity/capability and a confirmed order cannot be rewritten by restoration.
	cases := []struct {
		name   string                      // The established-history invariant under test.
		change func(*protocol.CreateReply) // Change one otherwise valid generation-two reply.
	}{
		{"identity", func(reply *protocol.CreateReply) { reply.Uuid[0] ^= 1 }},
		{"capability", func(reply *protocol.CreateReply) { reply.Capability[0] = 1 }},
		{"older-order", func(reply *protocol.CreateReply) { reply.Order = 0 }},
		{"same-order-data", func(reply *protocol.CreateReply) { reply.Data = []byte("rewritten") }},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			creates, updates := atomic.Int32{}, atomic.Int32{}
			fixture := newFixture(t, fixtureHandlers{
				create: func(_ context.Context, request *protocol.CreateRequest) (*protocol.CreateReply, error) {
					reply := &protocol.CreateReply{Instance: []byte("star-a"), Uuid: fixtureID(), Capability: make([]byte, 32),
						Generation: request.Generation, TtlMs: request.TtlMs, Order: request.Order, Data: request.Data}
					if creates.Add(1) > 1 {
						if request.Generation != 2 || request.Order != 1 || string(request.Data) != "confirmed" || string(request.Uuid) != string(fixtureID()) {
							t.Error("recovery changed the prescribed confirmed history")
						}
						item.change(reply)
					}
					return reply, nil
				},
				update: func(ctx context.Context, request *protocol.UpdateRequest) (*protocol.UpdateReply, error) {
					if updates.Add(1) == 1 {
						return &protocol.UpdateReply{Order: request.Order}, nil
					}
					return nil, rejected(ctx, protocol.Reason_REASON_ENDED)
				},
			})
			client := fixtureClient(t, fixture)
			beacon, cause := client.Beacon(context.Background(), testScope(), nil, []byte("initial"), 10*time.Second, time.Second)
			if cause != nil {
				t.Fatal(cause)
			}
			receipt, cause := beacon.Update(context.Background(), []byte("confirmed"))
			if cause != nil || receipt.Order != 1 {
				t.Fatalf("first update lacked its confirmation: %#v %v", receipt, cause)
			}
			_, cause = beacon.Update(context.Background(), []byte("unapplied"))
			requireCode(t, cause, CodeEnded, Unapplied)
			awaitCondition(t, func() bool { return beacon.State().Phase == Failed })
			state := beacon.State()
			requireCode(t, state.Error, CodeProtocol, Unknown)
			if !state.HasIdentity || state.Identity != receipt.Identity {
				t.Fatal("failed restoration replaced the original logical identity")
			}
			beacon.mu.Lock()
			confirmed, issued, data, capability := beacon.confirmed, beacon.issued, beacon.data.String(), beacon.capability
			beacon.mu.Unlock()
			if confirmed != 1 || issued != 2 || data != "confirmed" || capability != string(make([]byte, 32)) {
				t.Fatal("failed restoration changed acknowledged data, consumed order or capability")
			}
			beacon.Destroy()
			if cause := beacon.Wait(testContext(t)); cause != nil || creates.Load() != 2 || updates.Load() != 2 {
				t.Fatalf("restoration failure retried or failed to drain: creates=%d updates=%d error=%v", creates.Load(), updates.Load(), cause)
			}
		})
	}
}

// TestBeaconRejectsMalformedRenewal keeps renewal and Data order spaces independent after a bad receipt.
func TestBeaconRejectsMalformedRenewal(t *testing.T) {
	for _, item := range []struct {
		name  string // Relation to the first independent renewal order.
		order uint64 // Deliberately wrong server acknowledgment.
	}{{"older", 0}, {"future", 2}} {
		t.Run(item.name, func(t *testing.T) {
			calls := atomic.Int32{}
			fixture := newFixture(t, fixtureHandlers{renew: func(_ context.Context, request *protocol.RenewRequest) (*protocol.RenewReply, error) {
				calls.Add(1)
				if request.Order != 1 || request.Generation != 1 || string(request.Uuid) != string(fixtureID()) {
					t.Error("renewal did not bind the original registration and independent order")
				}
				return &protocol.RenewReply{Order: item.order}, nil
			}})
			client := fixtureClient(t, fixture)
			beacon, cause := client.Beacon(context.Background(), testScope(), nil, []byte("initial"), time.Second, 20*time.Millisecond)
			if cause != nil {
				t.Fatal(cause)
			}
			awaitCondition(t, func() bool { return beacon.State().Phase == Failed })
			requireCode(t, beacon.State().Error, CodeProtocol, Unknown)
			beacon.mu.Lock()
			confirmed, issued, renewal, data := beacon.confirmed, beacon.issued, beacon.renewal, beacon.data.String()
			beacon.mu.Unlock()
			if confirmed != 0 || issued != 0 || renewal != 1 || data != "initial" {
				t.Fatal("bad renewal receipt changed Data history or reused its order")
			}
			beacon.Destroy()
			if cause := beacon.Wait(testContext(t)); cause != nil || calls.Load() != 1 {
				t.Fatalf("permanent renewal failure retried or failed to drain: calls=%d error=%v", calls.Load(), cause)
			}
		})
	}
}

// TestBeaconChangedReplacement fences a panicking old callback without removing its replacement.
func TestBeaconChangedReplacement(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	once := sync.Once{}
	fixture := newFixture(t, fixtureHandlers{})
	client := fixtureClient(t, fixture)
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	beacon, cause := client.Beacon(context.Background(), testScope(), nil, nil, 10*time.Second, time.Second)
	if cause != nil {
		t.Fatal(cause)
	}
	if cause := beacon.Changed(func(BeaconState) { close(entered); <-release; panic("private callback data") }); cause != nil {
		t.Fatal(cause)
	}
	receiveTest(t, entered)
	replaced := make(chan BeaconState, 1)
	if cause := beacon.Changed(func(state BeaconState) { recordTest(t, replaced, state) }); cause != nil {
		t.Fatal(cause)
	}
	once.Do(func() { close(release) })
	state := receiveTest(t, replaced)
	if state.Phase != Ready || state.Error != nil || !state.HasIdentity || client.Panics() != 1 {
		t.Fatalf("old callback panic disabled or contaminated its replacement: %#v panics=%d", state, client.Panics())
	}
	if cause := beacon.Changed(nil); cause != nil {
		t.Fatal(cause)
	}
	beacon.Destroy()
	if cause := beacon.Wait(testContext(t)); cause != nil {
		t.Fatal(cause)
	}
}
