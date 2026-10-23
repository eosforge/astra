// Verify bounded public admission with real blocked unary calls and drained role ownership.
package comet

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// TestExplicitUnaryCapacity admits the documented 256 calls and rejects overflow without hidden queuing.
func TestExplicitUnaryCapacity(t *testing.T) {
	queries, active, writes, creates := atomic.Int32{}, atomic.Int32{}, atomic.Int32{}, atomic.Int32{}
	entered := make(chan struct{}, 256)
	fixture := newFixture(t, fixtureHandlers{
		query: func(ctx context.Context, request *protocol.CatalogQueryRequest) (*protocol.CatalogQueryReply, error) {
			if queries.Add(1) <= 256 {
				active.Add(1)
				defer active.Add(-1)
				recordTest(t, entered, struct{}{})
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return &protocol.CatalogQueryReply{Instance: []byte("star-a"), Entries: []*protocol.CatalogQueryReply_Entry{{Key: request.Keys[0], Version: 3}}}, nil
		},
		publish: func(_ context.Context, request *protocol.PublishRequest) (*protocol.PublishReply, error) {
			writes.Add(1)
			return &protocol.PublishReply{Instance: request.Instance, Version: request.Version}, nil
		},
		create: func(_ context.Context, request *protocol.CreateRequest) (*protocol.CreateReply, error) {
			creates.Add(1)
			return &protocol.CreateReply{Instance: []byte("star-a"), Uuid: fixtureID(), Capability: make([]byte, 32),
				Generation: request.Generation, TtlMs: request.TtlMs, Order: request.Order, Data: request.Data}, nil
		},
	})
	client := fixtureClient(t, fixture, Options{Anonymous: true, Plaintext: true, Beacons: 512})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	finished := make(chan error, 256)
	for range 256 {
		publisher, cause := client.Publisher(testScope())
		if cause != nil {
			t.Fatal(cause)
		}
		go func() {
			_, cause := publisher.Update(ctx, []Entry{{Key: "held"}}, time.Second)
			finished <- cause
		}()
	}
	for range 256 {
		receiveTest(t, entered)
	}
	if queries.Load() != 256 || active.Load() != 256 {
		t.Fatal("fixture did not retain all 256 actual unary calls")
	}
	overflow, cause := client.Publisher(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	receipt, cause := overflow.Update(testContext(t), []Entry{{Key: "overflow"}}, time.Second)
	requireCode(t, cause, CodeBusy, Unapplied)
	if receipt != (Receipt{}) {
		t.Fatal("rejected admission returned a receipt")
	}
	beacon, cause := client.Beacon(testContext(t), testScope(), nil, nil, time.Second, 500*time.Millisecond)
	requireCode(t, cause, CodeBusy, Unapplied)
	if beacon != nil || creates.Load() != 0 || queries.Load() != 256 || writes.Load() != 0 {
		t.Fatal("shared unary overflow reached the network or queued business work")
	}
	cancel()
	for range 256 {
		requireCode(t, receiveTest(t, finished), CodeCanceled, Unapplied)
	}
	awaitCondition(t, func() bool { return active.Load() == 0 })
	receipt, cause = overflow.Update(testContext(t), []Entry{{Key: "fresh"}}, time.Second)
	if cause != nil || receipt.Version != 4 || receipt.Instance != "star-a" || queries.Load() != 257 || writes.Load() != 1 || creates.Load() != 0 {
		t.Fatalf("drained calls did not return admission or queued rejected work reappeared: %#v %v", receipt, cause)
	}
}

// TestSharedWriterQuota returns one shared Publisher/Beacon slot only after the original owner drains.
func TestSharedWriterQuota(t *testing.T) {
	creates := atomic.Int32{}
	fixture := newFixture(t, fixtureHandlers{create: func(_ context.Context, request *protocol.CreateRequest) (*protocol.CreateReply, error) {
		creates.Add(1)
		return &protocol.CreateReply{Instance: []byte("star-a"), Uuid: fixtureID(), Capability: make([]byte, 32),
			Generation: request.Generation, TtlMs: request.TtlMs, Order: request.Order, Data: request.Data}, nil
	}})
	client := fixtureClient(t, fixture, Options{Anonymous: true, Plaintext: true, Beacons: 1})
	publisher, cause := client.Publisher(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	_, cause = client.Publisher(testScope())
	requireCode(t, cause, CodeBusy, Unapplied)
	beacon, cause := client.Beacon(testContext(t), testScope(), nil, nil, time.Second, 500*time.Millisecond)
	requireCode(t, cause, CodeBusy, Unapplied)
	if beacon != nil || creates.Load() != 0 {
		t.Fatal("shared writer quota was bypassed by Beacon construction")
	}
	publisher.Close()
	if cause := publisher.Wait(testContext(t)); cause != nil {
		t.Fatal(cause)
	}
	beacon, cause = client.Beacon(testContext(t), testScope(), nil, nil, time.Second, 500*time.Millisecond)
	if cause != nil || beacon == nil || creates.Load() != 1 {
		t.Fatalf("Publisher drain did not release the shared writer slot: %v", cause)
	}
	_, cause = client.Publisher(testScope())
	requireCode(t, cause, CodeBusy, Unapplied)
	beacon.Destroy()
	if cause := beacon.Wait(testContext(t)); cause != nil {
		t.Fatal(cause)
	}
	final, cause := client.Publisher(testScope())
	if cause != nil {
		t.Fatalf("Beacon drain did not release the shared writer slot: %v", cause)
	}
	final.Close()
	if cause := final.Wait(testContext(t)); cause != nil {
		t.Fatal(cause)
	}
}
