// Verify synchronous Catalog receipts, single-conflict repair and unknown-outcome fences.
package comet

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// TestPublisherWatermarksAndCache compares requests with fixed independent server watermarks.
func TestPublisherWatermarksAndCache(t *testing.T) {
	queries := atomic.Int32{}
	writes := make(chan *protocol.PublishRequest, 4)
	fixture := newFixture(t, fixtureHandlers{
		query: func(_ context.Context, request *protocol.CatalogQueryRequest) (*protocol.CatalogQueryReply, error) {
			queries.Add(1)
			reply := &protocol.CatalogQueryReply{Instance: []byte("star-a")}
			for _, key := range request.Keys {
				version := uint64(9)
				if key == "b" {
					version = 41
				}
				reply.Entries = append(reply.Entries, &protocol.CatalogQueryReply_Entry{Key: key, Version: version})
			}
			return reply, nil
		},
		publish: func(_ context.Context, request *protocol.PublishRequest) (*protocol.PublishReply, error) {
			recordTest(t, writes, request)
			return &protocol.PublishReply{Instance: request.Instance, Version: request.Version}, nil
		},
	})
	client := fixtureClient(t, fixture)
	publisher, cause := client.Publisher(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	entries := []Entry{{Key: "b", Data: nil}, {Key: "a", Data: []byte("one")}}
	for index := range 3 {
		batch := entries
		if index == 2 {
			batch = entries[1:]
		}
		receipt, cause := publisher.Update(context.Background(), batch, time.Second)
		if cause != nil || receipt.Version != uint64(42+index) || receipt.Instance != "star-a" {
			t.Fatalf("receipt %d: %#v, %v", index, receipt, cause)
		}
		request := receiveTest(t, writes)
		if request.Key != "" || len(request.Entries) != len(batch) || request.Entries[0].Key != "a" || string(request.Entries[0].Value) != "one" {
			t.Fatal("batch encoding or canonical order is wrong")
		}
	}
	if queries.Load() != 2 || entries[0].Key != "b" {
		t.Fatal("query cache changed caller order or missed exact-key-set reuse")
	}
}

// TestPublisherRepairsOnlyOneExplicitConflict fixes expected history as Query7/Publish8/Query19/Publish20.
func TestPublisherRepairsOnlyOneExplicitConflict(t *testing.T) {
	queries, writes := atomic.Int32{}, atomic.Int32{}
	versions := make(chan uint64, 2)
	fixture := newFixture(t, fixtureHandlers{
		query: func(_ context.Context, request *protocol.CatalogQueryRequest) (*protocol.CatalogQueryReply, error) {
			version := uint64(7)
			if queries.Add(1) > 1 {
				version = 19
			}
			return &protocol.CatalogQueryReply{Instance: []byte("star-a"), Entries: []*protocol.CatalogQueryReply_Entry{{Key: request.Keys[0], Version: version}}}, nil
		},
		publish: func(ctx context.Context, request *protocol.PublishRequest) (*protocol.PublishReply, error) {
			recordTest(t, versions, request.Version)
			if writes.Add(1) == 1 {
				return nil, rejected(ctx, protocol.Reason_REASON_VERSION)
			}
			return &protocol.PublishReply{Instance: request.Instance, Version: request.Version}, nil
		},
	})
	client := fixtureClient(t, fixture)
	publisher, cause := client.Publisher(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	receipt, cause := publisher.Update(context.Background(), []Entry{{Key: "k", Data: []byte("same")}}, time.Second)
	if cause != nil || receipt.Version != 20 || queries.Load() != 2 || writes.Load() != 2 || receiveTest(t, versions) != 8 || receiveTest(t, versions) != 20 {
		t.Fatalf("repair history mismatch: %#v %v", receipt, cause)
	}
}

// TestPublisherStopsAfterSecondConflict forbids an unbounded successful-looking retry loop.
func TestPublisherStopsAfterSecondConflict(t *testing.T) {
	writes := atomic.Int32{}
	fixture := newFixture(t, fixtureHandlers{publish: func(ctx context.Context, _ *protocol.PublishRequest) (*protocol.PublishReply, error) {
		writes.Add(1)
		return nil, rejected(ctx, protocol.Reason_REASON_VERSION)
	}})
	client := fixtureClient(t, fixture)
	publisher, cause := client.Publisher(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	_, cause = publisher.Update(context.Background(), []Entry{{Key: "k"}}, time.Second)
	requireCode(t, cause, CodeVersion, Unapplied)
	if writes.Load() != 2 {
		t.Fatal("conflict repair exceeded one additional send")
	}
}

// TestPublisherUnknownOutcomeConsumesVersion submits fresh caller data only after a lost receipt.
func TestPublisherUnknownOutcomeConsumesVersion(t *testing.T) {
	writes := make(chan *protocol.PublishRequest, 3)
	count := atomic.Int32{}
	fixture := newFixture(t, fixtureHandlers{publish: func(_ context.Context, request *protocol.PublishRequest) (*protocol.PublishReply, error) {
		recordTest(t, writes, request)
		if count.Add(1) == 1 {
			return nil, status.Error(codes.Unavailable, "receipt lost after possible commit")
		}
		return &protocol.PublishReply{Instance: request.Instance, Version: request.Version}, nil
	}})
	client := fixtureClient(t, fixture)
	publisher, cause := client.Publisher(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	_, cause = publisher.Update(context.Background(), []Entry{{Key: "k", Data: []byte("old")}}, time.Second)
	requireCode(t, cause, CodeTransport, Unknown)
	receipt, cause := publisher.Update(context.Background(), []Entry{{Key: "k", Data: []byte("new")}}, time.Second)
	if cause != nil || receipt.Version != 2 || count.Load() != 2 {
		t.Fatalf("unknown write was replayed or its version reused: %#v %v", receipt, cause)
	}
	first, second := receiveTest(t, writes), receiveTest(t, writes)
	if first.Version != 1 || string(first.Entries[0].Value) != "old" || second.Version != 2 || string(second.Entries[0].Value) != "new" {
		t.Fatal("wire history did not preserve explicit caller updates")
	}
}

// TestPublisherOverlapAndClose proves cancellation belongs to one Publisher, not its Client.
func TestPublisherOverlapAndClose(t *testing.T) {
	entered := make(chan struct{}, 1)
	calls := atomic.Int32{}
	fixture := newFixture(t, fixtureHandlers{publish: func(ctx context.Context, request *protocol.PublishRequest) (*protocol.PublishReply, error) {
		if calls.Add(1) == 1 {
			entered <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return &protocol.PublishReply{Instance: request.Instance, Version: request.Version}, nil
	}})
	client := fixtureClient(t, fixture)
	publisher, cause := client.Publisher(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	done := make(chan error, 1)
	go func() {
		_, cause := publisher.Update(context.Background(), []Entry{{Key: "k"}}, time.Second)
		done <- cause
	}()
	receiveTest(t, entered)
	_, cause = publisher.Update(context.Background(), []Entry{{Key: "other"}}, time.Second)
	requireCode(t, cause, CodeBusy, Unapplied)
	publisher.Close()
	requireCode(t, receiveTest(t, done), CodeClosed, Unknown)
	if cause := publisher.Wait(testContext(t)); cause != nil {
		t.Fatal(cause)
	}
	other, cause := client.Publisher(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	if _, cause := other.Update(context.Background(), []Entry{{Key: "other"}}, time.Second); cause != nil {
		t.Fatalf("one Publisher closed its Client: %v", cause)
	}
}

// TestPublisherInvalidBatchAndOverflow rejects malformed input and exhausted counters before Publish.
func TestPublisherInvalidBatchAndOverflow(t *testing.T) {
	writes := atomic.Int32{}
	fixture := newFixture(t, fixtureHandlers{publish: func(_ context.Context, request *protocol.PublishRequest) (*protocol.PublishReply, error) {
		writes.Add(1)
		return &protocol.PublishReply{Instance: request.Instance, Version: request.Version}, nil
	}})
	client := fixtureClient(t, fixture)
	publisher, cause := client.Publisher(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	_, cause = publisher.Update(context.Background(), []Entry{{Key: "duplicate"}, {Key: "duplicate"}}, time.Second)
	requireCode(t, cause, CodeInput, Unapplied)
	publisher.issued = ^uint64(0) // Unshared idle owner: force the finite counter boundary.
	_, cause = publisher.Update(context.Background(), []Entry{{Key: "k"}}, time.Second)
	requireCode(t, cause, CodeLimit, Unapplied)
	if writes.Load() != 0 {
		t.Fatal("invalid/exhausted batch reached Publish")
	}
}
