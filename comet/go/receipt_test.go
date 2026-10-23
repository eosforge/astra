// Verify Catalog wire receipts against prescribed request histories and commit effects.
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

// TestPublisherRejectsMalformedQuery preserves the caller and sends no write for an invalid watermark reply.
func TestPublisherRejectsMalformedQuery(t *testing.T) {
	cases := []struct {
		name   string
		change func(*protocol.CatalogQueryReply)
	}{
		{"empty-instance", func(reply *protocol.CatalogQueryReply) { reply.Instance = nil }},
		{"other-instance", func(reply *protocol.CatalogQueryReply) { reply.Instance = []byte("star-b") }},
		{"missing-entry", func(reply *protocol.CatalogQueryReply) { reply.Entries = reply.Entries[:1] }},
		{"extra-entry", func(reply *protocol.CatalogQueryReply) {
			reply.Entries = append(reply.Entries, &protocol.CatalogQueryReply_Entry{Key: "c"})
		}},
		{"reordered-keys", func(reply *protocol.CatalogQueryReply) {
			reply.Entries[0], reply.Entries[1] = reply.Entries[1], reply.Entries[0]
		}},
		{"duplicate-key", func(reply *protocol.CatalogQueryReply) { reply.Entries[1].Key = "a" }},
		{"empty-entry", func(reply *protocol.CatalogQueryReply) { reply.Entries[0] = &protocol.CatalogQueryReply_Entry{} }},
	}
	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			queries, writes := atomic.Int32{}, atomic.Int32{}
			commits := make(chan *protocol.PublishRequest, 2)
			fixture := newFixture(t, fixtureHandlers{
				query: func(_ context.Context, request *protocol.CatalogQueryRequest) (*protocol.CatalogQueryReply, error) {
					if len(request.Keys) != 2 || request.Keys[0] != "a" || request.Keys[1] != "b" || string(request.Instance) != "star-a" {
						t.Error("query changed the fixed instance or canonical key set")
					}
					reply := &protocol.CatalogQueryReply{Instance: []byte("star-a"), Entries: []*protocol.CatalogQueryReply_Entry{{Key: "a", Version: 7}, {Key: "b", Version: 11}}}
					if queries.Add(1) == 1 {
						testcase.change(reply)
					}
					return reply, nil
				},
				publish: func(_ context.Context, request *protocol.PublishRequest) (*protocol.PublishReply, error) {
					writes.Add(1)
					recordTest(t, commits, request)
					return &protocol.PublishReply{Instance: request.Instance, Version: request.Version}, nil
				},
			})
			client := fixtureClient(t, fixture, Options{Key: "key", Secret: []byte("fixture"), Plaintext: true})
			publisher, cause := client.Publisher(testScope())
			if cause != nil {
				t.Fatal(cause)
			}
			entries := []Entry{{Key: "b", Data: []byte("first-b")}, {Key: "a", Data: []byte("first-a")}}
			receipt, cause := publisher.Update(testContext(t), entries, time.Second)
			requireCode(t, cause, CodeProtocol, Unapplied)
			if receipt != (Receipt{}) || queries.Load() != 1 || writes.Load() != 0 || entries[0].Key != "b" || string(entries[0].Data) != "first-b" {
				t.Fatal("invalid Query changed input, produced a receipt or reached Publish")
			}
			entries[0].Data, entries[1].Data = []byte("fresh-b"), []byte("fresh-a")
			receipt, cause = publisher.Update(testContext(t), entries, time.Second)
			if cause != nil || receipt.Instance != "star-a" || receipt.Version != 12 || queries.Load() != 2 || writes.Load() != 1 {
				t.Fatalf("fresh caller update could not recover after Query rejection: %#v %v", receipt, cause)
			}
			request := receiveTest(t, commits)
			if len(request.Entries) != 2 || request.Version != 12 || string(request.Entries[0].Value) != "fresh-a" || string(request.Entries[1].Value) != "fresh-b" {
				t.Fatal("healthy request reused rejected data or the wrong version")
			}
		})
	}
}

// TestPublisherRejectsMalformedReceipt consumes submitted versions without replaying uncertain Data.
func TestPublisherRejectsMalformedReceipt(t *testing.T) {
	cases := []struct {
		name  string
		reply *protocol.PublishReply
	}{
		{"empty-instance", &protocol.PublishReply{Version: 1}},
		{"other-instance", &protocol.PublishReply{Instance: []byte("star-b"), Version: 1}},
		{"zero-version", &protocol.PublishReply{Instance: []byte("star-a")}},
		{"future-version", &protocol.PublishReply{Instance: []byte("star-a"), Version: 2}},
	}
	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			calls := atomic.Int32{}
			commits := make(chan *protocol.PublishRequest, 3)
			fixture := newFixture(t, fixtureHandlers{publish: func(_ context.Context, request *protocol.PublishRequest) (*protocol.PublishReply, error) {
				recordTest(t, commits, request)
				if calls.Add(1) == 1 {
					return testcase.reply, nil
				}
				return &protocol.PublishReply{Instance: request.Instance, Version: request.Version}, nil
			}})
			client := fixtureClient(t, fixture)
			publisher, cause := client.Publisher(testScope())
			if cause != nil {
				t.Fatal(cause)
			}
			receipt, cause := publisher.Update(testContext(t), []Entry{{Key: "k", Data: []byte("uncertain")}}, time.Second)
			requireCode(t, cause, CodeProtocol, Unknown)
			if receipt != (Receipt{}) || calls.Load() != 1 {
				t.Fatal("malformed receipt was accepted or replayed")
			}
			receipt, cause = publisher.Update(testContext(t), []Entry{{Key: "k", Data: []byte("fresh")}}, time.Second)
			if cause != nil || receipt.Version != 2 || receipt.Instance != "star-a" || calls.Load() != 2 {
				t.Fatalf("unknown receipt reused a version or blocked the new caller: %#v %v", receipt, cause)
			}
			first, second := receiveTest(t, commits), receiveTest(t, commits)
			if first.Version != 1 || second.Version != 2 || string(first.Entries[0].Value) != "uncertain" || string(second.Entries[0].Value) != "fresh" {
				t.Fatal("actual history replayed rejected Data or changed the explicit versions")
			}
		})
	}
}

// TestPublisherQueryFailureIsUnapplied distinguishes a failed read from an uncertain commit and drains Close.
func TestPublisherQueryFailureIsUnapplied(t *testing.T) {
	for _, closing := range []bool{false, true} {
		name := "transport"
		if closing {
			name = "close"
		}
		t.Run(name, func(t *testing.T) {
			entered := make(chan struct{}, 1)
			queries, writes := atomic.Int32{}, atomic.Int32{}
			fixture := newFixture(t, fixtureHandlers{
				query: func(ctx context.Context, request *protocol.CatalogQueryRequest) (*protocol.CatalogQueryReply, error) {
					if queries.Add(1) == 1 {
						recordTest(t, entered, struct{}{})
						if closing {
							<-ctx.Done()
							return nil, ctx.Err()
						}
						return nil, status.Error(codes.Unavailable, "private query failure")
					}
					return &protocol.CatalogQueryReply{Instance: []byte("star-a"), Entries: []*protocol.CatalogQueryReply_Entry{{Key: request.Keys[0], Version: 5}}}, nil
				},
				publish: func(_ context.Context, request *protocol.PublishRequest) (*protocol.PublishReply, error) {
					writes.Add(1)
					return &protocol.PublishReply{Instance: request.Instance, Version: request.Version}, nil
				},
			})
			client := fixtureClient(t, fixture)
			publisher, cause := client.Publisher(testScope())
			if cause != nil {
				t.Fatal(cause)
			}
			finished := make(chan error, 1)
			ctx := testContext(t)
			go func() {
				_, cause := publisher.Update(ctx, []Entry{{Key: "k"}}, time.Second)
				finished <- cause
			}()
			receiveTest(t, entered)
			code := CodeTransport
			if closing {
				publisher.Close()
				code = CodeClosed
			}
			requireCode(t, receiveTest(t, finished), code, Unapplied)
			if writes.Load() != 0 || queries.Load() != 1 {
				t.Fatal("failed query reached a write or was transparently retried")
			}
			publisher.Close()
			if cause := publisher.Wait(testContext(t)); cause != nil {
				t.Fatal(cause)
			}
			healthy, cause := client.Publisher(testScope())
			if cause != nil {
				t.Fatal(cause)
			}
			receipt, cause := healthy.Update(testContext(t), []Entry{{Key: "healthy"}}, time.Second)
			if cause != nil || receipt.Version != 6 || writes.Load() != 1 {
				t.Fatalf("failed query or one role's Close damaged shared admission: %#v %v", receipt, cause)
			}
		})
	}
}
