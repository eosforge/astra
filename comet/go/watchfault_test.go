// Verify real stream watchdogs, Session cancellation and pre-install wire limits.
package comet

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// TestWatchWireDeadlines cancels stalled initial/partial batches before a fresh complete stream can publish.
func TestWatchWireDeadlines(t *testing.T) {
	for _, partial := range []bool{false, true} {
		name := "initial"
		if partial {
			name = "partial"
		}
		t.Run(name, func(t *testing.T) {
			canceled, finish := make(chan struct{}), make(chan struct{})
			streams := atomic.Int32{}
			fixture := newFixture(t, fixtureHandlers{catalog: func(request *protocol.WatchRequest, stream grpc.ServerStreamingServer[protocol.CatalogWatchReply]) error {
				number := streams.Add(1)
				if number == 1 {
					if partial {
						if cause := stream.Send(&protocol.CatalogWatchReply{Mode: protocol.Mode_MODE_RESET, Changes: []*protocol.CatalogChange{catalogValue("k", "partial", 1)}}); cause != nil {
							return cause
						}
					}
					<-stream.Context().Done()
					close(canceled)
					return stream.Context().Err()
				}
				if number != 2 || request.Version != nil || len(request.Instance) != 0 {
					t.Error("incomplete content became a recovery cursor or spawned extra streams")
				}
				select {
				case <-finish:
				case <-stream.Context().Done():
					return stream.Context().Err()
				}
				if cause := stream.Send(&protocol.CatalogWatchReply{Mode: protocol.Mode_MODE_RESET, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(9),
					Changes: []*protocol.CatalogChange{catalogValue("k", "complete", 4)}}); cause != nil {
					return cause
				}
				<-stream.Context().Done()
				return stream.Context().Err()
			}})
			client := fixtureClient(t, fixture, Options{Anonymous: true, Plaintext: true, Timeout: 250 * time.Millisecond})
			subscriber, cause := client.Subscriber(testScope())
			if cause != nil {
				t.Fatal(cause)
			}
			receiveTest(t, canceled)
			awaitCondition(t, func() bool { state := subscriber.State(); return state.Error != nil && state.Error.Code == CodeTimeout })
			if state := subscriber.State(); state.HasVersion || state.Data.Len() != 0 {
				t.Fatal("a stalled page became publicly visible")
			}
			close(finish)
			awaitCondition(t, func() bool { return subscriber.State().Phase == Ready })
			state := subscriber.State()
			value, present := state.Data.Get("k")
			if streams.Load() != 2 || state.Version != 9 || !present || value.String() != "complete" || state.Error != nil {
				t.Fatal("watchdog recovery failed to publish one complete replacement")
			}
		})
	}
}

// TestWatchCanceledSessionReauthenticates treats server cancellation of an authenticated stream as Session invalidation.
func TestWatchCanceledSessionReauthenticates(t *testing.T) {
	logins, streams := atomic.Int32{}, atomic.Int32{}
	fixture := newFixture(t, fixtureHandlers{
		session: func(_ *protocol.SessionRequest, stream grpc.ServerStreamingServer[protocol.SessionReply]) error {
			logins.Add(1)
			if cause := stream.Send(&protocol.SessionReply{Instance: []byte("star-a"), Session: make([]byte, 32)}); cause != nil {
				return cause
			}
			<-stream.Context().Done()
			return stream.Context().Err()
		},
		catalog: func(_ *protocol.WatchRequest, stream grpc.ServerStreamingServer[protocol.CatalogWatchReply]) error {
			if streams.Add(1) == 1 {
				return status.Error(codes.Canceled, "private session cancellation")
			}
			if cause := stream.Send(&protocol.CatalogWatchReply{Mode: protocol.Mode_MODE_RESET, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(12)}); cause != nil {
				return cause
			}
			<-stream.Context().Done()
			return stream.Context().Err()
		},
	})
	client := fixtureClient(t, fixture, Options{Plaintext: true, Key: "key", Secret: []byte("secret")})
	subscriber, cause := client.Subscriber(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	awaitCondition(t, func() bool { return subscriber.State().Phase == Ready })
	if logins.Load() != 2 || streams.Load() != 2 || subscriber.State().Version != 12 || subscriber.State().Error != nil {
		t.Fatal("authenticated cancellation failed to replace the Session and complete stream")
	}
}

// TestWatchWireLimitsPreserveBaseline rejects excess raw rows/bytes without installing them or damaging retained snapshots.
func TestWatchWireLimitsPreserveBaseline(t *testing.T) {
	for _, name := range []string{"rows", "bytes"} {
		t.Run(name, func(t *testing.T) {
			reject := make(chan struct{})
			streams := atomic.Int32{}
			fixture := newFixture(t, fixtureHandlers{catalog: func(_ *protocol.WatchRequest, stream grpc.ServerStreamingServer[protocol.CatalogWatchReply]) error {
				streams.Add(1)
				if cause := stream.Send(&protocol.CatalogWatchReply{Mode: protocol.Mode_MODE_RESET, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(1),
					Changes: []*protocol.CatalogChange{catalogValue("k", "retained", 1)}}); cause != nil {
					return cause
				}
				select {
				case <-reject:
				case <-stream.Context().Done():
					return stream.Context().Err()
				}
				changes := []*protocol.CatalogChange{catalogValue("k", strings.Repeat("x", 32*1024), 2)}
				if name == "rows" {
					changes = []*protocol.CatalogChange{catalogValue("a", "x", 1), catalogValue("b", "x", 1), catalogValue("c", "x", 1)}
				}
				if cause := stream.Send(&protocol.CatalogWatchReply{Mode: protocol.Mode_MODE_APPLY, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(2), Changes: changes}); cause != nil {
					return cause
				}
				<-stream.Context().Done()
				return stream.Context().Err()
			}})
			client := fixtureClient(t, fixture)
			subscriber, cause := client.Subscriber(testScope(), ReadOptions{Bytes: 16 * 1024, Records: 1})
			if cause != nil {
				t.Fatal(cause)
			}
			awaitCondition(t, func() bool { return subscriber.State().Phase == Ready })
			retained := subscriber.State().Data
			close(reject)
			awaitCondition(t, func() bool { return subscriber.State().Phase == Failed })
			state := subscriber.State()
			value, present := state.Data.Get("k")
			before, _ := retained.Get("k")
			if state.Error == nil || state.Error.Code != CodeLimit || state.Version != 1 || !present || value.String() != "retained" || before.String() != "retained" || streams.Load() != 1 {
				t.Fatal("raw wire overflow changed the committed view or silently retried permanent input")
			}
		})
	}
}
