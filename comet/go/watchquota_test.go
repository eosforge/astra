// Verify public Watch timeout classification while the live Session occupies the only HTTP/2 stream slot.
package comet

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// TestWatchAdmissionDeadline preserves the initial watchdog's cause before a Watch request reaches the server.
func TestWatchAdmissionDeadline(t *testing.T) {
	var sessions, watches atomic.Int32
	fixture := newFixture(t, fixtureHandlers{
		session: func(_ *protocol.SessionRequest, stream grpc.ServerStreamingServer[protocol.SessionReply]) error {
			sessions.Add(1)
			if cause := stream.Send(&protocol.SessionReply{Instance: []byte("star-a"), Session: make([]byte, 32)}); cause != nil {
				return cause
			}
			<-stream.Context().Done()
			return stream.Context().Err()
		},
		catalog: func(_ *protocol.WatchRequest, stream grpc.ServerStreamingServer[protocol.CatalogWatchReply]) error {
			watches.Add(1)
			<-stream.Context().Done()
			return stream.Context().Err()
		},
	}, grpc.MaxConcurrentStreams(1))
	client := fixtureClient(t, fixture, Options{Plaintext: true, Key: "key", Secret: []byte("secret"), Timeout: 250 * time.Millisecond})
	subscriber, cause := client.Subscriber(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	awaitCondition(t, func() bool { return subscriber.State().Error != nil })
	state := subscriber.State()
	if sessions.Load() != 1 || watches.Load() != 0 || state.HasVersion || state.Data.Len() != 0 {
		t.Fatal("stream quota did not isolate admission behind one live Session or published incomplete state")
	}
	requireCode(t, state.Error, CodeTimeout, Unapplied)
	if !errors.Is(state.Error, context.DeadlineExceeded) || errors.Is(state.Error, context.Canceled) {
		t.Fatal("Watch admission watchdog lost its canonical deadline cause")
	}
}

// TestWatchAdmissionAndStop installs complete content beside the live Session and drains without a false timeout.
func TestWatchAdmissionAndStop(t *testing.T) {
	// The two HTTP/2 slots belong to one confirmed Session and one Catalog Watch.
	var sessions, watches atomic.Int32
	finished := make(chan struct{})
	fixture := newFixture(t, fixtureHandlers{
		session: func(_ *protocol.SessionRequest, stream grpc.ServerStreamingServer[protocol.SessionReply]) error {
			sessions.Add(1)
			if cause := stream.Send(&protocol.SessionReply{Instance: []byte("star-a"), Session: make([]byte, 32)}); cause != nil {
				return cause
			}
			<-stream.Context().Done()
			return stream.Context().Err()
		},
		catalog: func(_ *protocol.WatchRequest, stream grpc.ServerStreamingServer[protocol.CatalogWatchReply]) error {
			watches.Add(1)
			defer close(finished)
			if cause := stream.Send(&protocol.CatalogWatchReply{Mode: protocol.Mode_MODE_RESET, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(5),
				Changes: []*protocol.CatalogChange{catalogValue("k", "complete", 1)}}); cause != nil {
				return cause
			}
			<-stream.Context().Done()
			return stream.Context().Err()
		},
	}, grpc.MaxConcurrentStreams(2))
	client := fixtureClient(t, fixture, Options{Plaintext: true, Key: "key", Secret: []byte("secret"), Timeout: time.Second})
	subscriber, cause := client.Subscriber(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	awaitCondition(t, func() bool { return subscriber.State().Phase == Ready })
	state := subscriber.State()
	value, present := state.Data.Get("k")
	if sessions.Load() != 1 || watches.Load() != 1 || !state.HasVersion || state.Version != 5 || state.Error != nil || !present || value.String() != "complete" {
		t.Fatal("available HTTP/2 slot did not publish the complete baseline")
	}
	subscriber.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if cause := subscriber.Wait(ctx); cause != nil {
		t.Fatal(cause)
	}
	receiveTest(t, finished)
	if state := subscriber.State(); state.Phase != Closed || state.Error != nil || !state.HasVersion || state.Version != 5 {
		t.Fatal("explicit Stop became a timeout or lost the complete retained view")
	}
	if value, present := state.Data.Get("k"); !present || value.String() != "complete" {
		t.Fatal("explicit Stop damaged the retained immutable baseline")
	}
}

// TestWatchAdmissionCanceled keeps an already-canceled owner distinct from an unexpired watchdog for every domain.
func TestWatchAdmissionCanceled(t *testing.T) {
	for _, kind := range []domain{almanac, catalog, ephemeris} {
		name := map[domain]string{almanac: "almanac", catalog: "catalog", ephemeris: "ephemeris"}[kind]
		t.Run(name, func(t *testing.T) {
			// A real authenticated binding occupies its only stream slot; the canceled
			// receive call is isolated from the supervisor so its failure is observable.
			fixture := newFixture(t, fixtureHandlers{}, grpc.MaxConcurrentStreams(1))
			client := fixtureClient(t, fixture, Options{Plaintext: true, Key: "key", Secret: []byte("secret"), Timeout: time.Second})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			selected, failure := client.acquire(ctx)
			if failure != nil {
				t.Fatal(failure)
			}
			canceled, stop := context.WithCancel(context.Background())
			stop()
			watch := &watching{life: &lifecycle{client: client, ctx: canceled}, domain: kind, scope: testScope()}
			failure = watch.receive(selected, false)
			requireCode(t, failure, CodeCanceled, Unknown)
			if !errors.Is(failure, context.Canceled) || errors.Is(failure, context.DeadlineExceeded) || watch.root != nil || watch.charged != 0 {
				t.Fatal("owner cancellation became watchdog expiry or installed content")
			}
		})
	}
}
