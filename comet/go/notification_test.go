// Verify public view notifications and retained quota through callback replacement and drain.
package comet

import (
	"context"
	"errors"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// TestChangedBaselinePanicAndReplacement retains complete snapshots and publishes sanitized callback failure.
func TestChangedBaselinePanicAndReplacement(t *testing.T) {
	baseline, advance := make(chan struct{}), make(chan struct{})
	fixture := newFixture(t, fixtureHandlers{catalog: func(_ *protocol.WatchRequest, stream grpc.ServerStreamingServer[protocol.CatalogWatchReply]) error {
		for index, release := range []<-chan struct{}{baseline, advance} {
			select {
			case <-release:
			case <-stream.Context().Done():
				return stream.Context().Err()
			}
			mode, data := protocol.Mode_MODE_RESET, "before"
			if index == 1 {
				mode, data = protocol.Mode_MODE_APPLY, "after"
			}
			if cause := stream.Send(&protocol.CatalogWatchReply{
				Mode: mode, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(uint64(7 + index)),
				Changes: []*protocol.CatalogChange{catalogValue("stable", data, uint64(1+index))},
			}); cause != nil {
				return cause
			}
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}})
	client := fixtureClient(t, fixture)
	subscriber, cause := client.Subscriber(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	states := make(chan View, 8)
	if cause := subscriber.Changed(func(view View) { recordTest(t, states, view) }); cause != nil {
		t.Fatal(cause)
	}
	initial := receiveTest(t, states)
	if initial.Phase != Waiting || initial.HasVersion || initial.Data.Len() != 0 {
		t.Fatal("Changed did not deliver the uninitialized state without inventing content")
	}
	close(baseline)
	ready := receiveTest(t, states)
	value, present := ready.Data.Get("stable")
	if ready.Phase != Ready || !ready.HasVersion || ready.Version != 7 || !present || value.String() != "before" {
		t.Fatal("Changed exposed an incomplete or incorrect baseline")
	}
	if cause := subscriber.Changed(func(View) { panic("private callback data") }); cause != nil {
		t.Fatal(cause)
	}
	awaitCondition(t, func() bool {
		view := subscriber.State()
		return client.Panics() == 1 && view.Error != nil && view.Error.Code == CodeCallback
	})
	if cause := subscriber.Changed(func(view View) { recordTest(t, states, view) }); cause != nil {
		t.Fatal(cause)
	}
	replacement := receiveTest(t, states)
	if replacement.Phase != Ready || replacement.Version != 7 || replacement.Error == nil || replacement.Error.Code != CodeCallback {
		t.Fatal("late replacement lost complete state or sanitized panic diagnostics")
	}
	replacement.Error.Code = CodeInternal
	if subscriber.State().Error.Code != CodeCallback {
		t.Fatal("application mutated the installed error through a callback value")
	}
	close(advance)
	updated := receiveTest(t, states)
	value, present = updated.Data.Get("stable")
	retained, retainedPresent := ready.Data.Get("stable")
	if updated.Phase != Ready || updated.Version != 8 || updated.Error != nil || !present || value.String() != "after" ||
		!retainedPresent || retained.String() != "before" || client.Panics() != 1 {
		t.Fatal("panic damaged receiver progress, retained data or replacement registration")
	}
}

// TestChangedReplacementWhileRunning fences a panicking prior registration without disabling the new one.
func TestChangedReplacementWhileRunning(t *testing.T) {
	fixture := newFixture(t, fixtureHandlers{catalog: func(_ *protocol.WatchRequest, stream grpc.ServerStreamingServer[protocol.CatalogWatchReply]) error {
		if cause := stream.Send(&protocol.CatalogWatchReply{Mode: protocol.Mode_MODE_RESET, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(0)}); cause != nil {
			return cause
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}})
	client := fixtureClient(t, fixture)
	subscriber, cause := client.Subscriber(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	awaitCondition(t, func() bool { return subscriber.State().Phase == Ready })
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	if cause := subscriber.Changed(func(View) { close(entered); <-release; panic("replaced callback") }); cause != nil {
		t.Fatal(cause)
	}
	receiveTest(t, entered)
	states := make(chan View, 2)
	if cause := subscriber.Changed(func(view View) { recordTest(t, states, view) }); cause != nil {
		t.Fatal(cause)
	}
	once.Do(func() { close(release) })
	view := receiveTest(t, states)
	if view.Phase != Ready || !view.HasVersion || view.Version != 0 || view.Data.Len() != 0 || client.Panics() != 1 {
		t.Fatal("old callback prevented the new registration's complete baseline")
	}
	if cause := subscriber.Changed(nil); cause != nil {
		t.Fatal(cause)
	}
	subscriber.Stop()
	if cause := subscriber.Wait(testContext(t)); cause != nil || subscriber.State().Phase != Closed {
		t.Fatal("replacement callback retained work after explicit close")
	}
}

// TestWatchStopRetainsQuotaUntilCallbackDrain makes logical closure and actual completion distinct.
func TestWatchStopRetainsQuotaUntilCallbackDrain(t *testing.T) {
	fixture := newFixture(t, fixtureHandlers{catalog: func(_ *protocol.WatchRequest, stream grpc.ServerStreamingServer[protocol.CatalogWatchReply]) error {
		if cause := stream.Send(&protocol.CatalogWatchReply{
			Mode: protocol.Mode_MODE_RESET, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(7),
			Changes: []*protocol.CatalogChange{catalogValue("stable", "retained", 1)},
		}); cause != nil {
			return cause
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}})
	client := fixtureClient(t, fixture, Options{Anonymous: true, Plaintext: true, Readers: 1})
	subscriber, cause := client.Subscriber(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	entered, release := make(chan Map, 1), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	if cause := subscriber.Watch(func(values Map) { recordTest(t, entered, values); <-release }); cause != nil {
		t.Fatal(cause)
	}
	retained := receiveTest(t, entered)
	subscriber.Stop()
	requireCode(t, subscriber.Watch(nil), CodeClosed, Unapplied)
	requireCode(t, subscriber.WatchKey(nil), CodeClosed, Unapplied)
	requireCode(t, subscriber.Changed(nil), CodeClosed, Unapplied)
	if view := subscriber.State(); view.Phase != Closed || !view.HasVersion || view.Version != 7 || view.Error != nil {
		t.Fatal("logical close discarded the last complete view or failed to mark Closed")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if cause := subscriber.Wait(cancelled); !errors.Is(cause, context.Canceled) {
		t.Fatalf("Wait completed while an application callback still owned work: %v", cause)
	}
	_, cause = client.Reader(testScope())
	requireCode(t, cause, CodeBusy, Unapplied)
	once.Do(func() { close(release) })
	if cause := subscriber.Wait(testContext(t)); cause != nil {
		t.Fatal(cause)
	}
	value, present := retained.Get("stable")
	if !present || value.String() != "retained" {
		t.Fatal("callback snapshot did not survive complete role drain")
	}
	replacement, cause := client.Subscriber(testScope())
	if cause != nil {
		t.Fatalf("drained callback kept the sole read quota: %v", cause)
	}
	replacement.Stop()
	if cause := replacement.Wait(testContext(t)); cause != nil {
		t.Fatal(cause)
	}
}
