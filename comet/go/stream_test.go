// Verify complete wire publication, explicit absence, authority floors and bounded repair.
package comet

import (
	"sync/atomic"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// catalogValue constructs protocol test input; zero bytes remain a present value.
func catalogValue(key, data string, version uint64) *protocol.CatalogChange {
	return &protocol.CatalogChange{Key: key, Version: version, Action: &protocol.CatalogChange_Value{Value: []byte(data)}}
}

// TestSubscriberCompletePagesAndStaleRetention exposes no partial or malformed replacement.
func TestSubscriberCompletePagesAndStaleRetention(t *testing.T) {
	partial, finish, corrupt := make(chan struct{}), make(chan struct{}), make(chan struct{})
	fixture := newFixture(t, fixtureHandlers{catalog: func(_ *protocol.WatchRequest, stream grpc.ServerStreamingServer[protocol.CatalogWatchReply]) error {
		if cause := stream.Send(&protocol.CatalogWatchReply{Mode: protocol.Mode_MODE_RESET, Changes: []*protocol.CatalogChange{catalogValue("a", "first", 4)}}); cause != nil {
			return cause
		}
		close(partial)
		select {
		case <-finish:
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
		if cause := stream.Send(&protocol.CatalogWatchReply{
			Mode: protocol.Mode_MODE_RESET, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(10),
			Changes: []*protocol.CatalogChange{catalogValue("b", "", 1)},
		}); cause != nil {
			return cause
		}
		select {
		case <-corrupt:
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
		return stream.Send(&protocol.CatalogWatchReply{
			Mode: protocol.Mode_MODE_APPLY, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(11),
			Changes: []*protocol.CatalogChange{catalogValue("a", "bad", 5), catalogValue("a", "duplicate", 6)},
		})
	}})
	client := fixtureClient(t, fixture)
	subscriber, cause := client.Subscriber(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	delivered := make(chan Map, 4)
	if cause := subscriber.Watch(func(values Map) { recordTest(t, delivered, values) }); cause != nil {
		t.Fatal(cause)
	}
	receiveTest(t, partial)
	if subscriber.State().HasVersion {
		t.Fatal("incomplete page became visible")
	}
	close(finish)
	retained := receiveTest(t, delivered)
	if retained.Len() != 2 {
		t.Fatal("whole-scope callback was not a complete map")
	}
	empty, present := retained.Get("b")
	if !present || empty.Len() != 0 {
		t.Fatal("empty value was reported absent")
	}
	value, _ := retained.Get("a")
	copy := value.Bytes()
	copy[0] = 'x'
	close(corrupt)
	awaitCondition(t, func() bool { return subscriber.State().Phase == Failed })
	state := subscriber.State()
	current, _ := state.Data.Get("a")
	if state.Version != 10 || current.String() != "first" || value.String() != "first" || state.Error.Code != CodeProtocol {
		t.Fatal("malformed batch damaged committed content or cursor")
	}
	select {
	case <-delivered:
		t.Fatal("malformed stream produced a content callback")
	default:
	}
	subscriber.Stop()
	if cause := subscriber.Wait(testContext(t)); cause != nil || retained.Len() != 2 {
		t.Fatal("retained snapshot did not survive Stop/Wait")
	}
}

// TestExactKeyPresence distinguishes empty data from an authoritative deletion.
func TestExactKeyPresence(t *testing.T) {
	erase := make(chan struct{})
	fixture := newFixture(t, fixtureHandlers{catalog: func(request *protocol.WatchRequest, stream grpc.ServerStreamingServer[protocol.CatalogWatchReply]) error {
		if string(request.Target) != "only" {
			return status.Error(codes.InvalidArgument, "wrong exact target")
		}
		if cause := stream.Send(&protocol.CatalogWatchReply{
			Mode: protocol.Mode_MODE_RESET, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(1),
			Changes: []*protocol.CatalogChange{catalogValue("only", "", 1)},
		}); cause != nil {
			return cause
		}
		select {
		case <-erase:
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
		if cause := stream.Send(&protocol.CatalogWatchReply{
			Mode: protocol.Mode_MODE_APPLY, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(2),
			Changes: []*protocol.CatalogChange{{Key: "only", Action: &protocol.CatalogChange_Erase{Erase: &protocol.Empty{}}}},
		}); cause != nil {
			return cause
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}})
	client := fixtureClient(t, fixture)
	subscriber, cause := client.SubscriberKey(testScope(), "only")
	if cause != nil {
		t.Fatal(cause)
	}
	requireCode(t, subscriber.Watch(func(Map) {}), CodeInput, Unapplied)
	presence := make(chan bool, 2)
	if cause := subscriber.WatchKey(func(key string, value Value, present bool) {
		if key != "only" || value.Len() != 0 {
			t.Error("exact callback changed key or empty payload")
		}
		recordTest(t, presence, present)
	}); cause != nil {
		t.Fatal(cause)
	}
	if !receiveTest(t, presence) {
		t.Fatal("empty baseline value was absent")
	}
	close(erase)
	if receiveTest(t, presence) {
		t.Fatal("erase remained present")
	}
}

// TestReaderRetainsFloorAcrossInstanceChange rejects v90 after observing v100.
func TestReaderRetainsFloorAcrossInstanceChange(t *testing.T) {
	calls := atomic.Int32{}
	requests := make(chan *protocol.WatchRequest, 4)
	fixture := newFixture(t, fixtureHandlers{almanac: func(request *protocol.WatchRequest, stream grpc.ServerStreamingServer[protocol.AlmanacWatchReply]) error {
		recordTest(t, requests, request)
		call := calls.Add(1)
		instance, version := "star-a", uint64(100)
		if call > 1 {
			instance = "star-b"
		}
		if call == 2 {
			version = 90
		}
		if cause := stream.Send(&protocol.AlmanacWatchReply{Mode: protocol.Mode_MODE_RESET, Complete: true, Instance: []byte(instance), Version: &version,
			Changes: []*protocol.AlmanacChange{{Key: "authority", Action: &protocol.AlmanacChange_Value{Value: []byte(instance)}}}}); cause != nil {
			return cause
		}
		if call == 1 {
			return status.Error(codes.Unavailable, "force another target generation")
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}})
	client := fixtureClient(t, fixture)
	reader, cause := client.Reader(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	first, second, third := receiveTest(t, requests), receiveTest(t, requests), receiveTest(t, requests)
	if first.Version != nil || second.Version == nil || *second.Version != 100 || third.Version == nil || *third.Version != 100 {
		t.Fatal("Reader discarded its authority floor on reconnect/retry")
	}
	awaitCondition(t, func() bool { state := reader.State(); return state.Phase == Ready && state.Instance == "star-b" })
	if reader.State().Version != 100 {
		t.Fatal("Reader installed a version below its observed floor")
	}
}

// TestHistoryRepairResumesItsNewCursor catches a sticky fresh-snapshot repair flag.
func TestHistoryRepairResumesItsNewCursor(t *testing.T) {
	calls := atomic.Int32{}
	requests := make(chan *protocol.WatchRequest, 4)
	fixture := newFixture(t, fixtureHandlers{ephemeris: func(request *protocol.WatchRequest, stream grpc.ServerStreamingServer[protocol.EphemerisWatchReply]) error {
		recordTest(t, requests, request)
		call := calls.Add(1)
		version := uint64(call)
		if cause := stream.Send(&protocol.EphemerisWatchReply{
			Mode: protocol.Mode_MODE_RESET, Complete: true, Instance: []byte("star-a"), Version: &version,
			Changes: []*protocol.EphemerisChange{{Uuid: fixtureID(), Action: &protocol.EphemerisChange_Record_{
				Record: &protocol.EphemerisChange_Record{Attr: []byte("fixed"), Data: []byte("complete")},
			}}},
		}); cause != nil {
			return cause
		}
		if call == 1 {
			missing := fixtureID()
			missing[0]++
			if cause := stream.Send(&protocol.EphemerisWatchReply{Mode: protocol.Mode_MODE_APPLY, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(2),
				Changes: []*protocol.EphemerisChange{{Uuid: missing, Action: &protocol.EphemerisChange_Data{Data: []byte("missing-attr")}}}}); cause != nil {
				return cause
			}
		} else if call == 2 {
			return status.Error(codes.Unavailable, "disconnect after complete repair")
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}})
	client := fixtureClient(t, fixture)
	observer, cause := client.Observer(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	first, repair, resume := receiveTest(t, requests), receiveTest(t, requests), receiveTest(t, requests)
	if first.Version != nil || repair.Version != nil || resume.Version == nil || *resume.Version != 2 || string(resume.Instance) != "star-a" {
		t.Fatal("history repair did not resume its newly completed baseline")
	}
	awaitCondition(t, func() bool {
		item, cause := observer.One(func(pool Pool) *Item { return pool.Find(string(fixtureID())) })
		return cause == nil && item != nil && item.Record().Attr.String() == "fixed"
	})
}

// TestWatchPanicDisablesOnlyItsCallback preserves the receiver and permits later callback replacement.
func TestWatchPanicDisablesOnlyItsCallback(t *testing.T) {
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
	if cause := subscriber.Watch(func(Map) { panic("private application data") }); cause != nil {
		t.Fatal(cause)
	}
	awaitCondition(t, func() bool { return client.Panics() == 1 })
	delivered := make(chan Map, 1)
	if cause := subscriber.Watch(func(values Map) { recordTest(t, delivered, values) }); cause != nil {
		t.Fatal(cause)
	}
	if values := receiveTest(t, delivered); values.Len() != 0 || !subscriber.State().HasVersion {
		t.Fatal("late callback did not receive the complete empty baseline")
	}
}

// TestObserverSelectorPanicPropagates verifies that synchronous application control flow is unchanged.
func TestObserverSelectorPanicPropagates(t *testing.T) {
	client := &Client{}
	watch := &watching{life: newLifecycle(client, true), root: &snapshot{data: emptyTable()}, phase: Ready}
	defer watch.life.cancel()
	observer := &Observer{watch: watch}
	defer func() {
		if caught := recover(); caught != "selector failure" {
			t.Fatalf("selector panic was converted or lost: %v", caught)
		}
	}()
	_, _ = observer.One(func(Pool) *Item { panic("selector failure") })
}

// TestReadQuotaReturnsAfterDrain checks admission and independent subscription ownership.
func TestReadQuotaReturnsAfterDrain(t *testing.T) {
	fixture := newFixture(t, fixtureHandlers{catalog: func(_ *protocol.WatchRequest, stream grpc.ServerStreamingServer[protocol.CatalogWatchReply]) error {
		<-stream.Context().Done()
		return stream.Context().Err()
	}})
	client := fixtureClient(t, fixture, Options{Anonymous: true, Plaintext: true, Readers: 1})
	first, cause := client.Subscriber(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	_, cause = client.Reader(testScope())
	requireCode(t, cause, CodeBusy, Unapplied)
	first.Stop()
	if cause := first.Wait(testContext(t)); cause != nil {
		t.Fatal(cause)
	}
	second, cause := client.Subscriber(testScope())
	if cause != nil {
		t.Fatalf("drained role retained quota: %v", cause)
	}
	second.Stop()
	if cause := second.Wait(testContext(t)); cause != nil {
		t.Fatal(cause)
	}
}

// TestStreamContextIsOwned verifies cancellation of a factory-independent read role.
func TestStreamContextIsOwned(t *testing.T) {
	entered, stopped := make(chan struct{}), make(chan struct{})
	fixture := newFixture(t, fixtureHandlers{catalog: func(_ *protocol.WatchRequest, stream grpc.ServerStreamingServer[protocol.CatalogWatchReply]) error {
		close(entered)
		<-stream.Context().Done()
		close(stopped)
		return stream.Context().Err()
	}})
	client := fixtureClient(t, fixture)
	subscriber, cause := client.Subscriber(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	receiveTest(t, entered)
	subscriber.Stop()
	receiveTest(t, stopped)
	if cause := subscriber.Wait(testContext(t)); cause != nil {
		t.Fatal(cause)
	}
	if _, cause := client.Publisher(testScope()); cause != nil {
		t.Fatalf("subscription cancellation closed shared client: %v", cause)
	}
}
