// Exercise retained public pools, foreign selections and bounded stream-history repair.
package comet

import (
	"sync/atomic"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// TestPoolSelectionAndStop preserves retained values, permits lock-free visitors and rejects foreign owners.
func TestPoolSelectionAndStop(t *testing.T) {
	first, second := fixtureID(), fixtureID()
	second[0]++
	fixture := newFixture(t, fixtureHandlers{ephemeris: func(_ *protocol.WatchRequest, stream grpc.ServerStreamingServer[protocol.EphemerisWatchReply]) error {
		if cause := stream.Send(&protocol.EphemerisWatchReply{
			Mode: protocol.Mode_MODE_RESET, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(1),
			Changes: []*protocol.EphemerisChange{
				{Uuid: first, Action: &protocol.EphemerisChange_Record_{Record: &protocol.EphemerisChange_Record{Attr: []byte("first-attr"), Data: []byte("first-data")}}},
				{Uuid: second, Action: &protocol.EphemerisChange_Record_{Record: &protocol.EphemerisChange_Record{Attr: []byte("second-attr"), Data: []byte("second-data")}}},
			},
		}); cause != nil {
			return cause
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}})
	client := fixtureClient(t, fixture)
	observer, cause := client.Observer(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	other, cause := client.Observer(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	var retained Pool
	var selected *Item
	awaitCondition(t, func() bool {
		selected, cause = observer.One(func(pool Pool) *Item { retained = pool; return pool.Find(string(first)) })
		return cause == nil && selected != nil
	})
	awaitCondition(t, func() bool {
		item, cause := other.One(func(pool Pool) *Item { return pool.Find(string(second)) })
		return cause == nil && item != nil
	})
	if retained.Len() != 2 || retained.Find("absent") != nil || selected.ID() != string(first) {
		t.Fatal("Pool did not expose the complete fixed identity set")
	}
	retained.Range(nil)
	visited := map[string]Record{}
	retained.Range(func(item *Item) bool {
		record := item.Record()
		visited[item.ID()] = record
		copy := record.Data.Bytes()
		copy[0] = '!'
		if cause := item.Update([]byte("local-estimate")); cause != nil {
			t.Fatal(cause)
		}
		return true
	})
	if len(visited) != 2 || visited[string(first)].Attr.String() != "first-attr" || visited[string(first)].Data.String() != "first-data" ||
		visited[string(second)].Attr.String() != "second-attr" || visited[string(second)].Data.String() != "second-data" ||
		retained.Find(string(first)).Record().Data.String() != "first-data" {
		t.Fatal("visitor mutation changed the retained pool or authoritative content")
	}
	count := 0
	retained.Range(func(*Item) bool { count++; return false })
	if count != 1 {
		t.Fatal("Range ignored early termination")
	}
	func() {
		defer func() {
			if caught := recover(); caught != "visitor" {
				t.Fatalf("synchronous Range panic was swallowed: %v", caught)
			}
		}()
		retained.Range(func(*Item) bool { panic("visitor") })
	}()
	requireCode(t, selected.Update(make([]byte, maxPayload+1)), CodeInput, Unapplied)
	_, cause = other.One(nil)
	requireCode(t, cause, CodeInput, Unapplied)
	_, cause = other.One(func(Pool) *Item { return selected })
	requireCode(t, cause, CodeInput, Unapplied)
	_, cause = observer.One(func(pool Pool) *Item { observer.Stop(); return pool.Find(string(first)) })
	requireCode(t, cause, CodeClosed, Unapplied)
	_, cause = observer.One(func(pool Pool) *Item { return pool.Find(string(first)) })
	requireCode(t, cause, CodeClosed, Unapplied)
	requireCode(t, selected.Update(nil), CodeClosed, Unapplied)
	if cause := observer.Wait(testContext(t)); cause != nil {
		t.Fatal(cause)
	}
	if selected.Record().Data.String() != "first-data" || retained.Len() != 2 || retained.Find(string(second)).Record().Data.String() != "second-data" {
		t.Fatal("explicit Stop invalidated retained records or pool")
	}
	item, cause := other.One(func(pool Pool) *Item { return pool.Find(string(first)) })
	if cause != nil || item == nil || item.Record().Data.String() != "first-data" {
		t.Fatal("one Observer's local estimates or Stop changed its independent peer")
	}
	other.Stop()
	if cause := other.Wait(testContext(t)); cause != nil {
		t.Fatal(cause)
	}
}

// TestRepeatedHistoryGapStopsRepair permits one fresh baseline but never retries repeated absent-Attr corruption forever.
func TestRepeatedHistoryGapStopsRepair(t *testing.T) {
	calls := atomic.Int32{}
	requests := make(chan *protocol.WatchRequest, 3)
	fixture := newFixture(t, fixtureHandlers{ephemeris: func(request *protocol.WatchRequest, stream grpc.ServerStreamingServer[protocol.EphemerisWatchReply]) error {
		call := calls.Add(1)
		recordTest(t, requests, request)
		if call > 2 {
			t.Error("repeated history corruption reopened a third stream")
			<-stream.Context().Done()
			return stream.Context().Err()
		}
		if cause := stream.Send(&protocol.EphemerisWatchReply{
			Mode: protocol.Mode_MODE_RESET, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(uint64(call)),
			Changes: []*protocol.EphemerisChange{{Uuid: fixtureID(), Action: &protocol.EphemerisChange_Record_{
				Record: &protocol.EphemerisChange_Record{Attr: []byte("fixed"), Data: []byte("complete")},
			}}},
		}); cause != nil {
			return cause
		}
		missing := fixtureID()
		missing[0]++
		if cause := stream.Send(&protocol.EphemerisWatchReply{
			Mode: protocol.Mode_MODE_APPLY, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(uint64(call + 1)),
			Changes: []*protocol.EphemerisChange{{Uuid: missing, Action: &protocol.EphemerisChange_Data{Data: []byte("missing-attr")}}},
		}); cause != nil {
			return cause
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}})
	client := fixtureClient(t, fixture)
	observer, cause := client.Observer(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	first, repair := receiveTest(t, requests), receiveTest(t, requests)
	if first.Version != nil || repair.Version != nil || string(repair.Instance) != "" {
		t.Fatal("one allowed repair did not request a fresh baseline")
	}
	awaitCondition(t, func() bool {
		_, cause := observer.One(func(pool Pool) *Item { return pool.Find(string(fixtureID())) })
		failure, ok := cause.(*Error)
		return ok && failure.Code == CodeProtocol
	})
	if calls.Load() != 2 {
		t.Fatal("repeated history failure exceeded its one-repair budget")
	}
	observer.Stop()
	if cause := observer.Wait(testContext(t)); cause != nil {
		t.Fatal(cause)
	}
}
