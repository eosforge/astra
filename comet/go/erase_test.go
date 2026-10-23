// Verify authoritative Ephemeris deletion and explicit erase presence without mutating retained views.
package comet

import (
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// TestObserverAuthoritativeErase removes a live candidate through the actual wire
// while retained pools/items stay readable and obsolete estimates cannot revive it.
func TestObserverAuthoritativeErase(t *testing.T) {
	t.Parallel()
	erase := make(chan struct{})
	fixture := newFixture(t, fixtureHandlers{ephemeris: func(_ *protocol.WatchRequest, stream grpc.ServerStreamingServer[protocol.EphemerisWatchReply]) error {
		if cause := stream.Send(&protocol.EphemerisWatchReply{
			Mode: protocol.Mode_MODE_RESET, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(1),
			Changes: []*protocol.EphemerisChange{{Uuid: fixtureID(), Action: &protocol.EphemerisChange_Record_{
				Record: &protocol.EphemerisChange_Record{Attr: []byte("fixed"), Data: []byte("initial")},
			}}},
		}); cause != nil {
			return cause
		}
		select {
		case <-erase:
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
		if cause := stream.Send(&protocol.EphemerisWatchReply{
			Mode: protocol.Mode_MODE_APPLY, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(2),
			Changes: []*protocol.EphemerisChange{{Uuid: fixtureID(), Action: &protocol.EphemerisChange_Erase{Erase: &protocol.Empty{}}}},
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
	var initial Pool // Retained before any local estimate or later authoritative change.
	var item *Item   // The original selection must become obsolete after deletion.
	awaitCondition(t, func() bool {
		item, cause = observer.One(func(pool Pool) *Item {
			initial = pool
			return pool.Find(string(fixtureID()))
		})
		return cause == nil && item != nil
	})
	if cause := item.Update([]byte("estimate")); cause != nil {
		t.Fatal(cause)
	}
	var estimated Pool // Captured after the local estimate, with its independent immutable root.
	selected, cause := observer.One(func(pool Pool) *Item {
		estimated = pool
		return pool.Find(string(fixtureID()))
	})
	if cause != nil || selected == nil || selected.Record().Data.String() != "estimate" {
		t.Fatalf("local estimate unavailable before erase: %v, %v", selected, cause)
	}
	close(erase)
	awaitCondition(t, func() bool {
		size := -1
		selected, cause = observer.One(func(pool Pool) *Item {
			size = pool.Len()
			return pool.Find(string(fixtureID()))
		})
		return cause == nil && size == 0 && selected == nil
	})
	if initial.Len() != 1 || initial.Find(string(fixtureID())).Record().Data.String() != "initial" ||
		estimated.Len() != 1 || estimated.Find(string(fixtureID())).Record().Data.String() != "estimate" ||
		item.Record().Data.String() != "estimate" || item.Record().Attr.String() != "fixed" {
		t.Fatal("authoritative erase mutated a retained pool, item or attribute")
	}
	requireCode(t, item.Update([]byte("resurrect")), CodeObsolete, Unapplied)
	selected, cause = observer.One(func(pool Pool) *Item { return pool.Find(string(fixtureID())) })
	if cause != nil || selected != nil {
		t.Fatal("obsolete local update revived an erased candidate")
	}
}

// TestErasePresencePreservesBaseline checks generated-message adapter boundaries
// separately from wire reachability: a nil erase payload is not explicit presence.
func TestErasePresencePreservesBaseline(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string                              // Business domain with distinct wire change types.
		kind    domain                              // Existing protocol assembler domain.
		key     string                              // Valid text key or fixed binary UUID.
		message func(*protocol.Empty) proto.Message // Same complete apply with only erase presence changed.
	}{
		{"almanac", almanac, "stable", func(presence *protocol.Empty) proto.Message {
			return &protocol.AlmanacWatchReply{Mode: protocol.Mode_MODE_APPLY, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(8),
				Changes: []*protocol.AlmanacChange{{Key: "stable", Action: &protocol.AlmanacChange_Erase{Erase: presence}}}}
		}},
		{"catalog", catalog, "stable", func(presence *protocol.Empty) proto.Message {
			return &protocol.CatalogWatchReply{Mode: protocol.Mode_MODE_APPLY, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(8),
				Changes: []*protocol.CatalogChange{{Key: "stable", Action: &protocol.CatalogChange_Erase{Erase: presence}}}}
		}},
		{"ephemeris", ephemeris, string(fixtureID()), func(presence *protocol.Empty) proto.Message {
			return &protocol.EphemerisWatchReply{Mode: protocol.Mode_MODE_APPLY, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(8),
				Changes: []*protocol.EphemerisChange{{Uuid: fixtureID(), Action: &protocol.EphemerisChange_Erase{Erase: presence}}}}
		}},
	}
	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			data := newDraft(emptyTable())
			data.set(testcase.key, &row{data: NewValue([]byte("before")), attr: NewValue([]byte("fixed")), version: 1})
			root := &snapshot{data: data.data, instance: "star-a", version: 7}
			assembly := testBatch(testcase.kind, root)
			next, failure := assembly.accept(decodePage(testcase.message(nil)))
			if next != nil || failure == nil || failure.Code != CodeProtocol {
				t.Fatal("missing erase payload was accepted as an authoritative deletion")
			}
			assembly.clear()
			next, failure = assembly.accept(decodePage(testcase.message(&protocol.Empty{})))
			if failure != nil || next == nil || next.version != 8 || next.instance != "star-a" || next.data.count != 0 || next.data.find(testcase.key) != nil {
				t.Fatalf("explicit erase did not commit the prescribed empty v8 view: %v, %v", next, failure)
			}
			if root.version != 7 || root.data.count != 1 || root.data.find(testcase.key).data.String() != "before" || root.data.find(testcase.key).attr.String() != "fixed" {
				t.Fatal("rejected or committed deletion changed a retained baseline")
			}
		})
	}
}
