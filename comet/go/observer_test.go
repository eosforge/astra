// Verify local estimate CAS and priority of authoritative replacement.
package comet

import (
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// TestObserverLocalCAS checks estimate conflict, authoritative replacement and explicit stop.
func TestObserverLocalCAS(t *testing.T) {
	t.Parallel()
	client := &Client{options: Options{Bytes: 1 << 20}}
	watch := &watching{life: newLifecycle(client, true), domain: ephemeris, estimates: emptyTable(), phase: Ready, options: ReadOptions{Bytes: 1 << 20, Records: 32}}
	defer watch.life.cancel()
	id := string(fixtureID())
	root := newDraft(emptyTable())
	authority := &row{attr: NewValue([]byte("fixed")), data: NewValue([]byte("10"))}
	root.set(id, authority)
	watch.root = &snapshot{data: root.data, instance: "star-a", version: 1}
	pool := Pool{owner: watch, root: watch.root, estimates: watch.estimates}
	first, competitor := pool.Find(id), pool.Find(id)
	if cause := first.Update([]byte("9")); cause != nil {
		t.Fatal(cause)
	}
	requireCode(t, competitor.Update([]byte("8")), CodeConflict, Unapplied)
	if first.Record().Data.String() != "9" || pool.Find(id).Record().Data.String() != "10" || authority.data.String() != "10" {
		t.Fatal("local adjustment mutated a retained pool or authority")
	}
	newAuthority := newDraft(watch.root.data)
	newAuthority.set(id, &row{attr: authority.attr, data: NewValue([]byte("20"))})
	watch.root = &snapshot{data: newAuthority.data, version: 2}
	requireCode(t, first.Update([]byte("7")), CodeObsolete, Unapplied)
	watch.life.cancel()
	requireCode(t, competitor.Update(nil), CodeClosed, Unapplied)
}

// TestObserverDataOnlyOverridesEstimate uses actual wire pages to preserve fixed
// Attr, replace a local estimate, and reject a later illegal Attr replacement.
func TestObserverDataOnlyOverridesEstimate(t *testing.T) {
	replace, corrupt := make(chan struct{}), make(chan struct{})
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
		case <-replace:
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
		if cause := stream.Send(&protocol.EphemerisWatchReply{
			Mode: protocol.Mode_MODE_APPLY, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(2),
			Changes: []*protocol.EphemerisChange{{Uuid: fixtureID(), Action: &protocol.EphemerisChange_Data{Data: []byte("authority")}}},
		}); cause != nil {
			return cause
		}
		select {
		case <-corrupt:
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
		return stream.Send(&protocol.EphemerisWatchReply{
			Mode: protocol.Mode_MODE_APPLY, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(3),
			Changes: []*protocol.EphemerisChange{{Uuid: fixtureID(), Action: &protocol.EphemerisChange_Record_{
				Record: &protocol.EphemerisChange_Record{Attr: []byte("changed"), Data: []byte("invalid")},
			}}},
		})
	}})
	client := fixtureClient(t, fixture)
	observer, cause := client.Observer(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	var original *Item // Selected only after a complete authoritative baseline.
	awaitCondition(t, func() bool {
		original, cause = observer.One(func(pool Pool) *Item { return pool.Find(string(fixtureID())) })
		return cause == nil && original != nil
	})
	if cause := original.Update([]byte("estimate")); cause != nil {
		t.Fatal(cause)
	}
	close(replace)
	var authoritative *Item // Retained separately to check failed-page isolation.
	awaitCondition(t, func() bool {
		authoritative, cause = observer.One(func(pool Pool) *Item { return pool.Find(string(fixtureID())) })
		return cause == nil && authoritative != nil && authoritative.Record().Data.String() == "authority"
	})
	if authoritative.Record().Attr.String() != "fixed" || original.Record().Data.String() != "estimate" {
		t.Fatal("Data-only replacement changed Attr or mutated a retained estimate")
	}
	requireCode(t, original.Update([]byte("late-estimate")), CodeObsolete, Unapplied)
	close(corrupt)
	awaitCondition(t, func() bool {
		observer.watch.mu.Lock()
		defer observer.watch.mu.Unlock()
		return observer.watch.phase == Failed
	})
	_, cause = observer.One(func(Pool) *Item { return nil })
	requireCode(t, cause, CodeProtocol, Unapplied)
	observer.watch.mu.Lock()
	current := observer.watch.root
	observer.watch.mu.Unlock()
	if current.version != 2 || authoritative.Record().Data.String() != "authority" || current.data.find(string(fixtureID())).attr.String() != "fixed" {
		t.Fatal("invalid Attr replacement damaged the last complete authority")
	}
}

// TestObserverEstimateCapacityPreservesSelection rejects a local oversized root
// without consuming the Item's compare-and-swap state or changing authority.
func TestObserverEstimateCapacityPreservesSelection(t *testing.T) {
	t.Parallel()
	client := &Client{options: Options{Bytes: 1 << 20}}
	watch := &watching{
		life: newLifecycle(client, true), domain: ephemeris, estimates: emptyTable(), phase: Ready,
		options: ReadOptions{Bytes: 16384, Records: 32},
	}
	defer watch.life.cancel()
	id := string(fixtureID())
	root := newDraft(emptyTable())
	root.set(id, &row{attr: NewValue([]byte("fixed")), data: NewValue([]byte("authority"))})
	watch.root = &snapshot{data: root.data, instance: "star-a", version: 1}
	item := (Pool{owner: watch, root: watch.root, estimates: watch.estimates}).Find(id)
	requireCode(t, item.Update([]byte(strings.Repeat("x", 16384))), CodeLimit, Unapplied)
	if item.Record().Data.String() != "authority" || watch.estimates.count != 0 || client.used.Load() != 0 {
		t.Fatal("rejected estimate changed selection or leaked an admission reservation")
	}
	if cause := item.Update([]byte("small")); cause != nil || item.Record().Data.String() != "small" {
		t.Fatalf("capacity rejection consumed the next valid local update: %v", cause)
	}
	client.release(watch.charged)
}
