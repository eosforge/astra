// Verify timer-driven installation recovery and incomplete-assessment expiry through the native TLS stream.
//go:build linux && cgo

package server

import (
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/internal/generated/comet"
	"github.com/eosforge/astra/internal/generated/polaris"
	"github.com/eosforge/astra/polaris/internal/storage"
)

// TestPeriodic retains one real connection through lost acknowledgement, replay and an incomplete next assessment.
func TestPeriodic(t *testing.T) {
	t.Parallel()
	system := environment(t, storage.Default())
	scope := storage.Scope{Sector: "s", Spectrum: "p"}
	position := &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}
	commit := func(version storage.Version, value string) {
		t.Helper()
		if _, err := system.store.Commit(t.Context(), scope, storage.Change{Version: version, Key: "key", Value: []byte(value)}); err != nil {
			t.Fatal("controlled durable commit failed", err)
		}
	}
	commit(1, "before")
	// Three production assessment periods are at most 105 seconds; this outer budget detects a missing transition.
	// No production deadline, random jitter source or real timer is replaced by the fixture.
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()
	started := time.Now()
	wire, err := polaris.NewAlmanacClient(system.channel).Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	send := func(packet *polaris.Packet) {
		t.Helper()
		if err := wire.Send(packet); err != nil {
			t.Fatal("peer could not send the required control frame", err)
		}
	}
	expect := func(expected *polaris.Packet) {
		t.Helper()
		packet, err := wire.Recv()
		if err != nil || !proto.Equal(packet, expected) {
			t.Fatal("stream changed the literal frame sequence or payload", packet, expected, err)
		}
	}
	acknowledge := func(version uint64) {
		t.Helper()
		send(&polaris.Packet{Body: &polaris.Packet_Acknowledged{Acknowledged: &polaris.Position{Scope: position, Version: version}}})
	}
	update := func(version uint64, value string) *polaris.Packet {
		return &polaris.Packet{Body: &polaris.Packet_Updates{Updates: &polaris.Updates{Scope: position, Patches: []*polaris.Patch{{Version: version, Change: &comet.AlmanacChange{Key: "key", Action: &comet.AlmanacChange_Value{Value: []byte(value)}}}}}}}
	}
	send(&polaris.Packet{Body: &polaris.Packet_Hello{Hello: system.star}})
	send(&polaris.Packet{Body: &polaris.Packet_Inventory{Inventory: &polaris.Inventory{Complete: true}}})
	expect(&polaris.Packet{Body: &polaris.Packet_Hello{Hello: system.node.Hello()}})
	expect(&polaris.Packet{Body: &polaris.Packet_Plan{Plan: &polaris.Inventory{Complete: true, Positions: []*polaris.Position{{Scope: position, Version: 1}}}}})
	expect(&polaris.Packet{Body: &polaris.Packet_Snapshot{Snapshot: &polaris.Snapshot{Scope: position, Version: proto.Uint64(1), Complete: true, Entries: []*comet.AlmanacChange{{Key: "key", Action: &comet.AlmanacChange_Value{Value: []byte("before")}}}}}})
	acknowledge(1)
	expect(&polaris.Packet{Body: &polaris.Packet_Ready{Ready: &comet.Empty{}}})

	// Version two is delivered but neither installed nor acknowledged by this peer.
	commit(2, "after")
	expect(update(2, "after"))
	expect(&polaris.Packet{Body: &polaris.Packet_Probe{Probe: &comet.Empty{}}})
	if elapsed := time.Since(started); elapsed < 30*time.Second {
		t.Fatal("assessment occurred before the first production interval", elapsed)
	}
	t.Log("first native assessment", time.Since(started))
	send(&polaris.Packet{Body: &polaris.Packet_Inventory{Inventory: &polaris.Inventory{Complete: true, Positions: []*polaris.Position{{Scope: position, Version: 1}}}}})
	// Recovery must repeat exactly the missing patch on this connection, without another Ready or full snapshot.
	expect(update(2, "after"))
	acknowledge(2)
	commit(3, "latest")
	expect(update(3, "latest"))
	expect(&polaris.Packet{Body: &polaris.Packet_Probe{Probe: &comet.Empty{}}})
	t.Log("second native assessment", time.Since(started))

	// A partial inventory cannot be published as actual state or start recovery; the following period must refuse overlap.
	send(&polaris.Packet{Body: &polaris.Packet_Inventory{Inventory: &polaris.Inventory{Positions: []*polaris.Position{{Scope: position, Version: 2}}}}})
	packet, err := wire.Recv()
	if packet != nil || status.Code(err) != codes.DeadlineExceeded || ctx.Err() != nil {
		t.Fatal("incomplete assessment did not terminate at the server boundary", packet, err, ctx.Err())
	}
	t.Log("incomplete native assessment expired", time.Since(started))
	cancel()
	system.streams.Wait()

	// Native worker retirement precedes resource inspection; a cancellation signal alone is insufficient.
	system.streams.mutex.Lock()
	active := len(system.streams.active)
	system.streams.mutex.Unlock()
	cache := system.streams.authority.cache
	if active != 0 || len(system.streams.slots) != 0 || cache.used != 0 || len(cache.entries) != 0 {
		t.Fatal("periodic termination retained an identity, receiver or snapshot reservation")
	}
	snapshot, err := system.store.Load(t.Context(), scope)
	expected := storage.Snapshot{Position: storage.Position{Scope: scope, Version: 3}, Records: []storage.Record{{Key: "key", Value: []byte("latest")}}}
	if err != nil || !reflect.DeepEqual(snapshot, expected) {
		t.Fatal("assessment replay or expiry changed durable authority state", snapshot, err)
	}
	positions, err := system.store.List(t.Context())
	if err != nil || !slices.Equal(positions, []storage.Position{{Scope: scope, Version: 3}}) {
		t.Fatal("assessment created or lost a durable scope", positions, err)
	}
	// Keep all reservations live together; a leaked stream subscription must make the last acquisition fail.
	for range 8 {
		feed, err := system.store.Subscribe(16<<20, 1)
		if err != nil {
			t.Fatal("periodic termination retained a feed reservation", err)
		}
		t.Cleanup(feed.Close)
	}
}
