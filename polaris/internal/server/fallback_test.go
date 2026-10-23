// Verify whole-suffix snapshot fallback without splitting an oversized atomic commit or reusing an older pinned target.
//go:build linux && cgo

package server

import (
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/internal/generated/comet"
	"github.com/eosforge/astra/internal/generated/polaris"
	"github.com/eosforge/astra/polaris/internal/storage"
)

// TestFallback requires a snapshot of the entire pending suffix, including a commit after the oversized batch.
func TestFallback(t *testing.T) {
	t.Parallel()
	state, wire, system := recovery(t, 16, 1)
	scope := storage.Scope{Sector: "s", Spectrum: "p"}
	if _, err := system.store.Commit(t.Context(), scope, storage.Change{Version: 2, Key: "key", Value: []byte("prefix")}); err != nil {
		t.Fatal(err)
	}
	values := []storage.Change{
		{Key: "a", Value: []byte(strings.Repeat("a", 600))},
		{Key: "b", Value: []byte(strings.Repeat("b", 600))},
		{Key: "key", Erase: true},
	}
	if _, err := system.store.CommitBatch(t.Context(), scope, 3, values); err != nil {
		t.Fatal(err)
	}
	cache := system.streams.authority.cache
	held, err := cache.acquire(t.Context(), scope, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer held.release()
	frozen := storage.Snapshot{Position: storage.Position{Scope: scope, Version: 3}, Records: []storage.Record{
		{Key: "a", Value: []byte(strings.Repeat("a", 600))},
		{Key: "b", Value: []byte(strings.Repeat("b", 600))},
	}}
	if !reflect.DeepEqual(*held.Snapshot, frozen) {
		t.Fatal("fixture did not pin the complete older atomic commit")
	}
	if _, err := system.store.Commit(t.Context(), scope, storage.Change{Version: 4, Key: "tail", Value: []byte("end")}); err != nil {
		t.Fatal(err)
	}
	replay, err := system.store.Since(t.Context(), scope, 1)
	if err != nil || len(replay.Changes) != 3 || replay.Version != 4 || replay.Changes[1].Key != "" {
		t.Fatal("fixture did not retain the prefix, atomic batch and later commit", err)
	}
	if err := state.update(scope, replay.Changes); err != nil {
		t.Fatal("oversized atomic suffix did not fall back to a complete snapshot", err)
	}
	position := &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}
	expected := []*polaris.Packet{
		{Body: &polaris.Packet_Snapshot{Snapshot: &polaris.Snapshot{Scope: position, Version: proto.Uint64(4), Entries: []*comet.AlmanacChange{
			{Key: "a", Action: &comet.AlmanacChange_Value{Value: []byte(strings.Repeat("a", 600))}},
		}}}},
		{Body: &polaris.Packet_Snapshot{Snapshot: &polaris.Snapshot{Scope: position, Version: proto.Uint64(4), Complete: true, Entries: []*comet.AlmanacChange{
			{Key: "b", Action: &comet.AlmanacChange_Value{Value: []byte(strings.Repeat("b", 600))}},
			{Key: "tail", Action: &comet.AlmanacChange_Value{Value: []byte("end")}},
		}}}},
	}
	if len(wire.packets) != len(expected) {
		t.Fatal("snapshot fallback leaked a buffered patch or duplicated the pending suffix")
	}
	for index, packet := range expected {
		if !proto.Equal(packet, wire.packets[index]) {
			t.Fatal("snapshot fallback lost the atomic content, later commit or final completion", index)
		}
	}
	if state.sent[scope] != 4 || state.installed[scope] != 1 || len(state.credits) != 2 || state.deadline.Load() != nil {
		t.Fatal("snapshot fallback lost sent progress or invented installed progress")
	}
	if err := state.control(&polaris.Packet{Body: &polaris.Packet_Acknowledged{Acknowledged: &polaris.Position{Scope: position, Version: 4}}}); err != nil || state.installed[scope] != 4 || len(state.credits) != 0 || state.bytes != 0 {
		t.Fatal("snapshot fallback failed to release its acknowledged suffix", err)
	}
	if cache.used != cache.reserve || len(cache.entries) != 1 || held.entry.references != 1 || !reflect.DeepEqual(*held.Snapshot, frozen) {
		t.Fatal("snapshot fallback damaged another reader or retained its own preparation")
	}
	held.release()
	if cache.used != 0 || len(cache.entries) != 0 {
		t.Fatal("snapshot fallback retained unowned preparation after the last reader")
	}
	got, err := system.store.Load(t.Context(), scope)
	want := storage.Snapshot{Position: storage.Position{Scope: scope, Version: 4}, Records: append(frozen.Records, storage.Record{Key: "tail", Value: []byte("end")})}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("snapshot fallback changed durable authority contents", err)
	}
}
