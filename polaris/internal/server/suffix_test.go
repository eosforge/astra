// Verify complete ordered suffix delivery across scope, page and retained-history boundaries.
//go:build linux && cgo

package server

import (
	"context"
	"errors"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/internal/generated/comet"
	"github.com/eosforge/astra/internal/generated/polaris"
	"github.com/eosforge/astra/polaris/internal/storage"
)

// TestSuffix checks literal transcripts and durable contents without deriving expected frames from received output.
func TestSuffix(t *testing.T) {
	t.Parallel()
	t.Run("grouped", func(t *testing.T) {
		system := environment(t, storage.Default())
		scopes := []storage.Scope{{Sector: "s", Spectrum: "p"}, {Sector: "s", Spectrum: "q"}}
		for _, scope := range scopes {
			if _, err := system.store.Commit(t.Context(), scope, storage.Change{Version: 1, Key: "key", Value: []byte{1}}); err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		wire := &dialogue{capture: capture{ctx: ctx}}
		state := &transfer{owner: system.streams, wire: wire, ctx: ctx, input: make(chan incoming, 1), wake: make(chan struct{}, 1), maximum: 8 << 20, sent: make(map[storage.Scope]storage.Version), installed: make(map[storage.Scope]storage.Version)}
		positions := []*polaris.Position{
			{Scope: &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}, Version: 1},
			{Scope: &comet.Scope{Sector: []byte("s"), Spectrum: []byte("q")}, Version: 1},
		}
		expected := []*polaris.Packet{
			{Body: &polaris.Packet_Hello{Hello: system.node.Hello()}},
			{Body: &polaris.Packet_Plan{Plan: &polaris.Inventory{Complete: true, Positions: positions}}},
		}
		for _, position := range positions {
			expected = append(expected, &polaris.Packet{Body: &polaris.Packet_Snapshot{Snapshot: &polaris.Snapshot{Scope: position.Scope, Version: proto.Uint64(1), Complete: true, Entries: []*comet.AlmanacChange{{Key: "key", Action: &comet.AlmanacChange_Value{Value: []byte{1}}}}}}})
		}
		expected = append(expected, &polaris.Packet{Body: &polaris.Packet_Ready{Ready: &comet.Empty{}}})
		// The independently specified transcript splits 129 adjacent commits at 128, then changes scope.
		for _, segment := range []struct {
			index int // Scope in the fixed input schedule.
			first int // Inclusive first committed version in this expected frame.
			last  int // Inclusive final version; no missing or duplicated patch is allowed.
		}{{0, 2, 129}, {0, 130, 130}, {1, 2, 2}} {
			page := &polaris.Updates{Scope: positions[segment.index].Scope}
			for version := segment.first; version <= segment.last; version++ {
				page.Patches = append(page.Patches, &polaris.Patch{Version: uint64(version), Change: &comet.AlmanacChange{Key: "key", Action: &comet.AlmanacChange_Value{Value: []byte{byte(version)}}}})
			}
			expected = append(expected, &polaris.Packet{Body: &polaris.Packet_Updates{Updates: page}})
		}
		enqueue := func(packet *polaris.Packet) {
			select {
			case state.input <- incoming{packet: packet}:
			default:
				t.Fatal("peer overwrote a pending FIFO control frame")
			}
		}
		wire.step = func(packet *polaris.Packet) error {
			index := len(wire.packets)
			if index >= len(expected) || !proto.Equal(packet, expected[index]) {
				t.Fatal("suffix changed the literal scope, page boundary, patch order or payload", index)
			}
			switch index {
			case 0:
				enqueue(&polaris.Packet{Body: &polaris.Packet_Inventory{Inventory: &polaris.Inventory{Complete: true}}})
			case 2, 3:
				enqueue(&polaris.Packet{Body: &polaris.Packet_Acknowledged{Acknowledged: positions[index-2]}})
			case 4:
				for index, scope := range scopes {
					last := 130
					if index == 1 {
						last = 2
					}
					for version := 2; version <= last; version++ {
						if _, err := system.store.Commit(ctx, scope, storage.Change{Version: storage.Version(version), Key: "key", Value: []byte{byte(version)}}); err != nil {
							t.Fatal(err)
						}
					}
				}
			case 5, 6, 7:
				page := expected[index].GetUpdates()
				enqueue(&polaris.Packet{Body: &polaris.Packet_Acknowledged{Acknowledged: &polaris.Position{Scope: page.Scope, Version: page.Patches[len(page.Patches)-1].Version}}})
				if index == 7 {
					cancel()
				}
			}
			return nil
		}
		enqueue(&polaris.Packet{Body: &polaris.Packet_Hello{Hello: system.star}})
		if err := state.run(); !errors.Is(err, context.Canceled) || len(wire.packets) != len(expected) {
			t.Fatal("suffix did not deliver the complete finite transcript before cancellation", err)
		}
		progress := map[storage.Scope]storage.Version{scopes[0]: 130, scopes[1]: 2}
		if !maps.Equal(state.sent, progress) || !maps.Equal(state.installed, progress) || len(state.credits) != 0 || state.bytes != 0 || len(state.input) != 0 || !state.ready {
			t.Fatal("suffix lost confirmed progress or retained credit after its last ACK")
		}
		if state.deadline.Load() != nil || len(system.streams.active) != 0 || system.streams.authority.cache.used != 0 || len(system.streams.authority.cache.entries) != 0 {
			t.Fatal("suffix retained its phase, identity or snapshot preparation")
		}
		for scope, version := range progress {
			got, err := system.store.Load(t.Context(), scope)
			want := storage.Snapshot{Position: storage.Position{Scope: scope, Version: version}, Records: []storage.Record{{Key: "key", Value: []byte{byte(version)}}}}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("delivery changed the complete durable scope", err)
			}
		}
		listed, err := system.store.List(t.Context())
		if err != nil || !slices.Equal(listed, []storage.Position{{Scope: scopes[0], Version: 130}, {Scope: scopes[1], Version: 2}}) {
			t.Fatal("delivery lost a scope or invented another durable position", err)
		}
		for range 8 {
			feed, err := system.store.Subscribe(16<<20, 1)
			if err != nil {
				t.Fatal("suffix did not return its subscription reservation", err)
			}
			t.Cleanup(feed.Close)
		}
	})
	t.Run("paged", func(t *testing.T) {
		state, _, system := recovery(t, 16, 2)
		scope := storage.Scope{Sector: "s", Spectrum: "p"}
		wire := &dialogue{capture: capture{ctx: state.ctx}}
		state.wire = wire
		var expected []*polaris.Packet
		for index, value := range []string{strings.Repeat("a", 600), strings.Repeat("b", 600)} {
			version := storage.Version(index + 3)
			if _, err := system.store.Commit(t.Context(), scope, storage.Change{Version: version, Key: "key", Value: []byte(value)}); err != nil {
				t.Fatal(err)
			}
			expected = append(expected, &polaris.Packet{Body: &polaris.Packet_Updates{Updates: &polaris.Updates{Scope: &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}, Patches: []*polaris.Patch{{Version: uint64(version), Change: &comet.AlmanacChange{Key: "key", Action: &comet.AlmanacChange_Value{Value: []byte(value)}}}}}}})
		}
		wire.step = func(packet *polaris.Packet) error {
			index := len(wire.packets)
			if index >= len(expected) || !proto.Equal(packet, expected[index]) {
				t.Fatal("paged suffix changed complete patch content or emitted an extra frame", index)
			}
			if index == 1 && (state.installed[scope] != 3 || len(state.credits) != 0 || state.bytes != 0) {
				t.Fatal("next page bypassed successful acknowledgment draining")
			}
			state.input <- incoming{packet: &polaris.Packet{Body: &polaris.Packet_Acknowledged{Acknowledged: &polaris.Position{Scope: expected[index].GetUpdates().Scope, Version: uint64(index + 3)}}}}
			return nil
		}
		if err := state.synchronize(storage.Position{Scope: scope, Version: 4}); err != nil || len(wire.packets) != 2 || state.sent[scope] != 4 || state.installed[scope] != 3 || len(state.input) != 1 {
			t.Fatal("paged history did not preserve sent versus confirmed progress", err)
		}
		if err := state.drain(); err != nil || state.installed[scope] != 4 || len(state.credits) != 0 || state.bytes != 0 || state.deadline.Load() != nil {
			t.Fatal("final page acknowledgment retained delivery resources", err)
		}
		got, err := system.store.Load(t.Context(), scope)
		want := storage.Snapshot{Position: storage.Position{Scope: scope, Version: 4}, Records: []storage.Record{{Key: "key", Value: []byte(strings.Repeat("b", 600))}}}
		if err != nil || !reflect.DeepEqual(got, want) || system.streams.authority.cache.used != 0 {
			t.Fatal("paged history changed durable contents or retained preparation resources", err)
		}
	})
	t.Run("history", func(t *testing.T) {
		state, wire, system := recovery(t, 1, 3)
		scope := storage.Scope{Sector: "s", Spectrum: "p"}
		if _, err := system.store.Since(t.Context(), scope, 1); !errors.Is(err, storage.ErrHistory) {
			t.Fatal("fixture did not establish a real retained-history gap", err)
		}
		state.sent[scope], state.credits, state.bytes = 1, nil, 0
		state.charge(scope, 1, 37)
		if err := state.synchronize(storage.Position{Scope: scope, Version: 3}); err != nil {
			t.Fatal("retained-history gap did not recover through a snapshot", err)
		}
		expected := &polaris.Packet{Body: &polaris.Packet_Snapshot{Snapshot: &polaris.Snapshot{Scope: &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}, Version: proto.Uint64(3), Complete: true, Entries: []*comet.AlmanacChange{{Key: "key", Action: &comet.AlmanacChange_Value{Value: []byte{3}}}}}}}
		if len(wire.packets) != 1 || !proto.Equal(wire.packets[0], expected) || state.sent[scope] != 3 || state.installed[scope] != 1 || len(state.credits) != 2 {
			t.Fatal("history gap invented a patch, installed progress or incomplete snapshot")
		}
		if err := state.control(&polaris.Packet{Body: &polaris.Packet_Acknowledged{Acknowledged: &polaris.Position{Scope: expected.GetSnapshot().Scope, Version: 3}}}); err != nil || state.installed[scope] != 3 || len(state.credits) != 0 || state.bytes != 0 || state.deadline.Load() != nil {
			t.Fatal("fallback acknowledgment retained delivery resources", err)
		}
		got, err := system.store.Load(t.Context(), scope)
		want := storage.Snapshot{Position: storage.Position{Scope: scope, Version: 3}, Records: []storage.Record{{Key: "key", Value: []byte{3}}}}
		if err != nil || !reflect.DeepEqual(got, want) || system.streams.authority.cache.used != 0 || len(system.streams.authority.cache.entries) != 0 {
			t.Fatal("fallback changed the durable snapshot or leaked its reservation", err)
		}
	})
}
