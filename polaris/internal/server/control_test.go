// Verify refusal, cumulative credit and exact paged protocol output at controlled stream boundaries.
//go:build linux && cgo

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"reflect"
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/internal/generated/comet"
	"github.com/eosforge/astra/internal/generated/orbit"
	"github.com/eosforge/astra/internal/generated/polaris"
	"github.com/eosforge/astra/polaris/internal/storage"
)

// TestControl requires literal output and exact ownership after every refusal or successful credit transition.
func TestControl(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string     // Independent protocol boundary with a required native child terminal.
		code codes.Code // Expected public category, except raw cancellation and transport causes.
	}{
		{"next-eof", codes.Canceled},
		{"inventory-duplicate", codes.InvalidArgument},
		{"send-cancelled", codes.Canceled},
		{"send-oversize", codes.ResourceExhausted},
		{"control-nil", codes.Unauthenticated},
		{"control-replaced", codes.Unauthenticated},
		{"budget-invalid", codes.InvalidArgument},
		{"budget-progress", codes.OK},
		{"manifest-paged", codes.OK},
		{"manifest-refused", codes.Unavailable},
		{"update-erase", codes.OK},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			state, wire, system := recovery(t, 16, 2)
			scope := storage.Scope{Sector: "s", Spectrum: "p"}
			position := &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}
			ack := func(version uint64) incoming {
				return incoming{packet: &polaris.Packet{Body: &polaris.Packet_Acknowledged{Acknowledged: &polaris.Position{Scope: position, Version: version}}}}
			}
			var changes []storage.Change
			if test.name == "update-erase" {
				if _, err := system.store.Commit(t.Context(), scope, storage.Change{Version: 3, Key: "key", Erase: true}); err != nil {
					t.Fatal(err)
				}
				if _, err := system.store.CommitBatch(t.Context(), scope, 4, []storage.Change{{Key: "empty", Value: []byte{}}, {Key: "absent", Erase: true}}); err != nil {
					t.Fatal(err)
				}
				replay, err := system.store.Since(t.Context(), scope, 2)
				if err != nil || len(replay.Changes) != 2 {
					t.Fatal("native history did not preserve both commits", err)
				}
				changes = replay.Changes
			}
			before, err := system.store.Load(t.Context(), scope)
			if err != nil {
				t.Fatal(err)
			}
			var expected []*polaris.Packet
			var cause error
			switch test.name {
			case "next-eof":
				state.input <- incoming{err: io.EOF}
				var packet *polaris.Packet
				packet, err = state.next()
				if packet != nil {
					t.Fatal("EOF produced a protocol frame")
				}
			case "inventory-duplicate":
				state.input <- incoming{packet: &polaris.Packet{Body: &polaris.Packet_Inventory{Inventory: &polaris.Inventory{Complete: true, Positions: []*polaris.Position{{Scope: position, Version: 1}, {Scope: position, Version: 2}}}}}}
				var inventory map[storage.Scope]storage.Version
				inventory, err = state.inventory()
				if inventory != nil {
					t.Fatal("rejected inventory published a partial installation map")
				}
			case "send-cancelled":
				ctx, cancel := context.WithCancel(state.ctx)
				cancel()
				state.ctx, cause = ctx, context.Canceled
				err = state.send(&polaris.Packet{Body: &polaris.Packet_Ready{Ready: &comet.Empty{}}})
			case "send-oversize":
				packet := &polaris.Packet{Body: &polaris.Packet_Snapshot{Snapshot: &polaris.Snapshot{Scope: position, Version: proto.Uint64(2), Complete: true, Entries: []*comet.AlmanacChange{{Key: "key", Action: &comet.AlmanacChange_Value{Value: make([]byte, 1024)}}}}}}
				if proto.Size(packet) <= state.maximum {
					t.Fatal("fixture does not exceed the negotiated frame bound")
				}
				err = state.send(packet)
			case "control-nil":
				err = state.control(nil)
			case "control-replaced":
				member := proto.Clone(state.remote).(*orbit.Member)
				member.Epoch++
				member.Id = []byte("replacement")
				hello := system.issuer.sign(member)
				if _, err := system.node.Directory().Verify(hello.Admission, hello.AdmissionSignature, orbit.Role_ROLE_STAR); err != nil {
					t.Fatal(err)
				}
				err = state.control(ack(2).packet)
			case "budget-invalid":
				state.input <- ack(3)
				err = state.budget(8 << 20)
			case "budget-progress":
				// The first ACK confirms no new credit. The producer cannot enqueue the second until it is consumed.
				state.input <- ack(1)
				ctx, cancel := context.WithCancel(state.ctx)
				state.ctx = ctx
				done := make(chan struct{})
				go func() {
					defer close(done)
					select {
					case state.input <- ack(2):
					case <-ctx.Done():
					}
				}()
				t.Cleanup(func() {
					cancel()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Error("ACK producer did not drain")
					}
				})
				err = state.budget(8 << 20)
			case "manifest-paged", "manifest-refused":
				positions := make([]storage.Position, 24)
				for index := range positions {
					positions[index] = storage.Position{Scope: storage.Scope{Sector: "s", Spectrum: fmt.Sprintf("%080d", index)}, Version: 2}
				}
				// These fixed-length legal names fit ten per 1 KiB frame. Expected pages never inspect emitted output.
				for _, span := range [][2]int{{0, 10}, {10, 20}, {20, 24}} {
					page := &polaris.Inventory{Complete: span[1] == 24}
					for index := span[0]; index < span[1]; index++ {
						page.Positions = append(page.Positions, &polaris.Position{Scope: &comet.Scope{Sector: []byte("s"), Spectrum: []byte(fmt.Sprintf("%080d", index))}, Version: 2})
					}
					expected = append(expected, &polaris.Packet{Body: &polaris.Packet_Plan{Plan: page}})
				}
				if test.name == "manifest-refused" {
					cause = status.Error(codes.Unavailable, "controlled second-page refusal")
					attempts := 0
					conversation := &dialogue{capture: *wire, step: func(*polaris.Packet) error {
						attempts++
						if attempts == 2 {
							return cause
						}
						return nil
					}}
					state.wire, wire = conversation, &conversation.capture
					expected = expected[:1]
					err = state.manifest(positions)
					if attempts != 2 {
						t.Fatal("manifest failed to stop at the refused page", attempts)
					}
				} else {
					err = state.manifest(positions)
				}
			case "update-erase":
				expected = []*polaris.Packet{{Body: &polaris.Packet_Updates{Updates: &polaris.Updates{Scope: position, Patches: []*polaris.Patch{
					{Version: 3, Change: &comet.AlmanacChange{Key: "key", Action: &comet.AlmanacChange_Erase{Erase: &comet.Empty{}}}},
					{Version: 4, Changes: []*comet.AlmanacChange{{Key: "empty", Action: &comet.AlmanacChange_Value{Value: []byte{}}}, {Key: "absent", Action: &comet.AlmanacChange_Erase{Erase: &comet.Empty{}}}}},
				}}}}}
				err = state.update(scope, changes)
			}
			if cause != nil {
				if !errors.Is(err, cause) {
					t.Fatal("control boundary lost its exact terminal cause", err, cause)
				}
			} else if status.Code(err) != test.code {
				t.Fatal("control boundary changed its refusal category", err, test.code)
			}
			if len(wire.packets) != len(expected) {
				t.Fatal("wrong successful output count", len(wire.packets), len(expected))
			}
			for index, packet := range wire.packets {
				if proto.Size(packet) > state.maximum || !proto.Equal(packet, expected[index]) {
					t.Fatal("encoded output changed its bounds, ordering, action or completion", index)
				}
			}
			sent, installed := map[storage.Scope]storage.Version{scope: 2}, map[storage.Scope]storage.Version{scope: 1}
			credits, charged := []credit{{scope: scope, version: 2, bytes: 37}}, int64(37)
			if test.name == "budget-progress" {
				installed[scope], credits, charged = 2, nil, 0
			} else if test.name == "update-erase" {
				cost := int64(proto.Size(expected[0]))
				sent[scope], charged = 4, charged+cost
				credits = append(credits, credit{scope: scope, version: 4, bytes: cost})
			}
			if !maps.Equal(state.sent, sent) || !maps.Equal(state.installed, installed) || !slices.Equal(state.credits, credits) || state.bytes != charged || !state.ready {
				t.Fatal("control outcome invented progress or released unconfirmed credit")
			}
			if len(state.input) != 0 || state.deadline.Load() != nil || system.streams.authority.cache.used != 0 || len(system.streams.authority.cache.entries) != 0 {
				t.Fatal("completed boundary retained input, deadline or snapshot ownership")
			}
			after, err := system.store.Load(t.Context(), scope)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("outbound control changed authoritative contents", err)
			}
		})
	}
}
