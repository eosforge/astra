// Exercise installation assessment and recovery with native storage and an explicitly controlled send boundary.
//go:build linux && cgo

package server

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/internal/generated/comet"
	"github.com/eosforge/astra/internal/generated/orbit"
	"github.com/eosforge/astra/internal/generated/polaris"
	"github.com/eosforge/astra/polaris/internal/storage"
)

// capture owns copied outbound frames and a selected transport failure; no background I/O is started.
type capture struct {
	ctx     context.Context   // Independent finite scope; cancellation does not imply transport success.
	packets []*polaris.Packet // Complete immutable copies of successful sends in their observed order.
	err     error             // Optional exact send failure, selected before the operation under test.
}

// Context exposes the owned operation scope.
func (capture *capture) Context() context.Context { return capture.ctx }

// Send copies only successful frames, preserving the caller's actual encoded message rather than an inferred outcome.
func (capture *capture) Send(packet *polaris.Packet) error {
	if capture.err != nil {
		return capture.err
	}
	capture.packets = append(capture.packets, proto.Clone(packet).(*polaris.Packet))
	return nil
}

// Recv rejects implicit transport activity; control frames are delivered explicitly by the scenario.
func (*capture) Recv() (*polaris.Packet, error) { return nil, errors.New("unexpected receive") }

// SetHeader rejects unused metadata paths instead of providing a permissive fake.
func (*capture) SetHeader(metadata.MD) error { return errors.New("unexpected header") }

// SendHeader rejects unused metadata paths.
func (*capture) SendHeader(metadata.MD) error { return errors.New("unexpected header send") }

// SetTrailer makes an unexpected side effect fail immediately.
func (*capture) SetTrailer(metadata.MD) { panic("unexpected trailer") }

// SendMsg rejects untyped writes outside the tested protocol boundary.
func (*capture) SendMsg(any) error { return errors.New("unexpected untyped send") }

// RecvMsg rejects untyped reads outside the tested protocol boundary.
func (*capture) RecvMsg(any) error { return errors.New("unexpected untyped receive") }

// recovery constructs literal sent/installed facts against a real authority, without waiting for a periodic timer.
func recovery(t *testing.T, history int64, tip storage.Version) (*transfer, *capture, *system) {
	t.Helper()
	limits := storage.Default()
	limits.History = history
	system := environment(t, limits)
	scope := storage.Scope{Sector: "s", Spectrum: "p"}
	for version := storage.Version(1); version <= tip; version++ {
		if _, err := system.store.Commit(t.Context(), scope, storage.Change{Version: version, Key: "key", Value: []byte{byte(version)}}); err != nil {
			t.Fatal(err)
		}
	}
	remote, err := system.node.Directory().Verify(system.star.Admission, system.star.AdmissionSignature, orbit.Role_ROLE_STAR)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	wire := &capture{ctx: ctx}
	state := &transfer{owner: system.streams, remote: remote, wire: wire, ctx: ctx, maximum: 1024, input: make(chan incoming, 1), wake: make(chan struct{}, 1), sent: map[storage.Scope]storage.Version{scope: tip}, installed: map[storage.Scope]storage.Version{scope: 1}, ready: true}
	state.charge(scope, tip, 37)
	return state, wire, system
}

// TestAssessment verifies frozen floors, exact refusals and cumulative credit release under explicit interleavings.
func TestAssessment(t *testing.T) {
	cases := []struct {
		name string     // Independent protocol condition whose child terminal is required by the gate.
		code codes.Code // Expected control result, not a substring of an implementation error.
	}{
		{"freeze", codes.OK},
		{"overlap", codes.DeadlineExceeded},
		{"pending", codes.DeadlineExceeded},
		{"partial", codes.OK},
		{"lost-scope", codes.DataLoss},
		{"lost-version", codes.DataLoss},
		{"ahead", codes.Aborted},
		{"unknown", codes.Aborted},
		{"duplicate", codes.InvalidArgument},
		{"lost-ack", codes.OK},
		{"concurrent-ack", codes.OK},
		{"send-failure", codes.Unavailable},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			state, wire, _ := recovery(t, 16, 2)
			scope := storage.Scope{Sector: "s", Spectrum: "p"}
			if test.name == "send-failure" {
				wire.err = status.Error(codes.Unavailable, "controlled send failure")
				if err := state.assess(); !errors.Is(err, wire.err) || len(wire.packets) != 0 || state.bytes != 37 {
					t.Fatal("failed Probe send was not preserved", err)
				}
				return
			}
			if err := state.assess(); err != nil {
				t.Fatal(err)
			}
			if len(wire.packets) != 1 || !proto.Equal(wire.packets[0], &polaris.Packet{Body: &polaris.Packet_Probe{Probe: &comet.Empty{}}}) {
				t.Fatal("assessment did not emit exactly one Probe")
			}
			if test.name == "freeze" {
				state.sent[scope], state.installed[scope] = 3, 2
				if state.boundary[scope] != 2 || state.floor[scope] != 1 || len(state.probe) != 0 {
					t.Fatal("assessment borrowed mutable progress maps")
				}
				return
			}
			if test.name == "overlap" || test.name == "pending" {
				if test.name == "pending" {
					state.actual, state.probe = map[storage.Scope]storage.Version{}, nil
				}
				if err := state.assess(); status.Code(err) != test.code || len(wire.packets) != 1 {
					t.Fatal("overlapping assessment transmitted another Probe", err)
				}
				return
			}
			page := &polaris.Inventory{Complete: true, Positions: []*polaris.Position{{Scope: &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}, Version: 2}}}
			switch test.name {
			case "partial":
				page.Complete = false
			case "lost-scope":
				page.Positions = nil
			case "lost-version":
				page.Positions[0].Version = 0
			case "ahead":
				page.Positions[0].Version = 3
			case "unknown":
				page.Positions = append(page.Positions, &polaris.Position{Scope: &comet.Scope{Sector: []byte("s"), Spectrum: []byte("other")}, Version: 1})
			case "duplicate":
				page.Positions = append(page.Positions, proto.Clone(page.Positions[0]).(*polaris.Position))
			case "concurrent-ack":
				state.charge(scope, 3, 19)
				ack := &polaris.Position{Scope: page.Positions[0].Scope, Version: 3}
				if err := state.control(&polaris.Packet{Body: &polaris.Packet_Acknowledged{Acknowledged: ack}}); err != nil {
					t.Fatal(err)
				}
				// An older duplicate cannot retract the newer cumulative acknowledgement.
				ack.Version = 2
				if err := state.control(&polaris.Packet{Body: &polaris.Packet_Acknowledged{Acknowledged: ack}}); err != nil || state.installed[scope] != 3 || state.bytes != 0 || len(state.credits) != 0 {
					t.Fatal("older acknowledgement regressed confirmed progress", err)
				}
			}
			err := state.control(&polaris.Packet{Body: &polaris.Packet_Inventory{Inventory: page}})
			if status.Code(err) != test.code || len(wire.packets) != 1 {
				t.Fatal("incorrect inventory category or recursive send", err)
			}
			if test.code != codes.OK {
				if state.actual != nil {
					t.Fatal("invalid assessment published a completed result")
				}
				return
			}
			if test.name == "partial" {
				if state.actual != nil || state.probe[scope] != 2 || state.installed[scope] != 1 || state.bytes != 37 {
					t.Fatal("incomplete inventory advanced installed state or released credits")
				}
				return
			}
			installed := storage.Version(2)
			if test.name == "concurrent-ack" {
				installed = 3
			}
			if state.probe != nil || !reflect.DeepEqual(state.actual, map[storage.Scope]storage.Version{scope: 2}) || state.installed[scope] != installed || state.bytes != 0 || len(state.credits) != 0 {
				t.Fatal("assessment regressed confirmation or retained acknowledged credits")
			}
		})
	}
}

// TestReconciliation checks exact replay or snapshot output while proving recovery never changes authority contents.
func TestReconciliation(t *testing.T) {
	cases := []struct {
		name string     // Literal recovery state, including native retained-history and newly created scope boundaries.
		code codes.Code // Exact terminal category; send substitutions separately require error identity.
	}{
		{"caught-up", codes.OK},
		{"replay", codes.OK},
		{"replay-new-write", codes.OK},
		{"snapshot-gap", codes.OK},
		{"snapshot-absent", codes.OK},
		{"new-scope", codes.OK},
		{"unknown", codes.Aborted},
		{"ahead-authority", codes.Aborted},
		{"ahead-sent", codes.Aborted},
		{"replay-send-failure", codes.Unavailable},
		{"snapshot-send-failure", codes.Unavailable},
		{"cancelled", codes.Canceled},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			history, tip := int64(16), storage.Version(2)
			if test.name == "snapshot-gap" {
				history, tip = 1, 4
			}
			state, wire, system := recovery(t, history, tip)
			scope := storage.Scope{Sector: "s", Spectrum: "p"}
			if test.name == "snapshot-absent" || test.name == "snapshot-send-failure" {
				clear(state.installed)
			}
			if err := state.assess(); err != nil {
				t.Fatal(err)
			}
			wire.packets = nil
			actual := map[storage.Scope]storage.Version{scope: 1}
			var expected []*polaris.Packet
			wireScope := &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}
			switch test.name {
			case "caught-up", "new-scope":
				actual[scope] = 2
			case "snapshot-absent", "snapshot-send-failure":
				clear(actual)
			case "unknown":
				actual[storage.Scope{Sector: "s", Spectrum: "unknown"}] = 1
			case "ahead-authority":
				actual[scope] = 3
				state.sent[scope] = 3
			case "ahead-sent":
				actual[scope] = 2
				state.sent[scope] = 1
			case "replay-new-write":
				if _, err := system.store.Commit(t.Context(), scope, storage.Change{Version: 3, Key: "key", Value: []byte{3}}); err != nil {
					t.Fatal(err)
				}
				tip = 3
			case "cancelled":
				ctx, cancel := context.WithCancel(state.ctx)
				cancel()
				state.ctx = ctx
			}
			if test.name == "new-scope" {
				other := storage.Scope{Sector: "s", Spectrum: "other"}
				if _, err := system.store.Commit(t.Context(), other, storage.Change{Version: 1, Key: "new", Value: []byte("new")}); err != nil {
					t.Fatal(err)
				}
				expected = []*polaris.Packet{{Body: &polaris.Packet_Snapshot{Snapshot: &polaris.Snapshot{Scope: &comet.Scope{Sector: []byte("s"), Spectrum: []byte("other")}, Version: proto.Uint64(1), Complete: true, Entries: []*comet.AlmanacChange{{Key: "new", Action: &comet.AlmanacChange_Value{Value: []byte("new")}}}}}}}
			} else if test.name == "snapshot-gap" || test.name == "snapshot-absent" {
				page := &polaris.Snapshot{
					Scope: wireScope, Version: proto.Uint64(uint64(tip)), Complete: true,
					Entries: []*comet.AlmanacChange{{Key: "key", Action: &comet.AlmanacChange_Value{Value: []byte{byte(tip)}}}},
				}
				expected = []*polaris.Packet{{Body: &polaris.Packet_Snapshot{Snapshot: page}}}
			} else if test.name == "replay" || test.name == "replay-new-write" {
				page := &polaris.Updates{Scope: wireScope}
				for version := storage.Version(2); version <= tip; version++ {
					page.Patches = append(page.Patches, &polaris.Patch{Version: uint64(version), Change: &comet.AlmanacChange{Key: "key", Action: &comet.AlmanacChange_Value{Value: []byte{byte(version)}}}})
				}
				expected = []*polaris.Packet{{Body: &polaris.Packet_Updates{Updates: page}}}
			}
			if test.name == "replay-send-failure" || test.name == "snapshot-send-failure" {
				wire.err = status.Error(codes.Unavailable, "controlled recovery send failure")
			}
			before, err := system.store.Load(t.Context(), scope)
			if err != nil {
				t.Fatal(err)
			}
			err = state.reconcile(actual)
			if status.Code(err) != test.code || wire.err != nil && !errors.Is(err, wire.err) {
				t.Fatal("incorrect recovery result", err)
			}
			if len(wire.packets) != len(expected) {
				t.Fatalf("recovery sent %d frames, want %d", len(wire.packets), len(expected))
			}
			for index, packet := range expected {
				if !proto.Equal(wire.packets[index], packet) {
					t.Fatal("recovery changed scope, ordering, completion, version or payload", index)
				}
			}
			after, err := system.store.Load(t.Context(), scope)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("recovery modified durable authority state", err)
			}
			if test.code == codes.OK && (state.boundary != nil || state.floor != nil) {
				t.Fatal("completed reconciliation retained the previous assessment boundary")
			}
			if system.streams.authority.cache.used != 0 || len(system.streams.authority.cache.entries) != 0 {
				t.Fatal("recovery retained a snapshot preparation lease")
			}
		})
	}
}
