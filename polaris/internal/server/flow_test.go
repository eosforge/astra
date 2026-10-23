// Drive complete stream phases against durable storage with controlled transport completion and refusal.
//go:build linux && cgo

package server

import (
	"context"
	"errors"
	"io"
	"maps"
	"reflect"
	"slices"
	"strings"
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

// dialogue advances an explicit peer schedule synchronously before recording each successfully sent frame.
type dialogue struct {
	capture                             // Own immutable successful sends and reject implicit receives.
	step    func(*polaris.Packet) error // Commit, acknowledge or reject at the selected send boundary.
}

// Send records no successful delivery when the controlled transport rejects the frame.
func (wire *dialogue) Send(packet *polaris.Packet) error {
	if err := wire.step(packet); err != nil {
		return err
	}
	return wire.capture.Send(packet)
}

// TestFlow verifies exact frames, durable content and ownership through initial and steady-state failures.
func TestFlow(t *testing.T) {
	t.Parallel()
	transport := errors.New("controlled transport refusal")
	cases := []struct {
		name   string     // Fixed schedule whose complete child outcome is required by the gate.
		cause  error      // Raw internal cause that must survive unchanged, when applicable.
		code   codes.Code // Stable protocol classification for the other terminal outcomes.
		frames int        // Exact successful prefix length; failed sends are not delivery evidence.
	}{
		{"initial-receive", transport, codes.OK, 0},
		{"hello-send", transport, codes.OK, 0},
		{"inventory-receive", transport, codes.OK, 1},
		{"initial-closed", nil, codes.Unavailable, 1},
		{"hello-replaced", nil, codes.Unauthenticated, 1},
		{"manifest-send", transport, codes.OK, 1},
		{"synchronize-closed", nil, codes.Unavailable, 2},
		{"snapshot-send", transport, codes.OK, 2},
		{"initial-drain", transport, codes.OK, 3},
		{"ready-send", transport, codes.OK, 3},
		{"feed-update", context.Canceled, codes.OK, 5},
		{"feed-update-send", transport, codes.OK, 4},
		{"feed-new", context.Canceled, codes.OK, 5},
		{"feed-new-send", transport, codes.OK, 4},
		{"feed-control", nil, codes.InvalidArgument, 5},
		{"feed-closed", nil, codes.Unavailable, 4},
		{"feed-gap", nil, codes.OutOfRange, 4},
		{"idle-eof", io.EOF, codes.OK, 4},
		{"idle-control", nil, codes.InvalidArgument, 4},
		{"idle-cancel", context.Canceled, codes.OK, 4},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			system := environment(t, storage.Default())
			scope := storage.Scope{Sector: "s", Spectrum: "p"}
			other := storage.Scope{Sector: "s", Spectrum: "q"}
			if _, err := system.store.Commit(t.Context(), scope, storage.Change{Version: 1, Key: "key", Value: []byte("before")}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			var observer *storage.Feed
			if test.name == "feed-gap" {
				var err error
				observer, err = system.store.Subscribe(1024, 1)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(observer.Close)
			}
			wire := &dialogue{capture: capture{ctx: ctx}}
			state := &transfer{owner: system.streams, wire: wire, ctx: ctx, input: make(chan incoming, 1), wake: make(chan struct{}, 1), maximum: 8 << 20, sent: make(map[storage.Scope]storage.Version), installed: make(map[storage.Scope]storage.Version)}
			// One-slot control input preserves FIFO and rejects a schedule that silently overwrites an earlier frame.
			enqueue := func(item incoming) {
				select {
				case state.input <- item:
				default:
					t.Fatal("controlled peer overran its one-frame input")
				}
			}
			acknowledge := func(scope *comet.Scope, version uint64) {
				enqueue(incoming{packet: &polaris.Packet{Body: &polaris.Packet_Acknowledged{Acknowledged: &polaris.Position{Scope: proto.Clone(scope).(*comet.Scope), Version: version}}}})
			}
			closed := false
			closeStore := func() {
				if err := system.store.Close(); err != nil {
					t.Fatal(err)
				}
				closed = true
			}
			wire.step = func(packet *polaris.Packet) error {
				switch {
				case packet.GetHello() != nil:
					if test.name == "hello-send" {
						return transport
					}
					if test.name == "inventory-receive" {
						enqueue(incoming{err: transport})
						return nil
					}
					if test.name == "initial-closed" {
						closeStore()
					}
					if test.name == "hello-replaced" {
						member := &orbit.Member{}
						if err := proto.Unmarshal(system.star.Admission, member); err != nil {
							t.Fatal(err)
						}
						member.Epoch++
						member.Id = []byte("replacement")
						hello := system.issuer.sign(member)
						if _, err := system.node.Directory().Verify(hello.Admission, hello.AdmissionSignature, orbit.Role_ROLE_STAR); err != nil {
							t.Fatal(err)
						}
					}
					enqueue(incoming{packet: &polaris.Packet{Body: &polaris.Packet_Inventory{Inventory: &polaris.Inventory{Complete: true}}}})
				case packet.GetPlan() != nil:
					if test.name == "manifest-send" {
						return transport
					}
					if test.name == "synchronize-closed" {
						closeStore()
					}
				case packet.GetSnapshot() != nil:
					page := packet.GetSnapshot()
					if test.name == "snapshot-send" || (state.ready && test.name == "feed-new-send") {
						return transport
					}
					if test.name == "initial-drain" {
						enqueue(incoming{err: transport})
					} else {
						acknowledge(page.Scope, page.GetVersion())
					}
					if state.ready {
						cancel()
					}
				case packet.GetReady() != nil:
					if test.name == "ready-send" {
						return transport
					}
					switch test.name {
					case "feed-update", "feed-update-send", "feed-control", "feed-gap":
						if _, err := system.store.Commit(ctx, scope, storage.Change{Version: 2, Key: "key", Value: []byte("after")}); err != nil {
							t.Fatal(err)
						}
						if observer != nil {
							events, err := observer.Take()
							if err != nil || len(events) != 1 || events[0].Version != 2 {
								t.Fatal("fault target is not the committed notification", err)
							}
							// Deliberately violate the borrowed event's readonly contract to model internal notification damage.
							// This is not a legal writer sequence; the durable transaction remains version two.
							events[0].Version = 3
						}
					case "feed-new", "feed-new-send":
						if _, err := system.store.Commit(ctx, other, storage.Change{Version: 1, Key: "new", Value: []byte("new")}); err != nil {
							t.Fatal(err)
						}
					case "feed-closed":
						closeStore()
					case "idle-eof":
						enqueue(incoming{err: io.EOF})
					case "idle-control":
						enqueue(incoming{packet: &polaris.Packet{Body: &polaris.Packet_Ready{Ready: &comet.Empty{}}}})
					case "idle-cancel":
						cancel()
					default:
						t.Fatal("unexpected steady-state entry", test.name)
					}
				case packet.GetUpdates() != nil:
					if test.name == "feed-update-send" {
						return transport
					}
					page := packet.GetUpdates()
					if test.name == "feed-control" {
						acknowledge(page.Scope, 3)
					} else {
						acknowledge(page.Scope, 2)
						cancel()
					}
				default:
					t.Fatal("unexpected outbound packet")
				}
				return nil
			}
			if test.name == "initial-receive" {
				enqueue(incoming{err: transport})
			} else {
				enqueue(incoming{packet: &polaris.Packet{Body: &polaris.Packet_Hello{Hello: system.star}}})
			}
			err := state.run()
			if observer != nil {
				observer.Close()
			}
			if test.cause != nil {
				if !errors.Is(err, test.cause) {
					t.Fatal("stream lost its terminal cause", err, test.cause)
				}
			} else if status.Code(err) != test.code {
				t.Fatal("stream returned the wrong protocol category", err, test.code)
			}
			// The expected transcript is literal protocol content, not derived from the observed frames.
			position := &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}
			expected := []*polaris.Packet{
				{Body: &polaris.Packet_Hello{Hello: system.node.Hello()}},
				{Body: &polaris.Packet_Plan{Plan: &polaris.Inventory{Complete: true, Positions: []*polaris.Position{{Scope: position, Version: 1}}}}},
				{Body: &polaris.Packet_Snapshot{Snapshot: &polaris.Snapshot{Scope: position, Version: proto.Uint64(1), Complete: true, Entries: []*comet.AlmanacChange{{Key: "key", Action: &comet.AlmanacChange_Value{Value: []byte("before")}}}}}},
				{Body: &polaris.Packet_Ready{Ready: &comet.Empty{}}},
			}
			if test.frames == 5 {
				if test.name == "feed-new" {
					expected = append(expected, &polaris.Packet{Body: &polaris.Packet_Snapshot{Snapshot: &polaris.Snapshot{Scope: &comet.Scope{Sector: []byte("s"), Spectrum: []byte("q")}, Version: proto.Uint64(1), Complete: true, Entries: []*comet.AlmanacChange{{Key: "new", Action: &comet.AlmanacChange_Value{Value: []byte("new")}}}}}})
				} else {
					expected = append(expected, &polaris.Packet{Body: &polaris.Packet_Updates{Updates: &polaris.Updates{Scope: position, Patches: []*polaris.Patch{{Version: 2, Change: &comet.AlmanacChange{Key: "key", Action: &comet.AlmanacChange_Value{Value: []byte("after")}}}}}}})
				}
			}
			if len(wire.packets) != test.frames {
				t.Fatal("wrong successful prefix length", len(wire.packets), test.frames)
			}
			for index, packet := range wire.packets {
				if !proto.Equal(packet, expected[index]) {
					t.Fatal("stream changed frame contents or order", index)
				}
			}
			sent, installed := make(map[storage.Scope]storage.Version), make(map[storage.Scope]storage.Version)
			if test.frames >= 3 {
				sent[scope] = 1
			}
			if test.frames >= 4 || test.name == "ready-send" {
				installed[scope] = 1
			}
			if test.frames == 5 {
				if test.name == "feed-new" {
					sent[other], installed[other] = 1, 1
				} else {
					sent[scope] = 2
					if test.name == "feed-update" {
						installed[scope] = 2
					}
				}
			}
			if !maps.Equal(state.sent, sent) || !maps.Equal(state.installed, installed) || state.ready != (test.frames >= 4) {
				t.Fatal("failed flow invented sent, installed or ready progress")
			}
			var credits []credit
			var charged int64
			if test.name == "initial-drain" {
				charged = 107 // Scope, record and fixed snapshot accounting for the literal first snapshot.
				credits = []credit{{scope: scope, version: 1, bytes: charged}}
			} else if test.name == "feed-control" {
				charged = int64(proto.Size(expected[4]))
				credits = []credit{{scope: scope, version: 2, bytes: charged}}
			}
			if !slices.Equal(state.credits, credits) || state.bytes != charged {
				t.Fatal("flow lost or invented pending delivery credit")
			}
			system.streams.mutex.Lock()
			active := len(system.streams.active)
			system.streams.mutex.Unlock()
			if active != 0 || system.streams.authority.cache.used != 0 || len(system.streams.authority.cache.entries) != 0 || state.deadline.Load() != nil {
				t.Fatal("flow retained identity, snapshot reservation or phase deadline")
			}
			if !closed {
				version, value := storage.Version(1), "before"
				if strings.HasPrefix(test.name, "feed-update") || test.name == "feed-control" || test.name == "feed-gap" {
					version, value = 2, "after"
				}
				snapshot, err := system.store.Load(t.Context(), scope)
				if err != nil || !reflect.DeepEqual(snapshot, storage.Snapshot{Position: storage.Position{Scope: scope, Version: version}, Records: []storage.Record{{Key: "key", Value: []byte(value)}}}) {
					t.Fatal("transport outcome changed authoritative content", err)
				}
				if strings.HasPrefix(test.name, "feed-new") {
					snapshot, err := system.store.Load(t.Context(), other)
					if err != nil || !reflect.DeepEqual(snapshot, storage.Snapshot{Position: storage.Position{Scope: other, Version: 1}, Records: []storage.Record{{Key: "new", Value: []byte("new")}}}) {
						t.Fatal("new scope was lost after transport failure", err)
					}
				}
				positions := []storage.Position{{Scope: scope, Version: version}}
				if strings.HasPrefix(test.name, "feed-new") {
					positions = append(positions, storage.Position{Scope: other, Version: 1})
				}
				listed, err := system.store.List(t.Context())
				if err != nil || !slices.Equal(listed, positions) {
					t.Fatal("flow created an unexpected durable position", err)
				}
				// Reacquire the entire public feed budget; one leaked run subscription would reject the last reservation.
				for range 8 {
					feed, err := system.store.Subscribe(16<<20, 1)
					if err != nil {
						t.Fatal("stream did not return its feed reservation", err)
					}
					t.Cleanup(feed.Close)
				}
			}
		})
	}
}
