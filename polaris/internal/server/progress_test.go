// Exercise watchdog rescheduling and busy-feed assessment with the production timers under virtual time.
//go:build linux && cgo

package server

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/internal/generated/comet"
	"github.com/eosforge/astra/internal/generated/polaris"
	"github.com/eosforge/astra/polaris/internal/storage"
)

// TestExpiration checks an already-ready timer against the current, rather than originally scheduled, phase.
func TestExpiration(t *testing.T) {
	for _, name := range []string{"extended", "cleared", "expired"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				state := &transfer{wake: make(chan struct{}, 1)}
				state.wait(5 * time.Second)
				timer := time.NewTimer(5 * time.Second)
				defer timer.Stop()
				time.Sleep(5 * time.Second)
				<-timer.C
				if name == "extended" {
					state.wait(10 * time.Second)
				} else if name == "cleared" {
					state.wait(0)
				}
				err := state.expire(timer)
				if name == "expired" {
					if status.Code(err) != codes.DeadlineExceeded {
						t.Fatal("elapsed phase did not expire", err)
					}
					return
				}
				if err != nil {
					t.Fatal("stale notification expired a replaced phase", err)
				}
				time.Sleep(10*time.Second - time.Nanosecond)
				select {
				case <-timer.C:
					t.Fatal("replacement deadline fired early or a cleared deadline was restarted")
				default:
				}
				time.Sleep(time.Nanosecond)
				select {
				case <-timer.C:
					if name != "extended" || status.Code(state.expire(timer)) != codes.DeadlineExceeded {
						t.Fatal("replacement deadline did not expire exactly once")
					}
				default:
					if name != "cleared" {
						t.Fatal("replacement deadline failed to rearm")
					}
				}
			})
		})
	}
}

// TestBusyAssessment advances virtual time in finite sends while every completed send creates the next durable write.
// Each send takes twelve virtual seconds, below its thirty-second budget; no production timer or jitter is replaced.
func TestBusyAssessment(t *testing.T) {
	for _, name := range []string{"resumed", "refused", "overlap", "closed"} {
		t.Run(name, func(t *testing.T) {
			// Real TLS admission and database connection setup finish outside the scheduling bubble.
			system := environment(t, storage.Default())
			scope := storage.Scope{Sector: "s", Spectrum: "p"}
			if _, err := system.store.Commit(t.Context(), scope, storage.Change{Version: 1, Key: "key", Value: []byte{1}}); err != nil {
				t.Fatal(err)
			}
			if _, err := system.store.List(t.Context()); err != nil {
				t.Fatal(err)
			}
			synctest.Test(t, func(t *testing.T) {
				// Commits replace the Store notification channel inside this bubble; close it here before returning.
				// The outer fixture's later Close is idempotent and must not touch a bubble-owned channel.
				defer func() {
					if err := system.store.Close(); err != nil {
						t.Error(err)
					}
				}()
				ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
				defer cancel()
				wire := &dialogue{capture: capture{ctx: ctx}}
				state := &transfer{owner: system.streams, wire: wire, ctx: ctx, input: make(chan incoming, 1), wake: make(chan struct{}, 1), maximum: 8 << 20, sent: make(map[storage.Scope]storage.Version), installed: make(map[storage.Scope]storage.Version)}
				position := &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}
				enqueue := func(packet *polaris.Packet) {
					select {
					case state.input <- incoming{packet: packet}:
					default:
						t.Fatal("peer overran the production one-frame input")
					}
				}
				acknowledge := func(version uint64) {
					enqueue(&polaris.Packet{Body: &polaris.Packet_Acknowledged{Acknowledged: &polaris.Position{Scope: position, Version: version}}})
				}
				commit := func(version uint64) {
					if _, err := system.store.Commit(ctx, scope, storage.Change{Version: storage.Version(version), Key: "key", Value: []byte{byte(version)}}); err != nil {
						t.Fatal("scheduled write failed", err)
					}
				}
				update := func(version uint64) *polaris.Packet {
					return &polaris.Packet{Body: &polaris.Packet_Updates{Updates: &polaris.Updates{Scope: position, Patches: []*polaris.Patch{{Version: version, Change: &comet.AlmanacChange{Key: "key", Action: &comet.AlmanacChange_Value{Value: []byte{byte(version)}}}}}}}}
				}
				transport := errors.New("controlled assessment transport refusal")
				start := time.Now()
				probes, sent := 0, uint64(1)
				closed := false
				wire.step = func(packet *polaris.Packet) error {
					switch {
					case packet.GetHello() != nil:
						enqueue(&polaris.Packet{Body: &polaris.Packet_Inventory{Inventory: &polaris.Inventory{Complete: true}}})
					case packet.GetPlan() != nil:
					case packet.GetSnapshot() != nil:
						acknowledge(1)
					case packet.GetReady() != nil:
						commit(2)
					case packet.GetUpdates() != nil:
						sent++
						if !proto.Equal(packet, update(sent)) || sent > 7 {
							t.Fatal("busy feed lost continuity or starved its assessment", packet)
						}
						time.Sleep(12 * time.Second)
						if sent == 5 {
							if len(state.input) != 1 {
								t.Fatal("assessment inventory was not deferred to the next drain")
							}
						} else {
							acknowledge(sent)
						}
						if sent < 5 || name == "overlap" {
							commit(sent + 1)
						}
						if name == "closed" && sent == 5 {
							snapshot, err := system.store.Load(ctx, scope)
							want := storage.Snapshot{Position: storage.Position{Scope: scope, Version: 5}, Records: []storage.Record{{Key: "key", Value: []byte{5}}}}
							if err != nil || !reflect.DeepEqual(snapshot, want) {
								t.Fatal("pre-close durable state changed", err)
							}
							if err := system.store.Close(); err != nil {
								t.Fatal(err)
							}
							closed = true
						}
					case packet.GetProbe() != nil:
						probes++
						if probes == 1 && (sent != 4 || time.Since(start) != 36*time.Second) {
							t.Fatal("continuous writes displaced the first assessment", sent, time.Since(start))
						}
						if probes == 2 {
							if name != "resumed" || time.Since(start) < 66*time.Second || time.Since(start) >= 71*time.Second {
								t.Fatal("completed recovery did not preserve the next assessment interval")
							}
							return transport
						}
						if name == "refused" {
							return transport
						}
						enqueue(&polaris.Packet{Body: &polaris.Packet_Inventory{Inventory: &polaris.Inventory{Complete: name != "overlap", Positions: []*polaris.Position{{Scope: position, Version: 4}}}}})
					default:
						t.Fatal("unexpected busy-feed packet")
					}
					return nil
				}
				enqueue(&polaris.Packet{Body: &polaris.Packet_Hello{Hello: system.star}})
				err := state.run()
				last, tip, installed, attempts := uint64(5), uint64(5), uint64(4), 2
				if name == "refused" {
					last, installed, attempts = 4, 4, 1
				} else if name == "overlap" {
					last, tip, installed, attempts = 7, 8, 7, 1
				} else if name == "closed" {
					attempts = 1
				}
				if name == "overlap" {
					if status.Code(err) != codes.DeadlineExceeded || time.Since(start) != 72*time.Second {
						t.Fatal("busy feed escaped incomplete-assessment expiry", err)
					}
				} else if name == "closed" {
					if status.Code(err) != codes.Unavailable || !closed || time.Since(start) != 48*time.Second {
						t.Fatal("completed inventory hid a reconciliation read failure", err)
					}
				} else if !errors.Is(err, transport) {
					t.Fatal("assessment lost its actual send failure", err)
				}
				expected := []*polaris.Packet{
					{Body: &polaris.Packet_Hello{Hello: system.node.Hello()}},
					{Body: &polaris.Packet_Plan{Plan: &polaris.Inventory{Complete: true, Positions: []*polaris.Position{{Scope: position, Version: 1}}}}},
					{Body: &polaris.Packet_Snapshot{Snapshot: &polaris.Snapshot{Scope: position, Version: proto.Uint64(1), Complete: true, Entries: []*comet.AlmanacChange{{Key: "key", Action: &comet.AlmanacChange_Value{Value: []byte{1}}}}}}},
					{Body: &polaris.Packet_Ready{Ready: &comet.Empty{}}},
				}
				for version := uint64(2); version <= last; version++ {
					expected = append(expected, update(version))
					if version == 4 && name != "refused" {
						expected = append(expected, &polaris.Packet{Body: &polaris.Packet_Probe{Probe: &comet.Empty{}}})
					}
				}
				if len(wire.packets) != len(expected) || probes != attempts || sent != last || !state.ready || state.sent[scope] != storage.Version(last) || state.installed[scope] != storage.Version(installed) {
					t.Fatal("busy-feed transcript or acknowledged progress changed")
				}
				for index, packet := range expected {
					if !proto.Equal(wire.packets[index], packet) {
						t.Fatal("busy-feed frame contents or order changed", index)
					}
				}
				pending := int64(0)
				if last > installed {
					pending = int64(proto.Size(update(5)))
				}
				if state.bytes != pending || len(state.credits) != int(last-installed) || len(state.input) != 0 || state.deadline.Load() != nil || len(state.owner.active) != 0 || state.owner.authority.cache.used != 0 {
					t.Fatal("busy-feed termination lost credit or retained execution ownership")
				}
				if !closed {
					snapshot, err := system.store.Load(ctx, scope)
					want := storage.Snapshot{Position: storage.Position{Scope: scope, Version: storage.Version(tip)}, Records: []storage.Record{{Key: "key", Value: []byte{byte(tip)}}}}
					if err != nil || !reflect.DeepEqual(snapshot, want) {
						t.Fatal("busy feed changed durable authority state", err)
					}
					var feeds []*storage.Feed
					defer func() {
						for _, feed := range feeds {
							feed.Close()
						}
					}()
					for range 8 {
						feed, err := system.store.Subscribe(16<<20, 1)
						if err != nil {
							t.Fatal("busy-feed termination leaked its subscription", err)
						}
						feeds = append(feeds, feed)
					}
				}
			})
		})
	}
}
