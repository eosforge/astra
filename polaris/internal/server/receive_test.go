// Verify bounded receive delivery, terminal propagation and cancellation without leaking an owned worker.
//go:build linux && cgo

package server

import (
	"context"
	"errors"
	"io"
	"testing"
	"testing/synctest"

	"github.com/eosforge/astra/internal/generated/comet"
	"github.com/eosforge/astra/internal/generated/polaris"
)

// TestReceive checks an explicit two-frame prefix while the one-slot consumer queue is full.
func TestReceive(t *testing.T) {
	for _, name := range []string{"eof", "failure", "cancel"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				wire := &delay{capture: capture{ctx: ctx}, input: make(chan incoming, 3)}
				state := &transfer{wire: wire, ctx: ctx, input: make(chan incoming, 1), received: make(chan struct{})}
				first := &polaris.Packet{Body: &polaris.Packet_Ready{Ready: &comet.Empty{}}}
				second := &polaris.Packet{Body: &polaris.Packet_Inventory{Inventory: &polaris.Inventory{Complete: true}}}
				terminal := error(io.EOF)
				if name == "failure" {
					terminal = errors.New("controlled receive failure")
				}
				wire.input <- incoming{packet: first}
				wire.input <- incoming{packet: second}
				wire.input <- incoming{err: terminal}
				done := make(chan struct{})
				go func() {
					defer close(done)
					state.receive()
				}()
				defer func() {
					cancel()
					close(wire.input)
					// A deliberately broken cancellation guard must still let the test own and drain its worker.
					for {
						select {
						case <-done:
							return
						case <-state.input:
						}
					}
				}()
				synctest.Wait()
				if wire.reads.Load() != 2 || len(state.input) != 1 || len(wire.input) != 1 {
					t.Fatal("full receive queue admitted more than one pending transport frame")
				}
				select {
				case <-state.received:
					t.Fatal("receiver retired before its pending frame was handled")
				default:
				}
				if name == "cancel" {
					cancel()
					synctest.Wait()
					select {
					case <-done:
					default:
						t.Fatal("full receive queue prevented cancellation retirement")
					}
					if wire.reads.Load() != 2 || len(state.input) != 1 || len(wire.input) != 1 {
						t.Fatal("cancelled receiver read ahead or overwrote the accepted frame")
					}
					if item := <-state.input; item.packet != first || item.err != nil {
						t.Fatal("cancelled receiver changed the already delivered frame")
					}
				} else {
					for index, expected := range []*polaris.Packet{first, second} {
						select {
						case item := <-state.input:
							if item.packet != expected || item.err != nil {
								t.Fatal("receive delivery lost frame identity, order or its success result", index)
							}
						default:
							t.Fatal("receiver omitted an accepted frame", index)
						}
						synctest.Wait()
					}
					select {
					case item := <-state.input:
						if item.packet != nil || item.err != terminal {
							t.Fatal("receiver replaced or discarded the terminal transport cause")
						}
					default:
						t.Fatal("receiver omitted its terminal transport result")
					}
					if wire.reads.Load() != 3 || len(state.input) != 0 || len(wire.input) != 0 {
						t.Fatal("receiver continued after its terminal result or duplicated delivery")
					}
				}
				select {
				case <-state.received:
				default:
					t.Fatal("receiver did not publish its completed retirement")
				}
				select {
				case <-done:
				default:
					t.Fatal("receiver reported retirement before worker completion")
				}
				if wire.writes.Load() != 0 {
					t.Fatal("receive ownership unexpectedly entered the send path")
				}
			})
		})
	}
}
