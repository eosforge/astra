// Exercise production stream deadlines with virtual monotonic time and explicitly delayed transport retirement.
//go:build linux && cgo

package server

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/eosforge/astra/internal/generated/polaris"
)

// delay separates handler cancellation from actual Recv completion inside one owned scheduling bubble.
type delay struct {
	capture               // Supply the owned Context and reject unused transport metadata paths.
	input   chan incoming // Only the fixture can deliver a frame or retire the outstanding receive.
	reads   atomic.Int32  // Count actual receives, including the blocked invocation.
	writes  atomic.Int32  // Any write before a valid Hello is a protocol violation.
}

// Recv remains owned after cancellation until its input is explicitly completed or closed.
func (wire *delay) Recv() (*polaris.Packet, error) {
	wire.reads.Add(1)
	item, open := <-wire.input
	if !open {
		return nil, io.EOF
	}
	return item.packet, item.err
}

// Send rejects unexpected progress before handshake completion.
func (wire *delay) Send(*polaris.Packet) error {
	wire.writes.Add(1)
	return errors.New("unexpected send before a valid Hello")
}

// TestDeadline checks the exact ten-second boundary and both orders of cancellation versus expiration.
func TestDeadline(t *testing.T) {
	for _, name := range []string{"expiry", "cancel-before", "eof-before", "invalid-before", "expiry-cancel"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				wire := &delay{capture: capture{ctx: ctx}, input: make(chan incoming, 1)}
				streams := NewStreams(nil, nil)
				result := make(chan error, 1)
				var handler sync.WaitGroup
				var closed sync.Once
				cleanup := func() {
					cancel()
					closed.Do(func() { close(wire.input) })
					handler.Wait()
					streams.Wait()
				}
				defer cleanup()
				start := time.Now()
				handler.Add(1)
				go func() {
					defer handler.Done()
					result <- streams.Open(wire)
				}()
				synctest.Wait()
				if wire.reads.Load() != 1 || wire.writes.Load() != 0 || len(streams.slots) != 1 || time.Since(start) != 0 {
					t.Fatal("stream did not establish its owned receive at the initial logical instant")
				}
				// Sleep advances only the bubble's virtual clock; no wall-clock delay selects this schedule.
				time.Sleep(10*time.Second - time.Nanosecond)
				synctest.Wait()
				select {
				case err := <-result:
					t.Fatal("handshake expired before its deadline", err)
				default:
				}
				if len(streams.slots) != 1 || ctx.Err() != nil {
					t.Fatal("pending handshake lost ownership or inherited an unrelated cancellation")
				}
				code := codes.DeadlineExceeded
				reads, slots := int32(1), 1
				switch name {
				case "cancel-before":
					cancel()
					code = codes.Canceled
				case "eof-before":
					closed.Do(func() { close(wire.input) })
					code, slots = codes.Canceled, 0
				case "invalid-before":
					wire.input <- incoming{packet: &polaris.Packet{}}
					code, reads = codes.InvalidArgument, 2
				default:
					time.Sleep(time.Nanosecond)
				}
				synctest.Wait()
				select {
				case err := <-result:
					if name == "cancel-before" {
						if !errors.Is(err, context.Canceled) && status.Code(err) != codes.Canceled {
							t.Fatal("cancelled handler lost its cancellation cause", err)
						}
					} else if status.Code(err) != code {
						t.Fatal("handshake changed its exact terminal category", err, code)
					}
				default:
					t.Fatal("handshake did not terminate at the selected boundary")
				}
				if name != "cancel-before" && ctx.Err() != nil {
					t.Fatal("fixture cancellation, not the protocol or watchdog, ended the handshake")
				}
				if name == "expiry-cancel" {
					cancel()
				}
				if wire.reads.Load() != reads || wire.writes.Load() != 0 || len(streams.slots) != slots || len(streams.active) != 0 {
					t.Fatal("terminal handler released an undrained receiver or invented protocol progress")
				}
				// Crossing the old deadline again must neither complete twice nor release blocked transport ownership.
				time.Sleep(time.Minute)
				synctest.Wait()
				if len(result) != 0 || wire.reads.Load() != reads || wire.writes.Load() != 0 || len(streams.slots) != slots {
					t.Fatal("late timeout or cancellation changed a completed handler")
				}
				// All handlers have returned; Wait must still own the undrained receive.
				drained := make(chan struct{})
				go func() {
					streams.Wait()
					close(drained)
				}()
				synctest.Wait()
				select {
				case <-drained:
					if slots != 0 {
						t.Fatal("Wait returned before transport retirement")
					}
				default:
					if slots == 0 {
						t.Fatal("Wait retained an already retired transport")
					}
				}
				cleanup()
				synctest.Wait()
				select {
				case <-drained:
				default:
					t.Fatal("Wait did not complete after transport retirement")
				}
				if len(streams.slots) != 0 || len(streams.active) != 0 {
					t.Fatal("real transport retirement did not return stream ownership")
				}
			})
		})
	}
}

// TestDeadlineCapacity keeps expired receivers charged, then reuses the complete capacity after actual drain.
func TestDeadlineCapacity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		streams := NewStreams(nil, nil)
		for range 2 {
			ctx, cancel := context.WithCancel(t.Context())
			clients := make([]*delay, 16)
			results := make([]chan error, 16)
			var handlers sync.WaitGroup
			var closed sync.Once
			cleanup := func() {
				cancel()
				closed.Do(func() {
					for _, wire := range clients {
						if wire != nil {
							close(wire.input)
						}
					}
				})
				handlers.Wait()
				streams.Wait()
			}
			defer cleanup()
			for index := range clients {
				clients[index] = &delay{capture: capture{ctx: ctx}, input: make(chan incoming, 1)}
				results[index] = make(chan error, 1)
				handlers.Add(1)
				go func() {
					defer handlers.Done()
					results[index] <- streams.Open(clients[index])
				}()
			}
			synctest.Wait()
			if len(streams.slots) != 16 {
				t.Fatal("stream capacity was not fully acquired or reusable")
			}
			time.Sleep(10*time.Second - time.Nanosecond)
			synctest.Wait()
			for _, result := range results {
				if len(result) != 0 {
					t.Fatal("a full-capacity handshake ended before its deadline")
				}
			}
			time.Sleep(time.Nanosecond)
			synctest.Wait()
			for _, result := range results {
				select {
				case err := <-result:
					if status.Code(err) != codes.DeadlineExceeded {
						t.Fatal("full-capacity expiration changed its terminal category", err)
					}
				default:
					t.Fatal("a full-capacity handshake failed to expire")
				}
			}
			extra := &delay{capture: capture{ctx: ctx}, input: make(chan incoming, 1)}
			if len(streams.slots) != 16 || status.Code(streams.Open(extra)) != codes.ResourceExhausted || extra.reads.Load() != 0 || extra.writes.Load() != 0 {
				t.Fatal("expired but undrained receivers did not retain admission capacity")
			}
			for _, wire := range clients {
				if wire.reads.Load() != 1 || wire.writes.Load() != 0 {
					t.Fatal("timeout changed transport ownership or emitted a false handshake")
				}
			}
			cleanup()
			if len(streams.slots) != 0 || len(streams.active) != 0 {
				t.Fatal("expired streams retained resources after real receive completion")
			}
		}
	})
}
