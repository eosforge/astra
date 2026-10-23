// Verify that handler cancellation does not release capacity still owned by blocked transport receivers.
//go:build linux && cgo

package server

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/eosforge/astra/internal/generated/astra"
	"github.com/eosforge/astra/internal/generated/polaris"
)

// receiver holds a native Recv invocation past cancellation until the test releases its transport barrier.
type receiver struct {
	ctx     context.Context   // Handler cancellation, independent of transport completion.
	prefix  []*polaris.Packet // Literal frames delivered before the blocked transport operation.
	entered chan struct{}     // Closed after the sole receiver has entered Recv.
	release chan struct{}     // Closed only when transport completion is permitted.
	reads   atomic.Int32      // Actual Recv calls, including forbidden duplicate receivers.
	writes  atomic.Int32      // Any send is unexpected before the first received Hello.
}

// Context supplies the handler's explicitly owned cancellation scope.
func (receiver *receiver) Context() context.Context { return receiver.ctx }

// Recv models an outstanding transport operation without adding synchronization to production state.
func (receiver *receiver) Recv() (*polaris.Packet, error) {
	index := int(receiver.reads.Add(1)) - 1
	if index < len(receiver.prefix) {
		return receiver.prefix[index], nil
	}
	if index == len(receiver.prefix) {
		close(receiver.entered)
	}
	<-receiver.release
	return nil, io.EOF
}

// Send records an unexpected write; this scenario never receives a handshake.
func (receiver *receiver) Send(*polaris.Packet) error {
	receiver.writes.Add(1)
	return errors.New("unexpected send before Hello")
}

// SetHeader rejects metadata operations outside the tested typed transport boundary.
func (*receiver) SetHeader(metadata.MD) error { return errors.New("unexpected header") }

// SendHeader rejects metadata operations outside the tested typed transport boundary.
func (*receiver) SendHeader(metadata.MD) error { return errors.New("unexpected header send") }

// SetTrailer fails loudly if the service unexpectedly changes its trailer behavior.
func (*receiver) SetTrailer(metadata.MD) { panic("unexpected trailer") }

// SendMsg rejects untyped messages rather than silently accepting an unused fake path.
func (*receiver) SendMsg(any) error { return errors.New("unexpected untyped send") }

// RecvMsg rejects untyped messages rather than silently accepting an unused fake path.
func (*receiver) RecvMsg(any) error { return errors.New("unexpected untyped receive") }

// TestStreamDrain holds all sixteen receivers after cancellation, checks rejection, then drains and reuses every slot.
func TestStreamDrain(t *testing.T) {
	// The timeout detects a hang; channels, not elapsed time, select the cancellation schedule.
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	streams := NewStreams(nil, nil)
	hits := 0
	check := func(condition bool, message string) {
		t.Helper()
		if !condition {
			t.Fatal(message)
		}
		hits++
	}
	t.Cleanup(func() { t.Logf(`ASTRA-CONTRACT {"contract":"POLARIS-DRAIN","hits":%d}`, hits) })
	for range 2 {
		// Each wave owns all handlers, their contexts and a single transport-release barrier.
		clients := make([]*receiver, 16)
		cancels := make([]context.CancelFunc, 16)
		results := make([]chan error, 16)
		release := make(chan struct{})
		var once sync.Once
		var handlers sync.WaitGroup
		cleanup := func() {
			for _, stop := range cancels {
				if stop != nil {
					stop()
				}
			}
			once.Do(func() { close(release) })
			handlers.Wait()
			streams.Wait()
		}
		t.Cleanup(cleanup)
		for index := range clients {
			child, stop := context.WithCancel(ctx)
			clients[index] = &receiver{ctx: child, entered: make(chan struct{}), release: release}
			cancels[index], results[index] = stop, make(chan error, 1)
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				results[index] <- streams.Open(clients[index])
			}()
		}
		for _, client := range clients {
			select {
			case <-client.entered:
			case <-ctx.Done():
				t.Fatal("receiver did not enter", ctx.Err())
			}
		}
		for _, stop := range cancels {
			stop()
		}
		for _, result := range results {
			select {
			case err := <-result:
				check(errors.Is(err, context.Canceled) || status.Code(err) == codes.Canceled, "handler lost cancellation")
			case <-ctx.Done():
				t.Fatal("handler did not cancel", ctx.Err())
			}
		}
		check(len(streams.slots) == 16, "cancellation released capacity before Recv finished")
		// Rejection must neither start another receiver nor send a protocol packet.
		extra := &receiver{ctx: ctx, entered: make(chan struct{}), release: release}
		check(status.Code(streams.Open(extra)) == codes.ResourceExhausted, "undrained capacity accepted another stream")
		check(extra.reads.Load() == 0 && extra.writes.Load() == 0, "rejected stream started transport work")
		cleanup()
		check(len(streams.slots) == 0 && len(streams.active) == 0, "drain retained a slot or active identity")
		for _, client := range clients {
			check(client.reads.Load() == 1 && client.writes.Load() == 0, "receiver ownership or handshake boundary changed")
		}
	}
	// Malformed first frames end the handler, but cannot release a still-blocked second Recv.
	packets := []*polaris.Packet{
		nil,
		{},
		{Body: &polaris.Packet_Hello{Hello: &astra.Hello{ProtocolMajor: 0, MaxFrameBytes: 1024}}},
		{Body: &polaris.Packet_Hello{Hello: &astra.Hello{ProtocolMajor: 2, MaxFrameBytes: 1024}}},
		{Body: &polaris.Packet_Hello{Hello: &astra.Hello{ProtocolMajor: 1, MaxFrameBytes: 0}}},
		{Body: &polaris.Packet_Hello{Hello: &astra.Hello{ProtocolMajor: 1, MaxFrameBytes: 1023}}},
		{Body: &polaris.Packet_Hello{Hello: &astra.Hello{ProtocolMajor: 1, MaxFrameBytes: (8 << 20) + 1}}},
		{Body: &polaris.Packet_Inventory{Inventory: &polaris.Inventory{Complete: true}}},
	}
	for _, packet := range packets {
		child, stop := context.WithCancel(ctx)
		release := make(chan struct{})
		client := &receiver{ctx: child, prefix: []*polaris.Packet{packet}, entered: make(chan struct{}), release: release}
		result := make(chan error, 1)
		var once sync.Once
		var handler sync.WaitGroup
		cleanup := func() {
			stop()
			once.Do(func() { close(release) })
			handler.Wait()
			streams.Wait()
		}
		t.Cleanup(cleanup)
		handler.Add(1)
		go func() {
			defer handler.Done()
			result <- streams.Open(client)
		}()
		select {
		case <-client.entered:
		case <-ctx.Done():
			t.Fatal("receiver did not reach the post-frame barrier", ctx.Err())
		}
		select {
		case err := <-result:
			check(status.Code(err) == codes.InvalidArgument, "malformed first frame lost its protocol refusal")
		case <-ctx.Done():
			t.Fatal("malformed first frame did not terminate the handler", ctx.Err())
		}
		check(client.reads.Load() == 2 && client.writes.Load() == 0, "refused handshake changed transport ownership")
		check(len(streams.slots) == 1, "refused handshake released its undrained receiver")
		cleanup()
		check(len(streams.slots) == 0 && len(streams.active) == 0, "refused handshake retained resources after drain")
	}
}
