// Verify deterministic cancellation, queue pressure and stream-fencing schedules locally.
package comet

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// isolatedContext schedules one owner event at a Context observation boundary.
type isolatedContext struct {
	context.Context
	err  func()
	done func()
}

// Err invokes the observation hook before returning the embedded context error.
func (ctx isolatedContext) Err() error {
	if ctx.err != nil {
		ctx.err()
	}
	return ctx.Context.Err()
}

// Done invokes the observation hook before returning the embedded cancellation channel.
func (ctx isolatedContext) Done() <-chan struct{} {
	if ctx.done != nil {
		ctx.done()
	}
	return ctx.Context.Done()
}

// TestIsolatedControlLoop models stop and credential notifications before any dialing is admissible.
func TestIsolatedControlLoop(t *testing.T) {
	for _, name := range []string{"closed", "blocked-cancel", "blocked-change"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client := &Client{changed: make(chan struct{})}
			var first sync.Once
			var calls atomic.Int32
			client.ctx = isolatedContext{Context: ctx, err: func() {
				if name == "closed" || name == "blocked-change" && calls.Add(1) == 2 {
					client.closed.Store(true)
				}
			}, done: func() {
				first.Do(func() {
					if name == "blocked-change" {
						close(client.changed)
					} else {
						cancel()
					}
				})
			}}
			if name != "closed" {
				client.blocked = localError(CodeInput)
			}
			client.manager.Add(1)
			client.connect()
			client.manager.Wait()
			if client.binding != nil {
				t.Fatal("blocked control loop published a transport")
			}
		})
	}
}

// TestIsolatedCancellationBoundary cancels the role between initial validation and actual admission.
func TestIsolatedCancellationBoundary(t *testing.T) {
	for _, name := range []string{"tick", "update", "publisher"} {
		t.Run(name, func(t *testing.T) {
			client := isolatedClient(t)
			selected := isolatedRPC(t, client, func(string, any, any) error { t.Fatal("cancellation fence performed RPC"); return nil })
			beacon := isolatedBeacon(t, client, selected)
			var calls atomic.Int32
			beacon.life.ctx = isolatedContext{Context: beacon.life.ctx, err: func() {
				if calls.Add(1) == 2 {
					beacon.life.cancel()
				}
			}}
			switch name {
			case "tick":
				isolatedCode(t, beacon.Tick(time.Millisecond, func() ([]byte, error) { t.Error("canceled sampler ran"); return nil, nil }), CodeClosed)
			case "update":
				_, cause := beacon.Update(context.Background(), []byte("new"))
				isolatedCode(t, cause, CodeCanceled)
			case "publisher":
				publisher := &Publisher{life: beacon.life, scope: testScope()}
				_, cause := publisher.Update(context.Background(), []Entry{{Key: "key", Data: []byte("new")}}, time.Second)
				isolatedCode(t, cause, CodeClosed)
			}
			if beacon.data.String() != "confirmed" || len(client.explicit) != 0 {
				t.Fatal("canceled preparation retained data or a slot")
			}
		})
	}
}

// TestIsolatedSamplingPressure defers a full local queue without a callback or overlapping renewal.
func TestIsolatedSamplingPressure(t *testing.T) {
	client := isolatedClient(t)
	selected := isolatedRPC(t, client, func(string, any, any) error { t.Fatal("sampling pressure performed RPC"); return nil })
	beacon := isolatedBeacon(t, client, selected)
	now, valid := leaseNow()
	if !valid {
		t.Fatal("native lease clock unavailable")
	}
	beacon.lease.confirm(now)
	beacon.sent, beacon.hasSent = now, true
	beacon.tick = func() ([]byte, error) { t.Error("full sampler queue invoked callback"); return nil, nil }
	beacon.samples = &sampler{jobs: make(chan sampleJob)}
	beacon.nextTick = time.Now().Add(-time.Second)
	beacon.advance()
	if beacon.sampling || !beacon.nextTick.After(time.Now()) || beacon.operations != 0 {
		t.Fatal("full sampler queue retained work or lost its retry boundary")
	}
	beacon.tick = nil
	beacon.automatic = true
	beacon.lease = lease{}
	beacon.advance()
	if beacon.state.Phase != Uncertain {
		t.Fatal("expired confirmation remained Ready")
	}
	old := &binding{ctx: selected.ctx, endpoint: selected.endpoint}
	instance := "star-a"
	old.target.Store(&instance)
	beacon.bound, beacon.active = old, true
	beacon.advance()
	if beacon.bound != old {
		t.Fatal("in-flight operation was silently rebound")
	}
}

// isolatedStream is a generated-client-compatible local receiver, with no socket or server.
type isolatedStream struct {
	ctx     context.Context
	receive func(context.Context, any) error
}

// Header returns no metadata or failure for this isolated stream.
func (stream isolatedStream) Header() (metadata.MD, error) { return nil, nil }

// Trailer returns no metadata for this isolated stream.
func (stream isolatedStream) Trailer() metadata.MD { return nil }

// CloseSend completes locally without sending or releasing the receive fixture.
func (stream isolatedStream) CloseSend() error { return nil }

// Context returns the context borrowed by this isolated stream.
func (stream isolatedStream) Context() context.Context { return stream.ctx }

// SendMsg accepts the unused outgoing-message boundary without network activity.
func (stream isolatedStream) SendMsg(any) error { return nil }

// RecvMsg delegates to the configured receiver with the stream context and caller-owned output.
func (stream isolatedStream) RecvMsg(message any) error { return stream.receive(stream.ctx, message) }

// TestIsolatedStreamFences preserves a baseline on late, stale, oversized-reservation and target-race replies.
func TestIsolatedStreamFences(t *testing.T) {
	for _, name := range []string{"late", "binding", "memory", "target-race", "closed-install"} {
		t.Run(name, func(t *testing.T) {
			client := isolatedClient(t)
			selected := isolatedRPC(t, client, func(string, any, any) error { t.Fatal("stream fixture used unary RPC"); return nil })
			life := isolatedLife(t, client, true)
			baseline := &snapshot{instance: "star-a", version: 7, data: emptyTable()}
			watch := &watching{life: life, domain: catalog, scope: testScope(), root: baseline, estimates: emptyTable(), phase: Ready,
				options: ReadOptions{Bytes: 1 << 20, Records: 16}}
			watch.note = &notification{queue: client.notifications, life: life, run: func() {}}
			life.onfinish = watch.finish
			if name == "closed-install" {
				if !life.begin() {
					t.Fatal("publication observation reference refused")
				}
				defer life.release()
				var observations atomic.Int32
				life.ctx = isolatedContext{Context: life.ctx, err: func() {
					if observations.Add(1) == 2 {
						life.stop()
					}
				}}
			}
			watch.charged = watch.retainedLocked()
			if !client.reserve(watch.charged) {
				t.Fatal("baseline reservation refused")
			}
			client.options.Timeout = 10 * time.Millisecond
			var count int
			connection, cause := grpc.NewClient("passthrough:///isolated-stream", grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
					t.Error("stream fixture dialed")
					return nil, errors.New("dial forbidden")
				}),
				grpc.WithStreamInterceptor(func(ctx context.Context, description *grpc.StreamDesc, connection *grpc.ClientConn, method string, streamer grpc.Streamer, options ...grpc.CallOption) (grpc.ClientStream, error) {
					return isolatedStream{ctx: ctx, receive: func(ctx context.Context, message any) error {
						count++
						if count > 1 {
							return io.EOF
						}
						switch name {
						case "late":
							<-ctx.Done()
						case "binding":
							client.binding = nil
						case "memory":
							client.options.Bytes = client.used.Load()
						case "target-race":
							other := "star-b"
							selected.target.Store(&other)
						}
						proto.Merge(message.(proto.Message), &protocol.CatalogWatchReply{Mode: protocol.Mode_MODE_APPLY, Complete: true,
							Instance: []byte("star-a"), Version: proto.Uint64(8), Changes: []*protocol.CatalogChange{{Key: "key", Version: 1, Action: &protocol.CatalogChange_Value{Value: []byte("new")}}}})
						return nil
					}}, nil
				}))
			if cause != nil {
				t.Fatal(cause)
			}
			defer connection.Close()
			selected.streams = connection
			failure := watch.receive(selected, false)
			expected := CodeInstance
			if name == "late" {
				expected = CodeTimeout
			} else if name == "memory" {
				expected = CodeLimit
			} else if name == "closed-install" {
				expected = CodeClosed
			}
			isolatedCode(t, failure, expected)
			if watch.root != baseline || baseline.version != 7 || watch.stage != 0 || watch.decoded != 0 {
				t.Fatal("rejected stream reply changed content or retained staging bytes")
			}
		})
	}
}
