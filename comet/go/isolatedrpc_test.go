// Verify admission pressure and late RPC results using interceptors that cannot dial.
package comet

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// isolatedRPC short-circuits every invocation before transport creation and rejects dialing.
func isolatedRPC(t *testing.T, client *Client, handler func(string, any, any) error) *binding {
	t.Helper()
	var dials atomic.Int32
	connection, cause := grpc.NewClient("passthrough:///isolated-unit", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("unit fixture forbids network access")
		}),
		grpc.WithUnaryInterceptor(func(ctx context.Context, method string, request, response any, connection *grpc.ClientConn, next grpc.UnaryInvoker, options ...grpc.CallOption) error {
			return handler(method, request, response)
		}))
	if cause != nil {
		t.Fatal(cause)
	}
	ctx, cancel := context.WithCancel(context.Background())
	selected := &binding{ctx: ctx, cancel: cancel, unary: connection, streams: connection, endpoint: "isolated-unit"}
	instance := "star-a"
	selected.target.Store(&instance)
	client.binding = selected
	t.Cleanup(func() {
		cancel()
		connection.Close()
		if dials.Load() != 0 {
			t.Errorf("local RPC fixture attempted %d network dials", dials.Load())
		}
	})
	return selected
}

// isolatedBeacon owns a mock registration and a no-op timer callback, never a remote lease.
func isolatedBeacon(t *testing.T, client *Client, selected *binding) *Beacon {
	t.Helper()
	beacon := &Beacon{life: isolatedLife(t, client, false), scope: testScope(), attr: NewValue([]byte("fixed")), data: NewValue([]byte("confirmed")),
		ttl: time.Second, beat: 100 * time.Millisecond, state: BeaconState{Phase: Ready, HasIdentity: true,
			Identity: Identity{Scope: testScope(), Instance: "star-a", ID: string(fixtureID())}},
		capability: strings.Repeat("c", 32), bound: selected, generation: 1, issued: 1, confirmed: 1, initialized: true}
	beacon.charged = int64(beacon.attr.Len()+beacon.data.Len()) + 2048
	if !client.reserve(beacon.charged) {
		t.Fatal("local fixture storage was refused")
	}
	beacon.life.onfinish = beacon.finish
	beacon.alarm = &alarm{life: beacon.life, index: -1, run: func() {}}
	beacon.note = &notification{queue: client.notifications, life: beacon.life, run: func() {}}
	return beacon
}

// TestIsolatedBatchBudget rejects cumulative incomplete pages without committing their prefix.
func TestIsolatedBatchBudget(t *testing.T) {
	base := &snapshot{instance: "star-a", version: 7, data: emptyTable()}
	assembly := testBatch(catalog, base)
	assembly.options.Records = 1
	for _, key := range []string{"first", "second"} {
		next, cause := assembly.accept(page{mode: protocol.Mode_MODE_RESET, changes: []mutation{{key: key, kind: replace, version: 1}}})
		if cause != nil || next != nil {
			t.Fatalf("bounded unpublished prefix was rejected: %v", cause)
		}
	}
	next, cause := assembly.accept(page{mode: protocol.Mode_MODE_RESET, changes: []mutation{{key: "third", kind: replace, version: 1}}})
	isolatedCode(t, cause, CodeLimit)
	if next != nil || base.version != 7 || base.data.count != 0 {
		t.Fatal("transient-record exhaustion changed the committed baseline")
	}
}

// TestIsolatedBeaconAdmission preserves cached data and returns every slot on pre-send refusal.
func TestIsolatedBeaconAdmission(t *testing.T) {
	for _, name := range []string{"explicit", "memory", "binding", "renewal-exhausted", "maintenance", "renewal-memory", "closing", "sample-obsolete", "remove-slot", "remove-memory", "remove-canceled"} {
		t.Run(name, func(t *testing.T) {
			client := isolatedClient(t)
			var calls int
			selected := isolatedRPC(t, client, func(string, any, any) error { calls++; return errors.New("unexpected RPC") })
			beacon := isolatedBeacon(t, client, selected)
			before := client.used.Load()
			switch name {
			case "explicit":
				client.explicit <- struct{}{}
				_, cause := beacon.Update(context.Background(), []byte("new"))
				isolatedCode(t, cause, CodeBusy)
				<-client.explicit
			case "memory":
				client.options.Bytes = 1
				_, cause := beacon.Update(context.Background(), []byte("new"))
				isolatedCode(t, cause, CodeBusy)
			case "binding":
				client.binding = nil
				_, cause := beacon.Update(context.Background(), []byte("new"))
				isolatedCode(t, cause, CodeInstance)
			case "renewal-exhausted":
				beacon.renewal = ^uint64(0)
				beacon.launchLocked(selected, false)
				isolatedCode(t, beacon.State().Error, CodeLimit)
			case "maintenance":
				client.maintenance <- struct{}{}
				beacon.launchLocked(selected, false)
				<-client.maintenance
			case "renewal-memory":
				client.options.Bytes = 1
				beacon.launchLocked(selected, false)
			case "closing":
				isolatedClosing(t, beacon.life)
				beacon.launchLocked(selected, false)
			case "sample-obsolete":
				beacon.ticket = &sampleTicket{}
				beacon.tick = func() ([]byte, error) { t.Error("obsolete sample ran"); return nil, nil }
				beacon.sample(&sampleTicket{})
			case "remove-slot":
				client.maintenance <- struct{}{}
				beacon.remove(context.Background())
				<-client.maintenance
			case "remove-memory":
				client.options.Bytes = 1
				beacon.remove(context.Background())
			case "remove-canceled":
				selected.cancel()
				beacon.remove(context.Background())
			}
			if calls != 0 || beacon.data.String() != "confirmed" || client.used.Load() != before || len(client.maintenance) != 0 || beacon.operations != 0 {
				t.Fatal("pre-send rejection performed I/O or retained admission capacity")
			}
		})
	}
}

// TestIsolatedLateAcknowledgments fences data/order installation after shutdown or rebinding.
func TestIsolatedLateAcknowledgments(t *testing.T) {
	for _, name := range []string{"update-closed", "update-rebound", "create-closed", "create-rebound", "create-notice", "create-closed-error", "renew-rebound"} {
		t.Run(name, func(t *testing.T) {
			client := isolatedClient(t)
			var beacon *Beacon
			selected := isolatedRPC(t, client, func(method string, request, response any) error {
				switch reply := response.(type) {
				case *protocol.UpdateReply:
					reply.Order = request.(*protocol.UpdateRequest).Order
				case *protocol.CreateReply:
					input := request.(*protocol.CreateRequest)
					reply.Instance, reply.Uuid, reply.Capability = []byte("star-a"), []byte(beacon.state.Identity.ID), []byte(beacon.capability)
					reply.Generation, reply.TtlMs, reply.Order, reply.Data = input.Generation, input.TtlMs, beacon.confirmed, []byte("confirmed")
				case *protocol.RenewReply:
					reply.Order = request.(*protocol.RenewRequest).Order
				default:
					t.Fatalf("unexpected local RPC: %s", method)
				}
				if strings.Contains(name, "closed") {
					beacon.life.stop()
				} else if strings.Contains(name, "rebound") {
					client.binding = nil
				}
				if name == "create-closed-error" {
					return context.Canceled
				}
				return nil
			})
			beacon = isolatedBeacon(t, client, selected)
			if !beacon.life.begin() {
				t.Fatal("sibling completion reference was refused")
			}
			defer beacon.life.release()
			before := client.used.Load()
			if strings.HasPrefix(name, "update-") {
				_, cause := beacon.Update(context.Background(), []byte("unconfirmed"))
				expected := CodeInstance
				if name == "update-closed" {
					expected = CodeClosed
				}
				isolatedCode(t, cause, expected)
				if beacon.data.String() != "confirmed" || beacon.confirmed != 1 {
					t.Fatal("late update overwrote acknowledged recovery data")
				}
			} else if name == "renew-rebound" {
				beacon.renew(context.Background(), selected, 2)
				if beacon.lease.known {
					t.Fatal("late renewal confirmed a replaced binding")
				}
			} else {
				beacon.notice = &beaconNotice{call: func(BeaconState) {}}
				reserved := int64(0)
				cause := beacon.create(context.Background(), selected, 1, &reserved)
				if name == "create-notice" {
					if cause != nil || !beacon.notice.pending {
						t.Fatalf("acknowledged identity did not notify: %v", cause)
					}
				} else {
					expected := CodeInstance
					if strings.Contains(name, "closed") {
						expected = CodeClosed
					}
					isolatedCode(t, cause, expected)
				}
			}
			if client.used.Load() != before {
				t.Fatal("late response leaked transient storage")
			}
		})
	}
}

// TestIsolatedPublisherPreparation refuses a canceled or superseded lookup before Publish.
func TestIsolatedPublisherPreparation(t *testing.T) {
	for _, name := range []string{"canceled", "rebound", "stale-query"} {
		t.Run(name, func(t *testing.T) {
			client := isolatedClient(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var queries int
			selected := isolatedRPC(t, client, func(method string, request, response any) error {
				queries++
				reply, ok := response.(*protocol.CatalogQueryReply)
				if !ok {
					t.Fatalf("business data submitted after refused preparation: %s", method)
				}
				reply.Instance = []byte("star-a")
				reply.Entries = []*protocol.CatalogQueryReply_Entry{{Key: "key", Version: 1}}
				if name == "canceled" {
					cancel()
				} else {
					client.binding = nil
				}
				return nil
			})
			publisher := &Publisher{life: isolatedLife(t, client, false), scope: testScope()}
			if name == "stale-query" {
				client.binding = nil
				_, _, cause := publisher.query(ctx, selected, []string{"key"}, "star-a")
				isolatedCode(t, cause, CodeInstance)
				if queries != 0 {
					t.Fatal("stale lookup performed an RPC")
				}
				return
			}
			_, cause := publisher.Update(ctx, []Entry{{Key: "key", Data: []byte("new")}}, time.Second)
			expected := CodeInstance
			if name == "canceled" {
				expected = CodeCanceled
			}
			isolatedCode(t, cause, expected)
			if queries != 1 || publisher.issued != 0 || client.used.Load() != 0 {
				t.Fatal("refused lookup consumed a write version or storage")
			}
		})
	}
}

// TestIsolatedCreatePreparation checks pre-send fences without invoking the RPC stub.
func TestIsolatedCreatePreparation(t *testing.T) {
	client := isolatedClient(t)
	selected := isolatedRPC(t, client, func(string, any, any) error { t.Fatal("pre-send fence invoked RPC"); return nil })
	beacon := isolatedBeacon(t, client, selected)
	reserved := int64(0)
	client.binding = nil
	isolatedCode(t, beacon.create(context.Background(), selected, 1, &reserved), CodeInstance)
	client.binding = selected
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	isolatedCode(t, beacon.create(ctx, selected, 1, &reserved), CodeCanceled)
	if beacon.State().Phase != Uncertain {
		t.Fatal("expired mock lease remained Ready")
	}
}
