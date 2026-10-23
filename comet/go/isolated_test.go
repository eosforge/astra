// Verify archived coverage gaps with local state and deterministic admission stubs.
package comet

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// isolatedCode checks the public error category without relying on diagnostic text.
func isolatedCode(t *testing.T, cause error, expected Code) {
	t.Helper()
	var failure *Error
	if !errors.As(cause, &failure) || failure.Code != expected {
		t.Fatalf("error = %v, want category %v", cause, expected)
	}
}

// isolatedClient owns local queues only; it never starts a connection supervisor.
func isolatedClient(t *testing.T) *Client {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	client := &Client{ctx: ctx, cancel: cancel, done: make(chan struct{}), changed: make(chan struct{}), actors: make(map[*lifecycle]struct{}),
		options: Options{Bytes: 64 << 20, Readers: 32, Beacons: 32, Timeout: time.Second}, explicit: make(chan struct{}, 1),
		recovery: make(chan struct{}, 1), maintenance: make(chan struct{}, 1), notifications: newDispatcher(), timers: newScheduler()}
	t.Cleanup(func() {
		client.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if cause := client.Wait(ctx); cause != nil {
			t.Errorf("local client did not drain: %v", cause)
		}
	})
	return client
}

// isolatedLife admits a local role with the same quota and completion ownership as a live role.
func isolatedLife(t *testing.T, client *Client, reader bool) *lifecycle {
	t.Helper()
	life := newLifecycle(client, reader)
	if cause := client.attach(life); cause != nil {
		t.Fatal(cause)
	}
	return life
}

// isolatedClosing models stop's admitted-close flag before cancellation is delivered.
func isolatedClosing(t *testing.T, life *lifecycle) {
	t.Helper()
	life.mu.Lock()
	life.closed = true
	life.mu.Unlock()
	t.Cleanup(func() {
		life.mu.Lock()
		life.closed = false
		life.mu.Unlock()
	})
}

// TestIsolatedBatch checks malformed decoded entries against atomic baseline preservation.
func TestIsolatedBatch(t *testing.T) {
	for _, testcase := range []struct {
		name    string
		kind    domain
		message proto.Message
	}{
		{"almanac", almanac, &protocol.AlmanacWatchReply{Mode: protocol.Mode_MODE_APPLY, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(8), Changes: []*protocol.AlmanacChange{nil}}},
		{"catalog", catalog, &protocol.CatalogWatchReply{Mode: protocol.Mode_MODE_APPLY, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(8), Changes: []*protocol.CatalogChange{nil}}},
		{"ephemeris", ephemeris, &protocol.EphemerisWatchReply{Mode: protocol.Mode_MODE_APPLY, Complete: true, Instance: []byte("star-a"), Version: proto.Uint64(8), Changes: []*protocol.EphemerisChange{nil}}},
	} {
		t.Run(testcase.name, func(t *testing.T) {
			base := &snapshot{instance: "star-a", version: 7, data: emptyTable()}
			assembly := testBatch(testcase.kind, base)
			next, cause := assembly.accept(decodePage(testcase.message))
			isolatedCode(t, cause, CodeProtocol)
			if next != nil || assembly.current != base || base.version != 7 || base.data.count != 0 {
				t.Fatal("malformed decoded entry changed the committed snapshot")
			}
		})
	}
}

// TestIsolatedClient checks failed admission and cancellation without starting any transport.
func TestIsolatedClient(t *testing.T) {
	_, cause := New(Options{})
	isolatedCode(t, cause, CodeInput)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := &Client{ctx: ctx, changed: make(chan struct{}), serial: ^uint64(0)}
	isolatedCode(t, client.Secret([]byte("replacement")), CodeLimit)
	if client.serial != ^uint64(0) || len(client.secret) != 0 {
		t.Fatal("exhausted credential generation accepted replacement")
	}
	for _, secret := range [][]byte{nil, make([]byte, 4097)} {
		isolatedCode(t, client.Secret(secret), CodeInput)
	}
	client.options.Anonymous = true
	isolatedCode(t, client.Secret([]byte("secret")), CodeInput)
	isolatedCode(t, (*Client)(nil).attach(nil), CodeClosed)
	client.closed.Store(true)
	isolatedCode(t, client.attach(nil), CodeClosed)
	_, failure := client.acquire(context.Background())
	isolatedCode(t, failure, CodeClosed)
	if client.sampleQueue() != nil {
		t.Fatal("closed client admitted sampler workers")
	}
	client.closed.Store(false)
	canceled, stop := context.WithCancel(context.Background())
	stop()
	_, failure = client.acquire(canceled)
	isolatedCode(t, failure, CodeCanceled)
	linked, release := linkedContext(context.Background(), canceled)
	defer release()
	if linked.Err() != context.Canceled {
		t.Fatal("already canceled owner did not cancel linked request")
	}
	isolatedCode(t, waitDone(nil, make(chan struct{})), CodeInput)
	_, failure = client.watch(catalog, testScope(), "", nil)
	isolatedCode(t, failure, CodeBusy)
	if client.used.Load() != 0 {
		t.Fatal("rejected watch retained storage")
	}
}

// TestIsolatedDispatch preserves distinct pending owners before worker execution.
func TestIsolatedDispatch(t *testing.T) {
	queue := &dispatcher{}
	queue.ready = sync.NewCond(&queue.mu)
	first, second := &notification{}, &notification{}
	queue.mu.Lock()
	queue.appendLocked(first)
	queue.appendLocked(second)
	queue.mu.Unlock()
	if queue.head != first || first.next != second || queue.tail != second || !first.queued || !second.queued {
		t.Fatal("a second owner replaced a pending notification")
	}
}

// TestIsolatedLifecycle checks rejection during the close-before-cancel admission window.
func TestIsolatedLifecycle(t *testing.T) {
	client := isolatedClient(t)
	life := isolatedLife(t, client, false)
	isolatedClosing(t, life)
	publisher := &Publisher{life: life}
	_, cause := publisher.Update(context.Background(), []Entry{{Key: "key", Data: []byte("value")}}, time.Second)
	isolatedCode(t, cause, CodeClosed)
	beacon := &Beacon{life: life, initialized: true, bound: &binding{}, state: BeaconState{Phase: Ready}}
	_, cause = beacon.Update(context.Background(), []byte("new"))
	isolatedCode(t, cause, CodeClosed)
	watch := &watching{life: life, root: &snapshot{}, phase: Ready}
	called := false
	_, cause = (&Observer{watch: watch}).One(func(Pool) *Item { called = true; return nil })
	isolatedCode(t, cause, CodeClosed)
	if called {
		t.Fatal("closing role invoked a new selector")
	}
}

// TestIsolatedWatch checks closed, targetless and storage-limited publication paths.
func TestIsolatedWatch(t *testing.T) {
	client := isolatedClient(t)
	life := isolatedLife(t, client, true)
	watch := &watching{life: life, root: &snapshot{data: emptyTable(), version: 7}, estimates: emptyTable(), phase: Ready}
	watch.note = &notification{queue: client.notifications, life: life, run: func() {}}
	isolatedCode(t, (&subscription{watch: watch}).WatchKey(func(string, Value, bool) {}), CodeInput)
	other, stop := context.WithCancel(context.Background())
	defer stop()
	selected := &binding{ctx: other}
	next := &snapshot{data: emptyTable(), version: 8}
	isolatedCode(t, watch.install(selected, &batch{}, next), CodeInstance)
	client.binding = selected
	watch.domain = ephemeris
	client.options.Bytes = 0
	isolatedCode(t, watch.install(selected, &batch{}, next), CodeLimit)
	client.options.Bytes = 64 << 20
	watch.options.Bytes = 0
	draft := newDraft(emptyTable())
	draft.set("registered", &row{data: NewValue([]byte("value"))})
	next.data = draft.data
	isolatedCode(t, watch.install(selected, &batch{}, next), CodeLimit)
	if watch.root.version != 7 {
		t.Fatal("rejected publication advanced the installed cursor")
	}
	noticed := 0
	watch.notice = &viewNotice{call: func(View) { noticed++ }}
	watch.content = &contentNotice{whole: func(Map) { panic("local callback rejection") }}
	watch.root.token = &snapshotToken{}
	watch.deliver()
	if noticed != 1 || watch.content != nil || client.Panics() != 1 {
		t.Fatal("callback panic was not isolated and reported")
	}
	life.cancel()
	watch.transition(Failed, localError(CodeProtocol))
	watch.deliver()
	isolatedCode(t, watch.install(selected, &batch{}, next), CodeClosed)
	if messageCount(&protocol.CreateRequest{}) != 1<<30 {
		t.Fatal("unknown message lost conservative storage reservation")
	}
}
