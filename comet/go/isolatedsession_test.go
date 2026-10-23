// Verify cumulative staging and authenticated-close handoff with a test-owned loopback fixture.
package comet

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// TestIsolatedApplyStaging includes the retained baseline in incomplete-batch record limits.
func TestIsolatedApplyStaging(t *testing.T) {
	draft := newDraft(emptyTable())
	draft.set("stable", &row{data: NewValue([]byte("before")), version: 1})
	base := &snapshot{data: draft.data, instance: "star-a", version: 7}
	assembly := testBatch(catalog, base)
	assembly.options.Records = 1
	next, cause := assembly.accept(page{mode: protocol.Mode_MODE_APPLY, changes: []mutation{{key: "first", kind: replace, version: 1}}})
	if cause != nil || next != nil {
		t.Fatalf("bounded unpublished update failed: %v", cause)
	}
	next, cause = assembly.accept(page{mode: protocol.Mode_MODE_APPLY, changes: []mutation{{key: "second", kind: replace, version: 1}}})
	isolatedCode(t, cause, CodeLimit)
	if next != nil || base.version != 7 || base.data.count != 1 || base.data.find("stable").data.String() != "before" {
		t.Fatal("unpublished apply growth changed committed content")
	}
}

// TestIsolatedAuthenticatedClose prevents a confirmed login from publishing after Close linearizes.
func TestIsolatedAuthenticatedClose(t *testing.T) {
	var client *Client
	fixture := newFixture(t, fixtureHandlers{session: func(_ *protocol.SessionRequest, stream grpc.ServerStreamingServer[protocol.SessionReply]) error {
		client.Close()
		if cause := stream.Send(&protocol.SessionReply{Instance: []byte("star-a"), Session: make([]byte, 32)}); cause != nil {
			return cause
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	}})
	client = isolatedClient(t)
	settings, trust, failure := normalizeOptions(Options{Endpoints: []string{fixture.address}, Plaintext: true, Key: "key", Secret: []byte("unit-only")})
	if failure != nil {
		t.Fatal(failure)
	}
	client.options, client.trust, client.secret = settings, trust, settings.Secret
	hold := isolatedLife(t, client, true)
	if !hold.begin() {
		t.Fatal("closing handoff reference refused")
	}
	defer hold.release()
	client.manager.Add(1)
	go client.connect()
	done := make(chan struct{})
	go func() { client.manager.Wait(); close(done) }()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if cause := waitDone(ctx, done); cause != nil {
		t.Fatal(cause)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if !client.closed.Load() || client.binding != nil {
		t.Fatal("late authenticated binding was published after closure")
	}
}
