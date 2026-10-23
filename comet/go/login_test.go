// Verify wire login rejection and deadline ownership before business admission.
package comet

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// TestMalformedSessionBlocksBusiness rejects invalid confirmation before query or commit.
func TestMalformedSessionBlocksBusiness(t *testing.T) {
	for _, testcase := range []struct {
		name  string
		reply *protocol.SessionReply
	}{
		{"empty-instance", &protocol.SessionReply{Session: make([]byte, 32)}},
		{"short-session", &protocol.SessionReply{Instance: []byte("star-a"), Session: make([]byte, 31)}},
		{"long-session", &protocol.SessionReply{Instance: []byte("star-a"), Session: make([]byte, 33)}},
	} {
		t.Run(testcase.name, func(t *testing.T) {
			var logins, queries, writes atomic.Int32
			fixture := newFixture(t, fixtureHandlers{
				session: func(_ *protocol.SessionRequest, stream grpc.ServerStreamingServer[protocol.SessionReply]) error {
					reply := &protocol.SessionReply{Instance: []byte("star-a"), Session: make([]byte, 32)}
					if logins.Add(1) == 1 {
						reply = testcase.reply
					}
					if cause := stream.Send(reply); cause != nil {
						return cause
					}
					<-stream.Context().Done()
					return stream.Context().Err()
				},
				query: func(_ context.Context, request *protocol.CatalogQueryRequest) (*protocol.CatalogQueryReply, error) {
					queries.Add(1)
					return &protocol.CatalogQueryReply{Instance: []byte("star-a"), Entries: []*protocol.CatalogQueryReply_Entry{{Key: request.Keys[0]}}}, nil
				},
				publish: func(_ context.Context, request *protocol.PublishRequest) (*protocol.PublishReply, error) {
					writes.Add(1)
					return &protocol.PublishReply{Instance: request.Instance, Version: request.Version}, nil
				},
			})
			client := fixtureClient(t, fixture, Options{Plaintext: true, Key: "key", Secret: []byte("secret")})
			publisher, cause := client.Publisher(testScope())
			if cause != nil {
				t.Fatal(cause)
			}
			for range 2 {
				receipt, cause := publisher.Update(testContext(t), []Entry{{Key: "blocked"}}, time.Second)
				requireCode(t, cause, CodeProtocol, Unapplied)
				if receipt != (Receipt{}) || queries.Load() != 0 || writes.Load() != 0 || logins.Load() != 1 {
					t.Fatal("malformed Session admitted business work or retried without explicit recovery")
				}
			}
			if cause := client.Secret([]byte("fresh-secret")); cause != nil {
				t.Fatal(cause)
			}
			receipt, cause := publisher.Update(testContext(t), []Entry{{Key: "healthy"}}, time.Second)
			if cause != nil || receipt.Version != 1 || logins.Load() != 2 || queries.Load() != 1 || writes.Load() != 1 {
				t.Fatalf("explicit credential recovery failed after protocol rejection: %#v %v", receipt, cause)
			}
		})
	}
}

// TestInitialSessionDeadlineCancelsWireRead includes login in the caller's unapplied deadline.
func TestInitialSessionDeadlineCancelsWireRead(t *testing.T) {
	entered, canceled := make(chan struct{}, 8), make(chan struct{}, 8)
	var queries atomic.Int32
	fixture := newFixture(t, fixtureHandlers{
		session: func(_ *protocol.SessionRequest, stream grpc.ServerStreamingServer[protocol.SessionReply]) error {
			recordTest(t, entered, struct{}{})
			<-stream.Context().Done()
			recordTest(t, canceled, struct{}{})
			return stream.Context().Err()
		},
		query: func(context.Context, *protocol.CatalogQueryRequest) (*protocol.CatalogQueryReply, error) {
			queries.Add(1)
			return nil, errors.New("unconfirmed login reached Query")
		},
	})
	client := fixtureClient(t, fixture, Options{Plaintext: true, Key: "key", Secret: []byte("secret"), Timeout: 100 * time.Millisecond})
	publisher, cause := client.Publisher(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		_, cause := publisher.Update(ctx, []Entry{{Key: "blocked"}}, time.Second)
		finished <- cause
	}()
	receiveTest(t, entered)
	receiveTest(t, canceled)
	cause = receiveTest(t, finished)
	requireCode(t, cause, CodeTimeout, Unapplied)
	if !errors.Is(cause, context.DeadlineExceeded) || queries.Load() != 0 || strings.Contains(cause.Error(), "secret") {
		t.Fatal("initial deadline lost its context cause, exposed credentials or submitted business work")
	}
	client.Close()
	if cause := client.Wait(testContext(t)); cause != nil {
		t.Fatal(cause)
	}
}
