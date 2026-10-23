// Authenticate one active Star and fence operations to their captured binding.
package comet

import (
	"bytes"
	"context"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// binding is a captured connection/session generation. A new Session always
// creates a different pointer, even when its endpoint and instance stay equal.
type binding struct {
	endpoint   string                 // Exact configured address, retained across Session replacements.
	ctx        context.Context        // This exact transport/Session generation's cancellation.
	cancel     context.CancelFunc     // Cancels all operations captured by this binding.
	streams    *grpc.ClientConn       // Independent HTTP/2 pool for Session and Watches.
	unary      *grpc.ClientConn       // Shared unary pool, separate from long-lived streams.
	target     atomic.Pointer[string] // Empty until a valid anonymous response pins it.
	session    string                 // Immutable 32-byte credential; never public or formatted.
	credential []byte                 // Private login copy, cleared after the Session/transport drains.
	failure    *Error                 // Set/read only under Client.mu for explicit invalidation.
	healthy    atomic.Bool            // Valid business progress, not merely TCP readiness.
}

// instance returns the pinned target; an anonymous first request may be empty.
func (selected *binding) instance() string {
	if target := selected.target.Load(); target != nil {
		return *target
	}
	return ""
}

// accept pins the first valid instance and rejects later inconsistent responses.
func (selected *binding) accept(instance string) bool {
	if !validText(instance, 128) {
		return false
	}
	if target := selected.target.Load(); target != nil {
		return *target == instance
	}
	return selected.target.CompareAndSwap(nil, &instance) || selected.instance() == instance
}

// context links a single operation to this binding and attaches only the SDK's
// session metadata; application metadata is not allowed to forge that credential.
func (selected *binding) context(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := linkedContext(parent, selected.ctx)
	trailer := metadata.MD{}
	if selected.session != "" {
		trailer.Set("comet-session-bin", selected.session)
	}
	return metadata.NewOutgoingContext(ctx, trailer), cancel
}

// transport creates an explicitly addressed connection without remote service
// configs, client retries, Health/Inspect RPCs or implicit credential fallback.
func (client *Client) transport(endpoint string) (*grpc.ClientConn, error) {
	var security credentials.TransportCredentials = credentials.NewTLS(client.trust.Clone())
	if client.options.Plaintext {
		security = insecure.NewCredentials()
	}
	return grpc.NewClient("passthrough:///"+endpoint,
		grpc.WithTransportCredentials(security), grpc.WithDisableServiceConfig(), grpc.WithDisableRetry(),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 2 * time.Hour, Timeout: 20 * time.Second}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(8*maxPayload), grpc.MaxCallSendMsgSize(4*maxPayload)),
	)
}

// ready waits for transport establishment within the existing confirmation budget.
func ready(ctx context.Context, connection *grpc.ClientConn) bool {
	connection.Connect()
	for {
		state := connection.GetState()
		if state == connectivity.Ready {
			return true
		}
		if state == connectivity.Shutdown || !connection.WaitForStateChange(ctx, state) {
			return false
		}
	}
}

// connect owns endpoint rotation, login admission and the live Session receiver.
func (client *Client) connect() {
	defer client.manager.Done()
	index, failures := 0, uint(0)
	for client.ctx.Err() == nil {
		client.mu.Lock()
		if client.closed.Load() {
			client.mu.Unlock()
			return
		}
		if client.blocked != nil {
			changed := client.changed
			client.mu.Unlock()
			select {
			case <-changed:
				continue
			case <-client.ctx.Done():
				return
			}
		}
		secret, serial := bytes.Clone(client.secret), client.serial // Independent login copy, cleared after its final user.
		client.mu.Unlock()
		selected, session, failure := client.login(client.options.Endpoints[index], secret)
		if selected != nil {
			selected.credential = secret
		} else {
			wipe(secret)
		}
		confirmed := failure == nil
		if confirmed {
			client.mu.Lock()
			if client.closed.Load() {
				selected.cancel()
			} else {
				client.binding = selected
				client.signalLocked()
			}
			client.mu.Unlock()
			if session == nil {
				<-selected.ctx.Done()
				failure = localError(CodeTransport)
			} else {
				// The protocol admits exactly one Session confirmation, followed by EOF.
				_, cause := session.Recv()
				if cause == nil {
					failure = localError(CodeProtocol)
				} else {
					failure = rpcError(cause, session.Trailer())
				}
			}
		}
		if selected != nil {
			client.mu.Lock()
			if selected.failure != nil {
				failure = selected.failure
			}
			if client.binding == selected {
				client.binding = nil
				client.signalLocked()
			}
			client.mu.Unlock()
			selected.cancel()
			selected.streams.Close()
			selected.unary.Close()
			wipe(selected.credential)
			selected.credential = nil
			if selected.healthy.Load() {
				failures = 0
			}
		}
		if client.ctx.Err() != nil || client.closed.Load() {
			return
		}
		client.mu.Lock()
		changedSecret := serial != client.serial
		// Established invalidation relogs in; only a definite new-login rejection pauses.
		if !changedSecret && (!confirmed && failure.Code == CodeSession || permanent(failure.Code)) {
			client.blocked = copyError(failure)
			client.signalLocked()
		}
		client.mu.Unlock()
		if changedSecret {
			continue
		}
		if failure.Code == CodeTransport || failure.Code == CodeTimeout || failure.Code == CodeInstance {
			index = (index + 1) % len(client.options.Endpoints)
		}
		if !pause(client.ctx, backoff(failures)) {
			return
		}
		failures = min(failures+1, 6)
	}
}

// login uses one initial deadline while leaving the established stream unbounded.
func (client *Client) login(endpoint string, secret []byte) (*binding, grpc.ServerStreamingClient[protocol.SessionReply], *Error) {
	streams, cause := client.transport(endpoint)
	if cause != nil {
		return nil, nil, localError(CodeInput)
	}
	unary, cause := client.transport(endpoint)
	if cause != nil {
		streams.Close()
		return nil, nil, localError(CodeInput)
	}
	ctx, cancel := context.WithCancel(client.ctx)
	selected := &binding{ctx: ctx, cancel: cancel, streams: streams, unary: unary, endpoint: endpoint}
	// Stop the deadline timer after confirmation; do not set a lifetime RPC deadline.
	deadline := newDeadline(cancel)
	deadline.arm(client.options.Timeout)
	defer deadline.stop()
	if !ready(ctx, streams) || !ready(ctx, unary) {
		return selected, nil, localError(CodeTimeout)
	}
	if client.options.Anonymous {
		if !deadline.disarm() || ctx.Err() != nil {
			return selected, nil, localError(CodeTimeout)
		}
		return selected, nil, nil
	}
	session, cause := protocol.NewGatewayClient(streams).Session(ctx, &protocol.SessionRequest{Key: client.options.Key, Secret: secret})
	if cause != nil {
		if deadline.expired() {
			return selected, nil, localError(CodeTimeout)
		}
		return selected, nil, rpcError(cause, nil)
	}
	reply, cause := session.Recv()
	if cause != nil {
		if deadline.expired() {
			return selected, nil, localError(CodeTimeout)
		}
		return selected, nil, rpcError(cause, session.Trailer())
	}
	if reply == nil || !selected.accept(string(reply.Instance)) || len(reply.Session) != 32 {
		return selected, nil, localError(CodeProtocol)
	}
	selected.session = string(reply.Session)
	if !deadline.disarm() || ctx.Err() != nil {
		return selected, nil, localError(CodeTimeout)
	}
	return selected, session, nil
}
