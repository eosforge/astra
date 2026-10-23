// Package bridge connects the Pulsar directory to the single Polaris authority without depending on Comet Go or copying authoritative state.
package bridge

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/eosforge/astra/internal/admission"
	"github.com/eosforge/astra/internal/generated/comet"
	"github.com/eosforge/astra/internal/generated/orbit"
	"github.com/eosforge/astra/internal/generated/polaris"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Backend swaps directory observations and connections under short locks; RPCs, network waits and channel closure run outside them.
type Backend struct {
	node     *admission.Node     // Immutable admission owner supplying directory and session context.
	identity *admission.Identity // Immutable process identity used to construct TLS credentials.
	mutex    sync.RWMutex
	target   *target           // Current Polaris target; nil when no unique authority is available.
	observed time.Time         // Local time of the last directory observation, used to report freshness.
	stale    bool              // Set after an observation fails or the directory changes.
	closed   bool              // Set once; prevents subsequent connection creation or replacement.
	nodes    []node            // Immutable projection rebuilt on directory refresh, avoiding per-request Member clones.
	members  map[string]string // Endpoint-to-instance index used to reject stale samples in constant time.
	metrics  map[string]metric // Latest samples for explicitly deployed endpoints; no time series or arbitrary business labels.
}

// target owns one Polaris member, channel and client; replacement swaps the whole set.
type target struct {
	member  *orbit.Member
	channel *grpc.ClientConn // Released outside the backend lock on replacement or shutdown.
	client  polaris.AuthorityClient
}

// New waits for Update to confirm a unique authority before connecting; it does not register a node.
func New(node *admission.Node, identity *admission.Identity) *Backend {
	return &Backend{node: node, identity: identity, stale: true}
}

// Update handles directory refreshes. Failure retains a stale target; multiple authorities never select an arbitrary winner.
// A non-nil observation reports a failed directory refresh and only marks the existing target stale.
func (backend *Backend) Update(observation error) {
	if observation != nil {

		backend.mutex.Lock()
		backend.stale = true
		backend.mutex.Unlock()
		return
	}

	members := backend.node.Directory().Members()
	var member *orbit.Member
	multiple := false
	nodes := make([]node, 0, len(members))
	index := make(map[string]string, len(members))
	for _, candidate := range members {
		nodes = append(nodes, describe(candidate))
		index[candidate.Advertise] = string(candidate.Id)
		if candidate.Role == orbit.Role_ROLE_POLARIS {
			multiple = multiple || member != nil
			member = candidate
		}
	}
	if multiple {
		member = nil
	}
	// Publish the directory and target decision atomically; perform any dialing outside the lock.
	backend.mutex.Lock()
	backend.observed, backend.stale, backend.nodes = time.Now(), false, nodes
	backend.members = index
	unchanged := backend.target != nil && member != nil && bytes.Equal(backend.target.member.Id, member.Id)
	closed := backend.closed
	backend.mutex.Unlock()
	if unchanged || closed {

		return
	}
	if member == nil {
		// Remove a missing or ambiguous authority so requests fail explicitly instead of using an expired connection.
		backend.replace(nil)
		return
	}
	// Disable transport retries: callers own write-result semantics. Message limits bound management-page memory.
	channel, err := grpc.NewClient("passthrough:///"+member.Advertise, grpc.WithTransportCredentials(credentials.NewTLS(backend.identity.Client())), grpc.WithDisableRetry(), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(8<<20), grpc.MaxCallSendMsgSize(2<<20)))
	if err != nil {
		backend.replace(nil)
		return
	}
	backend.replace(&target{member: member, channel: channel, client: polaris.NewAuthorityClient(channel)})
}

// replace closes the old channel outside the lock; interrupted writes remain uncertain and are never resent to the new instance.
// A nil next target clears the authority during shutdown or loss of a unique candidate.
func (backend *Backend) replace(next *target) {
	backend.mutex.Lock()
	if backend.closed {

		backend.mutex.Unlock()
		if next != nil {
			_ = next.channel.Close()
		}
		return
	}
	old := backend.target
	backend.target = next
	backend.mutex.Unlock()
	if old != nil {

		_ = old.channel.Close()
	}
}

// Close cancels owned RPCs idempotently. Stop background Update calls before closing Node.
func (backend *Backend) Close() {
	backend.mutex.Lock()
	backend.closed = true
	old := backend.target
	backend.target = nil
	backend.mutex.Unlock()
	if old != nil {
		_ = old.channel.Close()
	}
}

// begin captures the current target and admitted metadata, avoiding a Pulsar login or lookup for every browser request.
// Derive a context from the caller's request and reject closed, absent or replaced targets before dispatch.
func (backend *Backend) begin(ctx context.Context) (context.Context, polaris.AuthorityClient, error) {

	backend.mutex.RLock()
	current, closed := backend.target, backend.closed
	backend.mutex.RUnlock()
	if closed || current == nil || !backend.node.Directory().Current(current.member) {

		return nil, nil, status.Error(codes.Unavailable, "Authority target unavailable")
	}
	ctx, err := backend.node.Context(ctx)
	if err != nil {
		return nil, nil, err
	}
	return ctx, current.client, nil
}

// Commit sends exactly one RPC; it neither rewrites the expected version nor waits for every Star to synchronize.
// Return the authority-confirmed position. Callers decide retries from the operation's position semantics.
func (backend *Backend) Commit(ctx context.Context, request *polaris.CommitRequest) (*polaris.Position, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, client, err := backend.begin(ctx)
	if err != nil {
		return nil, err
	}
	if request == nil || len(request.Changes) == 0 || request.Change != nil {
		return client.Commit(ctx, request)
	}
	stream, err := client.Batch(ctx)
	if err != nil {
		return nil, err
	}
	// Aim for 256 KiB pages; a large value occupies its own page, so a snapshot can exceed one frame's size limit.
	page := &polaris.BatchRequest{Scope: request.Scope, Version: request.Version}
	size := proto.Size(page) + 16
	for _, change := range request.Changes {
		cost := proto.Size(change) + 6
		if len(page.Changes) != 0 && size+cost > 256<<10 {
			if err := stream.Send(page); err != nil {
				return nil, err
			}
			page = &polaris.BatchRequest{Scope: request.Scope, Version: request.Version}
			size = proto.Size(page) + 16
		}
		page.Changes = append(page.Changes, change)
		size += cost
	}
	page.Complete = true
	if err := stream.Send(page); err != nil {
		return nil, err
	}
	return stream.CloseAndRecv()
}

// List reads authoritative scope metadata rather than inferring management state from a Star cache.
func (backend *Backend) List(ctx context.Context) (*polaris.Inventory, error) {
	ctx, client, err := backend.begin(ctx)
	if err != nil {
		return nil, err
	}
	return client.List(ctx, &comet.Empty{})
}

// Load owns its derived context; HTTP disconnection or validation failure cancels only this request's gRPC stream.
// Receive snapshot pages for scope until EOF or a receive callback returns an error.
func (backend *Backend) Load(ctx context.Context, scope *comet.Scope, receive func(*polaris.Snapshot) error) error {

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, client, err := backend.begin(ctx)
	if err != nil {
		return err
	}
	stream, err := client.Load(ctx, scope)
	if err != nil {
		return err
	}

	for {
		page, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := receive(page); err != nil {
			return err
		}
	}
}

// node is a fixed public projection without principals, signed payloads, signatures or account material.
type node struct {
	ID       string `json:"id"`
	Role     string `json:"role"`
	Galaxy   string `json:"galaxy"`
	Group    string `json:"group"` // Display group; does not participate in routing.
	Endpoint string `json:"endpoint"`
	Epoch    string `json:"epoch"` // Decimal string representation preserves all uint64 epoch bits in JSON.
}

func describe(member *orbit.Member) node {
	return node{string(member.Id), member.Role.String(), member.Galaxy, member.Group, member.Advertise, strconv.FormatUint(member.Epoch, 10)}
}

// Nodes returns an immutable redacted projection. Observation freshness is not node liveness; requests do not clone all Protobuf members.
func (backend *Backend) Nodes() any {
	backend.mutex.RLock()
	nodes, observed, stale := backend.nodes, backend.observed, backend.stale || backend.closed
	backend.mutex.RUnlock()
	if nodes == nil {
		nodes = []node{}
	}
	return struct {
		Nodes    []node    `json:"nodes"`
		Observed time.Time `json:"observed"`
		Stale    bool      `json:"stale"`
	}{nodes, observed.UTC(), stale || observed.IsZero()}
}
