// Own Go control-plane node admission and peer connectivity state.

package admission

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	randv2 "math/rand/v2"
	"sync"
	"time"

	"github.com/eosforge/astra/internal/generated/astra"
	"github.com/eosforge/astra/internal/generated/orbit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Node owns one startup idempotency key and control-plane Channel; gate prevents overlapping registration/refresh calls.
type Node struct {
	identity  *Identity
	directory *Directory
	channel   *grpc.ClientConn
	client    orbit.AdmissionClient
	request   *orbit.RegistrationRequest
	gate      chan struct{}
	mutex     sync.RWMutex
	member    *orbit.Member
	hello     *astra.Hello
}

// Open prepares resources without RPCs; super/advertise require canonical numeric endpoints and role must be Polaris/Astrolabe.
func Open(identity *Identity, super, galaxy, advertise, group string, role orbit.Role) (*Node, error) {
	if _, err := Endpoint(super); err != nil {
		return nil, err
	}
	if _, err := Endpoint(advertise); err != nil || identity == nil || !Name(galaxy) || !Name(group) || role != orbit.Role_ROLE_POLARIS && role != orbit.Role_ROLE_ASTROLABE {
		return nil, ErrIdentity
	}
	directory, err := NewDirectory(identity, galaxy, role, 16384)
	if err != nil {
		return nil, err
	}
	startup := make([]byte, 32)
	if _, err := rand.Read(startup); err != nil {
		return nil, ErrIdentity
	}
	channel, err := grpc.NewClient(super, grpc.WithTransportCredentials(credentials.NewTLS(identity.Client())), grpc.WithDisableRetry(), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(8<<20), grpc.MaxCallSendMsgSize(4096)))
	if err != nil {
		return nil, err
	}
	return &Node{identity: identity, directory: directory, channel: channel, client: orbit.NewAdmissionClient(channel), gate: make(chan struct{}, 1), request: &orbit.RegistrationRequest{Galaxy: galaxy, Advertise: advertise, Role: role, Group: group, Username: identity.username, Password: identity.password, RequestId: startup}}, nil
}

// Close cancels Channel calls; caller must first cancel and await its own Join/Refresh loops.
func (node *Node) Close() error { return node.channel.Close() }

// Directory returns shared controlled access without writable internal Members or locks.
func (node *Node) Directory() *Directory { return node.directory }

// Hello returns an independent credential frame only after registration, otherwise nil.
func (node *Node) Hello() *astra.Hello {
	node.mutex.RLock()
	defer node.mutex.RUnlock()
	if node.hello == nil {
		return nil
	}
	return proto.Clone(node.hello).(*astra.Hello)
}

// Member returns an independent current-process identity; later directory changes cannot silently replace it.
func (node *Node) Member() *orbit.Member {
	node.mutex.RLock()
	defer node.mutex.RUnlock()
	if node.member == nil {
		return nil
	}
	return proto.Clone(node.member).(*orbit.Member)
}

// Context adds raw admission metadata without account/password; caller must not supply the same field already.
func (node *Node) Context(ctx context.Context) (context.Context, error) {
	hello := node.Hello()
	if hello == nil {
		return nil, status.Error(codes.Unavailable, "Infrastructure admission pending")
	}
	values, _ := metadata.FromOutgoingContext(ctx)
	if len(values.Get("astra-admission-bin")) != 0 || len(values.Get("astra-signature-bin")) != 0 {
		return nil, ErrIdentity
	}
	return metadata.AppendToOutgoingContext(ctx, "astra-admission-bin", string(hello.Admission), "astra-signature-bin", string(hello.AdmissionSignature)), nil
}

// Register performs one finite attempt; timeout retries reuse this object and success ends password registration.
func (node *Node) Register(ctx context.Context) error {
	select {
	case node.gate <- struct{}{}:
		defer func() { <-node.gate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if node.Member() != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	response, err := node.client.Register(ctx, node.request)
	if err != nil {
		return err
	}
	member, err := node.identity.Verify(response.Admission, response.Signature)
	if err != nil || member.Galaxy != node.request.Galaxy || member.Role != node.request.Role || member.Group != node.request.Group || member.Advertise != node.request.Advertise || !bytes.Equal(member.Principal, node.identity.Principal(node.request.Galaxy, node.request.Advertise)) {
		return ErrIdentity
	}
	if !slicesContains(response.Members, member) {
		return ErrIdentity
	}
	if err := node.directory.Install(response.Members); err != nil {
		return err
	}
	if !node.directory.Current(member) {
		return ErrIdentity
	}
	node.mutex.Lock()
	node.member = member
	node.hello = &astra.Hello{ProtocolMajor: 1, MaxFrameBytes: 8 << 20, Admission: response.Admission, AdmissionSignature: response.Signature}
	node.mutex.Unlock()
	return nil
}

// Refresh reads one complete directory under the shared registration gate; explicit revocation never creates a new startup key.
func (node *Node) Refresh(ctx context.Context) error {
	select {
	case node.gate <- struct{}{}:
		defer func() { <-node.gate }()
	case <-ctx.Done():
		return ctx.Err()
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ctx, err := node.Context(ctx)
	if err != nil {
		return err
	}
	response, err := node.client.List(ctx, &orbit.DirectoryRequest{})
	if err != nil {
		return err
	}
	member := node.Member()
	if !slicesContains(response.Members, member) {
		return status.Error(codes.Unauthenticated, "Process admission replaced")
	}
	if err := node.directory.Install(response.Members); err != nil {
		return err
	}
	if !node.directory.Current(member) {
		return status.Error(codes.Unauthenticated, "Process admission replaced")
	}
	return nil
}

// Join retries with bounded backoff until registration or context completion; permanent rejection returns without replacing the startup key.
func (node *Node) Join(ctx context.Context) error {
	return node.join(ctx, pause)
}

// join separates waiting from retry transitions without supplying RPC synchronization.
func (node *Node) join(ctx context.Context, wait func(context.Context, time.Duration) error) error {
	delay := 500 * time.Millisecond
	for {
		err := node.Register(ctx)
		if err == nil || fatal(err) {
			return err
		}
		// Preserve permanent refusals and completed admission, but expose the owner's cancellation cause.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := wait(ctx, delay); err != nil {
			return err
		}
		delay = min(delay*2, 30*time.Second)
	}
}

// Run refreshes infrequently, once per process; changed must return promptly and must not reenter Register/Refresh.
// Temporary failure retains complete directory and backs off; permanent identity rejection returns so the host can stop new management work.
func (node *Node) Run(ctx context.Context, changed func(error)) error {
	return node.run(ctx, changed, pause)
}

// run permits explicit logical time while preserving refresh and callback order.
func (node *Node) run(ctx context.Context, changed func(error), wait func(context.Context, time.Duration) error) error {
	delay := 30 * time.Second
	for {
		if err := wait(ctx, delay); err != nil {
			return err
		}
		err := node.Refresh(ctx)
		if changed != nil {
			changed(err)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if fatal(err) {
			return err
		}
		if err == nil {
			delay = 30 * time.Second
		} else {
			delay = min(delay*2, 2*time.Minute)
		}
	}
}

// slicesContains compares defined identity fields only, excluding pointer identity and unknown protocol fields.
func slicesContains(members []*orbit.Member, local *orbit.Member) bool {
	for _, member := range members {
		if same(member, local) {
			return true
		}
	}
	return false
}

// fatal distinguishes permanent identity/argument failures from temporary outages without retrying password rejection forever.
func fatal(err error) bool {
	return errors.Is(err, ErrIdentity) || status.Code(err) == codes.Unauthenticated || status.Code(err) == codes.PermissionDenied || status.Code(err) == codes.InvalidArgument || status.Code(err) == codes.Aborted
}

// pause provides cancelable jittered backoff; math/rand is scheduling-only, never credentials or startup IDs.
func pause(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay + time.Duration(randv2.Int64N(int64(delay/5)+1)))
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
