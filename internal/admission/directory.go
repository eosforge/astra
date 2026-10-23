// Maintain the admitted peer directory and its identity and endpoint relationships.

package admission

import (
	"bytes"
	"context"
	"slices"
	"sync"

	"github.com/eosforge/astra/internal/generated/orbit"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Directory retains the highest observed identity per deployment; omissions or outages erase neither replacement history nor business data.
// Directory installs and handshakes share a commit lock so late queries cannot replace newer verified credentials.
type Directory struct {
	mutex    sync.RWMutex
	identity *Identity
	galaxy   string
	role     orbit.Role
	maximum  int
	known    map[string]*orbit.Member
}

// NewDirectory bounds all known deployment slots by maximum, 1..16384, including offline Members.
func NewDirectory(identity *Identity, galaxy string, role orbit.Role, maximum int) (*Directory, error) {
	if identity == nil || !Name(galaxy) || !Role(role) || role == orbit.Role_ROLE_PLANET || maximum < 1 || maximum > 16384 {
		return nil, ErrIdentity
	}
	return &Directory{identity: identity, galaxy: galaxy, role: role, maximum: maximum, known: make(map[string]*orbit.Member)}, nil
}

// Install validates the whole directory outside the lock, then merges observed handshake identities under lock; conflicts preserve complete prior state.
func (directory *Directory) Install(members []*orbit.Member) error {
	if len(members) > directory.maximum {
		return status.Error(codes.ResourceExhausted, "Directory capacity exceeded")
	}
	prepared := make(map[string]*orbit.Member, len(members))
	addresses := make(map[string]bool, len(members))
	var previous []byte
	for index, member := range members {
		if !Valid(member) || member.Galaxy != directory.galaxy || directory.role != orbit.Role_ROLE_ASTROLABE && member.Role != orbit.Role_ROLE_STAR && member.Role != orbit.Role_ROLE_POLARIS || index != 0 && bytes.Compare(previous, member.Id) >= 0 || prepared[string(member.Principal)] != nil || addresses[member.Advertise] {
			return ErrIdentity
		}
		previous = member.Id
		addresses[member.Advertise] = true
		prepared[string(member.Principal)] = proto.Clone(member).(*orbit.Member)
	}
	directory.mutex.Lock()
	defer directory.mutex.Unlock()
	for principal, old := range directory.known {
		incoming := prepared[principal]
		if incoming == nil || incoming.Epoch < old.Epoch {
			prepared[principal] = old
			continue
		}
		if incoming.Epoch == old.Epoch && !same(incoming, old) || incoming.Role != old.Role || incoming.Advertise != old.Advertise || incoming.Epoch > old.Epoch && bytes.Equal(incoming.Id, old.Id) {
			return ErrIdentity
		}
	}
	if len(prepared) > directory.maximum {
		return status.Error(codes.ResourceExhausted, "Directory capacity exceeded")
	}
	// Recheck aliases after merging so new addresses/IDs cannot conflict with retained omitted deployments.
	clear(addresses)
	ids := make(map[string]bool, len(prepared))
	for _, member := range prepared {
		if addresses[member.Advertise] || ids[string(member.Id)] {
			return ErrIdentity
		}
		addresses[member.Advertise], ids[string(member.Id)] = true, true
	}
	directory.known = prepared
	return nil
}

// observe accepts Verify-validated handshake identities without letting unknown/stale credentials regress state or create aliases.
func (directory *Directory) observe(member *orbit.Member) error {
	directory.mutex.Lock()
	defer directory.mutex.Unlock()
	old := directory.known[string(member.Principal)]
	if old != nil {
		if member.Epoch < old.Epoch || member.Epoch == old.Epoch && !same(member, old) || member.Role != old.Role || member.Advertise != old.Advertise || member.Epoch > old.Epoch && bytes.Equal(member.Id, old.Id) {
			return ErrIdentity
		}
		if same(member, old) {
			return nil
		}
	} else if len(directory.known) == directory.maximum {
		return status.Error(codes.ResourceExhausted, "Directory capacity exceeded")
	}
	for principal, known := range directory.known {
		if principal != string(member.Principal) && (bytes.Equal(known.Id, member.Id) || known.Advertise == member.Advertise) {
			return ErrIdentity
		}
	}
	directory.known[string(member.Principal)] = proto.Clone(member).(*orbit.Member)
	return nil
}

// Verify checks first-frame or management-metadata signatures and allowed roles, recording trusted replacement without a live Pulsar query.
func (directory *Directory) Verify(data, signature []byte, roles ...orbit.Role) (*orbit.Member, error) {
	member, err := directory.identity.Verify(data, signature)
	if err != nil || member.Galaxy != directory.galaxy || !slices.Contains(roles, member.Role) {
		return nil, status.Error(codes.Unauthenticated, "Infrastructure admission rejected")
	}
	if err := directory.observe(member); err != nil {
		if status.Code(err) == codes.ResourceExhausted {
			return nil, err
		}
		return nil, status.Error(codes.Unauthenticated, "Infrastructure admission replaced or conflicting")
	}
	return member, nil
}

// Authorize requires one raw credential for each short management RPC; long streams verify their first frame only.
func (directory *Directory) Authorize(ctx context.Context, roles ...orbit.Role) (*orbit.Member, error) {
	values, _ := metadata.FromIncomingContext(ctx)
	data, signature := values.Get("astra-admission-bin"), values.Get("astra-signature-bin")
	if len(data) != 1 || len(signature) != 1 {
		return nil, status.Error(codes.Unauthenticated, "Current admission required")
	}
	return directory.Verify([]byte(data[0]), []byte(signature[0]), roles...)
}

// Current checks a signed identity against this process's known latest value, without claiming knowledge of every partitioned replacement.
func (directory *Directory) Current(member *orbit.Member) bool {
	if member == nil {
		return false
	}
	directory.mutex.RLock()
	defer directory.mutex.RUnlock()
	return same(directory.known[string(member.Principal)], member)
}

// Members returns independent messages in stable ID order; callers cannot mutate the directory, and ordering says nothing about live health.
func (directory *Directory) Members() []*orbit.Member {
	directory.mutex.RLock()
	defer directory.mutex.RUnlock()
	result := make([]*orbit.Member, 0, len(directory.known))
	for _, member := range directory.known {
		result = append(result, proto.Clone(member).(*orbit.Member))
	}
	slices.SortFunc(result, func(a, b *orbit.Member) int {
		return bytes.Compare(a.Id, b.Id)
	})
	return result
}

// same compares validated identity fields; unknown Protobuf fields do not create a new identity generation.
func same(a, b *orbit.Member) bool {
	return a != nil && b != nil && a.Galaxy == b.Galaxy && bytes.Equal(a.Id, b.Id) && bytes.Equal(a.Principal, b.Principal) && a.Advertise == b.Advertise && a.Epoch == b.Epoch && a.Role == b.Role && a.Group == b.Group
}
