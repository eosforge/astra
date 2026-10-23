// Verify authority ambiguity, malformed unary forwarding and freshness after irreversible backend closure.
package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/internal/generated/comet"
	"github.com/eosforge/astra/internal/generated/orbit"
	"github.com/eosforge/astra/internal/generated/polaris"
)

// evidence records only assertions reached by one named contract scenario.
func evidence(t *testing.T, contract string) func(bool, string) {
	t.Helper()
	hits := 0
	t.Cleanup(func() { t.Logf(`ASTRA-CONTRACT {"contract":%q,"hits":%d}`, contract, hits) })
	return func(ok bool, message string) {
		t.Helper()
		hits++
		if !ok {
			t.Fatal(message)
		}
	}
}

// TestSelection preserves ambiguity when later directory inputs omit previously known authorities.
func TestSelection(t *testing.T) {
	check := evidence(t, "ASTROLABE-TARGET")
	service := &authority{}
	backend, owner, first := transport(t, service)
	second, third := proto.Clone(first).(*orbit.Member), proto.Clone(first).(*orbit.Member)
	second.Id, second.Principal, second.Advertise = []byte("second"), bytes.Repeat([]byte{42}, 32), "127.0.0.1:65534"
	third.Id, third.Principal, third.Advertise = []byte("third"), bytes.Repeat([]byte{43}, 32), "127.0.0.1:65533"
	authorities := []*orbit.Member{first, second, third}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for _, state := range []struct {
		incoming int // Authorities in the next directory response.
		known    int // Monotonic retained authority count required by Directory.Install.
	}{{1, 1}, {2, 2}, {3, 3}, {1, 3}, {0, 3}, {1, 3}} {
		members := append([]*orbit.Member{owner.Member()}, authorities[:state.incoming]...)
		check(owner.Directory().Install(members) == nil, "could not publish the declared authority directory")
		old := backend.target
		backend.Update(nil)
		check((backend.target != nil) == (state.known == 1), "ambiguous authority became a write target after an incomplete observation")
		check(old == nil || old == backend.target || old.channel.GetState() == connectivity.Shutdown, "withdrawn authority retained its connection")
		before := service.lists.Load()
		result, err := backend.List(ctx)
		if state.known == 1 {
			check(err == nil && result != nil && result.Complete && service.lists.Load() == before+1, "sole authority did not recover through the real transport")
		} else {
			check(result == nil && status.Code(err) == codes.Unavailable && service.lists.Load() == before, "refusal contacted an arbitrary authority")
		}
		check(!backend.stale && !backend.observed.IsZero() && len(backend.nodes) == state.known+1, "directory ambiguity was confused with failed observation or member removal")
	}
}

// TestCommitInput requires malformed unary requests to reach the authority once without batch reinterpretation.
func TestCommitInput(t *testing.T) {
	good := &polaris.CommitRequest{Scope: &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}, Version: 1, Change: &comet.AlmanacChange{Key: "a", Action: &comet.AlmanacChange_Value{Value: []byte("public")}}}
	mixed := proto.Clone(good).(*polaris.CommitRequest)
	mixed.Changes = []*comet.AlmanacChange{proto.Clone(good.Change).(*comet.AlmanacChange)}
	for _, input := range []struct {
		name string                 // Stable malformed shape.
		body *polaris.CommitRequest // Input supplied to the public bridge operation.
		wire *polaris.CommitRequest // Expected protobuf representation at the authority.
	}{
		{"nil", nil, &polaris.CommitRequest{}},
		{"mixed", mixed, mixed},
	} {
		t.Run(input.name, func(t *testing.T) {
			check := evidence(t, "ASTROLABE-TRANSPORT")
			rejected := make(chan *polaris.CommitRequest, 1)
			service := &authority{commit: func(_ context.Context, received *polaris.CommitRequest) (*polaris.Position, error) {
				if proto.Equal(received, good) {
					return &polaris.Position{Scope: received.Scope, Version: received.Version}, nil
				}
				select {
				case rejected <- received:
				default:
					return nil, status.Error(codes.Internal, "unexpected repeated request")
				}
				return nil, status.Error(codes.InvalidArgument, "invalid commit shape")
			}}
			backend, _, _ := transport(t, service)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			before := proto.Clone(input.body)
			result, err := backend.Commit(ctx, input.body)
			check(result == nil && status.Code(err) == codes.InvalidArgument, "malformed request did not preserve authority rejection")
			select {
			case received := <-rejected:
				check(proto.Equal(received, input.wire), "bridge changed the rejected request before authority validation")
			case <-ctx.Done():
				t.Fatal("authority did not observe the rejected request")
			}
			check(service.commits.Load() == 1 && service.batches.Load() == 0, "malformed request was retried or converted to a batch")
			check(proto.Equal(before, input.body), "bridge mutated caller-owned input")
			result, err = backend.Commit(ctx, good)
			check(err == nil && result != nil && result.Version == 1 && proto.Equal(result.Scope, good.Scope), "healthy unary request did not recover")
			check(service.commits.Load() == 2 && service.batches.Load() == 0, "recovery did not perform exactly one unary request")
		})
	}
}

// TestClosedView makes closure alone invalidate a fresh directory and matching metrics without rewriting snapshots.
func TestClosedView(t *testing.T) {
	check := evidence(t, "ASTROLABE-METRICS")
	now := time.Now().UTC()
	backend := &Backend{observed: now, nodes: []node{{ID: "star", Role: "ROLE_STAR", Endpoint: "127.0.0.1:7447"}}, metrics: map[string]metric{"127.0.0.1:7447": {ID: "star", Observed: now, Attempted: now}}}
	nodes, metrics := backend.Nodes(), backend.Metrics()
	for _, closed := range []bool{false, true} {
		if closed {
			backend.Close()
		}
		data, err := json.Marshal(backend.Nodes())
		check(err == nil, "could not encode directory observation")
		var directory struct {
			Stale bool `json:"stale"` // Public directory freshness.
		}
		check(json.Unmarshal(data, &directory) == nil && directory.Stale == closed, "closure did not independently invalidate directory freshness")
		data, err = json.Marshal(backend.Metrics())
		check(err == nil, "could not encode metrics observation")
		var observed struct {
			Samples []metric `json:"samples"` // Public immutable observations.
		}
		check(json.Unmarshal(data, &observed) == nil && len(observed.Samples) == 1 && observed.Samples[0].Stale == closed, "closure did not independently invalidate metric freshness")
	}
	for _, snapshot := range []any{nodes, metrics} {
		data, err := json.Marshal(snapshot)
		check(err == nil && !bytes.Contains(data, []byte(`"stale":true`)), "closure mutated an already captured observation")
	}
	check(!backend.stale && !backend.metrics["127.0.0.1:7447"].Stale, "projection rewrote the underlying fresh observation")
}
