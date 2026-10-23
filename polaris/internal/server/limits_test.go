// Verify refusal boundaries without partial installation, durable writes or lost resource ownership.
//go:build linux && cgo

package server

import (
	"context"
	"reflect"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/internal/admission"
	"github.com/eosforge/astra/internal/generated/comet"
	"github.com/eosforge/astra/internal/generated/orbit"
	"github.com/eosforge/astra/internal/generated/polaris"
	"github.com/eosforge/astra/polaris/internal/storage"
)

// TestPageCapacity checks both inclusive frame limits before any callback can observe a snapshot.
func TestPageCapacity(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string     // Required independently observed boundary.
		limit int        // Advertised maximum encoded frame size.
		code  codes.Code // Literal protocol outcome.
	}{
		{"negative", -1, codes.InvalidArgument},
		{"zero", 0, codes.InvalidArgument},
		{"below", 1023, codes.InvalidArgument},
		{"minimum", 1024, codes.OK},
		{"maximum", 8 << 20, codes.OK},
		{"above", 8<<20 + 1, codes.InvalidArgument},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := storage.Snapshot{Position: storage.Position{Scope: storage.Scope{Sector: "s", Spectrum: "p"}, Version: 7}}
			calls := 0
			err := pages(&snapshot, test.limit, func(page *polaris.Snapshot) error {
				calls++
				expected := &polaris.Snapshot{Scope: &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}, Version: proto.Uint64(7), Complete: true}
				if !proto.Equal(page, expected) {
					t.Fatal("frame capacity changed the empty snapshot contract")
				}
				return nil
			})
			want := 0
			if test.code == codes.OK {
				want = 1
			}
			if status.Code(err) != test.code || calls != want {
				t.Fatal("invalid capacity sent content or valid capacity lost its completion", err, calls)
			}
		})
	}
}

// TestInventoryInput refuses the whole initial inventory when a later frame has the wrong kind.
func TestInventoryInput(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"nil", "empty", "partial", "position-nil", "scope-nil"} {
		t.Run(name, func(t *testing.T) {
			state, wire, _ := recovery(t, 16, 1)
			state.input = make(chan incoming, 2)
			var packet *polaris.Packet
			if name != "nil" {
				packet = &polaris.Packet{}
			}
			if name == "partial" {
				scope := &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}
				state.input <- incoming{packet: &polaris.Packet{Body: &polaris.Packet_Inventory{Inventory: &polaris.Inventory{Positions: []*polaris.Position{{Scope: scope, Version: 1}}}}}}
				packet.Body = &polaris.Packet_Acknowledged{Acknowledged: &polaris.Position{Scope: scope, Version: 1}}
			}
			if name == "position-nil" || name == "scope-nil" {
				var entry *polaris.Position
				if name == "scope-nil" {
					entry = &polaris.Position{Version: 1}
				}
				packet.Body = &polaris.Packet_Inventory{Inventory: &polaris.Inventory{Complete: true, Positions: []*polaris.Position{entry}}}
			}
			state.input <- incoming{packet: packet}
			positions, err := state.inventory()
			if status.Code(err) != codes.InvalidArgument || positions != nil || len(state.input) != 0 || len(wire.packets) != 0 || state.deadline.Load() != nil {
				t.Fatal("malformed inventory escaped as a partial success or retained its deadline", err)
			}
		})
	}
}

// TestCreditCapacity separates the record limit from the byte budget and checks the exact acknowledged prefix.
func TestCreditCapacity(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"below", "full", "invalid"} {
		t.Run(name, func(t *testing.T) {
			state, wire, system := recovery(t, 256, 128)
			scope := storage.Scope{Sector: "s", Spectrum: "p"}
			before, err := system.store.Load(t.Context(), scope)
			if err != nil {
				t.Fatal(err)
			}
			// The fixed tiny charges cannot exhaust the independent eight-megabyte byte budget.
			count, acknowledged := 128, uint64(1)
			if name == "below" {
				count = 127
			} else if name == "invalid" {
				acknowledged = 129
			}
			state.installed[scope], state.sent[scope] = 0, storage.Version(count)
			state.credits, state.bytes = nil, int64(count)
			for index := 1; index <= count; index++ {
				state.credits = append(state.credits, credit{scope: scope, version: storage.Version(index), bytes: 1})
			}
			state.input <- incoming{packet: &polaris.Packet{Body: &polaris.Packet_Acknowledged{Acknowledged: &polaris.Position{Scope: &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}, Version: acknowledged}}}}
			err = state.budget(1)
			want, first, pending := codes.OK, 1, 0
			if name == "below" {
				pending = 1
			} else if name == "full" {
				first = 2
			} else {
				want = codes.InvalidArgument
			}
			if status.Code(err) != want || state.installed[scope] != storage.Version(first-1) || state.sent[scope] != storage.Version(count) || len(state.input) != pending {
				t.Fatal("credit admission consumed an unnecessary ACK, accepted invented progress or failed to release the acknowledged prefix", err)
			}
			if len(state.credits) != count-first+1 || state.bytes != int64(count-first+1) || len(wire.packets) != 0 || state.deadline.Load() != nil {
				t.Fatal("credit admission changed output, accounting or deadline ownership")
			}
			for index, item := range state.credits {
				if item != (credit{scope: scope, version: storage.Version(first + index), bytes: 1}) {
					t.Fatal("credit admission lost or reordered an unconfirmed boundary")
				}
			}
			after, err := system.store.Load(t.Context(), scope)
			if err != nil || !reflect.DeepEqual(before, after) || system.streams.authority.cache.used != 0 {
				t.Fatal("flow control changed durable content or retained preparation resources", err)
			}
		})
	}
}

// TestDrainBudget models an already-ready control backlog independently of the production one-frame receiver.
// Exactly sixteen frames may advance per call; the remainder and its credits must survive for the next call.
func TestDrainBudget(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string // Explicit terminal required by the parser.
		count int    // Ready acknowledgements, independent of scheduler timing.
	}{{"sixteen", 16}, {"seventeen", 17}} {
		t.Run(test.name, func(t *testing.T) {
			state, wire, system := recovery(t, 32, 17)
			scope := storage.Scope{Sector: "s", Spectrum: "p"}
			before, err := system.store.Load(t.Context(), scope)
			if err != nil {
				t.Fatal(err)
			}
			state.input = make(chan incoming, test.count)
			state.credits, state.bytes = nil, 0
			state.installed[scope] = 0
			for number := 1; number <= test.count; number++ {
				state.charge(scope, storage.Version(number), 1)
				state.input <- incoming{packet: &polaris.Packet{Body: &polaris.Packet_Acknowledged{Acknowledged: &polaris.Position{Scope: &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}, Version: uint64(number)}}}}
			}
			if err := state.drain(); err != nil || state.installed[scope] != 16 || len(state.input) != test.count-16 || state.bytes != int64(test.count-16) || len(state.credits) != test.count-16 {
				t.Fatal("drain exceeded its fairness budget or lost deferred acknowledgements", err)
			}
			if err := state.drain(); err != nil || state.installed[scope] != storage.Version(test.count) || len(state.input) != 0 || state.bytes != 0 || len(state.credits) != 0 || len(wire.packets) != 0 {
				t.Fatal("subsequent drain lost progress or leaked delivery credit", err)
			}
			after, err := system.store.Load(t.Context(), scope)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("control processing changed durable data", err)
			}
		})
	}
}

// revoking replaces admission exactly at a receive completion, including the final EOF boundary.
type revoking struct {
	upload         // Literal pages, read count and attempted final receipt.
	cut     int    // One-based receive boundary selected by the case.
	replace func() // Independently signed replacement, with no production scheduling hook.
}

// Recv invalidates the old identity before returning the selected page or EOF to the handler.
func (wire *revoking) Recv() (*polaris.BatchRequest, error) {
	page, err := wire.upload.Recv()
	if wire.reads == wire.cut {
		wire.replace()
	}
	return page, err
}

// TestBatchRevocation never commits a received prefix or a complete old-identity batch after revocation.
func TestBatchRevocation(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string // Initial page, partial-prefix continuation or finalization boundary.
		cut  int    // Deterministic receive completion at which admission changes.
	}{{"first", 1}, {"second", 2}, {"eof", 3}} {
		t.Run(test.name, func(t *testing.T) {
			system := environment(t, storage.Default())
			authority := system.streams.authority
			scope := storage.Scope{Sector: "s", Spectrum: "p"}
			if _, err := system.store.Commit(t.Context(), scope, storage.Change{Version: 1, Key: "key", Value: []byte("before")}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("astra-admission-bin", string(system.manager.Admission), "astra-signature-bin", string(system.manager.AdmissionSignature)))
			position := &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}
			wire := &revoking{upload: upload{capture: capture{ctx: ctx}, receipt: true, pages: []*polaris.BatchRequest{
				{Scope: position, Version: 2, Changes: []*comet.AlmanacChange{{Key: "key", Action: &comet.AlmanacChange_Value{Value: []byte("after")}}}},
				{Scope: position, Version: 2, Complete: true, Changes: []*comet.AlmanacChange{{Key: "other", Action: &comet.AlmanacChange_Value{Value: []byte("new")}}}},
			}}, cut: test.cut}
			wire.replace = func() {
				member := &orbit.Member{}
				if err := proto.Unmarshal(system.manager.Admission, member); err != nil {
					t.Fatal(err)
				}
				member.Epoch++
				member.Id = []byte("replacement")
				hello := system.issuer.sign(member)
				if _, err := system.node.Directory().Verify(hello.Admission, hello.AdmissionSignature, orbit.Role_ROLE_ASTROLABE); err != nil {
					t.Fatal(err)
				}
			}
			err := authority.Batch(wire)
			if status.Code(err) != codes.Unauthenticated || wire.reads != test.cut || wire.result != nil || len(authority.slots) != 0 || authority.cache.used != 0 {
				t.Fatal("revoked batch continued reading, acknowledged success or retained resources", err)
			}
			expected := storage.Snapshot{Position: storage.Position{Scope: scope, Version: 1}, Records: []storage.Record{{Key: "key", Value: []byte("before")}}}
			after, err := system.store.Load(t.Context(), scope)
			if err != nil || !reflect.DeepEqual(after, expected) {
				t.Fatal("revoked batch modified its durable prefix", err)
			}
		})
	}
}

// TestRecoveryLimits preserves other readers' snapshots when reconciliation cannot reserve preparation space.
func TestRecoveryLimits(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"snapshot", "new-scope"} {
		t.Run(name, func(t *testing.T) {
			state, wire, system := recovery(t, 16, 2)
			limits := system.store.Limits()
			reserve := limits.Bytes + limits.Records*128 + 2<<20
			authority, err := NewAuthority(system.store, system.node.Directory(), reserve)
			if err != nil {
				t.Fatal(err)
			}
			state.owner = NewStreams(system.node, authority)
			scope := storage.Scope{Sector: "s", Spectrum: "p"}
			actual := map[storage.Scope]storage.Version{}
			if name == "new-scope" {
				actual[scope] = 2
				if _, err := system.store.Commit(t.Context(), storage.Scope{Sector: "s", Spectrum: "q"}, storage.Change{Version: 1, Key: "new", Value: []byte("new")}); err != nil {
					t.Fatal(err)
				}
			} else {
				clear(state.installed)
			}
			if err := state.assess(); err != nil {
				t.Fatal(err)
			}
			wire.packets = nil
			held, err := authority.cache.acquire(state.ctx, scope, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer held.release()
			before := storage.Snapshot{Position: storage.Position{Scope: scope, Version: 2}, Records: []storage.Record{{Key: "key", Value: []byte{2}}}}
			err = state.reconcile(actual)
			if status.Code(err) != codes.ResourceExhausted || len(wire.packets) != 0 || state.boundary == nil || state.floor == nil || authority.cache.used != reserve || len(authority.cache.entries) != 1 || held.entry.references != 1 {
				t.Fatal("failed recovery reported completion or stole another reader's budget", err)
			}
			if !reflect.DeepEqual(*held.Snapshot, before) {
				t.Fatal("failed recovery damaged a retained snapshot")
			}
			held.release()
			if err := state.reconcile(actual); err != nil || state.boundary != nil || state.floor != nil || authority.cache.used != 0 || len(authority.cache.entries) != 0 || len(wire.packets) != 1 {
				t.Fatal("recovery did not resume after the independent reader released capacity", err)
			}
			target, version, key, value := "p", uint64(2), "key", []byte{2}
			if name == "new-scope" {
				target, version, key, value = "q", 1, "new", []byte("new")
			}
			expected := &polaris.Packet{Body: &polaris.Packet_Snapshot{Snapshot: &polaris.Snapshot{Scope: &comet.Scope{Sector: []byte("s"), Spectrum: []byte(target)}, Version: proto.Uint64(version), Complete: true, Entries: []*comet.AlmanacChange{{Key: key, Action: &comet.AlmanacChange_Value{Value: value}}}}}}
			if !proto.Equal(wire.packets[0], expected) {
				t.Fatal("capacity recovery changed the resumed snapshot")
			}
			after, err := system.store.Load(t.Context(), scope)
			if err != nil || !reflect.DeepEqual(after, before) {
				t.Fatal("recovery changed durable authority data", err)
			}
		})
	}
}

// TestPendingAdmission refuses an authenticated peer while the local node still lacks its own admission.
func TestPendingAdmission(t *testing.T) {
	t.Parallel()
	system := environment(t, storage.Default())
	// Open creates a lazy channel only. No registration or connection to this unused endpoint is attempted.
	node, err := admission.Open(system.issuer.identity, "127.0.0.1:1", "alpha", "127.0.0.1:7443", "default", orbit.Role_ROLE_POLARIS)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	authority, err := NewAuthority(system.store, node.Directory(), 256<<20)
	if err != nil {
		t.Fatal(err)
	}
	owner := NewStreams(node, authority)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	wire := &capture{ctx: ctx}
	state := &transfer{owner: owner, wire: wire, ctx: ctx, input: make(chan incoming, 1), wake: make(chan struct{}, 1), sent: make(map[storage.Scope]storage.Version), installed: make(map[storage.Scope]storage.Version)}
	state.input <- incoming{packet: &polaris.Packet{Body: &polaris.Packet_Hello{Hello: system.star}}}
	err = state.run()
	if status.Code(err) != codes.Unavailable || state.remote == nil || !node.Directory().Current(state.remote) || node.Hello() != nil || len(wire.packets) != 0 || len(owner.active) != 0 || len(state.input) != 0 || state.deadline.Load() != nil {
		t.Fatal("pending local admission exposed a stream or retained its peer identity", err)
	}
	if authority.cache.used != 0 || len(state.sent) != 0 || len(state.installed) != 0 || state.ready {
		t.Fatal("pending admission invented installation progress or retained resources")
	}
}
