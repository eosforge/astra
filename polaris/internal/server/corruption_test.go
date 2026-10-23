// Verify protocol refusal and resource return after explicit damage to a fixture-owned SQLite database.
//go:build linux && cgo

package server

import (
	"context"
	"database/sql"
	"errors"
	"maps"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/internal/generated/comet"
	"github.com/eosforge/astra/internal/generated/orbit"
	"github.com/eosforge/astra/internal/generated/polaris"
	"github.com/eosforge/astra/polaris/internal/storage"
)

// TestStoredDamage injects schema, metadata and history faults through SQLite, never through production test hooks.
// These fixtures intentionally violate storage invariants; their rejection is not evidence of valid-input reachability.
func TestStoredDamage(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"inventory", "initial", "history"} {
		t.Run(name, func(t *testing.T) {
			// Admission remains real while the damaged database has its own path, handles and cleanup scope.
			system := environment(t, storage.Default())
			path := filepath.Join(t.TempDir(), "damage.db")
			store, err := storage.Open(t.Context(), path, storage.Binding{Galaxy: "alpha", Username: "polaris", Advertise: "127.0.0.1:7445"}, storage.Default(), true)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := store.Close(); err != nil {
					t.Error(err)
				}
			})
			database, err := sql.Open("sqlite3", path)
			if err != nil {
				t.Fatal(err)
			}
			database.SetMaxOpenConns(1)
			t.Cleanup(func() {
				if err := database.Close(); err != nil {
					t.Error(err)
				}
			})
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			scope := storage.Scope{Sector: "s", Spectrum: "p"}
			for version := storage.Version(1); version <= 2; version++ {
				if _, err := store.Commit(ctx, scope, storage.Change{Version: version, Key: "key", Value: []byte{byte(version)}}); err != nil {
					t.Fatal(err)
				}
			}
			authority, err := NewAuthority(store, system.node.Directory(), 256<<20)
			if err != nil {
				t.Fatal(err)
			}
			owner := NewStreams(system.node, authority)
			wire := &dialogue{capture: capture{ctx: ctx}, step: func(*polaris.Packet) error { return errors.New("unexpected outbound frame") }}
			state := &transfer{owner: owner, wire: wire, ctx: ctx, maximum: 1024, input: make(chan incoming, 1), wake: make(chan struct{}, 1), sent: make(map[storage.Scope]storage.Version), installed: make(map[storage.Scope]storage.Version)}
			switch name {
			case "inventory":
				// Legal scope names are bounded at 128 bytes; oversize persisted metadata is an explicit corruption fixture.
				if _, err := database.ExecContext(ctx, "UPDATE scopes SET sector=?", strings.Repeat("s", 8<<20)); err != nil {
					t.Fatal(err)
				}
				var size int
				if err := database.QueryRowContext(ctx, "SELECT length(sector) FROM scopes").Scan(&size); err != nil || size != 8<<20 {
					t.Fatal("metadata fault was not installed", err, size)
				}
				request := metadata.NewIncomingContext(ctx, metadata.Pairs("astra-admission-bin", string(system.manager.Admission), "astra-signature-bin", string(system.manager.AdmissionSignature)))
				inventory, err := authority.List(request, &comet.Empty{})
				if status.Code(err) != codes.ResourceExhausted || inventory != nil {
					t.Fatal("oversized damaged metadata was truncated or accepted", err)
				}
			case "initial":
				if _, err := database.ExecContext(ctx, "DROP TABLE scopes"); err != nil {
					t.Fatal(err)
				}
				if _, err := store.List(ctx); !errors.Is(err, storage.ErrUnavailable) {
					t.Fatal("schema fault did not reject the storage read", err)
				}
				wire.step = func(packet *polaris.Packet) error {
					if packet.GetHello() == nil {
						t.Fatal("damaged initial inventory emitted a plan or data")
					}
					state.input <- incoming{packet: &polaris.Packet{Body: &polaris.Packet_Inventory{Inventory: &polaris.Inventory{Complete: true}}}}
					return nil
				}
				state.input <- incoming{packet: &polaris.Packet{Body: &polaris.Packet_Hello{Hello: system.star}}}
				if err := state.run(); status.Code(err) != codes.Unavailable || len(wire.packets) != 1 || !proto.Equal(wire.packets[0], &polaris.Packet{Body: &polaris.Packet_Hello{Hello: system.node.Hello()}}) {
					t.Fatal("initial inventory failure lost its exact terminal prefix", err)
				}
			case "history":
				if _, err := database.ExecContext(ctx, "UPDATE history SET cost=cost+1"); err != nil {
					t.Fatal(err)
				}
				if _, err := store.Since(ctx, scope, 1); !errors.Is(err, storage.ErrCorrupt) {
					t.Fatal("history fault was not detected independently", err)
				}
				remote, err := system.node.Directory().Verify(system.star.Admission, system.star.AdmissionSignature, orbit.Role_ROLE_STAR)
				if err != nil {
					t.Fatal(err)
				}
				state.remote, state.ready = remote, true
				state.sent[scope], state.installed[scope] = 2, 1
				state.boundary = map[storage.Scope]storage.Version{scope: 2}
				state.floor = map[storage.Scope]storage.Version{scope: 1}
				state.charge(scope, 2, 37)
				if err := state.reconcile(map[storage.Scope]storage.Version{scope: 1}); status.Code(err) != codes.Unavailable {
					t.Fatal("damaged history was treated as a recoverable retention gap", err)
				}
				if len(wire.packets) != 0 || state.bytes != 37 || len(state.credits) != 1 || state.installed[scope] != 1 || !maps.Equal(state.boundary, map[storage.Scope]storage.Version{scope: 2}) || !maps.Equal(state.floor, map[storage.Scope]storage.Version{scope: 1}) {
					t.Fatal("history refusal invented progress or discarded the recovery boundary")
				}
				snapshot, err := store.Load(ctx, scope)
				want := storage.Snapshot{Position: storage.Position{Scope: scope, Version: 2}, Records: []storage.Record{{Key: "key", Value: []byte{2}}}}
				if err != nil || !reflect.DeepEqual(snapshot, want) {
					t.Fatal("history refusal changed durable contents", err)
				}
			}
			if len(owner.active) != 0 || len(authority.slots) != 0 || authority.cache.used != 0 || len(authority.cache.entries) != 0 || state.deadline.Load() != nil || len(state.input) != 0 {
				t.Fatal("damaged storage retained execution ownership")
			}
			// Reserve the entire feed budget concurrently to expose a leaked initial subscription.
			for range 8 {
				feed, err := store.Subscribe(16<<20, 1)
				if err != nil {
					t.Fatal("damaged storage leaked a feed reservation", err)
				}
				t.Cleanup(feed.Close)
			}
		})
	}
}
