// Verify startup admission and management reads against native storage and controlled send boundaries.
//go:build linux && cgo

package server

import (
	"bytes"
	"context"
	"errors"
	"io"
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

// TestStartup refuses invalid durable credentials before exposing an authority, without rewriting their bytes.
func TestStartup(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"nil", "empty", "valid", "opaque", "malformed", "secret-empty", "secret-long", "key-long", "closed"} {
		t.Run(name, func(t *testing.T) {
			if name == "nil" {
				if err := Validate(t.Context(), nil); !errors.Is(err, storage.ErrInput) {
					t.Fatal("nil storage accepted", err)
				}
				return
			}
			store := fixture(t, storage.Default())
			scope := storage.Scope{Sector: "__auth", Spectrum: "comet"}
			key, secret := "client", []byte("secret")
			var want error
			switch name {
			case "opaque":
				scope.Sector = "business"
			case "malformed", "secret-empty", "secret-long", "key-long":
				want = storage.ErrCorrupt
			}
			switch name {
			case "secret-empty":
				secret = nil
			case "secret-long":
				secret = bytes.Repeat([]byte{1}, 4097)
			case "key-long":
				key = strings.Repeat("k", 129)
			}
			value, err := proto.Marshal(&orbit.Credential{Secret: secret})
			if err != nil {
				t.Fatal(err)
			}
			if name == "malformed" || name == "opaque" {
				value = []byte{0xff}
			}
			if name != "empty" && name != "closed" {
				if _, err := store.Commit(t.Context(), scope, storage.Change{Version: 1, Key: key, Value: value}); err != nil {
					t.Fatal(err)
				}
			}
			before, err := store.Load(t.Context(), scope)
			if err != nil {
				t.Fatal(err)
			}
			if name == "closed" {
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
				want = storage.ErrClosed
			}
			if err := Validate(t.Context(), store); !errors.Is(err, want) {
				t.Fatal("startup classification changed", err, want)
			}
			if name != "closed" {
				after, err := store.Load(t.Context(), scope)
				if err != nil || !reflect.DeepEqual(before, after) {
					t.Fatal("validation mutated durable input", err)
				}
			}
		})
	}
}

// readout copies snapshot frames and invokes a synchronous hook after each successful send.
type readout struct {
	capture                     // Reject all unused transport methods and own the finite request scope.
	pages   []*polaris.Snapshot // Frozen frames, including the explicit completion boundary.
	after   func() error        // Controlled mutation, admission replacement or transport failure.
}

// Send never retains mutable protobuf buffers owned by the production paginator.
func (wire *readout) Send(page *polaris.Snapshot) error {
	wire.pages = append(wire.pages, proto.Clone(page).(*polaris.Snapshot))
	if wire.after != nil {
		return wire.after()
	}
	return nil
}

// TestManagement freezes one read across a concurrent commit and releases permits on every refusal.
func TestManagement(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"frozen", "replaced", "send-failure", "nil-scope", "invalid-scope", "closed", "capacity", "missing-auth", "wrong-role", "no-deadline", "long-deadline", "expired"} {
		t.Run(name, func(t *testing.T) {
			system := environment(t, storage.Default())
			authority, err := NewAuthority(system.store, system.node.Directory(), 256<<20)
			if err != nil {
				t.Fatal(err)
			}
			scope := storage.Scope{Sector: "s", Spectrum: "p"}
			value := bytes.Repeat([]byte{0, 255, 17}, 100000)
			changes := []storage.Change{{Key: "a", Value: value}, {Key: "b", Value: value}, {Key: "zero"}}
			if _, err := system.store.CommitBatch(t.Context(), scope, 1, changes); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			hello := system.manager
			want := codes.OK
			switch name {
			case "missing-auth", "wrong-role", "replaced":
				want = codes.Unauthenticated
			case "nil-scope", "invalid-scope", "no-deadline", "long-deadline", "expired":
				want = codes.InvalidArgument
			case "capacity":
				want = codes.ResourceExhausted
			case "closed":
				want = codes.Unavailable
			}
			switch name {
			case "no-deadline":
				ctx = t.Context()
			case "long-deadline":
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(t.Context(), time.Minute)
				defer stop()
			case "expired":
				var stop context.CancelFunc
				ctx, stop = context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
				defer stop()
			case "wrong-role":
				hello = system.star
			}
			if name != "missing-auth" {
				ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("astra-admission-bin", string(hello.Admission), "astra-signature-bin", string(hello.AdmissionSignature)))
			}
			request := &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}
			switch name {
			case "nil-scope":
				request = nil
			case "invalid-scope":
				request.Sector = nil
			case "closed":
				if err := system.store.Close(); err != nil {
					t.Fatal(err)
				}
			case "capacity":
				for range cap(authority.slots) {
					authority.slots <- struct{}{}
				}
			}
			wire := &readout{capture: capture{ctx: ctx}}
			sentinel := errors.New("controlled send failure")
			wire.after = func() error {
				if name == "send-failure" {
					return sentinel
				}
				if len(wire.pages) != 1 {
					return nil
				}
				if name == "frozen" {
					_, err := system.store.Commit(t.Context(), scope, storage.Change{Version: 2, Key: "b", Value: []byte("new")})
					return err
				}
				if name == "replaced" {
					member := &orbit.Member{}
					if err := proto.Unmarshal(system.manager.Admission, member); err != nil {
						return err
					}
					member.Epoch++
					member.Id = []byte("replacement")
					next := system.issuer.sign(member)
					_, err := system.node.Directory().Verify(next.Admission, next.AdmissionSignature, orbit.Role_ROLE_ASTROLABE)
					return err
				}
				return nil
			}
			err = authority.Load(request, wire)
			if name == "send-failure" {
				if !errors.Is(err, sentinel) {
					t.Fatal("send failure changed", err)
				}
			} else if status.Code(err) != want {
				t.Fatal("read classification changed", err, want)
			}
			if name == "capacity" {
				if len(authority.slots) != cap(authority.slots) {
					t.Fatal("refusal consumed another request's permit")
				}
				for range cap(authority.slots) {
					<-authority.slots
				}
			}
			if len(authority.slots) != 0 || authority.cache.used != 0 || len(authority.cache.entries) != 0 {
				t.Fatal("read leaked permit or snapshot ownership")
			}
			if name == "frozen" {
				if len(wire.pages) != 3 {
					t.Fatal("missing pagination exercise", len(wire.pages))
				}
				for index, page := range wire.pages {
					expected := &polaris.Snapshot{Scope: request, Version: proto.Uint64(1), Complete: index == 2, Entries: []*comet.AlmanacChange{{Key: changes[index].Key, Action: &comet.AlmanacChange_Value{Value: changes[index].Value}}}}
					if !proto.Equal(page, expected) {
						t.Fatal("snapshot mixed versions or lost a value", index)
					}
				}
				current, err := system.store.Load(t.Context(), scope)
				if err != nil || current.Version != 2 || string(current.Records[1].Value) != "new" {
					t.Fatal("interleaved commit was not durable", err)
				}
			} else if name == "replaced" || name == "send-failure" {
				if len(wire.pages) != 1 || wire.pages[0].Complete {
					t.Fatal("failed stream falsely completed")
				}
			} else if len(wire.pages) != 0 {
				t.Fatal("refused read exposed data")
			}
		})
	}
}

// TestManagementRPC reads ordered inventory and an empty-value snapshot over the real authenticated TLS boundary.
func TestManagementRPC(t *testing.T) {
	t.Parallel()
	system := environment(t, storage.Default())
	scope := storage.Scope{Sector: "s", Spectrum: "p"}
	if _, err := system.store.Commit(t.Context(), scope, storage.Change{Version: 1, Key: "zero"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "astra-admission-bin", string(system.manager.Admission), "astra-signature-bin", string(system.manager.AdmissionSignature))
	client := polaris.NewAuthorityClient(system.channel)
	request := &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}
	inventory, err := client.List(ctx, &comet.Empty{})
	if err != nil || !proto.Equal(inventory, &polaris.Inventory{Complete: true, Positions: []*polaris.Position{{Scope: request, Version: 1}}}) {
		t.Fatal("inventory lost position or completion", err)
	}
	stream, err := client.Load(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	page, err := stream.Recv()
	if err != nil || !proto.Equal(page, &polaris.Snapshot{Scope: request, Version: proto.Uint64(1), Complete: true, Entries: []*comet.AlmanacChange{{Key: "zero", Action: &comet.AlmanacChange_Value{}}}}) {
		t.Fatal("empty value lost its set action", err)
	}
	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		t.Fatal("missing clean stream completion", err)
	}
}

// TestPreparation returns failed snapshot reservations and preserves an already pinned reader under overload.
func TestPreparation(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"ahead", "closed", "cancelled", "capacity"} {
		t.Run(name, func(t *testing.T) {
			store := fixture(t, storage.Default())
			cache := newCache(store, store.Limits(), 256<<20)
			cache.maximum = cache.reserve
			scope := storage.Scope{Sector: "s", Spectrum: "p"}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			minimum := storage.Version(0)
			want := storage.ErrCapacity
			var held *pin
			switch name {
			case "ahead":
				minimum, want = 1, storage.ErrVersion
			case "closed":
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
				want = storage.ErrClosed
			case "cancelled":
				cancel()
				want = context.Canceled
			case "capacity":
				var err error
				held, err = cache.acquire(ctx, scope, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer held.release()
				scope.Spectrum = "other"
			}
			if result, err := cache.acquire(ctx, scope, minimum); result != nil || !errors.Is(err, want) {
				t.Fatal("preparation refusal changed", err, want)
			}
			if held != nil {
				if cache.used != cache.reserve || len(cache.entries) != 1 || held.Snapshot.Version != 0 {
					t.Fatal("overload damaged an admitted reader")
				}
				held.release()
			}
			if cache.used != 0 || len(cache.entries) != 0 {
				t.Fatal("failed preparation leaked ownership")
			}
		})
	}
}

// TestAuthorityLimits enforces dependency presence and inclusive allocation limits without allocating that capacity.
func TestAuthorityLimits(t *testing.T) {
	t.Parallel()
	system := environment(t, storage.Default())
	limits := system.store.Limits()
	reserve := limits.Bytes + limits.Records*128 + 2<<20
	for _, name := range []string{"nil-store", "nil-directory", "below", "minimum", "maximum", "above"} {
		t.Run(name, func(t *testing.T) {
			store, directory, budget := system.store, system.node.Directory(), reserve
			switch name {
			case "nil-store":
				store = nil
			case "nil-directory":
				directory = nil
			case "below":
				budget--
			case "maximum":
				budget = 1 << 30
			case "above":
				budget = 1<<30 + 1
			}
			authority, err := NewAuthority(store, directory, budget)
			if name == "minimum" || name == "maximum" {
				if err != nil || authority == nil || len(authority.slots) != 0 || authority.cache.used != 0 {
					t.Fatal("legal boundary refused or eagerly reserved", err)
				}
			} else if authority != nil || !errors.Is(err, storage.ErrInput) {
				t.Fatal("invalid construction accepted", err)
			}
		})
	}
}
