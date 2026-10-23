// Verify management action presence, fresh admission and atomic refusal against durable storage.
//go:build linux && cgo

package server

import (
	"context"
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

// TestCommitInput distinguishes absent actions from empty values without consuming versions or permits on refusal.
func TestCommitInput(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"request-nil", "scope-nil",
		"single-value-nil", "single-erase-nil", "single-erase-empty", "single-action-missing",
		"batch-entry-nil", "batch-value-nil", "batch-erase-nil", "batch-erase-empty", "batch-action-missing",
		"credential-invalid", "single-replaced", "batch-replaced", "single-version", "batch-version",
		"single-empty", "single-delete", "batch-empty", "batch-delete",
	} {
		t.Run(name, func(t *testing.T) {
			system := environment(t, storage.Default())
			authority, err := NewAuthority(system.store, system.node.Directory(), 256<<20)
			if err != nil {
				t.Fatal(err)
			}
			scope := storage.Scope{Sector: "s", Spectrum: "p"}
			value := []byte("before")
			if name == "credential-invalid" {
				scope = storage.Scope{Sector: "__auth", Spectrum: "comet"}
				value, err = proto.Marshal(&orbit.Credential{Secret: []byte("valid")})
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := system.store.Commit(t.Context(), scope, storage.Change{Version: 1, Key: "key", Value: value}); err != nil {
				t.Fatal(err)
			}
			before, err := system.store.Load(t.Context(), scope)
			if err != nil {
				t.Fatal(err)
			}
			positions, err := system.store.List(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			request := &polaris.CommitRequest{
				Scope: &comet.Scope{Sector: []byte(scope.Sector), Spectrum: []byte(scope.Spectrum)}, Version: 2,
				Change: &comet.AlmanacChange{Key: "key", Action: &comet.AlmanacChange_Value{}},
			}
			if strings.HasPrefix(name, "batch-") {
				request.Changes, request.Change = []*comet.AlmanacChange{request.Change}, nil
			}
			want := codes.InvalidArgument
			switch name {
			case "request-nil":
				request = nil
			case "scope-nil":
				request.Scope = nil
			case "single-value-nil":
				request.Change.Action = (*comet.AlmanacChange_Value)(nil)
			case "single-erase-nil":
				request.Change.Action = (*comet.AlmanacChange_Erase)(nil)
			case "single-erase-empty":
				request.Change.Action = &comet.AlmanacChange_Erase{}
			case "single-action-missing":
				request.Change.Action = nil
			case "batch-entry-nil":
				request.Changes[0] = nil
			case "batch-value-nil":
				request.Changes[0].Action = (*comet.AlmanacChange_Value)(nil)
			case "batch-erase-nil":
				request.Changes[0].Action = (*comet.AlmanacChange_Erase)(nil)
			case "batch-erase-empty":
				request.Changes[0].Action = &comet.AlmanacChange_Erase{}
			case "batch-action-missing":
				request.Changes[0].Action = nil
			case "single-replaced", "batch-replaced":
				want = codes.Unauthenticated
			case "single-version", "batch-version":
				request.Version, want = 1, codes.Aborted
			case "single-empty", "batch-empty":
				want = codes.OK
			case "single-delete":
				request.Change.Action, want = &comet.AlmanacChange_Erase{Erase: &comet.Empty{}}, codes.OK
			case "batch-delete":
				request.Changes[0].Action, want = &comet.AlmanacChange_Erase{Erase: &comet.Empty{}}, codes.OK
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("astra-admission-bin", string(system.manager.Admission), "astra-signature-bin", string(system.manager.AdmissionSignature)))
			var result *polaris.Position
			if strings.HasSuffix(name, "-replaced") {
				var member *orbit.Member
				member, err = authority.directory.Authorize(ctx, orbit.Role_ROLE_ASTROLABE)
				if err != nil {
					t.Fatal(err)
				}
				next := proto.Clone(member).(*orbit.Member)
				next.Epoch++
				next.Id = []byte("replacement")
				hello := system.issuer.sign(next)
				if _, err := authority.directory.Verify(hello.Admission, hello.AdmissionSignature, orbit.Role_ROLE_ASTROLABE); err != nil {
					t.Fatal(err)
				}
				// Hold the previously authorized member across a deterministic admission replacement.
				result, err = authority.commit(ctx, member, request)
			} else {
				result, err = authority.Commit(ctx, request)
			}
			if status.Code(err) != want {
				t.Fatal("commit returned the wrong category", err, want)
			}
			if len(authority.slots) != 0 || authority.cache.used != 0 || len(authority.cache.entries) != 0 {
				t.Fatal("commit retained a permit or snapshot reservation")
			}
			after, err := system.store.Load(t.Context(), scope)
			if err != nil {
				t.Fatal(err)
			}
			listed, err := system.store.List(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if want != codes.OK {
				if result != nil || !reflect.DeepEqual(before, after) || !reflect.DeepEqual(positions, listed) {
					t.Fatal("refusal changed durable content, inventory or receipt")
				}
			} else {
				if !proto.Equal(result, &polaris.Position{Scope: request.Scope, Version: 2}) || after.Version != 2 {
					t.Fatal("successful commit lost its exact version receipt")
				}
				if strings.HasSuffix(name, "-delete") {
					if len(after.Records) != 0 {
						t.Fatal("explicit erase retained the record")
					}
				} else if len(after.Records) != 1 || after.Records[0].Key != "key" || len(after.Records[0].Value) != 0 {
					t.Fatal("empty value was confused with absence")
				}
				if len(listed) != 1 || listed[0].Scope != scope || listed[0].Version != 2 {
					t.Fatal("successful commit changed the wrong inventory position")
				}
			}
			// A healthy next transaction must retain its natural version after either outcome.
			if version, err := system.store.Commit(t.Context(), scope, storage.Change{Version: after.Version + 1, Key: "next", Value: value}); err != nil || version != after.Version+1 {
				t.Fatal("commit left storage unusable or consumed a hidden version", version, err)
			}
		})
	}
}
