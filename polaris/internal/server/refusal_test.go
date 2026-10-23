// Distinguish management transport failure, admission refusal and durable commit acknowledgement.
//go:build linux && cgo

package server

import (
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
	"github.com/eosforge/astra/internal/generated/polaris"
	"github.com/eosforge/astra/polaris/internal/storage"
)

// upload exposes literal input pages and records only the attempted terminal receipt.
type upload struct {
	capture                         // Reject unrelated transport operations and supply the finite context.
	pages   []*polaris.BatchRequest // Fixed independent page sequence.
	reads   int                     // Exact receive call count, including EOF or refusal.
	failure error                   // Selected failure after the available pages or when returning a receipt.
	receipt bool                    // Choose receipt failure after complete input instead of receive failure.
	result  *polaris.Position       // Copy of the receipt attempted after a durable commit.
}

// Recv preserves the ordered prefix and either reports the selected transport failure or explicit EOF.
func (wire *upload) Recv() (*polaris.BatchRequest, error) {
	wire.reads++
	if wire.reads <= len(wire.pages) {
		if wire.pages[wire.reads-1] == nil {
			return nil, nil
		}
		return proto.Clone(wire.pages[wire.reads-1]).(*polaris.BatchRequest), nil
	}
	if wire.receipt {
		return nil, io.EOF
	}
	return nil, wire.failure
}

// SendAndClose records an attempted receipt without turning a failed send into delivery evidence.
func (wire *upload) SendAndClose(result *polaris.Position) error {
	wire.result = proto.Clone(result).(*polaris.Position)
	return wire.failure
}

// TestRefusal verifies state, permit ownership and receipt ambiguity on management refusal paths.
func TestRefusal(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"list-unauthenticated", "list-closed", "batch-unauthenticated", "batch-receive", "batch-prefix", "batch-receipt", "batch-nil", "load-preparation"} {
		t.Run(name, func(t *testing.T) {
			system := environment(t, storage.Default())
			limits := system.store.Limits()
			reserve := limits.Bytes + limits.Records*128 + 2<<20
			authority, err := NewAuthority(system.store, system.node.Directory(), reserve)
			if err != nil {
				t.Fatal(err)
			}
			scope := storage.Scope{Sector: "s", Spectrum: "p"}
			if _, err := system.store.Commit(t.Context(), scope, storage.Change{Version: 1, Key: "key", Value: []byte("before")}); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if !strings.HasSuffix(name, "-unauthenticated") {
				ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("astra-admission-bin", string(system.manager.Admission), "astra-signature-bin", string(system.manager.AdmissionSignature)))
			}
			position := &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}
			failure := errors.New("controlled management transport refusal")
			wire := &upload{capture: capture{ctx: ctx}, failure: failure}
			want, calls := codes.Unauthenticated, 0
			var held *pin
			switch name {
			case "list-closed":
				if err := system.store.Close(); err != nil {
					t.Fatal(err)
				}
				want = codes.Unavailable
			case "batch-receive":
				calls = 1
			case "batch-nil":
				wire.pages = []*polaris.BatchRequest{nil}
				want, calls = codes.InvalidArgument, 1
			case "batch-prefix", "batch-receipt":
				calls = 2
				wire.receipt = name == "batch-receipt"
				wire.pages = []*polaris.BatchRequest{{Scope: position, Version: 2, Complete: wire.receipt, Changes: []*comet.AlmanacChange{{Key: "key", Action: &comet.AlmanacChange_Value{Value: []byte("after")}}}}}
			case "load-preparation":
				held, err = authority.cache.acquire(ctx, storage.Scope{Sector: "s", Spectrum: "other"}, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer held.release()
				want = codes.ResourceExhausted
			}
			switch {
			case strings.HasPrefix(name, "list-"):
				var result *polaris.Inventory
				result, err = authority.List(ctx, &comet.Empty{})
				if result != nil {
					t.Fatal("failed inventory exposed a partial success")
				}
			case name == "load-preparation":
				read := &readout{capture: capture{ctx: ctx}}
				err = authority.Load(position, read)
				if len(read.pages) != 0 {
					t.Fatal("failed snapshot preparation exposed content")
				}
			default:
				err = authority.Batch(wire)
			}
			if strings.HasPrefix(name, "batch-") && name != "batch-unauthenticated" && name != "batch-nil" {
				if !errors.Is(err, failure) {
					t.Fatal("batch lost its transport cause", err)
				}
			} else if status.Code(err) != want {
				t.Fatal("refusal changed its public category", err, want)
			}
			if wire.reads != calls || len(authority.slots) != 0 {
				t.Fatal("refused management request retained a permit or continued reading")
			}
			if held != nil {
				expected := storage.Snapshot{Position: storage.Position{Scope: storage.Scope{Sector: "s", Spectrum: "other"}}}
				if authority.cache.used != reserve || len(authority.cache.entries) != 1 || held.entry.references != 1 || !reflect.DeepEqual(*held.Snapshot, expected) {
					t.Fatal("overload changed another snapshot's reservation")
				}
				held.release()
			}
			if authority.cache.used != 0 || len(authority.cache.entries) != 0 {
				t.Fatal("failed management request retained preparation ownership")
			}
			version, value := storage.Version(1), "before"
			if name == "batch-receipt" {
				version, value = 2, "after"
				if !proto.Equal(wire.result, &polaris.Position{Scope: position, Version: 2}) {
					t.Fatal("durable commit did not attempt the exact terminal receipt")
				}
			} else if wire.result != nil {
				t.Fatal("uncommitted input attempted a success receipt")
			}
			if name != "list-closed" {
				expected := storage.Snapshot{Position: storage.Position{Scope: scope, Version: version}, Records: []storage.Record{{Key: "key", Value: []byte(value)}}}
				snapshot, err := system.store.Load(t.Context(), scope)
				if err != nil || !reflect.DeepEqual(snapshot, expected) {
					t.Fatal("transport result and durable state disagree", err)
				}
				positions, err := system.store.List(t.Context())
				if err != nil || !reflect.DeepEqual(positions, []storage.Position{{Scope: scope, Version: version}}) {
					t.Fatal("refusal created or lost a durable scope", err)
				}
				if name == "batch-receipt" {
					// A lost receipt is an unknown client outcome; retrying the identical committed input must not create version 3.
					result, err := authority.Commit(ctx, &polaris.CommitRequest{Scope: position, Version: 2, Changes: wire.pages[0].Changes})
					if err != nil || !proto.Equal(result, &polaris.Position{Scope: position, Version: 2}) {
						t.Fatal("receipt recovery duplicated or lost the original commit", err)
					}
					after, err := system.store.Load(t.Context(), scope)
					if err != nil || !reflect.DeepEqual(after, expected) || len(authority.slots) != 0 {
						t.Fatal("receipt recovery changed durable state or retained a permit", err)
					}
				}
			}
		})
	}
}
