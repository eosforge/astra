// Verify multi-page management commits through real TLS without exposing a partially accepted batch.
//go:build linux && cgo

package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/eosforge/astra/internal/generated/comet"
	"github.com/eosforge/astra/internal/generated/polaris"
	"github.com/eosforge/astra/polaris/internal/storage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// TestBatchTransport binds each malformed page sequence to its exact result and a complete durable-state oracle.
func TestBatchTransport(t *testing.T) {
	cases := []struct {
		name string     // Stable wire scenario, independently registered in the required test inventory.
		code codes.Code // Expected receipt category after the client closes its send direction.
	}{
		{"empty", codes.InvalidArgument},
		{"empty-page", codes.InvalidArgument},
		{"scope-missing", codes.InvalidArgument},
		{"version-zero", codes.InvalidArgument},
		{"changes-empty", codes.InvalidArgument},
		{"complete-missing", codes.InvalidArgument},
		{"scope-change", codes.InvalidArgument},
		{"version-change", codes.InvalidArgument},
		{"complete-extra", codes.InvalidArgument},
		{"duplicate", codes.InvalidArgument},
		{"action-missing", codes.InvalidArgument},
		{"key-empty", codes.InvalidArgument},
		{"key-nul", codes.InvalidArgument},
		{"key-long", codes.InvalidArgument},
		{"sector-empty", codes.InvalidArgument},
		{"spectrum-empty", codes.InvalidArgument},
		{"scope-internal", codes.InvalidArgument},
		{"version-conflict", codes.Aborted},
		{"valid-replace", codes.OK},
		{"valid-large", codes.OK},
		{"valid-retry", codes.OK},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			system := environment(t, storage.Default())
			scope := storage.Scope{Sector: "s", Spectrum: "p"}
			if _, err := system.store.Commit(t.Context(), scope, storage.Change{Version: 1, Key: "original", Value: []byte("before")}); err != nil {
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
			wire := &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}
			pages := []*polaris.BatchRequest{
				{Scope: proto.Clone(wire).(*comet.Scope), Version: 2, Changes: []*comet.AlmanacChange{{Key: "original", Action: &comet.AlmanacChange_Erase{Erase: &comet.Empty{}}}}},
				{Scope: proto.Clone(wire).(*comet.Scope), Version: 2, Changes: []*comet.AlmanacChange{{Key: "a", Action: &comet.AlmanacChange_Value{Value: []byte("after")}}}},
				{Scope: proto.Clone(wire).(*comet.Scope), Version: 2, Changes: []*comet.AlmanacChange{{Key: "b", Action: &comet.AlmanacChange_Value{}}}, Complete: true},
			}
			// The success oracle is a literal map, independent of page accumulation and storage encoding.
			expected := map[string][]byte{"a": []byte("after"), "b": nil}
			switch test.name {
			case "empty":
				pages = nil
			case "empty-page":
				pages[1] = &polaris.BatchRequest{}
			case "scope-missing":
				pages[1].Scope = nil
			case "version-zero":
				pages[1].Version = 0
			case "changes-empty":
				pages[1].Changes = nil
			case "complete-missing":
				pages[len(pages)-1].Complete = false
			case "scope-change":
				pages[1].Scope.Spectrum = []byte("other")
			case "version-change":
				pages[1].Version = 3
			case "complete-extra":
				pages[0].Complete = true
			case "duplicate":
				pages[2].Changes[0].Key = "a"
			case "action-missing":
				pages[2].Changes[0].Action = nil
			case "key-empty":
				pages[2].Changes[0].Key = ""
			case "key-nul":
				pages[2].Changes[0].Key = "b\x00"
			case "key-long":
				pages[2].Changes[0].Key = strings.Repeat("b", 1025)
			case "sector-empty", "spectrum-empty", "scope-internal", "version-conflict":
				for _, page := range pages {
					switch test.name {
					case "sector-empty":
						page.Scope.Sector = nil
					case "spectrum-empty":
						page.Scope.Spectrum = nil
					case "scope-internal":
						page.Scope.Sector = []byte("__auth")
					case "version-conflict":
						page.Version = 1
					}
				}
			case "valid-large":
				// The 128-key Catalog limit must not leak into an Almanac batch transported across many pages.
				pages = nil
				expected = map[string][]byte{"original": []byte("before")}
				for index := range 129 {
					key, value := fmt.Sprintf("key%03d", index), bytes.Repeat([]byte{byte(index)}, 2048)
					pages = append(pages, &polaris.BatchRequest{Scope: wire, Version: 2, Changes: []*comet.AlmanacChange{{Key: key, Action: &comet.AlmanacChange_Value{Value: value}}}, Complete: index == 128})
					expected[key] = bytes.Clone(value)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			ctx = metadata.AppendToOutgoingContext(ctx, "astra-admission-bin", string(system.manager.Admission), "astra-signature-bin", string(system.manager.AdmissionSignature))
			attempts := 1
			if test.name == "valid-retry" {
				attempts = 2
			}
			for range attempts {
				stream, err := polaris.NewAuthorityClient(system.channel).Batch(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, page := range pages {
					if err := stream.Send(page); err != nil {
						// A server may refuse a prefix before later sends; its final status must still match exactly.
						if errors.Is(err, io.EOF) && test.code != codes.OK {
							break
						}
						t.Fatal("batch send failed without its expected refusal", err)
					}
				}
				result, err := stream.CloseAndRecv()
				if status.Code(err) != test.code {
					t.Fatalf("batch receipt code = %v, want %v", status.Code(err), test.code)
				}
				if test.code == codes.OK {
					if result == nil || result.Version != 2 || !proto.Equal(result.Scope, wire) {
						t.Fatal("receipt did not confirm the whole batch at one version")
					}
				} else if result != nil {
					t.Fatal("failed batch returned a successful position")
				}
			}
			after, err := system.store.Load(t.Context(), scope)
			if err != nil {
				t.Fatal(err)
			}
			directory, err := system.store.List(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if test.code != codes.OK {
				if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(positions, directory) {
					t.Fatal("rejected batch published a prefix or created an unintended scope")
				}
				// The rejected request must return its management permit and preserve the next legal version.
				request := &polaris.CommitRequest{Scope: wire, Version: 2, Change: &comet.AlmanacChange{Key: "recovered", Action: &comet.AlmanacChange_Value{Value: []byte("healthy")}}}
				if result, err := polaris.NewAuthorityClient(system.channel).Commit(ctx, request); err != nil || result.Version != 2 {
					t.Fatal("healthy commit could not follow a rejected batch", err)
				}
				return
			}
			if after.Version != 2 || len(after.Records) != len(expected) || len(directory) != 1 || directory[0].Version != 2 {
				t.Fatal("batch did not publish exactly one complete durable version")
			}
			for _, record := range after.Records {
				value, found := expected[record.Key]
				if !found || !bytes.Equal(record.Value, value) {
					t.Fatal("committed content differs from the independent map", record.Key)
				}
				delete(expected, record.Key)
			}
			if len(expected) != 0 {
				t.Fatal("committed batch omitted expected keys")
			}
		})
	}
}
