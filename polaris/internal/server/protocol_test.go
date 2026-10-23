// Verify authenticated Almanac refusal boundaries through real TLS, RPC framing and a durable authority.
//go:build linux && cgo

package server

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/eosforge/astra/internal/generated/astra"
	"github.com/eosforge/astra/internal/generated/comet"
	"github.com/eosforge/astra/internal/generated/polaris"
	"github.com/eosforge/astra/polaris/internal/storage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// TestStreamProtocol requires exact refusal categories and byte-identical durable contents for each rejected session.
func TestStreamProtocol(t *testing.T) {
	// Each row owns its servers, database and connection; no predecessor's live stream can supply its outcome.
	cases := []struct {
		name  string     // Stable independently selected boundary, also required by the native test inventory.
		phase string     // Last accepted protocol phase before the deliberately invalid input.
		code  codes.Code // Contractual wire result; transport failure or a different refusal cannot pass.
	}{
		{"first-empty", "hello", codes.InvalidArgument},
		{"first-inventory", "hello", codes.InvalidArgument},
		{"protocol-zero", "hello", codes.InvalidArgument},
		{"protocol-future", "hello", codes.InvalidArgument},
		{"frame-small", "hello", codes.InvalidArgument},
		{"frame-large", "hello", codes.InvalidArgument},
		{"admission-empty", "hello", codes.Unauthenticated},
		{"signature-short", "hello", codes.Unauthenticated},
		{"signature-changed", "hello", codes.Unauthenticated},
		{"manager-role", "hello", codes.Unauthenticated},
		{"inventory-entry", "inventory", codes.InvalidArgument},
		{"inventory-scope", "inventory", codes.InvalidArgument},
		{"inventory-sector", "inventory", codes.InvalidArgument},
		{"inventory-spectrum", "inventory", codes.InvalidArgument},
		{"inventory-nul", "inventory", codes.InvalidArgument},
		{"inventory-long", "inventory", codes.InvalidArgument},
		{"inventory-duplicate", "inventory", codes.InvalidArgument},
		{"inventory-pages", "inventory", codes.InvalidArgument},
		{"inventory-capacity", "inventory", codes.ResourceExhausted},
		{"inventory-unknown", "inventory", codes.Aborted},
		{"inventory-ahead", "inventory", codes.Aborted},
		{"control-empty", "ready", codes.InvalidArgument},
		{"control-hello", "ready", codes.InvalidArgument},
		{"control-probe", "ready", codes.InvalidArgument},
		{"control-ready", "ready", codes.InvalidArgument},
		{"control-plan", "ready", codes.InvalidArgument},
		{"control-snapshot", "ready", codes.InvalidArgument},
		{"control-updates", "ready", codes.InvalidArgument},
		{"ack-scope", "ready", codes.InvalidArgument},
		{"ack-invalid", "ready", codes.InvalidArgument},
		{"ack-unknown", "ready", codes.InvalidArgument},
		{"ack-ahead", "ready", codes.InvalidArgument},
		{"inventory-unsolicited", "ready", codes.InvalidArgument},
		{"identity-duplicate", "ready", codes.AlreadyExists},
		{"cancel-ready", "ready", codes.Canceled},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			// A one-scope authority makes the inventory budget exact without artificial internal state.
			limits := storage.Default()
			limits.Scopes = 1
			system := environment(t, limits)
			scope := storage.Scope{Sector: "s", Spectrum: "p"}
			if _, err := system.store.Commit(t.Context(), scope, storage.Change{Version: 1, Key: "key", Value: []byte("original")}); err != nil {
				t.Fatal(err)
			}
			before, err := system.store.Load(t.Context(), scope)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			stream, err := polaris.NewAlmanacClient(system.channel).Open(ctx)
			if err != nil {
				t.Fatal(err)
			}
			// Mutable requests are private copies; changing a rejection case cannot alter fixture credentials.
			hello := proto.Clone(system.star).(*astra.Hello)
			first := &polaris.Packet{Body: &polaris.Packet_Hello{Hello: hello}}
			switch test.name {
			case "first-empty":
				first = &polaris.Packet{}
			case "first-inventory":
				first = &polaris.Packet{Body: &polaris.Packet_Inventory{Inventory: &polaris.Inventory{Complete: true}}}
			case "protocol-zero":
				hello.ProtocolMajor = 0
			case "protocol-future":
				hello.ProtocolMajor = 2
			case "frame-small":
				hello.MaxFrameBytes = 1023
			case "frame-large":
				hello.MaxFrameBytes = (8 << 20) + 1
			case "admission-empty":
				hello.Admission = nil
			case "signature-short":
				hello.AdmissionSignature = hello.AdmissionSignature[:len(hello.AdmissionSignature)-1]
			case "signature-changed":
				hello.AdmissionSignature[0] ^= 1
			case "manager-role":
				first = &polaris.Packet{Body: &polaris.Packet_Hello{Hello: system.manager}}
			}
			if err := stream.Send(first); err != nil {
				t.Fatal("initial frame did not reach the transport", err)
			}
			if test.phase != "hello" {
				packet, err := stream.Recv()
				if err != nil || !proto.Equal(packet.GetHello(), system.node.Hello()) {
					t.Fatal("valid Star did not receive the signed Polaris Hello", err)
				}
				// Version one is an actual installed baseline. Invalid pages must never produce a Plan or Ready.
				position := &polaris.Position{Scope: &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}, Version: 1}
				page := &polaris.Inventory{Complete: true, Positions: []*polaris.Position{position}}
				switch test.name {
				case "inventory-entry":
					page.Positions[0] = nil
				case "inventory-scope":
					position.Scope = nil
				case "inventory-sector":
					position.Scope.Sector = nil
				case "inventory-spectrum":
					position.Scope.Spectrum = nil
				case "inventory-nul":
					position.Scope.Sector = []byte("s\x00")
				case "inventory-long":
					position.Scope.Sector = []byte(strings.Repeat("s", 129))
				case "inventory-duplicate":
					page.Positions = append(page.Positions, proto.Clone(position).(*polaris.Position))
				case "inventory-pages":
					prefix := proto.Clone(page).(*polaris.Inventory)
					prefix.Complete = false
					if err := stream.Send(&polaris.Packet{Body: &polaris.Packet_Inventory{Inventory: prefix}}); err != nil {
						t.Fatal("incomplete inventory prefix was not sent", err)
					}
				case "inventory-capacity":
					page.Positions = append(page.Positions, &polaris.Position{Scope: &comet.Scope{Sector: []byte("s"), Spectrum: []byte("other")}})
				case "inventory-unknown":
					position.Scope.Spectrum = []byte("other")
				case "inventory-ahead":
					position.Version = 2
				}
				if err := stream.Send(&polaris.Packet{Body: &polaris.Packet_Inventory{Inventory: page}}); err != nil {
					t.Fatal("inventory was not sent", err)
				}
			}
			if test.phase == "ready" {
				// A caught-up peer must receive exactly the literal one-scope Plan followed by Ready.
				expected := &polaris.Inventory{Complete: true, Positions: []*polaris.Position{{Scope: &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}, Version: 1}}}
				packet, err := stream.Recv()
				if err != nil || !proto.Equal(packet.GetPlan(), expected) {
					t.Fatal("initial plan differs from the durable baseline", err)
				}
				packet, err = stream.Recv()
				if err != nil || packet.GetReady() == nil {
					t.Fatal("confirmed initial baseline did not become ready", err)
				}
				invalid := &polaris.Packet{}
				switch test.name {
				case "control-hello":
					invalid.Body = &polaris.Packet_Hello{Hello: system.star}
				case "control-probe":
					invalid.Body = &polaris.Packet_Probe{Probe: &comet.Empty{}}
				case "control-ready":
					invalid.Body = &polaris.Packet_Ready{Ready: &comet.Empty{}}
				case "control-plan":
					invalid.Body = &polaris.Packet_Plan{Plan: expected}
				case "control-snapshot":
					invalid.Body = &polaris.Packet_Snapshot{Snapshot: &polaris.Snapshot{}}
				case "control-updates":
					invalid.Body = &polaris.Packet_Updates{Updates: &polaris.Updates{}}
				case "ack-scope":
					invalid.Body = &polaris.Packet_Acknowledged{Acknowledged: &polaris.Position{Version: 1}}
				case "ack-invalid", "ack-unknown", "ack-ahead":
					position := proto.Clone(expected.Positions[0]).(*polaris.Position)
					if test.name == "ack-invalid" {
						position.Scope.Sector = nil
					} else if test.name == "ack-unknown" {
						position.Scope.Spectrum = []byte("other")
					} else {
						position.Version = 2
					}
					invalid.Body = &polaris.Packet_Acknowledged{Acknowledged: position}
				case "inventory-unsolicited":
					invalid.Body = &polaris.Packet_Inventory{Inventory: expected}
				case "identity-duplicate":
					stream, err = polaris.NewAlmanacClient(system.channel).Open(ctx)
					if err != nil {
						t.Fatal("duplicate stream could not be opened", err)
					}
					invalid.Body = &polaris.Packet_Hello{Hello: system.star}
				case "cancel-ready":
					cancel()
				}
				if test.name != "cancel-ready" {
					if err := stream.Send(invalid); err != nil {
						t.Fatal("control input was not sent", err)
					}
				}
			}
			packet, err := stream.Recv()
			if packet != nil || status.Code(err) != test.code {
				t.Fatalf("refusal: got packet %T and code %v, want %v", packet, status.Code(err), test.code)
			}
			after, err := system.store.Load(t.Context(), scope)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("rejected session changed the durable authority", err)
			}
		})
	}
}
