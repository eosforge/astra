// Verify partial delivery refuses false progress and keeps internal failures out of public replies.
//go:build linux && cgo

package server

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/eosforge/astra/internal/generated/comet"
	"github.com/eosforge/astra/internal/generated/polaris"
	"github.com/eosforge/astra/polaris/internal/storage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestEmission preserves installed state and snapshot ownership across controlled pagination failures.
func TestEmission(t *testing.T) {
	cases := []struct {
		name string     // Exact failure boundary selected before the operation starts.
		code codes.Code // Stable refusal category; transport substitutions also require error identity.
	}{
		{"updates-empty", codes.OK},
		{"updates-corrupt", codes.Unavailable},
		{"updates-cancelled", codes.Canceled},
		{"updates-send", codes.Unavailable},
		{"updates-drain", codes.Unavailable},
		{"snapshot-cancelled", codes.Canceled},
		{"snapshot-send", codes.Unavailable},
		{"snapshot-ack", codes.InvalidArgument},
		{"snapshot-drain", codes.Unavailable},
		{"snapshot-oversize", codes.ResourceExhausted},
		{"manifest-send", codes.Unavailable},
		{"ready-send", codes.Unavailable},
		{"synchronize-closed", codes.Unavailable},
		{"restore-capacity", codes.ResourceExhausted},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			state, wire, system := recovery(t, 16, 2)
			scope := storage.Scope{Sector: "s", Spectrum: "p"}
			before, err := system.store.Load(t.Context(), scope)
			if err != nil {
				t.Fatal(err)
			}
			blocked := status.Error(codes.Unavailable, "controlled transport boundary")
			if strings.HasSuffix(test.name, "-send") {
				wire.err = blocked
			}
			if strings.HasSuffix(test.name, "-cancelled") {
				ctx, cancel := context.WithCancel(state.ctx)
				cancel()
				state.ctx = ctx
			}
			if strings.HasSuffix(test.name, "-drain") {
				state.input <- incoming{err: blocked}
			}
			changes := []storage.Change{
				{Version: 3, Key: "key", Value: []byte(strings.Repeat("a", 600))},
				{Version: 4, Key: "key", Value: []byte(strings.Repeat("b", 600))},
			}
			snapshot := storage.Snapshot{Position: storage.Position{Scope: scope, Version: 3}, Records: []storage.Record{
				{Key: "a", Value: []byte(strings.Repeat("a", 600))},
				{Key: "b", Value: []byte(strings.Repeat("b", 600))},
			}}
			switch test.name {
			case "updates-empty":
				err = state.update(scope, nil)
			case "updates-corrupt":
				err = state.update(scope, []storage.Change{{Version: 3}})
			case "updates-cancelled", "updates-send", "updates-drain":
				err = state.update(scope, changes)
			case "snapshot-cancelled", "snapshot-send", "snapshot-drain":
				err = state.snapshot(&snapshot)
			case "snapshot-ack":
				// A prefix page cannot authorize acknowledging the new snapshot version.
				state.input <- incoming{packet: &polaris.Packet{Body: &polaris.Packet_Acknowledged{Acknowledged: &polaris.Position{
					Scope: &comet.Scope{Sector: []byte("s"), Spectrum: []byte("p")}, Version: 3,
				}}}}
				err = state.snapshot(&snapshot)
			case "snapshot-oversize":
				snapshot.Records[0].Value = make([]byte, 1024)
				err = state.snapshot(&snapshot)
			case "manifest-send":
				positions := make([]storage.Position, 32)
				for index := range positions {
					positions[index] = storage.Position{Scope: storage.Scope{Sector: "s", Spectrum: fmt.Sprintf("%080d", index)}, Version: 2}
				}
				err = state.manifest(positions)
			case "ready-send":
				// An already completed installation must not attempt another transport write.
				if err := state.complete(); err != nil || !state.ready || len(wire.packets) != 0 {
					t.Fatal("completed installation attempted another Ready send", err)
				}
				state.ready = false
				state.plan = map[storage.Scope]storage.Version{scope: 2}
				if err := state.complete(); err != nil || state.ready || len(wire.packets) != 0 {
					t.Fatal("readiness ignored an unconfirmed minimum", err)
				}
				state.plan[scope] = 0
				delete(state.installed, scope)
				if err := state.complete(); err != nil || state.ready || len(wire.packets) != 0 {
					t.Fatal("readiness invented an absent zero-version baseline", err)
				}
				state.installed[scope] = 1
				state.plan = map[storage.Scope]storage.Version{scope: 1}
				err = state.complete()
			case "synchronize-closed":
				if err := system.store.Close(); err != nil {
					t.Fatal(err)
				}
				err = state.synchronize(storage.Position{Scope: scope, Version: 3})
			case "restore-capacity":
				system.streams.authority.cache.maximum = 0
				err = state.restore(storage.Position{Scope: scope, Version: 2})
			}
			// Internal delivery preserves the Context cause; the RPC boundary encodes it separately.
			if strings.HasSuffix(test.name, "-cancelled") {
				if !errors.Is(err, context.Canceled) {
					t.Fatal("delivery lost the cancellation cause", err)
				}
			} else if status.Code(err) != test.code {
				t.Fatal("delivery returned the wrong terminal category", err, test.code)
			}
			if (strings.HasSuffix(test.name, "-send") || strings.HasSuffix(test.name, "-drain")) && !errors.Is(err, blocked) {
				t.Fatal("delivery lost the selected transport failure", err)
			}
			partial := test.name == "updates-drain" || test.name == "snapshot-drain" || test.name == "snapshot-ack"
			want := 0
			if partial {
				want = 1
			}
			if len(wire.packets) != want || state.installed[scope] != 1 || len(state.installed) != 1 || state.deadline.Load() != nil {
				t.Fatal("failed delivery continued sending, advanced installation or retained a wait deadline")
			}
			if test.name == "updates-drain" {
				page := wire.packets[0].GetUpdates()
				if page == nil || len(page.Patches) != 1 || page.Patches[0].Version != 3 || string(page.Patches[0].GetChange().GetValue()) != strings.Repeat("a", 600) || state.sent[scope] != 3 || len(state.credits) != 2 || state.bytes <= 37 {
					t.Fatal("accepted update prefix lost its payload or independently acknowledged credit")
				}
			} else if state.sent[scope] != 2 || state.bytes != 37 || len(state.credits) != 1 {
				t.Fatal("unsent commit or partial snapshot acquired confirmation credit")
			}
			if partial && test.name != "updates-drain" {
				page := wire.packets[0].GetSnapshot()
				if page == nil || page.Complete || page.GetVersion() != 3 || len(page.Entries) != 1 || page.Entries[0].Key != "a" || string(page.Entries[0].GetValue()) != strings.Repeat("a", 600) {
					t.Fatal("partial snapshot carried a false completion or wrong frozen prefix")
				}
			}
			if test.name == "ready-send" && state.ready {
				t.Fatal("failed Ready write changed readiness")
			}
			if system.streams.authority.cache.used != 0 || len(system.streams.authority.cache.entries) != 0 {
				t.Fatal("failed delivery retained snapshot ownership")
			}
			if test.name != "synchronize-closed" {
				after, err := system.store.Load(t.Context(), scope)
				if err != nil || !reflect.DeepEqual(before, after) {
					t.Fatal("outbound failure modified the durable authority", err)
				}
			}
		})
	}
}

// TestFailure checks stable public categories and redaction for direct and wrapped private storage errors.
func TestFailure(t *testing.T) {
	cases := []struct {
		name string     // Publicly meaningful failure class; unknown errors must remain unavailable.
		err  error      // Original internal result, also tested beneath a private diagnostic wrapper.
		code codes.Code // Caller-visible recovery category.
	}{
		{"input", storage.ErrInput, codes.InvalidArgument},
		{"version", storage.ErrVersion, codes.Aborted},
		{"history", storage.ErrHistory, codes.OutOfRange},
		{"uncertain", storage.ErrUncertain, codes.Unknown},
		{"capacity", storage.ErrCapacity, codes.ResourceExhausted},
		{"cancelled", context.Canceled, codes.Canceled},
		{"deadline", context.DeadlineExceeded, codes.DeadlineExceeded},
		{"corrupt", storage.ErrCorrupt, codes.Unavailable},
		{"closed", storage.ErrClosed, codes.Unavailable},
		{"binding", storage.ErrBinding, codes.Unavailable},
		{"unavailable", storage.ErrUnavailable, codes.Unavailable},
		{"unknown", errors.New("private-database-path-and-account"), codes.Unavailable},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var message string
			for index, input := range []error{test.err, fmt.Errorf("private-database-path-and-account: %w", test.err)} {
				result := status.Convert(failure(input))
				if result.Code() != test.code || result.Message() == "" || len(result.Details()) != 0 || strings.Contains(result.Message(), "private-") || strings.Contains(result.Message(), test.err.Error()) {
					t.Fatal("public failure exposed private diagnostics or changed its category", result)
				}
				if index == 0 {
					message = result.Message()
				} else if result.Message() != message {
					t.Fatal("private wrapping changed the stable public reply")
				}
			}
		})
	}
}
