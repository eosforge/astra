// Verify public SDK owners across explicit real-fixture crashes and trusted restarts.
package comet_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eosforge/astra/comet/go"
)

// systemRecovery keeps the initial Clients and roles alive through A/B/C failure.
// The external fixture owns processes; command files only confirm its completed actions.
func systemRecovery(t *testing.T, settings comet.Options, nodes []systemNode, scope comet.Scope, identities, addresses []string, control string, residence *residence) {
	t.Helper()
	instances := systemInstances(t, settings, scope, addresses)
	readers := make([]*comet.Reader, len(nodes))
	for index, node := range nodes {
		readers[index] = node.reader
	}
	for index := range nodes {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
			defer cancel()
			if residence != nil {
				residence.replicate(t)
				residence.replicate(t)
			}
			systemEvent(t, "go_mesh_ready", index)
			systemCommand(t, ctx, control, "crashed", index)
			systemAwait(t, ctx, "stable Beacon identities at surviving targets", func() bool {
				for owner, node := range nodes {
					state := node.beacon.State()
					if state.HasIdentity && state.Identity.ID != identities[owner] {
						t.Fatal("Beacon recovery replaced its confirmed logical identity")
					}
					if state.Phase != comet.Ready || !state.HasIdentity || state.Identity.Instance == instances[index] {
						return false
					}
				}
				return true
			})
			phase := fmt.Sprintf("failover-%d", index)
			// Each call is a fresh prescribed write after recovery, not replay of an unknown attempt.
			systemWritePhase(t, ctx, nodes, scope, phase, false)
			systemConverged(t, ctx, nodes, identities, phase)
			systemAuthorityViews(t, ctx, readers, 8, 8, []byte("go-after"))
			systemEvent(t, "go_mesh_failover", index)
			systemCommand(t, ctx, control, "restored", index)
			systemRestored(t, ctx, settings, nodes, scope, phase, addresses[index], instances[index], index)
			systemConverged(t, ctx, nodes, identities, phase)
			systemAuthorityViews(t, ctx, readers, 8, 8, []byte("go-after"))
			if residence != nil {
				residence.replicate(t)
				residence.replicate(t)
			}
			systemEvent(t, "go_mesh_recovered", index)
		}()
	}
}

// systemInstances binds physical fixture endpoints independently of the clients'
// active target choice, which can already have rotated before the first crash.
func systemInstances(t *testing.T, settings comet.Options, scope comet.Scope, addresses []string) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	instances := make([]string, len(addresses))
	seen := make(map[string]bool)
	for index, address := range addresses {
		instances[index] = func() string {
			settings.Endpoints = []string{strings.TrimSpace(address)}
			client, cause := comet.New(settings)
			if cause != nil {
				t.Fatal(cause)
			}
			defer func() {
				client.Close()
				drain, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if cause := client.Wait(drain); cause != nil {
					t.Errorf("target identity probe drain: %v", cause)
				}
			}()
			target := comet.Scope{Sector: scope.Sector, Spectrum: fmt.Sprintf("%s-target-%d", scope.Spectrum, index)}
			publisher, cause := client.Publisher(target)
			if cause != nil {
				t.Fatal(cause)
			}
			receipt, cause := publisher.Update(ctx, []comet.Entry{{Key: "identity", Data: []byte("probe")}}, time.Minute)
			if cause != nil || receipt.Instance == "" || seen[receipt.Instance] {
				t.Fatalf("fixed endpoints do not identify three live independent Stars: %v", cause)
			}
			seen[receipt.Instance] = true
			return receipt.Instance
		}()
	}
	return instances
}

// systemRestored checks both directions using a fresh client pinned to the restarted Star.
// Existing owners remain unchanged; every extra client/role has explicit final cleanup.
func systemRestored(t *testing.T, ctx context.Context, settings comet.Options, nodes []systemNode, scope comet.Scope, phase, endpoint, previous string, cycle int) {
	t.Helper()
	settings.Endpoints = []string{strings.TrimSpace(endpoint)}
	client, cause := comet.New(settings)
	if cause != nil {
		t.Fatal(cause)
	}
	t.Cleanup(func() {
		client.Close()
		drain, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if cause := client.Wait(drain); cause != nil {
			t.Errorf("restored client drain: %v", cause)
		}
	})
	incoming, cause := client.Subscriber(scope)
	if cause != nil {
		t.Fatal(cause)
	}
	systemAwait(t, ctx, "restored Star receives all surviving writers", func() bool {
		view := incoming.State()
		if view.Phase != comet.Ready || !view.HasVersion || view.Data.Len() != len(nodes) {
			return false
		}
		for index := range nodes {
			value, present := view.Data.Get(fmt.Sprintf("node-%d", index))
			if !present || value.String() != fmt.Sprintf("%s-%d", phase, index) {
				return false
			}
		}
		return true
	})
	local := comet.Scope{Sector: scope.Sector, Spectrum: fmt.Sprintf("%s-restored-%d", scope.Spectrum, cycle)}
	publisher, cause := client.Publisher(local)
	if cause != nil {
		t.Fatal(cause)
	}
	payload := []byte(fmt.Sprintf("restored-local-%d", cycle))
	receipt, cause := publisher.Update(ctx, []comet.Entry{{Key: "restored", Data: payload}}, time.Minute)
	if cause != nil || receipt.Instance == "" || receipt.Instance == previous {
		t.Fatalf("restarted Star did not accept a local write with a new instance: %v", cause)
	}
	for _, node := range nodes {
		outgoing, cause := node.client.Subscriber(local)
		if cause != nil {
			t.Fatal(cause)
		}
		systemAwait(t, ctx, "restored local write reaches an existing owner", func() bool {
			view := outgoing.State()
			value, present := view.Data.Get("restored")
			return view.Phase == comet.Ready && view.HasVersion && view.Data.Len() == 1 && present && value.String() == string(payload)
		})
		outgoing.Stop()
		if cause := outgoing.Wait(ctx); cause != nil {
			t.Fatal(cause)
		}
	}
}

// systemAwait polls public immutable views under one phase budget without resetting it.
func systemAwait(t *testing.T, ctx context.Context, label string, complete func() bool) {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for !complete() {
		select {
		case <-ctx.Done():
			t.Fatalf("%s exceeded its phase budget", label)
		case <-ticker.C:
		}
	}
}

// systemCommand rejects malformed handshakes and waits only for its named owned phase.
func systemCommand(t *testing.T, ctx context.Context, directory, action string, cycle int) {
	t.Helper()
	name := fmt.Sprintf("%s-%d", action, cycle)
	systemAwait(t, ctx, name, func() bool {
		data, cause := os.ReadFile(filepath.Join(directory, name))
		if os.IsNotExist(cause) {
			return false
		}
		if cause != nil || string(data) != name+"\n" {
			t.Fatalf("invalid owned fixture handshake %s: %v", name, cause)
		}
		return true
	})
}

// systemEvent reports the completed public oracle phase, never a requested outcome.
func systemEvent(t *testing.T, event string, cycle int) {
	t.Helper()
	data, cause := json.Marshal(struct {
		Event string `json:"event"` // Public phase recognized by the owning fixture.
		Cycle int    `json:"cycle"` // A/B/C cycle index.
		Star  int    `json:"star"`  // Independently crashed/restored origin index.
	}{event, cycle, cycle})
	if cause != nil {
		t.Fatal(cause)
	}
	fmt.Println(string(data))
}
