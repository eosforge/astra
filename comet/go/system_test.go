// Exercise three independently writable existing Stars only after explicit opt-in.
package comet_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/eosforge/astra/comet/go"
)

// systemNode owns only test-created SDK roles; it never controls deployed services.
type systemNode struct {
	client     *comet.Client     // One fixed existing Star target per node.
	publisher  *comet.Publisher  // Independent local Catalog writer.
	subscriber *comet.Subscriber // Cross-node complete Catalog view.
	beacon     *comet.Beacon     // Independent local registration and Data writer.
	observer   *comet.Observer   // Cross-node Ephemeris selector/estimate pool.
	reader     *comet.Reader     // Real Almanac stream; this SDK has no authority writer.
}

// TestSystemThreeStars is a functional mesh case, not a performance/soak claim.
// It requires COMET_SYSTEM_ENABLE=1 and exactly three prepared peer-connected Stars.
func TestSystemThreeStars(t *testing.T) {
	if os.Getenv("COMET_SYSTEM_ENABLE") != "1" {
		t.Skip("explicit three-Star system-test opt-in is absent")
	}
	addresses := strings.Split(os.Getenv("COMET_SYSTEM_ENDPOINTS"), ",")
	if len(addresses) != 3 {
		t.Fatal("COMET_SYSTEM_ENDPOINTS must contain exactly three comma-separated Star endpoints")
	}
	settings := comet.Options{Key: os.Getenv("COMET_SYSTEM_KEY"), Secret: []byte(os.Getenv("COMET_SYSTEM_SECRET")), CA: []byte(os.Getenv("COMET_SYSTEM_CA"))}
	if path := os.Getenv("COMET_SYSTEM_SECRET_FILE"); path != "" {
		if len(settings.Secret) != 0 {
			t.Fatal("provide only one of COMET_SYSTEM_SECRET and COMET_SYSTEM_SECRET_FILE")
		}
		secret, cause := os.ReadFile(path)
		if cause != nil {
			t.Fatalf("read system fixture secret: %v", cause)
		}
		settings.Secret = secret
	}
	settings.Anonymous = systemFlag(t, "COMET_SYSTEM_ANONYMOUS")
	settings.Plaintext = systemFlag(t, "COMET_SYSTEM_PLAINTEXT")
	control := os.Getenv("COMET_SYSTEM_CONTROL") // Optional owned-fixture crash/restart handshakes.
	if control != "" {
		entries, cause := os.ReadDir(control)
		if cause != nil || len(entries) != 0 {
			t.Fatalf("recovery control must be a fresh empty owned directory: %v", cause)
		}
	}
	var nonce [8]byte // A unique public scope prevents collision with other test/data owners.
	if _, cause := rand.Read(nonce[:]); cause != nil {
		t.Fatal(cause)
	}
	scope := comet.Scope{Sector: "comet-go-system", Spectrum: "run-" + hex.EncodeToString(nonce[:])}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	nodes := make([]systemNode, 3)
	identities := make([]string, 3)
	for index := range nodes {
		settings.Endpoints = []string{strings.TrimSpace(addresses[index])}
		if control != "" {
			for offset := 1; offset < len(addresses); offset++ {
				settings.Endpoints = append(settings.Endpoints, strings.TrimSpace(addresses[(index+offset)%len(addresses)]))
			}
		}
		client, cause := comet.New(settings)
		if cause != nil {
			t.Fatalf("node %d configuration: %v", index, cause)
		}
		nodes[index].client = client
		t.Cleanup(func() {
			client.Close()
			drain, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if cause := client.Wait(drain); cause != nil {
				t.Errorf("node %d cleanup: %v", index, cause)
			}
		})
		node := &nodes[index]
		if node.subscriber, cause = client.Subscriber(scope); cause != nil {
			t.Fatal(cause)
		}
		if node.reader, cause = client.Reader(scope); cause != nil {
			t.Fatal(cause)
		}
		if node.observer, cause = client.Observer(scope); cause != nil {
			t.Fatal(cause)
		}
		if node.publisher, cause = client.Publisher(scope); cause != nil {
			t.Fatal(cause)
		}
	}
	systemWritePhase(t, ctx, nodes, scope, "first", true)
	for index, node := range nodes {
		identities[index] = node.beacon.State().Identity.ID
	}
	systemConverged(t, ctx, nodes, identities, "first")
	// A local estimate on node zero must not modify another observer or source Beacon.
	selected, cause := nodes[0].observer.One(func(pool comet.Pool) *comet.Item { return pool.Find(identities[1]) })
	if cause != nil || selected == nil {
		t.Fatalf("cross-node selection: %v", cause)
	}
	if cause := selected.Update([]byte("local-estimate")); cause != nil {
		t.Fatal(cause)
	}
	other, cause := nodes[1].observer.One(func(pool comet.Pool) *comet.Item { return pool.Find(identities[1]) })
	if cause != nil || other == nil || other.Record().Data.String() != "first-1" {
		t.Fatal("local estimate leaked across observers")
	}
	// Every Star receives its own second-phase writes; traffic is bidirectional.
	systemWritePhase(t, ctx, nodes, scope, "second", true)
	systemConverged(t, ctx, nodes, identities, "second")
	residence := systemResidence(t, settings, addresses, scope, control)
	if control != "" {
		systemAuthority(t, settings, nodes, addresses, control)
		systemRecovery(t, settings, nodes, scope, identities, addresses, control, residence)
	}
	if residence != nil {
		residence.steady(t, nodes, control)
	}
}

// systemWritePhase releases all three local writers together and drains every
// result before reporting failures, so cleanup cannot race a late registration.
func systemWritePhase(t *testing.T, ctx context.Context, nodes []systemNode, scope comet.Scope, phase string, distinct bool) {
	t.Helper()
	type outcome struct {
		index    int    // Origin node, independent of completion order.
		instance string // Receipt target, used to reject duplicate endpoints.
		cause    error  // Primary write/registration failure for this node.
	}
	start := make(chan struct{})
	results := make(chan outcome, len(nodes))
	for index := range nodes {
		go func() {
			<-start
			node := &nodes[index]
			key := fmt.Sprintf("node-%d", index)
			payload := []byte(fmt.Sprintf("%s-%d", phase, index))
			receipt, cause := node.publisher.Update(ctx, []comet.Entry{{Key: key, Data: payload}}, time.Minute)
			if cause == nil {
				if node.beacon == nil {
					node.beacon, cause = node.client.Beacon(ctx, scope, []byte(key), payload, 10*time.Second, time.Second)
				} else {
					_, cause = node.beacon.Update(ctx, payload)
				}
			}
			results <- outcome{index: index, instance: receipt.Instance, cause: cause}
		}()
	}
	close(start)
	instances := make(map[string]bool)
	for range nodes {
		result := <-results
		if result.cause != nil {
			t.Errorf("node %d %s write: %v", result.index, phase, result.cause)
			continue
		}
		if distinct && instances[result.instance] {
			t.Error("system endpoints did not identify three independent Stars")
		}
		instances[result.instance] = true
	}
	if t.Failed() {
		t.FailNow()
	}
}

// systemConverged compares each live SDK projection with the prescribed write history.
func systemConverged(t *testing.T, ctx context.Context, nodes []systemNode, identities []string, phase string) {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		complete := true
		for _, node := range nodes {
			view, authority := node.subscriber.State(), node.reader.State()
			if view.Phase != comet.Ready || view.Data.Len() != 3 || authority.Phase != comet.Ready || !authority.HasVersion {
				complete = false
			}
			for index := range nodes {
				value, present := view.Data.Get(fmt.Sprintf("node-%d", index))
				if !present || value.String() != fmt.Sprintf("%s-%d", phase, index) {
					complete = false
				}
			}
			_, cause := node.observer.One(func(pool comet.Pool) *comet.Item {
				if pool.Len() != 3 {
					complete = false
				}
				for index, id := range identities {
					item := pool.Find(id)
					if item == nil || item.Record().Attr.String() != fmt.Sprintf("node-%d", index) || item.Record().Data.String() != fmt.Sprintf("%s-%d", phase, index) {
						complete = false
					}
				}
				return nil
			})
			if cause != nil {
				complete = false
			}
		}
		if complete {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("three-Star %s projections did not converge within the fixed budget", phase)
		case <-ticker.C:
		}
	}
}

// systemFlag requires explicit security opt-outs; missing values preserve secure defaults.
func systemFlag(t *testing.T, name string) bool {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		return false
	}
	flag, cause := strconv.ParseBool(value)
	if cause != nil {
		t.Fatalf("%s must be a Boolean", name)
	}
	return flag
}
