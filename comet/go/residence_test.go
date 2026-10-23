// Retain the finite three-origin workload and its workers across real node faults.
package comet_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eosforge/astra/comet/go"
)

// residenceJob borrows one immutable round payload until its result is drained.
type residenceJob struct {
	context context.Context // One finite budget covers readiness, writes and convergence.
	data    []byte          // Exactly 2 KiB, independently prescribed by round and origin.
	start   <-chan struct{} // Release all 96 persistent workers after every job is assigned.
}

// residenceResult carries an actual native receipt, never a requested outcome.
type residenceResult struct {
	slot         int                 // Two persistent workers per record, Catalog then Beacon.
	publication  comet.Receipt       // Present only for the Catalog worker.
	registration comet.BeaconReceipt // Present only for the Beacon worker.
	cause        error               // Preserve every original write failure without retry.
}

// residence owns 48 records per domain on three fixed physical endpoints.
type residence struct {
	nodes      [3]systemNode         // Fixed clients retain their public roles across all faults.
	publishers [48]*comet.Publisher  // One original Publisher for each independently owned key.
	beacons    [48]*comet.Beacon     // One original registration for each fixed logical identity.
	identities [48]string            // Confirmed IDs cannot be replaced after trusted restart.
	versions   [48]uint64            // Every acknowledged Catalog update must advance.
	orders     [48]uint64            // Every acknowledged Beacon update must advance.
	jobs       [96]chan residenceJob // Workers persist through the complete observation interval.
	results    chan residenceResult  // All in-flight work drains before a failure is reported.
	workers    sync.WaitGroup        // Test cleanup joins workers before closing their clients.
	seconds    int                   // Zero is a short control; 7200 is the declared finite envelope.
	round      uint64                // Strictly increasing payload oracle and progress counter.
}

// systemResidence prepares optional finite resource work before any authority or
// Star fault. The same clients, roles, registration IDs and workers survive them.
func systemResidence(t *testing.T, settings comet.Options, addresses []string, scope comet.Scope, control string) *residence {
	t.Helper()
	value, enabled := os.LookupEnv("COMET_SYSTEM_RESIDENCE_SECONDS")
	if !enabled {
		return nil
	}
	if control == "" || (value != "0" && value != "7200") || len(addresses) != 3 {
		t.Fatal("residence requires an owned three-Star fixture and exactly 0 or 7200 seconds")
	}
	workload := &residence{results: make(chan residenceResult, 96)}
	if value == "7200" {
		workload.seconds = 7200
	}
	scope.Sector = "comet-go-residence"
	settings.Timeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	for index := range workload.nodes {
		settings.Endpoints = []string{strings.TrimSpace(addresses[index])}
		client, cause := comet.New(settings)
		if cause != nil {
			t.Fatal(cause)
		}
		t.Cleanup(func() {
			client.Close()
			drain, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if cause := client.Wait(drain); cause != nil {
				t.Errorf("residence client %d drain: %v", index, cause)
			}
		})
		node := &workload.nodes[index]
		node.client = client
		if node.subscriber, cause = client.Subscriber(scope); cause != nil {
			t.Fatal(cause)
		}
		if node.observer, cause = client.Observer(scope); cause != nil {
			t.Fatal(cause)
		}
	}
	identities := make(map[string]bool, len(workload.beacons))
	for index := range workload.publishers {
		client := workload.nodes[index%len(workload.nodes)].client
		var cause error
		if workload.publishers[index], cause = client.Publisher(scope); cause != nil {
			t.Fatal(cause)
		}
		if workload.beacons[index], cause = client.Beacon(ctx, scope, []byte("attr"), nil, 3*time.Second, time.Second); cause != nil {
			t.Fatal(cause)
		}
		state := workload.beacons[index].State()
		if !state.HasIdentity || len(state.Identity.ID) != 16 || identities[state.Identity.ID] {
			t.Fatal("residence registration lacks a distinct confirmed identity")
		}
		identities[state.Identity.ID] = true
		workload.identities[index] = state.Identity.ID
	}
	for slot := range workload.jobs {
		workload.jobs[slot] = make(chan residenceJob)
		workload.workers.Add(1)
		go func() {
			defer workload.workers.Done()
			for job := range workload.jobs[slot] {
				<-job.start
				index := slot / 2
				result := residenceResult{slot: slot}
				if slot%2 == 0 {
					result.publication, result.cause = workload.publishers[index].Update(job.context, []comet.Entry{{Key: fmt.Sprint(index), Data: job.data}}, 3*time.Second)
				} else {
					result.registration, result.cause = workload.beacons[index].Update(job.context, job.data)
				}
				workload.results <- result
			}
		}()
	}
	t.Cleanup(func() {
		for _, jobs := range workload.jobs {
			close(jobs)
		}
		workload.workers.Wait()
	})
	workload.replicate(t)
	workload.replicate(t)
	return workload
}

// replicate commits fresh bytes at every physical Star and observes all nine
// replication routes without retries, replacement owners or new per-round workers.
func (workload *residence) replicate(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	systemAwait(t, ctx, "all original residence Beacons ready", func() bool {
		for index, beacon := range workload.beacons {
			state := beacon.State()
			if state.HasIdentity && state.Identity.ID != workload.identities[index] {
				t.Fatal("residence Beacon replaced its original logical identity")
			}
			if state.Phase != comet.Ready || !state.HasIdentity {
				return false
			}
		}
		return true
	})
	workload.round++
	if workload.round == 0 {
		t.Fatal("residence round exhausted")
	}
	var payloads [48][]byte
	for index := range payloads {
		payloads[index] = bytes.Repeat([]byte{byte(index)}, 2048)
		binary.LittleEndian.PutUint64(payloads[index], workload.round)
	}
	start := make(chan struct{})
	for slot, jobs := range workload.jobs {
		jobs <- residenceJob{context: ctx, data: payloads[slot/2], start: start}
	}
	close(start)
	var receipts [48]comet.Receipt
	var registrations [48]comet.BeaconReceipt
	for range workload.jobs {
		result := <-workload.results
		if result.cause != nil {
			t.Errorf("residence round %d worker %d: %v", workload.round, result.slot, result.cause)
		}
		if result.slot%2 == 0 {
			receipts[result.slot/2] = result.publication
		} else {
			registrations[result.slot/2] = result.registration
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	var instances [3]string
	for index, receipt := range receipts {
		origin := index % len(workload.nodes)
		if index < len(workload.nodes) {
			instances[origin] = receipt.Instance
		}
		if receipt.Instance == "" || receipt.Instance != instances[origin] || receipt.Version <= workload.versions[index] || registrations[index].Identity.Instance != instances[origin] || registrations[index].Identity.ID != workload.identities[index] || registrations[index].Order <= workload.orders[index] {
			t.Fatal("residence receipt changed its physical origin, version or logical identity")
		}
		workload.versions[index] = receipt.Version
		workload.orders[index] = registrations[index].Order
	}
	if instances[0] == instances[1] || instances[0] == instances[2] || instances[1] == instances[2] {
		t.Fatal("residence writes did not reach three distinct Stars")
	}
	systemAwait(t, ctx, "complete residence projections on all three Stars", func() bool {
		complete := true
		for target, node := range workload.nodes {
			view := node.subscriber.State()
			if view.Phase != comet.Ready || !view.HasVersion || view.Instance != instances[target] || view.Data.Len() != len(payloads) {
				complete = false
			}
			for index, payload := range payloads {
				value, present := view.Data.Get(fmt.Sprint(index))
				if !present || value.String() != string(payload) {
					complete = false
				}
			}
			_, cause := node.observer.One(func(pool comet.Pool) *comet.Item {
				if pool.Len() != len(payloads) {
					complete = false
				}
				for index, id := range workload.identities {
					item := pool.Find(id)
					if item == nil || item.Record().Attr.String() != "attr" || item.Record().Data.String() != string(payloads[index]) {
						complete = false
					}
				}
				return nil
			})
			if cause != nil {
				complete = false
			}
		}
		return complete
	})
	if workload.round == 1 || workload.round%100 == 0 {
		fmt.Printf("{\"event\":\"mesh_progress\",\"round\":%d,\"workers\":96}\n", workload.round)
	}
}

// steady retains exactly the declared workload through one monotonic interval.
// The owner samples native process resources; this helper cannot grant a pass.
func (workload *residence) steady(t *testing.T, nodes []systemNode, control string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	readers := make([]*comet.Reader, len(nodes))
	for index, node := range nodes {
		node.publisher.Close()
		node.beacon.Destroy()
		node.subscriber.Stop()
		node.observer.Stop()
		for _, wait := range []func(context.Context) error{node.publisher.Wait, node.beacon.Wait, node.subscriber.Wait, node.observer.Wait} {
			if cause := wait(ctx); cause != nil {
				t.Fatal(cause)
			}
		}
		readers[index] = node.reader
	}
	started := workload.round
	fmt.Printf("{\"event\":\"mesh_steady\",\"cycles\":3,\"seconds\":%d,\"records\":48,\"workers\":96}\n", workload.seconds)
	// The fixture records its observation boundary before releasing the SDK clock.
	systemCommand(t, ctx, control, "residence-start", 0)
	until := time.Now().Add(time.Duration(workload.seconds) * time.Second)
	for {
		workload.replicate(t)
		func() {
			check, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			systemAuthorityViews(t, check, readers, 8, 8, []byte("go-after"))
		}()
		if workload.round-started >= 2 && !time.Now().Before(until) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, node := range workload.nodes {
		if node.client.Panics() != 0 {
			t.Fatal("residence callback panic")
		}
	}
	fmt.Printf("{\"event\":\"mesh_replicated\",\"rounds\":%d,\"records\":48}\n", workload.round-started)
}
