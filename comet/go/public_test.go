// Exercise public validation and byte admission against observable RPC histories.
package comet

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// TestPublicFactoriesRejectInvalidInput leaves role admission and remote state untouched.
func TestPublicFactoriesRejectInvalidInput(t *testing.T) {
	var calls atomic.Int32
	fixture := newFixture(t, fixtureHandlers{
		catalog: func(_ *protocol.WatchRequest, _ grpc.ServerStreamingServer[protocol.CatalogWatchReply]) error {
			calls.Add(1)
			return status.Error(codes.Unimplemented, "invalid local input reached Catalog")
		},
		almanac: func(_ *protocol.WatchRequest, _ grpc.ServerStreamingServer[protocol.AlmanacWatchReply]) error {
			calls.Add(1)
			return status.Error(codes.Unimplemented, "invalid local input reached Almanac")
		},
		ephemeris: func(_ *protocol.WatchRequest, _ grpc.ServerStreamingServer[protocol.EphemerisWatchReply]) error {
			calls.Add(1)
			return status.Error(codes.Unimplemented, "invalid local input reached Ephemeris")
		},
		create: func(context.Context, *protocol.CreateRequest) (*protocol.CreateReply, error) {
			calls.Add(1)
			return nil, status.Error(codes.Unimplemented, "invalid local input reached Create")
		},
	})
	client := fixtureClient(t, fixture, Options{Anonymous: true, Plaintext: true, Readers: 1, Beacons: 1})
	invalid := Scope{Sector: "__private", Spectrum: "unchanged"}
	cases := []struct {
		name string
		call func() error
	}{
		{"publisher-scope", func() error { _, cause := client.Publisher(invalid); return cause }},
		{"subscriber-scope", func() error { _, cause := client.Subscriber(invalid); return cause }},
		{"reader-scope", func() error { _, cause := client.Reader(invalid); return cause }},
		{"observer-scope", func() error { _, cause := client.Observer(invalid); return cause }},
		{"subscriber-key", func() error { _, cause := client.SubscriberKey(testScope(), ""); return cause }},
		{"reader-key", func() error { _, cause := client.ReaderKey(testScope(), "bad\x00key"); return cause }},
		{"subscriber-options", func() error { _, cause := client.Subscriber(testScope(), ReadOptions{Records: -1}); return cause }},
		{"reader-options", func() error { _, cause := client.Reader(testScope(), ReadOptions{Bytes: 1}); return cause }},
		{"observer-options", func() error { _, cause := client.Observer(testScope(), ReadOptions{}, ReadOptions{}); return cause }},
		{"beacon-scope", func() error {
			_, cause := client.Beacon(testContext(t), invalid, nil, nil, time.Second, time.Millisecond)
			return cause
		}},
		{"beacon-ttl", func() error {
			_, cause := client.Beacon(testContext(t), testScope(), nil, nil, time.Second+1, time.Millisecond)
			return cause
		}},
		{"beacon-beat", func() error {
			_, cause := client.Beacon(testContext(t), testScope(), nil, nil, time.Second, time.Second)
			return cause
		}},
		{"beacon-attr", func() error {
			_, cause := client.Beacon(testContext(t), testScope(), make([]byte, 1024*1024+1), nil, time.Second, time.Millisecond)
			return cause
		}},
	}
	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) { requireCode(t, testcase.call(), CodeInput, Unapplied) })
	}
	if calls.Load() != 0 || client.used.Load() != 0 {
		t.Fatal("rejected public factory retained bytes or submitted an RPC")
	}
	publisher, cause := client.Publisher(testScope())
	if cause != nil {
		t.Fatalf("rejected factory consumed the writer quota: %v", cause)
	}
	publisher.Close()
	if cause := publisher.Wait(testContext(t)); cause != nil {
		t.Fatal(cause)
	}
}

// TestPublisherLocalRejectionsPreserveAdmission checks public inputs, cancellation and actual recovery.
func TestPublisherLocalRejectionsPreserveAdmission(t *testing.T) {
	var queries, writes atomic.Int32
	fixture := newFixture(t, fixtureHandlers{
		query: func(_ context.Context, request *protocol.CatalogQueryRequest) (*protocol.CatalogQueryReply, error) {
			queries.Add(1)
			return &protocol.CatalogQueryReply{Instance: []byte("star-a"), Entries: []*protocol.CatalogQueryReply_Entry{{Key: request.Keys[0]}}}, nil
		},
		publish: func(_ context.Context, request *protocol.PublishRequest) (*protocol.PublishReply, error) {
			writes.Add(1)
			return &protocol.PublishReply{Instance: request.Instance, Version: request.Version}, nil
		},
	})
	client := fixtureClient(t, fixture, Options{Anonymous: true, Plaintext: true, Bytes: 16384})
	publisher, cause := client.Publisher(testScope())
	if cause != nil {
		t.Fatal(cause)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	cases := []struct {
		name    string
		ctx     context.Context
		entries []Entry
		ttl     time.Duration
		code    Code
	}{
		{"nil-context", nil, []Entry{{Key: "k"}}, time.Second, CodeInput},
		{"canceled", canceled, []Entry{{Key: "k"}}, time.Second, CodeCanceled},
		{"empty-batch", testContext(t), nil, time.Second, CodeInput},
		{"too-many", testContext(t), make([]Entry, 129), time.Second, CodeInput},
		{"ttl", testContext(t), []Entry{{Key: "k"}}, time.Millisecond, CodeInput},
		{"key", testContext(t), []Entry{{Key: strings.Repeat("k", 1025)}}, time.Second, CodeInput},
		{"body", testContext(t), []Entry{{Key: "k", Data: make([]byte, 1024*1024+1)}}, time.Second, CodeInput},
		{"total", testContext(t), []Entry{{Key: "k", Data: make([]byte, 1024*1024)}}, time.Second, CodeInput},
		{"budget", testContext(t), []Entry{{Key: "k", Data: make([]byte, 8192)}}, time.Second, CodeBusy},
	}
	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			receipt, cause := publisher.Update(testcase.ctx, testcase.entries, testcase.ttl)
			requireCode(t, cause, testcase.code, Unapplied)
			if receipt != (Receipt{}) || queries.Load() != 0 || writes.Load() != 0 {
				t.Fatal("local rejection fabricated a receipt or reached the wire")
			}
		})
	}
	receipt, cause := publisher.Update(testContext(t), []Entry{{Key: "k", Data: []byte("fresh")}}, time.Second)
	if cause != nil || receipt.Version != 1 || queries.Load() != 1 || writes.Load() != 1 {
		t.Fatalf("local rejections leaked admission or consumed a version: %#v %v", receipt, cause)
	}
}

// TestBeaconLocalAdmission leaves failed factories ownerless and rejects invalid updates before submission.
func TestBeaconLocalAdmission(t *testing.T) {
	var creates, updates atomic.Int32
	fixture := newFixture(t, fixtureHandlers{
		create: func(_ context.Context, request *protocol.CreateRequest) (*protocol.CreateReply, error) {
			creates.Add(1)
			return &protocol.CreateReply{Instance: []byte("star-a"), Uuid: fixtureID(), Capability: make([]byte, 32), Generation: request.Generation, TtlMs: request.TtlMs, Data: request.Data}, nil
		},
		update: func(_ context.Context, request *protocol.UpdateRequest) (*protocol.UpdateReply, error) {
			updates.Add(1)
			return &protocol.UpdateReply{Order: request.Order}, nil
		},
	})
	limited := fixtureClient(t, fixture, Options{Anonymous: true, Plaintext: true, Bytes: 16384})
	_, cause := limited.Beacon(testContext(t), testScope(), make([]byte, 32768), nil, time.Second, time.Millisecond)
	requireCode(t, cause, CodeBusy, Unapplied)
	if creates.Load() != 0 || limited.used.Load() != 0 {
		t.Fatal("factory budget rejection retained work or reached Create")
	}
	client := fixtureClient(t, fixture)
	_, cause = client.Beacon(nil, testScope(), nil, nil, time.Second, time.Millisecond)
	requireCode(t, cause, CodeInput, Unapplied)
	beacon, cause := client.Beacon(testContext(t), testScope(), nil, nil, 10*time.Second, 5*time.Second)
	if cause != nil {
		t.Fatal(cause)
	}
	_, cause = beacon.Update(nil, nil)
	requireCode(t, cause, CodeInput, Unapplied)
	_, cause = beacon.Update(testContext(t), make([]byte, 1024*1024+1))
	requireCode(t, cause, CodeInput, Unapplied)
	requireCode(t, beacon.Tick(0, func() ([]byte, error) { t.Error("rejected sampler ran"); return nil, nil }), CodeInput, Unapplied)
	if creates.Load() != 1 || updates.Load() != 0 {
		t.Fatal("invalid Beacon operation performed network work")
	}
	receipt, cause := beacon.Update(testContext(t), nil)
	if cause != nil || receipt.Order != 1 || updates.Load() != 1 {
		t.Fatalf("invalid operation consumed an order or damaged admission: %#v %v", receipt, cause)
	}
	beacon.Destroy()
	if cause := beacon.Wait(testContext(t)); cause != nil {
		t.Fatal(cause)
	}
	requireCode(t, beacon.Changed(func(BeaconState) { t.Error("closed callback ran") }), CodeClosed, Unapplied)
}

// TestFailedBeaconFactoryReturnsQuota distinguishes a failed submitted Create from a retained owner.
func TestFailedBeaconFactoryReturnsQuota(t *testing.T) {
	var creates atomic.Int32
	fixture := newFixture(t, fixtureHandlers{create: func(_ context.Context, request *protocol.CreateRequest) (*protocol.CreateReply, error) {
		if creates.Add(1) == 1 {
			return nil, status.Error(codes.Unavailable, "private lost create reply")
		}
		return &protocol.CreateReply{Instance: []byte("star-a"), Uuid: fixtureID(), Capability: make([]byte, 32), Generation: request.Generation, TtlMs: request.TtlMs, Data: request.Data}, nil
	}})
	client := fixtureClient(t, fixture, Options{Anonymous: true, Plaintext: true, Beacons: 1})
	beacon, cause := client.Beacon(testContext(t), testScope(), nil, nil, 10*time.Second, 5*time.Second)
	requireCode(t, cause, CodeTransport, Unknown)
	if beacon != nil || creates.Load() != 1 {
		t.Fatal("failed factory returned a live owner or retried the submitted Create")
	}
	// A failed factory returns no handle, but its bounded cleanup still owns the
	// quota until actual drain. Observe that boundary before a new caller retries.
	awaitCondition(t, func() bool {
		client.mu.Lock()
		defer client.mu.Unlock()
		return client.writers == 0
	})
	beacon, cause = client.Beacon(testContext(t), testScope(), nil, nil, 10*time.Second, 5*time.Second)
	if cause != nil || beacon == nil || creates.Load() != 2 || !beacon.State().HasIdentity {
		t.Fatalf("failed factory retained quota or damaged the fresh caller: %v", cause)
	}
	beacon.Destroy()
	if cause := beacon.Wait(testContext(t)); cause != nil {
		t.Fatal(cause)
	}
}
