// Isolate unary forwarding, mapped-role filtering and failure freshness from unrelated input defects.
package bridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/eosforge/astra/internal/generated/polaris"
)

// TestEmptyCommit forwards a nonnil empty request once and preserves the authority's refusal.
func TestEmptyCommit(t *testing.T) {
	check := evidence(t, "ASTROLABE-TRANSPORT")
	service := &authority{commit: func(_ context.Context, input *polaris.CommitRequest) (*polaris.Position, error) {
		if input.Change != nil || len(input.Changes) != 0 || input.Scope != nil || input.Version != 0 {
			return nil, status.Error(codes.Internal, "empty request changed")
		}
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}}
	backend, _, _ := transport(t, service)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	value, err := backend.Commit(ctx, &polaris.CommitRequest{})
	check(value == nil && status.Code(err) == codes.InvalidArgument, "empty unary request lost its authority refusal")
	check(service.commits.Load() == 1 && service.batches.Load() == 0, "empty request was retried or changed into a batch")
}

// TestMappedRole proves that an explicit scrape mapping never overrides the directory role.
func TestMappedRole(t *testing.T) {
	for _, role := range []string{"ROLE_STAR", "ROLE_POLARIS"} {
		t.Run(role, func(t *testing.T) {
			check := evidence(t, "ASTROLABE-METRICS")
			var calls atomic.Int32
			endpoint := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				calls.Add(1)
				response.WriteHeader(http.StatusServiceUnavailable)
			}))
			defer endpoint.Close()
			backend := &Backend{nodes: []node{{ID: "member", Role: role, Endpoint: "127.0.0.1:7447"}}, members: map[string]string{"127.0.0.1:7447": "member"}}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			backend.sample(ctx, endpoint.Client(), map[string]string{"127.0.0.1:7447": endpoint.URL + "/metrics"})
			if role == "ROLE_STAR" {
				check(calls.Load() == 1 && len(backend.metrics) == 1, "mapped Star was not sampled exactly once")
				check(backend.metrics["127.0.0.1:7447"].Stale, "failed scrape became a healthy observation")
			} else {
				check(calls.Load() == 0 && len(backend.metrics) == 0, "mapped non-Star received a Star scrape")
			}
		})
	}
}

// TestCachedFailure preserves recent values while exposing a failed refresh as stale immediately.
func TestCachedFailure(t *testing.T) {
	for _, failed := range []bool{false, true} {
		name := "fresh"
		if failed {
			name = "failed"
		}
		t.Run(name, func(t *testing.T) {
			check := evidence(t, "ASTROLABE-METRICS")
			now := time.Now()
			backend := &Backend{nodes: []node{{ID: "member", Role: "ROLE_STAR", Endpoint: "127.0.0.1:7447"}}, metrics: map[string]metric{"127.0.0.1:7447": {ID: "member", Observed: now, Attempted: now, Stale: failed}}}
			data, err := json.Marshal(backend.Metrics())
			check(err == nil, "could not encode cached metrics")
			var result struct {
				Samples []metric `json:"samples"` // Public freshness projection.
			}
			check(json.Unmarshal(data, &result) == nil && len(result.Samples) == 1, "cached member disappeared")
			check(result.Samples[0].Stale == failed && result.Samples[0].Observed.Equal(now), "failed refresh discarded observation identity or stayed fresh")
			check(backend.metrics["127.0.0.1:7447"].Stale == failed, "projection changed the stored freshness flag")
		})
	}
}
