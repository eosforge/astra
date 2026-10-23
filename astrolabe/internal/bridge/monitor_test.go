// Verify bounded monitoring, periodic sampling and owner cancellation through native HTTP requests.
package bridge

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// receive bounds fixture coordination without advancing application time by sleeping.
func receive[T any](t *testing.T, channel <-chan T) T {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-time.After(10 * time.Second):
		t.Fatal("monitor fixture did not reach its owned boundary")
		var zero T
		return zero
	}
}

// monitor owns the parent context and joins the collector before server or fixture teardown.
func monitor(t *testing.T, backend *Backend, targets map[string]string) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		backend.Monitor(ctx, targets, &tls.Config{})
	}()
	t.Cleanup(func() { cancel(); receive(t, done) })
	return cancel, done
}

// TestMonitor observes actual requests and cache publication before checking cancellation retirement.
func TestMonitor(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		check := counter(t)
		backend := &Backend{}
		backend.Monitor(t.Context(), nil, nil)
		check(backend.metrics == nil, "disabled monitoring created observation state")
	})
	for _, name := range []string{"cancel", "closed"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			check := counter(t)
			backend := &Backend{members: make(map[string]string)}
			targets := make(map[string]string)
			started, retired := make(chan bool, 5), make(chan struct{}, 5)
			var calls atomic.Int32
			for index := range 5 {
				endpoint := strconv.Itoa(index)
				// Separate hosts permit all four workers to enter despite the per-host connection cap.
				server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
					calls.Add(1)
					started <- request.Header.Get("Authorization") == "" && request.Header.Get("Cookie") == ""
					<-request.Context().Done()
					retired <- struct{}{}
				}))
				t.Cleanup(server.Close)
				targets[endpoint] = server.URL + "/metrics"
				backend.nodes = append(backend.nodes, node{ID: "current", Endpoint: endpoint, Role: "ROLE_STAR"})
				backend.members[endpoint] = "current"
			}
			cancel, done := monitor(t, backend, targets)
			for range 4 {
				check(receive(t, started), "collector forwarded an authorization header or cookie")
			}
			check(calls.Load() == 4, "collector exceeded its four-worker admission bound")
			if name == "closed" {
				backend.Close()
			}
			cancel()
			receive(t, done)
			for range 4 {
				receive(t, retired)
			}
			check(calls.Load() == 4, "a queued scrape escaped cancellation")
			backend.mutex.RLock()
			defer backend.mutex.RUnlock()
			if name == "closed" {
				check(len(backend.metrics) == 0, "late canceled work published after backend close")
			}
			for _, value := range backend.metrics {
				check(value.Stale && value.Values == nil && value.Observed.IsZero(), "canceled scrape became a successful observation")
			}
		})
	}
	for _, name := range []string{"periodic", "redirect"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			check := counter(t)
			backend := &Backend{nodes: []node{{ID: "current", Endpoint: "endpoint", Role: "ROLE_STAR"}}, members: map[string]string{"endpoint": "current"}}
			type observation struct {
				path    string // The second request must come from the next tick, not a followed redirect.
				clean   bool   // Public metrics never carry control-plane credentials.
				metric  metric // Immutable first-round values, captured under the backend lock.
				present bool   // The first round must have published before the next one starts.
			}
			observed, retired := make(chan observation, 1), make(chan struct{}, 1)
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if calls.Add(1) == 1 {
					if name == "redirect" {
						response.Header().Set("Location", "/trap")
						response.WriteHeader(http.StatusTemporaryRedirect)
					} else {
						response.Header().Set("X-Astra-Instance", "current")
						_, _ = response.Write([]byte(payload))
					}
					return
				}
				backend.mutex.RLock()
				value, present := backend.metrics["endpoint"]
				backend.mutex.RUnlock()
				observed <- observation{request.URL.Path, request.Header.Get("Authorization") == "" && request.Header.Get("Cookie") == "", value, present}
				<-request.Context().Done()
				retired <- struct{}{}
			}))
			t.Cleanup(server.Close)
			cancel, done := monitor(t, backend, map[string]string{"endpoint": server.URL + "/metrics"})
			value := receive(t, observed)
			check(value.path == "/metrics" && value.clean && value.present, "collector followed a redirect, leaked credentials or skipped publication")
			check(value.metric.ID == "current" && !value.metric.Attempted.IsZero(), "first attempt lost its identity or timestamp")
			if name == "periodic" {
				check(!value.metric.Stale && !value.metric.Observed.IsZero() && len(value.metric.Values) == 8 && value.metric.Values["astra_members"] == "2", "complete first sample was not retained across ticks")
			} else {
				check(value.metric.Stale && value.metric.Observed.IsZero() && value.metric.Values == nil, "redirect became a trusted observation")
			}
			cancel()
			receive(t, done)
			receive(t, retired)
			check(calls.Load() == 2, "collector failed to retire at the controlled second request")
		})
	}
}
