// Verify shared snapshot cancellation with transparent Context probes and owned, drained workers.
//go:build linux && cgo

package server

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eosforge/astra/polaris/internal/storage"
)

// barrier pauses the first storage deadline query after its creator has reserved a cache entry.
type barrier struct {
	context.Context                 // Preserve the actual deadline, cancellation and values.
	reached         chan struct{}   // Publish that the creator reached the read boundary.
	resume          <-chan struct{} // Release the creator without waiting for business time.
	once            sync.Once       // Later deadline queries retain ordinary Context behavior.
}

// Deadline exposes the real deadline after a bounded, explicitly released scheduling checkpoint.
func (probe *barrier) Deadline() (time.Time, bool) {
	probe.once.Do(func() {
		close(probe.reached)
		select {
		case <-probe.resume:
		case <-probe.Context.Done():
		}
	})
	return probe.Context.Deadline()
}

// observing reports when a waiter has reached its real cancellation channel.
type observing struct {
	context.Context               // Retain the underlying cancellation channel and error.
	reached         chan struct{} // Notify only after acquire has taken the additional reference.
	once            sync.Once     // Repeated channel queries do not close the notification twice.
}

// Done observes access without replacing readiness or manufacturing a cancellation result.
func (probe *observing) Done() <-chan struct{} {
	probe.once.Do(func() { close(probe.reached) })
	return probe.Context.Done()
}

// cancelling cancels at the post-readiness error check, after an initially live request.
type cancelling struct {
	context.Context                    // Supply the real cancellation result.
	cancel          context.CancelFunc // Trigger cancellation after selection of a ready entry.
	calls           atomic.Int32       // Identify the explicit preflight and post-readiness queries.
}

// Err performs the scheduled cancellation and returns only the underlying Context's actual error.
func (probe *cancelling) Err() error {
	if probe.calls.Add(1) == 2 {
		probe.cancel()
	}
	return probe.Context.Err()
}

// TestSnapshotCancellation preserves the creator's pin while returning only the cancelled waiter's ownership.
func TestSnapshotCancellation(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"waiting", "ready"} {
		t.Run(name, func(t *testing.T) {
			store := fixture(t, storage.Default())
			scope := storage.Scope{Sector: "s", Spectrum: "p"}
			if _, err := store.Commit(t.Context(), scope, storage.Change{Version: 1, Key: "key", Value: []byte("before")}); err != nil {
				t.Fatal(err)
			}
			cache := newCache(store, store.Limits(), 256<<20)
			cache.maximum = cache.reserve
			ctx, stop := context.WithTimeout(t.Context(), 5*time.Second)
			defer stop()
			waiter, cancel := context.WithCancel(ctx)
			defer cancel()
			type result struct {
				pin *pin  // Transfer the acquired reference to the caller or cleanup owner.
				err error // Preserve the actual acquisition result.
			}
			start := func(child context.Context) <-chan result {
				out, done := make(chan result, 1), make(chan struct{})
				go func() {
					defer close(done)
					pin, err := cache.acquire(child, scope, 1)
					out <- result{pin, err}
				}()
				t.Cleanup(func() {
					stop()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Fatal("snapshot worker did not drain")
					}
					select {
					case value := <-out:
						if value.pin != nil {
							value.pin.release()
						}
					default:
					}
				})
				return out
			}
			take := func(out <-chan result) result {
				select {
				case value := <-out:
					return value
				case <-ctx.Done():
					t.Fatal("controlled acquisition did not finish", ctx.Err())
					return result{}
				}
			}
			wait := func(signal <-chan struct{}) {
				select {
				case <-signal:
				case <-ctx.Done():
					t.Fatal("snapshot checkpoint was not reached", ctx.Err())
				}
			}
			ownership := func(references int) {
				cache.mutex.Lock()
				defer cache.mutex.Unlock()
				entry := cache.entries[position{Scope: scope, version: 1}]
				if entry == nil || len(cache.entries) != 1 || entry.references != references || cache.used != cache.reserve {
					t.Fatal("cancellation changed another reader's ownership")
				}
			}
			var held *pin
			if name == "waiting" {
				resume := make(chan struct{})
				probe := &barrier{Context: ctx, reached: make(chan struct{}), resume: resume}
				creator := start(probe)
				wait(probe.reached)
				ownership(1)
				observed := &observing{Context: waiter, reached: make(chan struct{})}
				pending := start(observed)
				wait(observed.reached)
				ownership(2)
				cancel()
				value := take(pending)
				if value.pin != nil {
					defer value.pin.release()
				}
				if value.pin != nil || !errors.Is(value.err, context.Canceled) {
					t.Fatal("cancelled waiter acquired the pending snapshot", value.err)
				}
				ownership(1)
				close(resume)
				value = take(creator)
				if value.err != nil || value.pin == nil {
					t.Fatal("waiter cancellation damaged the creator", value.err)
				}
				held = value.pin
			} else {
				var err error
				held, err = cache.acquire(ctx, scope, 1)
				if err != nil {
					t.Fatal(err)
				}
				defer held.release()
				probe := &cancelling{Context: waiter, cancel: cancel}
				value, err := cache.acquire(probe, scope, 1)
				if value != nil || !errors.Is(err, context.Canceled) || probe.calls.Load() != 2 {
					t.Fatal("ready selection ignored cancellation", err)
				}
			}
			defer held.release()
			ownership(1)
			expected := storage.Snapshot{Position: storage.Position{Scope: scope, Version: 1}, Records: []storage.Record{{Key: "key", Value: []byte("before")}}}
			if !reflect.DeepEqual(*held.Snapshot, expected) {
				t.Fatal("cancellation changed the creator's frozen content")
			}
			held.release()
			if cache.used != 0 || len(cache.entries) != 0 {
				t.Fatal("last reader failed to return the full reservation")
			}
			healthy, err := cache.acquire(ctx, scope, 1)
			if healthy != nil {
				defer healthy.release()
			}
			if err != nil || healthy == nil || !reflect.DeepEqual(*healthy.Snapshot, expected) {
				t.Fatal("cancelled request poisoned the next acquisition", err)
			}
			healthy.release()
			if cache.used != 0 || len(cache.entries) != 0 {
				t.Fatal("healthy acquisition retained ownership")
			}
		})
	}
}
