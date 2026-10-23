//go:build linux && cgo

package storage

import (
	"errors"
	"testing"
)

// TestFeedBoundary subscribes before baseline and checks continuous suffix after history trimming without depending on network speed.
func TestFeedBoundary(t *testing.T) {
	t.Parallel()
	limits := Default()
	limits.History = 1
	store, _, _ := fixture(t, limits)
	feed, err := store.Subscribe(4096, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer feed.Close()
	scope := Scope{"s", "p"}
	ready := feed.Ready()
	for version := Version(1); version <= 4; version++ {
		value := []byte{byte(version)}
		requireCommit(t, store, scope, Change{Version: version, Key: "k", Value: value})
		value[0] = 255
	}
	select {
	case <-ready:
	default:
		t.Fatal("lost commit notification")
	}
	if _, err := store.Since(t.Context(), scope, 0); !errors.Is(err, ErrHistory) {
		t.Fatal("test did not exceed durable replay window", err)
	}
	events, err := feed.Take()
	if err != nil || len(events) != 4 {
		t.Fatal("missing bounded catch-up suffix", err)
	}
	for index, event := range events {
		if event.Version != Version(index+1) || event.Scope != scope || event.Value[0] != byte(index+1) {
			t.Fatal("feed reordered commit or retained mutable input")
		}
	}
	// Confirmed retries do not rebroadcast, and failed commits leave no partial Event.
	requireCommit(t, store, scope, Change{Version: 4, Key: "k", Value: []byte{4}})
	if _, err := store.Commit(t.Context(), scope, Change{Version: 6, Key: "k"}); !errors.Is(err, ErrVersion) {
		t.Fatal(err)
	}
	if events, err := feed.Take(); err != nil || len(events) != 0 {
		t.Fatal("retry or failure became new publication", err)
	}
}

// TestFeedCapacity ends only the slow consumer on budget failure, preserving commits, other targets, and later subscriptions.
func TestFeedCapacity(t *testing.T) {
	t.Parallel()
	store, _, _ := fixture(t, Default())
	small, err := store.Subscribe(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer small.Close()
	fast, err := store.Subscribe(4096, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer fast.Close()
	requireCommit(t, store, Scope{"s", "p"}, Change{Version: 1, Key: "k"})
	if _, err := small.Take(); !errors.Is(err, ErrCapacity) {
		t.Fatal("slow feed did not report overflow", err)
	}
	if events, err := fast.Take(); err != nil || len(events) != 1 {
		t.Fatal("slow feed blocked independent consumer", err)
	}
	small.Close()
	small.Close()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := fast.Take(); !errors.Is(err, ErrClosed) {
		t.Fatal("closed store left feed alive", err)
	}
	if _, err := store.Subscribe(4096, 8); !errors.Is(err, ErrClosed) {
		t.Fatal("closed store accepted new feed", err)
	}
}
