// Verify durable retry intent independently of current values and network/process identity.
//go:build linux && cgo

package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

// TestRetryIdentity covers ordered batch identity, normalization, cross-scope isolation and expired receipts.
func TestRetryIdentity(t *testing.T) {
	check := verification(t, "STORAGE-RETRY-IDENTITY")
	rows := 0
	for _, mode := range []string{"retained", "evicted", "disabled"} {
		limits := Default()
		limits.History = 1
		if mode == "disabled" {
			limits.History = 0
		}
		store, path, binding := fixture(t, limits)
		scope := Scope{"retry", mode}
		original := []Change{{Key: "a", Value: []byte{}}, {Key: "b", Value: []byte{0, 1, 255}}}
		version, err := store.CommitBatch(t.Context(), scope, 1, original)
		check(err == nil && version == 1, "establish the complete original request")
		if mode == "evicted" {
			version, err = store.CommitBatch(t.Context(), scope, 2, original)
			check(err == nil && version == 2, "evict version one while retaining identical final values")
		}
		check(store.Close() == nil, "close the original authority owner")
		store, err = Open(t.Context(), path, binding, limits, false)
		check(err == nil, "reopen the same database and deployment binding")
		opened := store
		t.Cleanup(func() { check(opened.Close() == nil, "close the reopened authority") })
		feed, err := store.Subscribe(4096, 8)
		check(err == nil, "observe only post-restart commits")
		defer feed.Close()
		capture := func() Snapshot {
			image, err := store.Load(t.Context(), scope)
			if err != nil {
				t.Fatal("capture complete current records independently of receipt retention", err)
			}
			return image
		}
		cases := []struct {
			name    string   // Explicit request distinction, not an implementation-derived result.
			changes []Change // Ordered request contents at the original version.
			accept  bool     // Only identical normalized batch bytes may confirm a retained receipt.
		}{
			{"identical", []Change{{Key: "a", Value: []byte{}}, {Key: "b", Value: []byte{0, 1, 255}}}, true},
			{"nil-empty", []Change{{Key: "a"}, {Key: "b", Value: []byte{0, 1, 255}}}, true},
			{"explicit-entry-version", []Change{{Version: 1, Key: "a"}, {Version: 1, Key: "b", Value: []byte{0, 1, 255}}}, true},
			{"changed-byte", []Change{{Key: "a"}, {Key: "b", Value: []byte{0, 2, 255}}}, false},
			{"changed-key", []Change{{Key: "c"}, {Key: "b", Value: []byte{0, 1, 255}}}, false},
			{"empty-to-delete", []Change{{Key: "a", Erase: true}, {Key: "b", Value: []byte{0, 1, 255}}}, false},
			{"reordered", []Change{{Key: "b", Value: []byte{0, 1, 255}}, {Key: "a"}}, false},
			{"omitted", []Change{{Key: "a"}}, false},
			{"additional", []Change{{Key: "a"}, {Key: "b", Value: []byte{0, 1, 255}}, {Key: "c", Erase: true}}, false},
		}
		for _, point := range cases {
			before, saved := capture(), contents(t, store.writeSQL)
			changed, ready := store.Changed(), feed.Ready()
			version, err := store.CommitBatch(t.Context(), scope, 1, point.changes)
			want := ErrVersion
			if mode != "retained" {
				want = ErrUncertain
			} else if point.accept {
				want = nil
			}
			check((want == nil && err == nil && version == 1) || (want != nil && errors.Is(err, want) && version == 0), "retry outcome follows retained intent evidence")
			check(reflect.DeepEqual(capture(), before) && contents(t, store.writeSQL) == saved, "retry leaves complete durable state, history and accounting unchanged")
			select {
			case <-changed:
				check(false, "a confirmed or refused retry cannot create a store notification")
			case <-ready:
				check(false, "a confirmed or refused retry cannot create a feed notification")
			default:
				check(true, "retry creates neither notification")
			}
			events, taken := feed.Take()
			check(taken == nil && len(events) == 0 && store.readSQL.Stats().InUse == 0 && store.writeSQL.Stats().InUse == 0 && len(store.writer) == 0, "retry drains owned transactions and emits no duplicate event")
			result := "conflict"
			if want == nil {
				result = "confirmed"
			} else if errors.Is(want, ErrUncertain) {
				result = "uncertain"
			}
			row, encoding := json.Marshal(map[string]any{"mode": mode, "case": point.name, "result": result, "version": uint64(version), "unchanged": true, "published": 0})
			check(encoding == nil, "encode the actual retry observation")
			t.Logf("STORAGE-RETRY-IDENTITY %s", row)
			rows++
		}
		for index, other := range []Scope{{scope.Sector + "-other", scope.Spectrum}, {scope.Sector, scope.Spectrum + "-other"}} {
			version, err := store.CommitBatch(t.Context(), other, 1, original)
			check(err == nil && version == 1, "same version and content are an independent commit in a different scope")
			image, loaded := store.Load(t.Context(), other)
			check(loaded == nil && image.Version == 1 && len(image.Records) == 2 && image.Records[0].Key == "a" && len(image.Records[0].Value) == 0 && bytes.Equal(image.Records[1].Value, []byte{0, 1, 255}), "scope isolation preserves complete ordered records")
			events, taken := feed.Take()
			check(taken == nil && len(events) == 1 && events[0].Scope == other && events[0].Version == 1, "a new scope publishes exactly its own complete commit")
			row, encoding := json.Marshal(map[string]any{"mode": mode, "scope": index, "version": uint64(version), "records": len(image.Records), "published": len(events)})
			check(encoding == nil, "encode the actual independent-scope observation")
			t.Logf("STORAGE-RETRY-IDENTITY %s", row)
		}
	}
	check(rows == 27, "all three receipt windows and nine intent variants are exercised")
}
