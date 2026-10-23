//go:build linux && cgo

// Compare durable batches with an independent finite map model and retained-log oracle.
package storage

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

// TestFinite explores every length-three sequence over nine declared operations on two keys.
// The model uses only map assignment/deletion; it shares no SQL, encoding, or quota helpers.
// This finite sequential domain does not enumerate concurrency, crashes, or arbitrary payloads.
func TestFinite(t *testing.T) {
	limits := Default()
	limits.History = 2
	store, _, _ := fixture(t, limits)
	check := verification(t, "STORAGE-FINITE")
	assurance := verification(t, "STORAGE-ASSURANCE")
	operations := [][]Change{
		{{Key: "a", Value: []byte{}}},
		{{Key: "a", Value: []byte{1}}},
		{{Key: "b", Value: []byte{}}},
		{{Key: "b", Value: []byte{1}}},
		{{Key: "a", Erase: true}},
		{{Key: "b", Erase: true}},
		{{Key: "a", Value: []byte{}}, {Key: "b", Value: []byte{1}}},
		{{Key: "a", Erase: true}, {Key: "b", Value: []byte{}}},
		{{Key: "a", Value: []byte{1}}, {Key: "b", Erase: true}},
	}
	trace(t, "sequence-start", struct {
		Operations [][]Change `json:"operations"`
		Depth      int        `json:"depth"`
		History    int64      `json:"history"`
	}{operations, 3, limits.History})
	sequences, transitions := 0, 0
	for first := range operations {
		for second := range operations {
			for third := range operations {
				sequence := []int{first, second, third}
				scope := Scope{"finite", fmt.Sprint(sequences)}
				model := map[string][]byte{}
				for step, index := range sequence {
					version := Version(step + 1)
					changes := operations[index]
					got, err := store.CommitBatch(t.Context(), scope, version, changes)
					check(err == nil && got == version, fmt.Sprintf("sequence %v step %d commit: %v", sequence, step, err))
					committed := receipt(got, err)
					for _, change := range changes {
						if change.Erase {
							delete(model, change.Key)
						} else {
							model[change.Key] = bytes.Clone(change.Value)
						}
					}
					got, err = store.CommitBatch(t.Context(), scope, version, changes)
					check(err == nil && got == version, "identical retry must not advance the version")
					retried := receipt(got, err)
					got, err = store.CommitBatch(t.Context(), scope, version+2, changes)
					check(errors.Is(err, ErrVersion), "skipped version must be rejected")
					gap := receipt(got, err)
					snapshot, err := store.Load(t.Context(), scope)
					assurance(err == nil && snapshot.Scope == scope && snapshot.Version == version && len(snapshot.Records) == len(model), "snapshot scope, version and cardinality")
					for position, record := range snapshot.Records {
						want, exists := model[record.Key]
						check(exists && bytes.Equal(record.Value, want), "snapshot agrees with independent map")
						check(position == 0 || snapshot.Records[position-1].Key < record.Key, "snapshot keys are unique and ordered")
					}
					floor := Version(0)
					var stale *lookup
					if version > 2 {
						floor = version - 2
						evicted, err := store.Since(t.Context(), scope, floor-1)
						check(errors.Is(err, ErrHistory), "evicted history is not a partial success")
						observed := lookup{evicted, receipt(evicted.Version, err).Error}
						stale = &observed
					}
					replay, err := store.Since(t.Context(), scope, floor)
					check(err == nil && replay.Version == version && len(replay.Changes) == int(version-floor), "retained history is a complete suffix")
					for position, change := range replay.Changes {
						want := operations[sequence[int(floor)+position]]
						entries, err := change.Entries()
						check(err == nil && change.Version == floor+Version(position)+1 && len(entries) == len(want), "one complete versioned batch per history position")
						for key, entry := range entries {
							check(entry.Key == want[key].Key && entry.Erase == want[key].Erase && bytes.Equal(entry.Value, want[key].Value), "history preserves every operation")
						}
					}
					trace(t, "step", trial{sequences, sequence, step, committed, retried, gap, snapshot, replay, floor, stale})
					transitions++
				}
				sequences++
			}
		}
	}
	check(sequences == 729 && transitions == 2187, "finite domain must not shrink or vacuously pass")
	t.Logf("finite-model version=1 keys=2 operations=9 depth=3 sequences=%d transitions=%d pruning=none", sequences, transitions)
	trace(t, "sequence-finish", struct {
		Sequences   int `json:"sequences"`
		Transitions int `json:"transitions"`
	}{sequences, transitions})
}
