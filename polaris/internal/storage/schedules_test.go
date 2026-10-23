//go:build linux && cgo

// Compare concurrent durable receipts, snapshots, and histories with one independent serial order.
package storage

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// operation assigns two registers: -2 leaves a key alone, -1 erases, and 0/1 select payloads.
type operation [2]int

// journal keeps complete accepted requests, independently of SQL and the production batch encoding.
type journal struct {
	records [2]int
	log     []operation
}

// domain fixes nine single-key and atomic two-key requests, including empty values and deletion.
func domain() []operation {
	return []operation{{0, -2}, {1, -2}, {-2, 0}, {-2, 1}, {-1, -2}, {-2, -1}, {0, 1}, {-1, 0}, {1, -1}}
}

// transition accepts the next version or an identical retained retry; conflicts leave everything intact.
func transition(state journal, version Version, action operation) (journal, bool) {
	if version <= Version(len(state.log)) {
		return state, version != 0 && state.log[int(version)-1] == action
	}
	if version != Version(len(state.log)+1) {
		return state, false
	}
	next := journal{records: state.records, log: append(append([]operation(nil), state.log...), action)}
	for index, value := range action {
		if value != -2 {
			next.records[index] = value
		}
	}
	return next, true
}

// entries only translates the declared register alphabet into public batch inputs.
func entries(action operation) []Change {
	result := []Change{}
	for index, value := range action {
		if value == -2 {
			continue
		}
		entry := Change{Key: []string{"a", "b"}[index], Value: []byte{}, Erase: value == -1}
		if value == 1 {
			entry.Value = []byte{1}
		}
		result = append(result, entry)
	}
	return result
}

// snapshotMatches compares the complete public state, including version, key order, and empty values.
func snapshotMatches(snapshot Snapshot, state journal, scope Scope) bool {
	if snapshot.Scope != scope || snapshot.Version != Version(len(state.log)) {
		return false
	}
	position := 0
	for index, value := range state.records {
		if value == -1 {
			continue
		}
		payload := []byte{}
		if value == 1 {
			payload = []byte{1}
		}
		if position >= len(snapshot.Records) || snapshot.Records[position].Key != []string{"a", "b"}[index] || !bytes.Equal(snapshot.Records[position].Value, payload) {
			return false
		}
		position++
	}
	return position == len(snapshot.Records)
}

// replayMatches checks every complete batch; it never infers accepted requests from the final values.
func replayMatches(replay Replay, state journal) bool {
	if replay.Version != Version(len(state.log)) || len(replay.Changes) != len(state.log) {
		return false
	}
	for index, change := range replay.Changes {
		actual, err := change.Entries()
		want := entries(state.log[index])
		if err != nil || change.Version != Version(index+1) || len(actual) != len(want) {
			return false
		}
		for key, entry := range actual {
			if entry.Version != change.Version || entry.Key != want[key].Key || entry.Erase != want[key].Erase || !bytes.Equal(entry.Value, want[key].Value) {
				return false
			}
		}
	}
	return true
}

// TestSchedules enumerates 972 pairs over four initial states and three version relationships.
// A shared start creates overlap, without claiming exhaustive internal schedules or crash durability.
func TestSchedules(t *testing.T) {
	store, _, _ := fixture(t, Default())
	check := verification(t, "STORAGE-SCHEDULE")
	actions := domain()
	initials := [][2]int{{-1, -1}, {0, -1}, {-1, 1}, {0, 1}}
	relations := [][2]Version{{1, 1}, {1, 2}, {2, 1}}
	trace(t, "pair-start", struct {
		Actions   []operation  `json:"actions"`
		Initials  [][2]int     `json:"initials"`
		Relations [][2]Version `json:"relations"`
		Reads     int          `json:"reads"`
	}{actions, initials, relations, 16})
	histories, observations := 0, 0
	for _, initial := range initials {
		for _, first := range actions {
			for _, second := range actions {
				for _, offsets := range relations {
					scope := Scope{"schedules", fmt.Sprint(histories)}
					before := journal{records: initial}
					if initial != [2]int{-1, -1} {
						action := operation(initial)
						for index := range action {
							if action[index] == -1 {
								action[index] = -2
							}
						}
						version, err := store.CommitBatch(t.Context(), scope, 1, entries(action))
						check(err == nil && version == 1, "initial batch")
						before.log = []operation{action}
					}
					frozen, err := store.Load(t.Context(), scope)
					check(err == nil && snapshotMatches(frozen, before, scope), "initial owned snapshot")
					requests := [2]operation{first, second}
					versions := [2]Version{Version(len(before.log)) + offsets[0], Version(len(before.log)) + offsets[1]}
					receipts := [2]Version{}
					failures := [2]error{}
					start := make(chan struct{})
					var workers sync.WaitGroup
					for index, action := range requests {
						workers.Go(func() {
							<-start
							receipts[index], failures[index] = store.CommitBatch(t.Context(), scope, versions[index], entries(action))
						})
					}
					close(start)
					// Collect errors without failing until both writers are joined, so cleanup cannot outlive them.
					views := [16]Snapshot{}
					logs := [16]Replay{}
					reads := [16][2]error{}
					for index := range views {
						views[index], reads[index][0] = store.Load(t.Context(), scope)
						logs[index], reads[index][1] = store.Since(t.Context(), scope, 0)
					}
					workers.Wait()
					final, err := store.Load(t.Context(), scope)
					check(err == nil, "final snapshot")
					log, err := store.Since(t.Context(), scope, 0)
					check(err == nil, "final history")
					for index, err := range failures {
						check(err == nil && receipts[index] == versions[index] || errors.Is(err, ErrVersion) && receipts[index] == 0, "stable complete receipt or version conflict")
					}
					for _, read := range reads {
						check(read[0] == nil && read[1] == nil, "all concurrent reads complete")
					}
					matched := false
					for _, order := range [][2]int{{0, 1}, {1, 0}} {
						prefixes := [3]journal{before}
						accepted := [2]bool{}
						for index, writer := range order {
							prefixes[index+1], accepted[writer] = transition(prefixes[index], versions[writer], requests[writer])
						}
						valid := accepted == [2]bool{failures[0] == nil, failures[1] == nil} && snapshotMatches(final, prefixes[2], scope) && replayMatches(log, prefixes[2])
						last := Version(len(before.log))
						for index, view := range views {
							foundView, foundLog := false, false
							for _, prefix := range prefixes {
								foundView = foundView || snapshotMatches(view, prefix, scope)
								foundLog = foundLog || replayMatches(logs[index], prefix)
							}
							valid = valid && foundView && foundLog && view.Version >= last && logs[index].Version >= view.Version
							last = logs[index].Version
						}
						matched = matched || valid
					}
					check(matched, fmt.Sprintf("history=%d initial=%v actions=%v versions=%v has no joint serial order", histories, initial, requests, versions))
					check(snapshotMatches(frozen, before, scope), "retained snapshot is unaffected by later commits")
					trace(t, "pair", overlap{histories, initial, requests, versions, [2]reply{receipt(receipts[0], failures[0]), receipt(receipts[1], failures[1])}, frozen, final, log, views, logs})
					observations += len(views)
					histories++
				}
			}
		}
	}
	check(len(actions) == 9 && histories == 972 && observations == 15552, "complete fixed pair and observation domain")
	t.Logf("storage-schedules version=1 states=4 operations=9 version-relations=3 histories=%d snapshots=%d replays=%d serializations=2 pruning=none internal-schedule-exhaustive=false", histories, observations, observations)
	trace(t, "pair-finish", struct {
		Histories    int `json:"histories"`
		Observations int `json:"observations"`
	}{histories, observations})
}

// TestOracle anchors accepted retries, conflicting retries, version gaps, and two-key transitions to fixed examples.
func TestOracle(t *testing.T) {
	check := verification(t, "STORAGE-ORACLE")
	initial := journal{records: [2]int{0, 1}, log: []operation{{0, 1}}}
	for _, example := range []struct {
		version  Version
		action   operation
		records  [2]int
		length   int
		accepted bool
	}{
		{1, operation{0, 1}, [2]int{0, 1}, 1, true},
		{1, operation{1, 1}, [2]int{0, 1}, 1, false},
		{3, operation{1, -1}, [2]int{0, 1}, 1, false},
		{2, operation{1, -1}, [2]int{1, -1}, 2, true},
		{2, operation{-1, 0}, [2]int{-1, 0}, 2, true},
		{2, operation{-2, 0}, [2]int{0, 0}, 2, true},
		{0, operation{0, 1}, [2]int{0, 1}, 1, false},
	} {
		after, accepted := transition(initial, example.version, example.action)
		check(accepted == example.accepted && after.records == example.records && len(after.log) == example.length, "independent journal axiom")
		check(initial.records == [2]int{0, 1} && len(initial.log) == 1 && initial.log[0] == operation{0, 1}, "model transition never changes a retained prefix")
	}
	scope := Scope{"oracle", "snapshot"}
	view := Snapshot{Position: Position{Scope: scope, Version: 1}, Records: []Record{{Key: "a", Value: []byte{}}, {Key: "b", Value: []byte{1}}}}
	check(snapshotMatches(view, initial, scope), "known complete snapshot")
	view.Records[0].Value = []byte{1}
	check(!snapshotMatches(view, initial, scope), "mixed-key snapshot must fail")
	view.Records = view.Records[1:]
	check(!snapshotMatches(view, initial, scope), "partial snapshot must fail")
	check(!replayMatches(Replay{Version: 1}, initial), "missing accepted history must fail")
}
