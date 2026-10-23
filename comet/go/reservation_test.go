// Verify receiver-local accounting refusals without modifying an installed immutable view.
package comet

import "testing"

// TestWatchingReservationRefusal preserves every old charge and permits healthy reuse after refusal.
func TestWatchingReservationRefusal(t *testing.T) {
	owner := localOwner(t)
	defer owner.stop()
	owner.client.options.Bytes = 16384
	draft := newDraft(emptyTable())
	draft.set("stable", &row{data: NewValue([]byte("before")), version: 2})
	root := &snapshot{data: draft.data, instance: "star-a", version: 7}
	watch := &watching{life: owner, domain: catalog, root: root, phase: Ready}
	owner.onfinish = func() { owner.client.release(watch.charged) }
	if !watch.message(1024) || !watch.prepare(2048) {
		t.Fatal("healthy bounded receiver reservations failed")
	}
	charge := watch.charged
	if charge <= 3072 || owner.client.used.Load() != charge {
		t.Fatal("receiver did not account retained content and both pending allocations")
	}
	// The requested charge is legal alone; simultaneous storage makes it unavailable.
	if !owner.client.reserve(owner.client.options.Bytes - charge) {
		t.Fatal("failed to occupy the remaining finite client budget")
	}
	if watch.message(1025) || watch.prepare(2049) {
		t.Fatal("exhausted parent budget admitted receiver growth")
	}
	if watch.charged != charge || watch.decoded != 1024 || watch.stage != 2048 || owner.client.used.Load() != 16384 {
		t.Fatal("refused receiver growth changed accounting or prepared state")
	}
	if watch.root != root || root.version != 7 || root.data.count != 1 || root.data.find("stable").data.String() != "before" || watch.phase != Ready {
		t.Fatal("receiver reservation refusal replaced the committed baseline")
	}
	owner.client.release(16384 - charge)
	if !watch.message(1025) || !watch.prepare(2049) || watch.charged != charge+2 || owner.client.used.Load() != charge+2 {
		t.Fatal("released storage was not reusable by the same receiver")
	}
	if !watch.message(0) || !watch.prepare(0) || watch.charged != charge-3072 || owner.client.used.Load() != charge-3072 {
		t.Fatal("discarded receiver drafts retained their transient storage")
	}
	owner.stop()
	if owner.client.used.Load() != 0 {
		t.Fatal("receiver completion retained its final storage charge")
	}
	if root.data.find("stable").data.String() != "before" {
		t.Fatal("receiver completion damaged an independently retained root")
	}
}
