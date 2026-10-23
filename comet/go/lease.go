// Track conservative leases using suspend-aware elapsed milliseconds.
package comet

import "time"

// lease retains the newest confirmed send origin, never receipt arrival time.
type lease struct {
	origin int64 // Suspend-aware milliseconds of a confirmed request's first send.
	known  bool  // Zero is a valid clock reading, so absence is separate.
}

// confirm cannot shorten the budget when independent Update/Renew replies reorder.
func (budget *lease) confirm(sent int64) {
	if !budget.known || sent > budget.origin {
		budget.origin, budget.known = sent, true
	}
}

// ready rejects failed/backward clocks and expires at the exact fixed TTL boundary.
func (budget lease) ready(now int64, valid bool, ttl time.Duration) bool {
	return valid && budget.known && now >= budget.origin && now-budget.origin < int64(ttl/time.Millisecond)
}
