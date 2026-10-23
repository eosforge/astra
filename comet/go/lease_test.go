// Verify lease origins, exact expiry, backward clocks and suspend jumps.
package comet

import (
	"testing"
	"time"
)

// TestLeaseOrigins uses an independent elapsed-time history, including suspend and reordering.
func TestLeaseOrigins(t *testing.T) {
	t.Parallel()
	budget := lease{}
	if budget.ready(0, true, time.Second) {
		t.Fatal("unconfirmed zero timestamp was treated as ready")
	}
	budget.confirm(100)
	budget.confirm(300)
	budget.confirm(200) // A slower old reply cannot shorten the newer confirmation.
	for _, row := range []struct {
		now   int64
		valid bool
		ready bool
	}{{300, true, true}, {1299, true, true}, {1300, true, false}, {299, true, false}, {301, false, false}, {30_000, true, false}} {
		if got := budget.ready(row.now, row.valid, time.Second); got != row.ready {
			t.Errorf("lease at %d/%t = %t", row.now, row.valid, got)
		}
	}
}
