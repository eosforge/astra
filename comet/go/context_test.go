// Verify caller deadlines, hard caps and identifiable cancellation causes.
package comet

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestRequestDeadline verifies one caller deadline, default/cap behavior and identifiable causes.
func TestRequestDeadline(t *testing.T) {
	t.Parallel()
	if _, _, failure := requestContext(nil, defaultTimeout); failure == nil || failure.Code != CodeInput {
		t.Fatal("nil Context accepted")
	}
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, failure := requestContext(parent, defaultTimeout)
	if !errors.Is(failure, context.Canceled) || failure.Effect != Unapplied {
		t.Fatal("cancellation cause/effect lost")
	}
	for _, timeout := range []time.Duration{40 * time.Millisecond, time.Hour} {
		parent, stop := context.WithTimeout(context.Background(), timeout)
		ctx, release, failure := requestContext(parent, defaultTimeout)
		if failure != nil {
			t.Fatal(failure)
		}
		deadline, present := ctx.Deadline()
		original, _ := parent.Deadline()
		if !present || deadline.After(original) || time.Until(deadline) > maximumTimeout {
			t.Fatal("request widened its original deadline")
		}
		release()
		stop()
	}
}
