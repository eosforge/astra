// Verify coalesced callback ownership and actual drain with controlled scheduling.
package comet

import (
	"testing"
	"testing/synctest"
)

// TestNotificationCoalescingAndDrain blocks one delivery while newer states coalesce.
func TestNotificationCoalescingAndDrain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		owner := localOwner(t)
		queue := newDispatcher()
		entered, release := make(chan struct{}), make(chan struct{})
		calls := 0 // Only callback writes; synctest.Wait synchronizes inspection.
		note := &notification{queue: queue, life: owner, run: func() {
			calls++
			if calls == 1 {
				close(entered)
				<-release
			}
		}}
		owner.onstop = note.stop
		defer queue.close()
		defer owner.stop()
		note.signal()
		<-entered
		for range 100 {
			note.signal()
		}
		close(release)
		synctest.Wait()
		if calls != 2 {
			t.Fatalf("coalesced callbacks = %d; want two actual deliveries", calls)
		}
		owner.stop()
		note.signal()
		synctest.Wait()
		if calls != 2 {
			t.Fatal("closed callback registration was invoked")
		}
		select {
		case <-owner.done:
		default:
			t.Fatal("drained notification retained its role token")
		}
	})
}

// TestInvokeCallbackPanicNil covers both normal returns and nil-valued panics.
func TestInvokeCallbackPanicNil(t *testing.T) {
	t.Parallel()
	if invokeCallback(func() {}) || !invokeCallback(func() { panic(nil) }) {
		t.Fatal("callback panic boundary confused panic(nil) with normal return")
	}
}
