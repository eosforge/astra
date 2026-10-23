// Verify timer replacement and cancellation using Go's isolated virtual clock.
package comet

import (
	"context"
	"testing"
	"testing/synctest"
	"time"
)

// localOwner constructs a counted owner without transport or application dependencies.
func localOwner(t *testing.T) *lifecycle {
	t.Helper()
	client := &Client{ctx: context.Background(), actors: make(map[*lifecycle]struct{}), options: Options{Beacons: 1}}
	life := newLifecycle(client, false)
	if failure := client.attach(life); failure != nil {
		t.Fatal(failure)
	}
	return life
}

// TestAlarmReplacementAndCancel advances virtual time across exact deadline boundaries.
func TestAlarmReplacementAndCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		owner := localOwner(t)
		timers := newScheduler()
		fired := make(chan time.Time, 2)
		entry := &alarm{life: owner, index: -1, run: func() { fired <- time.Now() }}
		owner.onstop = func() { timers.cancel(entry) }
		defer timers.close()
		defer owner.stop()
		start := time.Now()
		timers.at(entry, start.Add(10*time.Second))
		timers.at(entry, start.Add(5*time.Second))
		<-time.After(4 * time.Second) // This advances only the isolated synctest clock.
		synctest.Wait()
		select {
		case <-fired:
			t.Fatal("alarm fired before its replacement deadline")
		default:
		}
		<-time.After(time.Second)
		synctest.Wait()
		if delivered := <-fired; delivered.Sub(start) != 5*time.Second {
			t.Fatal("replaced alarm retained its old deadline")
		}
		timers.at(entry, time.Now().Add(2*time.Second))
		timers.cancel(entry)
		<-time.After(20 * time.Second)
		synctest.Wait()
		select {
		case <-fired:
			t.Fatal("canceled alarm was delivered")
		default:
		}
		owner.stop()
		select {
		case <-owner.done:
		default:
			t.Fatal("alarm cancellation leaked a lifecycle reference")
		}
	})
}

// TestDeadlineReplacementFencesOldTimer advances exactly through old and new deadlines.
func TestDeadlineReplacementFencesOldTimer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		guard := newDeadline(cancel)
		defer guard.stop()
		guard.arm(time.Second)
		if !guard.disarm() {
			t.Fatal("unexpired guard reported expiry")
		}
		guard.arm(3 * time.Second)
		<-time.After(time.Second)
		synctest.Wait()
		if ctx.Err() != nil {
			t.Fatal("old timer canceled its replacement")
		}
		<-time.After(2 * time.Second)
		synctest.Wait()
		if ctx.Err() == nil || guard.disarm() {
			t.Fatal("new deadline failed to cancel or was resurrected")
		}
	})
}
