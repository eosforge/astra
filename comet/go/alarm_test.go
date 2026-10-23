// Verify shared-heap ordering and lifecycle tokens under virtual-clock replacement and closure.
package comet

import (
	"testing"
	"testing/synctest"
	"time"
)

// TestAlarmHeapPreservesOwnership compares deliveries with prescribed deadlines after independent edits.
func TestAlarmHeapPreservesOwnership(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		owner := localOwner(t)
		timers := newScheduler()
		defer timers.close()
		defer owner.stop()
		fired := make(chan int, 4)
		entries := make([]*alarm, 4)
		start := time.Now()
		for index := range entries {
			entries[index] = &alarm{life: owner, index: -1, run: func() { fired <- index }}
			timers.at(entries[index], start.Add(time.Duration(index+1)*time.Second))
		}
		owner.onstop = func() {
			for _, entry := range entries {
				timers.cancel(entry)
			}
		}
		timers.at(entries[3], start.Add(500*time.Millisecond))
		timers.at(entries[0], start.Add(3500*time.Millisecond))
		timers.cancel(entries[2])
		for _, expected := range []struct {
			index int           // Independent identity, unaffected by heap swaps.
			due   time.Duration // Absolute offset from this test's virtual start.
		}{{3, 500 * time.Millisecond}, {1, 2 * time.Second}, {0, 3500 * time.Millisecond}} {
			<-time.After(time.Until(start.Add(expected.due)))
			synctest.Wait()
			select {
			case observed := <-fired:
				if observed != expected.index {
					t.Fatalf("alarm order = %d, want %d", observed, expected.index)
				}
			default:
				t.Fatalf("alarm %d missed its exact virtual deadline", expected.index)
			}
			select {
			case observed := <-fired:
				t.Fatalf("alarm %d fired early or twice", observed)
			default:
			}
		}
		// A client closing before its role is stopped must reject a new operation.
		owner.client.closed.Store(true)
		if owner.begin() {
			t.Fatal("closed client admitted new lifecycle work")
		}
		owner.stop()
		timers.at(entries[2], time.Now().Add(time.Second))
		<-time.After(5 * time.Second)
		synctest.Wait()
		select {
		case observed := <-fired:
			t.Fatalf("canceled or closed alarm %d was delivered", observed)
		default:
		}
		select {
		case <-owner.done:
		default:
			t.Fatal("heap replacement or cancellation leaked lifecycle ownership")
		}
		if owner.client.writers != 0 || len(owner.client.actors) != 0 {
			t.Fatal("completed heap retained the parent role quota")
		}
	})
}
