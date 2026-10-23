// Schedule Beacon maintenance with one heap and timer per Client.
package comet

import (
	"container/heap"
	"math/rand/v2"
	"sync"
	"time"
)

// alarm is one reusable Beacon entry. run may start bounded work but never wait
// for a network response or invoke application code on the scheduler goroutine.
type alarm struct {
	life  *lifecycle // One reference while the alarm is queued or being delivered.
	run   func()     // Short owner state transition.
	due   time.Time  // Next monotonic maintenance deadline.
	index int        // Heap position, -1 when detached; protected by scheduler.mu.
}

// alarms implements heap.Interface; all mutations happen under scheduler.mu.
type alarms []*alarm

// Len implements heap.Interface's current entry count.
func (items alarms) Len() int { return len(items) }

// Less orders the earliest monotonic deadline first.
func (items alarms) Less(i, j int) bool { return items[i].due.Before(items[j].due) }

// Swap maintains each entry's position for replacement and cancellation.
func (items alarms) Swap(i, j int) {
	items[i], items[j] = items[j], items[i]
	items[i].index, items[j].index = i, j
}

// Push attaches an entry whose lifecycle reference was acquired by the caller.
func (items *alarms) Push(value any) {
	entry := value.(*alarm)
	entry.index = len(*items)
	*items = append(*items, entry)
}

// Pop detaches the entry while transferring its lifecycle reference to delivery.
func (items *alarms) Pop() any {
	last := len(*items) - 1
	entry := (*items)[last]
	(*items)[last], entry.index = nil, -1
	*items = (*items)[:last]
	return entry
}

// scheduler owns one background goroutine and all Beacon timer entries.
type scheduler struct {
	mu     sync.Mutex    // Protects heap and stopped state.
	items  alarms        // At most one queued entry per live Beacon.
	wake   chan struct{} // Coalesced scheduling changes.
	stop   chan struct{} // Closed only after all roles have drained.
	done   chan struct{} // Actual scheduler exit.
	closed bool          // Prevents insertion during final shutdown.
}

// newScheduler starts the single monotonic scheduling loop.
func newScheduler() *scheduler {
	timers := &scheduler{wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	go timers.work()
	return timers
}

// signal wakes the loop without allocating one event per timer update.
func (timers *scheduler) signal() {
	select {
	case timers.wake <- struct{}{}:
	default:
	}
}

// at replaces a pending deadline or admits one new retained alarm.
func (timers *scheduler) at(entry *alarm, due time.Time) {
	timers.mu.Lock()
	if timers.closed || entry.life.stopped() {
		timers.mu.Unlock()
		return
	}
	if entry.index >= 0 {
		entry.due = due
		heap.Fix(&timers.items, entry.index)
	} else if entry.life.begin() {
		entry.due = due
		heap.Push(&timers.items, entry)
	}
	timers.mu.Unlock()
	timers.signal()
}

// cancel detaches pending work; a popped alarm still owns its completion token.
func (timers *scheduler) cancel(entry *alarm) {
	timers.mu.Lock()
	removed := entry.index >= 0
	if removed {
		heap.Remove(&timers.items, entry.index)
	}
	timers.mu.Unlock()
	if removed {
		entry.life.release()
	}
	timers.signal()
}

// work delivers due entries outside the heap lock and resets one reusable timer.
func (timers *scheduler) work() {
	defer close(timers.done)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		timers.mu.Lock()
		delay := time.Hour
		if len(timers.items) != 0 {
			delay = time.Until(timers.items[0].due)
			if delay <= 0 {
				entry := heap.Pop(&timers.items).(*alarm)
				timers.mu.Unlock()
				if !entry.life.stopped() {
					entry.run()
				}
				entry.life.release()
				continue
			}
		}
		timers.mu.Unlock()
		timer.Reset(delay)
		select {
		case <-timers.stop:
			return
		case <-timers.wake:
		case <-timer.C:
		}
	}
}

// close joins the timer loop; owners have already canceled every alarm.
func (timers *scheduler) close() {
	timers.mu.Lock()
	timers.closed = true
	timers.mu.Unlock()
	close(timers.stop)
	<-timers.done
}

// backoff bounds persistent failures and spreads unrelated client retries.
func backoff(attempt uint) time.Duration {
	base := min(100*time.Millisecond<<min(attempt, 6), 5*time.Second)
	return base + time.Duration(rand.Int64N(int64(base/4)+1))
}
