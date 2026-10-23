//go:build linux && cgo

// Verify reached shutdown interleavings against real transactions, writer admission and feed ownership.
package storage

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
)

// lifetime observes the existing deadline lookup after lifecycle admission without blocking or changing context behavior.
type lifetime struct {
	context.Context               // Original cancellation and deadline semantics.
	entered         chan struct{} // One reached context lookup, before writer admission.
	once            sync.Once     // Context methods may be queried more than once.
}

// Deadline delegates the value and only reports the actual production lookup.
func (probe *lifetime) Deadline() (time.Time, bool) {
	probe.once.Do(func() { close(probe.entered) })
	return probe.Context.Deadline()
}

// thread captures the current goroutine's identity for an observed wait, not a guessed scheduling delay.
func thread() string {
	var buffer [128]byte
	runtime.Stack(buffer[:], false)
	fields := strings.Fields(string(buffer[:]))
	if len(fields) < 2 || fields[0] != "goroutine" {
		panic("goroutine identity unavailable")
	}
	if _, err := strconv.ParseUint(fields[1], 10, 64); err != nil {
		panic(err)
	}
	return fields[1]
}

// until bounds observation only; it never sleeps to advance business time or supplies missing production synchronization.
func until(t *testing.T, ctx context.Context, condition func() bool) {
	t.Helper()
	for !condition() {
		select {
		case <-ctx.Done():
			t.Fatal("controlled lifecycle boundary not reached", ctx.Err())
		default:
			runtime.Gosched()
		}
	}
}

// waiting requires an actually blocked goroutine at the named production lock, within a bounded stack snapshot.
func waiting(identity, method, lock string) bool {
	buffer := make([]byte, 1<<20)
	size := runtime.Stack(buffer, true)
	if size == len(buffer) {
		return false
	}
	for _, stack := range strings.Split(string(buffer[:size]), "\n\n") {
		if strings.HasPrefix(stack, "goroutine "+identity+" ") {
			return strings.Contains(stack, method) && strings.Contains(stack, lock)
		}
	}
	return false
}

// TestLifecycle drains admitted operations before close and refuses later work without a partial durable transaction.
func TestLifecycle(t *testing.T) {
	verified := verification(t, "STORAGE-LIFETIME")
	for _, mode := range []string{"commit", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			check := func(ok bool, detail string) {
				t.Helper()
				if !ok {
					t.Fatal(detail)
				}
				verified(true, detail)
			}
			store, path, binding := fixture(t, Default())
			scope := Scope{"lifecycle", mode}
			feed, err := store.Subscribe(4096, 8)
			check(err == nil, "capture owned feed before admitted work")
			changed, ready := store.Changed(), feed.Ready()
			ctx, cancel := context.WithCancel(t.Context())
			queued, discard := context.WithCancel(t.Context())
			watch, stop := context.WithTimeout(t.Context(), 4*time.Second)
			defer stop()
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			var work sync.WaitGroup
			t.Cleanup(func() {
				cancel()
				discard()
				once.Do(func() { close(release) })
				work.Wait()
				store.write.Callback().Raw().Remove("assurance:lifecycle")
			})
			check(store.write.Callback().Raw().After("gorm:raw").Register("assurance:lifecycle", func(tx *gorm.DB) {
				if tx.Error == nil && strings.HasPrefix(tx.Statement.SQL.String(), "INSERT INTO records") && len(tx.Statement.Vars) > 2 && tx.Statement.Vars[2] == "a" {
					close(entered)
					<-release
				}
			}) == nil, "pause only after a real first record write")
			result := make(chan struct {
				version Version
				err     error
			}, 1)
			work.Go(func() {
				version, err := store.CommitBatch(ctx, scope, 1, []Change{{Key: "a", Value: []byte("new")}, {Key: "b", Value: []byte("new")}})
				result <- struct {
					version Version
					err     error
				}{version, err}
			})
			until(t, watch, func() bool {
				select {
				case <-entered:
					return true
				default:
					return false
				}
			})
			probe := &lifetime{Context: queued, entered: make(chan struct{})}
			cancelled := make(chan error, 1)
			work.Go(func() {
				version, err := store.Commit(probe, scope, Change{Version: 2, Key: "queued"})
				if version != 0 {
					err = fmt.Errorf("cancelled waiter returned version %d", version)
				}
				cancelled <- err
			})
			until(t, watch, func() bool {
				select {
				case <-probe.entered:
					return true
				default:
					return false
				}
			})
			closed := make(chan error, 1)
			work.Go(func() { closed <- store.Close() })
			until(t, watch, func() bool {
				if store.life.TryRLock() {
					store.life.RUnlock()
					return false
				}
				return true
			})
			late := make(chan error, 3)
			identities := make(chan struct {
				identity string
				method   string
			}, 3)
			for _, method := range []string{"commit", "readOnly", "Subscribe"} {
				work.Go(func() {
					identities <- struct {
						identity string
						method   string
					}{thread(), method}
					switch method {
					case "commit":
						_, err := store.Commit(t.Context(), scope, Change{Version: 2, Key: "late"})
						late <- err
					case "readOnly":
						_, err := store.Load(t.Context(), scope)
						late <- err
					default:
						_, err := store.Subscribe(4096, 8)
						late <- err
					}
				})
			}
			for range 3 {
				identity := <-identities
				until(t, watch, func() bool { return waiting(identity.identity, "(*Store)."+identity.method, "sync.(*RWMutex).RLock") })
				check(true, "observe later work blocked behind the pending lifecycle writer")
			}
			discard()
			select {
			case err := <-cancelled:
				check(errors.Is(err, context.Canceled), "cancelled admitted waiter releases its lifecycle borrow")
			case <-watch.Done():
				t.Fatal("writer-admission cancellation did not drain")
			}
			select {
			case <-closed:
				t.Fatal("close returned while the real transaction still owned the database")
			default:
				check(true, "close still waits for the admitted native transaction")
			}
			if mode == "cancel" {
				cancel()
			}
			once.Do(func() { close(release) })
			outcome := <-result
			if mode == "commit" {
				check(outcome.version == 1 && outcome.err == nil, "admitted transaction durably completes before close")
			} else {
				check(outcome.version == 0 && errors.Is(outcome.err, ErrUnavailable), "cancelled prepared transaction returns no committed receipt")
			}
			check(<-closed == nil, "close completes after all admitted database work drains")
			for range 3 {
				check(errors.Is(<-late, ErrClosed), "late operations cannot reopen admission during teardown")
			}
			work.Wait()
			check(len(store.writer) == 0 && store.readSQL.Stats().InUse == 0 && store.writeSQL.Stats().InUse == 0, "writer and both borrowed pools drain")
			check(store.readSQL.Stats().OpenConnections == 0 && store.writeSQL.Stats().OpenConnections == 0, "native database connections close")
			check(len(store.feeds) == 0 && store.feedBytes == 0 && feed.queue == nil && feed.bytes == 0, "close releases feed registration, reservations and queued references")
			_, err = feed.Take()
			check(errors.Is(err, ErrClosed), "closed feed reports its stable terminal result")
			for _, signal := range []<-chan struct{}{changed, ready, store.Changed(), feed.Ready()} {
				select {
				case <-signal:
					check(true, "all captured and final waiters wake after close")
				default:
					t.Fatal("close retained a notification waiter")
				}
			}
			feed.Close()
			feed.Close()
			check(store.Close() == nil && store.feedBytes == 0, "repeated close cannot double-release resources")
			opened, err := Open(t.Context(), path, binding, Default(), false)
			check(err == nil, "reopen after release of the actual database lock")
			defer opened.Close()
			view, err := opened.Load(t.Context(), scope)
			check(err == nil, "read the recovered authoritative snapshot")
			want := Version(1)
			if mode == "cancel" {
				want = 0
			}
			check(view.Version == want && len(view.Records) == 2*int(want), "shutdown never persists a partial prefix")
			for _, record := range view.Records {
				check((record.Key == "a" || record.Key == "b") && string(record.Value) == "new", "recovered content agrees with the literal submitted batch")
			}
			journal, err := opened.Since(t.Context(), scope, 0)
			check(err == nil && journal.Version == want && len(journal.Changes) == int(want), "recovered history retains exactly the permitted complete version")
			t.Logf("STORAGE-LIFETIME {\"mode\":%q,\"late\":3,\"queued_cancelled\":true,\"drained\":true,\"version\":%d,\"records\":%d}", mode, view.Version, len(view.Records))
		})
	}
	t.Run("feed", func(t *testing.T) {
		check := func(ok bool, detail string) {
			t.Helper()
			if !ok {
				t.Fatal(detail)
			}
			verified(true, detail)
		}
		store, _, _ := fixture(t, Default())
		feed, err := store.Subscribe(4096, 8)
		check(err == nil, "own one feed for lock-order observation")
		feed.mutex.Lock()
		var once sync.Once
		var work sync.WaitGroup
		t.Cleanup(func() {
			once.Do(feed.mutex.Unlock)
			work.Wait()
		})
		watch, stop := context.WithTimeout(t.Context(), 4*time.Second)
		defer stop()
		finished := make(chan struct{}, 1)
		work.Go(func() { feed.Close(); finished <- struct{}{} })
		until(t, watch, func() bool {
			if store.notify.TryLock() {
				store.notify.Unlock()
				return false
			}
			return true
		})
		closed := make(chan error, 1)
		identity := make(chan string, 1)
		work.Go(func() { identity <- thread(); closed <- store.Close() })
		owner := <-identity
		until(t, watch, func() bool { return waiting(owner, "(*Store).Close", "sync.(*Mutex).Lock") })
		check(true, "Store close reaches the notification lock held by feed removal")
		once.Do(feed.mutex.Unlock)
		<-finished
		check(<-closed == nil, "both close paths complete in the shared notification-to-feed order")
		work.Wait()
		feed.Close()
		check(store.Close() == nil && len(store.feeds) == 0 && store.feedBytes == 0, "concurrent close returns each reservation once")
		_, err = feed.Take()
		check(errors.Is(err, ErrClosed) && feed.queue == nil && feed.bytes == 0, "the removed feed retains no queued work")
		check(store.readSQL.Stats().OpenConnections == 0 && store.writeSQL.Stats().OpenConnections == 0, "both native pools terminate after feed draining")
		t.Log("STORAGE-LIFETIME {\"mode\":\"feed\",\"late\":0,\"queued_cancelled\":false,\"drained\":true,\"version\":0,\"records\":0}")
	})
}
