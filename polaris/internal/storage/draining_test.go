//go:build linux && cgo

// Verify that cancellation cannot return a Storage operation while its real native rollback still owns a connection.
package storage

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// draining retains the existing native connection while exposing only its reached rollback scheduling boundary.
type draining struct {
	*termination                             // Real SQLite opening/closing and ownership counters.
	entered, release, finished chan struct{} // Actual rollback entry, controlled resumption and completed native release.
}

// Connect preserves the native connection; no shared driver registration or global fault state is used.
func (probe *draining) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := probe.termination.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &drainingConnection{terminated: conn.(*terminated), probe: probe}, nil
}

// drainingConnection retains optional native interfaces and wraps only the real transaction's finalization.
type drainingConnection struct {
	*terminated           // Existing native connection, SQL execution and completed-close accounting.
	probe       *draining // This fixture's reached rollback boundary.
}

// BeginTx keeps the driver's actual context and isolation semantics unchanged.
func (conn *drainingConnection) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	tx, err := conn.SQLiteConn.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return &drainingTransaction{Tx: tx, probe: conn.probe}, nil
}

// drainingTransaction holds the native rollback at its entry, after database/sql has claimed transaction finalization.
type drainingTransaction struct {
	driver.Tx           // The actual SQLite transaction; commit remains native.
	probe     *draining // This fixture's lifecycle signals.
}

// Rollback observes the actual background finalizer and then delegates native rollback exactly once.
func (tx *drainingTransaction) Rollback() error {
	close(tx.probe.entered)
	<-tx.probe.release
	err := tx.Tx.Rollback()
	close(tx.probe.finished)
	return err
}

// TestDraining reaches the cancellation race for both public writers and readers without sleeping.
func TestDraining(t *testing.T) {
	verified := verification(t, "STORAGE-DRAINING")
	for _, mode := range []string{"write", "read"} {
		verified(t.Run(mode, func(t *testing.T) {
			store, _, _ := fixture(t, Default())
			original := store.writeSQL
			if mode == "read" {
				original = store.readSQL
			}
			if err := original.Close(); err != nil {
				t.Fatal(err)
			}
			probe := &draining{termination: &termination{SQLiteDriver: &sqlite3.SQLiteDriver{ConnectHook: connection}, path: store.path + "?_journal_mode=WAL&_synchronous=FULL&_foreign_keys=on"}, entered: make(chan struct{}), release: make(chan struct{}), finished: make(chan struct{})}
			pool := sql.OpenDB(probe)
			pool.SetMaxOpenConns(1)
			pool.SetMaxIdleConns(1)
			t.Cleanup(func() { pool.Close() })
			db, err := gorm.Open(sqlite.New(sqlite.Config{Conn: pool}), &gorm.Config{SkipDefaultTransaction: true, Logger: logger.Discard})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "read" {
				store.read, store.readSQL = db, pool
			} else {
				store.write, store.writeSQL = db, pool
			}
			ctx, cancel := context.WithCancel(t.Context())
			watch, stop := context.WithTimeout(t.Context(), 4*time.Second)
			t.Cleanup(stop)
			working, resume := make(chan struct{}), make(chan struct{})
			var resumeOnce, releaseOnce sync.Once
			var work sync.WaitGroup
			t.Cleanup(func() {
				cancel()
				resumeOnce.Do(func() { close(resume) })
				releaseOnce.Do(func() { close(probe.release) })
				work.Wait()
				cleanup, finish := context.WithTimeout(context.WithoutCancel(t.Context()), 4*time.Second)
				defer finish()
				select {
				case <-probe.finished:
				case <-cleanup.Done():
					t.Error("native rollback did not drain during cleanup")
				}
			})
			callback := func(tx *gorm.DB) {
				if tx.Error == nil {
					close(working)
					<-resume
				}
			}
			if mode == "write" {
				if err := db.Callback().Raw().After("gorm:raw").Register("assurance:draining", callback); err != nil {
					t.Fatal(err)
				}
			} else if err := db.Callback().Query().After("gorm:query").Register("assurance:draining", callback); err != nil {
				t.Fatal(err)
			}
			returned := make(chan error, 1)
			identity := make(chan string, 1)
			work.Go(func() {
				identity <- thread()
				if mode == "write" {
					_, err := store.Commit(ctx, Scope{"draining", "write"}, Change{Version: 1, Key: "retained", Value: []byte("uncommitted")})
					returned <- err
				} else {
					_, err := store.List(ctx)
					returned <- err
				}
			})
			until(t, watch, func() bool {
				select {
				case <-working:
					return true
				default:
					return false
				}
			})
			cancel()
			until(t, watch, func() bool {
				select {
				case <-probe.entered:
					return true
				default:
					return false
				}
			})
			resumeOnce.Do(func() { close(resume) })
			owner := <-identity
			var early error
			premature := false
			until(t, watch, func() bool {
				select {
				case early = <-returned:
					premature = true
					return true
				default:
					// The pinned Go 1.27 connection borrow guard uses closingMutex and sync.Cond, not RWMutex.
					return waiting(owner, "database/sql.(*Conn).close", "database/sql.(*closingMutex).Lock")
				}
			})
			if premature {
				t.Fatalf("STORAGE-ROLLBACK-NOT-DRAINED mode=%s error=%v in_use=%d", mode, early, pool.Stats().InUse)
			}
			if pool.Stats().InUse != 1 || probe.closed.Load() != 0 {
				t.Fatal("rollback boundary did not retain its actual borrowed native connection")
			}
			releaseOnce.Do(func() { close(probe.release) })
			select {
			case err := <-returned:
				if err == nil || errors.Is(err, ErrClosed) {
					t.Fatal("cancelled operation returned an invalid receipt", err)
				}
			case <-watch.Done():
				t.Fatal("operation did not return after native rollback completed")
			}
			work.Wait()
			if pool.Stats().InUse != 0 || len(store.writer) != 0 {
				t.Fatal("native rollback completion retained pool or writer ownership")
			}
			if err := store.Close(); err != nil || probe.opened.Load() != probe.closed.Load() {
				t.Fatal("close did not release the complete native connection cohort", err)
			}
			t.Logf("STORAGE-DRAINED mode=%s rollback=1 in_use=0 writer=0 opened=%d closed=%d", mode, probe.opened.Load(), probe.closed.Load())
		}), "native cancellation rollback drains before operation return: "+mode)
	}
}
