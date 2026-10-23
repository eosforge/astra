// Own the authority database connection and storage lifecycle.

package storage

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/mattn/go-sqlite3"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Store exclusively owns one authority database; calls are bounded and Close waits for actual SQL work before unlocking.
type Store struct {
	life      sync.RWMutex       // Lifecycle read/write lock excludes closure from operations.
	closed    bool               // Closed flag rejects later operations.
	poisoned  atomic.Bool        // Poisoned transaction state makes writes uncertain until restart recovery.
	writer    chan struct{}      // Capacity-one single-writer permit.
	file      *os.File           // Exclusive database lock handle, released on closure.
	path      string             // Absolute database path.
	limits    Limits             // Validated immutable resource limits.
	read      *gorm.DB           // Read ORM handle, separate from writes.
	write     *gorm.DB           // Write ORM handle for transactions.
	readSQL   *sql.DB            // Owned underlying read pool.
	writeSQL  *sql.DB            // Owned underlying write pool.
	cancel    context.CancelFunc // Stop the Store-owned maintenance task before closing its SQL pools.
	done      <-chan struct{}    // Closed only after maintenance has released its timer and connection.
	changed   chan struct{}      // Shared change channel closes on a new commit.
	notify    sync.Mutex         // Protects subscriptions and notification channel.
	feeds     map[*Feed]struct{} // Active Feed set.
	feedBytes int64              // Aggregate subscription budgets, capped at 128 MiB.
}

// driverOnce registers fixed connection initialization only, without per-request drivers or dynamic DSNs.
var driverOnce sync.Once

// Limits returns actual validated configuration by value; callers cannot supply smaller preparation limits to bypass charging.
func (store *Store) Limits() Limits { return store.limits }

// Open distinguishes initialization from recovery, retaining failed files rather than deleting WAL or rebuilding a rejected database.
// path, binding, limits and initialize select the database, deployment identity, resource limits and creation mode.
func Open(ctx context.Context, path string, binding Binding, limits Limits, initialize bool) (*Store, error) {
	return open(ctx, path, binding, limits, initialize, system{})
}

// open owns initialization and cleanup while its per-call file boundary supplies native or controlled I/O outcomes.
func open(ctx context.Context, path string, binding Binding, limits Limits, initialize bool, files filesystem) (_ *Store, result error) {
	// Validate canonical advertise, limits, names, and nonempty path before opening.
	endpoint, err := netip.ParseAddrPort(binding.Advertise)
	if !limits.valid() || !name(binding.Galaxy) || !name(binding.Username) || err != nil || endpoint.String() != binding.Advertise || endpoint.Port() == 0 || endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() || endpoint.Addr().Is4In6() || endpoint.Addr().Zone() != "" || path == "" {
		return nil, ErrInput
	}
	// Resolve absolute path once for all locking and connections.
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, ErrInput
	}
	// Acquire file exclusivity before connecting to prevent two processes owning one database.
	file, err := lock(absolute)
	if err != nil {
		return nil, err
	}
	store := &Store{file: file, path: absolute, limits: limits, writer: make(chan struct{}, 1), changed: make(chan struct{}), feeds: make(map[*Feed]struct{})}
	// Every subsequent failure closes acquired resources, including lock and connections.
	defer func() {
		if result != nil {
			store.Close()
		}
	}()
	// Explicit initialization exclusively creates a new file; later write connection creates schema.
	if initialize {
		created, err := files.open(absolute, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, ErrUnavailable
		}
		if err = created.Close(); err != nil {
			return nil, ErrUnavailable
		}
	}
	// Reject symlinks and nonregular database paths before SQLite can follow aliases or open unintended files.
	info, err := os.Lstat(absolute)
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrUnavailable
	}
	// Register the driver once; write-connection failure still invokes deferred Close.
	driverOnce.Do(func() { sql.Register("astra-polaris", &sqlite3.SQLiteDriver{ConnectHook: connection}) })
	ctx, cancel := context.WithTimeout(ctx, limits.Timeout)
	defer cancel()
	if store.write, store.writeSQL, err = database(ctx, absolute, true); err != nil {
		return nil, err
	}
	// Initialization creates tables/metadata on the write connection and synchronizes the parent directory.
	if initialize {
		err = store.transaction(ctx, func(tx *gorm.DB) error {
			for _, statement := range schema {
				if err := tx.Exec(statement).Error; err != nil {
					return ErrCorrupt
				}
			}
			return tx.Exec("INSERT INTO meta(id,format,galaxy,username,advertise,scopes,bytes) VALUES(1,1,?,?,?,0,0)", binding.Galaxy, binding.Username, binding.Advertise).Error
		})
		if err != nil {
			return nil, err
		}
		// SQLite FULL confirms file contents; extra parent sync confirms the new directory entry.
		directory, err := files.open(filepath.Dir(absolute), os.O_RDONLY, 0)
		if err != nil {
			return nil, ErrUnavailable
		}
		synced := directory.Sync()
		closed := directory.Close()
		if synced != nil || closed != nil {
			return nil, ErrUncertain
		}
	}
	// Open read pool, then validate format, binding, and counters before permitting startup.
	if store.read, store.readSQL, err = database(ctx, absolute, false); err != nil {
		return nil, err
	}
	if err = store.validate(ctx, binding); err != nil {
		return nil, err
	}
	// Initialization has its own deadline; recurring maintenance belongs to the returned Store's lifetime.
	maintenance, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	store.cancel, store.done = cancel, done
	go func() {
		defer close(done)
		store.maintenance(maintenance)
	}()
	return store, nil
}

// database separates one writer from a bounded read pool; deferred reads do not acquire the write lock early.
// path/writer select database and role; returns ORM/pool or closes the created pool on failure.
func database(ctx context.Context, path string, writer bool) (*gorm.DB, *sql.DB, error) {
	// Fixed WAL, FULL sync, one-second busy timeout, and foreign keys; deferred reads and immediate writes.
	parameters := url.Values{"mode": {"rw"}, "_journal_mode": {"WAL"}, "_synchronous": {"FULL"}, "_busy_timeout": {"1000"}, "_foreign_keys": {"1"}, "_txlock": {"deferred"}}
	maximum := 4
	if writer {
		parameters.Set("_txlock", "immediate")
		maximum = 1
	}
	location := url.URL{Scheme: "file", Path: path, RawQuery: parameters.Encode()}
	pool, err := sql.Open("astra-polaris", location.String())
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	// One write connection and four read connections.
	pool.SetMaxOpenConns(maximum)
	pool.SetMaxIdleConns(maximum)
	if err = pool.PingContext(ctx); err != nil {
		pool.Close()
		return nil, nil, ErrUnavailable
	}
	// Disable ORM default transactions/logging; callers own explicit transactions.
	db, err := gorm.Open(sqlite.New(sqlite.Config{Conn: pool}), &gorm.Config{SkipDefaultTransaction: true, Logger: logger.Discard, DisableAutomaticPing: true})
	if err != nil {
		pool.Close()
		return nil, nil, ErrUnavailable
	}
	return db, pool, nil
}

// Close is idempotent and deletes no database/lock files; close connections before releasing the process lock.
func (store *Store) Close() error {
	// Exclusive lifecycle lock excludes reads/writes; repeated Close returns immediately.
	store.life.Lock()
	defer store.life.Unlock()
	if store.closed {
		return nil
	}
	store.closed = true
	// End every Feed and wake waiters before closing connections.
	store.notify.Lock()
	close(store.changed)
	for feed := range store.feeds {
		feed.mutex.Lock()
		feed.stop(ErrClosed)
		feed.mutex.Unlock()
	}
	clear(store.feeds)
	store.feedBytes = 0
	store.notify.Unlock()
	// Maintenance never takes life: Close can cancel and join it while admission remains exclusively closed.
	if store.cancel != nil {
		store.cancel()
		<-store.done
	}
	// Close read pool, write pool, and lock, combining failures into unavailable.
	var result error
	if store.readSQL != nil {
		result = errors.Join(result, store.readSQL.Close())
	}
	if store.writeSQL != nil {
		result = errors.Join(result, store.writeSQL.Close())
	}
	result = errors.Join(result, store.file.Close())
	if result != nil {
		return ErrUnavailable
	}
	return nil
}

// Changed is captured before reading current version; channel closure requires rechecking state, without per-Star event queues.
func (store *Store) Changed() <-chan struct{} {
	store.notify.Lock()
	defer store.notify.Unlock()
	return store.changed
}

// transaction runs under serialized writer admission; any COMMIT error freezes writes conservatively until restart recovery.
// apply is the transaction closure; poisoned state returns uncertain without another write attempt.
func (store *Store) transaction(ctx context.Context, apply func(*gorm.DB) error) error {

	if store.poisoned.Load() {
		return ErrUncertain
	}
	// Own the connection until any database/sql cancellation rollback has actually finished.
	db, conn, err := session(ctx, store.writeSQL, store.write)
	if err != nil {
		return err
	}
	defer conn.Close()

	tx := db.Begin()
	if tx.Error != nil {
		return ErrUnavailable
	}
	// Rollback guard also covers apply panic; ErrTxDone after commit/confirmed rollback preserves the original result.
	defer tx.Rollback()
	if err := apply(tx); err != nil {
		// apply failure rolls back; rollback failure other than already-complete poisons storage.
		if rollback := tx.Rollback().Error; rollback != nil && !errors.Is(rollback, sql.ErrTxDone) {
			store.poisoned.Store(true)
			return ErrUncertain
		}
		return err
	}
	// COMMIT failure likewise poisons writes for restart confirmation.
	if err := tx.Commit().Error; err != nil {
		store.poisoned.Store(true)
		return ErrUncertain
	}
	return nil
}

// session reserves a connection for one operation while preserving its context and immutable ORM configuration.
// Conn.Close waits for the transaction's actual release, even when a concurrent rollback already reports ErrTxDone.
func session(ctx context.Context, pool *sql.DB, db *gorm.DB) (*gorm.DB, *sql.Conn, error) {
	conn, err := pool.Conn(ctx)
	if err != nil {
		// Preserve caller cancellation and deadlines before SQL starts; the service maps these stable context errors.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, nil, err
		}
		return nil, nil, ErrUnavailable
	}
	current := db.WithContext(ctx)
	current.Statement.ConnPool = conn
	return current, conn, nil
}

// maintain attempts a bounded passive checkpoint at WAL pressure without truncating the reusable file.
// Fully checkpointed retained space permits admission; incomplete or failed work remains unavailable.
func (store *Store) maintain(ctx context.Context) error {
	// Absent or below-threshold WAL skips checkpoints but still needs one file-status query.
	info, err := os.Stat(store.path + "-wal")
	if os.IsNotExist(err) || err == nil && info.Size() < store.limits.WAL {
		return nil
	}
	if err != nil {
		return ErrUnavailable
	}
	// Incomplete work is retried by foreground admission or the Store-owned maintenance task.
	var progress struct {
		Busy         int64
		Log          int64
		Checkpointed int64
	}
	if err := store.write.WithContext(ctx).Raw("PRAGMA wal_checkpoint(PASSIVE)").Scan(&progress).Error; err != nil || progress.Busy != 0 || progress.Log > progress.Checkpointed {
		return ErrUnavailable
	}
	return nil
}

// name validates 1..64 safe ASCII bytes matching infrastructure account/Galaxy rules, without path or endpoint aliases.
func name(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '.' || char == '_' || char == '-') {
			return false
		}
	}
	return true
}
