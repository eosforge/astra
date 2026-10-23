//go:build linux && cgo

// Verify initialization rejection and cleanup with isolated native SQLite connections.
package storage

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
	"golang.org/x/sys/unix"
)

// opening owns a child-only driver; SQL, durability and connection shutdown remain native.
type opening struct {
	native                   sqlite3.SQLiteDriver // Pinned native driver and production connection setup.
	point                    string               // One initialization boundary selected before execution.
	root                     string               // Parent-created private directory; moves stay within it.
	active                   atomic.Bool          // Disable the fault before an independent healthy reopen.
	connects, opened, closed atomic.Int32         // Actual hook entries and delegated connection lifetimes.
	hits                     atomic.Int32         // Reached authorizer or post-commit fault boundaries.
	scans, steps, finalized  atomic.Int32         // Reached retained-history streams, native rows and completed cursor closes.
	files, released          atomic.Int32         // Actual descriptors acquired and closed through the private opening boundary.
}

// open acquires a real descriptor before applying one explicitly selected initialization fault.
func (probe *opening) open(path string, flags int, mode os.FileMode) (handle, error) {
	file, err := os.OpenFile(path, flags, mode)
	if err != nil {
		return nil, err
	}
	probe.files.Add(1)
	return &openingFile{File: file, probe: probe, created: flags&os.O_EXCL != 0}, nil
}

// openingFile preserves descriptor ownership while returning a reached close or sync failure.
type openingFile struct {
	*os.File          // Actual private file or directory, never an in-memory replacement.
	probe    *opening // Fault selection and native release accounting for this child only.
	created  bool     // Distinguish the new database file from its parent directory.
}

// Close completes the native descriptor release before modelling an error returned by that completed close.
func (file *openingFile) Close() error {
	err := file.File.Close()
	if err != nil {
		return err
	}
	file.probe.released.Add(1)
	if file.probe.active.Load() && (file.created && file.probe.point == "created-close" || !file.created && (file.probe.point == "directory-close" || file.probe.point == "directory-both")) {
		file.probe.hits.Add(1)
		return unix.EIO
	}
	return nil
}

// Sync refuses only the owned parent-directory durability operation and leaves its subsequent Close observable.
func (file *openingFile) Sync() error {
	if !file.created && file.probe.active.Load() && (file.probe.point == "directory-sync" || file.probe.point == "directory-both") {
		file.probe.hits.Add(1)
		return unix.EIO
	}
	return file.File.Sync()
}

// preparing models the standard DriverContext preparation error without replacing native SQL execution.
type preparing struct {
	*opening // Child-owned native driver and fault lifetime.
}

// OpenConnector fails before a SQL pool exists; after the fault is disabled it returns a native connector.
func (probe *preparing) OpenConnector(name string) (driver.Connector, error) {
	if probe.active.Load() {
		probe.hits.Add(1)
		return nil, unix.EIO
	}
	return &connector{source: probe.opening, name: name}, nil
}

// connector delegates connection creation to the same observed native driver used by all other opening cases.
type connector struct {
	source *opening // Isolated driver that owns native connection counters.
	name   string   // Exact DSN constructed by the production database adapter.
}

// Connect respects cancellation before acquiring a native connection.
func (connector *connector) Connect(ctx context.Context) (driver.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return connector.source.Open(connector.name)
}

// Driver reports the owner of every connection returned by Connect.
func (connector *connector) Driver() driver.Driver { return connector.source }

// Open preserves native error handling, including ConnectHook failures before a connection is returned.
func (probe *opening) Open(name string) (driver.Conn, error) {
	conn, err := probe.native.Open(name)
	if err != nil {
		return nil, err
	}
	probe.opened.Add(1)
	return &initializing{SQLiteConn: conn.(*sqlite3.SQLiteConn), probe: probe}, nil
}

// initializing adds lifecycle observation without replacing native SQL or its optional interfaces.
type initializing struct {
	*sqlite3.SQLiteConn          // Real SQLite connection and context-aware driver interfaces.
	probe               *opening // Child-owned fault and resource accounting.
}

// Close counts only a successfully completed native close.
func (conn *initializing) Close() error {
	err := conn.SQLiteConn.Close()
	if err == nil {
		conn.probe.closed.Add(1)
	}
	return err
}

// BeginTx delegates SQLite transaction creation before observing its durable completion.
func (conn *initializing) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	tx, err := conn.SQLiteConn.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return &initialized{Tx: tx, probe: conn.probe}, nil
}

// initialized preserves the actual transaction and changes only the owned directory after COMMIT.
type initialized struct {
	driver.Tx          // Native COMMIT and rollback operations.
	probe     *opening // Immutable selected boundary and private path ownership.
}

// Commit moves the private directory only after SQLite has acknowledged the initialization commit.
func (tx *initialized) Commit() error {
	if err := tx.Tx.Commit(); err != nil {
		return err
	}
	if tx.probe.active.Load() && tx.probe.point == "directory" {
		tx.probe.hits.Add(1)
		return os.Rename(filepath.Join(tx.probe.root, "parent"), filepath.Join(tx.probe.root, "held"))
	}
	return nil
}

// openingFiles rejects any leaked descriptor into the private database, WAL, lock or moved directory.
func openingFiles(t *testing.T, root string) {
	t.Helper()
	files, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", file.Name()))
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if strings.HasPrefix(target, root+string(os.PathSeparator)) {
			t.Fatal("initialization retained an owned descriptor", target)
		}
	}
}

// openingChild executes one declared boundary in a fresh process, never replacing the parent's driver.
func openingChild(t *testing.T, point, root string) {
	t.Helper()
	if strings.HasPrefix(point, "retain-") {
		retentionChild(t, point, root)
		return
	}
	expected := map[string]error{
		"control": nil, "schema": ErrCorrupt, "orm": ErrUnavailable, "read": ErrUnavailable, "directory": ErrUnavailable, "path": ErrInput,
		"created-close": ErrUnavailable, "directory-sync": ErrUncertain, "directory-close": ErrUncertain, "directory-both": ErrUncertain, "sql-open": ErrUnavailable,
	}
	want, exists := expected[point]
	if !exists || !filepath.IsAbs(root) || filepath.Clean(root) == string(os.PathSeparator) {
		t.Fatal("invalid child boundary or private directory")
	}
	parent := filepath.Join(root, "parent")
	path := filepath.Join(parent, "polaris.db")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	probe := &opening{point: point, root: root}
	probe.active.Store(true)
	probe.native.ConnectHook = func(conn *sqlite3.SQLiteConn) error {
		ordinal := probe.connects.Add(1)
		if err := connection(conn); err != nil {
			return err
		}
		if !probe.active.Load() {
			return nil
		}
		if point == "read" && ordinal == 2 {
			probe.hits.Add(1)
			return errors.New("assurance-read-connection")
		}
		conn.RegisterAuthorizer(func(operation int, first, second, _ string) int {
			if point == "schema" && operation == sqlite3.SQLITE_CREATE_TABLE && first == "meta" || point == "orm" && operation == sqlite3.SQLITE_FUNCTION && second == "sqlite_version" {
				probe.hits.Add(1)
				return sqlite3.SQLITE_DENY
			}
			return sqlite3.SQLITE_OK
		})
		return nil
	}
	driverOnce.Do(func() {
		if point == "sql-open" {
			sql.Register("astra-polaris", &preparing{probe})
		} else {
			sql.Register("astra-polaris", probe)
		}
	})
	binding := Binding{Galaxy: "test", Username: "polaris", Advertise: "127.0.0.1:45101"}
	if point == "created-close" || point == "directory-sync" || point == "directory-close" || point == "directory-both" || point == "sql-open" {
		openingFaults(t, probe, parent, binding, want)
		return
	}
	location := path
	if point == "path" {
		previous, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		cwd := filepath.Join(root, "cwd")
		if err := os.Mkdir(cwd, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chdir(cwd); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.Chdir(previous); err != nil {
				t.Error(err)
			}
		}()
		if err := os.Remove(cwd); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Getwd(); err == nil {
			t.Fatal("deleted owned cwd did not reject relative resolution")
		}
		probe.hits.Add(1)
		location = "polaris.db"
	}
	store, err := Open(t.Context(), location, binding, Default(), true)
	if point == "control" {
		if err != nil || store == nil {
			t.Fatal("healthy initialization rejected", err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	} else if store != nil || !errors.Is(err, want) || probe.hits.Load() != 1 {
		t.Fatalf("point=%s store=%v error=%v wanted=%v hits=%d", point, store != nil, err, want, probe.hits.Load())
	}
	if probe.opened.Load() != probe.closed.Load() {
		t.Fatalf("initialization leaked native connections: opened=%d closed=%d", probe.opened.Load(), probe.closed.Load())
	}
	openingFiles(t, root)
	probe.active.Store(false)
	if point == "directory" {
		if err := os.Rename(filepath.Join(root, "held"), parent); err != nil {
			t.Fatal(err)
		}
	}
	if point == "path" {
		if _, err := os.Stat(path); !os.IsNotExist(err) || probe.opened.Load() != 0 {
			t.Fatal("invalid relative path created a database or connection", err)
		}
	} else {
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
			t.Fatal("failed initialization deleted its evidence file", err)
		}
		if point == "schema" || point == "orm" {
			pool, err := sql.Open("sqlite3", "file:"+path+"?mode=rw")
			if err != nil {
				t.Fatal(err)
			}
			var tables int
			err = pool.QueryRowContext(t.Context(), "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&tables)
			closed := pool.Close()
			if err != nil || closed != nil || tables != 0 {
				t.Fatal("rejected preparation left a partial schema", tables, err, closed)
			}
			owner, err := lock(path)
			if err != nil {
				t.Fatal("initialization retained file ownership", err)
			}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
		} else {
			store, err := Open(t.Context(), path, binding, Default(), false)
			if err != nil {
				t.Fatal("durable initialization could not be independently recovered", err)
			}
			defer store.Close()
			scope := Scope{"startup", "fresh"}
			version, err := store.Commit(t.Context(), scope, Change{Version: 1, Key: "k", Value: []byte{7}})
			image, read := store.Load(t.Context(), scope)
			if err != nil || read != nil || version != 1 || image.Version != 1 || len(image.Records) != 1 || image.Records[0].Key != "k" || len(image.Records[0].Value) != 1 || image.Records[0].Value[0] != 7 {
				t.Fatal("recovered initialization failed a complete public commit", version, image, err, read)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	if probe.opened.Load() != probe.closed.Load() {
		t.Fatal("recovery left a native connection open")
	}
	openingFiles(t, root)
	fmt.Printf("STORAGE-OPEN point=%s hits=%d opened=%d closed=%d\n", point, probe.hits.Load(), probe.opened.Load(), probe.closed.Load())
}

// openingFaults repeats each startup failure, verifies resource release and evidence, then executes an independent healthy recovery.
func openingFaults(t *testing.T, probe *opening, parent string, binding Binding, want error) {
	t.Helper()
	perAttempt := int32(1)
	if probe.point == "directory-both" {
		perAttempt = 2
	}
	initialized := strings.HasPrefix(probe.point, "directory-")
	for attempt := range 2 {
		path := filepath.Join(parent, fmt.Sprintf("failed-%d.db", attempt))
		store, err := open(t.Context(), path, binding, Default(), true, probe)
		if store != nil || !errors.Is(err, want) || probe.hits.Load() != int32(attempt+1)*perAttempt {
			t.Fatalf("point=%s attempt=%d store=%v error=%v wanted=%v hits=%d", probe.point, attempt, store != nil, err, want, probe.hits.Load())
		}
		files := int32(attempt + 1)
		if initialized {
			files *= 2
		}
		if probe.files.Load() != files || probe.files.Load() != probe.released.Load() || probe.opened.Load() != probe.closed.Load() {
			t.Fatal("failed initialization retained an acquired descriptor or connection")
		}
		openingFiles(t, probe.root)
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
			t.Fatal("initialization removed its failure evidence", err)
		}
		probe.active.Store(false)
		if initialized {
			store, err = Open(t.Context(), path, binding, Default(), false)
			if err != nil || store == nil {
				t.Fatal("uncertain directory durability prevented native recovery", err)
			}
			openingCommit(t, store)
		} else {
			pool, err := sql.Open("sqlite3", "file:"+path+"?mode=ro")
			if err != nil {
				t.Fatal(err)
			}
			var tables int
			err = pool.QueryRowContext(t.Context(), "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'").Scan(&tables)
			closed := pool.Close()
			if err != nil || closed != nil || tables != 0 {
				t.Fatal("failure before initialization left a partial schema", tables, err, closed)
			}
			store, err = Open(t.Context(), path, binding, Default(), false)
			if store != nil || !errors.Is(err, ErrCorrupt) {
				t.Fatal("recovery silently initialized an uncommitted file", store != nil, err)
			}
		}
		owner, err := lock(path)
		if err != nil {
			t.Fatal("failed opening retained exclusive ownership", err)
		}
		if err := owner.Close(); err != nil {
			t.Fatal(err)
		}
		openingFiles(t, probe.root)
		probe.active.Store(true)
	}
	probe.active.Store(false)
	store, err := Open(t.Context(), filepath.Join(parent, "healthy.db"), binding, Default(), true)
	if err != nil || store == nil {
		t.Fatal("healthy initialization failed after persistent faults", err)
	}
	openingCommit(t, store)
	if probe.files.Load() != probe.released.Load() || probe.opened.Load() != probe.closed.Load() || probe.hits.Load() != 2*perAttempt {
		t.Fatal("healthy recovery repeated a fault or retained native resources")
	}
	openingFiles(t, probe.root)
	fmt.Printf("STORAGE-OPEN point=%s hits=%d opened=%d closed=%d files=%d released=%d\n", probe.point, probe.hits.Load(), probe.opened.Load(), probe.closed.Load(), probe.files.Load(), probe.released.Load())
}

// openingCommit verifies one public mutation and complete snapshot before releasing all native resources.
func openingCommit(t *testing.T, store *Store) {
	t.Helper()
	defer store.Close()
	scope := Scope{"startup", "recovered"}
	version, err := store.Commit(t.Context(), scope, Change{Version: 1, Key: "k", Value: []byte{7}})
	image, read := store.Load(t.Context(), scope)
	if err != nil || read != nil || version != 1 || image.Version != 1 || len(image.Records) != 1 || image.Records[0].Key != "k" || len(image.Records[0].Value) != 1 || image.Records[0].Value[0] != 7 {
		t.Fatal("healthy recovery failed a complete public commit", version, image, err, read)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

// openingCases bounds and joins isolated driver checks, including startup and retained-cursor failures.
func openingCases(t *testing.T, verified func(bool, string)) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, point := range []string{"control", "schema", "orm", "read", "directory", "path", "created-close", "directory-sync", "directory-close", "directory-both", "sql-open", "retain-control", "retain-next", "retain-close", "retain-both"} {
		verified(t.Run("open-"+point, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			arguments := []string{"-test.run=^TestWriteFault$", "-test.count=1"}
			if testing.CoverMode() != "" {
				cover := flag.Lookup("test.gocoverdir")
				if cover == nil || cover.Value.String() == "" {
					t.Fatal("instrumented parent lacks its native coverage directory")
				}
				// Each joined child emits native counters for the parent's final profile merge.
				arguments = append(arguments, "-test.gocoverdir="+cover.Value.String())
			}
			command := exec.CommandContext(ctx, binary, arguments...)
			command.Env = append(os.Environ(), "ASTRA_STORAGE_OPEN_POINT="+point, "ASTRA_STORAGE_OPEN_ROOT="+t.TempDir())
			command.WaitDelay = time.Second
			output, err := command.CombinedOutput()
			marker := "STORAGE-OPEN point=" + point + " "
			if err != nil || strings.Count(string(output), marker) != 1 || ctx.Err() != nil {
				t.Fatalf("native driver child failed: error=%v context=%v output=%s", err, ctx.Err(), output)
			}
			t.Log(strings.TrimSpace(string(output)))
		}), "joined native driver "+point)
	}
}
