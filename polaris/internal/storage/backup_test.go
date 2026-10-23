//go:build linux && cgo

// Verify native consistent backup watermarks and recovery without treating an older image as lossless rollback.
package storage

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/mattn/go-sqlite3"
)

// backup copies one source connection's fixed read transaction using the admitted native SQLite backup API.
// after runs once after copying begins; every remaining step must progress within the finite page budget.
func backup(ctx context.Context, source *sql.Conn, path string, after func() error) (steps, pages int, result error) {
	location := url.URL{Scheme: "file", Path: path, RawQuery: "mode=rwc&_synchronous=FULL&_busy_timeout=1000"}
	database, err := sql.Open("sqlite3", location.String())
	if err != nil {
		return 0, 0, err
	}
	defer func() { result = errors.Join(result, database.Close()) }()
	database.SetMaxOpenConns(1)
	destination, err := database.Conn(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer func() { result = errors.Join(result, destination.Close()) }()
	result = source.Raw(func(value any) error {
		original, ok := value.(*sqlite3.SQLiteConn)
		if !ok {
			return fmt.Errorf("unexpected source driver %T", value)
		}
		return destination.Raw(func(value any) (result error) {
			connection, ok := value.(*sqlite3.SQLiteConn)
			if !ok {
				return fmt.Errorf("unexpected destination driver %T", value)
			}
			copy, err := connection.Backup("main", original, "main")
			if err != nil {
				return err
			}
			defer func() { result = errors.Join(result, copy.Finish()) }()
			remaining := -1
			for steps = 1; steps <= 4096; steps++ {
				if err := ctx.Err(); err != nil {
					return err
				}
				done, err := copy.Step(4)
				if err != nil {
					return err
				}
				pages = copy.PageCount()
				left := copy.Remaining()
				if pages < 5 || pages > 2048 || left < 0 || left >= pages || (remaining >= 0 && left >= remaining && !done) {
					return fmt.Errorf("backup lacks bounded progress: pages=%d remaining=%d previous=%d", pages, left, remaining)
				}
				remaining = left
				if steps == 1 && after != nil {
					if done {
						return errors.New("backup finished before the concurrent-write boundary")
					}
					if err := after(); err != nil {
						return err
					}
				}
				if done {
					if left != 0 {
						return errors.New("completed backup retains uncopied pages")
					}
					return nil
				}
			}
			return errors.New("backup exceeded its finite step budget")
		})
	})
	return steps, pages, result
}

// backupFixture owns two known scopes and leaves the public maintenance task running through backup and recovery.
func backupFixture(t *testing.T) (*Store, Binding, []Scope) {
	t.Helper()
	binding := Binding{Galaxy: "backup", Username: "polaris", Advertise: "127.0.0.1:45101"}
	store, err := Open(t.Context(), filepath.Join(t.TempDir(), "source.db"), binding, Default(), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	scopes := []Scope{{Sector: "backup", Spectrum: "a"}, {Sector: "backup", Spectrum: "b"}}
	for index, scope := range scopes {
		changes := make([]Change, 8)
		for key := range changes {
			changes[key] = Change{Key: fmt.Sprintf("k%d", key), Value: bytes.Repeat([]byte{byte(index*16 + key)}, 64<<10)}
		}
		if version, err := store.CommitBatch(t.Context(), scope, 1, changes); err != nil || version != 1 {
			t.Fatal("initialize the independent backup vector", version, err)
		}
	}
	return store, binding, scopes
}

// backupImage derives expected bytes and versions from the fixed operation vector, independently of Store output.
func backupImage(scope Scope, index int, version Version) Snapshot {
	image := Snapshot{Position: Position{Scope: scope, Version: version}}
	for key := range 8 {
		value := bytes.Repeat([]byte{byte(index*16 + key)}, 64<<10)
		if version == 2 && key == 0 {
			value = []byte{byte(200 + index)}
		}
		image.Records = append(image.Records, Record{Key: fmt.Sprintf("k%d", key), Value: value})
	}
	return image
}

// TestOnlineBackup fixes a real source read mark before copying and commits both scopes while native copying is active.
func TestOnlineBackup(t *testing.T) {
	check := verification(t, "STORAGE-BACKUP-ONLINE")
	store, binding, scopes := backupFixture(t)
	connection, err := store.readSQL.Conn(t.Context())
	check(err == nil, "own the exact backup source connection")
	defer connection.Close()
	read, err := connection.BeginTx(t.Context(), nil)
	check(err == nil, "start one consistent backup read transaction")
	defer read.Rollback()
	var count int
	check(read.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM scopes WHERE version=X'0000000000000001'").Scan(&count) == nil && count == 2, "freeze both version-one scopes at one read mark")
	var writes int
	path := filepath.Join(t.TempDir(), "online.db")
	steps, pages, err := backup(t.Context(), connection, path, func() error {
		for index, scope := range scopes {
			version, err := store.Commit(t.Context(), scope, Change{Version: 2, Key: "k0", Value: []byte{byte(200 + index)}})
			if err != nil || version != 2 {
				return fmt.Errorf("concurrent durable commit %d: version=%d error=%v", index, version, err)
			}
			writes++
		}
		return nil
	})
	check(err == nil && steps > 1 && writes == 2, "both durable commits complete after native copy begins and before it finishes")
	check(read.Rollback() == nil && connection.Close() == nil, "release the original read mark and native source owner")
	recovered, err := Open(t.Context(), path, binding, Default(), false)
	check(err == nil, "validate the completed online image using the current Store")
	defer recovered.Close()
	for index, scope := range scopes {
		image, err := recovered.Load(t.Context(), scope)
		check(err == nil && reflect.DeepEqual(image, backupImage(scope, index, 1)), "online image retains the complete fixed watermark, including large values")
		live, err := store.Load(t.Context(), scope)
		check(err == nil && reflect.DeepEqual(live, backupImage(scope, index, 2)), "live authority independently retains both later acknowledged commits")
	}
	check(recovered.Close() == nil && store.readSQL.Stats().InUse == 0 && store.writeSQL.Stats().InUse == 0, "backup and recovered readers release every connection")
	t.Logf("STORAGE-BACKUP mode=online steps=%d pages=%d watermark=1 concurrent_commits=%d live_version=2", steps, pages, writes)
}

// TestBackupRestore verifies the quiesced watermark, exact retry receipts and a new commit in a working copy.
func TestBackupRestore(t *testing.T) {
	check := verification(t, "STORAGE-BACKUP-RESTORE")
	store, binding, scopes := backupFixture(t)
	for index, scope := range scopes {
		requireCommit(t, store, scope, Change{Version: 2, Key: "k0", Value: []byte{byte(200 + index)}})
	}
	connection, err := store.readSQL.Conn(t.Context())
	check(err == nil, "acquire the quiesced source connection")
	defer connection.Close()
	read, err := connection.BeginTx(t.Context(), nil)
	check(err == nil, "begin the quiesced backup snapshot")
	defer read.Rollback()
	var count int
	check(read.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM scopes WHERE version=X'0000000000000002'").Scan(&count) == nil && count == 2, "fix the final acknowledged watermark with no later writers")
	path := filepath.Join(t.TempDir(), "backup.db")
	steps, pages, err := backup(t.Context(), connection, path, nil)
	check(err == nil && steps > 1, "complete the native backup within its finite page budget")
	check(read.Rollback() == nil && connection.Close() == nil, "drain source backup ownership before restore")
	sealed, err := os.ReadFile(path)
	check(err == nil && len(sealed) > 0 && len(sealed) <= 8<<20, "retain the complete bounded backup image")
	working := filepath.Join(t.TempDir(), "working.db")
	check(os.WriteFile(working, sealed, 0600) == nil, "restore a separate working copy without editing the retained backup")
	recovered, err := Open(t.Context(), working, binding, Default(), false)
	check(err == nil, "recover the native image under the current generation and binding")
	defer recovered.Close()
	for index, scope := range scopes {
		image, err := recovered.Load(t.Context(), scope)
		check(err == nil && reflect.DeepEqual(image, backupImage(scope, index, 2)), "restore preserves the complete final acknowledged state and version")
		receipt := Change{Version: 2, Key: "k0", Value: []byte{byte(200 + index)}}
		changed := recovered.Changed()
		version, err := recovered.Commit(t.Context(), scope, receipt)
		check(err == nil && version == 2 && recovered.Changed() == changed, "restore preserves exact retry evidence without a new commit or notification")
		receipt.Value = []byte{0}
		version, err = recovered.Commit(t.Context(), scope, receipt)
		check(version == 0 && errors.Is(err, ErrVersion) && recovered.Changed() == changed, "restored retry rejects conflicting intent without side effects")
		requireCommit(t, recovered, scope, Change{Version: 3, Key: "next", Value: []byte{byte(index)}})
		image, err = recovered.Load(t.Context(), scope)
		expected := backupImage(scope, index, 2)
		expected.Version = 3
		expected.Records = append(expected.Records, Record{Key: "next", Value: []byte{byte(index)}})
		check(err == nil && reflect.DeepEqual(image, expected), "recovered authority continues from the preserved version without renumbering")
	}
	check(recovered.Close() == nil && store.Close() == nil, "drain both Store maintenance tasks and SQL pools")
	retained, err := os.ReadFile(path)
	check(err == nil && bytes.Equal(retained, sealed), "restore and later writes leave the retained backup bytes unchanged")
	t.Logf("STORAGE-BACKUP mode=quiesced steps=%d pages=%d watermark=2 restored_scopes=2 retries=2 continued_commits=2", steps, pages)
}
