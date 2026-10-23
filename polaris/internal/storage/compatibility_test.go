//go:build linux && cgo

// Verify frozen persisted formats and offline-copy recovery for the first supported generation.
package storage

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

// TestCompatibility uses independent SQL vectors, never the production writer to create its input database.
func TestCompatibility(t *testing.T) {
	check := verification(t, "STORAGE-ASSURANCE")
	scope := Scope{Sector: "release", Spectrum: "baseline"}
	binding := Binding{Galaxy: "test", Username: "polaris", Advertise: "127.0.0.1:45101"}
	payload, err := hex.DecodeString("4142303200000000000000030001000000020061000100010000000000620001000000000163")
	check(err == nil && len(payload) == 38, "the published three-entry golden vector has 38 bytes")
	definitions, err := os.ReadFile("testdata/schema.sql")
	check(err == nil && bytes.Count(definitions, []byte("CREATE TABLE")) == 4, "load four frozen historical table definitions")
	for _, name := range []string{"single", "batch", "unknown", "truncated"} {
		t.Run(name, func(t *testing.T) {
			check := verification(t, "STORAGE-ASSURANCE")
			vector := "batch"
			if name == "single" {
				vector = name
			}
			data, err := os.ReadFile("testdata/" + vector + ".sql")
			check(err == nil, "load the independent persisted vector")
			bad := name == "unknown" || name == "truncated"
			body := bytes.Clone(payload)
			if bad {
				check(bytes.Count(data, []byte(hex.EncodeToString(payload))) == 1, "the negative control changes exactly one encoded history body")
				if name == "unknown" {
					body[3] = '3'
				} else {
					body = body[:len(body)-1]
					check(bytes.Count(data, []byte(",1,102)")) == 1 && bytes.Count(data, []byte(",0,102)")) == 1, "adjust only the literal history charges for the shorter body")
					data = bytes.Replace(data, []byte(",1,102)"), []byte(",1,101)"), 1)
					data = bytes.Replace(data, []byte(",0,102)"), []byte(",0,101)"), 1)
				}
				data = bytes.Replace(data, []byte(hex.EncodeToString(payload)), []byte(hex.EncodeToString(body)), 1)
			}
			original := filepath.Join(t.TempDir(), "original.db")
			location := url.URL{Scheme: "file", Path: original, RawQuery: "mode=rwc&_journal_mode=DELETE&_synchronous=FULL"}
			pool, err := sql.Open("sqlite3", location.String())
			check(err == nil, "create a private native SQLite fixture without Store initialization")
			t.Cleanup(func() { check(pool.Close() == nil, "close the independent fixture connection") })
			_, err = pool.ExecContext(t.Context(), string(definitions)+string(data))
			check(err == nil, "install the fixed schema and literal rows")
			check(pool.Close() == nil, "finish the offline source before copying")
			backup, err := os.ReadFile(original)
			check(err == nil && len(backup) > 0, "retain the complete closed source database")
			working := filepath.Join(t.TempDir(), "working.db")
			check(os.WriteFile(working, backup, 0600) == nil, "validate a separate working copy")
			store, err := Open(t.Context(), working, binding, Default(), false)
			if bad {
				if store != nil {
					t.Cleanup(func() { check(store.Close() == nil, "drain an unexpectedly accepted malformed database") })
				}
				check(store == nil && errors.Is(err, ErrCorrupt), "unknown or truncated history refuses startup without a partial Store")
				store, err = Open(t.Context(), working, binding, Default(), false)
				if store != nil {
					t.Cleanup(func() { check(store.Close() == nil, "drain an unexpected second startup") })
				}
				check(store == nil && errors.Is(err, ErrCorrupt), "refused startup releases its lock and never silently repairs history")
				location = url.URL{Scheme: "file", Path: working, RawQuery: "mode=ro"}
				inspection, err := sql.Open("sqlite3", location.String())
				check(err == nil, "inspect the rejected working copy read-only")
				t.Cleanup(func() { check(inspection.Close() == nil, "close rejected-copy inspection") })
				var preserved []byte
				err = inspection.QueryRowContext(t.Context(), "SELECT value FROM history").Scan(&preserved)
				check(err == nil && bytes.Equal(preserved, body), "refusal preserves the offending history bytes for recovery")
			} else {
				check(err == nil && store != nil, "current generation validates a frozen supported format")
				t.Cleanup(func() { check(store.Close() == nil, "close the imported Store") })
				image, err := store.Load(t.Context(), scope)
				count := 1
				if name == "batch" {
					count = 2
				}
				check(err == nil && image.Version == 1 && len(image.Records) == count, "recover exact authoritative version and live cardinality")
				check(image.Records[0].Key == "a" && bytes.Equal(image.Records[0].Value, []byte{0, 1}), "binary content survives the independent format")
				if name == "batch" {
					check(image.Records[1].Key == "b" && len(image.Records[1].Value) == 0, "empty Set survives while the deleted key is absent")
				}
				history, err := store.Since(t.Context(), scope, 0)
				check(err == nil && history.Version == 1 && len(history.Changes) == 1, "one durable version retains one complete history entry")
				change := history.Changes[0]
				if name == "single" {
					check(change.Key == "a" && bytes.Equal(change.Value, []byte{0, 1}) && !change.Erase, "old single-key layout retains its exact intent")
				} else {
					check(change.Key == "" && bytes.Equal(change.Value, payload) && !change.Erase, "the writer-independent AB02 bytes are preserved")
					entries, err := change.Entries()
					check(err == nil && len(entries) == 3, "decode the complete ordered batch")
					for index, key := range []string{"a", "b", "c"} {
						entry := entries[index]
						check(entry.Key == key && entry.Version == 1 && entry.Erase == (index == 2), "all entries retain the common version, order and operation")
					}
				}
				changes := []Change{{Key: "a", Value: []byte{9}}, {Key: "b", Erase: true}, {Key: "d"}}
				version, err := store.CommitBatch(t.Context(), scope, 2, changes)
				check(err == nil && version == 2, "import accepts the next complete atomic commit without resetting versions")
				check(store.Close() == nil, "drain the current writer before taking its offline recovery copy")
				current, err := os.ReadFile(working)
				check(err == nil && len(current) > 0, "capture current durable state after acknowledged writes")
				restored := filepath.Join(t.TempDir(), "restored.db")
				check(os.WriteFile(restored, current, 0600) == nil, "restore only the current-generation offline copy")
				recovered, err := Open(t.Context(), restored, binding, Default(), false)
				check(err == nil && recovered != nil, "restore validates using the current generation")
				t.Cleanup(func() { check(recovered.Close() == nil, "close restored Store") })
				image, err = recovered.Load(t.Context(), scope)
				check(err == nil && image.Version == 2 && len(image.Records) == 2, "restore preserves the last acknowledged version and atomic cardinality")
				check(image.Records[0].Key == "a" && bytes.Equal(image.Records[0].Value, []byte{9}) && image.Records[1].Key == "d" && len(image.Records[1].Value) == 0, "restore does not lose the acknowledged overwrite, erase or empty Set")
				version, err = recovered.CommitBatch(t.Context(), scope, 2, changes)
				check(err == nil && version == 2, "restore retains complete idempotent retry evidence")
				changes[0].Value = []byte{10}
				_, err = recovered.CommitBatch(t.Context(), scope, 2, changes)
				check(errors.Is(err, ErrVersion), "restore rejects conflicting retry intent")
				history, err = recovered.Since(t.Context(), scope, 0)
				check(err == nil && history.Version == 2 && len(history.Changes) == 2, "both complete commits remain in ordered history after restore and retry")
			}
			after, err := os.ReadFile(original)
			check(err == nil && bytes.Equal(after, backup), "successful and failed imports never alter the offline source")
		})
	}
}
