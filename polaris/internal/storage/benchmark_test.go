//go:build linux && cgo

package storage

import (
	"fmt"
	"path/filepath"
	"testing"
)

// BenchmarkCommit uses production SQLite/disk transactions to compare steady commits with different full-history lengths.
// Setup/prefill is untimed; each request has a new version and results describe durable disk commits.
func BenchmarkCommit(b *testing.B) {
	for _, history := range []int64{16, 4096} {
		b.Run(fmt.Sprint(history), func(b *testing.B) {
			limits := Default()
			limits.History = history
			store, err := Open(b.Context(), filepath.Join(b.TempDir(), "polaris.db"), Binding{Galaxy: "measure", Username: "polaris", Advertise: "127.0.0.1:45101"}, limits, true)
			if err != nil {
				b.Fatal(err)
			}
			defer func() {
				if err := store.Close(); err != nil {
					b.Error(err)
				}
			}()
			scope := Scope{"measure", "commit"}
			value := make([]byte, 128)
			version := Version(0)
			commit := func() {
				version++
				confirmed, err := store.Commit(b.Context(), scope, Change{Version: version, Key: "key", Value: value})
				if err != nil || confirmed != version {
					b.Fatalf("commit=%d error=%v", confirmed, err)
				}
			}
			for range history {
				commit()
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				commit()
			}
			b.StopTimer()
		})
	}
}
