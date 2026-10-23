// Check preparation accounting against literal byte budgets and real independent snapshot readers.
//go:build linux && cgo

package server

import (
	"errors"
	"testing"

	"github.com/eosforge/astra/polaris/internal/storage"
)

// TestReservation distinguishes payload, record-index and page reserves from live payload occupancy.
func TestReservation(t *testing.T) {
	t.Parallel()
	limits := storage.Default()
	limits.Bytes, limits.Records = 1048576, 3
	store := fixture(t, limits)
	scope := storage.Scope{Sector: "s", Spectrum: "p"}
	other := storage.Scope{Sector: "s", Spectrum: "q"}
	for _, test := range []struct {
		name    string // Stable native boundary name.
		bytes   int64  // Shared preparation budget, including two MiB for the page workspace.
		readers int    // Number of independent targets the declared budget permits.
	}{{"below", 3146111, 0}, {"one", 3146112, 1}, {"two", 6292224, 2}} {
		t.Run(test.name, func(t *testing.T) {
			cache := newCache(store, limits, test.bytes)
			if cache.reserve != 3146112 || cache.maximum != test.bytes || cache.used != 0 || len(cache.entries) != 0 {
				t.Fatal("preparation omitted payload, index or page reserve or eagerly charged a reader")
			}
			first, err := cache.acquire(t.Context(), scope, 0)
			if first != nil {
				defer first.release()
			}
			if test.readers == 0 {
				if first != nil || !errors.Is(err, storage.ErrCapacity) || cache.used != 0 || len(cache.entries) != 0 {
					t.Fatal("insufficient preparation reserve admitted work or retained ownership", err)
				}
				return
			}
			if err != nil || first == nil || cache.used != 3146112 || len(cache.entries) != 1 {
				t.Fatal("one preparation target was not charged exactly once", err)
			}
			shared, err := cache.acquire(t.Context(), scope, 0)
			if shared != nil {
				defer shared.release()
			}
			if err != nil || shared == nil || shared.Snapshot != first.Snapshot || cache.used != 3146112 || first.entry.references != 2 {
				t.Fatal("shared preparation consumed another target reservation", err)
			}
			second, err := cache.acquire(t.Context(), other, 0)
			if second != nil {
				defer second.release()
			}
			if test.readers == 1 {
				if second != nil || !errors.Is(err, storage.ErrCapacity) || cache.used != 3146112 || len(cache.entries) != 1 {
					t.Fatal("independent target exceeded the remaining preparation budget", err)
				}
			} else {
				if err != nil || second == nil || second.Snapshot == first.Snapshot || cache.used != 6292224 || len(cache.entries) != 2 {
					t.Fatal("two independent targets did not own two exact reservations", err)
				}
				second.release()
			}
			first.release()
			if cache.used != 3146112 || len(cache.entries) != 1 || shared.entry.references != 1 {
				t.Fatal("releasing one reader discarded a still-owned target")
			}
			shared.release()
			if cache.used != 0 || len(cache.entries) != 0 {
				t.Fatal("preparation retained a reservation after all readers retired")
			}
		})
	}
}
