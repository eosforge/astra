// Exhaust bounded acknowledgement histories against a plain independent credit list and byte sum.
//go:build linux && cgo

package server

import (
	"slices"
	"testing"

	"github.com/eosforge/astra/polaris/internal/storage"
)

// TestVerification enumerates all 6^4 histories; admission and wire parsing remain separate native tests.
func TestVerification(t *testing.T) {
	hits := 0
	check := func(condition bool) {
		t.Helper()
		if !condition {
			t.Fatal("acknowledgement credit model diverged")
		}
		hits++
	}
	t.Cleanup(func() { t.Logf(`ASTRA-CONTRACT {"contract":"POLARIS-WINDOW","hits":%d}`, hits) })
	scopes := []storage.Scope{{Sector: "model", Spectrum: "a"}, {Sector: "model", Spectrum: "b"}}
	for history := 0; history < 1296; history++ {
		actual := &transfer{sent: make(map[storage.Scope]storage.Version)}
		type entry struct {
			scope   int
			version storage.Version
			bytes   int64
		}
		expected := []entry{}
		position := [2]storage.Version{}
		remaining := history
		for depth := 0; depth < 4; depth++ {
			operation := remaining % 6
			remaining /= 6
			scope := operation % 2
			if operation < 2 {
				position[scope]++
				cost := int64(depth + 1)
				actual.charge(scopes[scope], position[scope], cost)
				expected = append(expected, entry{scope, position[scope], cost})
			} else {
				version := position[scope]
				if operation < 4 && version > 0 {
					version--
				}
				actual.release(scopes[scope], version)
				expected = slices.DeleteFunc(expected, func(value entry) bool { return value.scope == scope && value.version <= version })
			}
			check(len(actual.credits) == len(expected))
			var bytes int64
			for index, value := range expected {
				bytes += value.bytes
				check(actual.credits[index] == (credit{scope: scopes[value.scope], version: value.version, bytes: value.bytes}))
			}
			check(actual.bytes == bytes)
			for index, value := range position {
				check(actual.sent[scopes[index]] == value)
			}
		}
	}
}
