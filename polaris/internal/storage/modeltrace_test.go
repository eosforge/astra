//go:build linux && cgo

// Export actual finite-model observations for independent gate reconstruction.
package storage

import (
	"encoding/json"
	"errors"
	"testing"
)

// reply records the actual public receipt without inferring it from a reference model.
type reply struct {
	Version Version `json:"version"` // Actual returned authority version.
	Error   string  `json:"error"`   // Stable error identity; an unexpected cause remains other.
}

// lookup retains a rejected replay's actual result as well as its stable error identity.
type lookup struct {
	History Replay `json:"history"` // Actual returned history, including any erroneous partial result.
	Error   string `json:"error"`   // Actual stable error identity.
}

// receipt translates only the public error identity; it supplies no expected result.
func receipt(version Version, err error) reply {
	code := ""
	if err != nil {
		code = "other"
		if errors.Is(err, ErrVersion) {
			code = "version"
		} else if errors.Is(err, ErrHistory) {
			code = "history"
		}
	}
	return reply{version, code}
}

// trial retains one executed sequential transition and its complete returned public values.
type trial struct {
	Case     int      `json:"case"`     // Zero-based sequence ordinal.
	Sequence []int    `json:"sequence"` // Actual operation indexes selected by this run.
	Step     int      `json:"step"`     // Zero-based position within the sequence.
	Commit   reply    `json:"commit"`   // Initial mutation receipt.
	Retry    reply    `json:"retry"`    // Identical retry receipt.
	Gap      reply    `json:"gap"`      // Skipped-version receipt.
	Snapshot Snapshot `json:"snapshot"` // Actual captured state, including empty records.
	History  Replay   `json:"history"`  // Actual encoded retained batches.
	Floor    Version  `json:"floor"`    // Cursor used for the retained suffix.
	Stale    *lookup  `json:"stale"`    // Null when no evicted-cursor query was applicable.
}

// overlap preserves actual concurrent receipts and all reads, without selecting a serial explanation.
type overlap struct {
	Case      int          `json:"case"`      // Zero-based request-pair ordinal.
	Initial   [2]int       `json:"initial"`   // Declared initial register values.
	Actions   [2]operation `json:"actions"`   // Actual writer requests.
	Versions  [2]Version   `json:"versions"`  // Requested authority versions.
	Receipts  [2]reply     `json:"receipts"`  // Returned writer receipts after both writers joined.
	Frozen    Snapshot     `json:"frozen"`    // Retained pre-write snapshot after the writes.
	Snapshot  Snapshot     `json:"snapshot"`  // Actual final snapshot.
	History   Replay       `json:"history"`   // Actual complete final history.
	Views     [16]Snapshot `json:"views"`     // Ordered observations during overlap.
	Histories [16]Replay   `json:"histories"` // Corresponding ordered replay observations.
}

// trace serializes actual values into native Go output; the external gate supplies expectations.
func trace(t *testing.T, event string, value any) {
	t.Helper()
	data, err := json.Marshal(struct {
		Model string `json:"model"`
		Event string `json:"event"`
		Value any    `json:"value"`
	}{"storage-commit-v1", event, value})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ASTRA-MODEL %s", data)
}
