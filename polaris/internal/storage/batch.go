// Prepare multi-key authority mutations and validate their atomic commit boundaries.

package storage

import (
	"context"
	"encoding/binary"
)

// CommitBatch updates unique Keys in one Scope transaction and advances version once.
// Empty history Key denotes AB02 batch encoding with uint64 count and no separate whole-batch cap; older binaries reject instead of replaying per Key.
func (store *Store) CommitBatch(ctx context.Context, scope Scope, version Version, changes []Change) (Version, error) {
	if len(changes) == 0 {
		return 0, ErrInput
	}
	data := []byte("AB02")
	data = binary.BigEndian.AppendUint64(data, uint64(len(changes)))
	seen := make(map[string]bool, len(changes))
	for _, change := range changes {
		if !validChange(change) || seen[change.Key] || change.Version != 0 && change.Version != version {
			return 0, ErrInput
		}
		seen[change.Key] = true
		data = binary.BigEndian.AppendUint16(data, uint16(len(change.Key)))
		data = binary.BigEndian.AppendUint32(data, uint32(len(change.Value)))
		data = append(data, byte(boolint(change.Erase)))
		data = append(data, change.Key...)
		data = append(data, change.Value...)
	}
	return store.commit(ctx, scope, Change{Version: version, Value: data})
}

// validChange omits outer authority-version validation; the batch has one shared version.
func validChange(change Change) bool {
	return text(change.Key, 1024) && len(change.Value) <= 1<<20 && (!change.Erase || len(change.Value) == 0)
}

// Entries decodes one complete commit, borrowing immutable history payload without copying; malformed encoding returns no partial result.
func (change Change) Entries() ([]Change, error) {
	if change.Key != "" {
		if !validChange(change) {
			return nil, ErrInput
		}
		return []Change{change}, nil
	}
	data := change.Value
	if change.Erase || len(data) < 12 || string(data[:4]) != "AB02" {
		return nil, ErrInput
	}
	count := binary.BigEndian.Uint64(data[4:12])
	data = data[12:]
	// Each item needs at least seven header bytes and one Key byte; validate actual input before int conversion/allocation.
	if count == 0 || count > uint64(len(data)/8) {
		return nil, ErrInput
	}
	entries := make([]Change, 0, int(count))
	seen := make(map[string]bool, int(count))
	for range count {
		if len(data) < 7 {
			return nil, ErrInput
		}
		key, length, erase := int(binary.BigEndian.Uint16(data[:2])), binary.BigEndian.Uint32(data[2:6]), data[6]
		data = data[7:]
		if key > len(data) || uint64(length) > uint64(len(data)-key) || erase > 1 {
			return nil, ErrInput
		}
		value := int(length) // Compare with the bounded input buffer before length conversion to avoid 32-bit overflow.
		entry := Change{Version: change.Version, Key: string(data[:key]), Value: data[key : key+value], Erase: erase == 1}
		if !validChange(entry) || seen[entry.Key] {
			return nil, ErrInput
		}
		seen[entry.Key] = true
		entries = append(entries, entry)
		data = data[key+value:]
	}
	if len(data) != 0 {
		return nil, ErrInput
	}
	return entries, nil
}
