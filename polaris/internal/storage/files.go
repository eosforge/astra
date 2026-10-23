// Keep initialization file operations behind a per-opening boundary, without shared mutable hooks.

package storage

import "os"

// handle owns the only file operations required before an initialized database is exposed.
type handle interface {
	Close() error
	Sync() error
}

// filesystem creates one owned file or directory handle with the requested native flags and permissions.
type filesystem interface {
	open(string, int, os.FileMode) (handle, error)
}

// system delegates initialization to the standard library; it owns no mutable state.
type system struct{}

// open preserves the native acquisition error and transfers each successful descriptor to its caller.
func (system) open(path string, flags int, mode os.FileMode) (handle, error) {
	return os.OpenFile(path, flags, mode)
}
