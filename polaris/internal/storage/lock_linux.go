//go:build linux

package storage

import (
	"os"

	"golang.org/x/sys/unix"
)

// lock owns the stable adjacent .lock file; never unlink on normal exit, preventing separate processes from locking different inodes.
// path is the database path; returns an exclusive lock handle or unavailable on failure.
func lock(path string) (*os.File, error) {
	// Open/create without following symlinks, with mode 0600.
	file, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, ErrUnavailable
	}
	// Require a regular lock file, not device or directory.
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, ErrUnavailable
	}
	// Nonblocking exclusive lock fails if another process owns it.
	if err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		return nil, ErrUnavailable
	}
	return file, nil
}
