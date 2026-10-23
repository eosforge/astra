// Open deployment material without following its final symlink or waiting for a FIFO writer.
package admission

import (
	"os"
	"syscall"
)

// Acquire opens a candidate handle. Callers must verify its type and identity before bounded reads.
// Parent directories remain deployment-owned; this is not a sandbox for untrusted path traversal.
func Acquire(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
