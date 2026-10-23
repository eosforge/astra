//go:build !linux

// Keep unsupported deployment-material acquisition explicit instead of silently weakening Linux guarantees.
package admission

import "os"

// Acquire rejects deployment acquisition on platforms outside the supported Go service matrix.
func Acquire(string) (*os.File, error) { return nil, ErrIdentity }
