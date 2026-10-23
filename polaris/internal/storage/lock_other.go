//go:build !linux

package storage

import "os"

// Initial service support is Linux; other systems must not silently drop process exclusivity.
// Unsupported-platform calls return unavailable without a weaker lock fallback.
func lock(string) (*os.File, error) { return nil, ErrUnavailable }
