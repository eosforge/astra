//go:build !linux && !windows

// Reject lease creation on platforms outside the Windows/Linux support boundary.
package comet

// leaseNow deliberately provides no wall-clock substitute for lease accounting.
func leaseNow() (int64, bool) { return 0, false }
