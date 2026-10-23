// Read Linux boot time, including suspend, without consulting a remote clock.
package comet

import "golang.org/x/sys/unix"

// leaseNow returns elapsed milliseconds, rejecting unavailable or malformed time.
func leaseNow() (int64, bool) {
	var stamp unix.Timespec // Kernel-owned result, validated before arithmetic.
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &stamp) != nil {
		return 0, false
	}
	seconds, nanos := int64(stamp.Sec), int64(stamp.Nsec)
	if seconds < 0 || nanos < 0 || nanos >= 1_000_000_000 || seconds > (int64(^uint64(0)>>1)-999)/1000 {
		return 0, false
	}
	return seconds*1000 + nanos/1_000_000, true
}
