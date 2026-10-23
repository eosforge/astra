// Read Windows interrupt time with suspend compensation, in elapsed milliseconds.
package comet

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// interruptTime uses the Windows 10/Server 2016 API contract; Kernel32 need not export this entry point.
var interruptTime = windows.NewLazySystemDLL("api-ms-win-core-realtime-l1-1-1.dll").NewProc("QueryInterruptTimePrecise")

// leaseNow reports an unavailable API as a clock failure, without a wall-clock fallback.
func leaseNow() (int64, bool) {
	if interruptTime.Find() != nil {
		return 0, false
	}
	var ticks uint64 // The API writes elapsed time in 100-nanosecond units.
	_, _, _ = interruptTime.Call(uintptr(unsafe.Pointer(&ticks)))
	return int64(ticks / 10_000), true
}
