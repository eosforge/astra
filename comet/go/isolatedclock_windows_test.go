// Verify Windows API absence without changing host clocks or installing any provider.
package comet

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestIsolatedClockFailure keeps registration, update and renewal unconfirmed when the API fails.
func TestIsolatedClockFailure(t *testing.T) {
	previous := interruptTime
	interruptTime = windows.NewLazySystemDLL("kernel32.dll").NewProc("AstraUnitMissingInterruptTime")
	defer func() { interruptTime = previous }()
	if _, valid := leaseNow(); valid {
		t.Fatal("absent clock API produced a valid reading")
	}
	client := isolatedClient(t)
	selected := isolatedRPC(t, client, func(string, any, any) error { t.Fatal("clock failure performed RPC"); return nil })
	beacon := isolatedBeacon(t, client, selected)
	reserved := int64(0)
	isolatedCode(t, beacon.create(context.Background(), selected, 1, &reserved), CodeClock)
	_, cause := beacon.Update(context.Background(), []byte("new"))
	isolatedCode(t, cause, CodeClock)
	beacon.advance()
	isolatedCode(t, beacon.State().Error, CodeClock)
	beacon.renew(context.Background(), selected, 2)
	if beacon.lease.known || beacon.data.String() != "confirmed" {
		t.Fatal("clock failure confirmed a lease or replaced recovery data")
	}
}

// TestIsolatedRestoreClock applies retry backoff to a pre-send recovery failure.
func TestIsolatedRestoreClock(t *testing.T) {
	previous := interruptTime
	interruptTime = windows.NewLazySystemDLL("kernel32.dll").NewProc("AstraUnitMissingInterruptTime")
	defer func() { interruptTime = previous }()
	client := isolatedClient(t)
	selected := isolatedRPC(t, client, func(string, any, any) error { t.Fatal("clock-failed restoration performed RPC"); return nil })
	beacon := isolatedBeacon(t, client, selected)
	beacon.mu.Lock()
	beacon.launchLocked(selected, true)
	quiet := beacon.quiet
	beacon.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if cause := waitDone(ctx, quiet); cause != nil {
		t.Fatal(cause)
	}
	beacon.mu.Lock()
	defer beacon.mu.Unlock()
	isolatedCode(t, beacon.state.Error, CodeClock)
	if beacon.retry.IsZero() || beacon.failures != 1 || beacon.data.String() != "confirmed" {
		t.Fatal("pre-send failure lost backoff or confirmed data")
	}
}
