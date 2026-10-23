// Verify session membership independently of the zero timestamp using explicit logical time.
package web

import (
	"testing"
	"time"
)

// TestSessionEpoch preserves the distinction between an absent entry and a valid zero expiry.
func TestSessionEpoch(t *testing.T) {
	for _, name := range []string{"missing", "present"} {
		t.Run(name, func(t *testing.T) {
			check := counter(t)
			var epoch time.Time
			sessions := sessions{values: make(map[string]time.Time), maximum: 1}
			token, expire, ok := sessions.create(epoch.Add(-8*time.Hour), "")
			check(ok && len(token) == 43 && expire.Equal(epoch), "creation did not preserve the explicit eight-hour lifetime")
			expected := 1
			if name == "missing" {
				sessions.remove(token)
				expected = 0
			}
			value, exists := sessions.get(token, epoch.Add(-time.Nanosecond))
			check(exists == (name == "present") && value.Equal(epoch), "membership was inferred from the zero expiry instead of the stored entry")
			check(len(sessions.values) == expected, "lookup changed live membership before its expiry")
			value, exists = sessions.get(token, epoch)
			check(!exists && value.IsZero() && len(sessions.values) == 0, "the closed expiry boundary retained an authenticated session")
			token, expire, ok = sessions.create(epoch, "")
			check(ok && expire.Equal(epoch.Add(8*time.Hour)), "expiry or missing lookup leaked the session slot")
			value, exists = sessions.get(token, epoch)
			check(exists && value.Equal(expire), "the same session table did not recover after expiry")
		})
	}
}
