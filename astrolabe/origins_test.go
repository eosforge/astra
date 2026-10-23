// Verify additional browser origins and cancelled preparation without changing the entry's dependencies.
package main

import (
	"context"
	"net"
	"testing"
)

// TestEntryOrigins requires invalid origin lists to fail and a valid list to retain normal cancellation cleanup.
func TestEntryOrigins(t *testing.T) {
	for _, input := range []struct {
		name  string // Independent additional-origin configuration.
		value string // Comma-separated values accepted by the entry options.
		ok    bool   // Whether preparation should reach the cancelled runtime.
	}{
		{"valid", "https://other.example,https://third.example", true},
		{"duplicate", "https://ADMIN.example:443", false},
		{"path", "https://other.example/path", false},
		{"empty", ",", false},
	} {
		t.Run(input.name, func(t *testing.T) {
			check := counter(t)
			config, reserved, _ := deployment(t)
			config.origins = input.value
			check(reserved.Close() == nil, "could not release the reserved listener")
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			err := run(ctx, config)
			check((err == nil) == input.ok, "additional-origin admission or cancellation changed")
			listener, err := net.Listen("tcp", config.listen)
			check(err == nil, "entry retained its listener after origin validation or cancellation")
			check(listener.Close() == nil, "rebound listener did not close")
		})
	}
}
