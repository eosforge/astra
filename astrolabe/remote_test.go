// Verify the management listener's transport requirement independently of its address.
package main

import "testing"

// TestRemote keeps a valid non-loopback address fixed while changing only plaintext permission.
func TestRemote(t *testing.T) {
	for _, name := range []string{"tls", "plain"} {
		t.Run(name, func(t *testing.T) {
			check := counter(t)
			args := []string{"--listen=192.0.2.1:8553", "--super=127.0.0.1:8554", "--galaxy=entry", "--account=account.json", "--public=https://admin.example"}
			if name == "plain" {
				args = append(args, "--http")
			}
			config, err := parse(args)
			check((err == nil) == (name == "tls"), "non-loopback management changed its transport requirement")
			if err == nil {
				check(config.listen == "192.0.2.1:8553" && !config.plain, "accepted listener lost its explicit TLS identity")
			}
		})
	}
}
