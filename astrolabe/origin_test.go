// Verify public-origin refusal independently of plaintext and deployment limits.
package main

import "testing"

// TestPublicOrigin keeps the permitted loopback plaintext deployment fixed while changing origin syntax.
func TestPublicOrigin(t *testing.T) {
	for _, name := range []string{"valid", "invalid"} {
		t.Run(name, func(t *testing.T) {
			check := counter(t)
			origin := "http://admin.example"
			if name == "invalid" {
				origin += "/path"
			}
			config, err := parse([]string{"--listen=127.0.0.1:8553", "--super=127.0.0.1:8554", "--galaxy=entry", "--account=account.json", "--http", "--public=" + origin})
			check((err == nil) == (name == "valid"), "origin validation was masked by another deployment field")
			if name == "valid" {
				check(config.plain && config.public == origin, "accepted plaintext origin changed its declared boundary")
			}
		})
	}
}
