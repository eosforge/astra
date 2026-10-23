// Verify management configuration rejection and normalized origin boundaries with counted assertions.
package web

import "testing"

// TestVerification uses independently declared HTTP origin and configuration contracts, without credentials or network I/O.
func TestVerification(t *testing.T) {
	hits := 0
	check := func(condition bool) {
		t.Helper()
		if !condition {
			t.Fatal("management boundary contract violated")
		}
		hits++
	}
	t.Cleanup(func() { t.Logf(`ASTRA-CONTRACT {"contract":"ASTROLABE-BOUNDARY","hits":%d}`, hits) })
	for _, input := range []struct{ raw, normalized string }{
		{"https://EXAMPLE.com:443", "https://example.com"},
		{"http://example.com:80", "http://example.com"},
		{"https://[::1]:443", "https://[::1]"},
		{"http://example.com:8080", "http://example.com:8080"},
	} {
		value, err := Origin(input.raw)
		check(err == nil && value == input.normalized)
	}
	for _, input := range []string{"", "ftp://example.com", "https://", "https://user@example.com", "https://example.com/", "https://example.com?", "https://example.com#x", "https://*.example.com", "https://example.com:0", "https://example.com:0443", "https://example.com:65536", "https://example.com:", "null"} {
		_, err := Origin(input)
		check(err != nil)
	}
	account := &Account{}
	backend := &backend{}
	valid := Options{Origins: []string{"https://example.com"}, Sessions: 1, Secure: true}
	configured, err := New(account, backend, valid)
	check(err == nil && configured != nil)
	check(cap(configured.logins) == 4 && cap(configured.requests) == 16 && cap(configured.loads) == 2)
	for _, options := range []Options{
		{Origins: valid.Origins, Sessions: 0},
		{Origins: valid.Origins, Sessions: 4097},
		{Sessions: 1},
		{Origins: []string{"https://example.com", "https://EXAMPLE.com:443"}, Sessions: 1},
		{Origins: []string{"null"}, Sessions: 1},
		{Origins: valid.Origins, Sessions: 1, Crosssite: true},
	} {
		value, err := New(account, backend, options)
		check(err != nil && value == nil)
	}
	value, err := New(nil, backend, valid)
	check(err != nil && value == nil)
	value, err = New(account, nil, valid)
	check(err != nil && value == nil)
}
