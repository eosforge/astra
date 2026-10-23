// Verify individual HTTP input refusals without a partial backend write or lost request capacity.
package web

import (
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"strings"
	"testing"
)

// TestRefusal isolates each rejected field and then commits a healthy request through the same server.
func TestRefusal(t *testing.T) {
	const single = `{"sector":"routes","spectrum":"main","version":"1","key":"a","value":""}`
	const batch = `{"sector":"routes","spectrum":"main","version":"1","changes":[{"key":"a","value":""}]}`
	const credential = `{"key":"application","secret":"AA==","version":"1"}`
	for _, input := range []struct {
		name   string // Stable rejection scenario.
		method string // Actual HTTP method, including read-only validation.
		path   string // Public management route.
		body   string // Independently malformed input.
		reason string // Stable error category required by the route contract.
	}{
		{"query-spectrum-duplicate", "GET", "/api/almanac?sector=routes&spectrum=main&spectrum=other", "", "input"},
		{"query-spectrum-empty", "GET", "/api/almanac?sector=routes&spectrum=", "", "input"},
		{"query-spectrum-overflow", "GET", "/api/almanac?sector=routes&spectrum=" + strings.Repeat("a", 129), "", "input"},
		{"sector-empty", "POST", "/api/almanac", strings.Replace(single, `"sector":"routes"`, `"sector":""`, 1), "input"},
		{"spectrum-empty", "POST", "/api/almanac", strings.Replace(single, `"spectrum":"main"`, `"spectrum":""`, 1), "input"},
		{"batch-value", "POST", "/api/almanac", strings.Replace(batch, `"changes":`, `"value":"","changes":`, 1), "input"},
		{"batch-erase", "POST", "/api/almanac", strings.Replace(batch, `"changes":`, `"erase":true,"changes":`, 1), "input"},
		{"key-empty", "POST", "/api/almanac", strings.Replace(single, `"key":"a"`, `"key":""`, 1), "input"},
		{"erase-false", "POST", "/api/almanac", strings.Replace(single, `"value":""`, `"erase":false`, 1), "input"},
		{"version-invalid", "POST", "/api/almanac", strings.Replace(single, `"version":"1"`, `"version":"invalid"`, 1), "version"},
		{"version-zero", "POST", "/api/almanac", strings.Replace(single, `"version":"1"`, `"version":"0"`, 1), "version"},
		{"credential-key-empty", "POST", "/api/credentials", strings.Replace(credential, `"key":"application"`, `"key":""`, 1), "input"},
		{"credential-version-invalid", "POST", "/api/credentials", strings.Replace(credential, `"version":"1"`, `"version":"invalid"`, 1), "version"},
		{"credential-version-zero", "POST", "/api/credentials", strings.Replace(credential, `"version":"1"`, `"version":"0"`, 1), "version"},
		{"credential-secret-overflow", "POST", "/api/credentials", strings.Replace(credential, "AA==", base64.StdEncoding.EncodeToString(make([]byte, 4097)), 1), "input"},
	} {
		t.Run(input.name, func(t *testing.T) {
			check := counter(t)
			target := &backend{}
			server, cookie := fixture(t, target)
			before := maps.Clone(server.sessions.values)
			response := request(server, input.method, input.path, input.body, cookie)
			var result struct {
				Error  string `json:"error"`  // Public failure category.
				Effect string `json:"effect"` // No write may have reached the authority.
			}
			check(response.Code == http.StatusBadRequest, "invalid input did not receive a stable refusal")
			check(json.Unmarshal(response.Body.Bytes(), &result) == nil && result.Error == input.reason && result.Effect == "unapplied", "refusal changed its category or claimed a possible write")
			check(target.calls.Load() == 0 && target.request == nil, "refused request sent a transaction or prefix")
			check(len(server.requests) == 0 && len(server.logins) == 0 && maps.Equal(before, server.sessions.values), "refusal lost capacity or changed the existing session")
			response = request(server, "POST", "/api/almanac", single, cookie)
			check(response.Code == http.StatusOK && target.calls.Load() == 1, "healthy request did not recover exactly once")
			check(target.request != nil && target.request.Version == 1 && target.request.Change.GetKey() == "a" && len(target.request.Changes) == 0, "recovery forwarded the wrong transaction")
			check(len(server.requests) == 0 && maps.Equal(before, server.sessions.values), "recovery retained a permit or changed the session")
		})
	}
}
