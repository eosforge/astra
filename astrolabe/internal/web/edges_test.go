// Verify management rejection, session ownership and exact value limits without changing production policy.
package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eosforge/astra/internal/generated/comet"
)

// TestSessionInput requires malformed credentials to fail before acquiring an occupied KDF permit.
func TestSessionInput(t *testing.T) {
	for _, input := range []struct {
		name string // Independently malformed authentication input.
		body string // Public request bytes, never a production credential.
	}{
		{"json", `{`}, {"unknown", `{"username":"admin","password":"test","other":1}`},
		{"username-empty", `{"username":"","password":"test"}`},
		{"username-overflow", `{"username":"` + strings.Repeat("a", 65) + `","password":"test"}`},
		{"password-empty", `{"username":"admin","password":""}`},
		{"password-overflow", `{"username":"admin","password":"` + strings.Repeat("a", 1025) + `"}`},
		{"body-overflow", strings.Repeat(" ", 4096) + `{}`},
	} {
		t.Run(input.name, func(t *testing.T) {
			check := counter(t)
			target := &backend{}
			server, _ := fixture(t, target)
			before := maps.Clone(server.sessions.values)
			for range cap(server.logins) {
				server.logins <- struct{}{}
			}
			response := request(server, "POST", "/api/session", input.body, nil)
			check(response.Code == http.StatusBadRequest && strings.Contains(response.Body.String(), `"effect":"unapplied"`), "malformed login reached KDF admission")
			check(maps.Equal(before, server.sessions.values) && len(response.Result().Cookies()) == 0, "rejected login changed an existing session")
			check(target.calls.Load() == 0 && len(server.requests) == 0 && len(server.logins) == cap(server.logins), "input refusal leaked or consumed unrelated ownership")
			for range cap(server.logins) {
				<-server.logins
			}
		})
	}
}

// TestSessionAdmission retains the real password derivation while isolating cancellation and full capacity.
func TestSessionAdmission(t *testing.T) {
	identity := account(t)
	for _, name := range []string{"cancelled", "capacity", "absent", "expired"} {
		t.Run(name, func(t *testing.T) {
			check := counter(t)
			target := &backend{}
			server, cookie := fixture(t, target)
			server.account = identity
			server.sessions.maximum = 1
			if name == "expired" {
				server.sessions.values[cookie.Value] = time.Unix(1, 0)
			}
			before := maps.Clone(server.sessions.values)
			value := httptest.NewRequest("POST", "/api/session", strings.NewReader(`{"username":"admin","password":"test-password"}`))
			value.Header.Set("Origin", "https://admin.example")
			value.Header.Set("Content-Type", "application/json")
			value.Header.Set("X-Astra-Request", "1")
			if name == "cancelled" {
				ctx, cancel := context.WithCancel(value.Context())
				cancel()
				value = value.WithContext(ctx)
			} else if name == "absent" || name == "expired" {
				value.Method = "GET"
				if name == "expired" {
					value.AddCookie(cookie)
				}
			}
			response := httptest.NewRecorder()
			server.ServeHTTP(response, value)
			switch name {
			case "cancelled":
				check(response.Body.Len() == 0, "cancelled login published a success or failure response")
			case "capacity":
				check(response.Code == http.StatusTooManyRequests && strings.Contains(response.Body.String(), `"effect":"unapplied"`), "full session table admitted another browser")
			case "absent", "expired":
				check(response.Code == http.StatusUnauthorized && strings.Contains(response.Body.String(), `"error":"session"`), "invalid session query claimed authentication")
			}
			if name == "expired" {
				check(len(server.sessions.values) == 0, "expired session was retained after query")
			} else {
				check(maps.Equal(before, server.sessions.values), "refused request changed another browser's session")
			}
			check(len(response.Result().Cookies()) == 0 && target.calls.Load() == 0, "refused authentication issued a cookie or called the backend")
			check(len(server.logins) == 0 && len(server.requests) == 0, "authentication did not return its permits")
		})
	}
}

// TestSessionExpiry uses explicit time to distinguish a live slot from expiration at the exact boundary.
func TestSessionExpiry(t *testing.T) {
	for _, name := range []string{"before", "exact", "after", "expired-replacement"} {
		t.Run(name, func(t *testing.T) {
			check := counter(t)
			expire := time.Unix(100000, 0)
			now := expire
			previous := ""
			if name == "before" {
				now = expire.Add(-time.Nanosecond)
			} else if name == "after" {
				now = expire.Add(time.Nanosecond)
			} else if name == "expired-replacement" {
				previous = "old"
			}
			values := sessions{values: map[string]time.Time{"old": expire}, maximum: 1}
			token, until, ok := values.create(now, previous)
			check(ok == (name != "before") && len(values.values) == 1, "session expiration or capacity boundary changed")
			if ok {
				check(len(token) == 43 && token != "old" && until.Equal(now.Add(8*time.Hour)), "new session lost its fixed lifetime")
				check(values.values[token].Equal(until) && values.values["old"].IsZero(), "expired slot was not atomically replaced")
			} else {
				check(token == "" && until.IsZero() && values.values["old"].Equal(expire), "refusal damaged the still-live session")
			}
		})
	}
}

// TestValueBoundary verifies decoded per-value limits and whole-batch refusal before any prefix is sent.
func TestValueBoundary(t *testing.T) {
	for _, batch := range []bool{false, true} {
		for _, input := range []struct {
			name string // Canonical wire boundary.
			data string // Exact Base64 input.
			size int    // Expected decoded length; negative means refusal.
		}{
			{"empty", "", 0}, {"byte", "AA==", 1}, {"encoding", "!", -1}, {"padding", "AB==", -1},
			{"limit", base64.StdEncoding.EncodeToString(make([]byte, 1<<20)), 1 << 20},
			{"overflow", base64.StdEncoding.EncodeToString(make([]byte, (1<<20)+1)), -1},
		} {
			name := "single/" + input.name
			if batch {
				name = "batch/" + input.name
			}
			t.Run(name, func(t *testing.T) {
				check := counter(t)
				target := &backend{}
				server, cookie := fixture(t, target)
				body := map[string]any{"sector": "routes", "spectrum": "main", "version": "7"}
				if batch {
					body["changes"] = []map[string]string{{"key": "before", "value": ""}, {"key": "a", "value": input.data}}
				} else {
					body["key"], body["value"] = "a", input.data
				}
				data, err := json.Marshal(body)
				check(err == nil, "could not prepare value fixture")
				response := request(server, "POST", "/api/almanac", string(data), cookie)
				if input.size < 0 {
					check(response.Code == http.StatusBadRequest && target.calls.Load() == 0 && target.request == nil, "malformed value published a scalar or batch prefix")
					check(strings.Contains(response.Body.String(), `"effect":"unapplied"`), "input refusal lost its effect")
					response = request(server, "POST", "/api/almanac", `{"sector":"routes","spectrum":"main","version":"7","key":"next","value":""}`, cookie)
					check(response.Code == http.StatusOK && target.calls.Load() == 1 && target.request.Change.Key == "next", "refused value prevented a subsequent legal request")
				} else {
					check(response.Code == http.StatusOK && target.calls.Load() == 1, "legal value was rejected or split")
					change := target.request.Change
					if batch {
						check(change == nil && len(target.request.Changes) == 2 && target.request.Changes[0].Key == "before", "batch shape or prefix changed")
						change = target.request.Changes[1]
					}
					value, ok := change.Action.(*comet.AlmanacChange_Value)
					check(change.Key == "a" && ok && bytes.Equal(value.Value, make([]byte, input.size)), "decoded value or empty-value action changed")
					check(target.request.Version == 7 && string(target.request.Scope.Sector) == "routes" && string(target.request.Scope.Spectrum) == "main", "request scope or version changed")
				}
				check(len(server.requests) == 0 && len(server.loads) == 0, "value handling retained an admission permit")
			})
		}
	}
}

// TestOriginLimit checks the inclusive configuration limit before any listening socket exists.
func TestOriginLimit(t *testing.T) {
	for _, count := range []int{31, 32, 33} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			check := counter(t)
			origins := make([]string, count)
			for index := range origins {
				origins[index] = fmt.Sprintf("https://host%d.example", index)
			}
			server, err := New(&Account{}, &backend{}, Options{Origins: origins, Sessions: 4096, Secure: true})
			if count > 32 {
				check(err != nil && server == nil, "origin overflow produced a usable handler")
			} else {
				check(err == nil && len(server.origins) == count && server.sessions.maximum == 4096, "legal origin or session capacity was changed")
			}
		})
	}
}
