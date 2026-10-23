// Verify management admission, CORS preflight and explicit backend error effects independently of password work.
package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fixture installs a known live session for post-login boundaries; existing login tests exercise the real KDF.
func fixture(t *testing.T, target Backend) (*Server, *http.Cookie) {
	t.Helper()
	server, err := New(&Account{username: "admin"}, target, Options{Origins: []string{"https://admin.example"}, Secure: true, Sessions: 8})
	if err != nil {
		t.Fatal(err)
	}
	value := strings.Repeat("a", 43)
	server.sessions.values[value] = time.Now().Add(time.Hour)
	return server, &http.Cookie{Name: "astra-session", Value: value}
}

// TestRouting checks that refusal cannot consume a backend request or leave an admission permit occupied.
func TestRouting(t *testing.T) {
	for _, input := range []struct {
		name string // Isolated routing or browser admission boundary.
		code int    // Exact independently required HTTP status.
	}{
		{"nodes", 200}, {"metrics", 200}, {"no-origin", 200}, {"missing-session", 401},
		{"duplicate-cookie", 401}, {"short-cookie", 401}, {"expired", 401}, {"head", 405},
		{"unknown", 404}, {"origin", 403}, {"origin-syntax", 403}, {"duplicate-origin", 403},
		{"write-origin", 403}, {"write-header", 403}, {"write-duplicate", 403}, {"write-value", 403},
		{"busy", 429}, {"session-method", 405}, {"almanac-method", 405},
		{"credentials-method", 405}, {"credentials-query", 400},
	} {
		t.Run(input.name, func(t *testing.T) {
			check := counter(t)
			backend := &backend{}
			server, cookie := fixture(t, backend)
			value := httptest.NewRequest("GET", "/api/nodes", nil)
			value.Header.Set("Origin", "https://admin.example")
			value.Header.Set("X-Astra-Request", "1")
			value.AddCookie(cookie)
			switch input.name {
			case "metrics":
				value.URL.Path = "/api/metrics"
			case "no-origin":
				value.Header.Del("Origin")
			case "missing-session":
				value.Header.Del("Cookie")
			case "duplicate-cookie":
				value.AddCookie(cookie)
			case "short-cookie":
				value.Header.Set("Cookie", "astra-session=short")
			case "expired":
				server.sessions.values[cookie.Value] = time.Now().Add(-time.Second)
			case "head":
				value.Method = "HEAD"
			case "unknown":
				value.URL.Path = "/api/unknown"
			case "origin":
				value.Header.Set("Origin", "https://other.example")
			case "origin-syntax":
				value.Header.Set("Origin", "://")
			case "duplicate-origin":
				value.Header.Add("Origin", "https://admin.example")
			case "write-origin", "write-header", "write-duplicate", "write-value":
				value.Method = "POST"
				switch input.name {
				case "write-origin":
					value.Header.Del("Origin")
				case "write-header":
					value.Header.Del("X-Astra-Request")
				case "write-duplicate":
					value.Header.Add("X-Astra-Request", "1")
				case "write-value":
					value.Header.Set("X-Astra-Request", "0")
				}
			case "busy":
				for range cap(server.requests) {
					server.requests <- struct{}{}
				}
			case "session-method", "almanac-method", "credentials-method":
				value.Method = "PUT"
				value.URL.Path = "/api/" + strings.TrimSuffix(input.name, "-method")
			case "credentials-query":
				value.URL.Path, value.URL.RawQuery = "/api/credentials", "sector=foreign"
			}
			before := len(server.requests)
			response := httptest.NewRecorder()
			server.ServeHTTP(response, value)
			check(response.Code == input.code, "routing returned an unexpected status")
			check(backend.calls.Load() == 0 && len(server.requests) == before, "non-mutating route wrote or leaked a permit")
			check(response.Header().Get("Cache-Control") == "no-store" && response.Header().Get("X-Content-Type-Options") == "nosniff", "security headers missing on a response")
			check(!strings.Contains(response.Body.String(), cookie.Value), "response exposed its session token")
		})
	}
}

// TestPreflight admits only the explicit method/header vocabulary and never needs a session.
func TestPreflight(t *testing.T) {
	for _, input := range []struct {
		name    string // Stable preflight scenario.
		method  string // Requested method header, independent of the outer OPTIONS method.
		headers string // Requested non-simple header names.
		ok      bool   // Whether the unauthenticated preflight is allowed.
	}{
		{"get", "GET", "", true}, {"post", "POST", "content-type,x-astra-request", true},
		{"delete", "DELETE", " CONTENT-TYPE , X-Astra-Request ", true}, {"empty-fields", "GET", ",,", true},
		{"missing-method", "", "", false}, {"unknown-method", "PATCH", "", false},
		{"duplicate-method", "GET", "", false}, {"header", "GET", "authorization", false},
		{"missing-origin", "GET", "", false},
	} {
		t.Run(input.name, func(t *testing.T) {
			check := counter(t)
			server, _ := fixture(t, &backend{})
			value := httptest.NewRequest("OPTIONS", "/api/almanac", nil)
			value.Header.Set("Origin", "https://admin.example")
			if input.method != "" {
				value.Header.Set("Access-Control-Request-Method", input.method)
			}
			value.Header.Set("Access-Control-Request-Headers", input.headers)
			if input.name == "duplicate-method" {
				value.Header.Add("Access-Control-Request-Method", input.method)
			} else if input.name == "missing-origin" {
				value.Header.Del("Origin")
			}
			response := httptest.NewRecorder()
			server.ServeHTTP(response, value)
			code := 403
			if input.ok {
				code = 204
				check(response.Header().Get("Access-Control-Allow-Methods") == "GET, POST, DELETE" && response.Header().Get("Access-Control-Allow-Headers") == "Content-Type, X-Astra-Request", "preflight widened its allowlist")
			}
			check(response.Code == code && len(server.requests) == 0 && len(server.logins) == 0, "preflight lost its status or consumed application admission")
		})
	}
}

// TestFailure keeps retry ambiguity and error redaction explicit for every documented backend error class.
func TestFailure(t *testing.T) {
	for _, input := range []struct {
		name   string // Public error class, not the backend's sensitive message.
		err    error  // Native wrapped or gRPC status returned by a backend.
		code   int    // Exact HTTP status.
		reason string // Stable public reason.
		known  bool   // Whether a write is proven unapplied by the error contract.
	}{
		{"deadline", context.DeadlineExceeded, 504, "timeout", false},
		{"wrapped", fmt.Errorf("private: %w", context.DeadlineExceeded), 504, "timeout", false},
		{"invalid", status.Error(codes.InvalidArgument, "private"), 400, "input", true},
		{"aborted", status.Error(codes.Aborted, "private"), 409, "version", true},
		{"range", status.Error(codes.OutOfRange, "private"), 409, "history", true},
		{"capacity", status.Error(codes.ResourceExhausted, "private"), 429, "capacity", true},
		{"unauthenticated", status.Error(codes.Unauthenticated, "private"), 503, "backend_identity", true},
		{"permission", status.Error(codes.PermissionDenied, "private"), 503, "backend_identity", true},
		{"rpc-deadline", status.Error(codes.DeadlineExceeded, "private"), 504, "timeout", false},
		{"rpc-cancel", status.Error(codes.Canceled, "private"), 503, "backend", false},
		{"cancel", context.Canceled, 503, "backend", false},
		{"unknown", errors.New("private"), 503, "backend", false},
		{"nil", nil, 503, "backend", false},
	} {
		for _, writing := range []bool{false, true} {
			mode := "read"
			if writing {
				mode = "write"
			}
			t.Run(input.name+"-"+mode, func(t *testing.T) {
				check := counter(t)
				code, reason, effect := failure(input.err, writing)
				expected := "unapplied"
				if writing && !input.known {
					expected = "unknown"
				}
				check(code == input.code && reason == input.reason && effect == expected, "backend failure changed status, exposed text or claimed a known write result")
			})
		}
	}
}
