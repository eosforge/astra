// Verify management routing, access boundaries, and response handling.

package web

import (
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eosforge/astra/internal/generated/comet"
	"github.com/eosforge/astra/internal/generated/polaris"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// backend isolates HTTP behavior; TLS, gRPC and SQLite durability have separate integration tests.
type backend struct {
	calls   atomic.Uint32
	request *polaris.CommitRequest
	failure error
	pages   []*polaris.Snapshot
}

// Commit records the borrowed request and returns its position or the configured backend error.
func (backend *backend) Commit(_ context.Context, request *polaris.CommitRequest) (*polaris.Position, error) {
	backend.calls.Add(1)
	backend.request = request
	if backend.failure != nil {
		return nil, backend.failure
	}
	return &polaris.Position{Scope: request.Scope, Version: request.Version}, nil
}

// List returns an empty complete inventory together with the configured error.
func (backend *backend) List(context.Context) (*polaris.Inventory, error) {
	return &polaris.Inventory{Complete: true}, backend.failure
}

// Load delivers configured pages in order, stopping at a callback error before returning the backend error.
func (backend *backend) Load(_ context.Context, _ *comet.Scope, receive func(*polaris.Snapshot) error) error {
	for _, page := range backend.pages {
		if err := receive(page); err != nil {
			return err
		}
	}
	return backend.failure
}

// Nodes returns a fresh stale-directory fixture.
func (backend *backend) Nodes() any { return map[string]bool{"stale": true} }

// Metrics returns a fresh empty-sample fixture.
func (backend *backend) Metrics() any { return map[string]any{"samples": []any{}} }

// account derives public fixture credentials using the real PBKDF2 implementation and production iteration count.
func account(t *testing.T) *Account {
	t.Helper()
	value := &Account{username: "admin", salt: [16]byte{1, 2, 3}}
	hash, err := pbkdf2.Key(sha256.New, "test-password", value.salt[:], 600000, 32)
	if err != nil {
		t.Fatal(err)
	}
	value.hash = [32]byte(hash)
	return value
}

func server(t *testing.T, backend *backend) *Server {
	t.Helper()
	server, err := New(account(t), backend, Options{Origins: []string{"https://admin.example"}, Secure: true, Sessions: 8})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

// request preserves real header/cookie encoding and the HTTP handler; only socket transport is replaced.
func request(server *Server, method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	input := httptest.NewRequest(method, "https://api.example"+path, strings.NewReader(body))
	input.Header.Set("Origin", "https://admin.example")
	input.Header.Set("Content-Type", "application/json")
	input.Header.Set("X-Astra-Request", "1")
	if cookie != nil {
		input.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, input)
	return response
}

func login(t *testing.T, server *Server) *http.Cookie {
	t.Helper()
	response := request(server, "POST", "/api/session", `{"username":"admin","password":"test-password"}`, nil)
	if response.Code != http.StatusOK || len(response.Result().Cookies()) != 1 {
		t.Fatal("valid login rejected")
	}
	cookie := response.Result().Cookies()[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.Domain != "" || cookie.Path != "/api" || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge <= 0 || cookie.MaxAge > 8*60*60 {
		t.Fatal("invalid cookie boundary")
	}
	if strings.Contains(response.Body.String(), cookie.Value) || strings.Contains(response.Body.String(), "password") {
		t.Fatal("login leaked secret or token")
	}
	return cookie
}

// TestAccount checks credential verification and strict account-file parsing.
func TestAccount(t *testing.T) {
	value := account(t)
	data := `{"username":"admin","salt":"` + hex.EncodeToString(value.salt[:]) + `","hash":"` + hex.EncodeToString(value.hash[:]) + `"}`
	path := filepath.Join(t.TempDir(), "account.json")
	if os.WriteFile(path, []byte(data), 0600) != nil {
		t.Fatal("cannot prepare account fixture")
	}
	loaded, err := LoadAccount(path)
	if err != nil || !loaded.verify("admin", "test-password") || loaded.verify("absent", "test-password") || loaded.verify("admin", "wrong") {
		t.Fatal("account KDF verification failed")
	}
	for _, invalid := range []string{strings.Replace(data, `"username":"admin"`, `"username":"admin","username":"other"`, 1), data + `{}`, strings.Replace(data, `"username":`, `"unknown":`, 1), strings.Repeat("x", 4097)} {
		if os.WriteFile(path, []byte(invalid), 0600) != nil {
			t.Fatal("cannot prepare invalid fixture")
		}
		if _, err := LoadAccount(path); err == nil {
			t.Fatal("invalid account accepted")
		}
	}
}

// TestSessions checks capacity and fixed session expiry without extending the lifetime on reads.
func TestSessions(t *testing.T) {
	sessions := sessions{values: make(map[string]time.Time), maximum: 1}
	now := time.Now()
	token, expire, ok := sessions.create(now, "")
	if !ok || expire.Sub(now) != 8*time.Hour {
		t.Fatal("incorrect fixed lifetime")
	}
	if _, _, ok := sessions.create(now, ""); ok {
		t.Fatal("session capacity bypassed")
	}
	if observed, ok := sessions.get(token, now.Add(7*time.Hour)); !ok || !observed.Equal(expire) {
		t.Fatal("query changed fixed expiry")
	}
	if _, ok := sessions.get(token, expire); ok {
		t.Fatal("expired token accepted")
	}
	if _, _, ok := sessions.create(expire, ""); !ok {
		t.Fatal("expired capacity not reclaimed")
	}
}

// TestSessionReplacement permits replacement only with a current token; unknown tokens cannot evict clients or bypass capacity.
func TestSessionReplacement(t *testing.T) {
	sessions := sessions{values: make(map[string]time.Time), maximum: 1}
	now := time.Now()
	previous, _, ok := sessions.create(now, "")
	if !ok {
		t.Fatal("cannot create initial session")
	}
	if _, _, ok := sessions.create(now, "unknown"); ok {
		t.Fatal("unknown token bypassed capacity")
	}
	current, expire, ok := sessions.create(now.Add(time.Hour), previous)
	if !ok || current == previous || expire.Sub(now) != 9*time.Hour || len(sessions.values) != 1 {
		t.Fatal("full-capacity replacement failed")
	}
	if _, ok := sessions.get(previous, now.Add(time.Hour)); ok {
		t.Fatal("replaced token still accepted")
	}
	if _, ok := sessions.get(current, now.Add(time.Hour)); !ok {
		t.Fatal("replacement token rejected")
	}
}

// TestOrigin checks origin normalization and rejects requests outside the configured origin.
func TestOrigin(t *testing.T) {
	for _, input := range []string{"null", "*", "https://*.example", "https://admin.example/path", "https://user@admin.example", "https://admin.example?x=1", "https://admin.example:0", "https://admin.example:", "file://admin.example"} {
		if _, err := Origin(input); err == nil {
			t.Fatalf("invalid origin accepted: %q", input)
		}
	}
	if origin, err := Origin("https://ADMIN.example:443"); err != nil || origin != "https://admin.example" {
		t.Fatal("default-port origin normalization failed")
	}
	server := server(t, &backend{})
	for _, origin := range []string{"", "null", "https://admin.example.evil", "https://other.example"} {
		input := httptest.NewRequest("POST", "/api/session", strings.NewReader(`{}`))
		if origin != "" {
			input.Header.Set("Origin", origin)
		}
		input.Header.Set("X-Astra-Request", "1")
		response := httptest.NewRecorder()
		server.ServeHTTP(response, input)
		if response.Code != http.StatusForbidden {
			t.Fatal("untrusted write origin accepted")
		}
	}
	input := httptest.NewRequest("OPTIONS", "/api/almanac", nil)
	input.Header.Set("Origin", "https://admin.example")
	input.Header.Set("Access-Control-Request-Method", "POST")
	input.Header.Set("Access-Control-Request-Headers", "content-type,x-astra-request")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, input)
	if response.Code != http.StatusNoContent || response.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatal("valid unauthenticated preflight failed")
	}
	input.Header.Set("Access-Control-Request-Headers", "authorization")
	response = httptest.NewRecorder()
	server.ServeHTTP(response, input)
	if response.Code != http.StatusForbidden {
		t.Fatal("unknown preflight header accepted")
	}
}

// TestLogin checks authentication failures, session queries, and idempotent logout.
func TestLogin(t *testing.T) {
	server := server(t, &backend{})
	for _, body := range []string{`{"username":"admin","password":"wrong"}`, `{"username":"other","password":"test-password"}`} {
		response := request(server, "POST", "/api/session", body, nil)
		if response.Code != http.StatusUnauthorized || response.Header().Get("Access-Control-Allow-Origin") != "https://admin.example" {
			t.Fatal("login rejection lost status or CORS")
		}
	}
	cookie := login(t, server)
	if request(server, "GET", "/api/session", "", cookie).Code != http.StatusOK {
		t.Fatal("session query failed")
	}
	for range 2 {
		response := request(server, "DELETE", "/api/session", "", cookie)
		if response.Code != http.StatusNoContent || response.Result().Cookies()[0].MaxAge != -1 {
			t.Fatal("logout is not idempotent")
		}
	}
	if request(server, "GET", "/api/nodes", "", cookie).Code != http.StatusUnauthorized {
		t.Fatal("revoked cookie still authorized")
	}
	for range cap(server.logins) {
		server.logins <- struct{}{}
	}
	if request(server, "POST", "/api/session", `{"username":"admin","password":"test-password"}`, nil).Code != http.StatusTooManyRequests {
		t.Fatal("login admission exceeded KDF slots")
	}
}

// TestCommit preserves uint64 versions, empty values, commit status, and safe backend error responses.
func TestCommit(t *testing.T) {
	backend := &backend{}
	server := server(t, backend)
	cookie := login(t, server)
	body := `{"sector":"routes","spectrum":"main","version":"18446744073709551615","key":"key","value":""}`
	response := request(server, "POST", "/api/almanac", body, cookie)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"18446744073709551615"`) || !strings.Contains(response.Body.String(), `"committed"`) || backend.calls.Load() != 1 {
		t.Fatal("durable response or uint64 precision lost")
	}
	if _, ok := backend.request.Change.Action.(*comet.AlmanacChange_Value); !ok {
		t.Fatal("empty value became erase")
	}
	backend.failure = status.Error(codes.Unknown, "deliberate sensitive backend text")
	response = request(server, "POST", "/api/almanac", body, cookie)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"unknown"`) || strings.Contains(response.Body.String(), "sensitive") || backend.calls.Load() != 2 {
		t.Fatal("uncertain write was retried or leaked backend text")
	}
	backend.failure = status.Error(codes.Aborted, "version conflict")
	response = request(server, "POST", "/api/almanac", body, cookie)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"unapplied"`) {
		t.Fatal("version rejection lost definite effect")
	}
	count := backend.calls.Load()
	for _, invalid := range []string{strings.Replace(body, `"value":""`, `"value":"","erase":true`, 1), strings.Replace(body, `"key":"key"`, `"key":"key","key":"other"`, 1), strings.Replace(body, `"18446744073709551615"`, `"01"`, 1), body + `{}`} {
		if request(server, "POST", "/api/almanac", invalid, cookie).Code != http.StatusBadRequest {
			t.Fatal("ambiguous request accepted")
		}
	}
	if backend.calls.Load() != count {
		t.Fatal("invalid request reached authority")
	}
}

// TestSnapshot emits completion only after the backend stream succeeds and reports late failure as incomplete.
func TestSnapshot(t *testing.T) {
	scope := &comet.Scope{Sector: []byte("routes"), Spectrum: []byte("main")}
	backend := &backend{pages: []*polaris.Snapshot{{Scope: scope, Version: proto.Uint64(7), Entries: []*comet.AlmanacChange{{Key: "key", Action: &comet.AlmanacChange_Value{Value: []byte{}}}}}, {Scope: scope, Version: proto.Uint64(7), Complete: true}}}
	server := server(t, backend)
	cookie := login(t, server)
	response := request(server, "GET", "/api/almanac?sector=routes&spectrum=main", "", cookie)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"value":""`) || !strings.Contains(response.Body.String(), `"complete":true`) || !strings.Contains(response.Body.String(), `"version":"7"`) {
		t.Fatal("complete snapshot was not emitted")
	}
	backend.failure = errors.New("deliberate late stream failure")
	response = request(server, "GET", "/api/almanac?sector=routes&spectrum=main", "", cookie)
	if strings.Contains(response.Body.String(), `"complete":true`) || !strings.Contains(response.Body.String(), `"complete":false`) {
		t.Fatal("complete marker preceded successful gRPC EOF")
	}
	backend.failure = nil
	backend.pages[1].Version = proto.Uint64(8)
	response = request(server, "GET", "/api/almanac?sector=routes&spectrum=main", "", cookie)
	if strings.Contains(response.Body.String(), `"complete":true`) || !strings.Contains(response.Body.String(), `"protocol"`) {
		t.Fatal("mixed snapshot versions accepted")
	}
	for _, query := range []string{"?sector=%FF&spectrum=main", "?sector=routes", "?sector=routes&sector=other&spectrum=main", "?x=%ZZ"} {
		if request(server, "GET", "/api/almanac"+query, "", cookie).Code != http.StatusBadRequest {
			t.Fatal("invalid query became a full inventory request")
		}
	}
}

// TestHTTPS exercises HTTPS and cookies with trust restricted to the fixture certificate, without changing system roots.
func TestHTTPS(t *testing.T) {
	server := server(t, &backend{})
	https := httptest.NewTLSServer(server)
	defer https.Close()
	input, err := http.NewRequest("POST", https.URL+"/api/session", strings.NewReader(`{"username":"admin","password":"test-password"}`))
	if err != nil {
		t.Fatal(err)
	}
	input.Header.Set("Origin", "https://admin.example")
	input.Header.Set("Content-Type", "application/json")
	input.Header.Set("X-Astra-Request", "1")
	response, err := https.Client().Do(input)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || len(response.Cookies()) != 1 || !response.Cookies()[0].Secure || !json.Valid(data) {
		t.Fatal("real HTTPS login failed")
	}
}
