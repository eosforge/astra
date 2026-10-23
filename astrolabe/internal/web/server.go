// Own management HTTP routing, security checks, and listener lifecycle.

package web

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/eosforge/astra/internal/generated/comet"
	"github.com/eosforge/astra/internal/generated/polaris"
)

// Backend's production implementation calls Polaris directly; HTTP fixtures do not replace cross-process durability acceptance.
type Backend interface {
	Commit(context.Context, *polaris.CommitRequest) (*polaris.Position, error)
	List(context.Context) (*polaris.Inventory, error)
	Load(context.Context, *comet.Scope, func(*polaris.Snapshot) error) error
	Nodes() any
	Metrics() any
}

// Options fixes browser policy and capacity at startup; untrusted Host or Forwarded headers never define allowed origins.
type Options struct {
	Origins   []string // One to 32 explicit origins, normalized and deduplicated at startup.
	Secure    bool     // Controls the cookie's Secure attribute.
	Crosssite bool     // Cross-site cookies require HTTPS.
	Sessions  int      // Session capacity, 1..4096.
}

// Server owns no database or persistent queue; KDF, authenticated requests and snapshot loads have separate concurrency limits.
type Server struct {
	account   *Account
	backend   Backend
	origins   map[string]bool
	secure    bool
	crosssite bool
	sessions  sessions      // Process-local sessions with a fixed eight-hour lifetime.
	logins    chan struct{} // Four concurrent KDF operations, separate from ordinary requests.
	requests  chan struct{} // Sixteen concurrent authenticated requests.
	loads     chan struct{} // Two concurrent snapshot loads.
}

// Origin normalizes scheme, host and default port; reject paths, user information, wildcards, null and deceptive subdomain suffixes.
func Origin(value string) (string, error) {

	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" && parsed.Scheme != "http" || parsed.Hostname() == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" {
		return "", errInput
	}
	// Lowercase hosts; reject wildcards, whitespace and a trailing colon without a port.
	host, port := strings.ToLower(parsed.Hostname()), parsed.Port()
	if strings.ContainsAny(host, "*%\\ \t\r\n") || strings.HasSuffix(parsed.Host, ":") {
		return "", errInput
	}
	if port != "" {
		// Explicit ports must be canonical nonzero decimal uint16 values.
		number, err := strconv.ParseUint(port, 10, 16)
		if err != nil || number == 0 || strconv.FormatUint(number, 10) != port {
			return "", errInput
		}
	}
	// Omit default ports and bracket IPv6 hosts without an explicit port.
	if parsed.Scheme == "https" && port == "443" || parsed.Scheme == "http" && port == "80" {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return parsed.Scheme + "://" + host, nil
}

// New validates account/backend dependencies, 1..4096 sessions, at most 32 origins and HTTPS for cross-site cookies.
func New(account *Account, backend Backend, options Options) (*Server, error) {

	if account == nil || backend == nil || options.Sessions < 1 || options.Sessions > 4096 || len(options.Origins) == 0 || len(options.Origins) > 32 || options.Crosssite && !options.Secure {
		return nil, errInput
	}
	// Reject invalid or duplicate origins after normalization.
	origins := make(map[string]bool, len(options.Origins))
	for _, value := range options.Origins {
		origin, err := Origin(value)
		if err != nil || origins[origin] {
			return nil, errInput
		}
		origins[origin] = true
	}
	return &Server{account: account, backend: backend, origins: origins, secure: options.Secure, crosssite: options.Crosssite, sessions: sessions{values: make(map[string]time.Time), maximum: options.Sessions}, logins: make(chan struct{}, 4), requests: make(chan struct{}, 16), loads: make(chan struct{}, 2)}, nil
}

// ServeHTTP checks origins and request headers before every write; CORS headers do not replace authentication.
func (server *Server) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	// Apply security headers to error responses too.
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Add("Vary", "Origin")
	// Requests without Origin are allowed as non-browser traffic; an explicit origin must be unique and allowlisted before returning CORS headers.
	origins := request.Header.Values("Origin")
	allowed := false
	if len(origins) == 1 {
		origin, err := Origin(origins[0])
		allowed = err == nil && server.origins[origin]
		if allowed {
			response.Header().Set("Access-Control-Allow-Origin", origins[0])
			response.Header().Set("Access-Control-Allow-Credentials", "true")
		}
	}
	if len(origins) != 0 && !allowed {
		problem(response, http.StatusForbidden, "origin", "unapplied")
		return
	}
	// Handle preflight separately from authentication and routing.
	if request.Method == http.MethodOptions {
		server.preflight(response, request, allowed)
		return
	}
	// Writes require both an allowed origin and the request marker to prevent CSRF; reads require either one.
	if request.Method != http.MethodGet && request.Method != http.MethodHead && (!allowed || len(request.Header.Values("X-Astra-Request")) != 1 || request.Header.Get("X-Astra-Request") != "1") {
		problem(response, http.StatusForbidden, "origin", "unapplied")
		return
	}
	// Only the session route is accessible without a valid login.
	if request.URL.Path == "/api/session" {
		server.session(response, request)
		return
	}
	if _, ok := server.sessions.get(token(request), time.Now()); !ok {
		problem(response, http.StatusUnauthorized, "session", "unapplied")
		return
	}

	select {
	case server.requests <- struct{}{}:
		defer func() { <-server.requests }()
	default:
		problem(response, http.StatusTooManyRequests, "busy", "unapplied")
		return
	}

	switch request.URL.Path {
	case "/api/almanac":
		server.almanac(response, request)
	case "/api/credentials":
		server.credentials(response, request)
	case "/api/nodes", "/api/metrics":
		if request.Method != http.MethodGet {
			problem(response, http.StatusMethodNotAllowed, "method", "unapplied")
			return
		}
		if request.URL.Path == "/api/metrics" {
			respond(response, server.backend.Metrics())
		} else {
			respond(response, server.backend.Nodes())
		}
	default:
		problem(response, http.StatusNotFound, "route", "unapplied")
	}
}

// preflight validates origin, methods and headers without cookies, KDF work or Polaris RPCs.
// Permit only GET/POST/DELETE and the two fixed request headers.
func (server *Server) preflight(response http.ResponseWriter, request *http.Request, allowed bool) {

	method := request.Header.Get("Access-Control-Request-Method")
	if !allowed || method != "GET" && method != "POST" && method != "DELETE" || len(request.Header.Values("Access-Control-Request-Method")) != 1 {
		problem(response, http.StatusForbidden, "preflight", "unapplied")
		return
	}
	// Only content-type and x-astra-request are allowed.
	for _, header := range strings.Split(request.Header.Get("Access-Control-Request-Headers"), ",") {
		header = strings.ToLower(strings.TrimSpace(header))
		if header != "" && header != "content-type" && header != "x-astra-request" {
			problem(response, http.StatusForbidden, "preflight", "unapplied")
			return
		}
	}
	response.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE")
	response.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Astra-Request")
	response.Header().Add("Vary", "Access-Control-Request-Method")
	response.Header().Add("Vary", "Access-Control-Request-Headers")
	response.WriteHeader(http.StatusNoContent)
}

// session separates login KDF capacity from ordinary session lookups and business RPC capacity.
// POST logs in, DELETE logs out and GET inspects the current session.
func (server *Server) session(response http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodPost:
		// Bound usernames to 1..64 bytes and passwords to 1..1024 bytes.
		var input struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if body(response, request, 4096, &input) != nil || len(input.Username) == 0 || len(input.Username) > 64 || len(input.Password) == 0 || len(input.Password) > 1024 {
			problem(response, http.StatusBadRequest, "input", "unapplied")
			return
		}

		select {
		case server.logins <- struct{}{}:
			defer func() { <-server.logins }()
		default:
			problem(response, http.StatusTooManyRequests, "busy", "unapplied")
			return
		}
		if !server.account.verify(input.Username, input.Password) {
			problem(response, http.StatusUnauthorized, "login", "unapplied")
			return
		}
		if request.Context().Err() != nil {
			// Do not create a session after the caller disconnects.
			return
		}
		// Replace this browser's existing token after successful verification; report busy when no session slot is available.
		value, expire, ok := server.sessions.create(time.Now(), token(request))
		if !ok {
			problem(response, http.StatusTooManyRequests, "busy", "unapplied")
			return
		}
		server.cookie(response, value, expire)
		respond(response, map[string]any{"username": server.account.username, "expires": expire.UTC()})
	case http.MethodDelete:
		// Logout revokes server state before clearing the cookie and is idempotent for missing tokens.
		server.sessions.remove(token(request))
		server.cookie(response, "", time.Time{})
		response.WriteHeader(http.StatusNoContent)
	case http.MethodGet:
		// Session inspection returns username and expiry, or unauthenticated for an invalid token.
		expire, ok := server.sessions.get(token(request), time.Now())
		if !ok {
			problem(response, http.StatusUnauthorized, "session", "unapplied")
			return
		}
		respond(response, map[string]any{"username": server.account.username, "expires": expire.UTC()})
	default:
		problem(response, http.StatusMethodNotAllowed, "method", "unapplied")
	}
}

// body bounds encoded JSON/base64 and rejects unsupported nesting, duplicate fields, extra documents and non-JSON content types.
// A zero maximum permits an unbounded whole Almanac batch; arrays names explicitly allowed arrays of scalar objects.
func body(response http.ResponseWriter, request *http.Request, maximum int64, target any, arrays ...string) error {

	media, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return errInput
	}
	// Other inputs retain size limits; JSON/base64 expansion must not introduce a hidden total limit on Almanac batches.
	if maximum > 0 {
		request.Body = http.MaxBytesReader(response, request.Body, maximum)
	}
	data, err := io.ReadAll(request.Body)
	if err != nil {
		return errInput
	}
	return object(data, target, arrays...)
}

// respond never echoes input, backend messages or SQL errors, and a failed write never repeats the management operation.
func respond(response http.ResponseWriter, value any) {
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(value)
}

// problem uses fixed code/effect categories; unknown must not be interpreted as proof that nothing committed.
func problem(response http.ResponseWriter, code int, reason, effect string) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(code)
	respond(response, map[string]string{"error": reason, "effect": effect})
}
