// Translate authenticated HTTP Almanac operations into backend requests and streamed responses.

package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/eosforge/astra/internal/generated/comet"
	"github.com/eosforge/astra/internal/generated/orbit"
	"github.com/eosforge/astra/internal/generated/polaris"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// text accepts bounded, nonempty UTF-8 without NUL, matching service rules; slashes do not imply paths or permissions.
func text(value string, maximum int) bool {
	return len(value) != 0 && len(value) <= maximum && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

// position encodes uint64 values as decimal strings to preserve precision in JavaScript.
func position(value *polaris.Position) map[string]string {
	return map[string]string{"sector": string(value.Scope.Sector), "spectrum": string(value.Scope.Spectrum), "version": strconv.FormatUint(value.Version, 10)}
}

// almanac GET is read-only; POST sends one complete key or atomic batch without retaining a workflow or retrying automatically.
func (server *Server) almanac(response http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodPost:
		server.commit(response, request)
	case http.MethodGet:
		// Reject malformed query strings; no parameters requests the directory, while the two-parameter form loads a snapshot.
		values, err := url.ParseQuery(request.URL.RawQuery)
		if err != nil || len(values) != 0 && (len(values) != 2 || len(values["sector"]) != 1 || len(values["spectrum"]) != 1) {
			problem(response, http.StatusBadRequest, "input", "unapplied")
			return
		}
		if len(values) == 0 {
			server.inventory(response, request)
			return
		}
		scope := &comet.Scope{Sector: []byte(values.Get("sector")), Spectrum: []byte(values.Get("spectrum"))}
		if !text(string(scope.Sector), 128) || !text(string(scope.Spectrum), 128) {
			problem(response, http.StatusBadRequest, "input", "unapplied")
			return
		}
		server.load(response, request, scope)
	default:
		problem(response, http.StatusMethodNotAllowed, "method", "unapplied")
	}
}

// commit reports committed only after Polaris confirms it; HTTP/RPC timeouts are never treated as an unapplied operation or retried.
func (server *Server) commit(response http.ResponseWriter, request *http.Request) {
	// Single-key input and changes batches are mutually exclusive; values remain strict base64.
	type item struct {
		Key   string  `json:"key"`
		Value *string `json:"value"`
		Erase *bool   `json:"erase"`
	}
	var input struct {
		Sector   string  `json:"sector"`
		Spectrum string  `json:"spectrum"`
		Version  string  `json:"version"`
		Key      string  `json:"key"`
		Value    *string `json:"value"`
		Erase    *bool   `json:"erase"`
		Changes  []item  `json:"changes"`
	}
	if body(response, request, 0, &input, "changes") != nil || !text(input.Sector, 128) || !text(input.Spectrum, 128) {
		problem(response, http.StatusBadRequest, "input", "unapplied")
		return
	}
	batch := input.Changes != nil
	if batch && (len(input.Changes) == 0 || input.Key != "" || input.Value != nil || input.Erase != nil || strings.HasPrefix(input.Sector, "__")) {
		problem(response, http.StatusBadRequest, "input", "unapplied")
		return
	}
	items := input.Changes
	if !batch {
		items = []item{{input.Key, input.Value, input.Erase}}
	}
	changes := make([]*comet.AlmanacChange, 0, len(items))
	seen := make(map[string]bool, len(items))
	for _, entry := range items {
		if !text(entry.Key, 1024) || seen[entry.Key] || (entry.Value == nil) == (entry.Erase == nil) || entry.Erase != nil && !*entry.Erase {
			problem(response, http.StatusBadRequest, "input", "unapplied")
			return
		}
		seen[entry.Key] = true
		change := &comet.AlmanacChange{Key: entry.Key}
		if entry.Value != nil {
			value, err := base64.StdEncoding.Strict().DecodeString(*entry.Value)
			if err != nil || len(value) > 1<<20 {
				problem(response, http.StatusBadRequest, "input", "unapplied")
				return
			}
			change.Action = &comet.AlmanacChange_Value{Value: value}
		} else {
			change.Action = &comet.AlmanacChange_Erase{Erase: &comet.Empty{}}
		}
		changes = append(changes, change)
	}

	// Require canonical nonzero decimal uint64 versions.
	version, err := strconv.ParseUint(input.Version, 10, 64)
	if err != nil || version == 0 || strconv.FormatUint(version, 10) != input.Version {
		problem(response, http.StatusBadRequest, "version", "unapplied")
		return
	}
	commit := &polaris.CommitRequest{Scope: &comet.Scope{Sector: []byte(input.Sector), Spectrum: []byte(input.Spectrum)}, Version: version}
	if batch {
		commit.Changes = changes
	} else {
		commit.Change = changes[0]
	}
	server.transaction(response, request, commit)
}

// submit is the sole write path for ordinary content and credentials; it never resends an uncertain operation or returns payloads or secrets.
// A successful position must match the requested scope and version; mismatch is a gateway protocol error.
func (server *Server) submit(response http.ResponseWriter, request *http.Request, scope *comet.Scope, change *comet.AlmanacChange, version uint64) {
	server.transaction(response, request, &polaris.CommitRequest{Scope: scope, Version: version, Change: change})
}

func (server *Server) transaction(response http.ResponseWriter, request *http.Request, commit *polaris.CommitRequest) {
	scope, version := commit.Scope, commit.Version
	// Bound each commit to five seconds; timeout maps to unknown, not proof that nothing committed.
	ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer cancel()
	result, err := server.backend.Commit(ctx, commit)
	if err != nil {
		code, reason, effect := failure(err, true)
		problem(response, code, reason, effect)
		return
	}

	if result == nil || result.Scope == nil || !bytes.Equal(result.Scope.Sector, scope.Sector) || !bytes.Equal(result.Scope.Spectrum, scope.Spectrum) || result.Version != version {
		problem(response, http.StatusBadGateway, "protocol", "unknown")
		return
	}
	respond(response, map[string]any{"effect": "committed", "position": position(result)})
}

// inventory returns one complete bounded directory, without per-key content or Star readiness information.
// Reject incomplete directories or more than 16384 entries.
func (server *Server) inventory(response http.ResponseWriter, request *http.Request) {
	// Use the same five-second request bound as commits.
	ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer cancel()
	result, err := server.backend.List(ctx)
	if err != nil {
		code, reason, effect := failure(err, false)
		problem(response, code, reason, effect)
		return
	}
	if result == nil || !result.Complete || len(result.Positions) > 16384 {
		problem(response, http.StatusBadGateway, "protocol", "unapplied")
		return
	}
	// Validate scope names and uniqueness before returning any directory; invalid entries reject the whole response.
	positions := make([]map[string]string, 0, len(result.Positions))
	seen := make(map[[2]string]bool, len(result.Positions))
	for _, value := range result.Positions {
		if value == nil || value.Scope == nil || !text(string(value.Scope.Sector), 128) || !text(string(value.Scope.Spectrum), 128) || seen[[2]string{string(value.Scope.Sector), string(value.Scope.Spectrum)}] {
			problem(response, http.StatusBadGateway, "protocol", "unapplied")
			return
		}
		seen[[2]string{string(value.Scope.Sector), string(value.Scope.Spectrum)}] = true
		positions = append(positions, position(value))
	}
	respond(response, map[string]any{"positions": positions, "complete": true})
}

// load forwards NDJSON records without copying a full 64 MiB snapshot; the browser installs only after the complete record.
// Send complete only after a successful Polaris EOF; an interrupted stream emits error rather than presenting a partial snapshot as complete.
// server.loads bounds concurrent snapshot loads.
func (server *Server) load(response http.ResponseWriter, request *http.Request, scope *comet.Scope) {
	// Reject a full concurrency semaphore immediately instead of queueing.
	select {
	case server.loads <- struct{}{}:
		defer func() { <-server.loads }()
	default:
		problem(response, http.StatusTooManyRequests, "busy", "unapplied")
		return
	}
	// Allow 30 seconds for a complete large-scope transfer.
	ctx, cancel := context.WithTimeout(request.Context(), 30*time.Second)
	defer cancel()
	response.Header().Set("Content-Type", "application/x-ndjson")
	encoder := json.NewEncoder(response)
	seen := make(map[string]bool) // Track at most 65536 distinct keys to bound memory and reject duplicates.
	var version uint64            // One version must remain consistent throughout the stream.
	var forwarded int             // Total forwarded payload is limited to 64 MiB.
	started, complete, wrote, disconnected := false, false, false, false
	err := server.backend.Load(ctx, scope, func(page *polaris.Snapshot) error {
		// Each page must match scope/version, contain entries when nonempty and occur before the terminal page.
		if page == nil || page.Scope == nil || !bytes.Equal(page.Scope.Sector, scope.Sector) || !bytes.Equal(page.Scope.Spectrum, scope.Spectrum) || page.Version == nil || complete || started && version != page.GetVersion() || !page.Complete && len(page.Entries) == 0 {
			return errInput
		}
		version, started = page.GetVersion(), true

		for _, entry := range page.Entries {
			if entry == nil || !text(entry.Key, 1024) || seen[entry.Key] || len(seen) == 65536 {
				return errInput
			}
			value, ok := entry.Action.(*comet.AlmanacChange_Value)
			if !ok || value == nil || len(value.Value) > 1<<20 || version == 0 {
				return errInput
			}
			forwarded += len(entry.Key) + len(value.Value)
			if forwarded > 64<<20 {
				return errInput
			}
			seen[entry.Key] = true
			row := map[string]any{"key": entry.Key}
			if string(scope.Sector) == "__auth" && string(scope.Spectrum) == "comet" {
				var credential orbit.Credential
				if !text(entry.Key, 128) || proto.Unmarshal(value.Value, &credential) != nil || len(credential.Secret) == 0 || len(credential.Secret) > 4096 {
					return errInput
				}
				row["redacted"] = true // Management reads expose APIKEY only; existing SECRET values never return to the browser.
			} else {
				row["value"] = base64.StdEncoding.EncodeToString(value.Value)
			}
			wrote = true
			if err := encoder.Encode(row); err != nil {
				// An encoding failure means the browser disconnected; do not attempt another error record.
				disconnected = true
				return err
			}
		}
		complete = page.Complete
		return nil
	})
	if disconnected {
		return
	}
	// Before any output, return an HTTP error; after output starts, send an error record without claiming a complete snapshot.
	if err != nil || !started || !complete {
		code, reason, _ := failure(err, false)
		if err == nil || errors.Is(err, errInput) {
			code, reason = http.StatusBadGateway, "protocol"
		}
		if !wrote {
			problem(response, code, reason, "unapplied")
		} else {
			_ = encoder.Encode(map[string]any{"error": reason, "complete": false})
		}
		return
	}

	_ = encoder.Encode(map[string]any{"complete": true, "position": position(&polaris.Position{Scope: scope, Version: version})})
}

// failure returns fixed HTTP/reason/effect categories. Writing defaults to unknown for network, deadline or cancellation errors; remote text is omitted.
func failure(err error, writing bool) (int, string, string) {
	effect := "unapplied"
	if writing {
		effect = "unknown"
	}
	// Classify context deadlines before mapping gRPC status codes.
	if errors.Is(err, context.DeadlineExceeded) {
		return http.StatusGatewayTimeout, "timeout", effect
	}

	switch status.Code(err) {
	case codes.InvalidArgument:
		return http.StatusBadRequest, "input", "unapplied"
	case codes.Aborted:
		return http.StatusConflict, "version", "unapplied"
	case codes.OutOfRange:
		return http.StatusConflict, "history", "unapplied"
	case codes.ResourceExhausted:
		return http.StatusTooManyRequests, "capacity", "unapplied"
	case codes.Unauthenticated, codes.PermissionDenied:
		return http.StatusServiceUnavailable, "backend_identity", "unapplied"
	case codes.DeadlineExceeded:
		return http.StatusGatewayTimeout, "timeout", effect
	default:
		return http.StatusServiceUnavailable, "backend", effect
	}
}
