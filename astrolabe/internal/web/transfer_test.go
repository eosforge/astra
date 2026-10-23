// Verify complete receipts, inventory validation and streamed snapshot refusal without replacing transport acceptance.
package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/internal/generated/comet"
	"github.com/eosforge/astra/internal/generated/orbit"
	"github.com/eosforge/astra/internal/generated/polaris"
)

// replies controls only the Web Backend interface; successful results do not imply native durable commits.
type replies struct {
	backend                      // Existing page/error fixture and atomic call counter.
	position  *polaris.Position  // Complete or independently damaged commit receipt.
	inventory *polaris.Inventory // Complete or independently damaged directory response.
	context   context.Context    // The operation context must be canceled after the handler returns.
}

// Commit records the exact input and returns the independently chosen receipt or failure.
func (replies *replies) Commit(ctx context.Context, value *polaris.CommitRequest) (*polaris.Position, error) {
	replies.calls.Add(1)
	replies.context, replies.request = ctx, value
	return replies.position, replies.failure
}

// List retains the caller's context for post-return lifetime assertions.
func (replies *replies) List(ctx context.Context) (*polaris.Inventory, error) {
	replies.calls.Add(1)
	replies.context = ctx
	return replies.inventory, replies.failure
}

// TestReceipt enforces one submission, byte-exact scope/version confirmation and owner-context retirement.
func TestReceipt(t *testing.T) {
	for _, name := range []string{"valid", "nil", "scope", "sector", "spectrum", "version", "refusal", "uncertain"} {
		t.Run(name, func(t *testing.T) {
			check := counter(t)
			target := &replies{position: &polaris.Position{Scope: &comet.Scope{Sector: []byte("routes"), Spectrum: []byte("main")}, Version: 7}}
			code, effect := 502, "unknown"
			switch name {
			case "valid":
				code, effect = 200, "committed"
			case "nil":
				target.position = nil
			case "scope":
				target.position.Scope = nil
			case "sector":
				target.position.Scope.Sector = []byte("other")
			case "spectrum":
				target.position.Scope.Spectrum = []byte("other")
			case "version":
				target.position.Version = 8
			case "refusal":
				target.failure = status.Error(codes.Aborted, "private")
				code, effect = 409, "unapplied"
			case "uncertain":
				target.failure = context.DeadlineExceeded
				code = 504
			}
			server, cookie := fixture(t, target)
			response := request(server, "POST", "/api/almanac", `{"sector":"routes","spectrum":"main","version":"7","key":"a","value":""}`, cookie)
			var value map[string]json.RawMessage
			check(response.Code == code && json.Unmarshal(response.Body.Bytes(), &value) == nil && string(value["effect"]) == `"`+effect+`"`, "receipt mismatch became a confirmed commit or lost its effect")
			check(target.calls.Load() == 1 && target.context.Err() == context.Canceled, "submission retried or its deadline context escaped")
			valueAction, ok := target.request.Change.Action.(*comet.AlmanacChange_Value)
			check(target.request.Version == 7 && target.request.Change.Key == "a" && ok && valueAction != nil && len(valueAction.Value) == 0, "request identity or empty-value action changed")
			check(len(server.requests) == 0 && !strings.Contains(response.Body.String(), "private"), "submission leaked capacity or backend text")
		})
	}
}

// TestInventory refuses partial or ambiguous inventories before writing any successful directory body.
func TestInventory(t *testing.T) {
	for _, name := range []string{"empty", "valid", "nil", "incomplete", "overflow", "entry", "scope", "sector", "spectrum", "duplicate", "failure"} {
		t.Run(name, func(t *testing.T) {
			check := counter(t)
			position := &polaris.Position{Scope: &comet.Scope{Sector: []byte("routes"), Spectrum: []byte("main")}, Version: ^uint64(0)}
			target := &replies{inventory: &polaris.Inventory{Complete: true, Positions: []*polaris.Position{position}}}
			code := 502
			switch name {
			case "empty":
				target.inventory.Positions, code = nil, 200
			case "valid":
				code = 200
			case "nil":
				target.inventory = nil
			case "incomplete":
				target.inventory.Complete = false
			case "overflow":
				target.inventory.Positions = make([]*polaris.Position, 16385)
			case "entry":
				target.inventory.Positions[0] = nil
			case "scope":
				position.Scope = nil
			case "sector":
				position.Scope.Sector = nil
			case "spectrum":
				position.Scope.Spectrum = []byte{0}
			case "duplicate":
				target.inventory.Positions = append(target.inventory.Positions, proto.Clone(position).(*polaris.Position))
			case "failure":
				target.failure, code = errors.New("private"), 503
			}
			server, cookie := fixture(t, target)
			response := request(server, "GET", "/api/almanac", "", cookie)
			check(response.Code == code && target.calls.Load() == 1, "inventory status or call count changed")
			check(target.context.Err() == context.Canceled && len(server.requests) == 0, "inventory context or permit escaped")
			if code == 200 {
				var result struct {
					Complete  bool                `json:"complete"`
					Positions []map[string]string `json:"positions"`
				}
				check(json.Unmarshal(response.Body.Bytes(), &result) == nil && result.Complete && len(result.Positions) == len(target.inventory.Positions), "successful inventory lost completeness or cardinality")
				if name == "valid" {
					check(result.Positions[0]["version"] == "18446744073709551615", "inventory version lost integer precision")
				}
			} else {
				check(!strings.Contains(response.Body.String(), `"positions"`) && !strings.Contains(response.Body.String(), "private"), "refused inventory leaked a prefix or backend text")
			}
		})
	}
}

// TestLoadFailures checks malformed pages at both sides of the first successful streamed row.
func TestLoadFailures(t *testing.T) {
	for _, name := range []string{"nil", "scope", "sector", "spectrum", "version", "empty", "changed", "after-complete", "entry", "key", "duplicate", "erase", "nil-action", "value", "zero", "credential-key", "credential-protobuf", "credential-empty", "credential-size", "no-page", "missing-complete", "late-error", "disconnected"} {
		t.Run(name, func(t *testing.T) {
			check := counter(t)
			scope := &comet.Scope{Sector: []byte("routes"), Spectrum: []byte("main")}
			entry := &comet.AlmanacChange{Key: "key", Action: &comet.AlmanacChange_Value{Value: []byte("value")}}
			page := &polaris.Snapshot{Scope: proto.Clone(scope).(*comet.Scope), Version: proto.Uint64(7), Entries: []*comet.AlmanacChange{entry}, Complete: true}
			target := &backend{pages: []*polaris.Snapshot{page}}
			wrote := false
			switch name {
			case "nil":
				target.pages[0] = nil
			case "scope":
				page.Scope = nil
			case "sector":
				page.Scope.Sector = []byte("other")
			case "spectrum":
				page.Scope.Spectrum = []byte("other")
			case "version":
				page.Version = nil
			case "empty":
				page.Complete, page.Entries = false, nil
			case "changed":
				page.Complete, wrote = false, true
				target.pages = append(target.pages, &polaris.Snapshot{Scope: scope, Version: proto.Uint64(8), Complete: true})
			case "after-complete":
				page.Entries = nil
				target.pages = append(target.pages, proto.Clone(page).(*polaris.Snapshot))
			case "entry":
				page.Entries[0] = nil
			case "key":
				entry.Key = ""
			case "duplicate":
				page.Entries, wrote = append(page.Entries, proto.Clone(entry).(*comet.AlmanacChange)), true
			case "erase":
				entry.Action = &comet.AlmanacChange_Erase{Erase: &comet.Empty{}}
			case "nil-action":
				entry.Action = (*comet.AlmanacChange_Value)(nil)
			case "value":
				entry.Action = &comet.AlmanacChange_Value{Value: make([]byte, (1<<20)+1)}
			case "zero":
				page.Version = proto.Uint64(0)
			case "credential-key", "credential-protobuf", "credential-empty", "credential-size":
				scope = &comet.Scope{Sector: []byte("__auth"), Spectrum: []byte("comet")}
				page.Scope = scope
				secret := []byte("s")
				if name == "credential-key" {
					entry.Key = strings.Repeat("k", 129)
				} else if name == "credential-empty" {
					secret = nil
				} else if name == "credential-size" {
					secret = make([]byte, 4097)
				}
				data, err := proto.Marshal(&orbit.Credential{Secret: secret})
				check(err == nil, "public credential fixture could not encode")
				if name == "credential-protobuf" {
					data = []byte{0xff}
				}
				entry.Action = &comet.AlmanacChange_Value{Value: data}
			case "no-page":
				target.pages = nil
			case "missing-complete":
				page.Complete, wrote = false, true
			case "late-error":
				target.failure, wrote = errors.New("private"), true
			}
			server, _ := fixture(t, target)
			request := httptest.NewRequest("GET", "/api/almanac", nil)
			if name == "disconnected" {
				response := &journal{header: make(http.Header), fail: true}
				server.load(response, request, scope)
				check(response.writes == 1 && response.complete == 0 && response.errors == 0, "disconnected client received retries or a completion marker")
			} else {
				response := httptest.NewRecorder()
				server.load(response, request, scope)
				code := 502
				if wrote {
					code = 200
					check(strings.Contains(response.Body.String(), `"complete":false`), "partial stream lacks an explicit failure terminal")
				}
				check(response.Code == code && !strings.Contains(response.Body.String(), `"complete":true`) && !strings.Contains(response.Body.String(), "private"), "damaged snapshot claimed success or exposed backend text")
			}
			check(len(server.loads) == 0, "snapshot refusal retained its admission slot")
		})
	}
}

// journal discards large value rows while retaining native writes and short JSON terminal semantics.
type journal struct {
	header   http.Header // Owned response headers.
	code     int         // First emitted status.
	writes   int         // Actual response write attempts.
	complete int         // Successful completion markers, independent of data rows.
	errors   int         // Explicit terminal errors.
	fail     bool        // A client write fault, applied through the standard ResponseWriter interface.
}

// Header returns the journal-owned response headers for mutation by the handler.
func (journal *journal) Header() http.Header { return journal.header }

// WriteHeader retains the first response status and ignores later attempts.
func (journal *journal) WriteHeader(code int) {
	if journal.code == 0 {
		journal.code = code
	}
}

// Write records output attempts and small completion messages, or injects a client disconnect.
func (journal *journal) Write(data []byte) (int, error) {
	journal.writes++
	journal.WriteHeader(200)
	if journal.fail {
		return 0, errors.New("client disconnected")
	}
	if len(data) < 1024 {
		var value struct {
			Complete bool   `json:"complete"`
			Error    string `json:"error"`
		}
		if err := json.Unmarshal(data, &value); err != nil {
			return 0, err
		}
		if value.Complete {
			journal.complete++
		}
		if value.Error != "" {
			journal.errors++
		}
	}
	return len(data), nil
}

// TestLoadBudget checks the existing management projection's key/byte bounds with bounded fixture memory.
func TestLoadBudget(t *testing.T) {
	for _, name := range []string{"keys-limit", "keys-overflow", "bytes-limit", "bytes-overflow", "busy"} {
		t.Run(name, func(t *testing.T) {
			check := counter(t)
			scope := &comet.Scope{Sector: []byte("routes"), Spectrum: []byte("main")}
			page := &polaris.Snapshot{Scope: scope, Version: proto.Uint64(7), Complete: true}
			rows := 65536
			if name == "keys-overflow" {
				rows++
			} else if strings.HasPrefix(name, "bytes-") {
				rows = 64
			} else if name == "busy" {
				rows = 0
			}
			value := &comet.AlmanacChange_Value{Value: []byte{}}
			if rows == 64 {
				value.Value = make([]byte, (1<<20)-1)
			}
			for index := range rows {
				key := fmt.Sprint(index)
				if rows == 64 {
					key = string(rune('!' + index))
				}
				page.Entries = append(page.Entries, &comet.AlmanacChange{Key: key, Action: value})
			}
			if name == "bytes-overflow" {
				page.Entries[63].Action = &comet.AlmanacChange_Value{Value: make([]byte, 1<<20)}
			}
			server, _ := fixture(t, &backend{pages: []*polaris.Snapshot{page}})
			if name == "busy" {
				for range cap(server.loads) {
					server.loads <- struct{}{}
				}
			}
			before := len(server.loads)
			response := &journal{header: make(http.Header)}
			server.load(response, httptest.NewRequest("GET", "/api/almanac", nil), scope)
			check(len(server.loads) == before, "snapshot budget path leaked or released another owner's permit")
			if strings.HasSuffix(name, "-limit") {
				check(response.code == 200 && response.writes == rows+1 && response.complete == 1 && response.errors == 0, "exact projection limit was refused or truncated")
			} else if name == "busy" {
				check(response.code == 429 && response.writes == 1 && response.complete == 0 && response.errors == 1, "full projection admission was not refused")
			} else {
				check(response.code == 200 && response.writes == rows && response.complete == 0 && response.errors == 1, "projection overflow was silently truncated or marked complete")
			}
		})
	}
}

// TestCookies fixes expiration semantics without sleeping and verifies both same-site modes.
func TestCookies(t *testing.T) {
	for _, name := range []string{"lax", "crosssite", "empty", "expired"} {
		t.Run(name, func(t *testing.T) {
			check := counter(t)
			server, _ := fixture(t, &backend{})
			server.crosssite = name == "crosssite"
			value, expire := strings.Repeat("b", 43), time.Now().Add(time.Hour)
			if name == "empty" {
				value = ""
			} else if name == "expired" {
				expire = time.Now().Add(-time.Second)
			}
			response := httptest.NewRecorder()
			server.cookie(response, value, expire)
			cookies := response.Result().Cookies()
			check(len(cookies) == 1, "cookie emission did not produce one cookie")
			cookie := cookies[0]
			check(cookie.Path == "/api" && cookie.Domain == "" && cookie.HttpOnly && cookie.Secure, "cookie scope or security flags changed")
			mode := http.SameSiteLaxMode
			if name == "crosssite" {
				mode = http.SameSiteNoneMode
			}
			check(cookie.SameSite == mode, "cookie mode changed")
			if name == "empty" || name == "expired" {
				check(cookie.Value == "" && cookie.MaxAge == -1 && cookie.Expires.Equal(time.Unix(1, 0)), "cookie revocation retained an active token")
			} else {
				check(cookie.Value == value && cookie.MaxAge > 0 && cookie.MaxAge <= 3600, "fixed cookie lifetime drifted")
			}
		})
	}
}
