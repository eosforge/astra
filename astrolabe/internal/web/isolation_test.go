// Verify partial decodes, independent input fields and snapshot redaction at management boundaries.
package web

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/internal/generated/comet"
	"github.com/eosforge/astra/internal/generated/orbit"
	"github.com/eosforge/astra/internal/generated/polaris"
)

// TestAccountSuffix rejects invalid hexadecimal suffixes even when a complete credential prefix was decoded.
func TestAccountSuffix(t *testing.T) {
	for _, name := range []string{"valid", "salt", "hash", "unknown"} {
		t.Run(name, func(t *testing.T) {
			check := counter(t)
			salt, hash := strings.Repeat("01", 16), strings.Repeat("02", 32)
			if name == "salt" {
				salt += "zz"
			}
			if name == "hash" {
				hash += "zz"
			}
			one, first := hex.DecodeString(salt)
			two, second := hex.DecodeString(hash)
			check(len(one) == 16 && len(two) == 32, "counterexample did not retain a complete decoded prefix")
			check((first != nil) == (name == "salt") && (second != nil) == (name == "hash"), "counterexample changed more than its selected encoding")
			data := `{"username":"admin","salt":"` + salt + `","hash":"` + hash + `"}`
			if name == "unknown" {
				data = strings.TrimSuffix(data, "}") + `,"unknown":1}`
			}
			path := filepath.Join(t.TempDir(), "account.json")
			check(os.WriteFile(path, []byte(data), 0600) == nil, "could not create isolated account input")
			account, err := LoadAccount(path)
			check((err == nil) == (name == "valid") && (account != nil) == (name == "valid"), "partial or unknown account input was published")
		})
	}
}

// TestArrayNames retains permission across later unrelated names and accepts either allowlist order.
func TestArrayNames(t *testing.T) {
	for _, name := range []string{"first", "last"} {
		t.Run(name, func(t *testing.T) {
			check := counter(t)
			fields := []string{"items", "other"}
			if name == "last" {
				fields[0], fields[1] = fields[1], fields[0]
			}
			var value map[string]json.RawMessage
			check(object([]byte(`{"items":[{"key":"value"}]}`), &value, fields...) == nil, "allowlist order revoked an allowed array")
			check(string(value["items"]) == `[{"key":"value"}]`, "accepted array lost its payload")
		})
	}
}

// TestInputField isolates complete but rejected requests from missing scope, key or decoded-value defects.
func TestInputField(t *testing.T) {
	const single = `{"sector":"routes","spectrum":"main","version":"1","key":"a","value":""}`
	const batch = `{"sector":"routes","spectrum":"main","version":"1","changes":[{"key":"a","value":""}]}`
	for _, input := range []struct {
		name string // Stable malformed field scenario.
		path string // Public route.
		body string // Full input, including the independently malformed field.
	}{
		{"batch-key", "/api/almanac", strings.Replace(batch, `"changes":`, `"key":"a","changes":`, 1)},
		{"almanac-unknown", "/api/almanac", strings.TrimSuffix(single, "}") + `,"unknown":1}`},
		{"credential-unknown", "/api/credentials", `{"key":"application","secret":"cHVibGlj","version":"1","unknown":1}`},
		{"credential-suffix", "/api/credentials", `{"key":"application","secret":"cHVibGlj!","version":"1"}`},
	} {
		t.Run(input.name, func(t *testing.T) {
			check := counter(t)
			if input.name == "credential-suffix" {
				decoded, err := base64.StdEncoding.Strict().DecodeString("cHVibGlj!")
				check(err != nil && string(decoded) == "public", "invalid suffix did not preserve its nonempty decoded prefix")
			}
			target := &backend{}
			server, cookie := fixture(t, target)
			response := request(server, http.MethodPost, input.path, input.body, cookie)
			check(response.Code == http.StatusBadRequest && target.calls.Load() == 0, "invalid independent field reached the authority")
			check(strings.Contains(response.Body.String(), `"effect":"unapplied"`) && len(server.requests) == 0, "refusal lost capacity or write certainty")
			response = request(server, http.MethodPost, "/api/almanac", single, cookie)
			check(response.Code == http.StatusOK && target.calls.Load() == 1, "valid request did not recover exactly once")
		})
	}
}

// TestSnapshotScope redacts only the credential scope and rejects a malformed suffix after a complete secret.
func TestSnapshotScope(t *testing.T) {
	for _, name := range []string{"credential", "sector", "spectrum", "suffix"} {
		t.Run(name, func(t *testing.T) {
			check := counter(t)
			scope := &comet.Scope{Sector: []byte("__auth"), Spectrum: []byte("comet")}
			if name == "sector" {
				scope.Sector = []byte("routes")
			}
			if name == "spectrum" {
				scope.Spectrum = []byte("other")
			}
			data, err := proto.Marshal(&orbit.Credential{Secret: []byte("public")})
			check(err == nil, "could not encode public fixture credential")
			if name == "suffix" {
				data = append(data, 0xff)
				var value orbit.Credential
				check(proto.Unmarshal(data, &value) != nil && string(value.Secret) == "public", "malformed protobuf did not retain its complete secret prefix")
			}
			target := &backend{pages: []*polaris.Snapshot{{Scope: scope, Version: proto.Uint64(1), Complete: true, Entries: []*comet.AlmanacChange{{Key: "application", Action: &comet.AlmanacChange_Value{Value: data}}}}}}
			server, cookie := fixture(t, target)
			response := request(server, http.MethodGet, "/api/almanac?sector="+string(scope.Sector)+"&spectrum="+string(scope.Spectrum), "", cookie)
			if name == "suffix" {
				check(response.Code == http.StatusBadGateway && !strings.Contains(response.Body.String(), `"complete":true`), "malformed credential snapshot was installed")
			} else {
				check(response.Code == http.StatusOK && strings.Contains(response.Body.String(), `"complete":true`), "valid scope lost snapshot completion")
				check(strings.Contains(response.Body.String(), `"redacted":true`) == (name == "credential"), "scope projection changed redaction policy")
				check(strings.Contains(response.Body.String(), `"value":"`+base64.StdEncoding.EncodeToString(data)+`"`) == (name != "credential"), "snapshot payload did not follow its scope policy")
			}
			check(len(server.loads) == 0, "snapshot retained its permit")
		})
	}
}

// TestSecureCrosssite keeps cross-site policy fixed while changing only the secure transport assertion.
func TestSecureCrosssite(t *testing.T) {
	for _, name := range []string{"secure", "insecure"} {
		t.Run(name, func(t *testing.T) {
			check := counter(t)
			server, err := New(&Account{}, &backend{}, Options{Origins: []string{"https://admin.example"}, Sessions: 8, Crosssite: true, Secure: name == "secure"})
			check((err == nil) == (name == "secure") && (server != nil) == (name == "secure"), "cross-site policy accepted an insecure deployment or refused a secure one")
		})
	}
}

// TestHeadOrigin distinguishes a read-only method from a write with the same absent CSRF header.
func TestHeadOrigin(t *testing.T) {
	for _, method := range []string{http.MethodHead, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			check := counter(t)
			target := &backend{}
			server, cookie := fixture(t, target)
			input := httptest.NewRequest(method, "/api/nodes", nil)
			input.Header.Set("Origin", "https://admin.example")
			input.AddCookie(cookie)
			response := httptest.NewRecorder()
			server.ServeHTTP(response, input)
			code := http.StatusMethodNotAllowed
			if method == http.MethodPost {
				code = http.StatusForbidden
			}
			check(response.Code == code, "method admission no longer distinguishes read from write")
			check(target.calls.Load() == 0 && len(server.requests) == 0, "refused method wrote or retained request capacity")
		})
	}
}
