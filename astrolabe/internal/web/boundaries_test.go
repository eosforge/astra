// Verify independent query, origin-port and partially parsed media boundaries.
package web

import (
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/internal/generated/comet"
	"github.com/eosforge/astra/internal/generated/polaris"
)

// TestQuerySize holds both required query fields fixed and rejects an unrelated third field.
func TestQuerySize(t *testing.T) {
	for _, name := range []string{"valid", "extra"} {
		t.Run(name, func(t *testing.T) {
			check := counter(t)
			scope := &comet.Scope{Sector: []byte("routes"), Spectrum: []byte("main")}
			target := &backend{pages: []*polaris.Snapshot{{Scope: scope, Version: proto.Uint64(1), Complete: true}}}
			server, cookie := fixture(t, target)
			path := "/api/almanac?sector=routes&spectrum=main"
			code := http.StatusOK
			if name == "extra" {
				path += "&other=1"
				code = http.StatusBadRequest
			}
			response := request(server, http.MethodGet, path, "", cookie)
			check(response.Code == code, "query cardinality changed snapshot admission")
			check(strings.Contains(response.Body.String(), `"complete":true`) == (name == "valid"), "refused query published a completed snapshot")
			check(len(server.loads) == 0, "query retained its snapshot permit")
		})
	}
}

// TestOriginPort removes a port only when it is the default for the selected scheme.
func TestOriginPort(t *testing.T) {
	for _, test := range []struct {
		name string // Independent scheme and default-port combination.
		url  string // Public input without credentials or paths.
		want string // Independently required canonical origin.
	}{
		{"https-443", "https://example.com:443", "https://example.com"},
		{"http-443", "http://example.com:443", "http://example.com:443"},
		{"http-80", "http://example.com:80", "http://example.com"},
		{"https-80", "https://example.com:80", "https://example.com:80"},
	} {
		t.Run(test.name, func(t *testing.T) {
			check := counter(t)
			value, err := Origin(test.url)
			check(err == nil && value == test.want, "origin port normalization did not follow its scheme")
		})
	}
}

// TestMediaSuffix preserves the parsed media prefix while requiring a malformed parameter to refuse decoding.
func TestMediaSuffix(t *testing.T) {
	for _, name := range []string{"valid", "invalid"} {
		t.Run(name, func(t *testing.T) {
			check := counter(t)
			header := "application/json"
			if name == "invalid" {
				header += ";="
			}
			media, _, err := mime.ParseMediaType(header)
			check((err != nil) == (name == "invalid") && media == "application/json", "media counterexample did not retain its valid prefix")
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"key":"value"}`))
			request.Header.Set("Content-Type", header)
			response := httptest.NewRecorder()
			var value map[string]string
			err = body(response, request, 100, &value)
			check((err != nil) == (name == "invalid") && (value["key"] == "value") == (name == "valid"), "media rejection decoded a body or valid media lost its payload")
		})
	}
}
