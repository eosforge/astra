// Handle administrative credential operations while preserving secret-redaction boundaries.

package web

import (
	"encoding/base64"
	"net/http"
	"strconv"

	"github.com/eosforge/astra/internal/generated/comet"
	"github.com/eosforge/astra/internal/generated/orbit"
	"google.golang.org/protobuf/proto"
)

// credentials uses the shared login and Origin protections; Polaris enforces the internal version contract.
// Credentials live in the fixed __auth/comet scope, with optimistic version checks at Polaris.
func (server *Server) credentials(response http.ResponseWriter, request *http.Request) {

	scope := &comet.Scope{Sector: []byte("__auth"), Spectrum: []byte("comet")}
	if request.URL.RawQuery != "" {
		// Reject query strings before method dispatch.
		problem(response, http.StatusBadRequest, "input", "unapplied")
		return
	}
	if request.Method == http.MethodGet {
		server.load(response, request, scope) // Return APIKEY and redacted status, never SECRET.
		return
	}
	if request.Method != http.MethodPost {
		problem(response, http.StatusMethodNotAllowed, "method", "unapplied")
		return
	}
	// Require a version and either a new secret or erase=true.
	var input struct {
		Key     string  `json:"key"`
		Secret  *string `json:"secret"`
		Erase   *bool   `json:"erase"`
		Version string  `json:"version"`
	}
	if body(response, request, 8<<10, &input) != nil || !text(input.Key, 128) || (input.Secret == nil) == (input.Erase == nil) || input.Erase != nil && !*input.Erase {
		problem(response, http.StatusBadRequest, "input", "unapplied")
		return
	}
	// Require canonical nonzero decimal uint64 versions.
	version, err := strconv.ParseUint(input.Version, 10, 64)
	if err != nil || version == 0 || strconv.FormatUint(version, 10) != input.Version {
		problem(response, http.StatusBadRequest, "version", "unapplied")
		return
	}
	change := &comet.AlmanacChange{Key: input.Key}
	if input.Secret != nil {
		// Strictly decode 1..4096 secret bytes from base64; clear the buffer immediately after encoding the credential message.
		secret, err := base64.StdEncoding.Strict().DecodeString(*input.Secret)
		if err != nil || len(secret) == 0 || len(secret) > 4096 {
			problem(response, http.StatusBadRequest, "input", "unapplied")
			return
		}
		value, err := proto.Marshal(&orbit.Credential{Secret: secret})
		clear(secret)
		if err != nil {
			problem(response, http.StatusInternalServerError, "encoding", "unapplied")
			return
		}
		change.Action = &comet.AlmanacChange_Value{Value: value}
	} else {

		change.Action = &comet.AlmanacChange_Erase{Erase: &comet.Empty{}}
	}
	server.submit(response, request, scope, change, version)
}
