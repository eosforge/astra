// Verify management Almanac request validation and response semantics.

package web

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestBatchCommit forwards one complete transaction and sends no prefix of an invalid batch.
func TestBatchCommit(t *testing.T) {
	backend := &backend{}
	server := server(t, backend)
	cookie := login(t, server)
	body := `{"sector":"routes","spectrum":"main","version":"1","changes":[{"key":"a","value":""},{"key":"b","erase":true}]}`
	response := request(server, "POST", "/api/almanac", body, cookie)
	if response.Code != http.StatusOK || backend.calls.Load() != 1 || backend.request.Change != nil || len(backend.request.Changes) != 2 || backend.request.Changes[0].Key != "a" || backend.request.Changes[1].GetErase() == nil {
		t.Fatal("complete batch not forwarded", response.Code)
	}
	for _, invalid := range []string{
		strings.Replace(body, `"key":"b"`, `"key":"a"`, 1),
		strings.Replace(body, `"changes":`, `"key":"old","value":"","changes":`, 1),
		strings.Replace(body, `"sector":"routes"`, `"sector":"__keys"`, 1),
		strings.Replace(body, `"key":"a"`, `"key":"a","key":"z"`, 1),
		strings.Replace(body, `"value":""`, `"value":"","unknown":true`, 1),
		strings.Replace(body, `"value":""`, `"value":{}`, 1),
		strings.Replace(body, `"value":""`, `"value":[]`, 1),
		`{"sector":"routes","spectrum":"main","version":"1","changes":[]}`,
	} {
		if response := request(server, "POST", "/api/almanac", invalid, cookie); response.Code != http.StatusBadRequest || backend.calls.Load() != 1 {
			t.Fatal("invalid batch reached backend", response.Code)
		}
	}
	backend.failure = status.Error(codes.DeadlineExceeded, "confirmation lost")
	response = request(server, "POST", "/api/almanac", body, cookie)
	if backend.calls.Load() != 2 || !strings.Contains(response.Body.String(), `"effect":"unknown"`) {
		t.Fatal("uncertain batch was retried or treated as unapplied", response.Body.String())
	}
}

// TestLargeBatchCommit forwards 257 keys and over 2 MiB of JSON as one operation, without applying Catalog limits.
func TestLargeBatchCommit(t *testing.T) {
	backend := &backend{}
	server := server(t, backend)
	cookie := login(t, server)
	changes := make([]map[string]string, 257)
	value := base64.StdEncoding.EncodeToString(make([]byte, 8192))
	for index := range changes {
		changes[index] = map[string]string{"key": fmt.Sprint(index), "value": value}
	}
	body, err := json.Marshal(map[string]any{"sector": "large", "spectrum": "batch", "version": "1", "changes": changes})
	if err != nil {
		t.Fatal(err)
	}
	response := request(server, "POST", "/api/almanac", string(body), cookie)
	if response.Code != http.StatusOK || backend.calls.Load() != 1 || len(backend.request.Changes) != len(changes) {
		t.Fatalf("large batch rejected or split: %d", response.Code)
	}
}
