// Verify strict management JSON, account-file and bounded-body input contracts without running a password KDF.
package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// counter records assertions reached by a named Web boundary, including a failed assertion.
func counter(t *testing.T) func(bool, string) {
	t.Helper()
	hits := 0
	t.Cleanup(func() { t.Logf(`ASTRA-CONTRACT {"contract":"ASTROLABE-BOUNDARY","hits":%d}`, hits) })
	return func(ok bool, reason string) {
		t.Helper()
		hits++
		if !ok {
			t.Fatal(reason)
		}
	}
}

// TestObject describes allowed JSON shapes independently of decoder tokens and implementation branches.
func TestObject(t *testing.T) {
	fields := make([]string, 17)
	for index := range fields {
		fields[index] = fmt.Sprintf(`"f%d":0`, index)
	}
	for _, input := range []struct {
		name   string // Stable contract scenario.
		data   string // Exact untrusted bytes.
		arrays bool   // Whether the single named array field is permitted.
		ok     bool   // Independently required acceptance result.
	}{
		{"empty-object", `{}`, false, true}, {"scalar-fields", `{"x":1,"s":"text","b":true,"n":null}`, false, true},
		{"field-limit", "{" + strings.Join(fields[:16], ",") + "}", false, true},
		{"field-overflow", "{" + strings.Join(fields, ",") + "}", false, false},
		{"empty", "", false, false}, {"utf8", "{\xff}", false, false}, {"top-array", `[]`, false, false},
		{"top-null", `null`, false, false}, {"duplicate", `{"x":1,"x":2}`, false, false},
		{"key", `{:1}`, false, false}, {"value", `{"x":}`, false, false}, {"nested", `{"x":{}}`, false, false},
		{"array-forbidden", `{"items":[]}`, false, false}, {"array-empty", `{"items":[]}`, true, true},
		{"array-objects", `{"items":[{}, {"x":1}]}`, true, true},
		{"array-wrong-field", `{"other":[]}`, true, false}, {"array-scalar", `{"items":[1]}`, true, false},
		{"array-nested", `{"items":[{"x":[]}]}`, true, false}, {"array-duplicate", `{"items":[{"x":1,"x":2}]}`, true, false},
		{"wrong-end", `{"x":1]`, false, false}, {"truncated", `{"x":1`, false, false},
		{"trailing", `{} {}`, false, false}, {"whitespace", " \n{}\t", false, true},
	} {
		t.Run(input.name, func(t *testing.T) {
			check := counter(t)
			var value map[string]json.RawMessage
			var arrays []string
			if input.arrays {
				arrays = []string{"items"}
			}
			err := object([]byte(input.data), &value, arrays...)
			check((err == nil) == input.ok, "JSON shape acceptance differs from the management contract")
			if input.ok {
				var expected map[string]json.RawMessage
				check(json.Unmarshal([]byte(input.data), &expected) == nil && len(value) == len(expected), "accepted object lost fields")
				for key, data := range expected {
					check(string(value[key]) == string(data), "accepted field bytes changed")
				}
			}
		})
	}
	t.Run("unknown-field", func(t *testing.T) {
		check := counter(t)
		var value struct{ Name string }
		check(object([]byte(`{"unknown":1}`), &value) != nil, "typed input accepted an unknown field")
	})
}

// TestAccountFile tests public deployment bytes; accepting this digest does not claim a login succeeds.
func TestAccountFile(t *testing.T) {
	const salt = "000102030405060708090a0b0c0d0e0f"
	const hash = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	const valid = `{"username":"admin","salt":"` + salt + `","hash":"` + hash + `"}`
	for _, input := range []struct {
		name string // File or independently malformed account boundary.
		data string // Public non-login fixture bytes.
		ok   bool   // Whether a complete account must be returned.
	}{
		{"valid", valid, true}, {"missing", "", false}, {"directory", "", false},
		{"limit", strings.Repeat(" ", 4096-len(valid)) + valid, true},
		{"overflow", strings.Repeat(" ", 4097-len(valid)) + valid, false},
		{"json", `{"username":`, false}, {"name", strings.Replace(valid, "admin", "", 1), false},
		{"salt-encoding", strings.Replace(valid, salt, "zz", 1), false},
		{"hash-encoding", strings.Replace(valid, hash, "zz", 1), false},
		{"salt-short", strings.Replace(valid, salt, salt[:30], 1), false},
		{"salt-long", strings.Replace(valid, salt, salt+"00", 1), false},
		{"hash-short", strings.Replace(valid, hash, hash[:62], 1), false},
		{"hash-long", strings.Replace(valid, hash, hash+"00", 1), false},
	} {
		t.Run(input.name, func(t *testing.T) {
			check := counter(t)
			path := filepath.Join(t.TempDir(), "account.json")
			if input.name == "directory" {
				path = t.TempDir()
			} else if input.name != "missing" {
				check(os.WriteFile(path, []byte(input.data), 0600) == nil, "account fixture write failed")
			}
			value, err := LoadAccount(path)
			if !input.ok {
				check(err != nil && value == nil, "invalid deployment returned a usable account")
				return
			}
			check(err == nil && value != nil && value.username == "admin", "complete account was rejected")
			for index := range value.salt {
				check(value.salt[index] == byte(index), "account salt bytes changed")
			}
			for index := range value.hash {
				check(value.hash[index] == byte(index), "account digest bytes changed")
			}
		})
	}
}

// broken returns a real reader error through the normal HTTP body interface.
type broken struct{}

// Read injects a body-read failure without returning partial bytes.
func (broken) Read([]byte) (int, error) { return 0, errors.New("fixture body read failed") }

// TestBody requires input refusal before a caller can submit, including native MaxBytesReader overflow.
func TestBody(t *testing.T) {
	for _, name := range []string{"valid", "limit", "overflow", "unlimited", "media", "media-syntax", "read", "json"} {
		t.Run(name, func(t *testing.T) {
			check := counter(t)
			data, maximum := `{"key":"value"}`, int64(100)
			if name == "limit" {
				maximum = int64(len(data))
			} else if name == "overflow" {
				maximum = int64(len(data) - 1)
			} else if name == "unlimited" {
				maximum, data = 0, strings.Repeat(" ", 16384)+data
			} else if name == "json" {
				data = `{`
			}
			request := httptest.NewRequest("POST", "/", strings.NewReader(data))
			request.Header.Set("Content-Type", "application/json; charset=utf-8")
			if name == "media" {
				request.Header.Set("Content-Type", "text/plain")
			} else if name == "media-syntax" {
				request.Header.Set("Content-Type", "application/json;=")
			} else if name == "read" {
				request.Body = io.NopCloser(broken{})
			}
			var value struct{ Key string }
			err := body(httptest.NewRecorder(), request, maximum, &value)
			ok := name == "valid" || name == "limit" || name == "unlimited"
			check((err == nil) == ok, "HTTP body admission differs from its bound or format contract")
			if ok {
				check(value.Key == "value", "accepted body lost content")
			}
		})
	}
}
