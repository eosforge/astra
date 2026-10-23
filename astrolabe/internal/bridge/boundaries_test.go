// Verify the independent metrics configuration, integer wire format and HTTP failure boundaries.
package bridge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// payload follows the eight public Star metrics; it is not generated from the parser's accepted-name map.
const payload = "astra_ready 1\nastra_almanac_ready 0\nastra_clock_ready 1\nastra_clock_synchronized 0\nastra_clock_uncertainty_nanoseconds 18446744073709551615\nastra_members 2\nastra_sessions 3\nastra_recovery_bytes 4\n"

// counter records reached semantic checks independently for each selected metrics boundary.
func counter(t *testing.T) func(bool, string) {
	t.Helper()
	hits := 0
	t.Cleanup(func() { t.Logf(`ASTRA-CONTRACT {"contract":"ASTROLABE-METRICS","hits":%d}`, hits) })
	return func(ok bool, message string) {
		t.Helper()
		hits++
		if !ok {
			t.Fatal(message)
		}
	}
}

// TestTargets keeps all malformed configuration failures atomic and checks both sides of the byte limit.
func TestTargets(t *testing.T) {
	const valid = `{"127.0.0.1:1":"https://127.0.0.1:2/metrics"}`
	for _, input := range []struct {
		name string // Fixed independent configuration scenario.
		data string // Complete local deployment bytes, never an environment or browser URL.
		ok   bool   // Whether the public configuration contract admits these bytes.
	}{
		{"valid", valid, true}, {"empty-map", `{}`, true}, {"disabled", "", true},
		{"missing", "", false}, {"directory", "", false}, {"empty", "", false}, {"array", `[]`, false},
		{"scalar", `1`, false}, {"key", `{"127.0.0.1:1"`, false}, {"value", `{"127.0.0.1:1":1}`, false},
		{"duplicate", strings.TrimSuffix(valid, "}") + `,"127.0.0.1:1":"http://127.0.0.1:3/metrics"}`, false},
		{"endpoint", strings.Replace(valid, "127.0.0.1:1", "localhost:1", 1), false},
		{"url", strings.Replace(valid, "https://", "://", 1), false},
		{"scheme", strings.Replace(valid, "https://", "ftp://", 1), false},
		{"path", strings.Replace(valid, "/metrics", "/other", 1), false},
		{"escaped", strings.Replace(valid, "/metrics", "/%6Detrics", 1), false},
		{"query", strings.Replace(valid, "/metrics", "/metrics?key=value", 1), false},
		{"empty-query", strings.Replace(valid, "/metrics", "/metrics?", 1), false},
		{"fragment", strings.Replace(valid, "/metrics", "/metrics#part", 1), false},
		{"user", strings.Replace(valid, "https://", "https://user@", 1), false},
		{"host", strings.Replace(valid, "127.0.0.1:2", "localhost:2", 1), false},
		{"ending", strings.TrimSuffix(valid, "}"), false}, {"trailing", valid + `{}`, false},
		{"limit", strings.Repeat(" ", (8<<20)-len(valid)) + valid, true},
		{"overflow", strings.Repeat(" ", (8<<20)-len(valid)+1) + valid, false},
	} {
		t.Run(input.name, func(t *testing.T) {
			check := counter(t)
			path := filepath.Join(t.TempDir(), "metrics.json")
			switch input.name {
			case "disabled":
				path = ""
			case "missing":
			case "directory":
				path = t.TempDir()
			default:
				check(os.WriteFile(path, []byte(input.data), 0600) == nil, "cannot prepare metrics configuration")
			}
			values, err := Targets(path)
			if input.ok {
				expected := 1
				if input.name == "disabled" || input.name == "empty-map" {
					expected = 0
				}
				check(err == nil && len(values) == expected, "valid metrics mapping was rejected or changed")
				if expected == 1 {
					check(values["127.0.0.1:1"] == "https://127.0.0.1:2/metrics", "metrics target bytes changed")
				}
			} else {
				check(err != nil && values == nil, "invalid configuration returned a complete or partial mapping")
			}
		})
	}
}

// TestMetricValues rejects partial, noncanonical and oversized lines without losing uint64 precision.
func TestMetricValues(t *testing.T) {
	for _, input := range []struct {
		name string // Wire-format boundary, selected independently of parser branches.
		data string // Complete byte sequence supplied to the parser.
		ok   bool   // Required public-format result.
	}{
		{"valid", payload, true}, {"comments", "\n# comment\nunknown_metric 7\n" + payload, true},
		{"no-newline", strings.TrimSuffix(payload, "\n"), true},
		{"missing", strings.Replace(payload, "astra_members 2\n", "", 1), false},
		{"duplicate", payload + "astra_members 2\n", false},
		{"columns", strings.Replace(payload, "astra_members 2", "astra_members 2 3", 1), false},
		{"no-value", strings.Replace(payload, "astra_members 2", "astra_members", 1), false},
		{"binary", strings.Replace(payload, "astra_ready 1", "astra_ready 2", 1), false},
		{"leading-zero", strings.Replace(payload, "astra_members 2", "astra_members 02", 1), false},
		{"negative", strings.Replace(payload, "astra_members 2", "astra_members -1", 1), false},
		{"plus", strings.Replace(payload, "astra_members 2", "astra_members +2", 1), false},
		{"decimal", strings.Replace(payload, "astra_members 2", "astra_members 2.0", 1), false},
		{"overflow", strings.Replace(payload, "18446744073709551615", "18446744073709551616", 1), false},
		{"scanner", payload + strings.Repeat("x", 65537), false},
	} {
		t.Run(input.name, func(t *testing.T) {
			check := counter(t)
			data := []byte(input.data)
			values, err := parseMetrics(data)
			if !input.ok {
				check(err != nil && values == nil, "malformed sample published partial metrics")
				return
			}
			clear(data)
			check(err == nil && len(values) == 8, "complete public metric set was lost")
			for _, line := range strings.Split(strings.TrimSpace(payload), "\n") {
				pair := strings.Split(line, " ")
				check(values[pair[0]] == pair[1], "metric changed precision or borrowed the input buffer")
			}
		})
	}
}

// TestScrape uses native HTTP framing failures and exact response-size edges; no synthetic success body is accepted on error.
func TestScrape(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("X-Astra-Instance", "current")
		switch request.URL.Path {
		case "/status":
			response.WriteHeader(http.StatusServiceUnavailable)
		case "/missing":
			response.Header().Del("X-Astra-Instance")
		case "/duplicate":
			response.Header().Add("X-Astra-Instance", "current")
		case "/identity":
			response.Header().Set("X-Astra-Instance", "previous")
		case "/truncated":
			response.Header().Set("Content-Length", "10000")
		case "/overflow":
			_, _ = response.Write([]byte(strings.Repeat("\n", 65537)))
			return
		case "/limit":
			_, _ = response.Write([]byte(strings.Repeat("\n", 65536-len(payload)) + payload))
			return
		case "/partial":
			_, _ = response.Write([]byte("astra_ready 1\n"))
			return
		}
		_, _ = response.Write([]byte(payload))
	}))
	defer server.Close()
	client := server.Client()
	defer client.CloseIdleConnections()
	for _, name := range []string{"valid", "limit", "status", "missing", "duplicate", "identity", "truncated", "overflow", "partial", "url", "cancel"} {
		t.Run(name, func(t *testing.T) {
			check := counter(t)
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			target := server.URL + "/" + name
			if name == "url" {
				target = "://"
			} else if name == "cancel" {
				cancel()
			}
			values, err := scrape(ctx, client, target, "current")
			if name == "valid" || name == "limit" {
				check(err == nil && len(values) == 8 && values["astra_clock_uncertainty_nanoseconds"] == "18446744073709551615", "valid response lost its complete integer values")
			} else {
				check(err != nil && values == nil, "failed HTTP response published a usable metrics sample")
			}
		})
	}
}
