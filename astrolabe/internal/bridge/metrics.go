// Collect bounded Star metrics and expose freshness and trust state to management clients.

package bridge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eosforge/astra/internal/admission"
)

// Targets loads the deployment's numeric Star endpoint to /metrics URL mapping; the trusted directory still selects scrape targets.
// The local mapping is limited to 8 MiB without imposing a separate node-count limit.
// Reject browser-provided URLs, guessed ports and environment proxy settings.
// An empty path disables scraping; malformed local mappings return an error.
func Targets(path string) (map[string]string, error) {
	result := make(map[string]string)
	if path == "" {

		return result, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open metrics targets")
	}
	defer file.Close()

	const maximum = 8 << 20
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(data) > maximum {
		return nil, errors.New("metrics targets exceed limit")
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, errors.New("metrics targets must be an object")
	}
	// Require canonical Star endpoints and strict /metrics URLs, rejecting duplicate keys.
	for decoder.More() {
		token, err := decoder.Token()
		key, valid := token.(string)
		var value string
		if err != nil || !valid || decoder.Decode(&value) != nil || result[key] != "" {
			return nil, errors.New("invalid or duplicate metrics target")
		}
		if _, err := admission.Endpoint(key); err != nil {
			return nil, errors.New("metrics target requires a canonical Star endpoint")
		}
		parsed, err := url.Parse(value)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Path != "/metrics" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.User != nil || parsed.Opaque != "" {
			return nil, errors.New("invalid metrics URL")
		}
		if _, err := admission.Endpoint(parsed.Host); err != nil {
			return nil, errors.New("metrics URL requires a canonical IP:PORT")
		}
		result[key] = value
	}
	// Require a complete top-level object with no trailing data.
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, errors.New("invalid metrics object end")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("trailing metrics target data")
	}
	return result, nil
}

// metric stores the latest redacted, fixed-cardinality observation; decimal strings preserve uint64 precision.
type metric struct {
	ID        string            `json:"id"`        // Reset this sample when the Star instance changes.
	Observed  time.Time         `json:"observed"`  // Time of the last successful scrape, used for freshness.
	Attempted time.Time         `json:"attempted"` // Time of the last attempt, including failures.
	Stale     bool              `json:"stale"`     // Set after failure, expiry or instance replacement.
	Values    map[string]string `json:"values"`    // Immutable published map of metric names to original decimal values.
}

// gauges lists the eight implemented, unlabeled Star integer metrics; unavailable histograms are not synthesized.
// True marks a binary gauge restricted to 0 or 1; false permits an ordinary counter.
var gauges = map[string]bool{
	"astra_ready": true, "astra_almanac_ready": true, "astra_clock_ready": true, "astra_clock_synchronized": true,
	"astra_clock_uncertainty_nanoseconds": false, "astra_members": false, "astra_sessions": false, "astra_recovery_bytes": false,
}

// parseMetrics accepts only the existing Star contract and publishes a complete, unique metric set without arbitrary label parsing.
func parseMetrics(data []byte) (map[string]string, error) {
	values := make(map[string]string, len(gauges))
	scanner := bufio.NewScanner(bytes.NewReader(data)) // Scanner.Text gives retained fields their own strings instead of borrowing the response buffer.
	// Skip blank lines, comments and unknown metrics; known metrics require exactly two columns and a unique name.
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		binary, known := gauges[fields[0]]
		if !known {
			continue
		}
		if len(fields) != 2 || values[fields[0]] != "" {
			return nil, errors.New("invalid metrics sample")
		}
		// Require canonical decimal uint64 values and binary 0/1 gauges; reject alternate spellings such as leading zeros.
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || binary && value > 1 || strconv.FormatUint(value, 10) != fields[1] {
			return nil, errors.New("invalid metrics value")
		}
		values[fields[0]] = fields[1]
	}
	// Reject incomplete samples after scanner errors or missing fields; never publish a partial set.
	if scanner.Err() != nil || len(values) != len(gauges) {
		return nil, errors.New("incomplete metrics sample")
	}
	return values, nil
}

// Monitor owns four workers, two-second request limits and 64 KiB responses, and joins all workers when the parent context ends.
// Do not follow redirects or send node bearer tokens or cookies. HTTPS uses the deployment CA.
// The parent ctx controls polling; targets supplies the deployment mapping and certificate configures scrape TLS.
func (backend *Backend) Monitor(ctx context.Context, targets map[string]string, certificate *tls.Config) {
	if len(targets) == 0 {
		return
	}
	// Disable proxies; bound dialing and response headers to two seconds, use one connection per host and retain idle connections for ten seconds.
	transport := &http.Transport{Proxy: nil, TLSClientConfig: certificate.Clone(), DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext, MaxConnsPerHost: 1, MaxIdleConns: len(targets), MaxIdleConnsPerHost: 1, IdleConnTimeout: 10 * time.Second, ResponseHeaderTimeout: 2 * time.Second, MaxResponseHeaderBytes: 8192, DisableCompression: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	// Sample every five seconds and stop the ticker on exit.
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		backend.sample(ctx, client, targets)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// sample scrapes outside the lock and discards late results after the directory replaces their instance.
// Reuse client and scrape only the intersection of the trusted directory and deployment mapping.
func (backend *Backend) sample(ctx context.Context, client *http.Client, targets map[string]string) {

	backend.mutex.RLock()
	nodes := backend.nodes
	backend.mutex.RUnlock()
	jobs := make(chan node)
	var group sync.WaitGroup
	defer func() { close(jobs); group.Wait() }() // Stop input before joining workers on both completion and cancellation.

	for range 4 {
		group.Go(func() {
			for current := range jobs {
				values, err := scrape(ctx, client, targets[current.Endpoint], current.ID)
				backend.mutex.Lock()
				valid := backend.members[current.Endpoint] == current.ID
				if valid && !backend.closed {
					if backend.metrics == nil {
						backend.metrics = make(map[string]metric)
					}
					previous := backend.metrics[current.Endpoint]
					if previous.ID != current.ID {

						previous = metric{ID: current.ID, Stale: true}
					}
					// Retain the cached timestamp's monotonic component; convert only response copies to UTC so wall-clock jumps cannot affect freshness.
					previous.Attempted, previous.Stale = time.Now(), err != nil
					if err == nil {
						previous.Values, previous.Observed = values, previous.Attempted
					}
					backend.metrics[current.Endpoint] = previous
				}
				backend.mutex.Unlock()
			}
		})
	}

	for _, current := range nodes {
		if current.Role != "ROLE_STAR" || targets[current.Endpoint] == "" {
			continue
		}
		select {
		case jobs <- current:
		case <-ctx.Done():
			return
		}
	}
}

// scrape requires the expected instance header, status, size and complete metric set; network failures mark stale without deleting the node.
func scrape(ctx context.Context, client *http.Client, target, instance string) (map[string]string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK || len(response.Header.Values("X-Astra-Instance")) != 1 || response.Header.Get("X-Astra-Instance") != instance {
		return nil, errors.New("metrics identity unavailable")
	}

	data, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(data) > 65536 {
		return nil, errors.New("metrics body exceeds limit")
	}
	return parseMetrics(data)
}

// Metrics covers every Star in the current directory; browser refreshes never initiate network requests.
// Unsampled or replaced instances have zero observation time and empty values; failed or expired samples remain visible as stale.
func (backend *Backend) Metrics() any {
	backend.mutex.RLock()
	defer backend.mutex.RUnlock()
	values := make([]metric, 0, len(backend.nodes))
	now := time.Now()
	for _, current := range backend.nodes {
		if current.Role != "ROLE_STAR" {
			continue
		} // Other roles do not expose the Star metrics contract.
		value, exists := backend.metrics[current.Endpoint]
		if !exists || value.ID != current.ID {
			value = metric{ID: current.ID, Stale: true}
		}
		value.Stale = value.Stale || backend.closed || now.Sub(value.Observed) > 15*time.Second
		value.Observed, value.Attempted = value.Observed.UTC(), value.Attempted.UTC()
		values = append(values, value) // Published Values maps are immutable and need no per-request copy.
	}
	return struct {
		Samples []metric `json:"samples"`
	}{values}
}
