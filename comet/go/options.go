// Validate local configuration and bounded public inputs before starting work.
package comet

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

const (
	maxPayload     = 1024 * 1024     // One opaque body, and total Catalog batch bytes.
	defaultTimeout = 3 * time.Second // Total unary/initial-stream confirmation budget.
	maximumTimeout = time.Minute     // Hard cap for any explicit unary request.
)

// Options configures one shared Client. Zero capacities/timeouts select defaults;
// security defaults require authentication and verified TLS. Options are copied.
type Options struct {
	Endpoints []string      // 1..64 distinct host:port addresses, tried in order.
	Key       string        // APIKEY, 1..128 UTF-8 bytes when authenticated.
	Secret    []byte        // 1..4096 opaque bytes, copied before New returns.
	Anonymous bool          // Explicitly omit login; Key and Secret must then be empty.
	Plaintext bool          // Explicitly disable TLS, without authentication fallback.
	CA        []byte        // Optional PEM trust roots, at most 1 MiB; nil uses system roots.
	Readers   int           // Live subscription/Observer quota; default 64, maximum 4096.
	Beacons   int           // Publisher/Beacon quota; default 1024, maximum 65536.
	Bytes     int64         // Controlled storage budget; default 256 MiB, 16 KiB..4 GiB.
	Timeout   time.Duration // Default unary/initial-confirmation budget, (0, 1 min].
}

// ReadOptions bounds a subscription's installed and staging content separately.
type ReadOptions struct {
	Bytes   int64 // Default 64 MiB per root/batch; 16 KiB..1 GiB.
	Records int   // Default and maximum 65536 records; must be positive after defaults.
}

// normalizeOptions owns credential/configuration bytes and constructs verified
// trust without installing certificates or reading user configuration files.
func normalizeOptions(options Options) (Options, *tls.Config, *Error) {
	if options.Readers == 0 {
		options.Readers = 64
	}
	if options.Beacons == 0 {
		options.Beacons = 1024
	}
	if options.Bytes == 0 {
		options.Bytes = 256 * 1024 * 1024
	}
	if options.Timeout == 0 {
		options.Timeout = defaultTimeout
	}
	if len(options.Endpoints) == 0 || len(options.Endpoints) > 64 || options.Readers < 1 || options.Readers > 4096 ||
		options.Beacons < 1 || options.Beacons > 65536 || options.Bytes < 16384 || options.Bytes > 4*1024*1024*1024 ||
		options.Timeout <= 0 || options.Timeout > maximumTimeout {
		return Options{}, nil, localError(CodeInput)
	}
	if options.Anonymous && (options.Key != "" || len(options.Secret) != 0) || !options.Anonymous && (!validText(options.Key, 128) || len(options.Secret) == 0 || len(options.Secret) > 4096) {
		return Options{}, nil, localError(CodeInput)
	}
	// Normalize only endpoint syntax; business scopes remain byte-exact.
	endpoints := make([]string, 0, len(options.Endpoints))
	seen := make(map[string]bool, len(options.Endpoints))
	for _, endpoint := range options.Endpoints {
		host, port, failure := net.SplitHostPort(endpoint)
		number, conversion := strconv.ParseUint(port, 10, 16)
		if failure != nil || conversion != nil || number == 0 || host == "" || len(host) > 253 || strings.ContainsAny(host, " /\\\t\r\n?#@%\x00") {
			return Options{}, nil, localError(CodeInput)
		}
		if ip := net.ParseIP(host); ip != nil {
			host = ip.String()
		} else if strings.Contains(host, ":") || !validText(host, 253) {
			return Options{}, nil, localError(CodeInput)
		}
		normalized := net.JoinHostPort(strings.ToLower(host), strconv.FormatUint(number, 10))
		if seen[normalized] {
			return Options{}, nil, localError(CodeInput)
		}
		seen[normalized] = true
		endpoints = append(endpoints, normalized)
	}
	if len(options.CA) > maxPayload || options.Plaintext && len(options.CA) != 0 || bytes.Contains(options.CA, []byte("PRIVATE KEY")) {
		return Options{}, nil, localError(CodeInput)
	}
	// Only immutable trust state survives initialization; no application aliases remain.
	configuration := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(options.CA) != 0 {
		configuration.RootCAs = x509.NewCertPool()
		if !configuration.RootCAs.AppendCertsFromPEM(options.CA) {
			return Options{}, nil, localError(CodeInput)
		}
	}
	options.CA = nil
	options.Endpoints, options.Key, options.Secret = endpoints, strings.Clone(options.Key), bytes.Clone(options.Secret)
	return options, configuration, nil
}

// normalizeRead accepts at most one optional set, preserving a small factory API.
func normalizeRead(settings []ReadOptions) (ReadOptions, *Error) {
	if len(settings) > 1 {
		return ReadOptions{}, localError(CodeInput)
	}
	options := ReadOptions{Bytes: 64 * 1024 * 1024, Records: 65536}
	if len(settings) == 1 {
		if settings[0].Bytes != 0 {
			options.Bytes = settings[0].Bytes
		}
		if settings[0].Records != 0 {
			options.Records = settings[0].Records
		}
	}
	if options.Bytes < 16384 || options.Bytes > 1024*1024*1024 || options.Records < 1 || options.Records > 65536 {
		return ReadOptions{}, localError(CodeInput)
	}
	return options, nil
}

// validText rejects NUL, invalid UTF-8, empty input and byte-limit overflow.
func validText(text string, limit int) bool {
	return len(text) > 0 && len(text) <= limit && !strings.ContainsRune(text, 0) && utf8.ValidString(text)
}

// validScope enforces the public boundary, not server-side fine-grained ACLs.
func validScope(scope Scope) bool {
	return validText(scope.Sector, 128) && validText(scope.Spectrum, 128) && !strings.HasPrefix(scope.Sector, "__")
}

// validID checks only the wire UUID's fixed size/version/variant, not authority.
func validID(id string) bool {
	return len(id) == 16 && id[6]&0xf0 == 0x40 && id[8]&0xc0 == 0x80
}

// validTTL preserves integer-millisecond protocol units without silent rounding.
func validTTL(ttl time.Duration) bool {
	return ttl >= time.Second && ttl <= 10*time.Minute && ttl%time.Millisecond == 0
}

// wireScope copies public names into the private request representation.
func wireScope(scope Scope) *protocol.Scope {
	return &protocol.Scope{Sector: []byte(scope.Sector), Spectrum: []byte(scope.Spectrum)}
}
