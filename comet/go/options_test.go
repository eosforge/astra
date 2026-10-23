// Verify local scope, lifetime, endpoint and security-configuration boundaries.
package comet

import (
	"crypto/tls"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestInputBoundaries checks public names, whole-millisecond TTLs and explicit security configuration.
func TestInputBoundaries(t *testing.T) {
	t.Parallel()
	check := oracle(t, "COMET-GO-INPUT")
	for _, scope := range []Scope{{}, {Sector: "__private", Spectrum: "x"}, {Sector: "x\x00y", Spectrum: "z"}, {Sector: "\xff", Spectrum: "z"}} {
		check(!validScope(scope), "invalid scope accepted")
	}
	check(!validTTL(time.Second-time.Millisecond) && !validTTL(time.Second+1) && !validTTL(10*time.Minute+time.Millisecond) && validTTL(time.Second) && validTTL(10*time.Minute), "TTL bounds or units changed")
	settings := Options{Endpoints: []string{"LOCALHOST:1234"}, Key: "key", Secret: []byte("secret")}
	owned, _, failure := normalizeOptions(settings)
	check(failure == nil && owned.Endpoints[0] == "localhost:1234", "valid configuration rejected")
	settings.Endpoints[0], settings.Secret[0] = "changed:1", 'x'
	check(string(owned.Secret) == "secret" && owned.Endpoints[0] == "localhost:1234", "options retained caller aliases")
	for _, settings := range []Options{{Endpoints: []string{"localhost:1"}}, {Endpoints: []string{"localhost:0"}, Anonymous: true},
		{Endpoints: []string{"localhost:1", "LOCALHOST:1"}, Anonymous: true}, {Endpoints: []string{"localhost:1"}, Anonymous: true, Secret: []byte("secret")},
		{Endpoints: []string{"localhost:1"}, Anonymous: true, Plaintext: true, CA: []byte("certificate")}} {
		_, _, failure := normalizeOptions(settings)
		check(failure != nil, "invalid options accepted")
	}
}

// TestOptionsLimits exercises independent public limits before any network owner exists.
func TestOptionsLimits(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string         // Named contract boundary, independent of a parser branch.
		change func(*Options) // One change to an otherwise valid anonymous configuration.
		valid  bool           // Acceptance required by the published inclusive limits.
	}{
		{"no-endpoints", func(value *Options) { value.Endpoints = nil }, false},
		{"64-endpoints", func(value *Options) {
			value.Endpoints = nil
			for port := 1; port <= 64; port++ {
				value.Endpoints = append(value.Endpoints, fmt.Sprintf("localhost:%d", port))
			}
		}, true},
		{"65-endpoints", func(value *Options) {
			value.Endpoints = nil
			for port := 1; port <= 65; port++ {
				value.Endpoints = append(value.Endpoints, fmt.Sprintf("localhost:%d", port))
			}
		}, false},
		{"readers-negative", func(value *Options) { value.Readers = -1 }, false},
		{"readers-minimum", func(value *Options) { value.Readers = 1 }, true},
		{"readers-maximum", func(value *Options) { value.Readers = 4096 }, true},
		{"readers-overflow", func(value *Options) { value.Readers = 4097 }, false},
		{"beacons-negative", func(value *Options) { value.Beacons = -1 }, false},
		{"beacons-minimum", func(value *Options) { value.Beacons = 1 }, true},
		{"beacons-maximum", func(value *Options) { value.Beacons = 65536 }, true},
		{"beacons-overflow", func(value *Options) { value.Beacons = 65537 }, false},
		{"bytes-below", func(value *Options) { value.Bytes = 16383 }, false},
		{"bytes-minimum", func(value *Options) { value.Bytes = 16384 }, true},
		{"bytes-maximum", func(value *Options) { value.Bytes = 4 * 1024 * 1024 * 1024 }, true},
		{"bytes-overflow", func(value *Options) { value.Bytes = 4*1024*1024*1024 + 1 }, false},
		{"timeout-negative", func(value *Options) { value.Timeout = -time.Nanosecond }, false},
		{"timeout-positive", func(value *Options) { value.Timeout = time.Nanosecond }, true},
		{"timeout-maximum", func(value *Options) { value.Timeout = time.Minute }, true},
		{"timeout-overflow", func(value *Options) { value.Timeout = time.Minute + time.Nanosecond }, false},
		{"secret-maximum", func(value *Options) {
			value.Anonymous, value.Key, value.Secret = false, "key", make([]byte, 4096)
		}, true},
		{"secret-overflow", func(value *Options) {
			value.Anonymous, value.Key, value.Secret = false, "key", make([]byte, 4097)
		}, false},
		{"key-maximum", func(value *Options) {
			value.Anonymous, value.Key, value.Secret = false, strings.Repeat("k", 128), []byte{0}
		}, true},
		{"key-overflow", func(value *Options) {
			value.Anonymous, value.Key, value.Secret = false, strings.Repeat("k", 129), []byte{0}
		}, false},
	}
	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			check := oracle(t, "COMET-GO-INPUT")
			settings := Options{Endpoints: []string{"localhost:1234"}, Anonymous: true}
			testcase.change(&settings)
			owned, trust, failure := normalizeOptions(settings)
			if !testcase.valid {
				check(failure != nil && failure.Code == CodeInput && failure.Effect == Unapplied, "invalid configuration lost its rejection evidence")
				check(trust == nil && len(owned.Endpoints) == 0 && len(owned.Secret) == 0, "invalid configuration returned admitted state")
				return
			}
			check(failure == nil && trust != nil && trust.MinVersion == tls.VersionTLS12 && !trust.InsecureSkipVerify, "valid inclusive boundary lost verified TLS")
			for _, pair := range [][2]int{{owned.Readers, settings.Readers}, {owned.Beacons, settings.Beacons}} {
				check(pair[1] == 0 || pair[0] == pair[1], "explicit capacity was silently changed")
			}
			check((settings.Bytes == 0 || owned.Bytes == settings.Bytes) && (settings.Timeout == 0 || owned.Timeout == settings.Timeout), "explicit storage or deadline was silently changed")
		})
	}
	settings, _, failure := normalizeOptions(Options{Endpoints: []string{"localhost:1"}, Anonymous: true})
	check := oracle(t, "COMET-GO-INPUT")
	check(failure == nil && settings.Readers == 64 && settings.Beacons == 1024 && settings.Bytes == 256*1024*1024 && settings.Timeout == 3*time.Second, "zero-valued options did not select the documented defaults")
}

// TestEndpointCanonicalization checks textual aliases and malformed host/port boundaries.
func TestEndpointCanonicalization(t *testing.T) {
	t.Parallel()
	check := oracle(t, "COMET-GO-INPUT")
	for _, endpoints := range [][]string{
		{"localhost"}, {":1"}, {"localhost:+1"}, {"localhost:65536"}, {"localhost:0"}, {"[bad:x]:1"}, {"\xff:1"},
		{"a b:1"}, {"localhost:1/path"}, {strings.Repeat("x", 254) + ":1"}, {"localhost:01", "LOCALHOST:1"},
		{"[0:0:0:0:0:0:0:1]:1", "[::1]:1"}, {"[::ffff:127.0.0.1]:1", "127.0.0.1:1"},
	} {
		_, _, failure := normalizeOptions(Options{Endpoints: endpoints, Anonymous: true})
		check(failure != nil && failure.Code == CodeInput && failure.Effect == Unapplied, "invalid endpoint lost its rejection evidence")
	}
	settings, _, failure := normalizeOptions(Options{Endpoints: []string{"LOCALHOST:0123", "[0:0:0:0:0:0:0:1]:65535"}, Anonymous: true})
	check(failure == nil && len(settings.Endpoints) == 2 && settings.Endpoints[0] == "localhost:123" && settings.Endpoints[1] == "[::1]:65535", "endpoint canonicalization lost host/port identity")
}

// TestTrustInputs requires bounded public certificates without retaining mutable PEM bytes.
func TestTrustInputs(t *testing.T) {
	t.Parallel()
	check := oracle(t, "COMET-GO-INPUT")
	for _, ca := range [][]byte{[]byte("not a certificate"), []byte("-----BEGIN PRIVATE KEY-----"), make([]byte, 1024*1024+1)} {
		_, _, failure := normalizeOptions(Options{Endpoints: []string{"localhost:1"}, Anonymous: true, CA: ca})
		check(failure != nil && failure.Code == CodeInput && failure.Effect == Unapplied, "invalid trust lost its rejection evidence")
	}
	_, certificate := fixtureCertificate(t)
	settings, trust, failure := normalizeOptions(Options{Endpoints: []string{"localhost:1"}, Anonymous: true, CA: certificate})
	check(failure == nil && settings.CA == nil && trust != nil && trust.RootCAs != nil, "valid public certificate was not owned")
	before := trust.RootCAs.Clone()
	clear(certificate)
	check(trust.RootCAs.Equal(before), "changing caller PEM mutated installed trust")
}

// TestReadOptionsLimits distinguishes defaults, explicit inclusive bounds and invalid multiplicity.
func TestReadOptionsLimits(t *testing.T) {
	t.Parallel()
	check := oracle(t, "COMET-GO-INPUT")
	for _, supplied := range [][]ReadOptions{nil, {{}}, {{Bytes: 16384, Records: 1}}, {{Bytes: 1024 * 1024 * 1024, Records: 65536}}} {
		settings, failure := normalizeRead(supplied)
		check(failure == nil, "valid read capacity rejected")
		if len(supplied) == 0 || supplied[0] == (ReadOptions{}) {
			check(settings == (ReadOptions{Bytes: 64 * 1024 * 1024, Records: 65536}), "read defaults changed")
		} else {
			check(settings == supplied[0], "explicit read bounds changed")
		}
	}
	for _, supplied := range [][]ReadOptions{{{}, {}}, {{Bytes: 16383}}, {{Bytes: 1024*1024*1024 + 1}}, {{Records: -1}}, {{Records: 65537}}} {
		_, failure := normalizeRead(supplied)
		check(failure != nil && failure.Code == CodeInput && failure.Effect == Unapplied, "invalid read capacity lost its rejection evidence")
	}
}
