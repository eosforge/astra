// Verify Polaris command configuration and startup validation boundaries.

package main

import (
	"errors"
	"flag"
	"testing"
)

// TestParse checks shared Polaris/Astrolabe duplicate-option rejection at this command entry.
func TestParse(t *testing.T) {
	base := []string{"--listen=127.0.0.1:9553", "--super=127.0.0.1:9554", "--galaxy=test"}
	if config, err := parse(base); err != nil || config.advertise != config.listen || config.initialize {
		t.Fatal("valid Polaris configuration rejected")
	}
	for _, extra := range [][]string{{"--listen=127.0.0.1:9555"}, {"--init", "--init=false"}, {"--snapshot-bytes=1"}, {"--unknown=1"}, {"positional"}} {
		if _, err := parse(append(append([]string{}, base...), extra...)); err == nil {
			t.Fatalf("invalid options accepted: %v", extra)
		}
	}
}

// TestOptions checks each independent deployment constraint and both inclusive budget limits.
func TestOptions(t *testing.T) {
	base := []string{"--listen=127.0.0.1:9553", "--super=127.0.0.1:9554", "--galaxy=test"}
	for _, test := range []struct {
		name string   // Stable boundary identity.
		args []string // Complete arguments, without hidden defaults from another case.
		ok   bool     // Whether the deployment contract admits the input.
	}{
		{"missing-listen", base[1:], false},
		{"missing-super", []string{base[0], base[2]}, false},
		{"missing-galaxy", base[:2], false},
		{"hostname", []string{"--listen=localhost:9553", base[1], base[2]}, false},
		{"wildcard", []string{"--listen=0.0.0.0:9553", base[1], base[2]}, false},
		{"advertise", append(append([]string{}, base...), "--advertise=127.0.0.1:9556"), true},
		{"advertise-invalid", append(append([]string{}, base...), "--advertise=localhost:9556"), false},
		{"galaxy", []string{base[0], base[1], "--galaxy="}, false},
		{"group", append(append([]string{}, base...), "--group="), false},
		{"state", append(append([]string{}, base...), "--state="), false},
		{"identity", append(append([]string{}, base...), "--identity="), false},
		{"lower", append(append([]string{}, base...), "--snapshot-bytes=83886080"), true},
		{"below", append(append([]string{}, base...), "--snapshot-bytes=83886079"), false},
		{"upper", append(append([]string{}, base...), "--snapshot-bytes=1073741824"), true},
		{"above", append(append([]string{}, base...), "--snapshot-bytes=1073741825"), false},
		{"overflow", append(append([]string{}, base...), "--snapshot-bytes=9223372036854775808"), false},
		{"initialize", append(append([]string{}, base...), "--init"), true},
		{"ipv6", []string{"--listen=[::1]:9553", "--super=[::1]:9554", "--galaxy=test"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, err := parse(test.args)
			if (err == nil) != test.ok {
				t.Fatalf("configuration admission = %v, want %v: %v", err == nil, test.ok, err)
			}
			if err != nil && config != (options{}) {
				t.Fatal("rejected options exposed partial deployment state")
			}
			if test.ok && (config.listen == "" || config.advertise == "" || config.super == "" || config.galaxy != "test" || config.group != "default") {
				t.Fatal("accepted deployment lost an explicit endpoint or default")
			}
			if test.name == "advertise" && config.advertise != "127.0.0.1:9556" || test.name == "initialize" && !config.initialize {
				t.Fatal("explicit option was silently ignored")
			}
		})
	}
	if config, err := parse([]string{"--help"}); !errors.Is(err, flag.ErrHelp) || config != (options{}) {
		t.Fatal("help requires neither deployment configuration nor a partial result", err)
	}
}
