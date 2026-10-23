// Verify Astrolabe command configuration and startup validation boundaries.

package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"testing"
)

// TestParse checks cold configuration without reading credentials or starting network connections.
func TestParse(t *testing.T) {
	base := []string{"--listen=127.0.0.1:8553", "--super=127.0.0.1:8554", "--galaxy=test", "--account=account.json", "--public=https://admin.example"}
	if config, err := parse(base); err != nil || config.advertise != config.listen || config.group != "default" {
		t.Fatal("valid deployment rejected")
	}
	for _, extra := range [][]string{
		{"--listen=127.0.0.1:8555"},
		{"--sessions=0"},
		{"--origins=*"},
		{"--origins=https://admin.example"},
		{"--origins=https://other.example,https://other.example"},
		{"--http=true", "--http=false"},
		{"positional"},
	} {
		if _, err := parse(append(append([]string{}, base...), extra...)); err == nil {
			t.Fatalf("invalid options accepted: %v", extra)
		}
	}
	if _, err := parse([]string{"--listen=192.168.0.5:8553", "--super=127.0.0.1:8554", "--galaxy=test", "--account=account.json", "--public=http://admin.example", "--http"}); err == nil {
		t.Fatal("non-loopback plaintext management accepted")
	}
	if _, err := parse(append(append([]string{}, base...), "--http", "--crosssite")); err != nil {
		t.Fatal("explicit HTTPS reverse-proxy deployment rejected")
	}
}

// TestOptions varies complete deployment arguments, never masking a boundary with duplicate flags.
func TestOptions(t *testing.T) {
	var origins []string
	for index := 0; index < 31; index++ {
		origins = append(origins, fmt.Sprintf("https://node%d.example", index))
	}
	for _, test := range []struct {
		name string   // Stable deployment boundary.
		args []string // Explicit replacements or additional switches.
		ok   bool     // Independent deployment expectation.
	}{
		{"minimum", []string{"--sessions=1"}, true},
		{"maximum", []string{"--sessions=4096"}, true},
		{"below", []string{"--sessions=0"}, false},
		{"above", []string{"--sessions=4097"}, false},
		{"listen", []string{"--listen=localhost:8553"}, false},
		{"advertise", []string{"--advertise=127.0.0.1:8555"}, true},
		{"advertise-invalid", []string{"--advertise=127.0.0.1:0"}, false},
		{"super", []string{"--super=localhost:8554"}, false},
		{"galaxy", []string{"--galaxy=bad/name"}, false},
		{"group", []string{"--group=bad/name"}, false},
		{"identity", []string{"--identity="}, false},
		{"account", []string{"--account="}, false},
		{"public", []string{"--public=https://admin.example/path"}, false},
		{"canonical", []string{"--public=https://ADMIN.example:443"}, true},
		{"plain", []string{"--http", "--public=http://admin.example"}, true},
		{"remote-plain", []string{"--listen=192.0.2.1:8553", "--http"}, false},
		{"plain-crosssite", []string{"--http", "--public=http://admin.example", "--crosssite"}, false},
		{"secure-crosssite", []string{"--http", "--crosssite"}, true},
		{"tls-public", []string{"--public=http://admin.example"}, false},
		{"origins-limit", []string{"--origins=" + strings.Join(origins, ",")}, true},
		{"origins-overflow", []string{"--origins=" + strings.Join(origins, ",") + ",https://overflow.example"}, false},
		{"origins-empty", []string{"--origins=https://other.example,"}, false},
		{"origins-duplicate", []string{"--origins=https://ADMIN.example:443"}, false},
		{"unknown", []string{"--unknown=1"}, false},
		{"positional", []string{"extra"}, false},
		{"help", []string{"--help"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			check := counter(t)
			args := []string{"--listen=127.0.0.1:8553", "--super=127.0.0.1:8554", "--galaxy=entry", "--account=account.json", "--public=https://admin.example"}
			for _, extra := range test.args {
				key, _, _ := strings.Cut(extra, "=")
				replaced := false
				for index, old := range args {
					if strings.HasPrefix(old, key+"=") {
						args[index], replaced = extra, true
						break
					}
				}
				if !replaced {
					args = append(args, extra)
				}
			}
			config, err := parse(args)
			if test.name == "help" {
				check(errors.Is(err, flag.ErrHelp), "help was not distinguished from configuration failure")
			} else {
				check((err == nil) == test.ok, "deployment boundary disagrees with its fixed expectation")
				if test.ok {
					check(config.sessions >= 1 && config.sessions <= 4096 && config.advertise != "", "accepted configuration omitted bounded defaults")
					if test.name == "canonical" {
						check(config.public == "https://admin.example", "public origin was not canonicalized")
					}
				}
			}
		})
	}
}
