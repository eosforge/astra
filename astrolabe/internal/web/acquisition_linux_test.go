// Check account replacement and I/O refusal without publishing credentials or relying on wall-clock races.
package web

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/eosforge/astra/internal/admission"
)

// accountInput retains a real handle while observing and selectively failing its owning operations.
type accountInput struct {
	*os.File
	fault         string
	reads, closes int
}

// Read records whether an unverified handle was consumed and can inject a native-shaped read refusal.
func (input *accountInput) Read(data []byte) (int, error) {
	input.reads++
	if input.fault == "read" {
		return 0, io.ErrUnexpectedEOF
	}
	return input.File.Read(data)
}

// Stat exposes a controlled post-open metadata failure.
func (input *accountInput) Stat() (os.FileInfo, error) {
	if input.fault == "stat" {
		return nil, os.ErrPermission
	}
	return input.File.Stat()
}

// Close physically releases the descriptor before reporting the injected close failure.
func (input *accountInput) Close() error {
	input.closes++
	err := input.File.Close()
	if input.fault == "close" {
		return os.ErrPermission
	}
	return err
}

// TestAccountAcquisition rejects substitution and each owned I/O failure, then loads the restored file.
func TestAccountAcquisition(t *testing.T) {
	const data = `{"username":"operator","salt":"000102030405060708090a0b0c0d0e0f","hash":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"}`
	for _, fault := range []string{"replacement", "stat", "read", "close"} {
		t.Run(fault, func(t *testing.T) {
			hits := 0
			check := func(value bool, message string) {
				t.Helper()
				if !value {
					t.Fatal(message)
				}
				hits++
			}
			t.Cleanup(func() { t.Logf(`ASTRA-CONTRACT {"contract":"ASTROLABE-BOUNDARY","hits":%d}`, hits) })
			path := filepath.Join(t.TempDir(), "account.json")
			check(os.WriteFile(path, []byte(data), 0600) == nil, "could not prepare account")
			var stream *accountInput
			open := func(name string) (accountFile, error) {
				if fault == "replacement" {
					if err := os.Rename(name, name+".held"); err != nil {
						return nil, err
					}
					if err := os.WriteFile(name, []byte(data), 0600); err != nil {
						return nil, err
					}
				}
				file, err := admission.Acquire(name)
				if err != nil {
					return nil, err
				}
				stream = &accountInput{File: file, fault: fault}
				t.Cleanup(func() { _ = file.Close() })
				return stream, nil
			}
			account, err := loadAccount(path, os.Lstat, open)
			check(errors.Is(err, errInput) && account == nil, "failed acquisition published an account")
			check(stream != nil && stream.closes == 1, "account handle was not closed once")
			if fault == "replacement" || fault == "stat" {
				check(stream.reads == 0, "unverified account handle was read")
			}
			_, err = stream.File.Stat()
			check(errors.Is(err, os.ErrClosed), "physical account handle remains open")
			if fault == "replacement" {
				check(os.Remove(path) == nil && os.Rename(path+".held", path) == nil, "could not restore account")
			}
			account, err = LoadAccount(path)
			check(err == nil && account != nil && account.username == "operator", "valid account did not recover")
		})
	}
}
