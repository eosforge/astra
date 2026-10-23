// Verify native account-file admission failures and recovery with owned, public fixture material.
//go:build linux

package web

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestAccountAccess requires native permission and symlink rejection without publishing a partial account.
func TestAccountAccess(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Fatal("account permission verification requires an unprivileged owner")
	}
	for _, name := range []string{"permission", "symlink"} {
		t.Run(name, func(t *testing.T) {
			check := counter(t)
			path := filepath.Join(t.TempDir(), "account.json")
			const data = `{"username":"admin","salt":"00000000000000000000000000000000","hash":"0000000000000000000000000000000000000000000000000000000000000000"}`
			check(os.WriteFile(path, []byte(data), 0600) == nil, "could not prepare public account material")
			input := path
			if name == "permission" {
				check(os.Chmod(path, 0) == nil, "could not deny access to the owned account file")
				t.Cleanup(func() {
					if err := os.Chmod(path, 0600); err != nil {
						t.Error("could not restore owned account permissions", err)
					}
				})
			} else {
				input = filepath.Join(filepath.Dir(path), "alias.json")
				check(os.Symlink(path, input) == nil, "could not create owned account alias")
			}
			for range 2 {
				value, err := LoadAccount(input)
				check(value == nil && errors.Is(err, errInput), "invalid file admission published an account or leaked an operating-system error")
			}
			if name == "permission" {
				check(os.Chmod(path, 0600) == nil, "could not restore native account access")
			}
			value, err := LoadAccount(path)
			check(err == nil && value != nil, "file admission failure prevented subsequent valid loading")
			check(value.username == "admin" && value.salt == [16]byte{} && value.hash == [32]byte{}, "recovery changed public account bytes")
		})
	}
}
