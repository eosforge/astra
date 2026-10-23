// Verify Linux file ownership, credential bounds and real certificate loading without deployment material.
package admission

import (
	"bytes"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// material copies only the public repository fixture into one owned temporary directory.
func material(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	for _, name := range []string{"ca.pem", "cert.pem", "key.pem", "admission.pub", "login.json"} {
		data, err := os.ReadFile(fixture("star-a/" + name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return directory
}

// TestLoadBoundaries uses real missing/nonregular/link/permission/size failures and malformed certificate material.
func TestLoadBoundaries(t *testing.T) {
	check := counter(t, "ADMISSION-IDENTITY-FILES")
	check(os.Geteuid() != 0, "permission oracle requires the configured unprivileged Linux runner")
	for scenario := range 14 {
		directory := material(t)
		value, err := Load(directory, "127.0.0.1:7443")
		check(err == nil && value != nil, "unchanged fixture failed before physical fault injection")
		advertise := "127.0.0.1:7443"
		healthy := false
		name, data := "", []byte(nil)
		switch scenario {
		case 0:
			advertise = "localhost:7443"
		case 1:
			if err := os.Remove(filepath.Join(directory, "ca.pem")); err != nil {
				t.Fatal(err)
			}
		case 2:
			path := filepath.Join(directory, "ca.pem")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
		case 3:
			path := filepath.Join(directory, "cert.pem")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			target, err := filepath.Abs(fixture("star-a/cert.pem"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		case 4:
			path := filepath.Join(directory, "key.pem")
			if err := os.Chmod(path, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.Chmod(path, 0600); err != nil {
					t.Error(err)
				}
			})
		case 5:
			name = "cert.pem"
			data, err = os.ReadFile(filepath.Join(directory, name))
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, bytes.Repeat([]byte(" "), 16385-len(data))...)
		case 6:
			name, data = "admission.pub", make([]byte, 31)
		case 7:
			name, data = "login.json", []byte{0xff}
		case 8:
			name, data = "cert.pem", []byte("invalid certificate")
		case 9:
			name = "key.pem"
			data, err = os.ReadFile(fixture("star-b/key.pem"))
			if err != nil {
				t.Fatal(err)
			}
		case 10:
			name, data = "ca.pem", []byte("invalid authority")
		case 11, 12:
			name = "cert.pem"
			data, err = os.ReadFile(filepath.Join(directory, name))
			if err != nil {
				t.Fatal(err)
			}
			if scenario == 11 {
				data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0xff}})...)
			} else {
				authority, err := os.ReadFile(filepath.Join(directory, "ca.pem"))
				if err != nil {
					t.Fatal(err)
				}
				data = append(data, authority...)
				healthy = true
			}
		case 13:
			advertise = "192.0.2.1:7443"
		}
		if name != "" {
			if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		value, err = Load(directory, advertise)
		if healthy {
			check(err == nil && value != nil && len(value.Server().Certificates[0].Certificate) >= 2, "valid explicit intermediate chain did not load")
		} else {
			check(value == nil && errors.Is(err, ErrIdentity), "physical material failure published a partial identity")
		}
	}
}
