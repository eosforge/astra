// Package web provides bounded management HTTP endpoints with browser authentication separate from Pulsar node identity.
package web

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"unicode/utf8"

	"github.com/eosforge/astra/internal/admission"
)

// Account stores one configured management account's digest, never a plaintext password or usable default account.
type Account struct {
	username string
	salt     [16]byte // Random 16-byte salt stored with the digest.
	hash     [32]byte // 32-byte PBKDF2 digest; the original password is not retained.
}

var errInput = errors.New("invalid management configuration or input")

// object accepts scalar fields and explicitly allowed arrays of scalar objects; deeper nesting is rejected.
// Decode data into target, rejecting duplicate or unknown fields, invalid UTF-8 and trailing documents.
func object(data []byte, target any, arrays ...string) error {

	if !utf8.Valid(data) {
		return errInput
	}
	// Check unique field names at the top level and in each array item; each object has at most 16 fields, without an array-length limit here.
	decoder := json.NewDecoder(bytes.NewReader(data))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return errInput
	}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] || len(seen) >= 16 {
			return errInput
		}
		seen[name] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil || len(value) == 0 || value[0] == '{' {
			return errInput
		}
		if value[0] == '[' {
			allowed := false
			for _, field := range arrays {
				allowed = allowed || field == name
			}
			if !allowed {
				return errInput
			}
			var entries []json.RawMessage
			if json.Unmarshal(value, &entries) != nil {
				return errInput
			}
			for _, entry := range entries {
				var fields map[string]json.RawMessage
				if object(entry, &fields) != nil {
					return errInput
				}
			}
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return errInput
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errInput
	}

	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errInput
	}
	return nil
}

// accountFile owns the read/stat/close boundary of one management account input.
type accountFile interface {
	io.Reader
	Stat() (os.FileInfo, error)
	Close() error
}

// LoadAccount reads one bounded regular account file without generating deployment defaults.
func LoadAccount(path string) (*Account, error) {
	return loadAccount(path, os.Lstat, func(name string) (accountFile, error) { return admission.Acquire(name) })
}

// loadAccount keeps injected file operations local to the owning load call.
func loadAccount(path string, inspect func(string) (os.FileInfo, error), open func(string) (accountFile, error)) (*Account, error) {
	// Retain native metadata so a regular replacement cannot pass the later handle check.
	before, err := inspect(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, errInput
	}
	file, err := open(path)
	if err != nil {
		return nil, errInput
	}
	// Never read an unverified handle; every successful open has exactly one close attempt.
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(before, info) {
		_ = file.Close()
		return nil, errInput
	}
	// Read at most 4 KiB; the account file contains three short hexadecimal fields.
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	closed := file.Close()
	if err != nil || closed != nil || len(data) > 4096 {
		return nil, errInput
	}
	var input struct {
		Username string `json:"username"`
		Salt     string `json:"salt"`
		Hash     string `json:"hash"`
	}
	if object(data, &input) != nil || !admission.Name(input.Username) {
		return nil, errInput
	}
	// Require exact hexadecimal salt and digest lengths of 16 and 32 bytes.
	salt, one := hex.DecodeString(input.Salt)
	hash, two := hex.DecodeString(input.Hash)
	if one != nil || two != nil || len(salt) != 16 || len(hash) != 32 {
		return nil, errInput
	}
	return &Account{username: input.Username, salt: [16]byte(salt), hash: [32]byte(hash)}, nil
}

// verify uses PBKDF2-HMAC-SHA256/600000/32 like Pulsar, including the full derivation for an unknown username.
func (account *Account) verify(username, password string) bool {
	derived, err := pbkdf2.Key(sha256.New, password, account.salt[:], 600000, len(account.hash))
	defer clear(derived)
	return err == nil && subtle.ConstantTimeCompare(derived, account.hash[:]) == 1 && username == account.username
}
