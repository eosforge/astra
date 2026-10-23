// Verify authority identity names against an independent ASCII alphabet and byte-length boundary.
//go:build linux && cgo

package storage

import (
	"fmt"
	"strings"
	"testing"
)

// TestNames checks every byte alone and at every position in a maximum-length name, including invalid UTF-8.
func TestNames(t *testing.T) {
	check := verification(t, "STORAGE-NAMES")
	const alphabet = ".-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"
	check(!name(""), "an authority identity must be nonempty")
	check(name("a"), "a one-byte identity is valid")
	check(name(strings.Repeat("a", 64)), "the 64-byte boundary is inclusive")
	check(!name(strings.Repeat("a", 65)), "a 65-byte identity exceeds the contract")

	// The literal alphabet is the product contract, independent of the production range predicates.
	for value := 0; value < 256; value++ {
		char := byte(value)
		allowed := strings.IndexByte(alphabet, char) >= 0
		check(name(string([]byte{char})) == allowed, fmt.Sprintf("single byte %02x", char))
		for position := 0; position < 64; position++ {
			input := []byte(strings.Repeat("a", 64))
			input[position] = char
			check(name(string(input)) == allowed, fmt.Sprintf("byte %02x at position %d", char, position))
		}
	}

	// Valid Unicode still lies outside the ASCII contract; the check is not merely a UTF-8 validator.
	for _, value := range []string{"é", "カ", "a🙂b"} {
		check(!name(value), "a valid Unicode name must be rejected")
	}
}
