//go:build linux && cgo

// Attack atomic batch decoding with native Go fuzzing and independent wire-shape properties.
package storage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"unicode/utf8"
)

// FuzzEntries rejects partial failures and independently re-encodes every accepted batch.
// Native Go persists minimized failing input; its pinned toolchain, corpus and log identify a campaign.
func FuzzEntries(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("AB02"))
	f.Add([]byte{'A', 'B', '0', '2', 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 'k', 'v'})
	f.Add([]byte{'A', 'B', '0', '2', 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 'k'})
	f.Fuzz(func(t *testing.T, data []byte) {
		entries, err := (Change{Version: 7, Value: data}).Entries()
		if err != nil {
			if !errors.Is(err, ErrInput) || len(entries) != 0 {
				t.Fatal("malformed input exposed partial entries or an unstable error")
			}
			return
		}
		if len(entries) == 0 || len(entries) > len(data)/8 {
			t.Fatal("accepted batch has an impossible cardinality")
		}
		seen := map[string]bool{}
		encoded := bytes.NewBufferString("AB02")
		if err := binary.Write(encoded, binary.BigEndian, uint64(len(entries))); err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.Version != 7 || len(entry.Key) == 0 || len(entry.Key) > 1024 || !utf8.ValidString(entry.Key) || seen[entry.Key] || len(entry.Value) > 1<<20 || entry.Erase && len(entry.Value) != 0 {
				t.Fatal("accepted entry violates the independent wire contract")
			}
			seen[entry.Key] = true
			if err := binary.Write(encoded, binary.BigEndian, uint16(len(entry.Key))); err != nil {
				t.Fatal(err)
			}
			if err := binary.Write(encoded, binary.BigEndian, uint32(len(entry.Value))); err != nil {
				t.Fatal(err)
			}
			flag := byte(0)
			if entry.Erase {
				flag = 1
			}
			encoded.WriteByte(flag)
			encoded.WriteString(entry.Key)
			encoded.Write(entry.Value)
		}
		if !bytes.Equal(encoded.Bytes(), data) {
			t.Fatal("decoder accepted a noncanonical or partially consumed batch")
		}
		if _, err := (Change{Value: append(bytes.Clone(data), 0)}).Entries(); !errors.Is(err, ErrInput) {
			t.Fatal("trailing bytes were accepted")
		}
	})
}
