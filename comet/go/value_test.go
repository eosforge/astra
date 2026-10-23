// Verify immutable payload ownership at the public byte boundaries.
package comet

import (
	"testing"
)

// TestValueOwnership checks both mutable boundaries, including valid empty bytes.
func TestValueOwnership(t *testing.T) {
	t.Parallel()
	check := oracle(t, "COMET-GO-INPUT")
	input := []byte("first")
	value := NewValue(input)
	input[0] = 'x'
	output := value.Bytes()
	output[1] = 'x'
	check(value.String() == "first" && value.Len() == 5 && NewValue(nil).Len() == 0, "Value leaked writable storage or confused empty data")
}
