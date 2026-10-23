// Demonstrate the exported immutable-value and explicit-presence API from another package.
package comet_test

import (
	"fmt"

	"github.com/eosforge/astra/comet/go"
)

// ExampleValue shows independent ownership at both byte-slice boundaries.
func ExampleValue() {
	input := []byte("ready")
	value := comet.NewValue(input)
	input[0] = 'x'
	copy := value.Bytes()
	copy[0] = 'y'
	fmt.Println(value.String())
	// Output: ready
}

// ExampleMap shows that absence is a Boolean, independent of a value's byte length.
func ExampleMap() {
	var snapshot comet.Map
	value, present := snapshot.Get("missing")
	fmt.Println(snapshot.Len(), value.Len(), present)
	// Output: 0 0 false
}
