// Define immutable payloads, public scopes and successful write receipts.
package comet

import "strings"

// Scope identifies two byte-exact UTF-8 names, each 1..128 bytes. Sector cannot
// start with __. Names are not paths and undergo no Unicode normalization.
type Scope struct {
	Sector   string // Public business sector.
	Spectrum string // Exact group within the sector.
}

// Value owns immutable bytes. Its zero value is a valid empty payload; absence
// is represented separately. Values may be copied and retained concurrently.
type Value struct {
	data string // Immutable storage, never a writable alias of application data.
}

// NewValue copies data, including a nil slice as a valid empty payload.
func NewValue(data []byte) Value { return Value{data: string(data)} }

// Bytes returns an independent writable copy of the complete payload.
func (value Value) Bytes() []byte { return []byte(value.data) }

// String returns the unchanged immutable bytes as a string, without decoding.
func (value Value) String() string { return value.data }

// Len reports the payload's byte length, not a Unicode character count.
func (value Value) Len() int { return len(value.data) }

// cloneScope makes a small independent binding even when names are substrings
// of a much larger application string.
func cloneScope(scope Scope) Scope {
	return Scope{Sector: strings.Clone(scope.Sector), Spectrum: strings.Clone(scope.Spectrum)}
}

// Entry is a complete Catalog value. Update copies admitted Data before sending;
// callers must not mutate input slices concurrently with that call. Nil is empty,
// not deletion. An atomic batch contains 1..128 distinct keys and at most 1 MiB.
type Entry struct {
	Key  string // UTF-8 text, 1..1024 bytes, without NUL.
	Data []byte // Opaque complete bytes; the SDK does not choose a codec.
}

// Receipt confirms a Catalog commit at one Star, not cluster replication.
type Receipt struct {
	Instance string // Actual accepting Star instance.
	Version  uint64 // Internally assigned positive version, for diagnostics only.
}

// Identity identifies an owned Beacon registration without exposing capability.
type Identity struct {
	Scope    Scope  // Fixed original registration scope.
	Instance string // Star that most recently acknowledged registration.
	ID       string // Opaque 16-byte UUID, not printable text; may contain NUL.
}

// BeaconReceipt confirms one Data update under its captured registration.
type BeaconReceipt struct {
	Identity Identity // Does not change when the Beacon later recovers elsewhere.
	Order    uint64   // Internally issued positive Data sequence.
}

// Record combines fixed Ephemeris attributes with complete dynamic data.
type Record struct {
	Attr Value // Registration attributes, unchanged by Data-only updates.
	Data Value // Authoritative data or a controlled Observer local estimate.
}
