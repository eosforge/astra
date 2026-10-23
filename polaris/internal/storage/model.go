// Package storage implements Polaris's sole authority store without exposing GORM or gRPC types.
package storage

import (
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

// Stable errors express storage semantics; RPC mapping is separate and exposes no SQL, paths, or payloads.
var (
	ErrInput       = errors.New("invalid almanac input")              // Invalid Scope, Key, version, or payload shape.
	ErrVersion     = errors.New("almanac version conflict")           // Version gap or differing content at the same version.
	ErrHistory     = errors.New("almanac history unavailable")        // Continuous retained history is unavailable.
	ErrUncertain   = errors.New("almanac commit cannot be confirmed") // Original commit cannot be confirmed after history loss.
	ErrCapacity    = errors.New("almanac capacity exhausted")         // Scope, record, byte, or preparation budget exhausted.
	ErrClosed      = errors.New("almanac storage closed")             // Storage has closed.
	ErrCorrupt     = errors.New("almanac database invalid")           // Database counters or value types are corrupt.
	ErrBinding     = errors.New("almanac deployment mismatch")        // Recovered deployment binding differs from expected identity.
	ErrUnavailable = errors.New("almanac storage unavailable")        // Storage/SQL operation unavailable.
)

// Version uses a fixed eight-byte big-endian BLOB, preserving uint64 range and SQLite lexical index order.
type Version uint64

// Value returns an independent BLOB without signed or floating-point conversion of high versions.
func (version Version) Value() (driver.Value, error) {
	return binary.BigEndian.AppendUint64(nil, uint64(version)), nil
}

// Scan requires an eight-byte BLOB, rejecting SQLite dynamic coercion and preserving prior value on failure.
func (version *Version) Scan(input any) error {
	bytes, ok := input.([]byte)
	if !ok || len(bytes) != 8 {
		return ErrCorrupt
	}
	*version = Version(binary.BigEndian.Uint64(bytes))
	return nil
}

// Scope matches independent Sector/Spectrum UTF-8 bytes exactly, without joining paths.
type Scope struct {
	Sector   string // First group, 1..128 bytes; __ prefix is internal.
	Spectrum string // Second group, 1..128 bytes.
}

// Valid permits internal __ groups; public business entries enforce access restrictions separately.
func (scope Scope) Valid() bool {
	return text(scope.Sector, 128) && text(scope.Spectrum, 128)
}

// Binding fixes the initially initialized deployment, without passwords or process IDs.
type Binding struct {
	Galaxy    string // Immutable initialized Galaxy.
	Username  string // Immutable infrastructure account.
	Advertise string // Immutable advertised address.
}

// Limits bounds one database; defaults are 64 MiB/65536 records per Scope and 256 MiB total active payload.
// Zero History or Backlog disables delta retention; other capacities and Timeout must be positive.
type Limits struct {
	Scopes  int64         // Maximum Scope count.
	Records int64         // Maximum records per Scope.
	Bytes   int64         // Maximum bytes per Scope.
	Total   int64         // Maximum database active bytes.
	History int64         // Retained history entries per Scope; zero disables.
	Backlog int64         // Retained history bytes per Scope; zero disables.
	Timeout time.Duration // Single database-operation timeout.
	WAL     int64         // WAL checkpoint threshold in bytes.
}

// Default returns engineering defaults, not protocol limits or RSS/disk guarantees.
func Default() Limits {
	return Limits{Scopes: 4096, Records: 65536, Bytes: 64 << 20, Total: 256 << 20, History: 1000, Backlog: 8 << 20, Timeout: 5 * time.Second, WAL: 128 << 20}
}

// valid rejects accounting overflow/unbounded queries and caps one database operation at 30 seconds.
func (limits Limits) valid() bool {
	return limits.Scopes > 0 && limits.Scopes <= 16384 && limits.Records > 0 && limits.Records <= 1<<20 && limits.Bytes > 0 && limits.Bytes <= 1<<30 && limits.Total >= limits.Bytes && limits.Total <= 4<<30 && limits.History >= 0 && limits.History <= 65536 && limits.Backlog >= 0 && limits.Backlog <= 64<<20 && limits.Timeout > 0 && limits.Timeout <= 30*time.Second && limits.WAL >= 1<<20 && limits.WAL <= 4<<30
}

// Change is one authority commit; Erase differs from zero-byte Set. Empty Key denotes internal complete-batch encoding decoded by Entries.
type Change struct {
	Version Version // Expected version must be current+1 except confirmed replay.
	Key     string  // Ordinary Key is valid 1..1024-byte text; internal batch-history Key is empty.
	Value   []byte  // One value is at most 1 MiB; complete encoded batches have no separate total cap. Delete requires empty payload.
	Erase   bool    // Deletion flag, exclusive with Set.
}

// Record is a complete current value; empty Value still means present.
type Record struct {
	Key   string // Record Key.
	Value []byte // Current payload, including valid zero-byte Set.
}

// Position identifies a committed Scope; empty Scopes retain their version.
type Position struct {
	Scope           // Committed Scope.
	Version Version // Committed version.
}

// Snapshot version and records come from one finite read transaction, retaining no SQL connection/cursor after return.
type Snapshot struct {
	Position          // Snapshot Scope/version.
	Records  []Record // Records from the same transaction as version.
}

// Replay is a complete continuous suffix; missing history returns ErrHistory without partial success.
type Replay struct {
	Version Version  // Final suffix version.
	Changes []Change // Contiguous changes with strictly +1 versions.
}

// text validates wire UTF-8 and byte bounds without case or Unicode normalization.
func text(value string, maximum int) bool {
	return len(value) > 0 && len(value) <= maximum && !strings.ContainsRune(value, 0) && utf8.ValidString(value)
}

// group is SQL-mapping state; charges, records, and history update within one transaction.
type group struct {
	Version  Version // Current Scope version.
	Records  int64   // Live record count.
	Bytes    int64   // Active Key and payload bytes.
	Retained int64   // Retained history count.
	Backlog  int64   // Retained history bytes.
}

// metadata avoids summing all Scopes on hot writes; startup revalidates persistent counters.
type metadata struct {
	Format    int64  // Database format version, currently 1.
	Galaxy    string // Initialized Galaxy.
	Username  string // Initialized infrastructure account.
	Advertise string // Initialized advertised address.
	Scopes    int64  // Total Scope count.
	Bytes     int64  // Total active database bytes.
}
