// Store immutable views with bucket-level copy-on-write publication.
package comet

import (
	"hash/maphash"
	"maps"
)

// Phase describes local observation or registration state, never global liveness.
type Phase uint8

const (
	Waiting    Phase = iota // No complete baseline/registration has been installed.
	Ready                   // Complete content or a conservatively confirmed lease exists.
	Stale                   // Last complete content remains usable with a known stream failure.
	Recovering              // An existing Beacon is restoring its identity.
	Uncertain               // A Beacon may exist remotely but its local lease is unconfirmed.
	Failed                  // A permanent failure pauses this object's automatic work.
	Closed                  // Local work stopped; retained snapshots remain readable.
)

// View captures read state and a complete Map at one local boundary. Error is a
// private copy. HasVersion distinguishes an absent baseline from an empty one.
type View struct {
	Phase      Phase  // Current local synchronization state.
	Scope      Scope  // Fixed scope of this subscription.
	Target     string // Empty for the whole scope, otherwise the exact key/ID.
	Instance   string // Instance of the last complete baseline, empty before one exists.
	Version    uint64 // Complete Watch cursor, not a Catalog key's business version.
	HasVersion bool   // Zero is a valid initialized empty-baseline cursor.
	Error      *Error // Sanitized most recent failure, independently owned.
	Data       Map    // Immutable complete content; may remain stale after disconnection.
}

// Map owns an immutable logical dictionary. Copying it or receiving a callback
// never copies every record. Iteration order is unspecified, not a selection policy.
type Map struct {
	root *snapshot // Retained independently of the subscription and Client.
}

// Len reports records in this fixed snapshot; the zero Map is empty.
func (values Map) Len() int {
	if values.root == nil {
		return 0
	}
	return values.root.data.count
}

// Get returns immutable Data and explicit presence; empty Data is still present.
func (values Map) Get(key string) (Value, bool) {
	if values.root != nil {
		if record := values.root.data.find(key); record != nil {
			return record.data, true
		}
	}
	return Value{}, false
}

// Range visits this fixed snapshot until visit returns false. It runs on the
// caller, without SDK locks. A panic propagates normally to that caller.
func (values Map) Range(visit func(string, Value) bool) {
	if values.root == nil || visit == nil {
		return
	}
	values.root.data.each(func(key string, record *row) bool { return visit(key, record.data) })
}

// row is immutable once inserted. Its pointer also fences Observer authority and
// local estimate changes without confusing equal bytes with equal generations.
type row struct {
	attr      Value  // Used only by Ephemeris rows.
	data      Value  // Complete opaque value.
	version   uint64 // Catalog business version, otherwise zero.
	authority *row   // Non-nil only for a local estimate of this authoritative row.
}

// footprint includes conservative owned map/key/record overhead, not an RSS limit.
func footprint(key string, record *row) int64 {
	if record == nil {
		return 0
	}
	return int64(len(key)+record.attr.Len()+record.data.Len()) + 192
}

// table is an immutable root of independently copied hash buckets.
type table struct {
	pages [64]map[string]*row // A changed draft clones a bucket at most once.
	seed  maphash.Seed        // Random hashing prevents adversarial fixed bucket selection.
	count int                 // Current logical record count.
	bytes int64               // Conservative complete-root storage charge.
}

// emptyTable starts an independent immutable root with a valid hash seed.
func emptyTable() table { return table{seed: maphash.MakeSeed(), bytes: 1024} }

// find borrows an immutable row; callers retain its root or the row itself.
func (contents *table) find(key string) *row {
	if contents.count == 0 {
		return nil
	}
	return contents.pages[maphash.String(contents.seed, key)%64][key]
}

// each visits borrowed immutable rows without requiring a map copy or lock.
func (contents *table) each(visit func(string, *row) bool) {
	for _, page := range contents.pages {
		for key, record := range page {
			if !visit(key, record) {
				return
			}
		}
	}
}

// draft owns only its changed buckets; unchanged buckets remain shared with base.
type draft struct {
	data  table    // Prospective root, never published before complete validation.
	dirty [64]bool // Prevent repeated bucket copying within one atomic batch.
}

// newDraft copies a small root but none of its immutable entries.
func newDraft(base table) *draft { return &draft{data: base} }

// sizeAfter predicts the logical footprint before allocations/mutations occur.
func (candidate *draft) sizeAfter(key string, value *row) int64 {
	return candidate.data.bytes - footprint(key, candidate.data.find(key)) + footprint(key, value)
}

// set changes one private bucket; value nil means erase. Caller has reserved its
// preparation budget. A completed draft must not be mutated after publication.
func (candidate *draft) set(key string, value *row) {
	index := maphash.String(candidate.data.seed, key) % 64
	page := candidate.data.pages[index]
	old := page[key]
	if old == nil && value == nil {
		return
	}
	if !candidate.dirty[index] {
		page = maps.Clone(page)
		if page == nil {
			page = make(map[string]*row)
		}
		candidate.data.pages[index], candidate.dirty[index] = page, true
	}
	candidate.data.bytes += footprint(key, value) - footprint(key, old)
	if value == nil {
		delete(page, key)
		candidate.data.count--
	} else {
		page[key] = value
		if old == nil {
			candidate.data.count++
		}
	}
}

// snapshot binds one complete root to its accepted instance and recovery cursor.
type snapshot struct {
	data     table          // Complete immutable record root.
	instance string         // Actual target that produced the complete cursor.
	version  uint64         // Watch cursor or Almanac floor; zero is a valid empty baseline.
	token    *snapshotToken // Callback deduplication never retains an old content root.
}

// snapshotToken is a nonzero-sized identity independent of a snapshot's storage.
type snapshotToken struct{ marker byte }
