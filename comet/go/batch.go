// Validate private protocol pages and atomically assemble complete read snapshots.
package comet

import (
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// action identifies a normalized oneof branch without treating absence as erase.
type action uint8

const (
	absent  action = iota // No usable oneof branch was present in the received message.
	replace               // Complete Almanac/Catalog value or complete Ephemeris record.
	erase                 // Explicit deletion, legal only in an apply batch.
	adjust                // Ephemeris Data-only replacement, preserving authoritative Attr.
)

// domain selects actual business recovery semantics without exposing wire types.
type domain uint8

const (
	almanac   domain = iota // Authoritative group cursor cannot regress across instances.
	catalog                 // Per-key versions and target-local Watch cursor are distinct.
	ephemeris               // Full records or Data-only deltas for stable binary IDs.
)

// mutation is a borrowed, validated-shape adapter input, owned by one received page.
type mutation struct {
	key     string // Borrowed complete key or copied binary UUID from this page.
	data    []byte // Borrowed opaque body; copied only after candidate reservation.
	attr    []byte // Borrowed fixed Ephemeris attributes for complete records.
	kind    action // Validated oneof action, with absence represented independently.
	version uint64 // Positive Catalog body version, zero on erase/other domains.
}

// page carries presence independently from zero cursor and empty payloads.
type page struct {
	mode     protocol.Mode // Reset or apply, fixed across every page in one batch.
	complete bool          // Only a final page may replace the visible baseline.
	version  *uint64       // Presence is required exactly on the complete page.
	instance string        // Complete page's validated target identity.
	changes  []mutation    // Normalized page operations with independent oneof presence.
}

// pageBytes bounds protocol storage and normalization copies before allocation.
func pageBytes(message proto.Message) int64 {
	return int64(proto.Size(message))*2 + int64(messageCount(message))*256 + 1024
}

// decodePage adapts generated values without exposing aliases to application code.
// Missing oneof branches remain kind zero and fail normal protocol validation.
func decodePage(message proto.Message) page {
	result := page{changes: make([]mutation, 0, messageCount(message))}
	switch value := message.(type) {
	case *protocol.AlmanacWatchReply:
		result.mode, result.complete, result.version, result.instance = value.Mode, value.Complete, value.Version, string(value.Instance)
		for _, change := range value.Changes {
			if change == nil {
				result.changes = append(result.changes, mutation{})
				continue
			}
			entry := mutation{key: change.Key}
			switch action := change.Action.(type) {
			case *protocol.AlmanacChange_Value:
				entry.kind, entry.data = replace, action.Value
			case *protocol.AlmanacChange_Erase:
				if action.Erase != nil {
					entry.kind = erase
				}
			}
			result.changes = append(result.changes, entry)
		}
	case *protocol.CatalogWatchReply:
		result.mode, result.complete, result.version, result.instance = value.Mode, value.Complete, value.Version, string(value.Instance)
		for _, change := range value.Changes {
			if change == nil {
				result.changes = append(result.changes, mutation{})
				continue
			}
			entry := mutation{key: change.Key, version: change.Version}
			switch action := change.Action.(type) {
			case *protocol.CatalogChange_Value:
				entry.kind, entry.data = replace, action.Value
			case *protocol.CatalogChange_Erase:
				if action.Erase != nil {
					entry.kind = erase
				}
			}
			result.changes = append(result.changes, entry)
		}
	case *protocol.EphemerisWatchReply:
		result.mode, result.complete, result.version, result.instance = value.Mode, value.Complete, value.Version, string(value.Instance)
		for _, change := range value.Changes {
			if change == nil {
				result.changes = append(result.changes, mutation{})
				continue
			}
			entry := mutation{key: string(change.Uuid)}
			switch action := change.Action.(type) {
			case *protocol.EphemerisChange_Record_:
				if action.Record != nil {
					entry.kind, entry.attr, entry.data = replace, action.Record.Attr, action.Record.Data
				}
			case *protocol.EphemerisChange_Erase:
				if action.Erase != nil {
					entry.kind = erase
				}
			case *protocol.EphemerisChange_Data:
				entry.kind, entry.data = adjust, action.Data
			}
			result.changes = append(result.changes, entry)
		}
	}
	return result
}

// batch holds one unpublished multi-page candidate. Only a complete validated
// final page returns a snapshot; failure leaves current and its cursor unchanged.
type batch struct {
	domain    domain              // Selects semantic validation and version floor rules.
	target    string              // Whole scope when empty; otherwise every key must equal it.
	expected  string              // Captured binding target, initially empty for anonymous login.
	options   ReadOptions         // Finite installed/staging bounds.
	current   *snapshot           // Last complete baseline; never mutated by accept.
	candidate *draft              // Private bucket copies for this incomplete batch.
	first     bool                // Reset is legal only for the stream's first complete batch.
	fresh     bool                // Explicit history repair requires reset, not an apply to stale data.
	mode      protocol.Mode       // Latched batch mode; unspecified between batches.
	seen      map[string]struct{} // Duplicate detection across all pages of the batch.
	metadata  int64               // Conservative key/set storage charge in bytes.
	reserve   func(int64) bool    // Sets preparation charge; no application code.
}

// clear discards only unpublished state and its accounting, not the visible root.
func (assembly *batch) clear() {
	assembly.candidate, assembly.seen, assembly.metadata = nil, nil, 0
	assembly.mode = protocol.Mode_MODE_UNSPECIFIED
	if assembly.reserve != nil {
		assembly.reserve(0)
	}
}

// accept enforces page shape, identity, duplicate and capacity rules before commit.
func (assembly *batch) accept(input page) (*snapshot, *Error) {
	if input.mode != protocol.Mode_MODE_RESET && input.mode != protocol.Mode_MODE_APPLY ||
		input.complete != (input.version != nil) || input.complete != (input.instance != "") ||
		!input.complete && len(input.changes) == 0 {
		return nil, localError(CodeProtocol)
	}
	if input.complete {
		if !validText(input.instance, 128) || assembly.expected != "" && assembly.expected != input.instance {
			return nil, localError(CodeProtocol)
		}
		if assembly.current != nil && *input.version < assembly.current.version {
			if assembly.domain == almanac {
				return nil, localError(CodeVersion)
			}
			if assembly.current.instance == input.instance {
				return nil, localError(CodeProtocol)
			}
		}
	}
	if assembly.candidate == nil {
		if input.mode == protocol.Mode_MODE_RESET && !assembly.first || input.mode == protocol.Mode_MODE_APPLY && (assembly.current == nil || assembly.fresh) {
			return nil, localError(CodeProtocol)
		}
		base := emptyTable()
		if input.mode == protocol.Mode_MODE_APPLY {
			base = assembly.current.data
		}
		assembly.candidate, assembly.mode = newDraft(base), input.mode
		assembly.seen = make(map[string]struct{})
	} else if input.mode != assembly.mode {
		return nil, localError(CodeProtocol)
	}
	if input.complete && assembly.mode == protocol.Mode_MODE_APPLY &&
		(assembly.current.instance != input.instance ||
			*input.version == assembly.current.version && (!assembly.first || len(assembly.seen) != 0 || len(input.changes) != 0)) {
		return nil, localError(CodeProtocol)
	}
	for _, change := range input.changes {
		if assembly.domain == ephemeris && !validID(change.key) || assembly.domain != ephemeris && !validText(change.key, 1024) || assembly.target != "" && change.key != assembly.target {
			return nil, localError(CodeProtocol)
		}
		if _, duplicate := assembly.seen[change.key]; duplicate {
			return nil, localError(CodeProtocol)
		}
		if len(assembly.seen) >= assembly.options.Records*2 {
			return nil, localError(CodeLimit)
		}
		if len(change.data) > maxPayload || len(change.attr) > maxPayload {
			return nil, localError(CodeLimit)
		}
		// Validate semantics using existing immutable rows, before copying received bytes.
		old := assembly.candidate.data.find(change.key)
		if failure := assembly.validate(change, old); failure != nil {
			return nil, failure
		}
		var next *row
		if change.kind != erase {
			next = &row{version: change.version}
			// This provisional footprint is computed without allocating payload copies.
			projected := assembly.candidate.data.bytes - footprint(change.key, old) + int64(len(change.key)+len(change.data)+len(change.attr)) + 192
			if change.kind == adjust {
				projected += int64(old.attr.Len())
			}
			if !assembly.charge(projected, change.key) {
				return nil, localError(CodeLimit)
			}
			next.data, next.attr = NewValue(change.data), NewValue(change.attr)
			if change.kind == adjust {
				next.attr = old.attr
			}
		} else if !assembly.charge(assembly.candidate.sizeAfter(change.key, nil), change.key) {
			return nil, localError(CodeLimit)
		}
		owned := strings.Clone(change.key)
		assembly.seen[owned] = struct{}{}
		assembly.metadata += int64(len(owned)) + 96
		assembly.candidate.set(owned, next)
		if assembly.candidate.data.count > assembly.options.Records*2 {
			return nil, localError(CodeLimit)
		}
	}
	if !assembly.charge(assembly.candidate.data.bytes, "") {
		return nil, localError(CodeLimit)
	}
	if !input.complete {
		return nil, nil
	}
	if assembly.candidate.data.count > assembly.options.Records || assembly.candidate.data.bytes > assembly.options.Bytes {
		return nil, localError(CodeLimit)
	}
	if *input.version == 0 && assembly.candidate.data.count != 0 {
		return nil, localError(CodeProtocol)
	}
	return &snapshot{data: assembly.candidate.data, instance: input.instance, version: *input.version, token: &snapshotToken{}}, nil
}

// charge checks candidate/duplicate metadata and parent storage before mutation.
func (assembly *batch) charge(content int64, key string) bool {
	prepared := content + assembly.metadata + int64(len(key)) + 96
	return prepared <= assembly.options.Bytes*2 && (assembly.reserve == nil || assembly.reserve(prepared))
}

// validate keeps domain-specific invariants separate from generic page assembly.
func (assembly *batch) validate(change mutation, old *row) *Error {
	if change.kind == absent || change.kind > adjust || change.kind != replace && assembly.mode != protocol.Mode_MODE_APPLY {
		return localError(CodeProtocol)
	}
	if assembly.domain != ephemeris && change.kind == adjust {
		return localError(CodeProtocol)
	}
	if assembly.domain == catalog && (change.kind == replace && change.version == 0 || change.kind == erase && change.version != 0) {
		return localError(CodeProtocol)
	}
	if assembly.domain == ephemeris {
		if change.kind == adjust && old == nil {
			return localError(CodeHistory)
		}
		if change.kind == replace && assembly.mode == protocol.Mode_MODE_APPLY && old != nil && old.attr.data != string(change.attr) {
			return localError(CodeProtocol)
		}
	}
	return nil
}
