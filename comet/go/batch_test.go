// Verify atomic pagination, domain floors and malformed-stream rejection.
package comet

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// testBatch creates a receiver-local assembler with explicit content bounds.
func testBatch(kind domain, current *snapshot) batch {
	return batch{domain: kind, current: current, first: true, options: ReadOptions{Bytes: 16384, Records: 32}}
}

// TestBatchCapacityPreservesBaseline rejects byte/count/reservation pressure
// before publication and preserves the previously installed content and cursor.
func TestBatchCapacityPreservesBaseline(t *testing.T) {
	t.Parallel()
	base := newDraft(emptyTable())
	base.set("stable", &row{data: NewValue([]byte("before")), version: 1})
	root := &snapshot{data: base.data, instance: "star-a", version: 7}
	cases := []struct {
		name    string     // Independent capacity boundary exercised by this case.
		changes []mutation // Otherwise valid complete Catalog changes.
		reject  bool       // Fail the parent reservation adapter, rather than local limits.
	}{
		{name: "bytes", changes: []mutation{{key: "stable", kind: replace, version: 2, data: []byte(strings.Repeat("x", 16384))}}},
		{name: "records", changes: []mutation{{key: "second", kind: replace, version: 1}}},
		{name: "parent", changes: []mutation{{key: "stable", kind: replace, version: 2, data: []byte("after")}}, reject: true},
	}
	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			assembly := testBatch(catalog, root)
			assembly.options.Records = 1
			if testcase.reject {
				assembly.reserve = func(size int64) bool { return size == 0 }
			}
			next, failure := assembly.accept(page{
				mode: protocol.Mode_MODE_APPLY, complete: true, instance: "star-a", version: proto.Uint64(8), changes: testcase.changes,
			})
			if next != nil || failure == nil || failure.Code != CodeLimit {
				t.Fatalf("capacity rejection = %v, %v", next, failure)
			}
			assembly.clear()
			if root.version != 7 || root.data.count != 1 || root.data.find("stable").data.String() != "before" {
				t.Fatal("capacity rejection damaged committed content or cursor")
			}
		})
	}
}

// TestPagedAtomicity leaves the installed root/cursor untouched until the final page.
func TestPagedAtomicity(t *testing.T) {
	t.Parallel()
	assembly := testBatch(catalog, nil)
	partial := page{mode: protocol.Mode_MODE_RESET, changes: []mutation{{key: "a", kind: replace, version: 5, data: []byte("A")}}}
	if next, failure := assembly.accept(partial); failure != nil || next != nil || assembly.current != nil {
		t.Fatal("partial reset was installed")
	}
	final := page{mode: protocol.Mode_MODE_RESET, complete: true, instance: "star-a", version: proto.Uint64(19), changes: []mutation{{key: "b", kind: replace, version: 1}}}
	root, failure := assembly.accept(final)
	if failure != nil || root.data.count != 2 || root.version != 19 || root.data.find("b").data.Len() != 0 {
		t.Fatalf("complete batch failed: %v", failure)
	}
	assembly = testBatch(catalog, root)
	if next, failure := assembly.accept(page{mode: protocol.Mode_MODE_APPLY, changes: []mutation{{key: "a", kind: erase}}}); next != nil || failure != nil {
		t.Fatal("valid partial erase failed")
	}
	_, failure = assembly.accept(page{mode: protocol.Mode_MODE_APPLY, complete: true, instance: "star-a", version: proto.Uint64(20), changes: []mutation{{key: "a", kind: replace, version: 6}}})
	if failure == nil || root.data.find("a").data.String() != "A" || root.version != 19 {
		t.Fatal("duplicate across pages damaged the installed baseline")
	}
}

// TestBatchProtocolRejections exercises absent presence, target fencing and invalid domain operations.
func TestBatchProtocolRejections(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		kind   domain
		page   page
		target string
	}{
		{"missing-cursor", catalog, page{mode: protocol.Mode_MODE_RESET, complete: true, instance: "star-a"}, ""},
		{"early-instance", catalog, page{mode: protocol.Mode_MODE_RESET, instance: "star-a"}, ""},
		{"zero-nonempty", catalog, page{mode: protocol.Mode_MODE_RESET, complete: true, instance: "star-a", version: proto.Uint64(0), changes: []mutation{{key: "k", kind: replace, version: 1}}}, ""},
		{"missing-action", almanac, page{mode: protocol.Mode_MODE_RESET, complete: true, instance: "star-a", version: proto.Uint64(1), changes: []mutation{{key: "k"}}}, ""},
		{"zero-key-version", catalog, page{mode: protocol.Mode_MODE_RESET, complete: true, instance: "star-a", version: proto.Uint64(1), changes: []mutation{{key: "k", kind: replace}}}, ""},
		{"wrong-target", catalog, page{mode: protocol.Mode_MODE_RESET, complete: true, instance: "star-a", version: proto.Uint64(1), changes: []mutation{{key: "k", kind: replace, version: 1}}}, "other"},
		{"bad-uuid", ephemeris, page{mode: protocol.Mode_MODE_RESET, complete: true, instance: "star-a", version: proto.Uint64(1), changes: []mutation{{key: "text-id", kind: replace}}}, ""},
		{"reset-erase", almanac, page{mode: protocol.Mode_MODE_RESET, complete: true, instance: "star-a", version: proto.Uint64(1), changes: []mutation{{key: "k", kind: erase}}}, ""},
	}
	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			assembly := testBatch(testcase.kind, nil)
			assembly.target = testcase.target
			if next, failure := assembly.accept(testcase.page); next != nil || failure == nil || failure.Code != CodeProtocol {
				t.Fatalf("invalid page accepted: next=%v failure=%v", next, failure)
			}
		})
	}
}

// TestBatchStreamBoundaries uses prescribed stream histories to distinguish
// initial cursor confirmation from changed, stale or cross-instance content.
func TestBatchStreamBoundaries(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string // Invalid continuation of the fixed v7 baseline.
		first    bool   // Whether this is the first batch on a newly opened stream.
		fresh    bool   // Whether history repair requires a replacement baseline.
		expected string // Authenticated instance, when known before the first page.
		pages    []page // Complete prescribed page transcript, including any staging.
	}{
		{"unknown-mode", true, false, "", []page{{mode: protocol.Mode(99), complete: true, instance: "star-a", version: proto.Uint64(8)}}},
		{"empty-partial", true, false, "", []page{{mode: protocol.Mode_MODE_APPLY}}},
		{"early-cursor", true, false, "", []page{{mode: protocol.Mode_MODE_APPLY, version: proto.Uint64(8), changes: []mutation{{key: "stable", kind: erase}}}}},
		{"missing-instance", true, false, "", []page{{mode: protocol.Mode_MODE_APPLY, complete: true, version: proto.Uint64(8)}}},
		{"invalid-instance", true, false, "", []page{{mode: protocol.Mode_MODE_APPLY, complete: true, instance: "bad\x00instance", version: proto.Uint64(8)}}},
		{"unexpected-instance", true, false, "star-b", []page{{mode: protocol.Mode_MODE_RESET, complete: true, instance: "star-a", version: proto.Uint64(8)}}},
		{"regressed-cursor", true, false, "", []page{{mode: protocol.Mode_MODE_RESET, complete: true, instance: "star-a", version: proto.Uint64(6)}}},
		{"repeated-reset", false, false, "", []page{{mode: protocol.Mode_MODE_RESET, complete: true, instance: "star-a", version: proto.Uint64(8)}}},
		{"repair-needs-reset", true, true, "", []page{{mode: protocol.Mode_MODE_APPLY, complete: true, instance: "star-a", version: proto.Uint64(8)}}},
		{"cross-instance-apply", true, false, "", []page{{mode: protocol.Mode_MODE_APPLY, complete: true, instance: "star-b", version: proto.Uint64(8)}}},
		{"repeated-cursor", false, false, "", []page{{mode: protocol.Mode_MODE_APPLY, complete: true, instance: "star-a", version: proto.Uint64(7)}}},
		{"changed-same-cursor", true, false, "", []page{{mode: protocol.Mode_MODE_APPLY, complete: true, instance: "star-a", version: proto.Uint64(7), changes: []mutation{{key: "stable", kind: erase}}}}},
		{"staged-same-cursor", true, false, "", []page{{mode: protocol.Mode_MODE_APPLY, changes: []mutation{{key: "stable", kind: erase}}}, {mode: protocol.Mode_MODE_APPLY, complete: true, instance: "star-a", version: proto.Uint64(7)}}},
		{"changed-mode", true, false, "", []page{{mode: protocol.Mode_MODE_APPLY, changes: []mutation{{key: "stable", kind: erase}}}, {mode: protocol.Mode_MODE_RESET, complete: true, instance: "star-a", version: proto.Uint64(8)}}},
		{"invalid-key", true, false, "", []page{{mode: protocol.Mode_MODE_APPLY, complete: true, instance: "star-a", version: proto.Uint64(8), changes: []mutation{{key: "bad\x00key", kind: erase}}}}},
		{"catalog-data-only", true, false, "", []page{{mode: protocol.Mode_MODE_APPLY, complete: true, instance: "star-a", version: proto.Uint64(8), changes: []mutation{{key: "stable", kind: adjust}}}}},
		{"versioned-erase", true, false, "", []page{{mode: protocol.Mode_MODE_APPLY, complete: true, instance: "star-a", version: proto.Uint64(8), changes: []mutation{{key: "stable", kind: erase, version: 2}}}}},
	}
	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			base := newDraft(emptyTable())
			base.set("stable", &row{data: NewValue([]byte("before")), version: 1})
			root := &snapshot{data: base.data, instance: "star-a", version: 7}
			assembly := testBatch(catalog, root)
			assembly.first, assembly.fresh, assembly.expected = testcase.first, testcase.fresh, testcase.expected
			reserved := int64(0)
			assembly.reserve = func(size int64) bool { reserved = size; return true }
			for index, input := range testcase.pages {
				next, failure := assembly.accept(input)
				if next != nil {
					t.Fatal("invalid transcript published a root")
				}
				if index < len(testcase.pages)-1 {
					if failure != nil {
						t.Fatalf("valid staging page failed: %v", failure)
					}
				} else if failure == nil || failure.Code != CodeProtocol || failure.Effect != Unapplied {
					t.Fatalf("invalid continuation = %v", failure)
				}
			}
			assembly.clear()
			if reserved != 0 || root.version != 7 || root.instance != "star-a" || root.data.count != 1 || root.data.find("stable").data.String() != "before" {
				t.Fatal("rejection changed the baseline or retained preparation storage")
			}
		})
	}
	assembly := testBatch(catalog, nil)
	if next, failure := assembly.accept(page{mode: protocol.Mode_MODE_APPLY, complete: true, instance: "star-a", version: proto.Uint64(0)}); next != nil || failure == nil || failure.Code != CodeProtocol {
		t.Fatal("apply without a baseline was accepted")
	}
	root := &snapshot{data: emptyTable(), instance: "star-a", version: 7}
	assembly = testBatch(catalog, root)
	confirmed, failure := assembly.accept(page{mode: protocol.Mode_MODE_APPLY, complete: true, instance: "star-a", version: proto.Uint64(7)})
	if failure != nil || confirmed == nil || confirmed.version != 7 || confirmed.data.count != 0 {
		t.Fatal("initial unchanged-cursor confirmation was rejected")
	}
}

// TestBatchTransientLimits bounds staged deletions as well as retained records,
// and returns all preparation charges after oversize or parent-budget failure.
func TestBatchTransientLimits(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		kind    domain
		changes []mutation
		deny    bool
	}{
		{"delete-metadata", catalog, []mutation{{key: "a", kind: erase}, {key: "b", kind: erase}, {key: "c", kind: erase}}, false},
		{"candidate-count", catalog, []mutation{{key: "a", kind: replace, version: 1}, {key: "b", kind: replace, version: 1}, {key: "c", kind: replace, version: 1}}, false},
		{"data-payload", catalog, []mutation{{key: "a", kind: replace, version: 1, data: make([]byte, maxPayload+1)}}, false},
		{"attr-payload", ephemeris, []mutation{{key: string(fixtureID()), kind: replace, attr: make([]byte, maxPayload+1)}}, false},
		{"erase-reservation", catalog, []mutation{{key: "a", kind: erase}}, true},
		{"empty-reservation", catalog, nil, true},
	}
	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			root := &snapshot{data: emptyTable(), instance: "star-a", version: 7}
			assembly := testBatch(testcase.kind, root)
			assembly.options.Records = 1
			reserved := int64(0)
			assembly.reserve = func(size int64) bool {
				if testcase.deny && size > 0 {
					return false
				}
				reserved = size
				return true
			}
			if next, failure := assembly.accept(page{mode: protocol.Mode_MODE_APPLY, complete: true, instance: "star-a", version: proto.Uint64(8), changes: testcase.changes}); next != nil || failure == nil || failure.Code != CodeLimit || failure.Effect != Unapplied {
				t.Fatalf("transient pressure was not rejected: %v, %v", next, failure)
			}
			assembly.clear()
			if reserved != 0 || root.data.count != 0 || root.version != 7 {
				t.Fatal("failed preparation retained a charge or changed the visible root")
			}
		})
	}
}

// TestReaderFloorAndDataOnlyRecovery distinguishes domain floors from target-local cursors.
func TestReaderFloorAndDataOnlyRecovery(t *testing.T) {
	t.Parallel()
	root := &snapshot{data: emptyTable(), instance: "old-star", version: 100}
	input := page{mode: protocol.Mode_MODE_RESET, complete: true, instance: "new-star", version: proto.Uint64(90)}
	reader := testBatch(almanac, root)
	if _, failure := reader.accept(input); failure == nil || failure.Code != CodeVersion {
		t.Fatal("Reader authority floor regressed across targets")
	}
	subscriber := testBatch(catalog, root)
	if next, failure := subscriber.accept(input); failure != nil || next.version != 90 {
		t.Fatal("Catalog could not reset its target-local cursor")
	}
	observer := testBatch(ephemeris, root)
	input = page{mode: protocol.Mode_MODE_APPLY, complete: true, instance: "old-star", version: proto.Uint64(101), changes: []mutation{{key: string(fixtureID()), kind: adjust}}}
	if _, failure := observer.accept(input); failure == nil || failure.Code != CodeHistory {
		t.Fatal("Data-only unknown registration was installed without Attr")
	}
}

// FuzzBatchRejectsUncommittedChanges keeps invalid pages from changing a retained baseline.
func FuzzBatchRejectsUncommittedChanges(f *testing.F) {
	f.Add([]byte{1, 2, 3}, uint64(1))
	f.Add([]byte{}, uint64(0))
	f.Fuzz(func(t *testing.T, data []byte, cursor uint64) {
		if len(data) > 2048 {
			t.Skip()
		}
		base := newDraft(emptyTable())
		base.set("stable", &row{data: NewValue([]byte("before")), version: 1})
		root := &snapshot{data: base.data, instance: "star-a", version: 1}
		assembly := testBatch(catalog, root)
		_, _ = assembly.accept(page{mode: protocol.Mode_MODE_APPLY, changes: []mutation{{key: "stable", kind: replace, version: cursor, data: data}}})
		assembly.clear()
		if root.version != 1 || root.data.find("stable").data.String() != "before" {
			t.Fatal("uncommitted page mutated a retained root")
		}
	})
}
