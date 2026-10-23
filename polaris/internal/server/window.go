// Bound stream flow and acknowledged progress for authority delivery.

package server

import (
	"time"

	"github.com/eosforge/astra/internal/generated/polaris"
	"github.com/eosforge/astra/polaris/internal/storage"
	"google.golang.org/protobuf/proto"
)

// credit retains sent boundaries not yet covered by cumulative installation ACK, without copying history payload.
type credit struct {
	scope   storage.Scope   // Scope used to match acknowledged prefixes.
	version storage.Version // Sent version released when covered by ACK.
	bytes   int64           // In-flight byte charge returned on release.
}

// budget pipelines normal commits within 8 MiB/128 boundaries; one larger full snapshot may exclusively own the window after old credits drain.
// Large snapshots still obey Scope/preparation limits and need no per-page stop-and-wait ACK.
// cost is this send's byte charge; consume controls until capacity returns or context ends.
func (transfer *transfer) budget(cost int64) error {
	// Apply a finite blocked-stage deadline while waiting; Open enforces slow-peer timeout.
	transfer.wait(30 * time.Second)
	defer transfer.wait(0)

	for len(transfer.credits) != 0 && (len(transfer.credits) >= 128 || cost > 8<<20-transfer.bytes) {
		packet, err := transfer.next()
		if err != nil {
			return err
		}
		if err := transfer.control(packet); err != nil {
			return err
		}
	}
	return transfer.ctx.Err()
}

// charge runs after the complete commit is handed to gRPC; even empty-Scope version zero needs an ACK boundary.
// Registers scope/version/cost credit and advances sent position.
func (transfer *transfer) charge(scope storage.Scope, version storage.Version, cost int64) {
	transfer.sent[scope] = max(transfer.sent[scope], version)
	transfer.credits = append(transfer.credits, credit{scope: scope, version: version, bytes: cost})
	transfer.bytes += cost
}

// release removes the confirmed Scope prefix by actual installed version; at most 128 entries are compacted in place without allocation.
func (transfer *transfer) release(scope storage.Scope, version storage.Version) {
	// Keep uncovered credits, subtract covered bytes, and clear the tail to release references.
	kept := transfer.credits[:0]
	for _, item := range transfer.credits {
		if item.scope == scope && item.version <= version {
			transfer.bytes -= item.bytes
		} else {
			kept = append(kept, item)
		}
	}
	clear(transfer.credits[len(kept):])
	transfer.credits = kept
}

// updates advances packet handoff and sent position together; caller guarantees contiguous +1 versions.
// Acquire window before sending scope/page, then register credit after sending.
func (transfer *transfer) updates(scope storage.Scope, page *polaris.Updates) error {
	packet := &polaris.Packet{Body: &polaris.Packet_Updates{Updates: page}}
	cost := int64(proto.Size(packet))
	if err := transfer.budget(cost); err != nil {
		return err
	}
	if err := transfer.send(packet); err != nil {
		return err
	}
	transfer.charge(scope, storage.Version(page.Patches[len(page.Patches)-1].Version), cost)
	return nil
}

// snapshot pages one frozen version, processes controls between pages, and creates its installation boundary only at final completion.
// Reserve estimated cost before paging; register credit only after all sends.
func (transfer *transfer) snapshot(snapshot *storage.Snapshot) error {
	// Admission estimate includes Scope names and per-record key/value overhead.
	cost := int64(64 + len(snapshot.Sector) + len(snapshot.Spectrum))
	for _, record := range snapshot.Records {
		cost += int64(32 + len(record.Key) + len(record.Value))
	}
	if err := transfer.budget(cost); err != nil {
		return err
	}

	if err := pages(snapshot, transfer.maximum, func(page *polaris.Snapshot) error {
		if err := transfer.send(&polaris.Packet{Body: &polaris.Packet_Snapshot{Snapshot: page}}); err != nil {
			return err
		}
		// Final-page ACK may already be queued; register sent before outer control consumption to avoid false ahead errors.
		if !page.Complete {
			return transfer.drain()
		}
		return nil
	}); err != nil {
		return err
	}
	transfer.charge(snapshot.Scope, snapshot.Version, cost)
	return nil
}
