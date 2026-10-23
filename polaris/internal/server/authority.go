// Package server exposes Polaris persistence to admitted management services and Stars, excluding Comet Sessions.
package server

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/eosforge/astra/internal/admission"
	"github.com/eosforge/astra/internal/generated/comet"
	"github.com/eosforge/astra/internal/generated/orbit"
	"github.com/eosforge/astra/internal/generated/polaris"
	"github.com/eosforge/astra/polaris/internal/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Authority provides management reads/writes; leases, Comet Sessions, and peer data stay outside the persistent store.
type Authority struct {
	polaris.UnimplementedAuthorityServer
	store     *storage.Store       // Sole persistent authority for commits, reads, and directory state.
	directory *admission.Directory // Admission directory verifies Astrolabe identity and current instance.
	cache     *cache               // Snapshot cache shares preparation budget and avoids duplicate large-range construction.
	slots     chan struct{}        // 16 management permits; full capacity rejects immediately without queuing.
}

// Validate checks the internal login baseline before publishing identity or listening; ordinary values remain opaque.
// Unreadable storage or invalid credentials fail startup under ctx.
func Validate(ctx context.Context, store *storage.Store) error {
	if store == nil {
		return storage.ErrInput
	}
	// Inspect the fixed internal credential Scope only.
	scope := storage.Scope{Sector: "__auth", Spectrum: "comet"}
	snapshot, err := store.Load(ctx, scope)
	if err != nil {
		return err
	}

	for _, record := range snapshot.Records {
		if !credential(scope, storage.Change{Key: record.Key, Value: record.Value}) {
			return storage.ErrCorrupt
		}
	}
	return nil
}

// NewAuthority requires snapshotBytes to fit one maximum legal Scope; store/directory supply dependencies.
// Shared budget must meet cache minimum and remain at most 1 GiB.
func NewAuthority(store *storage.Store, directory *admission.Directory, snapshotBytes int64) (*Authority, error) {
	if store == nil || directory == nil {
		return nil, storage.ErrInput
	}
	cache := newCache(store, store.Limits(), snapshotBytes)
	if snapshotBytes < cache.reserve || snapshotBytes > 1<<30 {
		return nil, storage.ErrInput
	}
	return &Authority{store: store, directory: directory, cache: cache, slots: make(chan struct{}, 16)}, nil
}

// begin validates Astrolabe and a finite deadline, returning an authorized Member or deadline/capacity/identity error without queuing overload.
func (authority *Authority) begin(ctx context.Context) (*orbit.Member, error) {
	// Deadline must exist and lie within 30 seconds to bound permit retention.
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 30*time.Second {
		return nil, status.Error(codes.InvalidArgument, "Management deadline must be finite and at most 30 seconds")
	}
	// Acquire before identity validation; full capacity rejects and failed validation returns the permit.
	select {
	case authority.slots <- struct{}{}:
	default:
		return nil, status.Error(codes.ResourceExhausted, "Management capacity exceeded")
	}
	member, err := authority.directory.Authorize(ctx, orbit.Role_ROLE_ASTROLABE)
	if err != nil {
		<-authority.slots
		return nil, err
	}
	return member, nil
}

// Commit atomically writes one Key or a unique-Key batch; success proves Polaris's durable transaction only.
// request must fit one frame; larger complete batches use Batch without a separate whole-batch size cap.
func (authority *Authority) Commit(ctx context.Context, request *polaris.CommitRequest) (*polaris.Position, error) {

	member, err := authority.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { <-authority.slots }()
	return authority.commit(ctx, member, request)
}

// Batch stages pages at one Scope/version and commits once only after an explicit complete page followed by normal EOF.
// No prefix enters records/history; interruption, cross-page duplicates, or inconsistent input rejects the entire batch.
func (authority *Authority) Batch(stream grpc.ClientStreamingServer[polaris.BatchRequest, polaris.Position]) error {
	ctx := stream.Context()
	member, err := authority.begin(ctx)
	if err != nil {
		return err
	}
	defer func() { <-authority.slots }()
	var request *polaris.CommitRequest
	complete := false
	// Retain batch-wide key identity so a known-invalid prefix never waits for more transport input.
	seen := make(map[string]struct{})
	for {
		page, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if !authority.directory.Current(member) {
			return status.Error(codes.Unauthenticated, "Management admission replaced")
		}
		if complete || page == nil || page.Scope == nil || page.Version == 0 || len(page.Changes) == 0 {
			return status.Error(codes.InvalidArgument, "Invalid batch page")
		}
		if request == nil {
			request = &polaris.CommitRequest{Scope: page.Scope, Version: page.Version}
		} else if !proto.Equal(request.Scope, page.Scope) || request.Version != page.Version {
			return status.Error(codes.InvalidArgument, "Batch position changed")
		}
		for _, change := range page.Changes {
			if change == nil || change.Key == "" {
				return status.Error(codes.InvalidArgument, "Missing batch entry")
			}
			if _, exists := seen[change.Key]; exists {
				return status.Error(codes.InvalidArgument, "Duplicate batch key")
			}
			seen[change.Key] = struct{}{}
		}
		request.Changes = append(request.Changes, page.Changes...)
		complete = page.Complete
	}
	if !complete {
		return status.Error(codes.InvalidArgument, "Incomplete batch")
	}
	result, err := authority.commit(ctx, member, request)
	if err != nil {
		return err
	}
	return stream.SendAndClose(result)
}

// commit shares full validation across single/multiple frames; caller owns a management permit and enters one durable transaction after checks.
func (authority *Authority) commit(ctx context.Context, member *orbit.Member, request *polaris.CommitRequest) (*polaris.Position, error) {
	if request == nil || request.Scope == nil || (request.Change == nil) == (len(request.Changes) == 0) {
		return nil, status.Error(codes.InvalidArgument, "Invalid authority commit")
	}
	scope := storage.Scope{Sector: string(request.Scope.Sector), Spectrum: string(request.Scope.Spectrum)}
	if len(request.Changes) != 0 {
		if strings.HasPrefix(scope.Sector, "__") {
			return nil, status.Error(codes.InvalidArgument, "Invalid batch scope")
		}
		changes := make([]storage.Change, 0, len(request.Changes))
		for _, item := range request.Changes {
			if item == nil {
				return nil, status.Error(codes.InvalidArgument, "Missing batch entry")
			}
			entry := storage.Change{Key: item.Key}
			switch action := item.Action.(type) {
			case *comet.AlmanacChange_Value:
				if action == nil {
					return nil, status.Error(codes.InvalidArgument, "Missing value action")
				}
				entry.Value = action.Value
			case *comet.AlmanacChange_Erase:
				if action == nil || action.Erase == nil {
					return nil, status.Error(codes.InvalidArgument, "Missing erase action")
				}
				entry.Erase = true
			default:
				return nil, status.Error(codes.InvalidArgument, "Missing batch action")
			}
			changes = append(changes, entry)
		}
		if !authority.directory.Current(member) {
			return nil, status.Error(codes.Unauthenticated, "Management admission replaced")
		}
		version, err := authority.store.CommitBatch(ctx, scope, storage.Version(request.Version), changes)
		if err != nil {
			return nil, failure(err)
		}
		return &polaris.Position{Scope: request.Scope, Version: uint64(version)}, nil
	}
	change := storage.Change{Version: storage.Version(request.Version), Key: request.Change.Key}
	// Exactly one action: Set carries payload and Delete requires explicit erase.
	switch action := request.Change.Action.(type) {
	case *comet.AlmanacChange_Value:
		if action == nil {
			return nil, status.Error(codes.InvalidArgument, "Missing value action")
		}
		change.Value = action.Value
	case *comet.AlmanacChange_Erase:
		if action == nil || action.Erase == nil {
			return nil, status.Error(codes.InvalidArgument, "Missing erase action")
		}
		change.Erase = true
	default:
		return nil, status.Error(codes.InvalidArgument, "Missing authority action")
	}
	// Internal credential Scopes validate credential shape before storage.
	if !credential(scope, change) {
		return nil, status.Error(codes.InvalidArgument, "Invalid internal credential")
	}
	// Recheck authorized instance before commit so replaced admission cannot authorize stale writes.
	if !authority.directory.Current(member) {
		return nil, status.Error(codes.Unauthenticated, "Management admission replaced")
	}
	version, err := authority.store.Commit(ctx, scope, change)
	if err != nil {
		return nil, failure(err)
	}
	return &polaris.Position{Scope: request.Scope, Version: uint64(version)}, nil
}

// credential parses only the fixed internal login Scope; business payload stays opaque and Delete still validates APIKEY.
// scope/change identify the pending write; noninternal Scopes pass without decoding.
func credential(scope storage.Scope, change storage.Change) bool {
	if scope.Sector != "__auth" || scope.Spectrum != "comet" {
		return true
	}
	// Require valid bounded Key text in the internal Scope.
	if len(change.Key) == 0 || len(change.Key) > 128 || !utf8.ValidString(change.Key) || strings.ContainsRune(change.Key, 0) {
		return false
	}
	if change.Erase {

		return true
	}
	// Set requires a valid credential message and bounded nonempty secret material.
	var value orbit.Credential
	return len(change.Value) <= 8192 && proto.Unmarshal(change.Value, &value) == nil && len(value.Secret) > 0 && len(value.Secret) <= 4096
}

// List reads complete bounded Scope metadata in one SQL read, without copying all payloads or implying Star installation.
// Reject responses above 8 MiB rather than returning a truncated directory.
func (authority *Authority) List(ctx context.Context, _ *comet.Empty) (*polaris.Inventory, error) {
	if _, err := authority.begin(ctx); err != nil {
		return nil, err
	}
	defer func() { <-authority.slots }()
	positions, err := authority.store.List(ctx)
	if err != nil {
		return nil, failure(err)
	}

	result := &polaris.Inventory{Complete: true}
	for _, position := range positions {
		result.Positions = append(result.Positions, &polaris.Position{Scope: &comet.Scope{Sector: []byte(position.Sector), Spectrum: []byte(position.Spectrum)}, Version: uint64(position.Version)})
	}
	if proto.Size(result) > 8<<20 {
		return nil, status.Error(codes.ResourceExhausted, "Scope inventory exceeds message capacity")
	}
	return result, nil
}

// Load finishes SQL before streaming a frozen root; version appears on the complete final page and network holds no database connection.
// request selects Scope; replacement of the authorized instance interrupts stream.
func (authority *Authority) Load(request *comet.Scope, stream grpc.ServerStreamingServer[polaris.Snapshot]) error {
	member, err := authority.begin(stream.Context())
	if err != nil {
		return err
	}
	defer func() { <-authority.slots }()
	if request == nil {
		return status.Error(codes.InvalidArgument, "Missing scope")
	}
	scope := storage.Scope{Sector: string(request.Sector), Spectrum: string(request.Spectrum)}
	// Capture this request's version floor independently of older cached snapshots.
	version, err := authority.store.Version(stream.Context(), scope)
	if err != nil {
		return failure(err)
	}
	// Pin the selected version through sending and release afterward.
	pin, err := authority.cache.acquire(stream.Context(), scope, version)
	if err != nil {
		return failure(err)
	}
	defer pin.release()
	return pages(pin.Snapshot, 8<<20, func(page *polaris.Snapshot) error {
		// Recheck authorized identity before every page; replacement stops delivery to the old instance.
		if !authority.directory.Current(member) {
			return status.Error(codes.Unauthenticated, "Management admission replaced")
		}
		return stream.Send(page)
	})
}

// pages packs once toward 256 KiB pages, not a record-size cap; one large value may own a page.
// snapshot is frozen, maximum is receiver capacity, and send failure aborts immediately.
func pages(snapshot *storage.Snapshot, maximum int, send func(*polaris.Snapshot) error) error {
	// Receiver capacity must be 1 KiB..8 MiB.
	if maximum < 1024 || maximum > 8<<20 {
		return status.Error(codes.InvalidArgument, "Invalid Almanac receive capacity")
	}
	scope := &comet.Scope{Sector: []byte(snapshot.Sector), Spectrum: []byte(snapshot.Spectrum)}
	page := &polaris.Snapshot{Scope: scope, Version: proto.Uint64(uint64(snapshot.Version))}
	size := proto.Size(scope) + 32
	// Flush full pages and reject a single entry above the frame limit.
	for _, record := range snapshot.Records {
		entry := &comet.AlmanacChange{Key: record.Key, Action: &comet.AlmanacChange_Value{Value: record.Value}}
		cost := proto.Size(entry) + 6
		if len(page.Entries) != 0 && size+cost > min(maximum, 256<<10) {
			if err := send(page); err != nil {
				return err
			}
			page = &polaris.Snapshot{Scope: scope, Version: proto.Uint64(uint64(snapshot.Version))}
			size = proto.Size(scope) + 32
		}
		if proto.Size(scope)+32+cost > maximum {
			return status.Error(codes.ResourceExhausted, "Almanac record exceeds receiver capacity")
		}
		page.Entries = append(page.Entries, entry)
		size += cost
	}
	// Final page marks complete; empty snapshots still send one complete empty page.
	page.Complete = true
	return send(page)
}

// failure maps internal errors to fixed gRPC categories without SQLite text, accounts, payloads, or host paths.
func failure(err error) error {
	// Unknown failures map to unavailable without forwarding their text.
	switch {
	case errors.Is(err, storage.ErrInput):
		return status.Error(codes.InvalidArgument, "Invalid authority input")
	case errors.Is(err, storage.ErrVersion):
		return status.Error(codes.Aborted, "Authority version conflict")
	case errors.Is(err, storage.ErrHistory):
		return status.Error(codes.OutOfRange, "Continuous history unavailable")
	case errors.Is(err, storage.ErrUncertain):
		return status.Error(codes.Unknown, "Authority commit cannot be confirmed")
	case errors.Is(err, storage.ErrCapacity):
		return status.Error(codes.ResourceExhausted, "Authority capacity exceeded")
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, "Authority request cancelled")
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, "Authority request deadline exceeded")
	default:
		return status.Error(codes.Unavailable, "Authority storage unavailable")
	}
}
