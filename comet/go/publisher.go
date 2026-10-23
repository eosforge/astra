// Publish synchronous atomic Catalog batches with internal version ownership.
package comet

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// Publisher binds one Catalog scope. Updates on the same Publisher never overlap
// or queue. Applications ensure different Publishers do not own the same key.
// It retains version metadata, not Data for recovery or automatic renewal.
type Publisher struct {
	life     *lifecycle // Explicit cancellation and final quota owner.
	scope    Scope      // Immutable scope shared by every batch on this Publisher.
	mu       sync.Mutex // Protects admission; one admitted call owns version/cache state.
	active   bool       // Exactly one caller owns issued/cache fields while admitted.
	issued   uint64     // Never reuse a possibly submitted version, including after failure.
	bound    *binding   // Binding for which the latest exact key set was confirmed.
	keys     []string   // Only the latest complete canonical key set.
	instance string     // Captured instance belonging to the metadata cache.
	bytes    int64      // Retained cache charge, released on replacement/failure/close.
	base     int64      // Fixed owner/scope allowance, independent of the metadata cache.
}

// Publisher admits a local Catalog publisher; it does not wait for connection.
func (client *Client) Publisher(scope Scope) (*Publisher, error) {
	if client == nil || client.ctx == nil || client.closed.Load() {
		return nil, localError(CodeClosed)
	}
	if !validScope(scope) {
		return nil, localError(CodeInput)
	}
	if !client.reserve(2048) {
		return nil, localError(CodeBusy)
	}
	publisher := &Publisher{life: newLifecycle(client, false), scope: cloneScope(scope), base: 2048}
	publisher.life.onfinish = publisher.finish
	if failure := client.attach(publisher.life); failure != nil {
		client.release(publisher.base)
		publisher.life.cancel()
		return nil, failure
	}
	return publisher, nil
}

// Close stops this Publisher without deleting its remote records or closing Client.
func (publisher *Publisher) Close() {
	if publisher != nil && publisher.life != nil {
		publisher.life.stop()
	}
}

// Wait waits for this already-closing Publisher's admitted call to settle.
func (publisher *Publisher) Wait(ctx context.Context) error {
	if publisher == nil || publisher.life == nil {
		if ctx == nil {
			return localError(CodeInput)
		}
		return nil
	}
	return waitDone(ctx, publisher.life.done)
}

// discard drops the single metadata cache; no concurrent operation may use it.
func (publisher *Publisher) discard() {
	publisher.life.client.release(publisher.bytes)
	publisher.bytes, publisher.keys, publisher.bound, publisher.instance = 0, nil, nil, ""
}

// finish returns both fixed ownership and the latest query metadata at final drain.
func (publisher *Publisher) finish() {
	publisher.discard()
	publisher.life.client.release(publisher.base)
}

// Update synchronously commits 1..128 distinct complete values under one version
// and TTL (1s..10min, whole milliseconds). Nil Data means an empty value. Input
// bytes are copied; do not mutate them concurrently with this call. The total
// key/body size is at most 1 MiB. A single Entry is the single-key operation.
//
// One deadline covers readiness, version lookup, commit and at most one repair
// after an explicit unapplied version conflict. Unknown outcomes are never replayed.
func (publisher *Publisher) Update(ctx context.Context, entries []Entry, ttl time.Duration) (Receipt, error) {
	if publisher == nil || publisher.life == nil || publisher.life.stopped() {
		return Receipt{}, localError(CodeClosed)
	}
	client := publisher.life.client
	budget, cancel, failure := requestContext(ctx, client.options.Timeout)
	if failure != nil {
		return Receipt{}, failure
	}
	defer cancel()
	if !validTTL(ttl) || len(entries) == 0 || len(entries) > 128 {
		return Receipt{}, localError(CodeInput)
	}
	// Validate bounded sizes before copying caller buffers or admitting network work.
	var size, names int64
	for _, entry := range entries {
		if !validText(entry.Key, 1024) || len(entry.Data) > maxPayload {
			return Receipt{}, localError(CodeInput)
		}
		names += int64(len(entry.Key))
		size += int64(len(entry.Key) + len(entry.Data))
		if size > maxPayload {
			return Receipt{}, localError(CodeInput)
		}
	}
	publisher.mu.Lock()
	if publisher.active {
		publisher.mu.Unlock()
		return Receipt{}, localError(CodeBusy)
	}
	if !publisher.life.begin() {
		publisher.mu.Unlock()
		return Receipt{}, localError(CodeClosed)
	}
	publisher.active = true
	publisher.mu.Unlock()
	success := false
	defer func() {
		if !success {
			publisher.discard()
		}
		publisher.mu.Lock()
		publisher.active = false
		publisher.mu.Unlock()
		publisher.life.release()
	}()
	if !claim(client.explicit) {
		return Receipt{}, localError(CodeBusy)
	}
	defer func() { <-client.explicit }()
	reserved := 3*size + 3*names + int64(len(entries))*768 + 8192
	if !client.reserve(reserved) {
		return Receipt{}, localError(CodeBusy)
	}
	defer func() { client.release(reserved) }()
	// Canonicalize privately; never reorder the application's slice.
	ordered := slices.Clone(entries)
	slices.SortFunc(ordered, func(left, right Entry) int { return strings.Compare(left.Key, right.Key) })
	keys := make([]string, len(ordered))
	request := &protocol.PublishRequest{Scope: wireScope(publisher.scope), TtlMs: uint32(ttl / time.Millisecond)}
	for index, entry := range ordered {
		if index > 0 && entry.Key == ordered[index-1].Key {
			return Receipt{}, localError(CodeInput)
		}
		keys[index] = strings.Clone(entry.Key)
		request.Entries = append(request.Entries, &protocol.CatalogEntry{Key: keys[index], Value: slices.Clone(entry.Data)})
	}
	call, stop := linkedContext(budget, publisher.life.ctx)
	defer stop()
	selected, failure := client.acquire(call)
	if failure != nil {
		if publisher.life.stopped() {
			failure.Code = CodeClosed
		}
		return Receipt{}, failure
	}
	current := publisher.bound == selected && slices.Equal(publisher.keys, keys)
	instance := selected.instance()
	if current {
		instance = publisher.instance
	}
	stub := protocol.NewCatalogClient(selected.unary)
	for attempt := 0; attempt < 2; attempt++ {
		version := publisher.issued
		if !current || attempt != 0 {
			var queried *Error
			version, instance, queried = publisher.query(call, selected, keys, instance)
			if queried != nil {
				return Receipt{}, queried
			}
		}
		if version == ^uint64(0) {
			return Receipt{}, localError(CodeLimit)
		}
		if !client.current(selected) {
			return Receipt{}, localError(CodeInstance)
		}
		if cause := call.Err(); cause != nil {
			return Receipt{}, contextError(cause, Unapplied)
		}
		version++
		request.Instance, request.Version = []byte(instance), version
		publisher.issued = version // Consume before send; an unknown result cannot reuse it.
		rpc, release := selected.context(call)
		var trailer metadata.MD
		reply, cause := stub.Publish(rpc, request, grpc.Trailer(&trailer))
		release()
		if cause != nil {
			failure := rpcError(cause, trailer)
			if publisher.life.stopped() {
				failure.Code = CodeClosed
			}
			if attempt == 0 && failure.Code == CodeVersion && failure.Effect == Unapplied {
				continue
			}
			client.lost(selected, failure)
			return Receipt{}, failure
		}
		if reply == nil || string(reply.Instance) != instance || reply.Version != version {
			return Receipt{}, &Error{Code: CodeProtocol, Effect: Unknown}
		}
		// Transfer an already-reserved metadata allowance after the successful receipt.
		publisher.discard()
		retained := names + int64(len(keys))*32 + int64(len(instance)) + 256
		reserved -= retained
		publisher.bytes, publisher.keys, publisher.instance, publisher.bound = retained, keys, instance, selected
		selected.healthy.Store(true)
		success = true
		return Receipt{Instance: instance, Version: version}, nil
	}
	return Receipt{}, localError(CodeInternal)
}

// query checks the complete ordered response and incorporates issued evidence
// without fetching any bodies or treating a read failure as a committed write.
func (publisher *Publisher) query(ctx context.Context, selected *binding, keys []string, instance string) (uint64, string, *Error) {
	client := publisher.life.client
	if !client.current(selected) {
		return 0, "", localError(CodeInstance)
	}
	rpc, cancel := selected.context(ctx)
	defer cancel()
	var trailer metadata.MD
	reply, cause := protocol.NewCatalogClient(selected.unary).Query(rpc, &protocol.CatalogQueryRequest{Instance: []byte(instance), Scope: wireScope(publisher.scope), Keys: keys}, grpc.Trailer(&trailer))
	if cause != nil {
		failure := rpcError(cause, trailer)
		failure.Effect = Unapplied
		if publisher.life.stopped() {
			failure.Code = CodeClosed
		}
		client.lost(selected, failure)
		return 0, "", failure
	}
	if reply == nil || !selected.accept(string(reply.Instance)) || instance != "" && string(reply.Instance) != instance || len(reply.Entries) != len(keys) {
		return 0, "", localError(CodeProtocol)
	}
	maximum := publisher.issued
	for index, entry := range reply.Entries {
		if entry == nil || entry.Key != keys[index] {
			return 0, "", localError(CodeProtocol)
		}
		maximum = max(maximum, entry.Version)
	}
	return maximum, string(reply.Instance), nil
}
