// Expose complete Catalog and Almanac views through the same small read surface.
package comet

import (
	"context"
	"strings"
)

// Subscriber continuously synchronizes Catalog values. Use Client.Subscriber or
// SubscriberKey. Methods are inherited from the private shared read implementation.
type Subscriber struct{ *subscription }

// Reader synchronizes authoritative Almanac values and never installs a version
// below its last observed floor, including after a Star change.
type Reader struct{ *subscription }

// subscription owns the shared public read surface, without exposing wire types.
type subscription struct{ watch *watching }

// Subscriber admits a whole-scope Catalog subscription and synchronizes in background.
func (client *Client) Subscriber(scope Scope, options ...ReadOptions) (*Subscriber, error) {
	watch, failure := client.watch(catalog, scope, "", options)
	if failure != nil {
		return nil, failure
	}
	return &Subscriber{&subscription{watch}}, nil
}

// SubscriberKey admits exactly one nonempty Catalog key; it uses WatchKey.
func (client *Client) SubscriberKey(scope Scope, key string, options ...ReadOptions) (*Subscriber, error) {
	if !validText(key, 1024) {
		return nil, localError(CodeInput)
	}
	watch, failure := client.watch(catalog, scope, key, options)
	if failure != nil {
		return nil, failure
	}
	return &Subscriber{&subscription{watch}}, nil
}

// Reader admits a whole-scope Almanac subscription; there is no write operation.
func (client *Client) Reader(scope Scope, options ...ReadOptions) (*Reader, error) {
	watch, failure := client.watch(almanac, scope, "", options)
	if failure != nil {
		return nil, failure
	}
	return &Reader{&subscription{watch}}, nil
}

// ReaderKey admits exactly one nonempty Almanac key, retaining the group's floor.
func (client *Client) ReaderKey(scope Scope, key string, options ...ReadOptions) (*Reader, error) {
	if !validText(key, 1024) {
		return nil, localError(CodeInput)
	}
	watch, failure := client.watch(almanac, scope, key, options)
	if failure != nil {
		return nil, failure
	}
	return &Reader{&subscription{watch}}, nil
}

// State returns a local immutable snapshot immediately, without issuing an RPC.
func (reader *subscription) State() View {
	if reader == nil || reader.watch == nil {
		return View{Phase: Closed}
	}
	reader.watch.mu.Lock()
	defer reader.watch.mu.Unlock()
	return reader.watch.viewLocked()
}

// Watch replaces the whole-scope callback and schedules the latest complete
// baseline, including an empty Map. Nil unregisters it. Intermediate undelivered
// states may coalesce; callbacks for this object are serial and run without locks.
// A panic disables this callback and records CodeCallback. Do not wait on this
// object's or Client's cleanup from its own callback.
func (reader *subscription) Watch(callback func(Map)) error {
	if reader == nil || reader.watch == nil {
		return localError(CodeClosed)
	}
	watch := reader.watch
	watch.mu.Lock()
	if watch.life.stopped() {
		watch.mu.Unlock()
		return localError(CodeClosed)
	}
	if watch.target != "" {
		watch.mu.Unlock()
		return localError(CodeInput)
	}
	watch.content = nil
	if callback != nil {
		watch.content = &contentNotice{whole: callback}
	}
	watch.mu.Unlock()
	watch.note.signal()
	return nil
}

// WatchKey replaces the exact-key callback. Present false means absence in a
// complete baseline or later deletion; valid empty Value remains present true.
// Disconnect, incomplete synchronization and decoding failure are never deletion.
func (reader *subscription) WatchKey(callback func(key string, value Value, present bool)) error {
	if reader == nil || reader.watch == nil {
		return localError(CodeClosed)
	}
	watch := reader.watch
	watch.mu.Lock()
	if watch.life.stopped() {
		watch.mu.Unlock()
		return localError(CodeClosed)
	}
	if watch.target == "" {
		watch.mu.Unlock()
		return localError(CodeInput)
	}
	watch.content = nil
	if callback != nil {
		watch.content = &contentNotice{exact: callback}
	}
	watch.mu.Unlock()
	watch.note.signal()
	return nil
}

// Changed replaces the state callback and schedules the current state even
// before data readiness. Nil unregisters it. Panic handling follows Watch.
func (reader *subscription) Changed(callback func(View)) error {
	if reader == nil || reader.watch == nil {
		return localError(CodeClosed)
	}
	watch := reader.watch
	watch.mu.Lock()
	if watch.life.stopped() {
		watch.mu.Unlock()
		return localError(CodeClosed)
	}
	watch.notice = nil
	if callback != nil {
		watch.notice = &viewNotice{call: callback, pending: true}
	}
	watch.mu.Unlock()
	watch.note.signal()
	return nil
}

// Stop immediately closes this subscription; already-delivered Maps remain valid.
func (reader *subscription) Stop() {
	if reader != nil && reader.watch != nil {
		reader.watch.life.stop()
	}
}

// Wait waits for actual stream/callback cleanup without implicitly calling Stop.
func (reader *subscription) Wait(ctx context.Context) error {
	if reader == nil || reader.watch == nil {
		if ctx == nil {
			return localError(CodeInput)
		}
		return nil
	}
	return waitDone(ctx, reader.watch.life.done)
}

// watch admits a fully initialized receiver so concurrent Client.Close never
// observes partially installed cleanup hooks or untracked receiver goroutines.
func (client *Client) watch(kind domain, scope Scope, target string, settings []ReadOptions) (*watching, *Error) {
	if client == nil || client.ctx == nil || client.closed.Load() {
		return nil, localError(CodeClosed)
	}
	if !validScope(scope) {
		return nil, localError(CodeInput)
	}
	options, failure := normalizeRead(settings)
	if failure != nil {
		return nil, failure
	}
	watch := &watching{life: newLifecycle(client, true), domain: kind, scope: cloneScope(scope), target: strings.Clone(target), options: options, phase: Waiting}
	watch.estimates = emptyTable()
	watch.note = &notification{queue: client.notifications, life: watch.life, run: watch.deliver}
	watch.life.onstop, watch.life.onfinish = watch.stop, watch.finish
	watch.life.active++ // Reserve the not-yet-launched receiver before publishing ownership.
	watch.charged = watch.retainedLocked()
	if !client.reserve(watch.charged) {
		watch.life.cancel()
		return nil, localError(CodeBusy)
	}
	if failure := client.attach(watch.life); failure != nil {
		client.release(watch.charged)
		watch.life.cancel()
		return nil, failure
	}
	go watch.run()
	return watch, nil
}
