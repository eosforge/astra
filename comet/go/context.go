// Compose request deadlines and shutdown cancellation without borrowing lifetimes.
package comet

import (
	"context"
	"time"
)

// requestContext fixes one total deadline before preparation. A successful
// factory never stores this context as the lifetime of its returned role.
func requestContext(parent context.Context, fallback time.Duration) (context.Context, context.CancelFunc, *Error) {
	if parent == nil {
		return nil, nil, localError(CodeInput)
	}
	if cause := parent.Err(); cause != nil {
		return nil, nil, contextError(cause, Unapplied)
	}
	// An explicit later deadline is capped, not repeatedly reset at RPC boundaries.
	now := time.Now()
	deadline, supplied := parent.Deadline()
	if !supplied {
		deadline = now.Add(fallback)
	} else if maximum := now.Add(maximumTimeout); deadline.After(maximum) {
		deadline = maximum
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	return ctx, cancel, nil
}

// linkedContext joins owner cancellation to a caller-owned deadline. Removing
// the AfterFunc releases registration without treating cancellation as drain.
func linkedContext(parent, owner context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(owner, cancel)
	if owner.Err() != nil {
		cancel()
	}
	return ctx, func() { stop(); cancel() }
}

// waitDone waits for actual completion; it does not start closing the owner.
func waitDone(ctx context.Context, done <-chan struct{}) error {
	if ctx == nil {
		return localError(CodeInput)
	}
	select {
	case <-done:
		return nil
	default:
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return contextError(ctx.Err(), Unapplied)
	}
}

// pause is a cancellable finite retry delay, never a polling busy loop.
func pause(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
