// Classify bounded SDK failures without leaking remote messages or credentials.
package comet

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// Code identifies a failure independently of whether a write may have committed.
type Code uint8

const (
	CodeInternal  Code = iota // Unexpected local failure; no arbitrary message is exposed.
	CodeInput                 // Invalid local argument or fixed public-scope rejection.
	CodeSession               // Authentication rejected or the Session invalidated.
	CodeClosed                // Role or Client has logically closed.
	CodeVersion               // Version conflict or an authority replica below the floor.
	CodeConflict              // Same identity/version has incompatible contents.
	CodeEnded                 // Registration or origin record no longer exists.
	CodeObsolete              // An older generation, order or local estimate lost a race.
	CodeHistory               // The requested cursor cannot be replayed continuously.
	CodeLimit                 // Permanent local or remote capacity limit.
	CodeBusy                  // Temporary admission contention or unready state.
	CodeInstance              // The operation's captured Star no longer matches.
	CodeClock                 // Reliable lease time is currently unavailable.
	CodeTimeout               // Total call deadline expired; commit may be unknown.
	CodeCanceled              // Caller canceled the call; commit may be unknown.
	CodeTransport             // Transport failed or ended incompletely.
	CodeProtocol              // A reply violates the current protocol contract.
	CodeCallback              // A sampler returned an error or an asynchronous callback panicked.
)

// Effect is evidence about this particular write attempt, never a global proof.
type Effect uint8

const (
	Unknown   Effect = iota // Submission may have occurred; do not automatically replay.
	Unapplied               // No send occurred, or the server explicitly rejected before commit.
)

// Error exposes stable classification to errors.As. Version zero is meaningful
// only with HasVersion. Error never includes payloads, secrets or server text.
type Error struct {
	Code       Code          // Stable SDK classification.
	Effect     Effect        // Current attempt's commit certainty.
	Instance   string        // Server-reported instance, empty if unknown.
	Version    uint64        // Observed authority watermark, when present.
	HasVersion bool          // Distinguishes unknown from the valid zero watermark.
	Retry      time.Duration // Bounded server hint; never extends a call deadline.
	cause      error         // Only context cancellation/deadline causes are retained.
}

// Error returns fixed diagnostic text, not an untrusted remote status message.
func (failure *Error) Error() string {
	if failure == nil {
		return "comet: no error"
	}
	// Indexed names cover every public Code; unknown codes retain a safe fallback.
	names := [...]string{
		"internal failure", "invalid input", "session unavailable", "closed", "version conflict", "content conflict",
		"registration ended", "obsolete operation", "history unavailable", "capacity limit", "busy", "instance changed",
		"lease clock unavailable", "deadline exceeded", "canceled", "transport failure", "protocol violation", "callback failure",
	}
	if int(failure.Code) >= len(names) {
		return "comet: unknown failure"
	}
	return "comet: " + names[failure.Code]
}

// Unwrap preserves errors.Is for context.Canceled and context.DeadlineExceeded.
func (failure *Error) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

// localError describes rejection before business submission.
func localError(code Code) *Error {
	switch code {
	case CodeTimeout:
		return contextError(context.DeadlineExceeded, Unapplied)
	case CodeCanceled:
		return contextError(context.Canceled, Unapplied)
	default:
		return &Error{Code: code, Effect: Unapplied}
	}
}

// copyError prevents callers from changing a stored diagnostic through a pointer.
func copyError(failure *Error) *Error {
	if failure == nil {
		return nil
	}
	copy := *failure
	return &copy
}

// contextError retains cancellation identity without claiming that sent writes failed.
func contextError(cause error, effect Effect) *Error {
	code := CodeCanceled
	if errors.Is(cause, context.DeadlineExceeded) {
		code = CodeTimeout
	}
	return &Error{Code: code, Effect: effect, cause: cause}
}

// rpcError admits only one bounded structured trailer and known reason/effect
// values. Missing, malformed or unknown details cannot prove noncommit.
func rpcError(cause error, trailer metadata.MD) *Error {
	failure := &Error{Code: CodeTransport, Effect: Unknown}
	switch status.Code(cause) {
	case codes.Unauthenticated, codes.PermissionDenied:
		failure.Code = CodeSession
	case codes.InvalidArgument:
		failure.Code = CodeInput
	case codes.ResourceExhausted:
		failure.Code = CodeBusy
	case codes.DeadlineExceeded:
		failure.Code, failure.cause = CodeTimeout, context.DeadlineExceeded
	case codes.Canceled:
		failure.Code, failure.cause = CodeCanceled, context.Canceled
	case codes.Unimplemented:
		failure.Code = CodeProtocol
	}
	// Trailers are transport-owned only until this call returns; decoded facts are copied.
	values := trailer.Get("comet-error-bin")
	if len(values) != 1 || len(values[0]) > 4096 {
		return failure
	}
	detail := new(protocol.Failure)
	if proto.Unmarshal([]byte(values[0]), detail) != nil {
		return failure
	}
	switch detail.Reason {
	case protocol.Reason_REASON_INPUT, protocol.Reason_REASON_DENIED:
		failure.Code = CodeInput
	case protocol.Reason_REASON_SESSION:
		failure.Code = CodeSession
	case protocol.Reason_REASON_VERSION:
		failure.Code = CodeVersion
	case protocol.Reason_REASON_CONFLICT:
		failure.Code = CodeConflict
	case protocol.Reason_REASON_ENDED:
		failure.Code = CodeEnded
	case protocol.Reason_REASON_OBSOLETE:
		failure.Code = CodeObsolete
	case protocol.Reason_REASON_HISTORY:
		failure.Code = CodeHistory
	case protocol.Reason_REASON_LIMIT:
		failure.Code = CodeLimit
	case protocol.Reason_REASON_BUSY:
		failure.Code = CodeBusy
	case protocol.Reason_REASON_INSTANCE:
		failure.Code = CodeInstance
	case protocol.Reason_REASON_CLOCK:
		failure.Code = CodeClock
	default:
		return failure
	}
	if detail.Effect == protocol.Effect_EFFECT_UNAPPLIED {
		failure.Effect = Unapplied
	}
	if validText(string(detail.Instance), 128) {
		failure.Instance = string(detail.Instance)
	}
	if detail.Version != nil {
		failure.Version, failure.HasVersion = *detail.Version, true
	}
	if detail.RetryMs != nil {
		failure.Retry = time.Duration(min(*detail.RetryMs, 5000)) * time.Millisecond
	}
	return failure
}

// permanent identifies failures that cannot be fixed by downloading the same
// snapshot or repeating the same registration with backoff.
func permanent(code Code) bool {
	return code == CodeInput || code == CodeLimit || code == CodeProtocol || code == CodeConflict
}

// sameFailure compares only public bounded facts to avoid repeated idle notices.
func sameFailure(left, right *Error) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Code == right.Code && left.Effect == right.Effect && left.Instance == right.Instance && left.Version == right.Version && left.HasVersion == right.HasVersion && left.Retry == right.Retry
}
