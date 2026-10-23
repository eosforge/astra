// Verify bounded structured errors without accepting invented noncommit evidence.
package comet

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/eosforge/astra/comet/go/internal/protocol"
)

// TestErrorMetadata rejects invented noncommit evidence and excludes private remote text.
func TestErrorMetadata(t *testing.T) {
	t.Parallel()
	remote := status.Error(codes.Unknown, "SECRET private payload")
	known, cause := proto.Marshal(&protocol.Failure{Reason: protocol.Reason_REASON_VERSION, Effect: protocol.Effect_EFFECT_UNAPPLIED,
		Message: "SECRET private payload", RetryMs: proto.Uint32(100_000), Version: proto.Uint64(0)})
	if cause != nil {
		t.Fatal(cause)
	}
	failure := rpcError(remote, metadata.Pairs("comet-error-bin", string(known)))
	if failure.Code != CodeVersion || failure.Effect != Unapplied || !failure.HasVersion || failure.Version != 0 || failure.Retry != 5*time.Second || strings.Contains(failure.Error(), "SECRET") {
		t.Fatalf("wrong bounded detail: %#v", failure)
	}
	unknown, cause := proto.Marshal(&protocol.Failure{Reason: protocol.Reason(999), Effect: protocol.Effect_EFFECT_UNAPPLIED})
	if cause != nil {
		t.Fatal(cause)
	}
	for _, values := range []metadata.MD{nil, metadata.Pairs("comet-error-bin", "invalid"), metadata.Pairs("comet-error-bin", string(unknown)),
		metadata.Pairs("comet-error-bin", string(known), "comet-error-bin", string(known)), metadata.Pairs("comet-error-bin", strings.Repeat("x", 4097))} {
		if failure := rpcError(remote, values); failure.Effect != Unknown {
			t.Fatal("untrusted detail proved noncommit")
		}
	}
	if !errors.Is(rpcError(status.Error(codes.DeadlineExceeded, ""), nil), context.DeadlineExceeded) {
		t.Fatal("deadline identity was lost")
	}
}

// TestErrorClassification separates transport status, protocol reason and commit evidence.
func TestErrorClassification(t *testing.T) {
	t.Parallel()
	statuses := []struct {
		status codes.Code // Native status with no trusted structured detail.
		code   Code       // Public classification, independent of the remote text.
		cause  error      // Only a standard Context identity may be retained.
	}{
		{codes.Unauthenticated, CodeSession, nil}, {codes.PermissionDenied, CodeSession, nil},
		{codes.InvalidArgument, CodeInput, nil}, {codes.ResourceExhausted, CodeBusy, nil},
		{codes.DeadlineExceeded, CodeTimeout, context.DeadlineExceeded}, {codes.Canceled, CodeCanceled, context.Canceled},
		{codes.Unimplemented, CodeProtocol, nil}, {codes.Unavailable, CodeTransport, nil}, {codes.Internal, CodeTransport, nil},
	}
	for _, testcase := range statuses {
		t.Run(testcase.status.String(), func(t *testing.T) {
			failure := rpcError(status.Error(testcase.status, "SECRET remote diagnostic"), nil)
			if failure.Code != testcase.code || failure.Effect != Unknown || failure.Unwrap() != testcase.cause {
				t.Fatalf("transport status changed classification or commit certainty: %#v", failure)
			}
			if strings.Contains(failure.Error(), "SECRET") || failure.HasVersion || failure.Instance != "" || failure.Retry != 0 {
				t.Fatal("transport status invented facts or leaked its message")
			}
		})
	}
	reasons := []struct {
		reason protocol.Reason // Explicit protocol reason with independent expected meaning.
		code   Code            // Public SDK classification required for that reason.
	}{
		{protocol.Reason_REASON_INPUT, CodeInput}, {protocol.Reason_REASON_DENIED, CodeInput},
		{protocol.Reason_REASON_SESSION, CodeSession}, {protocol.Reason_REASON_VERSION, CodeVersion},
		{protocol.Reason_REASON_CONFLICT, CodeConflict}, {protocol.Reason_REASON_ENDED, CodeEnded},
		{protocol.Reason_REASON_OBSOLETE, CodeObsolete}, {protocol.Reason_REASON_HISTORY, CodeHistory},
		{protocol.Reason_REASON_LIMIT, CodeLimit}, {protocol.Reason_REASON_BUSY, CodeBusy},
		{protocol.Reason_REASON_INSTANCE, CodeInstance}, {protocol.Reason_REASON_CLOCK, CodeClock},
	}
	for _, testcase := range reasons {
		t.Run(testcase.reason.String(), func(t *testing.T) {
			for _, effect := range []protocol.Effect{protocol.Effect_EFFECT_UNKNOWN, protocol.Effect_EFFECT_UNAPPLIED, protocol.Effect(999)} {
				detail := &protocol.Failure{Reason: testcase.reason, Effect: effect, Instance: []byte("star-a"), Version: proto.Uint64(17), RetryMs: proto.Uint32(250), Message: "SECRET"}
				data, cause := proto.Marshal(detail)
				if cause != nil {
					t.Fatal(cause)
				}
				failure := rpcError(status.Error(codes.Unknown, "SECRET"), metadata.Pairs("comet-error-bin", string(data)))
				confirmed := Unknown
				if effect == protocol.Effect_EFFECT_UNAPPLIED {
					confirmed = Unapplied
				}
				if failure.Code != testcase.code || failure.Effect != confirmed || failure.Instance != "star-a" || !failure.HasVersion || failure.Version != 17 || failure.Retry != 250*time.Millisecond {
					t.Fatalf("structured facts lost their protocol meaning: %#v", failure)
				}
				if failure.Unwrap() != nil || strings.Contains(failure.Error(), "SECRET") {
					t.Fatal("structured classification retained private diagnostics")
				}
			}
		})
	}
	for _, instance := range [][]byte{nil, {0}, {0xff}, []byte(strings.Repeat("x", 129))} {
		data, cause := proto.Marshal(&protocol.Failure{Reason: protocol.Reason_REASON_BUSY, Instance: instance})
		if cause != nil {
			t.Fatal(cause)
		}
		failure := rpcError(status.Error(codes.Unknown, ""), metadata.Pairs("comet-error-bin", string(data)))
		if failure.Code != CodeBusy || failure.Instance != "" || failure.HasVersion || failure.Version != 0 || failure.Retry != 0 || failure.Effect != Unknown {
			t.Fatal("invalid or absent structured fields became public evidence")
		}
	}
}

// TestErrorOwnership protects stored diagnostics and notification change detection.
func TestErrorOwnership(t *testing.T) {
	t.Parallel()
	var empty *Error
	if empty.Error() != "comet: no error" || empty.Unwrap() != nil || copyError(empty) != nil || !sameFailure(nil, nil) {
		t.Fatal("nil diagnostic behavior changed")
	}
	original := &Error{Code: CodeVersion, Effect: Unapplied, Instance: "star-a", Version: 7, HasVersion: true, Retry: time.Second}
	copy := copyError(original)
	if copy == original || !sameFailure(original, copy) || sameFailure(original, nil) || sameFailure(nil, original) {
		t.Fatal("diagnostic copying or absence comparison lost ownership")
	}
	for _, change := range []func(*Error){
		func(value *Error) { value.Code = CodeBusy }, func(value *Error) { value.Effect = Unknown },
		func(value *Error) { value.Instance = "star-b" }, func(value *Error) { value.Version++ },
		func(value *Error) { value.HasVersion = false }, func(value *Error) { value.Retry++ },
	} {
		copy := copyError(original)
		change(copy)
		if sameFailure(original, copy) || original.Code != CodeVersion || original.Effect != Unapplied || original.Instance != "star-a" || original.Version != 7 || !original.HasVersion || original.Retry != time.Second {
			t.Fatal("public diagnostic mutation was ignored or changed stored facts")
		}
	}
	copy.cause = context.Canceled
	if !sameFailure(original, copy) {
		t.Fatal("private cancellation identity changed public notification equality")
	}
	for code := CodeInternal; code <= CodeCallback; code++ {
		failure := &Error{Code: code, Instance: "SECRET"}
		if !strings.HasPrefix(failure.Error(), "comet: ") || strings.Contains(failure.Error(), "SECRET") || failure.Error() == "comet: unknown failure" {
			t.Fatal("known classification produced unsafe or unknown diagnostic text")
		}
	}
	if (&Error{Code: Code(255)}).Error() != "comet: unknown failure" {
		t.Fatal("unknown classification lost its safe fallback")
	}
}

// TestLocalContextErrorIdentity preserves canonical local causes and diagnostic ownership.
func TestLocalContextErrorIdentity(t *testing.T) {
	t.Parallel()
	for code := CodeInternal; code <= CodeCallback; code++ {
		var cause error
		switch code {
		case CodeTimeout:
			cause = context.DeadlineExceeded
		case CodeCanceled:
			cause = context.Canceled
		}
		failure := localError(code)
		copy := copyError(failure)
		if copy == failure || failure.Code != code || failure.Effect != Unapplied || !sameFailure(failure, copy) {
			t.Fatal("local error changed classification, effect or ownership")
		}
		for _, value := range []*Error{failure, copy} {
			if value.Unwrap() != cause || errors.Is(value, context.DeadlineExceeded) != (code == CodeTimeout) || errors.Is(value, context.Canceled) != (code == CodeCanceled) {
				t.Fatalf("local error lost canonical context identity: code=%v cause=%v", code, value.Unwrap())
			}
			if value.Instance != "" || value.HasVersion || value.Version != 0 || value.Retry != 0 {
				t.Fatal("local rejection invented remote evidence")
			}
		}
	}
}
