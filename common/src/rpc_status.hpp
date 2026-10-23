// Maps gRPC failures to internal categories without importing remote error text.
#pragma once

#include <astra/types.hpp>

#include <grpcpp/support/status.h>

namespace astra {
/// Shared transport classification uses status codes only, never remote message/details, and avoids allocating a Status just to obtain its code.
/// Transient transport failure alone cannot permanently quarantine a configured candidate.
constexpr Status::Code rpcErrorCode(grpc::StatusCode status) noexcept {

    switch (status) {
    case grpc::StatusCode::UNAUTHENTICATED:
    case grpc::StatusCode::PERMISSION_DENIED:

        return Status::Code::Identity;
    case grpc::StatusCode::ABORTED:
    case grpc::StatusCode::ALREADY_EXISTS:

        return Status::Code::Conflict;
    case grpc::StatusCode::CANCELLED:

        return Status::Code::Cancelled;
    case grpc::StatusCode::RESOURCE_EXHAUSTED:

        return Status::Code::Capacity;
    case grpc::StatusCode::DEADLINE_EXCEEDED:

        return Status::Code::Timeout;
    case grpc::StatusCode::UNKNOWN:
    case grpc::StatusCode::UNAVAILABLE:

        return Status::Code::Transport;
    default:
        // Unmapped protocol/framework status codes default to protocol incompatibility.
        return Status::Code::Protocol;
    }
}

/// Returns owned Status with the mapped code and fixed local diagnostic, discarding all remote message/details.
inline Status rpcError(const grpc::Status& status) {

    return {rpcErrorCode(status.error_code()), "gRPC operation failed"};
}
} // namespace astra
