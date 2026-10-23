// Scalar fields use set_, submessages use mutable_, and repeated fields replace the collection; allocation follows Protobuf semantics.
#pragma once

#include "astra.pb.h"
#include "orbit.pb.h"
#include "pulsar.pb.h"

#include <utility>

namespace astra {

/// Message must be an explicitly adapted generated type; unsupported types have no reflection or runtime fallback.
/// Input is the field input type; value preserves its value category. Protocol consumers still validate fields.
template <typename Message>
struct Mutator;

/// Hello proxy for protocol version, frame limit, and admission material.
template <>
struct Mutator<::proto::astra::v1::Hello> {
    /// Borrows message; this proxy and returned references must not outlive it.
    ::proto::astra::v1::Hello& message;

    /// Sets protocol_major and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto protocolMajor(Input&& value) {
        message.set_protocol_major(std::forward<Input>(value));
        return *this;
    }

    /// Sets protocol_minor and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto protocolMinor(Input&& value) {
        message.set_protocol_minor(std::forward<Input>(value));
        return *this;
    }

    /// Sets max_frame_bytes and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto maxFrameBytes(Input&& value) {
        message.set_max_frame_bytes(std::forward<Input>(value));
        return *this;
    }

    /// Sets admission and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto admission(Input&& value) {
        message.set_admission(std::forward<Input>(value));
        return *this;
    }

    /// Sets admission_signature and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto admissionSignature(Input&& value) {
        message.set_admission_signature(std::forward<Input>(value));
        return *this;
    }
};

/// Astra Ping proxy sets Session keepalive sequence, independent of Pulsar four-timestamp synchronization.
template <>
struct Mutator<::proto::astra::v1::Ping> {
    /// Borrows message; this proxy and returned references must not outlive it.
    ::proto::astra::v1::Ping& message;

    /// Sets request_id and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto requestId(Input&& value) {
        message.set_request_id(std::forward<Input>(value));
        return *this;
    }
};

/// Astra Pong proxy echoes Session keepalive sequence without synchronization timestamps.
template <>
struct Mutator<::proto::astra::v1::Pong> {
    /// Borrows message; this proxy and returned references must not outlive it.
    ::proto::astra::v1::Pong& message;

    /// Sets request_id and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto requestId(Input&& value) {
        message.set_request_id(std::forward<Input>(value));
        return *this;
    }
};

/// Pulsar Ping proxy for time-probe fields.
template <>
struct Mutator<::proto::pulsar::v1::Ping> {
    /// Borrows the send-time sample message without owning or extending its lifetime.
    ::proto::pulsar::v1::Ping& message;

    /// Sets Star's send monotonic nanoseconds without reading or converting clocks.
    template <typename Input>
    auto t0(Input&& value) {
        message.set_t0(std::forward<Input>(value));
        return *this;
    }
};

/// Pulsar Pong proxy for time-response fields.
template <>
struct Mutator<::proto::pulsar::v1::Pong> {
    /// Borrows the four-timestamp response; avoid mutation during in-flight gRPC Write.
    ::proto::pulsar::v1::Pong& message;

    /// Echoes T0 unchanged for Star to match its sole in-flight request.
    template <typename Input>
    auto t0(Input&& value) {
        message.set_t0(std::forward<Input>(value));
        return *this;
    }

    /// Sets Pulsar's receive-time Unix nanosecond estimate.
    template <typename Input>
    auto t1(Input&& value) {
        message.set_t1(std::forward<Input>(value));
        return *this;
    }

    /// Sets Pulsar's Unix nanosecond estimate immediately before send submission.
    template <typename Input>
    auto t2(Input&& value) {
        message.set_t2(std::forward<Input>(value));
        return *this;
    }

    /// Sets nanosecond error estimate including upstream uncertainty and residual correction.
    template <typename Input>
    auto uncertaintyNanoseconds(Input&& value) {
        message.set_uncertainty_ns(std::forward<Input>(value));
        return *this;
    }

    /// Reports a calibrated source meeting quality requirements; defaults to false.
    template <typename Input>
    auto synchronized(Input&& value) {
        message.set_synchronized(std::forward<Input>(value));
        return *this;
    }

    /// Reports Pulsar monotonic-clock rho for Star tolerance and uncertainty estimates.
    template <typename Input>
    auto precisionNanoseconds(Input&& value) {
        message.set_precision_ns(std::forward<Input>(value));
        return *this;
    }
};

/// Protocol-error proxy sets failure category and reason.
template <>
struct Mutator<::proto::astra::v1::ProtocolError> {
    /// Borrows message; this proxy and returned references must not outlive it.
    ::proto::astra::v1::ProtocolError& message;

    /// Sets code and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto code(Input&& value) {
        message.set_code(std::forward<Input>(value));
        return *this;
    }
};

/// Session-frame proxy for Hello, Ping, Pong, and errors; other business frames use generated APIs directly.
template <>
struct Mutator<::proto::astra::v1::SessionPacket> {
    /// Borrows message; this proxy and returned references must not outlive it.
    ::proto::astra::v1::SessionPacket& message;

    /// Sets hello and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto hello(Input&& value) {
        *message.mutable_hello() = std::forward<Input>(value);
        return *this;
    }

    /// Sets ping and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto ping(Input&& value) {
        *message.mutable_ping() = std::forward<Input>(value);
        return *this;
    }

    /// Sets pong and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto pong(Input&& value) {
        *message.mutable_pong() = std::forward<Input>(value);
        return *this;
    }

    /// Sets rejection and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto rejection(Input&& value) {
        *message.mutable_rejection() = std::forward<Input>(value);
        return *this;
    }
};

/// Registration-request proxy for Member description and request identity.
template <>
struct Mutator<::proto::orbit::v1::RegistrationRequest> {
    /// Borrows message; this proxy and returned references must not outlive it.
    ::proto::orbit::v1::RegistrationRequest& message;

    /// Sets galaxy and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto galaxy(Input&& value) {
        message.set_galaxy(std::forward<Input>(value));
        return *this;
    }

    /// Sets advertise and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto advertise(Input&& value) {
        message.set_advertise(std::forward<Input>(value));
        return *this;
    }

    /// Sets role and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto role(Input&& value) {
        message.set_role(std::forward<Input>(value));
        return *this;
    }

    /// Sets group and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto group(Input&& value) {
        message.set_group(std::forward<Input>(value));
        return *this;
    }

    /// Sets candidate_round and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto candidateRound(Input&& value) {
        message.set_candidate_round(std::forward<Input>(value));
        return *this;
    }

    /// Sets username and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto username(Input&& value) {
        message.set_username(std::forward<Input>(value));
        return *this;
    }

    /// Sets password and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto password(Input&& value) {
        message.set_password(std::forward<Input>(value));
        return *this;
    }

    /// Sets request_id and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto requestId(Input&& value) {
        message.set_request_id(std::forward<Input>(value));
        return *this;
    }
};

/// Registration-response proxy for Member, directory, and signature.
template <>
struct Mutator<::proto::orbit::v1::RegistrationResponse> {
    /// Borrows message; this proxy and returned references must not outlive it.
    ::proto::orbit::v1::RegistrationResponse& message;

    /// Sets members and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto members(Input&& value) {
        *message.mutable_members() = std::forward<Input>(value);
        return *this;
    }

    /// Sets admission and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto admission(Input&& value) {
        message.set_admission(std::forward<Input>(value));
        return *this;
    }

    /// Sets signature and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto signature(Input&& value) {
        message.set_signature(std::forward<Input>(value));
        return *this;
    }
};

/// Member-description proxy for identity, endpoint, role, and epoch.
template <>
struct Mutator<::proto::orbit::v1::Member> {
    /// Borrows message; this proxy and returned references must not outlive it.
    ::proto::orbit::v1::Member& message;

    /// Sets galaxy and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto galaxy(Input&& value) {
        message.set_galaxy(std::forward<Input>(value));
        return *this;
    }

    /// Sets id and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto id(Input&& value) {
        message.set_id(std::forward<Input>(value));
        return *this;
    }

    /// Sets principal and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto principal(Input&& value) {
        message.set_principal(std::forward<Input>(value));
        return *this;
    }

    /// Sets advertise and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto advertise(Input&& value) {
        message.set_advertise(std::forward<Input>(value));
        return *this;
    }

    /// Sets epoch and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto epoch(Input&& value) {
        message.set_epoch(std::forward<Input>(value));
        return *this;
    }

    /// Sets role and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto role(Input&& value) {
        message.set_role(std::forward<Input>(value));
        return *this;
    }

    /// Sets group and returns this proxy; Protobuf determines copy/move behavior.
    template <typename Input>
    auto group(Input&& value) {
        message.set_group(std::forward<Input>(value));
        return *this;
    }
};

/// mutate returns a proxy borrowing message without extending lifetime, serialization, or allocation.
/// Returned chainable proxy must not outlive the target message.
template <typename Message>
inline Mutator<Message> mutate(Message& message) {
    return {message};
}

} // namespace astra
