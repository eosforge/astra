// Define public SDK values and result types without exposing gRPC implementation details.
#pragma once
#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace comet {
/// Opaque immutable payload; a non-null pointer to an empty vector is a valid empty value. Null means no record.
using Value = std::shared_ptr<const std::vector<std::uint8_t>>;

/// Two independent UTF-8 group names, without path, wildcard, or Unicode normalization semantics.
struct Scope {
    /// 1..128 bytes; public entries cannot start with __.
    std::string sector;
    /// 1..128 bytes, matched exactly with sector.
    std::string spectrum;
    /// Raw-byte equality checks binding consistency, not ownership or permission.
    bool operator==(const Scope&) const = default;
};

/// Bounded local errors expose no gRPC types, SECRET, or arbitrary remote payloads.
struct Error {
    /// Failure reason is separate from commit certainty; a network timeout does not prove that no commit occurred.
    enum class Code {
        /// Invalid argument or bound range.
        Input,
        /// Login rejected or expired; requires new credentials or login.
        Session,
        /// Local object is closed and rejects new work.
        Closed,
        /// Authority version is behind or the write version conflicts.
        Version,
        /// Conflicting content for the same business identity.
        Conflict,
        /// Registration or the target record has ended.
        Ended,
        /// Operation is stale or an unsent request was superseded.
        Obsolete,
        /// Server cannot resume continuously from this cursor.
        History,
        /// Permanent local or remote resource limit; stop repeated downloads.
        Limit,
        /// Temporary capacity shortage; bounded retry is allowed.
        Busy,
        /// Actual Star differs from the requested binding.
        Instance,
        /// Server business time is unavailable.
        Clock,
        /// Finite operation deadline exceeded; does not imply no commit.
        Timeout,
        /// Network failure or incomplete closure; bounded recovery is allowed.
        Transport,
        /// Successful reply or stream violates the agreed contract.
        Protocol,
        /// Unexpected internal failure; exception text is not exposed.
        Internal
    };
    /// What the SDK can establish about this failed attempt's commit effect.
    enum class Effect {
        /// No evidence by default that this attempt did not commit.
        Unknown,
        /// This attempt was not sent, or the server explicitly reported no commit.
        Unapplied
    };
    /// Defaults to neither success nor an argument error safe to retry.
    Code code = Code::Internal;
    /// Commit evidence covers this write attempt only, not earlier attempts.
    Effect effect = Effect::Unknown;
    /// Actual instance explicitly reported by the server; empty means unknown.
    std::string instance;
    /// Observed authority position; unknown differs from zero.
    std::optional<std::uint64_t> version;
    /// Bounded retry hint; zero means no remote hint.
    std::chrono::milliseconds retry{};
};

/// Expected business failures use uniform value semantics; allocation failure may still throw a standard exception.
template <class T>
using Result = std::expected<T, Error>;
} // namespace comet
