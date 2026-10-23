// Expose the native Catalog domain and its retained business-state operations.
#pragma once
#include <astra/clock.hpp>

#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <vector>

namespace astra {
/// Catalog native records and merge rules. Application versions are per key; outer commits sequence source groups across all Scopes.
/// Prepares candidates without networking, allocating versions, or mutating old records. The caller atomically publishes index/history/wheel/projection.
class Catalog {
public:
    /// Commit boundary for local source, public projection, and local TTL.
    class State;
    /// Bounded encoding of frozen public batches.
    class Edition;
    /// Public Watch lifetime and backpressure.
    class Feed;
    /// Publish/Renew/Watch on the separate application endpoint.
    class Service;
    /// Opaque complete application bytes; an empty Buffer is present.
    using Buffer = std::vector<std::uint8_t>;
    /// Immutable payload ownership; null is only a watermark, distinct from empty content.
    using Value = std::shared_ptr<const Buffer>;

    /// Candidate failure preserves state; RPC adapters distinguish version, missing-record, time, and input errors.
    enum class Error {
        /// Invalid version, TTL, payload, or inconsistent native record.
        Input,
        /// Local application time is unavailable; reference disconnection alone is insufficient.
        Clock,
        /// No live complete local-source body; Renew cannot take ownership of a remote source.
        Ended,
        /// Below the highest known application version, or Renew differs from the local-source version.
        Version,
        /// Different complete bodies claim the same application version.
        Conflict,
        /// Absolute-deadline overflow; never converted into an infinite lease.
        Exhausted
    };

    /// One source fact or local merged watermark, without source/key/Scope strings or replication position.
    struct Record {
        /// Known positive content version, retained in its watermark after payload cleanup.
        std::uint64_t version{};
        /// Shared active content; when absent, deadline must also be absent.
        Value value;
        /// Finite Unix deadline paired with value. Watermarks have no deadline or active wheel node.
        std::optional<Clock::Time> deadline;
    };

    /// Merged candidates are not source facts; other-source higher versions never write back into the local-source table.
    struct Change {
        /// New merged watermark and visible candidate, swapped only with the current merged record without direct broadcast.
        Record record;
        /// Only visible content changes update projection/cursor. Invisible watermark increases and deadline extensions do not wake subscribers.
        bool visible{};
    };

    /// Full Publish may start without a local source or rebuild an expired body at the same version; higher versions may skip numbers.
    /// Null source/merged means unseen. Read time under final acceptance protection; never borrow a remote deadline.
    static std::expected<Record, Error> publish(const Record* source, const Record* merged, Value value, std::uint64_t version, std::uint32_t ttl, const Clock::Reading& reading) noexcept;
    /// Renews a live complete local-source record while checking cross-source watermarks, without creating an application version.
    static std::expected<Record, Error> renew(const Record* source, const Record* merged, std::uint64_t version, std::uint32_t ttl, const Clock::Reading& reading) noexcept;
    /// Merges verified facts; higher expired facts/watermarks raise the floor. Equal-version watermarks preserve valid bodies elsewhere.
    /// Use current epoch time and the incoming original deadline, without adding TTL again. Conflict preserves current.
    static std::expected<Change, Error> merge(const Record* current, const Record& incoming, Clock::Time now) noexcept;
    /// Expires bodies while retaining highest versions. Missing/live bodies are unchanged; creates no source event.
    static Record expire(const Record& current, Clock::Time now) noexcept;
    /// Validates native shape and single-body limits without reading the clock, for source baselines and local candidates.
    static bool valid(const Record& record) noexcept;

private:
    /// Public paging policy, keeping Protobuf types outside native storage.
    class Encoding;
    /// Validates established nonnegative time without requiring current Pulsar synchronization.
    static std::expected<void, Error> ready(const Clock::Reading& reading) noexcept;
    /// Validates both optional old records without creating missing index entries.
    static bool valid(const Record* source, const Record* merged) noexcept;
    /// Checks highest versions and equal-version bodies exactly, including present empty values.
    static std::expected<void, Error> check(const Record* current, std::uint64_t version, const Value& value) noexcept;
    /// Compares only downstream presence, body, and content version; deadline changes are not content updates.
    static bool visible(const Record* current, const Record& candidate) noexcept;
    /// Maps local deadline errors to native failure categories.
    static Error error(Clock::Error value) noexcept;
};
} // namespace astra
