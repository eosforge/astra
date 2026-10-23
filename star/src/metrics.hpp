// Serve independent read-only metrics without business RPCs, record payloads, or authentication material.
#pragma once
#include <astra/types.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace astra {

/// Own a bounded native HTTP listener and publish immutable observations from the control thread.
class Metrics {
public:
    /// Fixed-cardinality runtime state; all counts start at zero and recovery bytes are logical budget, not RSS.
    struct Sample {
        /// Admitted process ID used only in the response header; empty means not yet admitted.
        std::string instance;
        /// Whether the process currently accepts business operations.
        bool ready{};
        /// Whether the first complete authoritative baseline has been installed.
        bool almanac{};
        /// Whether continuous local epoch time is available.
        bool clock{};
        /// Whether current reference synchronization quality meets its threshold.
        bool synchronized{};
        /// Estimated clock uncertainty in nanoseconds; clock=false makes no precision claim.
        std::uint64_t uncertainty{};
        /// Trusted Star member count, including this node.
        std::size_t members{};
        /// Installed bidirectional peer sessions.
        std::size_t sessions{};
        /// Logical bytes held by frozen baselines and recovery candidates.
        std::size_t recovery{};
    };

    /// Bind a numeric endpoint and start the dedicated bounded HTTP loop; RAII releases resources on failure.
    explicit Metrics(const Endpoint& endpoint);
    /// Request stop, wake polling, and join before releasing clients and the listener, without waiting for network replies.
    ~Metrics();
    /// Preserve unique listener ownership.
    Metrics(const Metrics&) = delete;
    /// Prevent assignment from replacing an active listener owner.
    Metrics& operator=(const Metrics&) = delete;
    /// Publish a full snapshot from the control thread, whose caller cadence is at most once per second.
    /// Return false and retain the old snapshot on invalid input or allocation failure, leaving business state unchanged.
    bool publish(const Sample& sample) noexcept;
    /// Return the actual bound endpoint, including a system-assigned test port, without exposing deployment identity.
    Endpoint endpoint() const;

private:
    /// Private nonblocking HTTP state using platform-specific transport primitives.
    struct Server;
    /// Retain server state until its worker has stopped and joined.
    std::unique_ptr<Server> server_;
};
} // namespace astra
