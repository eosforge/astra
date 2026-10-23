// Expose Catalog publication and its completion and cancellation contracts.
#pragma once
#include "types.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace comet {
namespace detail {
class Publishing;
}
class Client;

/// Synchronous Catalog publisher bound to one Scope, with explicit per-commit TTL and SDK-managed versions.
class Publisher {
public:
    /// Acknowledgment from one Star for this publish attempt, without a replication guarantee.
    struct Receipt {
        /// Star that acknowledged this attempt; does not prove replication completion.
        std::string instance;
        /// Positive SDK-assigned content version, not a global transaction ID.
        std::uint64_t version{};
    };

    /// Atomic batch of 1..128 unique UTF-8 keys; combined key/payload size is at most 1 MiB.
    struct Entry {
        /// 1..1024 bytes; the application guarantees one writer for a key.
        std::string key;
        /// Shared immutable complete value; nullptr is rejected while an empty vector is valid.
        Value value;
    };

    /// An empty handle starts no network activity or timers.
    Publisher() = default;
    /// Transfer activity ownership to this handle, leaving the source empty.
    Publisher(Publisher&&) noexcept;
    /// Close the old object before transferring ownership.
    Publisher& operator=(Publisher&&) noexcept;
    /// Keep one owner of publication activity; copying is forbidden.
    Publisher(const Publisher&) = delete;
    /// Keep one owner of publication activity; copying is forbidden.
    Publisher& operator=(const Publisher&) = delete;
    /// Cancel owned calls without blocking or closing the shared Client.
    ~Publisher();

    /// Synchronously commit one complete atomic batch; ttl is 1 s..10 min and timeout is (0, 1 min].
    /// Reuse a confirmed baseline only for the same target and exact key set; otherwise query first. Payloads are not retained.
    /// One deadline covers connection, query and at most one explicit version-conflict repair; timeout may follow a committed write.
    /// Concurrent calls on this object return busy without coalescing; synchronous writes inside SDK notifications also return busy.
    /// No payload remains queued for resend or renewal after return; buffers survive only until the real RPC completes.
    Result<Receipt> update(std::vector<Entry> entries, std::chrono::milliseconds ttl, std::chrono::milliseconds timeout = std::chrono::seconds(3));
    /// A single key is a batch special case; vector overloads transfer payload ownership without exposing a version parameter.
    Result<Receipt> update(std::string key, std::vector<std::uint8_t> data, std::chrono::milliseconds ttl, std::chrono::milliseconds timeout = std::chrono::seconds(3));
    /// Stop local admission idempotently and cancel the current RPC.
    void close() noexcept;
    /// Wait only for real call drainage, without implicitly closing.
    bool wait(std::chrono::milliseconds timeout) const;

private:
    friend class Client;
    /// Take the factory-created publication activity without sending a new request.
    explicit Publisher(std::shared_ptr<detail::Publishing> publishing);
    /// In-flight internal calls retain their own lifetime.
    std::shared_ptr<detail::Publishing> publishing_;
};
} // namespace comet
