// Persist member identities and endpoint claims with explicit transaction and capacity boundaries.
#pragma once
#include <astra/types.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

namespace astra {
/// Pulsar SQLite member ledger. Publishes an immutable current view only after durable confirmation; stores no application data.
class Ledger {
public:
    /// One current member per deployment digest; old startup requests retain compact bindings rather than complete responses.
    using Members = std::map<std::string, Member, std::less<>>;
    /// Opens the dedicated database and exclusive service lock. Default initialize=false rejects a missing database; true explicitly creates a new one.
    /// Galaxy and authority bind database purpose. Maximum limits members per role; starts limits cumulative startups. Full capacity rejects new registrations.
    Ledger(const std::filesystem::path& path, std::string galaxy, std::string authority, std::size_t maximum, std::size_t starts, bool initialize = false);
    /// Closes files and releases the process lock after every service handler has stopped.
    ~Ledger();

    /// Keep one owner of SQLite connection and prepared statements; copying is forbidden.
    Ledger(const Ledger&) = delete;

    /// Keep one owner of SQLite connection and prepared statements; copying is forbidden.
    Ledger& operator=(const Ledger&) = delete;
    /// Under the writer lock, validates retries or prepares a new member and owned response before durable commit.
    /// If prepare throws, disk and visible state are unchanged. It must not reenter this ledger's registration methods.
    Result<void> registerMember(Member candidate, std::string_view requestId, const std::function<void(const Member&, const Members&)>& prepare);
    /// Verifies current credentials using an immutable snapshot, without waiting for password computation or the disk commit lock.
    bool current(const Member& member) const;
    /// Returns the captured immutable directory if member is current in that same view; otherwise returns null.
    /// Verification and directory lookup share one snapshot; membership does not establish liveness.
    std::shared_ptr<const Members> snapshot(const Member& member) const;

private:
    /// Each startup request binds deployment and committed epoch; superseded requests can never regain admission.
    struct Start {
        /// Owned deployment digest, preventing request ID reuse across deployments.
        std::string principal;
        /// Nonzero committed epoch, checked against the current deployment before allowing an idempotent retry.
        std::uint64_t epoch{};
    };

    /// Validates a new record against existing state. Recovery populates in place; live commits copy the small current-member table.
    Result<void> validate(const Member& member, std::string_view requestId, const Members& view) const;
    /// Hides the SQLite connection, statements, and process lock from client headers.
    struct Database;
    /// Atomically persists current member and startup binding; full uint64 epochs use eight-byte big-endian BLOBs.
    /// Any database exception disables writes and preserves the old view; restart is required to establish the actual commit result.
    bool commit(const Member& member, std::string_view request, std::string_view payload);
    /// Validates known schema, bindings, and all member/startup history before publishing recovered memory; imports no legacy journal.
    void restore();
    /// Contended only by registration handlers; Pulse reads never take this lock.
    std::mutex mutex_;
    /// Published snapshots are immutable; atomic shared ownership transfers their lifetimes.
    std::atomic<std::shared_ptr<const Members>> members_{std::make_shared<const Members>()};
    /// Bounded startup history, accessed only under the writer lock.
    std::map<std::string, Start, std::less<>> starts_;
    /// Fixed Galaxy; requests cannot switch it or continue against a mismatched database.
    std::string galaxy_;
    /// Per-role member and cumulative startup limits.
    std::size_t maximum_, maximumStarts_;
    /// Owns the SQLite connection and exclusive service lock; destruction releases every handle.
    std::unique_ptr<Database> database_;
    /// Remains false after I/O errors until restart recovery establishes the durable result.
    bool writable_ = true;
};
} // namespace astra
