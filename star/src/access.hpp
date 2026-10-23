// Validate public access credentials and authorization against authoritative Star state.
#pragma once
#include "almanac.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <unordered_map>

namespace astra {
/// Application login index and logical sessions, updated only by Receiver at internal-credential commit boundaries. No ACL or idle scanning.
/// Lock order: Access -> Library -> Almanac. Business writes retain Permit through actual commit.
class Access {
    /// Shared snapshot validity; full replacement invalidates old sessions in O(1), with cancellation propagated outside the lock.
    struct Group;
    /// Parsed SECRET and shared account validity; consecutive same-value Set preserves the object.
    struct Account;

public:
    /// Login failure category, excluding APIKEY, SECRET, and session bytes.
    enum class Error {
        /// Invalid, deleted, rotated, or stream-ended credentials/token.
        Denied,
        /// Active-token capacity reached; existing sessions are preserved.
        Capacity,
        /// Random source failure or bounded collision retries exhausted.
        Random
    };

    /// Session owned by a real Session stream. The token authenticates later RPC metadata without extending stream lifetime.
    class Session {
    public:
        /// Detaches stop forwarding. May be destroyed after Gateway OnDone without accessing the Access owner.
        ~Session() = default;
        /// Borrows the raw 32-byte token for this object's lifetime; no text encoding.
        std::string_view token() const noexcept;
        /// Cancellation source for the actual stream. Rotation, snapshot replacement, and close request stop; callbacks must be short and noexcept.
        std::stop_token stopped() const noexcept;

    private:
        friend class Access;

        /// Forwards invalidation to session cancellation without capturing the Session address.
        struct Relay {
            /// Owns shared session stop state without owning the service.
            std::stop_source target;
            /// Propagates cancellation without taking Access or storage locks.
            void operator()() const noexcept;
        };

        /// Access-only construction from one installed account/group pair and a system-generated token.
        Session(std::string token, std::shared_ptr<Account> account, std::shared_ptr<Group> group);
        /// Raw random token, immutable after installation.
        const std::string token_;
        /// Retains this account's credential version independently of index-node lifetime.
        const std::shared_ptr<Account> account_;
        /// Retains the creating snapshot's validity without a public authentication epoch.
        const std::shared_ptr<Group> group_;
        /// Logical-stream stop state, triggered by invalidation or explicit close.
        std::stop_source stop_;
        /// Destroyed before account_ to avoid dangling access.
        std::stop_callback<Relay> accountStop_;
        /// Destroyed before group_.
        std::stop_callback<Relay> groupStop_;
    };

    /// Shared-lock guard for final business validation and commit; never retain across network waits or external callbacks.
    class Permit {
    public:
        /// Transfer the held shared lock and its stop token without extending authorization beyond the guard.
        Permit(Permit&&) noexcept = default;

        /// Keep one owner of held authorization lock; copying is forbidden.
        Permit(const Permit&) = delete;
        /// Session-close/credential-revocation notification may outlive Permit, without extending authorization.
        std::stop_token stopped() const noexcept;

    private:
        friend class Access;
        /// Takes an already held shared lock; authorization is no longer guaranteed after unlock.
        explicit Permit(std::shared_lock<std::shared_mutex> lock, std::stop_token stopped);
        /// Spans business commit, ordered against exclusive credential replacement and Session close.
        std::shared_lock<std::shared_mutex> lock_;
        /// The actual logical Session, without idle scanning or an extra lease.
        std::stop_token stopped_;
    };

    /// Privately prepared full credential index, installed or discarded together with Receiver's Almanac Draft.
    class Draft {
    public:
        /// Creates a fresh validity group without changing current sessions.
        Draft();

        /// Transfer the private candidate and its publication responsibility without copying mutable preparation state.
        Draft(Draft&&) noexcept = default;

        /// Keep one owner of privately prepared candidate state; copying is forbidden.
        Draft(const Draft&) = delete;
        /// Owns parsed SECRET. Key: 1..128 UTF-8 bytes; secret: 1..4096 bytes. Duplicate keys are rejected.
        bool set(std::string key, Almanac::Buffer secret);

    private:
        friend class Access;
        /// Exclusive during preparation and consumed by installation.
        std::shared_ptr<Group> group_;
        /// At most 65536 parsed credentials; Almanac's full preparation budget still limits payloads.
        std::map<std::string, std::shared_ptr<Account>, std::less<>> accounts_;
    };

    /// Runs once: true means new commit, false means replay. Failure or exception must leave no partial commit.
    using Commit = std::move_only_function<std::expected<bool, Almanac::Error>()>;
    /// Empty table with 1..65536 active Sessions, default 4096. Creates no thread or listener.
    explicit Access(std::size_t maximum = 4096);
    /// Owner drains business calls first; destruction invalidates externally retained Sessions and stops their notification sources.
    ~Access();
    /// Owns the full index and orders installation with the Almanac commit. New versions revoke old sessions; replay does not.
    std::expected<bool, Almanac::Error> reset(Draft&& draft, Commit commit);
    /// Contiguous single-key credential commit. Empty secret deletes; same-value Set preserves sessions. Allocate before commit.
    std::expected<bool, Almanac::Error> apply(std::string key, std::optional<Almanac::Buffer> secret, Commit commit);
    /// Compares SECRET once and bounds random-token retries. The actual RPC calls close from OnDone.
    std::expected<std::shared_ptr<Session>, Error> open(std::string_view key, std::span<const std::uint8_t> secret);
    /// Validates token and current credentials, returning a guard through final commit without rechecking SECRET.
    std::expected<Permit, Error> enter(std::string_view token) const;
    /// Removes authorization before sending stop outside the lock. Repeated close is harmless and cannot affect new sessions.
    void close(const std::shared_ptr<Session>& session);

private:
    /// Transparent token lookup avoids allocating temporary strings for borrowed 32-byte metadata.
    struct Hash {

        using is_transparent = void;

        /// Hash token bytes directly so borrowed metadata lookup needs no temporary string.
        std::size_t operator()(std::string_view value) const noexcept;
    };

    /// Shared input checks for login/credential preparation, outside authenticated-RPC hot paths.
    static bool valid(std::string_view key, std::span<const std::uint8_t> secret) noexcept;
    /// Equal-length SECRET uses BoringSSL constant-time comparison.
    static bool equal(std::span<const std::uint8_t> left, std::span<const std::uint8_t> right) noexcept;
    /// Active-session limit; Gateway separately bounds RPCs still authenticating.
    const std::size_t maximum_;
    /// Protects index and authorization state only; cancellation and reclamation run outside the lock.
    mutable std::shared_mutex mutex_;
    /// Current snapshot group, initially valid and empty, with no usable APIKEY.
    std::shared_ptr<Group> group_;
    /// Validated credentials updated at the same commit boundary as internal Almanac.
    std::map<std::string, std::shared_ptr<Account>, std::less<>> accounts_;
    /// Direct token index. Revoked entries still count until OnDone, preventing cancellation backlog from bypassing capacity.
    std::unordered_map<std::string, std::shared_ptr<Session>, Hash, std::equal_to<>> sessions_;
};
} // namespace astra
