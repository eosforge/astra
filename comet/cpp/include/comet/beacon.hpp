// Expose lifetime-bound Ephemeris publication and renewal through the public SDK.
#pragma once
#include "types.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace comet {
namespace detail {
class Beaming;
}
class Client;

/// One automatic registration lifetime with fixed Attr/TTL and a shared Client; it does not adopt an application's old UUID.
class Beacon {
public:
    /// Confirmed logical registration identity, independent of the current transport connection.
    struct Identity {
        /// Fixed application scope, excluding internal __ scopes.
        Scope scope;
        /// Star that admitted this UUID; instance changes recover the same logical UUID.
        std::string instance;
        /// Raw 16-byte UUIDv4 issued by Star, possibly containing NUL; Identity is unavailable until confirmation.
        std::string uuid;
        /// Compare identity only, independently of Session and TCP connections.
        bool operator==(const Identity&) const = default;
    };

    /// Own the identity and positive order acknowledged for one Data update.
    struct Receipt {
        /// Identity fixed for this Data request, unaffected by later registration recovery.
        Identity identity;
        /// Confirmed positive Data order; does not attest renewal or cluster durability.
        std::uint64_t order{};
    };
    /// Local registration and lease confidence; these states do not prove remote liveness.
    enum class Phase {
        /// Recovering the same logical ID; new Data updates are refused.
        Recovering,
        /// UUID unconfirmed while initial creation or registration recovery proceeds.
        Waiting,
        /// Identity confirmed with remaining conservative local lease budget.
        Ready,
        /// The old identity may still exist, but local budget or network state cannot confirm it.
        Uncertain,
        /// Automatic creation paused after a permanent configuration/protocol failure.
        Failed,
        /// Application recovery stopped; remote removal remains bounded best effort.
        Closed
    };

    /// Owned registration snapshot with optional confirmed identity and recent failure.
    struct State {
        /// State at snapshot capture, not a live remote-liveness guarantee.
        Phase phase = Phase::Waiting;
        /// Present only after actual identity confirmation.
        std::optional<Identity> identity;
        /// Bounded recent cause without payload or login secrets.
        std::optional<Error> error;
    };

    /// Initial-registration budget and serial state-notification callback.
    struct Options {
        /// Total initial-registration deadline for connection, authentication and RPC, in (0, 1 min].
        std::chrono::milliseconds timeout{3000};
        /// Serial identity/state notifications outside SDK locks; callbacks must return promptly.
        std::move_only_function<void(State)> changed;
    };

    /// An empty handle starts no network or automatic task.
    Beacon() = default;
    /// Transfer sole automatic-renewal ownership.
    Beacon(Beacon&&) noexcept;
    /// Close the previous object without blocking before transfer.
    Beacon& operator=(Beacon&&) noexcept;
    /// Keep one owner of registration activity and its cleanup responsibility; copying is forbidden.
    Beacon(const Beacon&) = delete;
    /// Keep one owner of registration activity and its cleanup responsibility; copying is forbidden.
    Beacon& operator=(const Beacon&) = delete;
    /// Close idempotently without waiting for network in the destructor.
    ~Beacon();
    /// Recheck the suspend-aware local lease budget without Pulsar or business RPCs.
    State state() const;
    /// Synchronously submit complete Data; concurrent calls return busy. Failure neither resends nor overwrites the confirmed recovery cache.
    Result<Receipt> update(std::vector<std::uint8_t> data, std::chrono::milliseconds timeout = std::chrono::seconds(3));
    /// Take an owned copy synchronously.
    Result<Receipt> update(std::span<const std::uint8_t> data, std::chrono::milliseconds timeout = std::chrono::seconds(3));
    /// The caller must exclude writable aliases; nullptr is invalid.
    Result<Receipt> update(Value data, std::chrono::milliseconds timeout = std::chrono::seconds(3));
    /// Set/replace serial sampling with interval > 0; an empty callback disables it and missed ticks are skipped.
    Result<void> tick(std::chrono::milliseconds interval, std::move_only_function<Value()> callback);
    /// Replace state notifications and schedule the current state immediately; an empty callback disables them.
    Result<void> changed(std::move_only_function<void(State)> callback);
    /// Close logically at once with bounded best-effort Remove.
    void destroy() noexcept;
    /// Stop renewal and registration recovery; bounded deregistration does not guarantee immediate remote deletion.
    void close() noexcept;
    /// Wait for actual local cleanup; blocking is rejected inside SDK callbacks.
    bool wait(std::chrono::milliseconds timeout) const;

private:
    friend class Client;
    /// Take the factory-created registration activity; the application handle owns its close responsibility.
    explicit Beacon(std::shared_ptr<detail::Beaming> beaming);
    /// Delivered identities and payloads do not keep automatic registration alive independently of the application handle.
    std::shared_ptr<detail::Beaming> beaming_;
};
} // namespace comet
