// Expose SDK client configuration and ownership of public read and write activities.
#pragma once
#include "beacon.hpp"
#include "observer.hpp"
#include "publisher.hpp"
#include "reader.hpp"
#include "subscriber.hpp"
#include "types.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace comet {
/// Shared native client for one active Star, with separate long-lived stream/unary channels and no direct Pulsar connection.
class Client {
public:
    /// Fixed connection, authentication, and resource limits validated by open before starting the core.
    struct Options {
        /// 1..64 distinct HOST:PORT business endpoints, tried sequentially with bounded switching rather than parallel connections to every candidate.
        std::vector<std::string> endpoints;
        /// Authenticated login by default; false explicitly selects anonymous access, without fallback after authentication failure.
        bool auth = true;
        /// Server TLS verification by default; false explicitly selects plaintext without changing the protocol or adding message signatures.
        bool tls = true;
        /// Fixed APIKEY, 1..128 bytes when authenticated; an existing Client cannot switch accounts.
        std::string key;
        /// Initial SECRET, 1..4096 bytes when authenticated; replace later with secret(), without echoing it.
        std::vector<std::uint8_t> secret;
        /// Optional CA PEM file overrides embedded roots; if neither is available, use gRPC's system trust roots.
        std::filesystem::path ca;
        /// Separate limits for subscription objects and actual RPCs, default 64, including canceled streams pending OnDone.
        std::size_t readers = 64;
        /// Shared Publisher/Beacon object limit, separate from Watch capacity.
        std::size_t beacons = 1024;
        /// Controlled current/prepared content budget, default 256 MiB; application-retained old Views are not forcibly reclaimed.
        std::size_t bytes = 256 * 1024 * 1024;
        /// Local initial Session/connection timeout, default three seconds; does not expire an established long-lived Session.
        std::chrono::milliseconds timeout{3000};
    };

    /// Success confirms local validation and asynchronous core admission, not remote readiness or successful login.
    static Result<Client> open(Options options);
    /// An empty handle creates no threads or network activity.
    Client() = default;
    /// Share the same application owner and core without authenticating again.
    Client(const Client&) = default;
    /// Transfer one owner reference, leaving the source empty.
    Client(Client&&) noexcept = default;
    /// Replace this handle's owner reference with a shared reference to the source owner.
    Client& operator=(const Client&) = default;
    /// Release this handle's owner reference and transfer the source reference, leaving the source empty.
    Client& operator=(Client&&) noexcept = default;
    /// Releasing the last Client does not close a core still owned by business objects.
    ~Client() = default;
    /// Replace SECRET for the same APIKEY, affecting later authentication only; Star credentials are unchanged.
    Result<void> secret(std::vector<std::uint8_t> value);
    /// Admit a fixed-scope Almanac reader; changed may run on another execution path before this call returns.
    Result<Reader> reader(Scope scope, std::string target = {}, Reader::Options options = {});
    /// Bind a complete Ephemeris scope or canonical UUID, sharing Reader's admission and bounded scheduling.
    Result<Observer> observer(Scope scope, std::string target = {}, Observer::Options options = {});
    /// Dynamic Catalog subscription with independent per-record content versions.
    Result<Subscriber> subscriber(Scope scope, std::string target = {}, Subscriber::Options options = {});
    /// Wait synchronously for initial registration confirmation; require 0 < beat < ttl.
    Result<Beacon> beacon(Scope scope, std::vector<std::uint8_t> attr, std::vector<std::uint8_t> data, std::chrono::milliseconds ttl, std::chrono::milliseconds beat, Beacon::Options options = {});
    /// Validate and bind a Catalog Scope; update performs synchronous commits with per-call TTL and SDK-managed versions.
    Result<Publisher> publisher(Scope scope);
    /// Close all owned business objects explicitly, idempotently and without blocking.
    void close() noexcept;
    /// Wait for local network/notification cleanup without implicitly closing; forbidden inside SDK callbacks.
    bool wait(std::chrono::milliseconds timeout) const;
    /// Observer exception count without sensitive text; zero for an empty Client.
    std::uint64_t exceptions() const noexcept;

private:
    /// Count application ownership separately from internal RPC references to avoid background self-retention.
    struct Owner;
    /// Retain an already admitted application owner without starting another core.
    explicit Client(std::shared_ptr<Owner> owner);
    /// Client copies share this application owner; internal callbacks do not count as application owners.
    std::shared_ptr<Owner> owner_;
};
} // namespace comet
