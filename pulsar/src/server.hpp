// Own Pulsar admission RPC handling and service lifecycle.
#pragma once
#include "issuer.hpp"
#include "pulse.hpp"

#include <cstddef>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace astra {
/// Owns Pulsar's admission and time listeners with their shared identity and ledger resources.
class Server {
public:
    /// Pulsar startup options, validated separately from Star's astra::Config.
    struct Config {
        /// Two required concrete IP:PORT endpoints. Port zero is allowed; wildcard IPs are not. Certificates require matching IP SANs.
        Endpoint listen, pulseListen;
        /// One Galaxy, a safe ASCII name of 1..64 bytes.
        std::string galaxy;
        /// Existing TLS/signing/account directory; defaults to identity, at most 4096 path bytes.
        std::filesystem::path identity = "identity";
        /// Dedicated SQLite file, default state/pulsar.db; parent must exist. Legacy journal/bbolt formats are rejected.
        std::filesystem::path state = "state/pulsar.db";
        /// Default restores an existing database. True explicitly initializes a new one and refuses to overwrite existing files.
        bool initialize = false;
        /// Current members per role: default 64, allowed 1..4096.
        std::size_t maximum = 64;
        /// Historical startup capacity: default 65536, allowed 1..1000000. Exhaustion requires explicit maintenance, never silent forgetting.
        std::size_t starts = 65536;
        /// Parses without reading identity files or creating directories; rejects duplicate and unknown options.
        static Result<Config> parse(std::span<const std::string_view> arguments);
        /// Static option and unit help; loads no secrets.
        static std::string_view help();
    };

    /// Loads identity and exclusively opens the ledger without listening. Failure leaves no partial service.
    explicit Server(Config config, Source::Provider provider = Source::sample);
    /// Stops both services and waits for every handler before releasing ledger and authority.
    ~Server();

    /// Keep one owner of RPC server and service lifecycle; copying is forbidden.
    Server(const Server&) = delete;

    /// Keep one owner of RPC server and service lifecycle; copying is forbidden.
    Server& operator=(const Server&) = delete;
    /// Starts Pulse before advertising its actual endpoint in registration replies. Listener failure rolls back listeners already started.
    void start();
    /// Idempotent shutdown with one shared five-second RPC deadline. Blocking system calls on failed disks can still delay handler exit.
    void stop();
    /// Actual bound endpoints, available after start succeeds.
    std::string admissionEndpoint() const;
    /// Return the bound Pulse endpoint, including the actual port selected by the listener.
    std::string pulseEndpoint() const;
    /// Current public time and quality; empty before cold-start calibration.
    std::optional<Clock::Reading> time() const;

private:
    /// Owned configuration; ephemeral ports are replaced after successful binding.
    Config config_;
    /// Declaration order destroys services before their borrowed material and storage.
    std::unique_ptr<Authority> authority_;
    /// Exclusive ledger, constructed before Issuer/Pulse and destroyed after them.
    std::unique_ptr<Ledger> ledger_;
    /// Continuous physical clock and sampling thread, destroyed only after all RPCs exit.
    std::unique_ptr<Source> clock_;
    /// Asynchronous four-timestamp service borrowing authority_, ledger_, and clock_.
    std::unique_ptr<Pulse> pulse_;
    /// Created after Pulse's actual port is known.
    std::unique_ptr<Issuer> issuer_;
    /// Owned time/admission listeners; stop clears them after every handler exits.
    std::unique_ptr<grpc::Server> pulseServer_, admissionServer_;
};
} // namespace astra
