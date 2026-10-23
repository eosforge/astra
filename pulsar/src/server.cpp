// Own Pulsar admission RPC handling and service lifecycle.
#include "server.hpp"

#include <grpc/support/time.h>
#include <grpcpp/server_builder.h>

#include <algorithm>
#include <bitset>
#include <charconv>
#include <stdexcept>

namespace astra {

std::string_view Server::Config::help() {

    return "Usage: pulsar --listen=IP:PORT --pulse-listen=IP:PORT --galaxy=ID [options]\n" "  --identity=DIR       TLS, admission.key/pub and accounts.json; default=identity\n" "  --state=FILE         Exclusive SQLite database; default=state/pulsar.db\n" "  --init=true|false    Initialize a new database; default=false\n" "  --max-members=N      Capacity per role, 1..4096; default=64\n" "  --max-starts=N       Retained startup records, 1..1000000; default=65536\n" "  --help / --version   Do not load credentials or start services\n" "Listeners require concrete IPs authorized by the TLS certificate. Stop with SIGINT or SIGTERM.\n";
}

Result<Server::Config> Server::Config::parse(std::span<const std::string_view> arguments) {

    constexpr std::array names{"listen", "pulse-listen", "galaxy", "identity", "state", "max-members", "max-starts", "init"};
    // Track explicit occurrences; defaults do not satisfy required options.
    std::bitset<names.size()> seen;

    Server::Config result;
    for (std::size_t i = 0; i < arguments.size(); ++i) {

        const auto argument = arguments[i];
        if (!argument.starts_with("--")) {
            return Status::configuration("Expected a named Pulsar option");
        }

        const auto equal = argument.find('=');

        const auto name = argument.substr(2, equal == std::string_view::npos ? equal : equal - 2);

        const auto found = std::ranges::find(names, name);
        if (found == names.end()) {
            return Status::configuration("Unknown Pulsar option");
        }

        const auto index = static_cast<std::size_t>(found - names.begin());
        if (seen.test(index)) {
            return Status::configuration("Duplicate Pulsar option");
        }
        seen.set(index);

        const auto value = equal != std::string_view::npos ? argument.substr(equal + 1) : i + 1 < arguments.size() ? arguments[++i]
                                                                                                                   : std::string_view{};
        if (value.empty() || value.size() > 4096 || value.starts_with("--")) {
            return Status::configuration("Missing or oversized Pulsar value");
        }
        if (index <= 1) {
            // Both listeners require concrete IPs; port zero permits system allocation.
            const auto endpoint = Endpoint::parse(value, true);
            if (!endpoint || endpoint->wildcard) {
                return Status::configuration("Pulsar requires a concrete numeric listener");
            }
            (index == 0 ? result.listen : result.pulseListen) = *endpoint;
        } else if (index == 2) {
            result.galaxy = value;
        } else if (index == 3) {
            result.identity = value;
        } else if (index == 4) {
            result.state = value;
        } else if (index == 7) {
            if (value != "true" && value != "false") {
                return Status::configuration("Pulsar init must be true or false");
            }
            result.initialize = value == "true";
        } else {

            std::size_t count{};

            const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), count);
            if (error != std::errc{} || end != value.data() + value.size() || count == 0 || count > (index == 5 ? 4096U : 1'000'000U)) {
                return Status::configuration("Invalid Pulsar capacity");
            }
            (index == 5 ? result.maximum : result.starts) = count;
        }
    }
    if (!seen.test(0) || !seen.test(1) || !seen.test(2) || !Member::validName(result.galaxy) || (result.listen.port != 0 && result.listen == result.pulseListen)) {
        return Status::configuration("Pulsar requires a Galaxy and two distinct listeners");
    }
    return result;
}

Server::Server(Server::Config config, Source::Provider provider) : config_(std::move(config)) {

    // Validate both TLS endpoints and signing material before creating the ledger or threads.
    auto authority = Authority::load(config_.identity, config_.listen, config_.pulseListen);
    if (!authority) {
        throw std::runtime_error("Cannot load Pulsar authority");
    }
    authority_ = std::move(*authority);
    ledger_ = std::make_unique<Ledger>(config_.state, config_.galaxy, authority_->keyId(), config_.maximum, config_.starts, config_.initialize);
    clock_ = std::make_unique<Source>(std::move(provider));
    pulse_ = std::make_unique<Pulse>(*authority_, *ledger_, *clock_);
}

Server::~Server() {
    stop();
}

void Server::start() {

    if (pulseServer_ || admissionServer_) {
        throw std::runtime_error("Pulsar already started");
    }

    // Separate listeners and ResourceQuotas isolate registration from Pulse even though they share a certificate.
    const auto build = [&](grpc::Service& service, Endpoint& endpoint, bool pulse) {
        grpc::ServerBuilder builder;
        // Disable port sharing so connections cannot reach different ledgers or time references at the same endpoint.
        builder.AddChannelArgument("grpc.so_reuseport", 0);
        builder.RegisterService(&service);
        builder.SetMaxReceiveMessageSize(pulse ? 128 : 4096);
        // Budget the full directory for four roles of up to 4096 members each, independently of Star/Polaris-only node reads.
        builder.SetMaxSendMessageSize(pulse ? 128 : 8 * 1024 * 1024);
        builder.AddChannelArgument("grpc.server_handshake_timeout_ms", 3000);
        builder.AddChannelArgument("grpc.max_connection_idle_ms", 30000);
        builder.AddChannelArgument("grpc.max_concurrent_streams", pulse ? 1 : 4);
        builder.AddChannelArgument("grpc.max_metadata_size", 4096);

        grpc::ResourceQuota quota;
        quota.Resize(pulse ? 16U * 1024 * 1024 : 32U * 1024 * 1024);
        if (!pulse) {
            // Only admission performs synchronous KDF and disk commits; Pulse callbacks create no blocking thread per stream.
            builder.SetSyncServerOption(grpc::ServerBuilder::SyncServerOption::NUM_CQS, 2);
            builder.SetSyncServerOption(grpc::ServerBuilder::SyncServerOption::MIN_POLLERS, 1);
            builder.SetSyncServerOption(grpc::ServerBuilder::SyncServerOption::MAX_POLLERS, 4);
            quota.SetMaxThreads(16);
        }
        builder.SetResourceQuota(quota);

        int port = 0;
        builder.AddListeningPort(endpoint.text(), authority_->identity().serverCredentials(), &port);

        auto server = builder.BuildAndStart();
        if (!server || port <= 0) {
            throw std::runtime_error("Cannot bind Pulsar TLS listener");
        }
        endpoint.port = static_cast<std::uint16_t>(port);
        return server;
    };
    try {
        pulseServer_ = build(*pulse_, config_.pulseListen, true);
        issuer_ = std::make_unique<Issuer>(config_.galaxy, pulseEndpoint(), *authority_, *ledger_);
        admissionServer_ = build(*issuer_, config_.listen, false);
    } catch (...) {
        stop();
        throw;
    }
}

void Server::stop() {

    // Both listeners share one five-second monotonic shutdown deadline; the second gets no new budget.
    const auto deadline = gpr_time_add(gpr_now(GPR_CLOCK_MONOTONIC), gpr_time_from_seconds(5, GPR_TIMESPAN));
    // Request shutdown on both listeners before waiting and releasing them, then remove the issuer.
    if (pulseServer_) {
        pulseServer_->Shutdown(deadline);
    }
    if (admissionServer_) {
        admissionServer_->Shutdown(deadline);
    }
    if (pulseServer_) {
        pulseServer_->Wait();
        pulseServer_.reset();
    }
    if (admissionServer_) {
        admissionServer_->Wait();
        admissionServer_.reset();
    }
    issuer_.reset();
}

std::string Server::admissionEndpoint() const {
    return config_.listen.text();
}

std::string Server::pulseEndpoint() const {
    return config_.pulseListen.text();
}

std::optional<Clock::Reading> Server::time() const {
    return clock_->now();
}
} // namespace astra
