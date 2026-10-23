// Bounded HTTP metrics state machine shared by Linux and Windows.
#include "metrics.hpp"

#include "metrics_io.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <stdexcept>
#include <thread>
#ifndef _WIN32
#include <arpa/inet.h>
#endif

namespace astra {

/// Own the bounded HTTP listener and immutable metric responses consumed by accepted clients.
struct Metrics::Server {
    using File = metrics::File; // Native descriptors retain their full platform width.

    /// Immutable published response shared by slow clients, with no formatting on the HTTP path.
    struct Snapshot {
        /// Complete HTTP 200 response with fixed metric cardinality, below 8 KiB.
        std::string response;
        /// Actual control-thread sample time; scraping does not make an old observation fresh.
        Steady::time_point sampled;
    };

    /// One request per connection in 16 fixed slots, with no keep-alive, request bodies, or pipelining.
    struct Client {
        /// Exclusive client socket; metrics::invalid denotes an empty slot on each platform.
        File socket;
        /// Hard 4 KiB request-header bound without dynamic growth.
        std::array<char, 4096> header{};
        /// Header bytes read, from zero through 4096.
        std::size_t received{};
        /// Response bytes already sent, initially zero.
        std::size_t sent{};
        /// Fixed two-second admission deadline shared by reads and writes, never renewed.
        Steady::time_point deadline{};
        /// Pin the response through transmission and release it on completion or timeout.
        std::shared_ptr<const Snapshot> view;
    };

    /// Prepare native listener and wakeup resources before starting the worker; member destructors release partial construction.
    explicit Server(const Endpoint& endpoint) : address(endpoint) {

        const auto family = address.ipv6 ? AF_INET6 : AF_INET; // Configuration supplies numeric IP addresses only.
        listener.reset(metrics::open(family));
        metrics::exclusive(listener.value);
        const int enabled = 1;      // IPv6 listeners reject mapped IPv4 addresses.
        sockaddr_storage storage{}; // Zero-initialized numeric address storage; no DNS lookup.
        metrics::Length length{};   // Native sockaddr byte count for the selected address family.
        if (address.ipv6) {
            auto* value = reinterpret_cast<sockaddr_in6*>(&storage); // Interpret storage only as the selected address family.
            value->sin6_family = AF_INET6;
            value->sin6_port = htons(address.port);
            length = sizeof(sockaddr_in6);
            if (::inet_pton(AF_INET6, address.host.c_str(), &value->sin6_addr) != 1 || ::setsockopt(listener.value, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&enabled), sizeof(enabled)) != 0) {
                throw std::runtime_error("Invalid metrics IPv6 listener");
            }
        } else {
            auto* value = reinterpret_cast<sockaddr_in*>(&storage); // IPv4 accepts no mapped-address aliases.
            value->sin_family = AF_INET;
            value->sin_port = htons(address.port);
            length = sizeof(sockaddr_in);
            if (::inet_pton(AF_INET, address.host.c_str(), &value->sin_addr) != 1) {
                throw std::runtime_error("Invalid metrics IPv4 listener");
            }
        }
        if (::bind(listener.value, reinterpret_cast<const sockaddr*>(&storage), length) != 0 || ::listen(listener.value, 16) != 0 || ::getsockname(listener.value, reinterpret_cast<sockaddr*>(&storage), &length) != 0) {
            throw std::runtime_error("Cannot bind metrics listener");
        }
        address.port = ntohs(address.ipv6 ? reinterpret_cast<const sockaddr_in6*>(&storage)->sin6_port : reinterpret_cast<const sockaddr_in*>(&storage)->sin_port);

        // All members are ready; the worker borrows no external Runtime object or business lock.
        worker = std::jthread([this](std::stop_token stop) { run(stop); });
    }

    /// Wake an idle native poll and join while clients and their pinned snapshots remain alive.
    ~Server() {
        worker.request_stop();
        wake.notify();
        worker.join();
    }

    /// Release all per-slot state together so previous request bytes and references cannot enter a new connection.
    static void close(Client& client) noexcept {
        client.socket.reset();
        client.view.reset();
        client.received = client.sent = 0;
    }

    /// Defer incomplete headers and close requests other than an exact GET /metrics; this port is not a general HTTP router.
    void read(Client& client, Steady::time_point now) noexcept {

        const auto count = metrics::read(client.socket.value, client.header.data() + client.received, client.header.size() - client.received); // One bounded read per round.
        if (count < 0 && metrics::transient()) {
            return;
        }
        if (count <= 0) {
            close(client);
            return;
        }
        client.received += static_cast<std::size_t>(count);
        const std::string_view request(client.header.data(), client.received); // Borrow only this slot's fixed header storage.
        const auto end = request.find("\r\n\r\n");                             // Reject LF-only headers to avoid ambiguous framing and request smuggling.
        if (end == std::string_view::npos) {
            if (client.received == client.header.size()) {
                close(client);
            }
            return;
        }
        if (end + 4 != request.size() || (!request.starts_with("GET /metrics HTTP/1.1\r\n") && !request.starts_with("GET /metrics HTTP/1.0\r\n"))) {
            close(client);
            return;
        }

        client.view = current.load(std::memory_order_acquire);
        // A stalled control loop must not present old data as a fresh successful management observation.
        if (!client.view || now - client.view->sampled > std::chrono::seconds(10)) {
            close(client);
        }
    }

    /// Advance only confirmed nonblocking writes without rebuilding the response or raising SIGPIPE on peer closure.
    static void write(Client& client) noexcept {
        const auto& response = client.view->response; // The slot retains view until completion or timeout.
        const auto count = metrics::write(client.socket.value, response.data() + client.sent, response.size() - client.sent);
        if (count < 0 && metrics::transient()) {
            return;
        }
        if (count <= 0) {
            close(client);
            return;
        }
        client.sent += static_cast<std::size_t>(count);
        if (client.sent == response.size()) {
            close(client);
        }
    }

    /// Poll at most 18 descriptors, admit at most 16 clients per round, and give each live slot one I/O step without starving stop.
    void run(std::stop_token stop) noexcept {
        while (!stop.stop_requested()) {
            std::array<metrics::Event, 18> events{}; // Only live descriptors enter native polling.
            std::array<std::size_t, 16> positions{}; // Map fixed client slots to compact poll entries.
            std::size_t size = 2;
            events[0] = {listener.value, POLLIN, 0};
            events[1] = {wake.reader.value, POLLIN, 0};
            for (std::size_t index = 0; index < clients.size(); ++index) {
                if (clients[index].socket.value != metrics::invalid) {
                    positions[index] = size;
                    events[size++] = {clients[index].socket.value, static_cast<short>(clients[index].view ? POLLOUT : POLLIN), 0};
                }
            }
            const auto count = metrics::poll(events.data(), size);
            if (stop.stop_requested() || (count < 0 && !metrics::transient())) {
                break;
            }
            const auto now = Steady::now(); // Share one monotonic deadline observation per round, never a reversible wall clock.
            for (std::size_t index = 0; index < clients.size(); ++index) {
                auto& client = clients[index];                       // The worker exclusively owns client state; no cross-thread client lock is needed.
                const auto flags = events[positions[index]].revents; // Process only connections included in this poll; new admissions wait for the next round.
                if (client.socket.value == metrics::invalid) {
                    continue;
                }
                if (now >= client.deadline || (flags & (POLLERR | POLLNVAL)) != 0) {
                    close(client);
                    continue;
                }
                if (client.view && (flags & POLLOUT) != 0) {
                    write(client);
                } else if (!client.view && (flags & POLLIN) != 0) {
                    read(client, now);
                } else if ((flags & POLLHUP) != 0) {
                    close(client);
                }
            }
            if (count <= 0 || (events[0].revents & POLLIN) == 0) {
                continue;
            }
            for (std::size_t accepted = 0; accepted < clients.size(); ++accepted) {
                const auto socket = metrics::accept(listener.value); // Never queue a waiter; close excess connections immediately.
                if (socket == metrics::invalid) {
                    break;
                }
                const auto slot = std::ranges::find_if(clients, [](const Client& value) { return value.socket.value == metrics::invalid; });
                if (slot == clients.end()) {
                    File rejected; // Close a surplus connection without retaining work.
                    rejected.reset(socket);
                    continue;
                }
                slot->socket.reset(socket);
                slot->deadline = now + std::chrono::seconds(2);
            }
        }
        for (auto& client : clients) {
            close(client); // Shutdown does not wait for slow clients to send or receive.
        }
    }

    /// Outlives every native socket, including failed construction.
    metrics::System system;
    /// Actual bound endpoint, immutable after construction.
    Endpoint address;
    /// Private HTTP listener, absent when metrics are not configured.
    File listener;
    /// Native stop wakeup that outlives the worker.
    metrics::Wake wake;
    /// Fixed connection count and input-memory bound.
    std::array<Client, 16> clients;
    /// Control-thread publication of immutable responses for the HTTP worker.
    std::atomic<std::shared_ptr<const Snapshot>> current;
    /// Construct last; stop and join before releasing its dependencies.
    std::jthread worker;
};

Metrics::Metrics(const Endpoint& endpoint) : server_(std::make_unique<Server>(endpoint)) {}

Metrics::~Metrics() = default;

Endpoint Metrics::endpoint() const {
    return server_->address;
}

bool Metrics::publish(const Sample& sample) noexcept {
    try {
        // Permit only safe header bytes in the process ID. Unadmitted ready=0 observations are not trusted instance associations.
        if (sample.instance.size() > 256 || std::ranges::any_of(sample.instance, [](unsigned char byte) { return byte < 33 || byte > 126; })) {
            return false;
        }
        std::string body; // Eight unlabelled gauges, without business keys, credentials, or unbounded cardinality.
        body.reserve(1024);
        const auto append = [&](std::string_view name, auto value) { body += "# TYPE "; body += name; body += " gauge\n"; body += name; body += ' '; body += std::to_string(value); body += '\n'; }; // Format each sample once.
        append("astra_ready", sample.ready);
        append("astra_almanac_ready", sample.almanac);
        append("astra_clock_ready", sample.clock);
        append("astra_clock_synchronized", sample.synchronized);
        append("astra_clock_uncertainty_nanoseconds", sample.uncertainty);
        append("astra_members", sample.members);
        append("astra_sessions", sample.sessions);
        append("astra_recovery_bytes", sample.recovery);
        auto snapshot = std::make_shared<Server::Snapshot>(); // Allocate the complete replacement before atomically publishing it.
        snapshot->sampled = Steady::now();
        snapshot->response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nConnection: close\r\nCache-Control: no-store\r\nX-Astra-Instance: " + sample.instance + "\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
        server_->current.store(std::move(snapshot), std::memory_order_release);
        return true;
    } catch (...) {
        return false;
    }
}
} // namespace astra
