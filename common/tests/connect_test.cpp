// Verify connection establishment and session lifecycle boundaries.
#include "admission.hpp"
#include "check.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace astra;

namespace {

/// Owns an unresponsive loopback endpoint only, without external blackhole addresses or system DNS changes.
struct Socket {
    /// Owned loopback socket, -1 before creation.
    int fd = -1;
    /// Initially zero; records OS-allocated positive TCP/UDP port after creation.
    std::uint16_t port{};

    /// Creates nonblocking loopback TCP/UDP by type; construction failure closes acquired descriptors.
    explicit Socket(int type) {

        fd = socket(AF_INET, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        CHECK(fd >= 0);
        // IPv4 loopback and port zero request an available bind port.
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
            close(fd);
            throw std::runtime_error("Cannot bind test socket");
        }

        // Initially address-buffer size; getsockname returns actual length.
        socklen_t size = sizeof(address);
        if (getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size) != 0 || (type == SOCK_STREAM && listen(fd, 8) != 0)) {
            close(fd);
            throw std::runtime_error("Cannot prepare test socket");
        }
        port = ntohs(address.sin_port);
    }

    /// Closes this fixture's socket only.
    ~Socket() {
        close(fd);
    }

    /// Forbids copying descriptor-close responsibility.
    Socket(const Socket&) = delete;
    /// Forbids assignment over existing descriptor ownership.
    Socket& operator=(const Socket&) = delete;
};

/// Connects identity to unresponsive address, optionally cancels early, and requires no pending client work on return.
void blocked(const std::shared_ptr<Identity>& identity, std::string address, bool cancel) {

    // Connection budget 300 ms and total handshake 600 ms, without system DNS changes.
    Config config;
    config.galaxy = "alpha";
    config.advertise = *Endpoint::parse("127.0.0.1:7443");
    config.pulsar = std::move(address);
    config.connectTimeout = Milliseconds(300);
    config.handshakeTimeout = Milliseconds(600);
    Admission client(config, identity, [] {});
    client.begin(0);
    // Monotonic wait start; cancel after 50 ms and cap total wait at two seconds.
    const auto started = Steady::now();
    while (Steady::now() - started < std::chrono::seconds(2)) {
        if (cancel && Steady::now() - started >= Milliseconds(50)) {
            client.cancel();
        }
        if (auto result = client.poll()) {
            CHECK(!*result && result->error().code == (cancel ? Status::Code::Cancelled : Status::Code::Timeout));
            CHECK(!client.pending());
            return;
        }
        std::this_thread::sleep_for(Milliseconds(1));
    }
    throw std::runtime_error("Blocked connection exceeded total budget");
}

} // namespace

/// Reports exceptions as nonzero process failure; assertions remain active under NDEBUG.
int main() {

    try {
        // Public TLS material ensures failure comes from the stalled endpoint, not missing identity files.
        auto identity = Identity::load(std::filesystem::path(ASTRA_FIXTURES) / "star-a", *Endpoint::parse("127.0.0.1:7443"));
        CHECK(identity);
        {
            Socket server(SOCK_STREAM);
            blocked(*identity, "127.0.0.1:" + std::to_string(server.port), false);
            // Confirms actual TCP arrival, then closes only this accepted descriptor.
            const auto accepted = accept4(server.fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
            CHECK(accepted >= 0);
            close(accepted);
        }
        {
            Socket dns(SOCK_DGRAM);
            blocked(*identity, "dns://127.0.0.1:" + std::to_string(dns.port) + "/astra-test.invalid:7440", false);
            // Receives local DNS traffic to prove the client queried this test UDP endpoint.
            std::array<char, 512> query{};
            CHECK(recv(dns.fd, query.data(), query.size(), 0) > 0);
        }
        {
            Socket server(SOCK_STREAM);
            blocked(*identity, "127.0.0.1:" + std::to_string(server.port), true);
        }
        std::cout << "PASS stalled TLS, stalled local DNS and connection cancellation\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
