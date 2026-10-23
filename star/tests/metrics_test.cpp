// Exercise the same bounded HTTP behavior on Linux and Windows loopback sockets.
#include "check.hpp"
#include "metrics.hpp"

#include <array>
#include <cerrno>
#include <iostream>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {
#ifdef _WIN32
/// Winsock uses a signed 32-bit I/O length.
using Size = int;
#else
/// POSIX retains the native buffer size type.
using Size = std::size_t;
#endif
/// Own one loopback socket per request and close it on every exceptional path.
class Client {
public:
    /// Connect to the actual bound metrics port with three-second native read and write timeouts.
    explicit Client(std::uint16_t port) {

#ifdef _WIN32
        descriptor_ = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT);
        CHECK(descriptor_ != INVALID_SOCKET);
#else
        descriptor_ = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        CHECK(descriptor_ >= 0);
#endif
        sockaddr_in address{}; // Restrict requests to fixture-owned loopback services.
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#ifdef _WIN32
        const DWORD timeout = 3000; // Winsock timeout is an integer millisecond count.
#else
        const timeval timeout{3, 0}; // Cover the server deadline without an unbounded fixture.
#endif
        if (::setsockopt(descriptor_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) != 0 || ::setsockopt(descriptor_, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) != 0 || ::connect(descriptor_, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
            close();
            throw std::runtime_error("Cannot connect metrics fixture");
        }
    }

    /// Close this fixture's uniquely owned descriptor.
    ~Client() {
        close();
    }

    /// Keep descriptor release responsibility unique.
    Client(const Client&) = delete;
    /// Prevent assignment from overwriting an active request.
    Client& operator=(const Client&) = delete;

    /// Send the complete test header, suppressing SIGPIPE on platforms that can raise it.
    void send(std::string_view request) {
#ifdef _WIN32
        constexpr int flags = 0; // Winsock never raises SIGPIPE.
#else
        constexpr int flags = MSG_NOSIGNAL;
#endif
        while (!request.empty()) {
            const auto count = ::send(descriptor_, request.data(), static_cast<Size>(request.size()), flags);
            CHECK(count > 0);
            request.remove_prefix(static_cast<std::size_t>(count));
        }
    }

    /// Read until the server closes; a single recv need not return the complete response.
    std::string read() {

        std::string result; // Bound the fixture's read-only response independently of the service.
        std::array<char, 2048> buffer{};
        for (;;) {
            const auto count = ::recv(descriptor_, buffer.data(), static_cast<Size>(buffer.size()), 0);
#ifdef _WIN32
            const auto error = count < 0 ? WSAGetLastError() : 0;
            if (count < 0 && error == WSAEINTR) {
                continue;
            }
            if (count < 0 && error == WSAECONNRESET) {
                break;
            }
#else
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count < 0 && errno == ECONNRESET) {
                break;
            }
#endif
            CHECK(count >= 0);
            if (count == 0) {
                break;
            }
            result.append(buffer.data(), static_cast<std::size_t>(count));
            CHECK(result.size() <= 8192);
        }
        return result;
    }

private:
    /// Close the fixture's descriptor with the matching native API.
    void close() noexcept {
#ifdef _WIN32
        closesocket(descriptor_);
#else
        ::close(descriptor_);
#endif
    }
#ifdef _WIN32
    /// A pointer-width Winsock descriptor.
    SOCKET descriptor_ = INVALID_SOCKET;
#else
    /// This fixture owns exactly one loopback connection.
    int descriptor_ = -1;
#endif
};

/// Check real HTTP boundaries, incomplete-header fairness, read deadlines, and shutdown resource release.
void exchange() {

    astra::Metrics metrics(*astra::Endpoint::parse("127.0.0.1:0", true));
    const auto port = metrics.endpoint().port; // A system-assigned port permits independent cases to run concurrently.
    CHECK(port != 0);
    CHECK(metrics.publish({.instance = "star-1", .ready = true, .almanac = true, .clock = true, .members = 3, .sessions = 2, .recovery = 123}));
    Client slow(port); // An incomplete header must not monopolize the worker and block another client.
    slow.send("GET /metrics HTTP/1.1\r\n");
    Client normal(port);
    normal.send("GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n");
    const auto response = normal.read();
    CHECK(response.starts_with("HTTP/1.1 200 OK\r\n"));
    CHECK(response.contains("X-Astra-Instance: star-1\r\n"));
    CHECK(response.contains("astra_ready 1\n") && response.contains("astra_recovery_bytes 123\n"));
    CHECK(slow.read().empty()); // The fixed total deadline releases the slot even if the client stays silent.

    for (const auto request : {"POST /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n", "GET /metrics?key=secret HTTP/1.1\r\nHost: localhost\r\n\r\n", "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"}) {
        Client invalid(port);
        invalid.send(request);
        CHECK(invalid.read().empty());
    }
    CHECK(!metrics.publish({.instance = "bad\r\nInjected: header"})); // Invalid publication preserves the previous valid observation.
    Client retained(port);
    retained.send("GET /metrics HTTP/1.0\r\n\r\n");
    CHECK(retained.read().contains("X-Astra-Instance: star-1\r\n"));
    CHECK(metrics.publish({.instance = "star-2"}));
    Client replaced(port);
    replaced.send("GET /metrics HTTP/1.0\r\n\r\n");
    CHECK(replaced.read().contains("astra_ready 0\n"));
}
} // namespace

/// Open a private listener only through explicitly authorized CTest execution; unrun code is not acceptance evidence.
int main() {
    try {
        exchange();
        std::cout << "PASS bounded metrics HTTP lifecycle\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
