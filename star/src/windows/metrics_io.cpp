// Winsock adaptation with fixed loopback wake endpoints and no background I/O tasks.
#include "../metrics_io.hpp"

#include <Windows.h>
#include <limits>
#include <stdexcept>

namespace astra::metrics {
namespace {
/// Configure accepted sockets too; no blocking operation may reach the HTTP loop.
bool configure(Handle socket) noexcept {
    u_long enabled = 1; // FIONBIO uses an unsigned long pointer.
    return SetHandleInformation(reinterpret_cast<HANDLE>(socket), HANDLE_FLAG_INHERIT, 0) && ioctlsocket(socket, FIONBIO, &enabled) == 0;
}

/// Acquire a noninherited descriptor and clean up if nonblocking setup fails.
Handle create(int family, int type, int protocol) {

    const auto value = WSASocketW(family, type, protocol, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT);
    if (value == invalid) {
        throw std::runtime_error("Cannot open metrics socket");
    }
    if (!configure(value)) {
        closesocket(value);
        throw std::runtime_error("Cannot configure metrics socket");
    }
    return value;
}
} // namespace

System::System() {

    WSADATA data{}; // Owned startup is paired with cleanup only after all sockets close.
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
        throw std::runtime_error("Cannot initialize metrics Winsock");
    }
    if (data.wVersion != MAKEWORD(2, 2)) {
        WSACleanup();
        throw std::runtime_error("Metrics requires Winsock 2.2");
    }
}

System::~System() {
    WSACleanup();
}

File::~File() {
    reset();
}

void File::reset(Handle next) noexcept {

    if (value != invalid) {
        closesocket(value);
    }
    value = next;
}

Wake::Wake() {

    reader.reset(create(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
    writer.reset(create(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
    sockaddr_in address{}; // Port zero chooses a private ephemeral loopback endpoint.
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int size = sizeof(address);
    if (::bind(reader.value, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0 || getsockname(reader.value, reinterpret_cast<sockaddr*>(&address), &size) != 0 || ::connect(writer.value, reinterpret_cast<const sockaddr*>(&address), size) != 0) {
        throw std::runtime_error("Cannot bind metrics wake endpoints");
    }
    // Connect both directions so unrelated loopback datagrams cannot keep the poll loop awake.
    size = sizeof(address);
    if (getsockname(writer.value, reinterpret_cast<sockaddr*>(&address), &size) != 0 || ::connect(reader.value, reinterpret_cast<const sockaddr*>(&address), size) != 0) {
        throw std::runtime_error("Cannot isolate metrics wake endpoints");
    }
}

void Wake::notify() noexcept {
    static_cast<void>(::send(writer.value, "!", 1, 0));
}

Handle open(int family) {
    return create(family, SOCK_STREAM, IPPROTO_TCP);
}

void exclusive(Handle socket) {

    const int enabled = 1; // SO_REUSEADDR on Windows permits takeover and is unsuitable here.
    if (setsockopt(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&enabled), sizeof(enabled)) != 0) {
        throw std::runtime_error("Cannot reserve exclusive metrics listener");
    }
}

Handle accept(Handle listener) noexcept {

    const auto value = ::accept(listener, nullptr, nullptr);
    if (value != invalid && !configure(value)) {
        closesocket(value);
        return invalid;
    }
    return value;
}

bool transient() noexcept {
    const auto error = WSAGetLastError(); // Read before another Winsock operation can replace it.
    return error == WSAEWOULDBLOCK || error == WSAEINTR;
}

int poll(Event* events, std::size_t count) noexcept {
    return WSAPoll(events, static_cast<ULONG>(count), 100);
}

int read(Handle socket, char* data, std::size_t count) noexcept {

    if (count > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        WSASetLastError(WSAEINVAL);
        return -1;
    }
    return ::recv(socket, data, static_cast<int>(count), 0);
}

int write(Handle socket, const char* data, std::size_t count) noexcept {

    if (count > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        WSASetLastError(WSAEINVAL);
        return -1;
    }
    return ::send(socket, data, static_cast<int>(count), 0);
}
} // namespace astra::metrics
