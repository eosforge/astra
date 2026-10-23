// Keep native socket ownership at the edge of the shared metrics HTTP state machine.
#pragma once
#include <cstddef>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <poll.h>
#include <sys/socket.h>
#endif

namespace astra::metrics {
#ifdef _WIN32
/// Native Windows socket handle; invalid marks absence.
using Handle = SOCKET;
/// Windows readiness request and result entry passed to the shared polling adapter.
using Event = WSAPOLLFD;
/// Windows socket-address byte length used by the native API.
using Length = int;
/// Windows failed or absent socket sentinel; never an owned handle.
inline constexpr auto invalid = INVALID_SOCKET;
#else
/// Native Linux descriptor; invalid marks absence.
using Handle = int;
/// Linux readiness request and result entry passed to the shared polling adapter.
using Event = pollfd;
/// Linux socket-address byte length used by the native API.
using Length = socklen_t;
/// Linux failed or absent descriptor sentinel; zero remains a valid descriptor.
inline constexpr auto invalid = -1;
#endif

/// Hold Winsock for the lifetime of every socket; Linux requires no initialization.
struct System {
    /// Initialize Winsock on Windows and throw on failure; Linux requires no native startup.
    System();
    /// Release owned Winsock startup after all sockets close; Linux needs no matching shutdown.
    ~System();
    /// Keep one owner of native socket-runtime initialization lifetime; copying is forbidden.
    System(const System&) = delete;
    /// Keep one owner of native socket-runtime initialization lifetime; copying is forbidden.
    System& operator=(const System&) = delete;
};

/// Own exactly one noninherited native descriptor, including Linux's wake eventfd.
struct File {
    /// Empty until native acquisition succeeds.
    Handle value = invalid;
    /// Start without an owned descriptor; acquisition occurs through reset.
    File() = default;
    /// Close the owned descriptor once without retrying or throwing.
    ~File();
    /// Keep one owner of native descriptor and its close responsibility; copying is forbidden.
    File(const File&) = delete;
    /// Keep one owner of native descriptor and its close responsibility; copying is forbidden.
    File& operator=(const File&) = delete;
    /// Close without retry, then adopt the supplied descriptor.
    void reset(Handle next = invalid) noexcept;
};

/// A pollable stop signal owns all endpoints until after the worker joins.
struct Wake {
    /// Pollable endpoint; eventfd on Linux, bound UDP on Windows.
    File reader;
#ifdef _WIN32
    /// Connected loopback sender used only for stop notification.
    File writer;
#endif
    /// Create owned nonblocking stop-signal endpoints; throw on acquisition or loopback setup failure.
    Wake();
    /// Notify without blocking; the poll timeout remains a bounded failure fallback.
    void notify() noexcept;
};

/// Open a nonblocking, noninherited TCP socket or throw.
[[nodiscard]] Handle open(int family);
/// Retain exclusive active listener ownership under each platform's socket semantics.
void exclusive(Handle socket);
/// Accept one connection without waiting; failure returns invalid.
[[nodiscard]] Handle accept(Handle listener) noexcept;
/// Report native retryable I/O errors immediately after the failed call.
[[nodiscard]] bool transient() noexcept;
/// Poll a bounded descriptor array for at most 100 ms.
[[nodiscard]] int poll(Event* events, std::size_t count) noexcept;
/// Read or write one bounded chunk; negative results retain the native error code.
[[nodiscard]] int read(Handle socket, char* data, std::size_t count) noexcept;
/// Write one bounded chunk without waiting; a negative result retains the native error code.
[[nodiscard]] int write(Handle socket, const char* data, std::size_t count) noexcept;
} // namespace astra::metrics
