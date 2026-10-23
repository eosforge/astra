// Linux socket and eventfd implementation for the bounded metrics listener.
#include "../metrics_io.hpp"

#include <cerrno>
#include <cstdint>
#include <stdexcept>
#include <sys/eventfd.h>
#include <unistd.h>

namespace astra::metrics {
System::System() = default;
System::~System() = default;

File::~File() {
    reset();
}

void File::reset(Handle next) noexcept {

    if (value != invalid) {
        ::close(value);
    }
    value = next;
}

Wake::Wake() {

    reader.reset(::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
    if (reader.value == invalid) {
        throw std::runtime_error("Cannot open metrics wake event");
    }
}

void Wake::notify() noexcept {
    const std::uint64_t value = 1; // A single stop notification, not a business counter.
    static_cast<void>(::write(reader.value, &value, sizeof(value)));
}

Handle open(int family) {

    const auto socket = ::socket(family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (socket == invalid) {
        throw std::runtime_error("Cannot open metrics listener");
    }
    return socket;
}

void exclusive(Handle socket) {

    const int enabled = 1; // Permit TIME_WAIT reuse, never simultaneous listeners.
    if (::setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0) {
        throw std::runtime_error("Cannot configure metrics listener");
    }
}

Handle accept(Handle listener) noexcept {
    return ::accept4(listener, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
}

bool transient() noexcept {
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
}

int poll(Event* events, std::size_t count) noexcept {
    return ::poll(events, count, 100);
}

int read(Handle socket, char* data, std::size_t count) noexcept {
    return static_cast<int>(::recv(socket, data, count, 0));
}

int write(Handle socket, const char* data, std::size_t count) noexcept {
    return static_cast<int>(::send(socket, data, count, MSG_NOSIGNAL));
}
} // namespace astra::metrics
