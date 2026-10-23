// Verify process wakeup, signal, and structured diagnostic behavior.
#include "check.hpp"
#include "process.hpp"

#include <array>
#include <cerrno>
#include <fcntl.h>
#include <iostream>
#include <thread>
#include <type_traits>
#include <unistd.h>

using namespace astra;
using namespace std::string_view_literals;

namespace {
static_assert(!std::is_copy_constructible_v<Signals> && !std::is_move_constructible_v<Signals>);
static_assert(!std::is_copy_constructible_v<Logger> && !std::is_move_constructible_v<Logger>);

/// Checks SIGINT/SIGTERM stop flags and ignored SIGPIPE; every scope restores original handlers.
void signalRestore() {

    // Three fixture-owned signal numbers aligned with original handler slots.
    constexpr std::array numbers{SIGINT, SIGTERM, SIGPIPE};
    // Pretest handler snapshots for exact post-destruction comparison.
    std::array<struct sigaction, numbers.size()> original{};
    for (std::size_t i = 0; i < numbers.size(); ++i) {
        CHECK(sigaction(numbers[i], nullptr, &original[i]) == 0);
    }
    for (const auto number : {SIGINT, SIGTERM}) {
        Signals signals;
        CHECK(!signals.requested());
        CHECK(raise(number) == 0);
        CHECK(signals.requested());
        CHECK(raise(SIGPIPE) == 0);
    }
    for (std::size_t i = 0; i < numbers.size(); ++i) {
        /// Post-scope handlers matched against corresponding original signal slots.
        struct sigaction current{};
        CHECK(sigaction(numbers[i], nullptr, &current) == 0);
        CHECK(current.sa_handler == original[i].sa_handler);
    }
}

/// Redirects only this process's stdout; restore it before closing owned pipe descriptors.
class Pipe {
public:
    /// Backs up stdout and redirects to an exclusive pipe with nonblocking read end, without affecting other processes.
    Pipe() {

        CHECK(pipe2(ends_.data(), O_CLOEXEC) == 0);
        saved_ = dup(STDOUT_FILENO);
        CHECK(saved_ >= 0);
        CHECK(dup2(ends_[1], STDOUT_FILENO) >= 0);
        CHECK(fcntl(ends_[0], F_SETFL, O_NONBLOCK) == 0);
    }

    /// Restore stdout before closing backup and pipe ends, preserving later test logs.
    ~Pipe() {

        dup2(saved_, STDOUT_FILENO);
        close(saved_);
        close(ends_[0]);
        close(ends_[1]);
    }

    /// Forbids copying stdout-restoration responsibility.
    Pipe(const Pipe&) = delete;
    /// Forbids overwriting active redirection; each object owns its full restoration.
    Pipe& operator=(const Pipe&) = delete;

    /// Returns an owned generated diagnostic line; no available bytes is assertion failure.
    std::string read() const {

        // Maximum one-record read buffer, matching production's bounded write limit.
        std::array<char, 4096> bytes{};
        // Actual read length, required positive before string-size conversion.
        const auto count = ::read(ends_[0], bytes.data(), bytes.size());
        CHECK(count > 0);
        return {bytes.data(), static_cast<std::size_t>(count)};
    }

private:
    /// Owned pipe read/write ends, both valid after construction.
    std::array<int, 2> ends_{};
    /// Copied original stdout descriptor; -1 before backup.
    int saved_ = -1;
};

/// Checks log fields, nonblocking output, and full-pipe behavior, then restores original stdout flags.
void boundedLog() {

    Pipe output;
    // Original stdout file flags before Logger construction; destruction must restore exactly.
    const auto flags = fcntl(STDOUT_FILENO, F_GETFL);
    CHECK((flags & O_NONBLOCK) == 0);
    {
        Logger logger(Member::Role::Planet);
        CHECK((fcntl(STDOUT_FILENO, F_GETFL) & O_NONBLOCK) != 0);
        logger.failure("connect_failed", Status::Code::Identity);
        // Owned actual log line checked for structure, component, event, and fixed error name.
        const auto record = output.read();
        CHECK(record.ends_with("}\n"));
        CHECK(record.contains("\"component\":\"planet\""));
        CHECK(record.contains("\"event\":\"connect_failed\""));
        CHECK(record.contains("\"reason\":\"identity\""));
        // Call the same log path with a full pipe; CTest timeout catches blocking without fragile microsecond assertions.
        std::array<char, 4096> padding{};
        while (::write(STDOUT_FILENO, padding.data(), padding.size()) > 0) {}
        CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
        logger.write("stopped");
    }
    CHECK(fcntl(STDOUT_FILENO, F_GETFL) == flags);
}

/// Producer sends 10000 notifications while consumer alternates observe/wait; sequence advancement must not be lost.
void concurrentWakeup() {

    Wakeup wake;
    // Borrows wake for a fixed notification count; joins before Wakeup destruction.
    std::jthread producer([&] {
        for (unsigned i = 0; i < 10000; ++i) {
            wake.notify();
        }
    });
    for (;;) {
        // Notification sequence before this check; wait sleeps only if unchanged.
        const auto observed = wake.observe();
        if (observed == 10000) {
            break;
        }
        wake.wait(observed);
    }
}

} // namespace

/// Reports exceptions as nonzero process failure; assertions remain active under NDEBUG.
int main() {

    // Control characters in opaque IDs must preserve line-delimited JSON structure and original Unicode bytes.
    CHECK(jsonString("カナ/\"\\\n\0"sv) == "\"カナ/\\\"\\\\\\u000a\\u0000\"");
    signalRestore();
    boundedLog();
    concurrentWakeup();
    std::cout << "Process signal, log backpressure and wakeup checks passed\n";
}
