// Shared control-loop wakeups and the existing Linux stdout logger.
#include "process.hpp"

#include <astra/profile.hpp>

#include <fcntl.h>
#include <format>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace astra {
/// Encode a validated UTF-8 view as a standalone quoted JSON literal without interpreting business identifiers.
/// Escape quotes, backslashes, and control bytes while retaining ordinary UTF-8 bytes.

std::string jsonString(std::string_view value) {

    // Hexadecimal digits encode JSON control bytes, not identity material.
    constexpr char hex[] = "0123456789abcdef";
    // Own the escaped bytes and append the closing quote after encoding.
    std::string result = "\"";
    for (char byte : value) {
        // Interpret bytes as unsigned so char sign extension cannot misclassify control characters.
        const auto c = static_cast<unsigned char>(byte);
        // Escape JSON string delimiters before appending the original byte.
        if (c == '"' || c == '\\') {
            result += '\\';
            result += static_cast<char>(c);
        } else if (c < 0x20) {
            // Encode bytes below 0x20 as four-digit JSON Unicode escapes.
            result += "\\u00";
            result += hex[c >> 4]; // High nibble.
            result += hex[c & 15]; // Low nibble.
        } else {
            // Ordinary UTF-8 bytes pass through unchanged.
            result += static_cast<char>(c);
        }
    }

    // Append in place; lvalue operator+ would copy the entire escaped result again.
    result += '"';
    return result;
}

/// Read the current notification counter atomically without taking the waiter mutex.

std::uint64_t Wakeup::observe() const noexcept {
    return sequence_.load(std::memory_order_relaxed);
}

/// Publish a sequence change before notifying the condition-variable waiter.

void Wakeup::notify() {

    ASTRA_PROFILE_SCOPE("common.process.Wakeup.notify");

    {
        // Share the waiter's mutex across predicate checking and entry to sleep.
        // Otherwise a producer can increment and notify after the consumer's check but before it sleeps,
        // losing the prompt wakeup and delaying processing until the polling deadline.
        ASTRA_PROFILE_BEGIN(profileLock119, "common.process.Wakeup.notify.wait.lock");
        std::lock_guard lock(mutex_);
        ASTRA_PROFILE_END(profileLock119);
        sequence_.fetch_add(1, std::memory_order_relaxed);
    }

    // Wake a control loop that may already be waiting.
    condition_.notify_one();
}

/// Return immediately after a sequence change, otherwise wait at most 10 ms.
/// observed is the counter captured before the caller's current processing step.

void Wakeup::wait(std::uint64_t observed) {

    ASTRA_PROFILE_SCOPE("common.process.Wakeup.wait");
    // Release the mutex during the condition-variable wait and reacquire it before checking the predicate.
    ASTRA_PROFILE_BEGIN(profileLock133, "common.process.Wakeup.wait.wait.lock");
    std::unique_lock lock(mutex_);
    ASTRA_PROFILE_END(profileLock133);
    condition_.wait_for(lock, Milliseconds(10), [&] { return observe() != observed; });
}

/// Select the fixed star or planet component name from the local role.

Logger::Logger(Member::Role role) : Logger(role == Member::Role::Star ? "star" : "planet") {}

Logger::Logger(std::string_view component) : component_(component) {

    struct stat status{};
    // Inspect stdout before altering flags; regular files retain their existing behavior.
    if (fstat(STDOUT_FILENO, &status) == 0 && (S_ISFIFO(status.st_mode) || S_ISSOCK(status.st_mode))) {
        // Capture the original flags only for a pipe or socket.
        flags_ = fcntl(STDOUT_FILENO, F_GETFL); // Preserve the descriptor's existing flags.
        if (flags_ >= 0) {
            // Attempt nonblocking output without changing unrelated descriptor flags.
            fcntl(STDOUT_FILENO, F_SETFL, flags_ | O_NONBLOCK);
        }
    }
}

/// Restore captured stdout flags after diagnostic ownership ends.

Logger::~Logger() {

    if (flags_ >= 0) {
        fcntl(STDOUT_FILENO, F_SETFL, flags_);
    }
}

/// Emit one bounded JSON diagnostic with the caller's validated event and field object.
/// Write failure drops this diagnostic without buffering or retry.

void Logger::write(std::string_view event, std::string_view fields) const {

    // Wall time is diagnostic metadata in Unix milliseconds, never a business deadline.
    const auto now = std::chrono::duration_cast<Milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    // Produce one newline-terminated JSON object from validated fields.
    const auto line = std::format(R"({{"time_unix_ms":{},"level":"INFO","component":"{}","event":"{}","fields":{}}})" "\n", now, component_, event, fields);
    // Writes within Linux PIPE_BUF (4096 bytes) are atomic for pipes; this is not a socket-write guarantee.
    // Drop larger diagnostic lines rather than retaining an unbounded backlog.
    if (line.size() <= 4096) {
        // A failed write does not create retry work for the control loop.
        const auto written = ::write(STDOUT_FILENO, line.data(), line.size());
        static_cast<void>(written); // Diagnostics are best effort; protocol progress takes precedence.
    }
}

/// Publish the validated connection snapshot and local node identity.

void Logger::status(const Policy::State& status, const Id& id) const {

    // Format the active upstream, if present, without reading credential material.
    const auto upstream = status.activeMember ? std::format(R"({{"id":{},"group":"{}","address":"{}"}})", jsonString(status.activeMember->id), status.activeMember->group, status.activeMember->address.text()) : "null";

    // Encode only validated state and counters through the bounded diagnostic writer.
    write("status", std::format(R"({{"id":{},"initialized":{},"members":{},"inbound":{},"outbound":{},"planet_inbound":{},"candidates":{},"upstream":{}}})", jsonString(id), status.initialized, status.members, status.inbound, status.outbound, status.planetInbound, status.candidates, upstream));
}

/// Map the internal error code to an allowlisted reason for a fixed event.
/// Never accept an untrusted remote error body as diagnostic text.

void Logger::failure(std::string_view event, Status::Code error) const {
    write(event, std::format(R"({{"reason":"{}"}})", Status::name(error)));
}
} // namespace astra
