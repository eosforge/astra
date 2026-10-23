// Exercise Linux adapter failures and Common parsing boundaries without changing host state.
#include "check.hpp"
#include "random.hpp"
#include "signals.hpp"
#include <astra/clock.hpp>
#include <astra/config.hpp>
#include <astra/policy.hpp>

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <sys/random.h>
#include <sys/timerfd.h>
#include <system_error>
#include <time.h>
#include <unistd.h>
#include <utility>

// Preserve the exact installed libc declarations for all unmodified native operations.
extern "C" decltype(clock_gettime) __real_clock_gettime;
extern "C" decltype(clock_getres) __real_clock_getres;
extern "C" decltype(timerfd_create) __real_timerfd_create;
extern "C" decltype(timerfd_settime) __real_timerfd_settime;
extern "C" decltype(read) __real_read;
extern "C" decltype(close) __real_close;
extern "C" decltype(getrandom) __real_getrandom;
extern "C" decltype(sigaction) __real_sigaction;
extern "C" decltype(inet_ntop) __real_inet_ntop;

namespace {
/// A single native response, with an explicit errno and a public nonsecret byte pattern.
struct Reply {
    /// A negative count fails; zero and positive short results remain distinct.
    ssize_t count{};
    /// Only failed responses assign errno.
    int error{};
    /// Successful scripted random reads fill only their confirmed prefix.
    std::uint8_t byte{};
};

/// Record whether a signal installation also borrowed a previous disposition.
struct Action {
    /// Native signal identity, never an array-derived substitute.
    int signal{};
    /// Constructors request a previous action; rollback/restoration does not.
    bool previous{};
    /// Compare the exact finite installation/rollback sequence.
    bool operator==(const Action&) const = default;
};

/// Own one main-thread injection domain; callbacks record facts without assertions or allocation.
struct Boundary {
    /// Reject unexpected callback shapes without throwing through a C function.
    bool valid = true;
    /// Enable one-shot elapsed responses or stepped readings for the timer adapter.
    bool clock{}, stepping{}, timer{}, random{}, signals{}, address{};
    /// The armed normalization accepts only this native address family.
    int family{};
    /// Full literal address bytes; IPv4 consumes only the first four.
    std::array<std::uint8_t, 16> bytes{};
    /// An admitted normalization reaches the actual wrapped call exactly once.
    unsigned normalized{};
    /// Scripted clock/resolution results retain the native error boundary.
    int clockResult{}, resolutionResult{}, createResult{}, armResult{};
    /// Native timestamps used by the independent integer boundary cases.
    timespec time{}, resolution{0, 1};
    /// Repeat the initial clock sample this many calls before producing one-nanosecond edges.
    unsigned repeated{};
    /// Record the real timer descriptor and every callback using it.
    int descriptor = -1;
    /// Observe actual syscall entry/close counts before accepting the scenario.
    unsigned clocks{}, resolutions{}, creates{}, arms{}, reads{}, closes{}, draws{}, installed{};
    /// Positive close receipts are distinct from attempted closes.
    unsigned closed{};
    /// A fixed read script drives EAGAIN, EINTR, expiry and invalid-length observations.
    std::array<Reply, 4> input{};
    /// Only these entries may be consumed; script exhaustion invalidates the fixture.
    unsigned length{};
    /// Borrow the destination only while the random adapter is executing.
    std::uint8_t* destination{};
    /// Confirmed random bytes; errors and interruptions cannot advance this cursor.
    std::size_t written{};
    /// Fail exactly this one-based signal installation; zero keeps every call native.
    unsigned failure{};
    /// No allocation or user callback occurs while recording signal transitions.
    std::array<Action, 8> actions{};
};

/// Other threads and operations outside the explicitly armed fixture always remain native.
thread_local Boundary* current{};

/// Disarm even when an oracle fails; no injected response survives its scenario.
class Injection {
public:
    /// Bind one live stack-owned boundary without permitting nested replacement.
    explicit Injection(Boundary& boundary) {
        CHECK(current == nullptr);
        current = &boundary;
    }

    /// Native fallback resumes before any enclosing owner is destroyed.
    ~Injection() {
        current = nullptr;
    }

    Injection(const Injection&) = delete;
    Injection& operator=(const Injection&) = delete;
};

/// Emit an identity only after its independent outcome and ownership assertions have passed.
void observed(std::string_view name) {
    std::cout << "COMMON-NATIVE {\"case\":\"" << name << "\"}\n";
}

/// Compare signed conversion boundaries with literal expected coordinates, not the implementation formula.
void elapsed() {
    const auto real = astra::Clock::Elapsed::now();
    CHECK(real.time_since_epoch().count() >= 0 && astra::Clock::Elapsed::now() >= real);
    observed("elapsed-native");

    /// Fixed native payloads, including invalid values that successful syscalls must still reject.
    struct Sample {
        /// Stable scenario and simulated syscall result.
        std::string_view name;
        /// Return this simulated syscall status independently of the supplied timespec.
        int result;
        /// The boundary owns this exact timespec, independent of host uptime.
        timespec value;
        /// Negative means refusal; otherwise the exact signed nanosecond result.
        std::int64_t expected;
    };

    const std::array samples{
        Sample{"elapsed-failure", -1, {0, 0}, -1},
        Sample{"elapsed-negative-seconds", 0, {-1, 0}, -1},
        Sample{"elapsed-negative-nanos", 0, {0, -1}, -1},
        Sample{"elapsed-invalid-nanos", 0, {0, 1'000'000'000}, -1},
        Sample{"elapsed-overflow", 0, {9'223'372'036, 854'775'808}, -1},
        Sample{"elapsed-zero", 0, {0, 0}, 0},
        Sample{"elapsed-fraction", 0, {1, 999'999'999}, 1'999'999'999},
        Sample{"elapsed-maximum", 0, {9'223'372'036, 854'775'807}, std::numeric_limits<std::int64_t>::max()},
    };
    for (const auto& sample : samples) {
        Boundary boundary;
        boundary.clock = true;
        boundary.clockResult = sample.result;
        boundary.time = sample.value;
        bool refused = false;
        std::int64_t result = -1;
        {
            Injection injection(boundary);
            try {
                result = astra::Clock::Elapsed::now().time_since_epoch().count();
            } catch (const std::runtime_error& error) {
                if (std::string_view(error.what()) != "Cannot read elapsed clock") {
                    throw;
                }
                refused = true;
            }
        }
        CHECK(boundary.valid && boundary.clocks == 1);
        CHECK(refused == (sample.expected < 0) && result == sample.expected);
        observed(sample.name);
    }
}

/// Verify native descriptor ownership through failures of each precision-budget operation.
void precision() {
    const auto native = astra::elapsedPrecisionNanoseconds({});
    CHECK(native >= 1 && native <= 20'000'000);
    observed("precision-native");

    for (const std::string_view name : {"timer-create", "resolution-failure", "resolution-seconds", "resolution-zero", "resolution-negative", "resolution-large",
                                        "timer-arm", "timer-read-error", "timer-read-short", "timer-read-zero", "timer-expired", "timer-retry", "resolution-maximum", "timer-cancel"}) {
        Boundary boundary;
        boundary.clock = boundary.stepping = boundary.timer = true;
        boundary.length = 1;
        boundary.input[0] = {-1, EAGAIN, 0};
        std::string_view expected;
        unsigned closes = 1, resolutions = 1, arms = 0, reads = 0;
        if (name == "timer-create") {
            boundary.createResult = -1;
            closes = resolutions = 0;
            expected = "Cannot start clock precision budget";
        } else if (name.starts_with("resolution-") && name != "resolution-maximum") {
            expected = "Unsupported elapsed clock resolution";
            if (name == "resolution-failure") {
                boundary.resolutionResult = -1;
            }
            if (name == "resolution-seconds") {
                boundary.resolution.tv_sec = 1;
            }
            if (name == "resolution-zero") {
                boundary.resolution.tv_nsec = 0;
            }
            if (name == "resolution-negative") {
                boundary.resolution.tv_nsec = -1;
            }
            if (name == "resolution-large") {
                boundary.resolution.tv_nsec = 20'000'001;
            }
        } else {
            arms = 1;
            if (name == "timer-arm") {
                boundary.armResult = -1;
                expected = "Cannot arm clock precision budget";
            } else if (name == "timer-cancel") {
                expected = "Clock precision cancelled";
            } else {
                reads = 1;
                if (name == "timer-read-error") {
                    boundary.input[0] = {-1, EIO, 0};
                }
                if (name == "timer-read-short") {
                    boundary.input[0] = {4, 0, 0};
                }
                if (name == "timer-read-zero") {
                    boundary.input[0] = {0, 0, 0};
                }
                if (name.starts_with("timer-read-")) {
                    expected = "Cannot read clock precision budget";
                }
                if (name == "timer-expired") {
                    boundary.input[0] = {8, 0, 0};
                    expected = "Cannot measure supported monotonic clock precision";
                }
                if (name == "timer-retry") {
                    boundary.input[0] = {-1, EINTR, 0};
                    boundary.input[1] = {-1, EAGAIN, 0};
                    boundary.length = reads = 2;
                    boundary.repeated = 129;
                }
                if (name == "resolution-maximum") {
                    boundary.resolution.tv_nsec = 20'000'000;
                }
            }
        }
        std::stop_source stop;
        if (name == "timer-cancel") {
            stop.request_stop();
        }
        bool refused = false;
        std::uint64_t result = 0;
        {
            Injection injection(boundary);
            try {
                result = astra::elapsedPrecisionNanoseconds(stop.get_token());
            } catch (const std::runtime_error& error) {
                if (expected.empty() || error.what() != expected) {
                    throw;
                }
                refused = true;
            }
        }
        CHECK(boundary.valid && boundary.creates == 1 && boundary.resolutions == resolutions && boundary.arms == arms && boundary.reads == reads);
        CHECK(boundary.closes == closes && boundary.closed == closes);
        if (boundary.descriptor >= 0) {
            errno = 0;
            CHECK(::fcntl(boundary.descriptor, F_GETFD) == -1 && errno == EBADF);
        }
        CHECK(refused == !expected.empty());
        CHECK(result == (expected.empty() ? (name == "resolution-maximum" ? 20'000'000U : 1U) : 0U));
        observed(name);
    }
}

/// Keep prefix writes, retry decisions and error categories independently visible to the oracle.
void entropy() {
    std::array<std::uint8_t, 10> bytes{};
    bytes.front() = 0xa1;
    bytes.back() = 0xb2;
    astra::random(std::span(bytes).subspan(1, 8));
    CHECK(bytes.front() == 0xa1 && bytes.back() == 0xb2);
    observed("random-native");

    for (const std::string_view name : {"random-empty", "random-short", "random-interrupted", "random-zero", "random-failure", "random-prefix-failure", "random-prefix-zero"}) {
        bytes.fill(0xa5);
        auto expected = bytes;
        Boundary boundary;
        boundary.random = true;
        boundary.destination = bytes.data() + 1;
        int error = 0;
        if (name == "random-short") {
            boundary.input = {Reply{2, 0, 0x11}, Reply{3, 0, 0x22}, Reply{3, 0, 0x33}, Reply{}};
            boundary.length = 3;
            expected = {0xa5, 0x11, 0x11, 0x22, 0x22, 0x22, 0x33, 0x33, 0x33, 0xa5};
        } else if (name == "random-interrupted") {
            boundary.input = {Reply{-1, EINTR, 0}, Reply{-1, EINTR, 0}, Reply{8, 0, 0x77}, Reply{}};
            boundary.length = 3;
            expected = {0xa5, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0xa5};
        } else if (name != "random-empty") {
            error = name == "random-failure" ? EACCES : EIO;
            boundary.length = 1;
            boundary.input[0] = {name == "random-zero" ? 0 : -1, error, 0};
            if (name.starts_with("random-prefix-")) {
                boundary.length = 2;
                boundary.input[0] = {3, 0, 0x13};
                boundary.input[1] = {name == "random-prefix-zero" ? 0 : -1, EIO, 0};
                expected = {0xa5, 0x13, 0x13, 0x13, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5};
            }
        }
        int actual = 0;
        {
            Injection injection(boundary);
            try {
                astra::random(std::span(bytes).subspan(1, name == "random-empty" ? 0 : 8));
            } catch (const std::system_error& failure) {
                CHECK(failure.code().category() == std::generic_category());
                actual = failure.code().value();
            }
        }
        CHECK(actual == error && bytes == expected);
        CHECK(boundary.valid && boundary.draws == boundary.length);
        observed(name);
    }
}

/// A benign prior action remains distinguishable from both the owner's action and SIG_IGN.
void previous(int) {}

/// Backstop restoration uses the actual kernel API even when a scenario assertion fails.
struct Dispositions {
    /// Own exactly the three signals that the production adapter modifies.
    static constexpr std::array names{SIGINT, SIGTERM, SIGPIPE};
    /// Preserve complete original dispositions; no signal is raised before capture completes.
    std::array<struct sigaction, 3> original{};

    /// Capture first, before the separately invoked setup changes any disposition.
    Dispositions() {
        for (std::size_t index = 0; index < names.size(); ++index) {
            CHECK(__real_sigaction(names[index], nullptr, &original[index]) == 0);
        }
    }

    /// Retry native restoration during unwinding; successful scenarios separately check restoration.
    ~Dispositions() {
        for (std::size_t index = 0; index < names.size(); ++index) {
            static_cast<void>(__real_sigaction(names[index], &original[index], nullptr));
        }
    }
};

/// Refused construction must roll back every successful earlier installation, in the exact order.
void signals() {
    Dispositions owner;
    std::array<struct sigaction, 3> baseline{};
    for (std::size_t index = 0; index < owner.names.size(); ++index) {
        struct sigaction action{};
        action.sa_handler = previous;
        action.sa_flags = SA_RESTART;
        CHECK(::sigemptyset(&action.sa_mask) == 0 && ::sigaddset(&action.sa_mask, SIGUSR1) == 0);
        CHECK(__real_sigaction(owner.names[index], &action, nullptr) == 0);
        CHECK(__real_sigaction(owner.names[index], nullptr, &baseline[index]) == 0);
    }
    for (unsigned failed = 0; failed != 4; ++failed) {
        Boundary boundary;
        boundary.signals = true;
        boundary.failure = failed;
        bool refused = false;
        {
            Injection injection(boundary);
            try {
                astra::Signals installed;
                CHECK(!installed.requested());
                CHECK(::raise(SIGTERM) == 0 && installed.requested());
            } catch (const std::runtime_error& error) {
                if (failed == 0 || std::string_view(error.what()) != (failed == 3 ? "Cannot install pipe signal handler" : "Cannot install exit signal handlers")) {
                    throw;
                }
                refused = true;
            }
        }
        CHECK(refused == (failed != 0) && boundary.valid);
        const unsigned attempts = failed == 0 ? 6 : failed * 2 - 1;
        CHECK(boundary.installed == attempts);
        const unsigned acquired = failed == 0 ? 3 : failed - 1;
        const unsigned first = failed == 0 ? 3 : failed;
        for (unsigned index = 0; index < first; ++index) {
            CHECK((boundary.actions[index] == Action{owner.names[index], true}));
        }
        for (unsigned index = 0; index < acquired; ++index) {
            CHECK((boundary.actions[first + index] == Action{owner.names[index], false}));
        }
        for (std::size_t index = 0; index < owner.names.size(); ++index) {
            struct sigaction action{};
            CHECK(__real_sigaction(owner.names[index], nullptr, &action) == 0);
            CHECK(action.sa_handler == baseline[index].sa_handler && action.sa_flags == baseline[index].sa_flags);
            for (int signal = 1; signal < NSIG; ++signal) {
                CHECK(::sigismember(&action.sa_mask, signal) == ::sigismember(&baseline[index].sa_mask, signal));
            }
        }
        observed(failed == 0 ? "signals-native" : failed == 1 ? "signals-interrupt"
                                              : failed == 2   ? "signals-terminate"
                                                              : "signals-pipe");
    }
    // Confirm original restoration now; the destructor remains only an exceptional-path backstop.
    for (std::size_t index = 0; index < owner.names.size(); ++index) {
        CHECK(__real_sigaction(owner.names[index], &owner.original[index], nullptr) == 0);
    }
}

/// Refuse native normalization after valid parsing, then recover through the untouched native implementation.
void addresses() {

    // Literal IPv4/IPv6 vectors anchor argument width, error class and canonical recovery independently.
    for (const bool ipv6 : std::array{false, true}) {
        Boundary boundary;
        boundary.address = true;
        boundary.family = ipv6 ? AF_INET6 : AF_INET;
        if (ipv6) {
            boundary.bytes.back() = 1;
        } else {
            boundary.bytes[0] = 127;
            boundary.bytes[3] = 1;
        }
        const std::string_view input = ipv6 ? "[::1]:4532" : "127.0.0.1:4532";

        // Rejected input must not consume the failure; accepted input reports the native dependency refusal.
        {
            Injection owner(boundary);
            const auto rejected = astra::Endpoint::parse("invalid:4532");
            CHECK(!rejected && rejected.error().code == astra::Status::Code::Configuration);
            CHECK(boundary.normalized == 0);
            const auto failed = astra::Endpoint::parse(input);
            CHECK(!failed);
            CHECK(failed.error().code == astra::Status::Code::Internal && failed.error().message == "Address normalization failed");
            CHECK(boundary.valid && boundary.normalized == 1);
        }

        // Destruction disarms the hook before a real retry, without changing any host network state.
        const auto recovered = astra::Endpoint::parse(input);
        CHECK(recovered && recovered->text() == input);
        CHECK(boundary.normalized == 1 && current == nullptr);
        observed(ipv6 ? "address-ipv6-normalization" : "address-ipv4-normalization");
    }
}

/// Verify literal parser boundaries, keeping classification separate from address reachability.
void parsing() {

    /// Bind an independently declared numeric input to every expected normalized endpoint field.
    struct Entry {
        /// Borrow a complete literal IP and port without performing network I/O.
        std::string_view input;
        /// Require a complete endpoint or a stable configuration refusal.
        std::optional<astra::Endpoint> expected;
    };

    // The intended mapped-prefix neighbor has five zero words, then ff00, zero and one.
    const std::array<std::uint8_t, 16> expected{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0, 0, 1};
    std::array<std::uint8_t, 16> bytes{};
    CHECK(inet_pton(AF_INET6, "::ff00:0:1", bytes.data()) == 1);
    CHECK(bytes == expected);

    // Keep the IPv4-compatible input as well; GNU libc formats its last 32 bits with dotted notation.
    // Neighboring multicast and mapped-address boundaries change one classification predicate at a time.
    const std::array entries{
        Entry{"223.255.255.255:4532", astra::Endpoint{"223.255.255.255", 4532, false, false}},
        Entry{"224.0.0.1:4532", std::nullopt},
        Entry{"239.255.255.255:4532", std::nullopt},
        Entry{"240.0.0.1:4532", astra::Endpoint{"240.0.0.1", 4532, false, false}},
        Entry{"[::ff00:1]:4532", astra::Endpoint{"::255.0.0.1", 4532, true, false}},
        Entry{"[::ff00:0:1]:4532", astra::Endpoint{"::ff00:0:1", 4532, true, false}},
        Entry{"[::ffff:127.0.0.1]:4532", std::nullopt},
        Entry{"[2001:db8:1234:5678:abcd:ef12:3456:7890]:4532", astra::Endpoint{"2001:db8:1234:5678:abcd:ef12:3456:7890", 4532, true, false}},
        Entry{"[::1:4532", std::nullopt},
    };
    for (const auto& entry : entries) {
        const auto result = astra::Endpoint::parse(entry.input);
        CHECK(result.has_value() == entry.expected.has_value());
        CHECK(result ? *result == *entry.expected : result.error().code == astra::Status::Code::Configuration);
    }
    observed("endpoint-predicates");

    // Opaque UTF-8 IDs retain legal NUL separators; an empty segment cannot hide an invalid following segment.
    const std::array identifiers{
        std::pair{std::string("\0", 1), true},
        std::pair{std::string("a\0\0b", 4), true},
        std::pair{std::string("\xc3\xa9\0z", 4), true},
        std::pair{std::string("\0\x80", 2), false},
        std::pair{std::string("\xed\xa0\x80", 3), false},
    };
    for (const auto& [input, expected] : identifiers) {
        const auto before = input;
        CHECK(astra::Member::validId(input) == expected);
        CHECK(input == before);
    }
    observed("identifier-segments");

    // DNS labels accept case, interior hyphens and digits; out-of-alphabet bytes remain explicit refusals.
    const std::array names{
        std::pair<std::string_view, bool>{"az-AZ09:4532", true},
        std::pair<std::string_view, bool>{"A-0.example:4532", true},
        std::pair<std::string_view, bool>{"a{b:4532", false},
        std::pair<std::string_view, bool>{"a\x7f" "b:4532", false},
    };
    for (const auto& [input, expected] : names) {
        const auto result = astra::Config::formatPulsar(input);
        CHECK(result.has_value() == expected);
        CHECK(result ? *result == input : result.error().code == astra::Status::Code::Configuration);
    }
    CHECK(current == nullptr);
    observed("pulsar-hostname-predicates");
}

/// Exhaust valid member changes across deployment bindings, incarnation fields and neighboring epochs.
void incarnations() {

    // Every candidate starts from the same independently declared valid deployment.
    astra::Member original;
    original.galaxy = "alpha";
    original.group = "default";
    original.id = "issued/1";
    original.principal.bytes[0] = 1;
    original.address = {"127.0.0.1", 4532, false, false};
    original.epoch = {7};
    original.role = astra::Member::Role::Star;
    CHECK(original.validate());
    const auto baseline = original;

    // Each of four binding fields and two incarnation fields changes independently; no combination is filtered.
    unsigned cases{};
    for (unsigned binding = 0; binding < 16; ++binding) {
        for (unsigned identity = 0; identity < 4; ++identity) {
            for (std::uint64_t epoch = 0; epoch < 3; ++epoch) {
                auto candidate = original;
                candidate.epoch = {epoch + 6};
                if (binding & 1U) {
                    candidate.principal.bytes[0] = 2;
                }
                if (binding & 2U) {
                    candidate.role = astra::Member::Role::Planet;
                }
                if (binding & 4U) {
                    candidate.address.port = 4533;
                }
                if (binding & 8U) {
                    candidate.galaxy = "beta";
                }
                if (identity & 1U) {
                    candidate.id = "issued/2";
                }
                if (identity & 2U) {
                    candidate.group = "other";
                }
                CHECK(candidate.validate());

                // A deployment change always conflicts. Its unchanged incarnation may be repeated or superseded.
                std::optional<bool> expected;
                if (binding == 0) {
                    if (epoch == 2) {
                        expected = true;
                    } else if (epoch == 1 && identity == 0) {
                        expected = false;
                    }
                }
                const auto before = candidate;
                const auto result = astra::supersedes(candidate, original);
                if (expected) {
                    CHECK(result && *result == *expected);
                } else {
                    CHECK(!result && result.error().code == astra::Status::Code::Conflict);
                }
                CHECK(candidate == before && original == baseline);
                ++cases;
            }
        }
    }
    CHECK(cases == 192 && current == nullptr);
    observed("member-bindings");
}
} // namespace

/// Override only the main test thread's explicitly armed CLOCK_BOOTTIME reads.
extern "C" int __wrap_clock_gettime(clockid_t id, timespec* output) noexcept {
    if (!current || !current->clock || id != CLOCK_BOOTTIME) {
        return __real_clock_gettime(id, output);
    }
    auto& boundary = *current;
    ++boundary.clocks;
    *output = boundary.time;
    if (boundary.stepping) {
        output->tv_nsec = boundary.clocks <= boundary.repeated ? 0 : static_cast<long>(boundary.clocks - boundary.repeated);
    }
    if (boundary.clockResult < 0) {
        errno = EIO;
    }
    return boundary.clockResult;
}

/// Supply a deterministic resolution receipt without modifying the host clock configuration.
extern "C" int __wrap_clock_getres(clockid_t id, timespec* output) noexcept {
    if (!current || !current->timer || id != CLOCK_BOOTTIME) {
        return __real_clock_getres(id, output);
    }
    ++current->resolutions;
    *output = current->resolution;
    if (current->resolutionResult < 0) {
        errno = EIO;
    }
    return current->resolutionResult;
}

/// Successful acquisition always owns a real timerfd; only the declared acquisition failure is synthetic.
extern "C" int __wrap_timerfd_create(int id, int flags) noexcept {
    if (!current || !current->timer) {
        return __real_timerfd_create(id, flags);
    }
    auto& boundary = *current;
    ++boundary.creates;
    boundary.valid = boundary.valid && id == CLOCK_BOOTTIME && flags == (TFD_NONBLOCK | TFD_CLOEXEC);
    if (boundary.createResult < 0) {
        errno = EMFILE;
        return -1;
    }
    boundary.descriptor = __real_timerfd_create(id, flags);
    boundary.valid = boundary.valid && boundary.descriptor >= 0;
    return boundary.descriptor;
}

/// Preserve actual one-shot arming except for the explicitly selected failure receipt.
extern "C" int __wrap_timerfd_settime(int descriptor, int flags, const itimerspec* value, itimerspec* old) noexcept {
    if (!current || !current->timer || descriptor != current->descriptor) {
        return __real_timerfd_settime(descriptor, flags, value, old);
    }
    auto& boundary = *current;
    ++boundary.arms;
    boundary.valid = boundary.valid && flags == 0 && !old && value->it_interval.tv_sec == 0 && value->it_interval.tv_nsec == 0 && value->it_value.tv_sec == 0 && value->it_value.tv_nsec == 200'000'000;
    if (boundary.armResult < 0) {
        errno = EIO;
        return -1;
    }
    const auto result = __real_timerfd_settime(descriptor, flags, value, old);
    boundary.valid = boundary.valid && result == 0;
    return result;
}

/// Substitute only the owned timer's finite budget observations, never arbitrary process reads.
extern "C" ssize_t __wrap_read(int descriptor, void* output, std::size_t size) {
    if (!current || !current->timer || descriptor != current->descriptor) {
        return __real_read(descriptor, output, size);
    }
    auto& boundary = *current;
    const auto index = boundary.reads++;
    boundary.valid = boundary.valid && size == sizeof(std::uint64_t) && index < boundary.length;
    if (!boundary.valid) {
        errno = EINVAL;
        return -1;
    }
    const auto reply = boundary.input[index];
    if (reply.count < 0) {
        errno = reply.error;
    } else {
        const auto count = static_cast<std::size_t>(reply.count);
        boundary.valid = boundary.valid && count <= size;
        if (!boundary.valid) {
            errno = EINVAL;
            return -1;
        }
        std::fill_n(static_cast<std::uint8_t*>(output), count, std::uint8_t{});
    }
    return reply.count;
}

/// Observe successful real descriptor closure rather than treating a destructor call as sufficient evidence.
extern "C" int __wrap_close(int descriptor) {
    const auto result = __real_close(descriptor);
    if (current && current->timer && descriptor == current->descriptor) {
        ++current->closes;
        current->closed += result == 0;
    }
    return result;
}

/// Preserve exact buffer position and remaining length across partial reads and interrupted attempts.
extern "C" ssize_t __wrap_getrandom(void* output, std::size_t size, unsigned flags) {
    if (!current || !current->random) {
        return __real_getrandom(output, size, flags);
    }
    auto& boundary = *current;
    const auto index = boundary.draws++;
    boundary.valid = boundary.valid && index < boundary.length && flags == 0 && output == boundary.destination + boundary.written && size == 8 - boundary.written;
    if (!boundary.valid) {
        errno = EINVAL;
        return -1;
    }
    const auto reply = boundary.input[index];
    if (reply.count < 0) {
        errno = reply.error;
    } else {
        const auto count = static_cast<std::size_t>(reply.count);
        boundary.valid = boundary.valid && count <= size;
        if (!boundary.valid) {
            errno = EINVAL;
            return -1;
        }
        std::fill_n(static_cast<std::uint8_t*>(output), count, reply.byte);
        boundary.written += count;
    }
    return reply.count;
}

/// Inject one failed installation while retaining all other real installations and rollback receipts.
extern "C" int __wrap_sigaction(int signal, const struct sigaction* action, struct sigaction* old) noexcept {
    if (!current || !current->signals || !action) {
        return __real_sigaction(signal, action, old);
    }
    auto& boundary = *current;
    const auto index = boundary.installed++;
    boundary.valid = boundary.valid && index < boundary.actions.size();
    if (!boundary.valid) {
        errno = EINVAL;
        return -1;
    }
    boundary.actions[index] = {signal, old != nullptr};
    if (boundary.failure == index + 1) {
        errno = EINVAL;
        return -1;
    }
    const auto result = __real_sigaction(signal, action, old);
    boundary.valid = boundary.valid && result == 0;
    return result;
}

/// Inject only the armed caller's validated numeric address, retaining exact native argument checks.
extern "C" const char* __wrap_inet_ntop(int family, const void* source, char* output, socklen_t size) noexcept {

    // Other operations retain the real implementation, including the post-refusal recovery call.
    if (!current || !current->address) {
        return __real_inet_ntop(family, source, output, size);
    }

    // No allocation or assertion crosses the C boundary; the owning scenario checks the recorded facts.
    auto& boundary = *current;
    ++boundary.normalized;
    const auto count = boundary.family == AF_INET6 ? 16U : 4U;
    boundary.valid = boundary.valid && family == boundary.family && source && output && size == INET6_ADDRSTRLEN && std::equal(boundary.bytes.begin(), boundary.bytes.begin() + count, static_cast<const std::uint8_t*>(source));
    errno = boundary.valid ? ENOSPC : EINVAL;
    return nullptr;
}

/// Run finite syscall-boundary oracles; no thread, clock adjustment or external service is created.
int main() {
    try {
        elapsed();
        precision();
        entropy();
        signals();
        addresses();
        parsing();
        incarnations();
        CHECK(current == nullptr);
        std::cout << "COMMON-NATIVE {\"complete\":true}\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
