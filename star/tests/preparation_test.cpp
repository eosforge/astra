// Isolated thread-local allocation pause; test hooks/replacement new never link into production services.
#include "catalog_state.hpp"
#include "check.hpp"
#include "ephemeris_state.hpp"

#include <atomic>
#include <cstdlib>
#include <future>
#include <iostream>
#include <new>
#include <semaphore>
#include <utility>

namespace {
using namespace std::chrono_literals;
using astra::Catalog;
using astra::Clock;
using astra::Ephemeris;
using astra::Scope;

/// Pauses one real allocation for at most three seconds, including assertion failure cleanup.
struct Pause {
    /// Worker reached off-domain native preparation.
    std::binary_semaphore entered{0};
    /// Main fixture thread permits preparation to continue.
    std::binary_semaphore released{0};
};

/// Pause is armed only after installation's initial time sample.
thread_local Pause* armed{};
/// One-shot ordinary-new pause, cleared before standard-library recursion.
thread_local Pause* allocation{};
/// Controlled business milliseconds, reset per scenario.
std::atomic<std::int64_t> epoch{1000};
/// Fault countdown: -1=off, 0=next allocation throws, positive=remaining successful allocations.
thread_local std::ptrdiff_t remaining = -1;
/// Only actual thread-local bad_alloc counts as injection coverage.
thread_local bool injected{};

/// Standard throwing allocator with zero-size storage/new_handler behavior.
[[gnu::noinline]] void* allocate(std::size_t size) {

    if (auto* pause = std::exchange(allocation, nullptr)) {
        pause->entered.release();
        static_cast<void>(pause->released.try_acquire_for(3s));
    }
    if (remaining == 0) {
        remaining = -1;
        injected = true;
        throw std::bad_alloc{};
    }
    if (remaining > 0) {
        --remaining;
    }
    for (;;) {
        if (void* result = std::malloc(size ? size : 1)) {
            return result;
        }
        if (auto handler = std::get_new_handler()) {
            handler();
        } else {
            throw std::bad_alloc{};
        }
    }
}

/// Same allocation domain, accepting null, without pausing during release.
[[gnu::noinline]] void release(void* value) noexcept {
    std::free(value);
}

/// Both domains use real scheduling boundaries; fixed time avoids unrelated bulk expiration.
auto time() {
    if (auto* pause = std::exchange(armed, nullptr)) {
        allocation = pause;
    }
    return std::optional(Clock::Reading{.time = Clock::Time(std::chrono::milliseconds(epoch.load())), .ready = true});
}

/// Immutable fixture names/data in real containers without emulating Source/Scene internals.
Catalog::Value bytes(std::string_view text) {
    return std::make_shared<const Catalog::Buffer>(text.begin(), text.end());
}

/// While restore pauses in allocation, local writes must finish and same-source waits must release domain.
template <typename Domain>
void concurrent(typename Domain::Record incoming, std::string key, auto&& write, bool revoke) {

    using State = typename Domain::State;
    epoch = 1000;
    typename State::Limits limits;
    limits.replicas = 1; // An empty retired source must reclaim the fixture's sole admission slot.
    State state(time, limits);
    const Scope remote{"remote", "main"}, local{"local", "main"};
    CHECK(write(state, local));
    CHECK(state.admit("peer"));
    auto draft = state.prepare("peer", 1);
    CHECK(draft && draft->set(remote, key, incoming));
    auto recovery = state.restore("peer", std::move(*draft));
    CHECK(recovery);
    Pause pause;
    auto installer = std::async(std::launch::async, [task = std::move(*recovery), &pause]() mutable {
        armed = &pause;
        auto result = task.step();
        armed = allocation = nullptr; // Disable hooks before worker exit.
        return result;
    });
    const bool entered = pause.entered.try_acquire_for(1s);
    std::promise<void> querying; // Synchronize waiter startup explicitly instead of estimating with sleep.
    auto queried = querying.get_future();
    auto reader = std::async(std::launch::async, [&] {
        querying.set_value();
        return state.received("peer");
    });
    queried.wait();
    auto writer = std::async(std::launch::async, [&] {
        if (revoke) {
            state.retire("peer"); // Identity retirement cannot wait for full preparation; final installation must recheck it.
        }
        return static_cast<bool>(write(state, local));
    });
    const bool independent = writer.wait_for(1s) == std::future_status::ready;
    pause.released.release(); // Unblock before all assertions, without relying on CHECK unwinding for thread cleanup.
    const auto installed = installer.get();
    const auto written = writer.get();
    const auto position = reader.get();
    CHECK(entered && independent && written && position && *position == 0);
    if (revoke) {
        state.tick(); // Deferred retirement completes even if fixed business time did not advance.
        CHECK(state.admit("replacement"));
        CHECK(!installed && !state.find(remote, key)->record); // Revoked-source late candidates cannot publish.
    } else {
        CHECK(installed == false && state.find(remote, key)->record); // Scope installation is not final full-source confirmation.
        auto next = state.prepare("peer", 1);                         // No leaked editing/source lock; another valid same-position candidate can prepare.
        CHECK(next);
    }
}

/// Expired old leases during off-lock preparation require reads to wait for complete expiration/installation, without exposing stale live content.
template <typename Domain>
void expiration(typename Domain::Record incoming, std::string key) {

    using State = typename Domain::State;
    epoch = 1000;
    State state(time, {});
    const Scope scope{"expiry", "main"};
    CHECK(state.admit("peer") && state.apply("peer", 1, scope, key, incoming, State::Source::Form::Record));
    auto draft = state.prepare("peer", 2);
    CHECK(draft && draft->set(scope, key, incoming));
    auto recovery = state.restore("peer", std::move(*draft));
    CHECK(recovery);
    Pause pause;
    auto installer = std::async(std::launch::async, [task = std::move(*recovery), &pause]() mutable {
        armed = &pause;
        auto result = task.step();
        armed = allocation = nullptr;
        return result;
    });
    const bool entered = pause.entered.try_acquire_for(1s);
    epoch = 5000; // Keep the original four-second deadline rather than granting TTL on recovery receipt.
    auto reader = std::async(std::launch::async, [&] { return state.find(scope, key); });
    const bool waiting = reader.wait_for(100ms) == std::future_status::timeout;
    pause.released.release();
    const auto installed = installer.get();
    const auto point = reader.get();
    CHECK(entered && waiting && installed == false && point && !point->record);
}

/// Enumerate off-lock native and locked final-projection allocations; failure leaks no editing/directory/hook/source lock.
template <typename Domain>
void rollback(typename Domain::Record old, typename Domain::Record newer, std::string key) {

    using State = typename Domain::State;
    epoch = 1000;
    bool completed{}; // Continue to an actual allocation-complete success rather than assuming a fixed loop exhausted every point.
    for (std::ptrdiff_t point = 0; point < 512; ++point) {
        State state(time, {});
        const Scope scope{"rollback", "main"};
        CHECK(state.admit("peer") && state.apply("peer", 1, scope, key, old, State::Source::Form::Record));
        auto frozen = state.capture(scope);
        auto draft = state.prepare("peer", 2);
        CHECK(frozen && draft && draft->set(scope, key, newer));
        std::expected<void, typename State::Error> result;
        bool failed{};
        injected = false;
        remaining = point;
        try {
            result = state.replace("peer", std::move(*draft));
        } catch (const std::bad_alloc&) {
            failed = true;
        }
        remaining = -1; // Assertions/recovery checks run outside allocation injection.
        if (!injected) {
            CHECK(!failed && result && state.received("peer") == 2);
            completed = true;
            break;
        }
        CHECK(failed && state.received("peer") == 1 && state.capture(scope)->version() == frozen->version());
        auto retry = state.prepare("peer", 2);
        CHECK(retry && retry->set(scope, key, newer) && state.replace("peer", std::move(*retry)));
        CHECK(state.received("peer") == 2 && state.find(scope, key)->record);
    }
    CHECK(completed);
}

/// Local higher versions committed during remote preparation must win final remerge over stale unlocked results.
void merging() {

    epoch = 1000;
    Catalog::State state(time, {});
    const Scope scope{"shared", "main"};
    CHECK(state.admit("peer"));
    auto draft = state.prepare("peer", 1);
    CHECK(draft && draft->set(scope, "key", {1, bytes("remote"), Clock::Time(4s)}));
    auto recovery = state.restore("peer", std::move(*draft));
    CHECK(recovery);
    Pause pause;
    auto installer = std::async(std::launch::async, [task = std::move(*recovery), &pause]() mutable {
        armed = &pause;
        auto result = task.step();
        armed = allocation = nullptr;
        return result;
    });
    const bool entered = pause.entered.try_acquire_for(1s);
    auto writer = std::async(std::launch::async, [&] { return state.publish(scope, "key", bytes("local"), 2, 1000); });
    const bool independent = writer.wait_for(1s) == std::future_status::ready;
    pause.released.release();
    const auto installed = installer.get();
    const auto written = writer.get();
    const auto visible = state.find(scope, "key");
    CHECK(entered && independent && installed == false && written && visible && visible->record);
    CHECK(visible->record->version == 2 && *visible->record->value == *bytes("local"));
    const auto remote = state.replica("peer", scope, "key"); // Remote source retains its version one; only the public merge selects version two.
    CHECK(remote && *remote && (*remote)->version == 1);
}

/// Independent sources can prepare concurrently at real allocation barriers, beyond merely allowing local SDK writes.
template <typename Domain>
void parallel(typename Domain::Record record, std::string first, std::string second) {

    using State = typename Domain::State;
    epoch = 1000;
    State state(time, {});
    const Scope scope{"parallel", "main"};
    CHECK(state.admit("a") && state.admit("b"));
    auto a = state.prepare("a", 1), b = state.prepare("b", 1);
    CHECK(a && b && a->set(scope, first, record) && b->set(scope, second, record));
    auto left = state.restore("a", std::move(*a)), right = state.restore("b", std::move(*b));
    CHECK(left && right);
    Pause one, two; // Each thread pauses once through its own thread-local hook.
    auto launch = [](typename State::Recovery task, Pause& pause) {
        return std::async(std::launch::async, [task = std::move(task), &pause]() mutable {
            armed = &pause;
            auto result = task.step();
            armed = allocation = nullptr;
            return result;
        });
    };
    auto firstTask = launch(std::move(*left), one);
    const bool firstEntered = one.entered.try_acquire_for(1s);
    auto secondTask = launch(std::move(*right), two);
    const bool secondEntered = two.entered.try_acquire_for(1s);
    one.released.release();
    two.released.release();
    const auto firstResult = firstTask.get(), secondResult = secondTask.get();
    CHECK(firstEntered && secondEntered && firstResult == false && secondResult == false);
    CHECK(state.find(scope, first)->record && state.find(scope, second)->record);
}

/// Private-preparation exceptions reacquire domain before releasing source responsibility; later callers still acquire locks.
void exception() {

    /// Supply only a replica mutex for testing domain-unlock and exceptional cleanup boundaries.
    struct Replica {
        /// Serialize preparation for one synthetic replica without holding the domain commit lock.
        std::mutex mutex;
    }; // Guard-only fixture without extending production State test APIs.

    std::shared_mutex domain;
    const auto replica = std::make_shared<Replica>();
    std::unique_lock locked(domain);
    {
        astra::Borrowing borrowed(replica, locked);
        bool failed{};
        try {
            astra::Borrowing<Replica>::outside(locked, [] { throw std::bad_alloc{}; });
        } catch (const std::bad_alloc&) {
            failed = true;
        }
        CHECK(failed && locked.owns_lock());
    }
    CHECK(replica->mutex.try_lock());
    replica->mutex.unlock();
}
} // namespace

/// Replacement overloads share one allocation domain, excluding over-aligned allocation.
void* operator new(std::size_t size) {
    return allocate(size);
}

void* operator new[](std::size_t size) {
    return allocate(size);
}

void operator delete(void* value) noexcept {
    release(value);
}

void operator delete[](void* value) noexcept {
    release(value);
}

void operator delete(void* value, std::size_t) noexcept {
    release(value);
}

void operator delete[](void* value, std::size_t) noexcept {
    release(value);
}

/// Bounded lock-interleaving checks, without timing benchmarks, global sleeps, or production fault switches.
int main() {

    try {
        exception();
        merging();
        parallel<Catalog>({1, bytes("remote"), Clock::Time(4s)}, "a", "b");
        parallel<Ephemeris>({bytes("attr"), bytes("data"), Clock::Time(4s), 0, 0, 1000}, Ephemeris::uuid(), Ephemeris::uuid());
        for (const bool revoke : {false, true}) {
            const Catalog::Record catalog{1, bytes("remote"), Clock::Time(4s)};
            concurrent<Catalog>(catalog, "remote", [](auto& state, const Scope& scope) { return state.publish(scope, "own", bytes("own"), 1, 1000); }, revoke);
            const Ephemeris::Record ephemeris{bytes("attr"), bytes("data"), Clock::Time(4s), 0, 0, 1000};
            concurrent<Ephemeris>(ephemeris, Ephemeris::uuid(), [](auto& state, const Scope& scope) { return state.create(scope, bytes("attr"), bytes("own"), 1000); }, revoke);
        }
        expiration<Catalog>({1, bytes("remote"), Clock::Time(4s)}, "remote");
        expiration<Ephemeris>({bytes("attr"), bytes("data"), Clock::Time(4s), 0, 0, 1000}, Ephemeris::uuid());
        rollback<Catalog>({1, bytes("old"), Clock::Time(4s)}, {2, bytes("new"), Clock::Time(5s)}, "key");
        rollback<Ephemeris>({bytes("attr"), bytes("old"), Clock::Time(4s), 0, 0, 1000}, {bytes("attr"), bytes("new"), Clock::Time(5s), 1, 1, 1000}, Ephemeris::uuid());
        std::cout << "Replica preparation: ok\n";
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
