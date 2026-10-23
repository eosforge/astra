// Verify Store allocation rollback, frozen views and controlled snapshot scheduling in this isolated executable.
#include "check.hpp"
#include "store.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <limits>
#include <new>
#include <semaphore>
#include <thread>
#include <utility>

#if defined(__linux__)
#include <pthread.h>
#endif

namespace {
/// Allocations allowed on this thread before the next injected failure; -1 disables injection without affecting other threads.
thread_local std::ptrdiff_t remaining = -1;
/// Records actual injection, distinguishing controlled failure from unrelated exceptions.
thread_local bool injected = false;

/// Pauses this test thread's next allocation to verify writers/TTL progress while snapshot construction is stalled.
struct Pause {
    /// entered signals the pause and released permits continuation; both initially have no permits.
    std::binary_semaphore entered{0}, released{0};
    /// Initially false; explicit and cleanup release together return one permit only.
    bool resumed{};

    /// Idempotently releases the allocation pause without allocation, avoiding stranded threads on unwinding.
    void resume() noexcept {

        if (!std::exchange(resumed, true)) {
            released.release();
        }
    }
};

/// Initially null; captures and clears this thread's one-shot next-allocation pause.
thread_local Pause* pauseNext{};

#if defined(__linux__)
/// Observe one reader's request for the snapshot builder lock after its initial cache check.
struct Waiting {
    /// Notify the owner before the second native mutex acquisition; no business state is substituted.
    std::binary_semaphore entered{0};
    /// Count this reader's actual mutex requests, read by the owner only after joining.
    unsigned requests{};
};

// Only the selected reader installs this borrowed observer; all other threads forward native calls unchanged.
thread_local Waiting* waiting{};
#endif

struct Watch;
/// Tracks current-thread allocations only, excluding other threads/services from bucket-reclamation checks.
thread_local Watch* allocationWatch{};

/// Observes the largest successful scoped allocation and its release, independent of RSS or allocator return to OS.
struct Watch {
    /// Installs one nonnested observer; no out-of-scope addresses or object-content access.
    Watch() {
        allocationWatch = this;
    }

    /// Removes hooks before Store destruction can access the observer.
    ~Watch() {
        allocationWatch = nullptr;
    }

    /// Forbids multiple copies competing for one thread hook.
    Watch(const Watch&) = delete;
    /// Forbids replacing an observer while its thread hook is installed.
    Watch& operator=(const Watch&) = delete;
    /// Selects the largest allocation during setup only; afterward still observes release of that address.
    bool collecting{true};
    /// largest identifies an allocation without reading/freeing it; released records the matching delete.
    void* largest{};
    /// Largest observed byte size, initially zero and updated only while collecting.
    std::size_t size{};
    /// Initially false; set on the target address's release, independent of OS reclamation.
    bool released{};
};

/// Allocates size bytes with normal alignment and non-null result for release; failure throws bad_alloc.
/// Normal mode retains new_handler. Injection is one-shot so exception handling/diagnostics may allocate afterward.
[[gnu::noinline]] void* allocate(std::size_t size) {

    if (auto* pause = std::exchange(pauseNext, nullptr)) {
        pause->entered.release();
        pause->released.acquire();
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
        // malloc result; zero-sized new still returns a releasable non-null address.
        if (void* value = std::malloc(size ? size : 1)) {
            if (allocationWatch && allocationWatch->collecting && size > allocationWatch->size) {
                allocationWatch->largest = value;
                allocationWatch->size = size;
                allocationWatch->released = false;
            }
            return value;
        }

        // Standard caller-installed allocation-failure handler, invoked only on actual malloc failure.
        if (auto handler = std::get_new_handler()) {
            handler();
        } else {
            throw std::bad_alloc{};
        }
    }
}

/// Nonthrowing release of allocate's result; null is valid.
/// Separate call prevents optimizer misclassification across new/free wrappers.
[[gnu::noinline]] void release(void* value) noexcept {

    if (value && allocationWatch && value == allocationWatch->largest) {
        allocationWatch->released = true;
        allocationWatch->largest = nullptr;
    }
    std::free(value);
}

/// Enables faults during the tested operation only; every exit disables injection before assertions/destruction.
class Failure {
public:
    /// Allows point allocations on this thread, then fails once and clears the previous injection marker.
    explicit Failure(std::ptrdiff_t point) {
        remaining = point;
        injected = false;
    }

    /// Every exit disables injection so later assertions and cleanup may allocate normally.
    ~Failure() {
        remaining = -1;
    }

    /// Forbids copying injection-scope responsibility.
    Failure(const Failure&) = delete;
    /// Forbids overwriting active injection responsibility.
    Failure& operator=(const Failure&) = delete;
};
} // namespace

/// Scalar new forwards size to controlled allocation, preserving throwing-new semantics.
void* operator new(std::size_t size) {
    return allocate(size);
}

/// Array new shares scalar injection count; compiler-supplied size includes array storage.
void* operator new[](std::size_t size) {
    return allocate(size);
}

/// Scalar delete releases storage without reading ended object lifetimes.
void operator delete(void* value) noexcept {
    release(value);
}

/// Array delete releases its allocation; null is allowed.
void operator delete[](void* value) noexcept {
    release(value);
}

/// Sized scalar delete ignores size and uses the ordinary scalar allocation domain.
void operator delete(void* value, std::size_t) noexcept {
    release(value);
}

/// Sized array delete ignores size and uses the ordinary array allocation domain.
void operator delete[](void* value, std::size_t) noexcept {
    release(value);
}

#if defined(__linux__)
/// Forward to the real mutex operation; the linker substitutes only calls from this test executable.
extern "C" int __real_pthread_mutex_lock(pthread_mutex_t* mutex) noexcept;

/// Announce the selected reader's builder-lock request without taking, releasing or replacing that lock.
extern "C" int __wrap_pthread_mutex_lock(pthread_mutex_t* mutex) noexcept {

    if (waiting && ++waiting->requests == 2) {
        waiting->entered.release();
    }
    return __real_pthread_mutex_lock(mutex);
}
#endif

using namespace astra;

namespace {
/// Mutating fault scenarios cover insertion rollback, replacement, deletion, and multi-Key expiry.
enum class Operation {
    /// New Key requires a map node and possibly bucket allocation.
    Insert,
    /// Existing value cannot be replaced before history allocation succeeds.
    Replace,
    /// Deletion and its delta commit together.
    Remove,
    /// Expiry succeeds as a whole or preserves the whole batch, with visible failure.
    Expire,
};

/// Injects each operation allocation point and returns actual failures; prefix varies deque segment position.
/// Recreate Store for every point; after all allocation failures, the operation must eventually succeed or fail the case.
std::size_t sweep(Operation operation, unsigned prefix) {

    // Count actual injected failures, not allocation-free no-ops.
    // Initially zero actual injected points; require at least one failure before accepting final success.
    std::size_t failures = 0;
    // Existing Key exceeds SSO, forcing string-allocation coverage.
    const std::string first(80, 'a');
    // Expires with first to detect partial deletion of one batch.
    const std::string second(80, 'b');
    // New long Key exercises map-node/bucket-growth candidates.
    const std::string added(80, 'c');
    // Allocation index to fail; upper bound prevents a test loop from hanging.
    for (std::ptrdiff_t point = 0; point < 128; ++point) {
        // Retains two history batches so successful commits also exercise trimming.
        Store store(2, std::chrono::minutes(10), std::chrono::milliseconds(1), Clock::Time{});
        store.put(first, {1}, Clock::Time{});
        store.put(second, {1}, Clock::Time{});
        // Advances setup commit position outside injection scope.
        for (unsigned i = 0; i < prefix; ++i) {
            store.put("seed", {1});
        }

        // Preoperation snapshot for version and actual-data comparison.
        // Retains preinjection view; every preparation failure must preserve this complete state.
        const auto before = store.snapshot();
        // Accepts visible bad_alloc only; injected detects swallowed failures.
        bool failed = false;
        {
            // Limits controlled failure to one operation.
            Failure failure(point);
            try {
                switch (operation) {
                case Operation::Insert:
                    store.put(added, {2});
                    break;
                case Operation::Replace:
                    store.put(first, {2});
                    break;
                case Operation::Remove:
                    store.remove(first);
                    break;
                case Operation::Expire:
                    store.tick(Clock::Time{} + std::chrono::milliseconds(1));
                    break;
                }
            } catch (const std::bad_alloc&) {
                failed = true;
            }
        }
        if (!failed) {
            CHECK(!injected);
            CHECK(failures != 0);
            CHECK(store.version() == before->version + 1);
            return failures;
        }
        CHECK(injected);
        ++failures;
        CHECK(store.version() == before->version);
        // Failed operation must create neither deltas nor version gaps.
        const auto history = store.extract(before->version);
        CHECK(!history.stale && history.deltas.empty());
        CHECK(store.snapshot() == before);

        // Commit an independent marker and rebuild the snapshot so old cache cannot hide mutated map state at an unchanged version.
        store.put("probe", {3});
        // Actual rebuilt map must reveal no partial writes hidden by old snapshot cache.
        const auto after = store.snapshot();
        CHECK(after->version == before->version + 1);
        CHECK(after->data.size() == before->data.size() + 1);
        // Borrowed old snapshot entries; each original value must remain in the postfailure snapshot.
        for (const auto& [key, value] : before->data) {
            CHECK(after->data.contains(key));
            CHECK(*after->data.at(key).value == *value.value);
            CHECK(after->data.at(key).deadline == value.deadline);
        }

        // Delta may contain only explicit probe marker, never any failed-operation record.
        const auto delta = store.extract(before->version);
        CHECK(!delta.stale && delta.deltas.size() == 1 && delta.deltas.front().key == "probe");
        // Failure cannot cancel existing leases; next catch-up deletes both finite entries while probe remains live.
        store.tick(Clock::Time{} + std::chrono::milliseconds(3));
        CHECK(store.version() == before->version + 2);
        CHECK(store.snapshot()->data.size() == before->data.size() - 1 && store.snapshot()->data.contains("probe"));
        CHECK(!store.snapshot()->data.contains(first) && !store.snapshot()->data.contains(second));
    }
    throw std::runtime_error("Allocation sweep did not reach a successful operation");
}

/// Injects snapshot construction when true or delta extraction when false, returning failure count.
/// Read-only allocation failures preserve published snapshots, current version, and complete history.
std::size_t sweepRead(bool snapshot) {

    // Require positive failures to establish controlled query-allocation failure coverage.
    // Initially zero actual injected points; require at least one failure before accepting final success.
    std::size_t failures = 0;
    // Long Key covers returned-name copying plus array/map allocation.
    const std::string key(80, 'r');
    // Move failure point through a freshly created uncached version each time.
    for (std::ptrdiff_t point = 0; point < 128; ++point) {
        // Default history capacity retains both setup writes.
        Store store;
        store.put(key, {1});
        // Previously delivered first-version snapshot must remain unchanged through query failure.
        const auto previous = store.snapshot();
        store.put(key, {2});
        // Whether the injected query exception reached the caller.
        bool failed = false;
        {
            // Injection ends with this scope; later checks cannot trigger another failure accidentally.
            Failure failure(point);
            try {
                if (snapshot) {
                    CHECK(store.snapshot()->data.at(key).value->front() == 2);
                } else {
                    CHECK(store.extract(0).deltas.size() == 2);
                }
            } catch (const std::bad_alloc&) {
                failed = true;
            }
        }
        CHECK(store.version() == 2);
        CHECK(previous->version == 1 && previous->data.at(key).value->front() == 1);
        CHECK(store.snapshot()->data.at(key).value->front() == 2);
        CHECK(store.extract(0).deltas.size() == 2);
        if (!failed) {
            CHECK(!injected && failures != 0);
            return failures;
        }
        CHECK(injected);
        ++failures;
    }
    throw std::runtime_error("Read allocation sweep did not reach success");
}

/// Expiry batches above the former reserve(64) fail at every point; afterward renewal, cancellation, and whole-batch retry must remain valid.
std::size_t sweepLargeExpiry() {

    // Initially zero actual injected points; require at least one failure before accepting final success.
    std::size_t failures = 0;
    for (std::ptrdiff_t point = 0; point < 512; ++point) {
        // Independent Store per injection point with explicit history, tick width, and epoch origin.
        Store store(200, std::chrono::minutes(10), std::chrono::milliseconds(1), Clock::Time{});
        for (unsigned index = 0; index < 96; ++index) {
            store.put(std::string(80, 'k') + std::to_string(index), {1}, Clock::Time{});
        }

        // Initially false; catches only expected bad_alloc, with state checks after injection ends.
        bool failed = false;
        {
            Failure failure(point);
            try {
                store.tick(Clock::Time{} + std::chrono::milliseconds(1));
            } catch (const std::bad_alloc&) {
                failed = true;
            }
        }
        if (!failed) {
            CHECK(!injected && failures != 0 && store.version() == 97 && store.snapshot()->data.empty());
            return failures;
        }
        CHECK(injected && store.version() == 96 && store.snapshot()->data.size() == 96);
        ++failures;
        // Nodes may remain in old ready_ or rescheduled slots; renewal and cancellation must work in both locations.
        const auto renewed = std::string(80, 'k') + "0";
        store.put(renewed, {2});
        store.remove(std::string(80, 'k') + "1");
        store.tick(Clock::Time{} + std::chrono::milliseconds(4));
        CHECK(store.version() == 99 && store.snapshot()->data.size() == 1);
        CHECK(store.snapshot()->data.at(renewed).value->front() == 2);
        // Complete successful retry batch must have no missing, duplicate, or partial changes.
        const auto changes = store.extract(98);
        CHECK(changes.deltas.size() == 94);
    }
    throw std::runtime_error("Large TTL allocation sweep did not reach success");
}

/// One catch-up across several expiry ticks still commits once and recovers completely after any allocation failure.
std::size_t sweepCatchupExpiry() {

    // Initially zero actual injected points; require at least one failure before accepting final success.
    std::size_t failures = 0;
    // Deterministic business-time origin; test advances expiry and history explicitly.
    const auto origin = Clock::Time{};
    // Single jump across 3000 millisecond ticks exercises failures spanning several expiry times.
    const auto target = origin + std::chrono::milliseconds(3000);
    for (std::ptrdiff_t point = 0; point < 128; ++point) {
        // Independent Store per injection point with explicit history, tick width, and epoch origin.
        Store store(20, std::chrono::minutes(10), std::chrono::milliseconds(1), origin);
        for (unsigned index = 1; index <= 3; ++index) {
            store.put(std::string(80, 'b') + std::to_string(index), {1}, origin + std::chrono::milliseconds(index * 1000 - 1));
        }

        // Retains preinjection view; every preparation failure must preserve this complete state.
        const auto before = store.snapshot();
        // Initially false; catches only expected bad_alloc, with state checks after injection ends.
        bool failed = false;
        {
            Failure failure(point);
            try {
                store.tick(target);
            } catch (const std::bad_alloc&) {
                failed = true;
            }
        }
        if (failed) {
            CHECK(injected && store.version() == 3 && store.snapshot() == before);
            CHECK(store.extract(3).deltas.empty());
            ++failures;
        } else {
            CHECK(!injected && failures != 0 && store.version() == 4 && store.snapshot()->data.empty());
        }

        // Commit allocation failure may leave the wheel at target; retry rescheduled entries next tick without relying on remaining catch-up count.
        store.tick(target + std::chrono::milliseconds(1));
        CHECK(store.version() == 4 && store.snapshot()->data.empty());
        // Complete successful retry batch must have no missing, duplicate, or partial changes.
        const auto changes = store.extract(3);
        CHECK(!changes.stale && changes.deltas.size() == 3);
        for (unsigned index = 1; index <= 3; ++index) {
            // Byte-exact setup Key for checking each Delete appears once.
            const auto key = std::string(80, 'b') + std::to_string(index);
            // Delete count for this Key, initially zero and required exactly one.
            std::size_t count = 0;
            for (const auto& delta : changes.deltas) {
                CHECK(delta.deleted && !delta.value && delta.version == 4);
                count += delta.key == key;
            }
            CHECK(count == 1);
        }
        if (!failed) {
            return failures;
        }
    }
    throw std::runtime_error("Catch-up TTL allocation sweep did not reach success");
}

/// Catch-up without expired entries allocates no array and succeeds even if the next new is forbidden.
void testEmptyTickAllocation() {

    // Independent Store per injection point with explicit history, tick width, and epoch origin.
    Store store(1000, std::chrono::minutes(10), std::chrono::milliseconds(1), Clock::Time{});
    store.put("permanent", {1});
    {
        Failure failure(0);
        store.tick(Clock::Time{} + std::chrono::seconds(3));
        store.tick(Clock::Time{} + std::chrono::seconds(3));
        CHECK(!injected);
    }
    CHECK(store.version() == 1);
}

/// Fail COW preparation at every point while readers retain old pages; partial private paths cannot corrupt current or old views.
void testSnapshotPageFailures() {

    for (const bool erase : {false, true}) {
        // True only after exhausting failure points and reaching full success; hitting the case limit first fails.
        bool completed = false;
        // Initially zero actual injected points; require at least one failure before accepting final success.
        std::size_t failures = 0;
        for (std::ptrdiff_t point = 0; point < 32; ++point) {
            Index index;
            // Old view's shared payload; preparation failure cannot change contents or reference identity.
            const auto original = std::make_shared<const Store::Buffer>(Store::Buffer{1});
            // New payload referenced only by the target slot after complete success.
            const auto changed = std::make_shared<const Store::Buffer>(Store::Buffer{2});
            for (std::uint64_t slot = 0; slot < 65; ++slot) {
                index.prepare(slot);
                index.set(slot, std::make_shared<const std::string>(std::to_string(slot)), {original, {}});
            }

            // Retains old root to force COW and detect partial-path corruption.
            const auto previous = index.capture();
            // Initially false; catches only expected bad_alloc, with state checks after injection ends.
            bool failed = false;
            {
                Failure failure(point);
                try {
                    index.prepare(64);
                    if (erase) {
                        index.erase(64);
                    } else {
                        index.set(64, {}, {changed, {}});
                    }
                } catch (const std::bad_alloc&) {
                    failed = true;
                }
            }
            previous.each([&](const std::string&, const Index::Record& record) { CHECK(record.value == original); });
            CHECK(previous.size() == 65);
            // Actual postinjection view checked against failure/deletion expectations.
            const auto current = index.capture();
            CHECK(current.size() == (failed || !erase ? 65U : 64U));
            current.each([&](const std::string& key, const Index::Record& record) { CHECK(record.value == (!failed && key == "64" ? changed : original)); });
            if (!failed) {
                CHECK(!injected && failures != 0);
                completed = true;
                break;
            }
            CHECK(injected);
            ++failures;
        }
        CHECK(completed);
    }
}

/// Fail every allocation in sparse growth and COW preparation, then recover on that same index.
void testSnapshotDepthFailures() {

    // Every representable branch level and the last usable slot have independent fresh fault sweeps.
    std::array<std::uint64_t, 16> slots{};
    for (unsigned level = 0; level < 15; ++level) {
        slots[level] = std::uint64_t{1} << (6 + 4 * level);
    }
    slots.back() = UINT64_MAX - 1;
    const auto low = std::make_shared<const std::string>("low");
    const auto high = std::make_shared<const std::string>("high");
    const auto original = std::make_shared<const Index::Buffer>(Index::Buffer{1});
    const auto changed = std::make_shared<const Index::Buffer>(Index::Buffer{2});
    std::size_t faults = 0; // Count actual allocation refusals, separately from successful guard assertions.

    for (const auto slot : slots) {
        for (unsigned operation = 0; operation < 4; ++operation) {
            // Modes cover empty growth, growth beside a live low slot, overwrite and deletion.
            for (unsigned repetition = 0; repetition < 2; ++repetition) {
                bool completed = false;
                for (std::ptrdiff_t point = 0; point < 64; ++point) {
                    Index index;
                    if (operation != 0) {
                        index.prepare(0);
                        index.set(0, low, {original, {}});
                    }
                    if (operation >= 2) {
                        index.prepare(slot);
                        index.set(slot, high, {original, {}});
                    }
                    const auto before = index.capture(); // Retain the original root through failed and successful preparation.
                    const auto count = static_cast<unsigned>(operation != 0) + static_cast<unsigned>(operation >= 2);
                    const auto inspect = [&](const Index::View& view, bool committed) {
                        const bool present = committed ? operation != 3 : operation >= 2;
                        const auto expected = (operation == 0 ? 0U : 1U) + static_cast<unsigned>(present);
                        CHECK(view.size() == expected);
                        std::size_t visited = 0;
                        view.each([&](const std::string& key, const Index::Record& record) {
                            CHECK(!record.deadline);
                            if (key == "low") {
                                CHECK(operation != 0 && record.value == original && visited == 0);
                            } else {
                                CHECK(key == "high" && present && record.value == (committed ? changed : original));
                                CHECK(visited == (operation == 0 ? 0U : 1U));
                            }
                            ++visited;
                        });
                        CHECK(visited == expected);
                    };

                    bool failed = false;
                    {
                        Failure failure(point);
                        try {
                            index.prepare(slot);
                        } catch (const std::bad_alloc&) {
                            failed = true;
                        }
                    }
                    CHECK(failed == injected);
                    CHECK(before.size() == count);
                    inspect(before, false);
                    inspect(index.capture(), false);
                    if (failed) {
                        ++faults;
                        index.prepare(slot); // Resume the partially prepared tree, without reconstructing its logical state.
                    }

                    // Once preparation succeeds, the commit itself must not allocate even at maximum depth.
                    {
                        Failure failure(0);
                        if (operation == 3) {
                            index.erase(slot);
                        } else {
                            index.set(slot, operation < 2 ? high : nullptr, {changed, {}});
                        }
                        CHECK(!injected);
                    }
                    inspect(index.capture(), true);
                    inspect(before, false);
                    CHECK(index.next() == (operation == 0 ? 0U : 1U));
                    if (!failed) {
                        CHECK(point > 0);
                        completed = true;
                        break;
                    }
                }
                CHECK(completed);
            }
        }
    }
    CHECK(faults > 0);
    std::cout << "PAGES-FAULT slots=16 modes=4 repetitions=2 faults=" << faults << '\n';
}

/// Pause builder at its first allocation while another thread replaces, deletes, and expires entries; fail also injects snapshot-read allocation failure.
/// Lock-held dump must fail explicitly instead of hanging; success and failure preserve state and later snapshots.
void testSnapshotWriterProgress(bool fail) {

    using namespace std::chrono_literals;
    // Independent Store per injection point with explicit history, tick width, and epoch origin.
    Store store(100, 10min, 1ms, Clock::Time{});
    store.put("keep", {1});
    store.put("remove", {2});
    store.put("expire", {3}, Clock::Time{} + 1ms);
    Pause pause;
    // Assigned only by reader, inspected after join for a complete old version.
    std::shared_ptr<const Store::Snapshot> captured;
    // Each thread writes its own exception slot; inspect and propagate only after both join.
    std::exception_ptr readerError, writerError;
    // Reader pauses its next allocation; borrowed store/pause outlive join.
    std::jthread reader([&] {
        try {
            pauseNext = &pause;
            Failure failure(fail ? 2 : -1);
            captured = store.snapshot();
        } catch (...) {
            readerError = std::current_exception();
        }
        pauseNext = nullptr;
    });

    /// Assertion or thread-creation failure releases the pause before jthread joins, preventing test-created permanent blocking.
    struct Unblock {
        /// Borrows external pause state; restoration guard must die before reader so join cannot wait forever.
        Pause& pause;

        /// Every exceptional path releases allocation pause before later thread owners exit.
        ~Unblock() {
            pause.resume();
        }
    } unblock{pause};

    CHECK(pause.entered.try_acquire_for(5s));
    // Initially no permits; writer signals completion on success or failure for bounded main-thread waiting.
    std::binary_semaphore written{0};
    // Writer replaces, deletes, expires, and inserts while snapshot reader is paused; full-table construction must not hold the state lock.
    std::jthread writer([&] {
        try {
            store.put("keep", {4});
            store.remove("remove");
            store.tick(Clock::Time{} + 1ms);
            store.put("added", {5});
        } catch (...) {
            writerError = std::current_exception();
        }
        written.release();
    });
    // Writer finished while reader was still paused; post-release completion does not count as concurrent progress.
    const bool progressed = written.try_acquire_for(5s);
    pause.resume();
    writer.join();
    reader.join();
    if (writerError) {
        std::rethrow_exception(writerError);
    }
    CHECK(progressed);
    if (fail) {
        CHECK(readerError && !captured);
        try {
            std::rethrow_exception(readerError);
        } catch (const std::bad_alloc&) {
            // Accept expected resource failures only; propagate other exceptions to the test entry.
        }
    } else {
        if (readerError) {
            std::rethrow_exception(readerError);
        }
        CHECK(captured && captured->version == 3 && captured->data.size() == 3);
        CHECK(captured->data.at("keep").value->front() == 1 && captured->data.contains("remove") && captured->data.contains("expire"));
    }

    // Writer's new version, distinct from the paused reader's old captured version.
    const auto current = store.snapshot();
    CHECK(current != captured && current->version == 7 && current->data.size() == 2);
    CHECK(current->data.at("keep").value->front() == 4 && current->data.at("added").value->front() == 5);
    CHECK(store.snapshot() == current);
}

#if defined(__linux__)
/// Instantiate only explicitly named private member pointers for quiescent boundary-fixture setup.
template <typename Tag, auto member>
class Access {
    /// ADL exposes the typed member pointer only to its fixture tag, without offsets or object-layout casts.
    friend constexpr auto field(Tag) {
        return member;
    }
};

/// Restore two valid boundary states before public operations; never mutate a running or borrowed Store.
class Seed {
public:
    /// Borrow the sole-owned Store throughout setup and its public suffix checks.
    explicit Seed(Store& store) : store_(store) {}

    /// Establish the empty, fully compacted prefix ending one commit before version exhaustion.
    void tail();
    /// Establish the quiescent last tick before a clamped long-lease wakeup, preserving its real deadline.
    void segment();

private:
    /// Name the last committed Store version for typed fixture restoration.
    struct Version {
        friend constexpr auto field(Version);
    };

    /// Name the compacted history floor, kept equal to the restored empty prefix version.
    struct Oldest {
        friend constexpr auto field(Oldest);
    };

    /// Name the business-time anchor synchronized with the fixture wheel position.
    struct Epoch {
        friend constexpr auto field(Epoch);
    };

    /// Name the actual Store-owned timer, retaining its production node ownership rules.
    struct Timer {
        friend constexpr auto field(Timer);
    };

    /// Name the sole stable map entry whose existing timer link must be relocated.
    struct Entries {
        friend constexpr auto field(Entries);
    };

    /// Name the wheel's logical position, changed only while every timer link is detached.
    struct Position {
        friend constexpr auto field(Position);
    };

    /// Name the cached view so an inconsistent version-only seed cannot pass unnoticed.
    struct Cache {
        friend constexpr auto field(Cache);
    };

    /// Borrow the fixture owner; methods require sole-thread access and never outlive it.
    Store& store_;
};

// Explicit instantiations bind real typed members; neither production declarations nor their layout change.
template class Access<Seed::Version, &Store::version_>;
template class Access<Seed::Oldest, &Store::oldest_>;
template class Access<Seed::Epoch, &Store::clock_>;
template class Access<Seed::Timer, &Store::wheel_>;
template class Access<Seed::Entries, &Store::entries_>;
template class Access<Seed::Position, &Store::Timer::clock_>;
template class Access<Seed::Cache, &Store::cache_>;

void Seed::tail() {

    CHECK(store_.version() == 0 && (store_.*field(Entries{})).empty() && !(store_.*field(Cache{})));
    store_.*field(Version{}) = std::numeric_limits<std::uint64_t>::max() - 1;
    store_.*field(Oldest{}) = std::numeric_limits<std::uint64_t>::max() - 1;
}

void Seed::segment() {

    auto& entries = store_.*field(Entries{}); // The sole live entry already owns a genuine clamped timer link.
    auto& timer = store_.*field(Timer{});     // Relink through the public wheel operations; no intrusive pointer is fabricated.
    auto& epoch = store_.*field(Epoch{});     // Keep business and wheel time at the same restored boundary.
    CHECK(entries.size() == 1 && timer.now() == 0 && epoch && *epoch == Clock::Time{});
    auto& entry = entries.begin()->second; // The unordered-map node remains at its original stable address.
    CHECK(entry.scheduled() && entry.deadline == Clock::Time{} + std::chrono::nanoseconds(static_cast<std::int64_t>(Store::Timer::limit + 17)));
    Store::Timer::cancel(entry);
    timer.*field(Position{}) = Store::Timer::limit - 1;
    epoch = Clock::Time{} + std::chrono::nanoseconds(static_cast<std::int64_t>(Store::Timer::limit - 1));
    CHECK(timer.schedule(entry, 1));
    CHECK(entry.scheduled() && timer.now() == Store::Timer::limit - 1);
}

/// Force two readers past the first cache check while the first builder is paused, with optional failure/write.
void snapshots(bool fail, bool changed) {

    using namespace std::chrono_literals;
    Store store; // This fresh owner starts without a cached root; two writes establish version two.
    store.put("first", {1});
    store.put("second", {2});
    Pause pause;                                              // Hold the first builder's first allocation after it captures the complete old root.
    Waiting requested;                                        // The second reader announces its builder-lock request before the first can publish.
    std::binary_semaphore written{0};                         // Bound writer progress without advancing time or sleeping.
    std::shared_ptr<const Store::Snapshot> original, current; // Each reader owns its returned root until all comparisons finish.
    std::exception_ptr firstError, secondError, writerError;  // Each task writes only its own result; joining publishes it.
    bool firstInjected = false;                               // Copy the first reader's thread-local fault receipt before it exits.
    std::jthread first, second, writer;                       // Declare all task owners before the unblock guard for safe exceptional teardown.

    /// Resume the paused builder before later task owners join during unwinding.
    struct Unblock {
        /// Borrow the allocation pause until all later tasks have joined.
        Pause& pause;

        /// Release the builder before the task owners can wait during exception unwinding.
        ~Unblock() {
            pause.resume();
        }
    } unblock{pause};

    first = std::jthread([&pause, &store, &original, &firstError, &firstInjected, fail] {
        try {
            pauseNext = &pause;
            Failure failure(fail ? 0 : -1);
            original = store.snapshot();
        } catch (...) {
            firstError = std::current_exception();
        }
        firstInjected = injected;
        pauseNext = nullptr;
    });
    CHECK(pause.entered.try_acquire_for(5s));
    second = std::jthread([&requested, &store, &current, &secondError] {
        waiting = &requested;
        try {
            current = store.snapshot();
        } catch (...) {
            secondError = std::current_exception();
        }
        waiting = nullptr;
    });
    CHECK(requested.entered.try_acquire_for(5s));

    bool progressed = true; // A concurrent write must finish while the first reader still owns the builder lock.
    if (changed) {
        writer = std::jthread([&store, &writerError, &written] {
            try {
                store.put("first", {3});
            } catch (...) {
                writerError = std::current_exception();
            }
            written.release();
        });
        progressed = written.try_acquire_for(5s);
    }
    pause.resume();
    if (writer.joinable()) {
        writer.join();
    }
    second.join();
    first.join();
    CHECK(progressed && firstInjected == fail && requested.requests >= 3);
    if (writerError) {
        std::rethrow_exception(writerError);
    }
    if (secondError) {
        std::rethrow_exception(secondError);
    }
    if (fail) {
        CHECK(firstError && !original);
        try {
            std::rethrow_exception(firstError);
        } catch (const std::bad_alloc&) {
            // Only this controlled allocation failure is the expected first-reader outcome.
        }
    } else {
        if (firstError) {
            std::rethrow_exception(firstError);
        }
        CHECK(original && original->version == 2 && original->data.size() == 2);
        CHECK(*original->data.at("first").value == Store::Buffer{1});
        CHECK(original == current || changed);
    }
    CHECK(current && current->version == (changed ? 3U : 2U) && current->data.size() == 2);
    CHECK(*current->data.at("first").value == Store::Buffer{static_cast<std::uint8_t>(changed ? 3 : 1)});
    CHECK(*current->data.at("second").value == Store::Buffer{2});
    CHECK(store.version() == current->version && store.snapshot() == current);
    CHECK(!changed || current != original);
}

/// Cross the last legal commit, then reject insert/overwrite/remove/expiry twice without publishing partial state.
void exhaustion() {

    using namespace std::chrono_literals;
    Store store(0, 0ns, 1ns, Clock::Time{}); // Compacted history makes the restored empty prefix internally consistent.
    Seed seed(store);
    seed.tail();
    const auto empty = store.snapshot(); // This old root must survive the sole remaining legal commit unchanged.
    CHECK(empty->version == std::numeric_limits<std::uint64_t>::max() - 1 && empty->data.empty());
    store.put("last", {7}, Clock::Time{} + 1ns);
    const auto before = store.snapshot(); // Hold the genuine final-version value through all rejected operations.
    CHECK(before->version == std::numeric_limits<std::uint64_t>::max() && before->data.size() == 1);
    for (const auto operation : {Operation::Insert, Operation::Replace, Operation::Remove, Operation::Expire}) {
        for (unsigned attempt = 0; attempt < 2; ++attempt) {
            bool exhausted = false; // Only the declared version-limit category counts as the expected refusal.
            try {
                switch (operation) {
                case Operation::Insert:
                    store.put("overflow", {9});
                    break;
                case Operation::Replace:
                    store.put("last", {9});
                    break;
                case Operation::Remove:
                    store.remove("last");
                    break;
                case Operation::Expire:
                    store.tick(Clock::Time{} + std::chrono::nanoseconds(attempt + 1));
                    break;
                }
            } catch (const std::overflow_error& error) {
                CHECK(std::string_view(error.what()) == "Store version exhausted");
                exhausted = true;
            }
            CHECK(exhausted);
            CHECK(store.version() == before->version && store.snapshot() == before);
            CHECK(before->data.size() == 1 && *before->data.at("last").value == Store::Buffer{7});
            const auto history = store.extract(before->version); // No refused operation may append a hidden batch or advance its cursor.
            CHECK(!history.stale && history.version == before->version && history.deltas.empty());
            CHECK(empty->version == before->version - 1 && empty->data.empty());
        }
    }
    store.remove("absent"); // A genuine no-op still succeeds at the exhausted version.
    CHECK(store.version() == before->version && store.snapshot() == before);
}

/// Continue the real scheduler from a valid clamped-wakeup checkpoint, retaining the complete long deadline.
void segment() {

    using namespace std::chrono_literals;
    Store store(0, 0ns, 1ns, Clock::Time{}); // One-nanosecond ticks expose segmentation without waiting through a trillion empty slots.
    const auto boundary = Clock::Time{} + std::chrono::nanoseconds(static_cast<std::int64_t>(Store::Timer::limit));
    store.put("far", {7}, boundary + 17ns);
    const auto before = store.snapshot(); // Preserve the original absolute deadline and value across the intermediate wakeup.
    Seed seed(store);
    seed.segment();
    store.tick(boundary);
    CHECK(store.version() == before->version && store.snapshot() == before);
    CHECK(before->data.size() == 1 && before->data.at("far").deadline == boundary + 17ns);
    store.tick(boundary + 16ns);
    CHECK(store.version() == before->version && store.snapshot() == before);
    store.tick(boundary + 17ns);
    const auto after = store.snapshot(); // Only the real deadline publishes the one complete expiry commit.
    CHECK(after->version == before->version + 1 && after->data.empty());
    CHECK(before->version == 1 && before->data.size() == 1 && *before->data.at("far").value == Store::Buffer{7});
    CHECK(store.extract(before->version).stale && !store.extract(after->version).stale);
}
#endif

/// Sweep writer allocation failures while a paused reader owns a two-level COW root; return actual injected failures.
std::size_t sharing(Operation operation) {

    using namespace std::chrono_literals;
    // Every attempt starts with the same 65 leased records, spanning two leaves; failures cannot borrow prior preparation.
    std::size_t failures = 0;
    for (std::ptrdiff_t point = 0; point < 128; ++point) {
        Store store(256, 10min, 1ms, Clock::Time{});
        for (unsigned key = 0; key < 65; ++key) {
            store.put(std::to_string(key), {1}, Clock::Time{} + 1ms);
        }

        // Pause only after snapshot() has captured the root and released the state lock, before dump's first allocation.
        Pause pause;
        std::shared_ptr<const Store::Snapshot> captured;
        std::exception_ptr readerError, writerError;
        std::jthread reader([&store, &pause, &captured, &readerError] {
            try {
                pauseNext = &pause;
                captured = store.snapshot();
            } catch (...) {
                readerError = std::current_exception();
            }
            pauseNext = nullptr;
        });

        // Declared after the reader so exception unwinding releases its allocation before joining it.
        struct Drain {
            /// Borrow the pause through reader completion; never own or destroy the reader's state.
            Pause& pause;

            /// Release at most once, including failed thread creation or a failed entry assertion.
            ~Drain() {
                pause.resume();
            }
        } drain{pause};

        CHECK(pause.entered.try_acquire_for(5s));

        // These observations belong to the writer until join; the semaphore gives the blocked-reader schedule a finite budget.
        bool failed = false;
        bool triggered = false;
        std::binary_semaphore written{0};
        std::jthread writer([&store, &failed, &triggered, &writerError, &written, point, operation] {
            try {
                Failure failure(point);
                try {
                    switch (operation) {
                    case Operation::Insert:
                        store.put("added", {2});
                        break;
                    case Operation::Replace:
                        store.put("64", {2});
                        break;
                    case Operation::Remove:
                        store.remove("64");
                        break;
                    case Operation::Expire:
                        store.tick(Clock::Time{} + 1ms);
                        break;
                    }
                } catch (const std::bad_alloc&) {
                    failed = true;
                }
                triggered = injected;
            } catch (...) {
                writerError = std::current_exception();
            }
            written.release();
        });
        const bool progressed = written.try_acquire_for(5s);
        pause.resume();
        writer.join();
        reader.join();
        if (readerError) {
            std::rethrow_exception(readerError);
        }
        if (writerError) {
            std::rethrow_exception(writerError);
        }
        CHECK(progressed && triggered == failed);
        CHECK(captured && captured->version == 65 && captured->data.size() == 65);
        for (unsigned key = 0; key < 65; ++key) {
            const auto& record = captured->data.at(std::to_string(key));
            CHECK(*record.value == Store::Buffer{1} && record.deadline == Clock::Time{} + 1ms);
        }

        // Old history must survive too; neither the frozen snapshot nor its cache alone establishes rollback.
        const auto history = store.extract(0);
        const std::size_t appended = failed ? 0 : operation == Operation::Expire ? 65
                                                                                 : 1;
        CHECK(!history.stale && history.version == (failed ? 65U : 66U) && history.deltas.size() == 65 + appended);
        for (unsigned key = 0; key < 65; ++key) {
            const auto& delta = history.deltas[key];
            CHECK(delta.key == std::to_string(key) && delta.version == key + 1 && !delta.deleted);
            CHECK(*delta.value == Store::Buffer{1} && delta.deadline == Clock::Time{} + 1ms);
        }
        for (std::size_t offset = 65; offset < history.deltas.size(); ++offset) {
            const auto& delta = history.deltas[offset];
            CHECK(delta.version == 66 && delta.deleted == (operation == Operation::Remove || operation == Operation::Expire));
            if (operation != Operation::Expire) {
                CHECK(delta.key == (operation == Operation::Insert ? "added" : "64"));
            }
            CHECK(delta.deleted ? !delta.value : *delta.value == Store::Buffer{2});
            CHECK(!delta.deadline);
        }

        // Invalidate any returned cache, then inspect a fresh root. An erased map entry or a partly updated index cannot hide here.
        store.put("probe", {3});
        const auto current = store.snapshot();
        const std::size_t retained = failed || operation == Operation::Replace ? 65 : operation == Operation::Insert ? 66
                                                                                  : operation == Operation::Remove   ? 64
                                                                                                                     : 0;
        CHECK(current->version == history.version + 1 && current->data.size() == retained + 1);
        CHECK(*current->data.at("probe").value == Store::Buffer{3});
        for (unsigned key = 0; key < 65; ++key) {
            const auto name = std::to_string(key);
            const bool erased = !failed && (operation == Operation::Expire || (operation == Operation::Remove && key == 64));
            CHECK(current->data.contains(name) != erased);
            if (!erased) {
                const bool replaced = !failed && operation == Operation::Replace && key == 64;
                const auto& record = current->data.at(name);
                CHECK(*record.value == Store::Buffer{static_cast<std::uint8_t>(replaced ? 2 : 1)});
                CHECK(record.deadline == (replaced ? std::optional<Clock::Time>{} : std::optional{Clock::Time{} + 1ms}));
            }
        }

        // Failed preparations must retain every original timer. Successful replacement alone removes that key's old lease.
        store.tick(Clock::Time{} + 3ms);
        const auto expired = store.snapshot();
        const bool permanent = !failed && (operation == Operation::Insert || operation == Operation::Replace);
        CHECK(expired->version == current->version + (!failed && operation == Operation::Expire ? 0 : 1));
        CHECK(expired->data.size() == (permanent ? 2U : 1U) && expired->data.contains("probe"));
        if (permanent) {
            CHECK(*expired->data.at(operation == Operation::Insert ? "added" : "64").value == Store::Buffer{2});
        }
        if (!failed) {
            CHECK(failures != 0);
            std::cout << "STORE-SHARING " << static_cast<unsigned>(operation) << " failures=" << failures << " completed=1\n";
            return failures;
        }
        ++failures;
    }
    throw std::runtime_error("Shared Store allocation sweep did not reach success");
}

/// Large empty maps return buckets; one live entry prevents shrinking. Small tables avoid churn and reclamation preserves history/snapshots.
void testEmptyBucketReclamation() {

    using namespace std::chrono_literals;
    // count selects below/above reclamation threshold; leaveLive retains a permanent entry to exclude nonempty shrinking.
    for (const std::size_t count : {1024U, 8192U}) {
        for (const bool leaveLive : {false, true}) {
            // Zero-history mode reclaims tombstones immediately, separating bucket release from retention policy.
            Store store(0, 10min, 1ms, Clock::Time{});
            Watch watch;
            for (std::size_t key = 0; key < count; ++key) {
                store.put(std::to_string(key), {1}, leaveLive && key == 0 ? std::optional<Clock::Time>{} : std::optional{Clock::Time{} + 1ms});
            }
            watch.collecting = false;
            // Fixed short Keys, tiny Values, and no history make buckets the largest allocation; pages, nodes, and single records are smaller.
            const bool large = count == 8192;
            CHECK(watch.largest && !watch.released && watch.size > 4096);
            CHECK(!large || watch.size > 4096 * sizeof(void*));
            store.tick(Clock::Time{} + 1ms);
            CHECK(watch.released == (large && !leaveLive));
            if (leaveLive) {
                CHECK(store.snapshot()->data.at("0").value->front() == 1);
                store.remove("0");
                CHECK(!watch.released);
            }

            // Empty-map maintenance allocates nothing, advances no version, and preserves a cached empty snapshot.
            const auto version = store.version();
            // Retains the cached empty snapshot; pure maintenance must preserve its version and identity.
            const auto empty = store.snapshot();
            {
                Failure failure(0);
                store.tick(Clock::Time{} + 2ms);
                CHECK(!injected);
            }
            CHECK(watch.released == large && store.version() == version && store.snapshot() == empty && empty->data.empty());
            CHECK(store.extract(version).deltas.empty() && store.extract(version - 1).stale);
            // Insert and expire again after table replacement to verify lookup, page-slot reuse, and wheel continuity.
            store.put("reborn", {2}, Clock::Time{} + 3ms);
            CHECK(store.snapshot()->data.at("reborn").value->front() == 2);
            store.tick(Clock::Time{} + 3ms);
            CHECK(store.version() == version + 2 && store.snapshot()->data.empty() && empty->data.empty());
        }
    }

    // No live values does not mean no map nodes; retained Delete batches must preserve tombstones and continuation floor.
    // Deterministic business-time origin; test advances expiry and history explicitly.
    const auto origin = Clock::Time{};
    Store retained(1, 10min, 1s, origin);
    Watch watch;
    for (std::size_t key = 0; key < 8192; ++key) {
        retained.put(std::to_string(key), {1}, origin + 1s);
    }
    watch.collecting = false;
    CHECK(watch.largest && !watch.released && watch.size > 4096 * sizeof(void*));
    retained.tick(origin + 1s);
    CHECK(retained.snapshot()->data.empty() && !watch.released);
    // Owned complete Delete extraction remains readable after history and bucket reclamation.
    const auto deletion = retained.extract(8192);
    CHECK(!deletion.stale && deletion.deltas.size() == 8192 && deletion.version == 8193);
    // Advance about 660 whole-second ticks; reclaim buckets only after retention expiry while external Delete results survive.
    {
        Failure failure(0);
        retained.tick(origin + 11min, Steady::now() + 11min);
        CHECK(!injected);
    }
    CHECK(watch.released && retained.version() == 8193 && retained.extract(8192).stale && deletion.deltas.size() == 8192);
}

/// After high-slot deletion, low-slot writes recover a leaf-only copy budget without exposing tree height or timing optimization.
void testSnapshotRootContraction() {

    // Old view's shared payload; preparation failure cannot change contents or reference identity.
    const auto original = std::make_shared<const Store::Buffer>(Store::Buffer{1});
    // New payload referenced only by the target slot after complete success.
    const auto changed = std::make_shared<const Store::Buffer>(Store::Buffer{2});
    // Retains the lowest-slot Key through high-level deletion to verify actual root contraction.
    const auto lowKey = std::make_shared<const std::string>("low");
    // High-slot Key forces root expansion; deletion exposes the subsequent low-slot allocation budget.
    const auto highKey = std::make_shared<const std::string>("high");
    // Crosses leaf, second-root, and maximum-height boundaries; UINT64_MAX remains exhaustion, never a valid slot.
    for (const auto high : std::array<std::uint64_t, 4>{64, 1024, std::uint64_t{1} << 62, UINT64_MAX - 1}) {
        Index index;
        index.prepare(0);
        index.set(0, lowKey, {original, {}});
        index.prepare(high);
        index.set(high, highKey, {original, {}});
        // Old root retains low and high slots; current contraction cannot change it.
        const auto before = index.capture();
        index.prepare(high);
        {
            Failure failure(0);
            index.erase(high);
            CHECK(!injected);
        }

        // Contracted low-slot-only view remains unchanged by later expansion.
        const auto contracted = index.capture();
        CHECK(before.size() == 2 && contracted.size() == 1 && index.next() == 1);
        {
            // Current target standard library needs one make_shared leaf allocation; an extra root chain exhausts this budget and fails.
            Failure failure(1);
            index.prepare(0);
            index.set(0, {}, {changed, {}});
            CHECK(!injected);
        }
        before.each([&](const std::string& key, const Index::Record& record) { CHECK((key == "low" || key == "high") && record.value == original); });
        contracted.each([&](const std::string& key, const Index::Record& record) { CHECK(key == "low" && record.value == original); });
        index.capture().each([&](const std::string& key, const Index::Record& record) { CHECK(key == "low" && record.value == changed); });
        // Contraction still permits re-expansion while captured shorter trees remain unchanged.
        index.prepare(high);
        index.set(high, highKey, {changed, {}});
        CHECK(index.capture().size() == 2 && contracted.size() == 1 && index.next() == 1);
    }
}

} // namespace

/// Nonzero exit reports invariant or injection-coverage failure; a case with no actual failure cannot pass as coverage.
int main() {

    try {
        // Total failures across mutating operations and deque positions.
        // Initially zero actual injected points; require at least one failure before accepting final success.
        std::size_t failures = 0;
        // Iterates mutating entries and selected deque segment prefixes.
        for (const auto operation : {Operation::Insert, Operation::Replace, Operation::Remove, Operation::Expire}) {
            for (const unsigned prefix : {0U, 13U, 29U, 61U}) {
                failures += sweep(operation, prefix);
            }
        }

        // Query-allocation failures are counted separately from write atomicity coverage.
        const auto readFailures = sweepRead(true) + sweepRead(false);
        failures += sweepLargeExpiry();
        failures += sweepCatchupExpiry();
        testEmptyTickAllocation();
        testSnapshotPageFailures();
        testSnapshotDepthFailures();
        testSnapshotWriterProgress(false);
        testSnapshotWriterProgress(true);
        for (const auto operation : {Operation::Insert, Operation::Replace, Operation::Remove, Operation::Expire}) {
            failures += sharing(operation);
        }
        testEmptyBucketReclamation();
        testSnapshotRootContraction();
#if defined(__linux__)
        // Enumerate both allocation outcomes and both version outcomes with the same reachable lock schedule.
        constexpr std::array names{"cache", "failure", "replacement", "failure-replacement"};
        for (unsigned scenario = 0; scenario < names.size(); ++scenario) {
            snapshots((scenario & 1U) != 0, (scenario & 2U) != 0);
            std::fprintf(stdout, "COMMON-SNAPSHOT {\"case\":\"%s\"}\n", names[scenario]);
        }
        exhaustion();
        std::fputs("COMMON-SNAPSHOT {\"case\":\"exhaustion\"}\n", stdout);
        segment();
        std::fputs("COMMON-SNAPSHOT {\"case\":\"segment\"}\n", stdout);
        std::fputs("COMMON-SNAPSHOT {\"complete\":true}\n", stdout);
        CHECK(std::ferror(stdout) == 0);
#endif
        std::cout << "PASS store atomicity under " << failures << " write and " << readFailures << " read allocation failures\n";
        return 0;
    } catch (const std::exception& error) {
        // First failure reason with nonzero status for CTest.
        std::cerr << error.what() << '\n';
        return 1;
    }
}
