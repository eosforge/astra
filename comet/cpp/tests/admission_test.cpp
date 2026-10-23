// Verify Core admission limits and rollback at every allocation in an isolated, transport-free test process.
#include "check.hpp"
#include "core.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace comet::detail {
/// Inspect the actual Core directories without starting an Alarm, network, or background activity.
class Probe {
public:
    /// Capture logical ownership and queue identities; allocator capacity is not part of the public rollback contract.
    struct State {
        /// Existing admitted objects, in their actual directory order.
        std::array<const Activity*, 32> directory{};
        /// Existing wakeups, including retained completed objects before pruning.
        std::array<const Activity*, 32> queue{};
        /// Number of directory entries, including expired weak references.
        std::size_t entries{};
        /// Number of queued weak references.
        std::size_t pending{};
        /// Client owner plus accepted, unclosed application activities.
        std::size_t owners{};
        /// Admission's irreversible close gate.
        bool closing{};
        /// Compare logical state independently of allocator capacity.
        bool operator==(const State&) const = default;
    };

    /// Delegate to the production admission transition; the fixture retains the candidate on every exit.
    static Result<void> accept(const std::shared_ptr<Core>& core, const std::shared_ptr<Activity>& object) {
        return core->accept(object);
    }

    /// Read a bounded snapshot under Core's lock while the single test thread retains every nonexpired object.
    static State state(const std::shared_ptr<Core>& core) {

        const std::lock_guard lock(core->mutex_);
        State state;
        CHECK(core->readers_.size() <= state.directory.size() && core->ready_.size() <= state.queue.size());
        state.entries = core->readers_.size();
        state.pending = core->ready_.size();
        state.owners = core->owners_;
        state.closing = core->closing_;
        for (std::size_t index = 0; index < state.entries; ++index) {
            state.directory[index] = core->readers_[index].lock().get();
        }
        for (std::size_t index = 0; index < state.pending; ++index) {
            state.queue[index] = core->ready_[index].lock().get();
        }
        return state;
    }
};
} // namespace comet::detail

namespace {
// Allocation injection belongs only to the calling test thread and ends before assertions, recovery, and cleanup.
thread_local std::ptrdiff_t remaining = -1;
thread_local bool injected{};

#if defined(_MSC_VER)
__declspec(noinline)
#else
[[gnu::noinline]]
#endif
/// Preserve ordinary throwing-new behavior while failing exactly one declared allocation.
void* allocate(std::size_t size) {

    if (remaining == 0) {
        remaining = -1;
        injected = true;
        throw std::bad_alloc{};
    }
    if (remaining > 0) {
        --remaining;
    }
    for (;;) {
        if (void* value = std::malloc(size ? size : 1)) {
            return value;
        }
        if (const auto handler = std::get_new_handler()) {
            handler();
        } else {
            throw std::bad_alloc{};
        }
    }
}

#if defined(_MSC_VER)
__declspec(noinline)
#else
[[gnu::noinline]]
#endif
/// Match the ordinary alignment domain used by this target's replacement new operators.
void release(void* value) noexcept {
    std::free(value);
}

/// Disarm injection on both normal return and exception unwinding.
class Failure {
public:
    explicit Failure(std::ptrdiff_t point) {
        CHECK(remaining == -1);
        remaining = point;
        injected = false;
    }

    ~Failure() {
        remaining = -1;
    }

    Failure(const Failure&) = delete;
    Failure& operator=(const Failure&) = delete;
};

/// Model the application ownership obligations of an Activity without creating an RPC or an artificial scheduler.
class Item final : public comet::detail::Activity {
public:
    Item(std::shared_ptr<comet::detail::Core> core, bool streaming) : core_(std::move(core)), streaming_(streaming) {}

    ~Item() override {
        stop();
    }

    /// Record only a successful production admission; rejected construction cannot release an owner it never acquired.
    void admitted() noexcept {
        admitted_ = true;
    }

    /// Match the real activity's one-time release while retaining its independently observable cleanup state.
    void stop() noexcept {
        if (admitted_ && !closed_) {
            closed_ = true;
            core_->release();
        }
    }

    /// Publish completed cleanup only after the application intent has closed.
    void finish() noexcept {
        stop();
        finished_ = true;
    }

    bool closed() const noexcept override {
        return closed_;
    }

    bool finished() const noexcept override {
        return finished_;
    }

    bool streaming() const noexcept override {
        return streaming_;
    }

    std::chrono::steady_clock::time_point poll(std::chrono::steady_clock::time_point, const std::shared_ptr<const comet::detail::Binding>&, const std::optional<comet::Error>&, bool) override {
        throw std::logic_error("Admission fixture must not start a control loop");
    }

private:
    /// Shared target outlives admission snapshots and cleanup.
    const std::shared_ptr<comet::detail::Core> core_;
    /// Watch and automatic-write activities have independent limits.
    const bool streaming_;
    /// Exactly one accepted application owner exists after installation.
    bool admitted_{};
    /// Application owner has been returned.
    bool closed_{};
    /// The retained activity is eligible for directory/queue pruning.
    bool finished_{};
};

/// Prepare a real Core with bounded local capacity, without starting transport or its asynchronous control loop.
std::shared_ptr<comet::detail::Core> prepare(std::size_t readers = 8, std::size_t beacons = 8) {

    comet::Client::Options options;
    options.endpoints = {"127.0.0.1:1"};
    options.auth = false;
    options.tls = false;
    options.readers = readers;
    options.beacons = beacons;
    auto result = comet::detail::Core::prepare(std::move(options));
    CHECK(result);
    return *result;
}

/// Install one fixture activity through the actual Core transition, then bind its one-time release obligation.
void install(const std::shared_ptr<comet::detail::Core>& core, const std::shared_ptr<Item>& object) {
    CHECK(comet::detail::Probe::accept(core, object));
    object->admitted();
}

/// Sweep allocations on fresh identical logical inputs; every injected failure must recover on that same Core.
bool allocation(bool streaming, std::string_view layout, std::ptrdiff_t point) {

    const auto core = prepare();
    std::array<std::shared_ptr<Item>, 4> seeds;
    if (layout != "empty") {
        for (auto& seed : seeds) {
            seed = std::make_shared<Item>(core, streaming);
            install(core, seed);
            if (layout == "retired") {
                seed->finish();
            }
        }
    }
    const auto candidate = std::make_shared<Item>(core, streaming);
    const auto before = comet::detail::Probe::state(core);
    bool failed = false;
    {
        const Failure failure(point);
        try {
            CHECK(comet::detail::Probe::accept(core, candidate));
        } catch (const std::bad_alloc&) {
            failed = true;
        }
    }
    CHECK(failed == injected);
    if (failed) {
        CHECK(comet::detail::Probe::state(core) == before);
        install(core, candidate);
    } else {
        candidate->admitted();
    }
    const auto after = comet::detail::Probe::state(core);
    const auto expected = layout == "retired" ? 1 : before.entries + 1;
    CHECK(after.entries == expected && after.pending == expected && after.owners == before.owners + 1 && !after.closing);
    CHECK(after.directory[after.entries - 1] == candidate.get() && after.queue[after.pending - 1] == candidate.get());
    if (layout == "retired") {
        for (const auto& seed : seeds) {
            core->wake(seed.get());
            CHECK(comet::detail::Probe::state(core) == after);
        }
    }
    return failed;
}

/// Reject active and retained over-capacity independently for both activity domains, with exact ownership preservation.
void limits(bool streaming, std::size_t limit) {

    const auto other = 3 - limit;
    const auto core = prepare(streaming ? limit : other, streaming ? other : limit);
    std::array<std::shared_ptr<Item>, 8> objects;
    std::size_t used{};
    for (std::size_t index = 0; index < other; ++index) {
        objects[used] = std::make_shared<Item>(core, !streaming);
        install(core, objects[used++]);
    }
    const auto start = used;
    for (std::size_t index = 0; index < limit; ++index) {
        objects[used] = std::make_shared<Item>(core, streaming);
        install(core, objects[used++]);
    }
    const auto candidate = std::make_shared<Item>(core, streaming);
    auto before = comet::detail::Probe::state(core);
    auto rejected = comet::detail::Probe::accept(core, candidate);
    CHECK(!rejected && rejected.error().code == comet::Error::Code::Busy && rejected.error().effect == comet::Error::Effect::Unapplied);
    CHECK(comet::detail::Probe::state(core) == before);

    // Closed application intents free their active quota but retain independent cleanup capacity until finished.
    for (std::size_t index = 0; index < limit; ++index) {
        objects[start + index]->stop();
        objects[used] = std::make_shared<Item>(core, streaming);
        install(core, objects[used]);
        objects[used++]->stop();
    }
    before = comet::detail::Probe::state(core);
    rejected = comet::detail::Probe::accept(core, candidate);
    CHECK(!rejected && rejected.error().code == comet::Error::Code::Busy && rejected.error().effect == comet::Error::Effect::Unapplied);
    CHECK(comet::detail::Probe::state(core) == before);
    objects[start]->finish();
    install(core, candidate);
    const auto after = comet::detail::Probe::state(core);
    CHECK(after.entries == before.entries && after.pending == before.pending && after.owners == before.owners + 1);
    core->wake(objects[start].get());
    CHECK(comet::detail::Probe::state(core) == after);

    core->close();
    before = comet::detail::Probe::state(core);
    const auto late = std::make_shared<Item>(core, streaming);
    rejected = comet::detail::Probe::accept(core, late);
    CHECK(!rejected && rejected.error().code == comet::Error::Code::Closed && rejected.error().effect == comet::Error::Effect::Unapplied);
    CHECK(comet::detail::Probe::state(core) == before);
    std::cout << "COMET-ADMISSION limits " << streaming << ' ' << limit << " passed\n";
}
} // namespace

/// Replace ordinary allocations only within this test executable; over-aligned and nonthrowing allocation domains stay unchanged.
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

/// Complete a finite allocation sweep and quota matrix; CTest separately owns the outer timeout and process cleanup.
int main() {
    try {
        for (const auto streaming : {false, true}) {
            for (const std::string_view layout : {"empty", "growth", "retired"}) {
                std::ptrdiff_t failures{};
                for (std::ptrdiff_t point = 0; point < 16; ++point) {
                    if (!allocation(streaming, layout, point)) {
                        break;
                    }
                    CHECK(allocation(streaming, layout, point));
                    ++failures;
                }
                CHECK(failures > 0 && failures < 16);
                std::cout << "COMET-ADMISSION allocations " << streaming << ' ' << layout << ' ' << failures << " passed\n";
            }
            for (const std::size_t limit : {1U, 2U}) {
                limits(streaming, limit);
            }
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
