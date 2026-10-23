// Ephemeris transaction fault injection in an isolated process; replacement new never enters production targets.
#include "allocation.hpp"
#include "check.hpp"
#include "ephemeris_state.hpp"
#include "origin.hpp"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <new>
#include <optional>

namespace {
/// Thread-local injection: -1=disabled, 0=next allocation throws, positive=successful allocations before failure.
thread_local std::ptrdiff_t remaining = -1;
/// Tracks actual injection hits so unrelated bad_alloc cannot count as fault coverage.
thread_local bool injected{};

/// Allocates size bytes, including releasable zero-size storage, preserving standard new_handler behavior.
[[gnu::noinline]] void* allocate(std::size_t size) {

    if (remaining == 0) {
        remaining = -1;
        injected = true;
        throw std::bad_alloc{};
    }
    if (remaining > 0) {
        --remaining;
    }
    for (;;) {
        // Ordinary malloc alignment only; excludes over-aligned objects.
        if (void* value = std::malloc(size ? size : 1)) {
            return value;
        }

        if (auto handler = std::get_new_handler()) {
            handler();
        } else {
            throw std::bad_alloc{};
        }
    }
}

[[gnu::noinline]] void release(void* value) noexcept {
    std::free(value);
}

/// Arm one allocation refusal and restore ordinary allocation when the scope exits.
class Failure {
public:
    explicit Failure(std::ptrdiff_t point) {
        remaining = point;
        injected = false;
    }

    ~Failure() {
        remaining = -1;
    }

    Failure(const Failure&) = delete;

    Failure& operator=(const Failure&) = delete;
};

} // namespace

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

namespace {
using namespace std::chrono_literals;
using astra::Clock;
using astra::Ephemeris;
using State = Ephemeris::State;

/// Inject real public-write preparation using source, COW projection, history, and intrusive wheels.
enum class Operation {
    /// New Scope/UUID/source/projection/wheel/hook preparation.
    Create,
    /// Shared source/content-root path copying.
    Update,
    /// Source/history/wheel-only renewal, without public-root copying.
    Renew,
    /// Joint source termination/content deletion preparation.
    Remove,
    /// Tick allocation failure reschedules for later expiration.
    Expire
};

/// Fresh State per allocation point prevents retained capacity from hiding preparation failures.
void atomicity(Operation operation) {

    bool completed{};
    unsigned failures{};
    for (std::ptrdiff_t point = 0; point < 128; ++point) {
        auto now = 1s; // Injected time; only expire advances to the deadline.
        State state([&] { return std::optional(Clock::Reading{.time = Clock::Time(now), .ready = true}); }, {});
        const astra::Scope initial{"initial", "scope"};
        const astra::Scope target{"target", "scope"};
        const auto attr = std::make_shared<const Ephemeris::Buffer>(12, 1);
        const auto data = std::make_shared<const Ephemeris::Buffer>(12, 2);
        const auto replacement = std::make_shared<const Ephemeris::Buffer>(16, 3);
        const auto first = state.create(initial, attr, data, 1000);
        CHECK(first);
        const auto source = state.source();       // Frozen source root forces COW and must remain unchanged.
        const auto view = state.capture(initial); // Frozen public root independently exercises update/deletion COW.
        CHECK(view);
        if (operation == Operation::Expire) {
            now = 2s;
        }
        bool failed{};
        try {
            const Failure failure(point);
            switch (operation) {
            case Operation::Create:
                CHECK(state.create(target, attr, data, 1000));
                break;
            case Operation::Update:
                CHECK(state.update(initial, first->uuid, replacement, 1));
                break;
            case Operation::Renew:
                CHECK(state.renew(initial, first->uuid, 1));
                break;
            case Operation::Remove:
                CHECK(state.remove(initial, first->uuid));
                break;
            case Operation::Expire:
                state.tick();
                break;
            }
            completed = !injected;
        } catch (const std::bad_alloc&) {
            CHECK(injected);
            failed = true;
            ++failures;
        }
        if (!failed) {
            CHECK(!injected); // Normal return must reach an allocation-complete operation.
        }
        const auto before = astra::test::allocation::current(state); // Export preserves a failed expiry boundary.

        // Frozen Attr/Data/deadline remain unchanged on success/failure, without advancing the saved view while checking current state.
        CHECK(source.position() == 1 && source.size() == 1 && view->version() == 1 && view->size() == 1);
        source.each([&](const astra::Scope&, const std::string&, const Ephemeris::Record& record) { CHECK(record.attr == attr && record.data == data && record.deadline == Clock::Time(2s)); });
        view->each([&](const std::string&, const State::Content& content) { CHECK(content.attr == attr && content.data == data); });
        if (operation == Operation::Expire) {
            now = 3s; // Failed expiration hooks reschedule for the next tick rather than losing deadlines.
            state.tick();
            CHECK(state.source().position() == 2 && state.source().size() == 0);
            CHECK(state.capture(initial)->version() == 2 && state.capture(initial)->size() == 0);
            const auto events = state.events(0);
            CHECK(events && events->size() == 2 && events->back().form == State::Source::Form::Erase);
        } else if (failed) {
            CHECK(state.source().position() == 1 && state.source().size() == 1);
            CHECK(state.capture(initial)->version() == 1);
            const auto events = state.events(0);
            CHECK(events && events->size() == 1);
            CHECK(state.find(initial, first->uuid)->record->data == data);
            CHECK(state.capture(target)->version() == 0 && state.capture(target)->size() == 0);
            // A normal write after rollback proves no editing flag, dangling lookup, or incorrect history charge remains.
            CHECK(state.update(initial, first->uuid, replacement, 1));
            CHECK(state.source().position() == 2 && state.capture(initial)->version() == 2);
        } else {
            CHECK(state.source().position() == 2);
            CHECK(state.capture(initial)->version() == (operation == Operation::Update || operation == Operation::Remove ? 2U : 1U));
            const auto events = state.events(0);
            CHECK(events && events->size() == 2);
            if (operation == Operation::Create) {
                CHECK(state.capture(target)->version() == 1 && state.source().size() == 2);
            }
        }
        constexpr const char* names[]{"create", "update", "renew", "remove", "expire"};
        std::cout << "ASTRA-ALLOCATION {\"event\":\"attempt\",\"operation\":\"" << names[static_cast<unsigned>(operation)] << "\",\"point\":" << point << ",\"injected\":" << (injected ? "true" : "false") << ",\"propagated\":" << (failed ? "true" : "false") << ",\"before\":" << before << ",\"after\":";
        astra::test::allocation::complete(std::cout, state, initial, target);
        std::cout << ",\"frozen\":[";
        astra::test::allocation::source(std::cout, source);
        std::cout << ',';
        astra::test::allocation::view(std::cout, *view);
        std::cout << "]}\n";
        if (completed) {
            break;
        }
    }
    CHECK(completed && failures > 0); // Require actual injected failure and eventual complete success.
}
} // namespace

/// Ordinary new only; excludes random-source failures, aligned allocation, and network-decoding OOM.
int main() {
    try {
        std::cout << "ASTRA-ALLOCATION {\"event\":\"start\",\"domain\":\"ephemeris\",\"sweeps\":[[\"create\",128],[\"update\",128],[\"renew\",128],[\"remove\",128],[\"expire\",128]]}\n";
        atomicity(Operation::Create);
        atomicity(Operation::Update);
        atomicity(Operation::Renew);
        atomicity(Operation::Remove);
        atomicity(Operation::Expire);
        std::cout << "ASTRA-ALLOCATION {\"event\":\"finish\",\"domain\":\"ephemeris\"}\n";
        CHECK(std::cout.good());
        std::cout << "Ephemeris fault tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
