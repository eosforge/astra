// Isolated source-transaction allocation faults; replacement new never enters production Star or other cases.
#include "catalog.hpp"
#include "check.hpp"
#include "origin.hpp"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <new>
#include <optional>

namespace {
/// Thread-local countdown: -1=off, 0=next allocation throws, positive=successful allocations before failure.
thread_local std::ptrdiff_t remaining = -1;
/// Records actual injected hits, excluding unrelated bad_alloc.
thread_local bool injected{};

/// Standard throwing allocation, including releasable zero-size storage and new_handler behavior.
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
        // Ordinary malloc alignment only, excluding over-aligned objects.
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

/// Releases storage including null, without reading destroyed objects.
[[gnu::noinline]] void release(void* value) noexcept {
    std::free(value);
}

/// Injection covers only the tested call; later assertions/cleanup allocate normally.
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
/// Real native Origin template, not a fake transaction container.
using Source = astra::Origin<astra::Catalog::Record>;

/// Watermarks have no payload; present bodies charge their full logical bytes.
std::size_t measure(const astra::Catalog::Record& record) noexcept {
    return record.value ? record.value->size() : 0;
}

/// Distinct preparation paths, with no partial candidate publication after failure.
enum class Operation {
    /// New Scope/name/buckets/pages/history.
    Insert,
    /// Shared-page COW and replacement.
    Replace,
    /// Deletion page/history preparation.
    Erase,
    /// Missing termination still consumes one complete source position.
    Absent
};

/// Any allocation failure preserves source/pages/directory/position/send history.
void atomicity(Operation operation) {

    bool completed{};
    unsigned failures{};
    for (std::ptrdiff_t point = 0; point < 128; ++point) {
        const auto gate = std::make_shared<std::shared_mutex>(); // Fresh synchronization/container capacity for every injection.
        Source source(gate, measure, true, {.history = 1});
        const auto now = std::chrono::steady_clock::now();
        const astra::Scope scope{"one", "scope"};
        const astra::Catalog::Record initial{1, std::make_shared<const astra::Catalog::Buffer>(8, 1), astra::Clock::Time(10s)};
        {
            Source::Retired retired;
            const std::lock_guard lock(*gate);
            auto edit = source.prepare(scope, "key", initial, 1, now);
            CHECK(edit);
            retired = edit->commit();
        }
        const auto frozen = [&] { const std::lock_guard lock(*gate); return source.capture(); }(); // Frozen roots force overwrite/deletion through COW.
        const astra::Scope target = operation == Operation::Insert ? astra::Scope{"new", "scope"} : scope;
        const std::string key = operation == Operation::Absent ? "absent" : "key";
        const std::optional<astra::Catalog::Record> value = operation == Operation::Erase || operation == Operation::Absent ? std::nullopt : std::optional(initial);
        bool failed{};
        {
            Source::Retired retired; // Declare retired resources before lock for off-lock release even on exceptions.
            const std::lock_guard lock(*gate);
            try {
                const Failure failure(point);
                auto edit = source.prepare(target, key, value, 2, now);
                CHECK(edit);
                retired = edit->commit();
                completed = true;
            } catch (const std::bad_alloc&) {
                CHECK(injected);
                failed = true;
                ++failures;
            }
            CHECK(source.position() == (failed ? 1U : 2U));
            const auto history = source.replay(failed ? 0 : 1);
            CHECK(history && history->size() == 1 && history->front().position == source.position());
            if (failed) {
                CHECK(source.capture().size() == 1 && source.find(scope, "key")->value == initial.value);
                CHECK(!source.find({"new", "scope"}, "key"));
                auto retry = source.prepare(target, key, value, 2, now); // Immediate retry proves no leaked editing state or Scope capacity.
                CHECK(retry);
            }
        }
        frozen.each([&](const auto&, const auto&, const auto& record) { CHECK(record.value == initial.value && record.version == 1); });
        if (completed) {
            break;
        }
    }
    CHECK(completed && failures != 0);
}

/// Cross-Scope merge faults preserve original directory/accounting/watermarks/positions.
void batch() {

    bool completed{};
    unsigned failures{};
    for (std::ptrdiff_t point = 0; point < 256; ++point) {
        const auto gate = std::make_shared<std::shared_mutex>();
        Source source(gate, measure, false);
        const astra::Scope scope{"one", "main"};
        {
            Source::Retired retired;
            const std::lock_guard lock(*gate);
            auto initial = source.prepare(scope, "key", astra::Catalog::Record{1, {}, {}}, 1, std::chrono::steady_clock::now());
            CHECK(initial);
            retired = initial->commit();
        }
        const auto frozen = [&] { const std::lock_guard lock(*gate); return source.capture(); }();
        std::optional<Source::Tree> retired;
        {
            const std::lock_guard lock(*gate);
            try {
                const Failure failure(point);
                auto candidate = source.prepare();
                CHECK(candidate.set(scope, "key", {10, {}, {}}));
                CHECK(candidate.set({"new", "scope"}, "new", {20, {}, {}}));
                retired.emplace(candidate.commit());
                completed = true;
            } catch (const std::bad_alloc&) {
                CHECK(injected);
                ++failures;
                CHECK(source.position() == 1 && source.capture().size() == 1);
                CHECK(source.find(scope, "key")->version == 1 && !source.find({"new", "scope"}, "new"));
                auto retry = source.prepare();
                CHECK(retry.set({"new", "scope"}, "new", {20, {}, {}}));
            }
        }
        frozen.each([](const auto&, const auto&, const auto& record) { CHECK(record.version == 1); });
        if (completed) {
            break;
        }
    }
    CHECK(completed && failures > 0);
}

/// Full-source preparation failure affects only private work; earlier candidate entries and installed roots remain readable.
void snapshot() {

    bool completed{};
    unsigned failures{};
    for (std::ptrdiff_t point = 0; point < 128; ++point) {
        const auto gate = std::make_shared<std::shared_mutex>();
        Source source(gate, measure, false);
        auto draft = source.prepare(100);
        CHECK(draft.set({"one", "scope"}, "key", {1, nullptr, std::nullopt}));
        bool failed{};
        try {
            const Failure failure(point);
            CHECK(draft.set({"two", "scope"}, "key", {2, nullptr, std::nullopt}));
            completed = true;
        } catch (const std::bad_alloc&) {
            CHECK(injected);
            failed = true;
            ++failures;
        }
        {
            std::optional<Source::Replaced> retired;
            const std::lock_guard lock(*gate);
            const Failure failure(0); // Atomic installation and root capture cannot allocate after complete preparation.
            auto installed = source.reset(std::move(draft));
            CHECK(installed);
            retired.emplace(std::move(*installed));
            const auto view = source.capture();
            CHECK(view.position() == 100 && view.size() == (failed ? 1U : 2U));
            CHECK(!injected);
        }
        if (completed) {
            break;
        }
    }
    CHECK(completed && failures != 0);
}
} // namespace

int main() {

    try {
        atomicity(Operation::Insert);
        atomicity(Operation::Replace);
        atomicity(Operation::Erase);
        atomicity(Operation::Absent);
        snapshot();
        batch();
        std::cout << "source allocation cases: ok\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
