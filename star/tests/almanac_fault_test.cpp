// Allocation faults in an isolated process; replacement new never links into Star or other tests.
#include "almanac.hpp"
#include "check.hpp"

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

/// Releases allocated storage, including null, without accessing destroyed objects.
[[gnu::noinline]] void release(void* value) noexcept {
    std::free(value);
}

/// Injection covers only the tested call; assertions/cleanup allocate normally after scope exit.
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

/// Distinct fallible preparations, enumerated rather than replaced by one random failure.
enum class Operation {
    /// New-key map/string/page/history preparation.
    Insert,
    /// Existing-key payload and shared-snapshot COW preparation.
    Replace,
    /// Existing-key deletion page/history preparation.
    Erase,
    /// Missing-key deletion still prepares authoritative history.
    Absent,
    /// Full-candidate root/history swap preserves old state on every preparation failure.
    Reset,
    /// Every allocation point in multi-key COW/directory/history preparation.
    Batch
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
/// Installs version ten and returns an old view sharing pages with later writes.
astra::Almanac::View initialize(astra::Almanac& book, bool full) {
    // Full fills the first 64-slot leaf to exercise rollback during new-key tree expansion.
    auto draft = book.prepare(10);
    CHECK(draft.set("existing", {1}));
    if (full) {

        for (unsigned index = 0; index < 63; ++index) {
            CHECK(draft.set("seed-" + std::to_string(index), {1}));
        }
    }
    CHECK(book.reset(std::move(draft)) == true);
    return *book.view();
}

/// Enumerates ordinary allocations from input ownership through final precommit history enqueue.
void atomicity(Operation operation) {

    // Requires both actual injected failures and eventual completion without injection.
    bool completed{};
    unsigned failures{};
    for (std::ptrdiff_t point = 0; point < 128; ++point) {
        // Fresh state per point prevents retained capacity from hiding later allocations.
        astra::Almanac book;
        const auto old = initialize(book, operation == Operation::Insert);
        auto draft = book.prepare(20);
        CHECK(draft.set("replacement", {2}));
        try {
            const Failure failure(point);
            switch (operation) {
            case Operation::Insert:
                CHECK(book.apply(11, "new", astra::Almanac::Buffer{2}) == true);
                break;
            case Operation::Replace:
                CHECK(book.apply(11, "existing", astra::Almanac::Buffer{2}) == true);
                break;
            case Operation::Erase:
                CHECK(book.apply(11, "existing", std::nullopt) == true);
                break;
            case Operation::Absent:
                CHECK(book.apply(11, "absent", std::nullopt) == true);
                break;
            case Operation::Batch: {
                std::vector<astra::Almanac::Change> changes;
                for (const auto* key : {"existing", "new"}) {
                    changes.push_back({std::make_shared<const std::string>(key), std::make_shared<const astra::Almanac::Buffer>(1, 2), 11});
                }
                CHECK(book.apply(11, std::move(changes), 1024 * 1024) == true);
                break;
            }
            case Operation::Reset:
                CHECK(book.reset(std::move(draft)) == true);
                break;
            }
            completed = true;
        } catch (const std::bad_alloc&) {
            CHECK(injected);
            ++failures;
            CHECK(book.view()->version() == 10 && book.view()->size() == old.size());
            CHECK(*book.find("existing")->value == astra::Almanac::Buffer{1});
            CHECK(book.find("new")->value == nullptr);
            CHECK(book.find("replacement")->value == nullptr);
            CHECK(book.replay(10)->changes.empty());
        }

        // Old captured roots remain unchanged on success/failure, including baseline state handoff.
        old.each([](const std::string& key, const astra::Almanac::Value& value) { CHECK((key == "existing" || key.starts_with("seed-")) && *value == astra::Almanac::Buffer{1}); });
        if (completed) {
            CHECK(book.view()->version() == (operation == Operation::Reset ? 20U : 11U));
            break;
        }
    }
    // Reset may allocate nothing; correctness does not depend on deque implementation choices.
    CHECK(completed && (failures != 0 || operation == Operation::Reset));
}

/// Oversized new history may evict itself and old entries, but preparation failure preserves data/version/complete history.
void eviction() {

    // Current data fits; only the replacement's history cost exceeds the exact history budget.
    astra::Almanac::Limits limits;
    limits.backlog = sizeof(astra::Almanac::Change) + 9;

    bool completed{};
    unsigned failures{};
    for (std::ptrdiff_t point = 0; point < 128; ++point) {
        // Rebuild version-eleven history and old view per injection point.
        astra::Almanac book(limits);
        const auto old = initialize(book, false);
        CHECK(book.apply(11, "existing", astra::Almanac::Buffer{1}) == true);
        const auto saved = book.replay(10);
        CHECK(saved && saved->changes.size() == 1);
        try {
            const Failure failure(point);
            CHECK(book.apply(12, "existing", astra::Almanac::Buffer{2, 3}) == true);
            completed = true;
        } catch (const std::bad_alloc&) {
            CHECK(injected);
            ++failures;
            CHECK(book.view()->version() == 11 && book.view()->size() == 1);
            CHECK(*book.find("existing")->value == astra::Almanac::Buffer{1});
            // Read the live history queue again, detecting preparation that prematurely moved old history.
            const auto replay = book.replay(10);
            CHECK(replay && replay->version == 11 && replay->changes.size() == 1);
            CHECK(replay->changes.front().version == 11 && *replay->changes.front().value == astra::Almanac::Buffer{1});
        }

        // Borrowed pages/history retain original values through commit and eviction without early release or mutation.
        old.each([](const std::string& key, const astra::Almanac::Value& value) { CHECK(key == "existing" && *value == astra::Almanac::Buffer{1}); });
        CHECK(saved->version == 11 && *saved->changes.front().value == astra::Almanac::Buffer{1});
        if (completed) {
            CHECK(book.view()->version() == 12 && book.view()->size() == 1);
            CHECK(*book.find("existing")->value == (astra::Almanac::Buffer{2, 3}));
            CHECK(book.replay(11) == std::unexpected(astra::Almanac::Error::History));
            CHECK(book.replay(12)->changes.empty());
            // A later small commit may rebuild retention, but cannot pretend a lost version is contiguous.
            CHECK(book.apply(13, "existing", astra::Almanac::Buffer{3}) == true);
            CHECK(book.replay(12)->changes.size() == 1 && book.replay(12)->changes.front().version == 13);
            CHECK(book.replay(11) == std::unexpected(astra::Almanac::Error::History));
            break;
        }
    }
    CHECK(completed && failures != 0);
}

/// Failed full preparation still permits complete installation of the original candidate, without half-present Map/index records.
void preparation() {

    bool completed{};
    unsigned failures{};
    for (std::ptrdiff_t point = 0; point < 128; ++point) {
        astra::Almanac book;
        auto draft = book.prepare(20);
        CHECK(draft.set("existing", {1}));
        bool failed{};
        try {
            const Failure failure(point);
            CHECK(draft.set("new", {2}));
            completed = true;
        } catch (const std::bad_alloc&) {
            CHECK(injected);
            failed = true;
            ++failures;
        }
        CHECK(book.reset(std::move(draft)) == true);
        CHECK(book.view()->version() == 20);
        CHECK(book.view()->size() == (failed ? 1U : 2U));
        CHECK(*book.find("existing")->value == astra::Almanac::Buffer{1});
        CHECK(static_cast<bool>(book.find("new")->value) == !failed);
        if (completed) {
            break;
        }
    }
    CHECK(completed && failures != 0);
}

/// Capturing an immutable root transfers references without whole-Map allocation.
void capture() {

    astra::Almanac book;
    auto draft = book.prepare(1);
    // Use multiple leaf pages so the no-allocation case is not merely an empty Scope.
    for (unsigned index = 0; index < 200; ++index) {
        CHECK(draft.set(std::to_string(index), {1}));
    }
    CHECK(book.reset(std::move(draft)) == true);

    const Failure failure(0);
    const auto result = book.view();
    CHECK(result && result->version() == 1 && result->size() == 200);
    CHECK(!injected);
}
} // namespace

int main() {
    try {
        atomicity(Operation::Batch);
        atomicity(Operation::Insert);
        atomicity(Operation::Replace);
        atomicity(Operation::Erase);
        atomicity(Operation::Absent);
        atomicity(Operation::Reset);
        eviction();
        preparation();
        capture();
        std::cout << "Almanac allocation tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
