// Verify authoritative Almanac versions, atomic mutations, and snapshot consistency.
#include "almanac.hpp"
#include "check.hpp"

#include <atomic>
#include <iostream>
#include <latch>
#include <limits>
#include <optional>
#include <stdexcept>
#include <thread>

namespace {
/// Installs a valid empty baseline at the authoritative version before increments.
void initialize(astra::Almanac& book, std::uint64_t version = 0) {

    auto draft = book.prepare(version);
    CHECK(book.reset(std::move(draft)) == true);
}

/// Unready differs from an installed empty version zero; partial receipt cannot imply initialization.
void baseline() {

    astra::Almanac book;
    CHECK(book.view() == std::unexpected(astra::Almanac::Error::Unready));
    CHECK(book.find("missing") == std::unexpected(astra::Almanac::Error::Unready));
    CHECK(book.replay(0) == std::unexpected(astra::Almanac::Error::Unready));
    CHECK(book.apply(1, "key", astra::Almanac::Buffer{1}) == std::unexpected(astra::Almanac::Error::Unready));

    auto partial = book.prepare(10);
    CHECK(partial.set("key", {1}));
    CHECK(book.view() == std::unexpected(astra::Almanac::Error::Unready));
    initialize(book);
    CHECK(book.view()->version() == 0);
    CHECK(book.view()->size() == 0);
    CHECK(book.find("missing")->value == nullptr);
    CHECK(book.replay(0)->changes.empty());

    // Version zero permits only an empty baseline.
    auto zero = book.prepare(0);
    CHECK(zero.set("key", {}) == std::unexpected(astra::Almanac::Error::Version));
    CHECK(book.reset(std::move(zero)) == false);
    CHECK(book.apply(0, "key", astra::Almanac::Buffer{}) == std::unexpected(astra::Almanac::Error::Version));
}

/// Every valid +1 commits, replay is idempotent, and empty Set differs from Delete.
void versions() {

    astra::Almanac book;
    astra::Almanac other;
    initialize(book);
    initialize(other);
    CHECK(book.apply(2, "key", astra::Almanac::Buffer{}) == std::unexpected(astra::Almanac::Error::Version));
    CHECK(book.apply(1, "key", astra::Almanac::Buffer{}) == true);
    CHECK(book.find("key")->value && book.find("key")->value->empty());
    CHECK(book.apply(2, "key", astra::Almanac::Buffer{}) == true);
    CHECK(book.apply(3, "absent", std::nullopt) == true);
    CHECK(book.apply(1, "ignored", astra::Almanac::Buffer{7}) == false);
    CHECK(book.find("ignored")->value == nullptr);
    CHECK(book.view()->version() == 3 && book.view()->size() == 1);
    CHECK(other.view()->version() == 0 && other.view()->size() == 0);

    // History retains repeated empty Set and missing Delete, rather than inferring commits from the final Map.
    const auto replay = book.replay(0);
    CHECK(replay && replay->version == 3 && replay->changes.size() == 3);
    CHECK(replay->changes[0].value && replay->changes[0].value->empty());
    CHECK(replay->changes[1].value && replay->changes[1].value->empty());
    CHECK(!replay->changes[2].value && *replay->changes[2].key == "absent");
    CHECK(book.apply(4, "key", std::nullopt) == true);
    CHECK(book.view()->version() == 4 && book.view()->size() == 0);
    CHECK(book.find("key")->value == nullptr);

    // Reject increments beyond UINT64_MAX instead of wrapping to zero.
    constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
    astra::Almanac ending;
    initialize(ending, maximum - 1);
    CHECK(ending.apply(maximum, "last", astra::Almanac::Buffer{9}) == true);
    CHECK(ending.apply(0, "last", std::nullopt) == std::unexpected(astra::Almanac::Error::Version));
    CHECK(ending.view()->version() == maximum);
}

/// Private baseline preparation, duplicate keys, atomic replacement, nonregressing versions, and stable old roots.
void snapshots() {

    astra::Almanac book;
    initialize(book);
    CHECK(book.apply(1, "old", astra::Almanac::Buffer{1}) == true);

    const auto old = book.view();
    auto draft = book.prepare(10);
    CHECK(draft.set("new", {10}));
    CHECK(draft.set("new", {11}) == std::unexpected(astra::Almanac::Error::Duplicate));
    CHECK(draft.set("empty", {}));
    CHECK(book.view()->version() == 1 && book.find("new")->value == nullptr);

    // Assigning over a populated private draft replaces all of it without publishing either candidate.
    auto displaced = book.prepare(8);
    CHECK(displaced.set("discarded", {8}));
    displaced = std::move(draft);
    CHECK(draft.set("late", {}) == std::unexpected(astra::Almanac::Error::Input));
    CHECK(book.reset(std::move(draft)) == std::unexpected(astra::Almanac::Error::Input));
    draft = std::move(displaced);
    CHECK(displaced.set("late", {}) == std::unexpected(astra::Almanac::Error::Input));
    CHECK(book.view()->version() == 1 && book.find("new")->value == nullptr);

    CHECK(book.reset(std::move(draft)) == true);
    CHECK(book.view()->version() == 10 && book.view()->size() == 2);
    CHECK(!book.find("old")->value && *book.find("new")->value == astra::Almanac::Buffer{10});
    CHECK(!book.find("discarded")->value);
    CHECK(book.replay(1) == std::unexpected(astra::Almanac::Error::History));
    CHECK(book.reset(std::move(draft)) == std::unexpected(astra::Almanac::Error::Input));

    std::size_t visited{};
    old->each([&visited](const std::string& key, const astra::Almanac::Value& value) {
        CHECK(key == "old" && *value == astra::Almanac::Buffer{1});
        ++visited;
    });
    CHECK(visited == 1 && old->version() == 1);

    // Lower baselines cannot replace; equal-version replay preserves the current root without another commit.
    auto lower = book.prepare(9);
    auto equal = book.prepare(10);
    CHECK(book.reset(std::move(lower)) == std::unexpected(astra::Almanac::Error::Version));
    CHECK(book.reset(std::move(equal)) == false);
    CHECK(book.view()->size() == 2);
    CHECK(book.apply(11, "new", astra::Almanac::Buffer{11}) == true);
    CHECK(book.replay(10)->changes.size() == 1);
    auto empty = book.prepare(12);
    CHECK(book.reset(std::move(empty)) == true);
    CHECK(book.view()->version() == 12 && book.view()->size() == 0);
}

/// Bounded history entry/byte retention with independent result lifetime; future cursors cannot bypass recovery.
void history() {

    astra::Almanac::Limits limits;
    limits.history = 2;
    astra::Almanac book(limits);
    initialize(book);
    CHECK(book.apply(1, "key", astra::Almanac::Buffer{1}) == true);
    CHECK(book.apply(2, "key", astra::Almanac::Buffer{2}) == true);
    const auto saved = book.replay(0);
    CHECK(book.apply(3, "key", astra::Almanac::Buffer{3}) == true);
    CHECK(book.replay(0) == std::unexpected(astra::Almanac::Error::History));
    CHECK(book.replay(4) == std::unexpected(astra::Almanac::Error::Version));
    CHECK(book.replay(1)->changes.size() == 2);
    CHECK(book.replay(1)->changes.front().version == 2);
    CHECK(book.replay(2)->changes.front().version == 3);
    CHECK(book.replay(3)->changes.empty());
    CHECK(saved->version == 2 && *saved->changes.front().value == astra::Almanac::Buffer{1});

    astra::Almanac::Limits budget;
    budget.backlog = sizeof(astra::Almanac::Change) + 4;
    astra::Almanac bounded(budget);
    initialize(bounded);
    CHECK(bounded.apply(1, "key", astra::Almanac::Buffer{1}) == true);
    CHECK(bounded.apply(2, "key", astra::Almanac::Buffer{2}) == true);
    CHECK(bounded.replay(0) == std::unexpected(astra::Almanac::Error::History));
    CHECK(bounded.replay(1)->changes.size() == 1);

    // A valid write may exceed history budget and evict old history plus itself; earlier returned history remains owned.
    const auto retained = bounded.replay(1);
    CHECK(bounded.apply(3, "key", astra::Almanac::Buffer(512 * 1024, 7)) == true);
    CHECK(bounded.find("key")->version == 3 && bounded.find("key")->value->size() == 512 * 1024);
    CHECK(bounded.replay(2) == std::unexpected(astra::Almanac::Error::History));
    CHECK(bounded.replay(3)->changes.empty());
    CHECK(retained->version == 2 && *retained->changes.front().value == astra::Almanac::Buffer{2});

    // Later small commits can restore retention but cannot bridge an evicted version with incomplete replay.
    CHECK(bounded.apply(4, "key", astra::Almanac::Buffer{4}) == true);
    CHECK(bounded.replay(2) == std::unexpected(astra::Almanac::Error::History));
    CHECK(bounded.replay(3)->version == 4 && bounded.replay(3)->changes.size() == 1);
    CHECK(bounded.replay(3)->changes.front().version == 4);
    CHECK(bounded.apply(5, "key", std::nullopt) == true);
    CHECK(bounded.view()->size() == 0);
    CHECK(bounded.replay(3) == std::unexpected(astra::Almanac::Error::History));
    CHECK(bounded.replay(4)->changes.size() == 1 && !bounded.replay(4)->changes.front().value);

    // The first write may already exceed history budget; empty deque is no exemption.
    astra::Almanac oversized(budget);
    initialize(oversized);
    CHECK(oversized.apply(1, "key", astra::Almanac::Buffer(512 * 1024, 8)) == true);
    CHECK(oversized.find("key")->value->size() == 512 * 1024);
    CHECK(oversized.replay(0) == std::unexpected(astra::Almanac::Error::History));
    CHECK(oversized.replay(1)->changes.empty());

    // Zero history still permits commits; old cursors require a full baseline.
    budget.history = 0;
    astra::Almanac zero(budget);
    initialize(zero);
    CHECK(zero.apply(1, "key", astra::Almanac::Buffer{}) == true);
    CHECK(zero.replay(0) == std::unexpected(astra::Almanac::Error::History));
    CHECK(zero.replay(1)->changes.empty());

    // Zero history bytes retain nothing, including metadata-only empty Set/missing Delete.
    budget.history = 1;
    budget.backlog = 0;
    astra::Almanac bytes(budget);
    initialize(bytes);
    CHECK(bytes.apply(1, "key", astra::Almanac::Buffer{}) == true);
    CHECK(bytes.find("key")->value && bytes.find("key")->value->empty());
    CHECK(bytes.replay(0) == std::unexpected(astra::Almanac::Error::History));
    CHECK(bytes.replay(1)->changes.empty());
    CHECK(bytes.apply(2, "missing", std::nullopt) == true);
    CHECK(bytes.view()->version() == 2 && bytes.view()->size() == 1);
    CHECK(bytes.replay(1) == std::unexpected(astra::Almanac::Error::History));
    CHECK(bytes.replay(2)->changes.empty());
}

/// Capacity failure preserves version; deletion releases current charge and baseline recovery obeys destination limits.
void capacity() {

    astra::Almanac::Limits limits;
    limits.records = 1;
    limits.bytes = 3;
    astra::Almanac book(limits);
    initialize(book);
    CHECK(book.apply(1, "a", astra::Almanac::Buffer{1, 2}) == true);
    CHECK(book.apply(2, "b", astra::Almanac::Buffer{}) == std::unexpected(astra::Almanac::Error::Capacity));
    CHECK(book.apply(2, "a", astra::Almanac::Buffer{1, 2, 3}) == std::unexpected(astra::Almanac::Error::Capacity));
    CHECK(book.view()->version() == 1 && book.find("a")->value->size() == 2);
    CHECK(book.apply(2, "a", astra::Almanac::Buffer{}) == true);
    CHECK(book.apply(3, "a", std::nullopt) == true);
    CHECK(book.apply(4, "b", astra::Almanac::Buffer{3, 4}) == true);

    // A larger source candidate cannot bypass the destination Almanac's capacity.
    astra::Almanac large;
    auto draft = large.prepare(5);
    CHECK(draft.set("long", {}));
    CHECK(book.reset(std::move(draft)) == std::unexpected(astra::Almanac::Error::Capacity));
    CHECK(book.view()->version() == 4);
    auto bounded = book.prepare(5);
    CHECK(bounded.set("a", {1, 2}));
    CHECK(bounded.set("b", {}) == std::unexpected(astra::Almanac::Error::Capacity));
    CHECK(book.reset(std::move(bounded)) == true);

    // Invalid records return input without advancing version.
    CHECK(book.apply(6, "", std::nullopt) == std::unexpected(astra::Almanac::Error::Input));
    CHECK(book.apply(6, std::string("a\0b", 3), std::nullopt) == std::unexpected(astra::Almanac::Error::Input));
    CHECK(book.apply(6, std::string(1025, 'x'), std::nullopt) == std::unexpected(astra::Almanac::Error::Input));
    CHECK(book.apply(6, "a", astra::Almanac::Buffer(1024 * 1024 + 1)) == std::unexpected(astra::Almanac::Error::Input));
    CHECK(book.view()->version() == 5);
}

/// Read completion survives owner destruction and callback exceptions without leaking a business lock.
void lifetime() {

    std::optional<astra::Almanac::View> saved;
    {
        astra::Almanac book;
        auto draft = book.prepare(99);
        CHECK(draft.set("alive", {9}));
        CHECK(book.reset(std::move(draft)) == true);
        saved = *book.view();

        bool interrupted{};
        try {
            saved->each([](const std::string&, const astra::Almanac::Value&) { throw std::runtime_error("reader stopped"); });
        } catch (const std::runtime_error&) {
            // Callback failure ends only traversal; subsequent writes still acquire and commit.
            interrupted = true;
        }
        CHECK(interrupted);
        CHECK(book.apply(100, "alive", astra::Almanac::Buffer{10}) == true);
        // Reader reentry into point lookup/write proves each holds no commit lock around user code.
        saved->each([&book](const std::string&, const astra::Almanac::Value&) {
            CHECK(book.find("alive")->version == 100);
            CHECK(book.apply(101, "alive", astra::Almanac::Buffer{11}) == true);
        });
    }
    saved->each([](const std::string& key, const astra::Almanac::Value& value) { CHECK(key == "alive" && *value == astra::Almanac::Buffer{9}); });
    CHECK(saved->version() == 99 && saved->size() == 1);
}

/// Concurrent capture/page reuse must keep version paired with content and synchronize read completion.
void concurrency() {

    astra::Almanac book;
    initialize(book);
    CHECK(book.apply(1, "key", astra::Almanac::Buffer{1}) == true);
    // Start coordination and result flag avoid throwing assertions through the reader thread entry.

    std::latch entered{1};
    std::atomic<bool> valid{true};
    std::jthread reader([&](std::stop_token stop) {
        entered.count_down();
        while (!stop.stop_requested()) {
            const auto view = book.view();
            if (!view || view->size() != 1) {
                valid = false;
                return;
            }
            view->each([&](const std::string& key, const astra::Almanac::Value& value) {
                if (key != "key" || value->size() != 1 || value->front() != static_cast<std::uint8_t>(view->version() % 256)) {
                    valid = false;
                }
            });
        }
    });
    entered.wait();
    // Versions 2..2000 encode their low byte in values so torn root/version pairs are observable.
    for (std::uint64_t version = 2; version <= 2000; ++version) {
        CHECK(book.apply(version, "key", astra::Almanac::Buffer{static_cast<std::uint8_t>(version % 256)}) == true);
    }
    reader.request_stop();
    reader.join();
    CHECK(valid.load());
}

/// Cross-leaf growth, deletion, and slot reuse preserve old bytes and Map/page-index agreement.
void pages() {

    astra::Almanac book;
    auto draft = book.prepare(10);
    for (unsigned index = 0; index < 150; ++index) {
        CHECK(draft.set(std::to_string(index), {1}));
    }
    CHECK(book.reset(std::move(draft)) == true);
    const auto old = book.view();

    std::uint64_t version = 10;
    for (unsigned index = 0; index < 150; ++index) {
        CHECK(book.apply(++version, std::to_string(index), std::nullopt) == true);
    }
    CHECK(book.view()->size() == 0);
    for (unsigned index = 0; index < 150; ++index) {
        CHECK(book.apply(++version, std::to_string(index), astra::Almanac::Buffer{2}) == true);
    }

    std::size_t visited{};
    std::size_t current{};
    old->each([&visited](const std::string&, const astra::Almanac::Value& value) {
        CHECK(*value == astra::Almanac::Buffer{1});
        ++visited;
    });
    book.view()->each([&book, &current](const std::string& key, const astra::Almanac::Value& value) {
        CHECK(*value == astra::Almanac::Buffer{2});
        CHECK(book.find(key)->value == value);
        ++current;
    });
    CHECK(visited == 150 && current == 150 && book.view()->version() == 310);

    // Seven-row pages resume by captured active-row rank despite holes or new-root slot reuse.
    std::size_t offset{};
    while (offset < old->size()) {
        const auto consumed = old->page(offset, 7, [&](const std::string& key, const astra::Almanac::Value& value) {
            CHECK(key == std::to_string(offset++) && *value == astra::Almanac::Buffer{1});
            return true;
        });
        CHECK(consumed > 0 && consumed <= 7);
    }
    CHECK(offset == 150 && old->bytes() == 490);
    CHECK(old->page(150, 7, [](const auto&, const auto&) { throw std::runtime_error("End page visited an item"); return true; }) == 0);
    CHECK(old->page(1, 7, [](const auto&, const auto&) { return false; }) == 0);
    CHECK(old->page(1, 0, [](const auto&, const auto&) { throw std::runtime_error("Zero page visited an item"); return true; }) == 0);
    bool rejected{}; // Out-of-range offset is invalid, not a completed empty page.
    try {
        static_cast<void>(old->page(151, 1, [](const auto&, const auto&) { return true; }));
    } catch (const std::out_of_range&) {
        rejected = true;
    }
    CHECK(rejected);
}

/// Concurrent readers see both batch values together. Old views remain fixed; duplicate keys and partial history are rejected.
void batches() {

    astra::Almanac book;
    initialize(book);
    const auto changes = [](std::uint8_t value) {
        std::vector<astra::Almanac::Change> result;
        const auto body = std::make_shared<const astra::Almanac::Buffer>(1, value);
        for (const auto* key : {"a", "b"}) {
            result.push_back({std::make_shared<const std::string>(key), body, 0});
        }
        return result;
    };
    CHECK(book.apply(1, changes(1), 1024 * 1024));
    const auto old = book.view();
    std::atomic_bool valid{true};
    std::latch observed{1}; // Require a completed read before writes so lack of reader scheduling cannot give an empty pass.
    std::jthread reader([&](std::stop_token stop) {
        bool first = true;
        while (!stop.stop_requested()) {
            const auto view = book.view();
            std::size_t count{};
            view->each([&](const auto&, const auto& value) { valid.store(valid.load() && value->at(0) == view->version()); ++count; });
            if (count != 2) {
                valid.store(false);
            }
            if (first) {
                first = false;
                observed.count_down();
            }
        }
    });
    observed.wait();
    for (std::uint64_t version = 2; version <= 64; ++version) {
        CHECK(book.apply(version, changes(static_cast<std::uint8_t>(version)), 1024 * 1024));
    }
    reader.request_stop();
    reader.join();
    CHECK(valid.load());
    old->each([](const auto&, const auto& value) { CHECK(value->at(0) == 1); });
    auto duplicate = changes(65); // A second same-key mutation is not a script; reject the whole batch.
    duplicate[1].key = duplicate[0].key;
    CHECK(!book.apply(65, std::move(duplicate), 1024 * 1024));
    CHECK(book.view()->version() == 64);
    CHECK(book.replay(63)->changes.size() == 2);

    astra::Almanac::Limits limits; // History budget cannot retain only a transaction's final item.
    limits.history = 1;
    astra::Almanac small(limits);
    initialize(small);
    CHECK(small.apply(1, changes(1), 1024 * 1024));
    CHECK(small.replay(0).error() == astra::Almanac::Error::History);
    CHECK(small.apply(2, "a", astra::Almanac::Buffer{2}));
    CHECK(small.replay(1)->changes.size() == 1);
}
} // namespace

int main() {
    try {
        batches();
        baseline();
        versions();
        snapshots();
        history();
        capacity();
        lifetime();
        concurrency();
        pages();
        std::cout << "Almanac state tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
