// Verify retained authoritative Almanac views and history delivery.
#include "check.hpp"
#include "library.hpp"

#include <atomic>
#include <iostream>
#include <thread>

namespace {
/// Installs complete Scope state; nonzero version is required for its single value.
void install(astra::Library& library, const astra::Scope& scope, std::uint64_t version, astra::Almanac::Buffer value) {

    auto draft = library.prepare(scope, version); // Private candidate remains invisible until set/reset complete.
    CHECK(draft);
    if (version != 0) {
        CHECK(draft->set("key", std::move(value)));
    }
    CHECK(library.reset(std::move(*draft)) == true);
}

/// UTF-8 exact two-level addresses: slash is ordinary data and __ is reserved only at entry boundaries.
void addresses() {

    CHECK((astra::Scope{"カナ", "サナ"}.valid()));
    CHECK((astra::Scope{"__auth", "comet"}.internal()));
    for (const auto value : {"", "\xc0\x80", "\xed\xa0\x80", "\xf4\x90\x80\x80", "\xe4\xb8", "\x80"}) {
        CHECK(!astra::Scope::text(value, 128));
    }
    CHECK(!astra::Scope::text(std::string_view("a\0b", 3), 128));
    CHECK(astra::Scope::text("\xf0\x9f\x8c\x9f", 4));

    astra::Library library; // Addresses with identical concatenated text remain distinct Sector/Spectrum pairs.
    const astra::Scope a{"a/b", "c"}, b{"a", "b/c"};
    install(library, a, 1, {1});
    install(library, b, 1, {2});
    CHECK(library.find(a)->find("key")->value->front() == 1);
    CHECK(library.find(b)->find("key")->value->front() == 2);
    CHECK(library.positions().size() == 2);
}

/// Incomplete candidates consume no route. Content/history have global limits; history exhaustion cannot reject valid authoritative data.
void budgets() {

    astra::Library::Limits limits; // Small deterministic limits instead of system memory pressure.
    limits.scopes = 2;
    limits.bytes = 8;
    limits.history = 0;
    limits.scope.bytes = 8;
    astra::Library library(limits);
    const astra::Scope a{"a", "s"}, b{"b", "s"};
    {
        auto abandoned = library.prepare(a, 4); // Scope exit simulates disconnection without leaving a fake empty Scope.
        CHECK(abandoned && abandoned->set("key", {1}));
    }
    CHECK(!library.find(a) && library.positions().empty());
    install(library, a, 1, {1});
    install(library, b, 1, {2});
    CHECK(library.apply(a, 2, "key", astra::Almanac::Buffer{1, 2}) == std::unexpected(astra::Almanac::Error::Capacity));
    CHECK(library.find(a)->usage().version == 1);
    CHECK(library.apply(a, 2, "key", std::nullopt) == true);
    CHECK(library.apply(b, 2, "key", astra::Almanac::Buffer{2, 3, 4}) == true);
    CHECK(library.find(b)->replay(1) == std::unexpected(astra::Almanac::Error::History));
    CHECK(!library.prepare({"c", "s"}, 0));
    CHECK(library.positions().size() == 2); // Empty groups retain versions and deployment slots.
}

/// Old views survive overwrite; independent traversal holds neither routing nor installation lock.
void readers() {

    astra::Library library;
    const astra::Scope scope{"a", "s"};
    install(library, scope, 1, {1});
    const auto original = library.find(scope)->view();
    CHECK(original);
    std::atomic_bool done{}; // Writer completion signals only the fixture reader, not business synchronization.
    std::jthread reader([&] {
        while (!done.load(std::memory_order_acquire)) {
            const auto book = library.find(scope);
            CHECK(book && book->find("key")->value->size() == 1);
        }
    });
    for (std::uint64_t version = 2; version <= 100; ++version) {
        CHECK(library.apply(scope, version, "key", astra::Almanac::Buffer{static_cast<std::uint8_t>(version)}) == true);
    }
    done.store(true, std::memory_order_release);
    reader.join();
    original->each([](const auto& key, const auto& value) { CHECK(key == "key" && value->front() == 1); });
    CHECK(library.positions().front().version == 100);
}

/// Actual commits notify immutable values even with zero history; replay/failure never notify twice.
void notifications() {

    using astra::Almanac;
    std::vector<Almanac::Change> events; // Retained notification ownership proves later overwrite cannot mutate earlier values.
    events.reserve(8);                   // Noexcept callback uses preallocated bounded event storage.
    astra::Library::Limits limits;
    limits.scope.history = 0;
    astra::Library library(limits, [&](const astra::Scope& scope, const Almanac::Change& change) noexcept {
        if (scope.sector != "routes" || scope.spectrum != "main") {
            std::terminate();
        }
        events.push_back(change);
    });
    auto draft = library.prepare({"routes", "main"}, 1);
    CHECK(draft && draft->set("key", {1}));
    CHECK(library.reset(std::move(*draft)));
    CHECK(events.size() == 1 && !events[0].key && events[0].version == 1);
    CHECK(library.apply({"routes", "main"}, 2, "key", Almanac::Buffer{2}));
    CHECK(events.size() == 2 && *events[1].key == "key" && *events[1].value == Almanac::Buffer{2});
    CHECK(!*library.apply({"routes", "main"}, 2, "key", Almanac::Buffer{2}));
    CHECK(!library.apply({"routes", "main"}, 4, "key", Almanac::Buffer{4}));
    CHECK(events.size() == 2);
    CHECK(library.apply({"routes", "main"}, 3, "key", std::nullopt));
    CHECK(events.size() == 3 && !events[2].value && *events[1].value == Almanac::Buffer{2});
    CHECK(!library.find({"routes", "main"})->replay(1));
}
} // namespace

int main() {
    addresses();
    budgets();
    readers();
    notifications();
    std::cout << "Almanac library checks passed\n";
}
