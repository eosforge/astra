// Verify native dynamic-domain operations independently of network transport.
#include "agenda.hpp"
#include "catalog.hpp"
#include "check.hpp"
#include "ephemeris.hpp"
#include "pages.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using namespace std::chrono_literals;
using astra::Agenda;
using astra::Catalog;
using astra::Clock;
using astra::Ephemeris;

/// Deterministic Unix nanoseconds, initially one second; no wall clock or Pulsar.
Clock::Reading clock(std::chrono::nanoseconds time = 1s) {
    return Clock::Reading{.time = Clock::Time(time), .ready = true, .synchronized = false};
}

/// Immutable bytes; empty text retains a nonnull Value, distinct from watermark.
Catalog::Value bytes(std::string_view value) {
    return std::make_shared<const Catalog::Buffer>(value.begin(), value.end());
}

/// Checks exact expected error categories, never exception/message text to infer commit effect.
template <typename T, typename E>
void error(const std::expected<T, E>& result, E expected) {
    CHECK(!result && result.error() == expected);
}

/// Native registration has fixed Attr, dynamic Data, and one deadline, with independent orders.
void ephemeris() {

    const auto attr = bytes("fixed");   // Immutable Attr reference retained by later candidates.
    const auto data = bytes("initial"); // Original Data remains unchanged by unaccepted candidates.
    auto initial = Ephemeris::create(attr, data, 1000, clock());
    CHECK(initial && initial->deadline == Clock::Time(2s) && initial->update == 0 && initial->renewal == 0);
    CHECK(initial->attr == attr && initial->data == data && initial->ttl == 1000);

    const auto changed = Ephemeris::update(*initial, bytes("next"), 17, clock(1200ms));
    CHECK(changed && changed->changed && changed->visible);
    CHECK(changed->record.deadline == Clock::Time(2200ms) && changed->record.attr == attr && changed->record.update == 17 && changed->record.renewal == 0);
    CHECK(initial->data == data && initial->update == 0); // Returning a candidate does not commit.
    const auto repeated = Ephemeris::update(changed->record, bytes("next"), 17, clock(1300ms));
    CHECK(repeated && !repeated->changed && !repeated->visible && repeated->record.deadline == changed->record.deadline);
    error(Ephemeris::update(changed->record, bytes("old"), 16, clock()), Ephemeris::Error::Obsolete);
    error(Ephemeris::update(changed->record, bytes("different"), 17, clock()), Ephemeris::Error::Conflict);
    const auto same = Ephemeris::update(changed->record, bytes("next"), 18, clock());
    CHECK(same && same->changed && !same->visible && same->record.data == changed->record.data);

    const auto renewed = Ephemeris::renew(changed->record, 4, clock(1500ms));
    CHECK(renewed && renewed->changed && !renewed->visible && renewed->record.deadline == Clock::Time(2500ms));
    CHECK(renewed->record.update == 17 && renewed->record.renewal == 4 && renewed->record.ttl == 1000);
    const auto retry = Ephemeris::renew(renewed->record, 4, clock(2000ms));
    CHECK(retry && !retry->changed && retry->record.deadline == renewed->record.deadline);
    error(Ephemeris::renew(renewed->record, 3, clock()), Ephemeris::Error::Obsolete);
    error(Ephemeris::renew(renewed->record, 4, clock(2500ms)), Ephemeris::Error::Ended);
    error(Ephemeris::update(renewed->record, bytes("next"), 17, clock(2500ms)), Ephemeris::Error::Ended);

    const auto empty = Ephemeris::create(bytes(""), bytes(""), 600000, clock());
    CHECK(empty && empty->attr && empty->data && empty->attr->empty() && empty->data->empty());
    for (const auto ttl : {0U, 999U, 600001U, UINT32_MAX}) {
        error(Ephemeris::create(attr, data, ttl, clock()), Ephemeris::Error::Input);
    }
    error(Ephemeris::create(nullptr, data, 1000, clock()), Ephemeris::Error::Input);
    error(Ephemeris::update(*initial, data, 0, clock()), Ephemeris::Error::Input);
    error(Ephemeris::renew(*initial, 0, clock()), Ephemeris::Error::Input);
    error(Ephemeris::create(attr, data, 1000, Clock::Reading{}), Ephemeris::Error::Clock);
    error(Ephemeris::renew(*initial, 1, Clock::Reading{}), Ephemeris::Error::Clock);
    error(Ephemeris::create(attr, data, 1000, clock(-1ns)), Ephemeris::Error::Input);

    auto maximum = *initial; // Large orders confirm without +1 overflow arithmetic.
    maximum.update = UINT64_MAX;
    maximum.renewal = UINT64_MAX;
    CHECK(Ephemeris::update(maximum, data, UINT64_MAX, clock()));
    CHECK(Ephemeris::renew(maximum, UINT64_MAX, clock()));
    error(Ephemeris::update(maximum, data, UINT64_MAX - 1, clock()), Ephemeris::Error::Obsolete);
    const auto edge = clock(std::chrono::nanoseconds(INT64_MAX) - 500ms);
    error(Ephemeris::create(attr, data, 1000, edge), Ephemeris::Error::Exhausted);
    maximum.deadline = Clock::Time(std::chrono::nanoseconds(INT64_MAX));
    CHECK(Ephemeris::renew(maximum, UINT64_MAX, edge)); // Same-order retry performs no unnecessary deadline addition that could overflow.
    maximum.renewal = UINT64_MAX - 1;
    error(Ephemeris::renew(maximum, UINT64_MAX, edge), Ephemeris::Error::Exhausted);
}

/// Raw UUID version/variant validation without formatting; generation occurs only at creation.
void uuid() {

    const std::string valid("\x00\x11\x22\x33\x44\x55\x46\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff", 16);
    CHECK(Ephemeris::valid(valid));
    const std::vector<std::string> invalid({"", "00112233445546778899aabbccddeeff", std::string("\x00\x11\x22\x33\x44\x55\x46\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff", 15), std::string("\x00\x11\x22\x33\x44\x55\x16\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff", 16), std::string("\x00\x11\x22\x33\x44\x55\x46\x77\x78\x99\xaa\xbb\xcc\xdd\xee\xff", 16), std::string("\x00\x11\x22\x33\x44\x55\x46\x77\xc8\x99\xaa\xbb\xcc\xdd\xee\xff", 16)});
    for (const auto& text : invalid) {
        CHECK(!Ephemeris::valid(text));
    }
    std::set<std::string> generated; // Bounded samples check shape/collision paths, without claiming statistical randomness verification.
    for (unsigned sample = 0; sample != 64; ++sample) {
        auto value = Ephemeris::uuid();
        CHECK(Ephemeris::valid(value));
        CHECK(generated.emplace(std::move(value)).second);
    }
}

/// Application versions and source deadlines are independent; remote longer deadlines cannot extend a new local source.
void catalog() {

    const auto value = bytes("one");
    const auto initial = Catalog::publish(nullptr, nullptr, value, 1, 1000, clock());
    CHECK(initial && initial->deadline == Clock::Time(2s));
    const auto first = Catalog::merge(nullptr, *initial, Clock::Time(1s));
    CHECK(first && first->visible && first->record.version == 1);

    const Catalog::Record distant{1, value, Clock::Time(100s)};
    const auto own = Catalog::publish(nullptr, &distant, bytes("one"), 1, 1000, clock());
    CHECK(own && own->value == value && own->deadline == Clock::Time(2s));
    error(Catalog::renew(nullptr, &distant, 1, 1000, clock()), Catalog::Error::Ended);
    const auto joined = Catalog::merge(&distant, *own, Clock::Time(1s));
    CHECK(joined && !joined->visible && joined->record.deadline == distant.deadline);
    const auto shorter = Catalog::renew(&distant, &distant, 1, 1000, clock());
    CHECK(shorter && shorter->deadline == distant.deadline); // Same-source/same-version requests cannot shorten confirmed deadlines.

    const Catalog::Record floor{8, nullptr, std::nullopt}; // Higher watermarks still prevent version fallback.
    error(Catalog::publish(&*initial, &floor, value, 1, 1000, clock()), Catalog::Error::Version);
    error(Catalog::renew(&*initial, &floor, 1, 1000, clock()), Catalog::Error::Version);
    const auto hidden = Catalog::merge(&distant, floor, Clock::Time(1s));
    CHECK(hidden && hidden->visible && hidden->record.version == 8 && !hidden->record.value);
    const auto old = Catalog::merge(&hidden->record, distant, Clock::Time(1s));
    CHECK(old && !old->visible && old->record.version == 8 && !old->record.value);
    const auto recovered = Catalog::publish(&floor, &floor, bytes("eight"), 8, 1000, clock());
    CHECK(recovered && recovered->value && recovered->deadline == Clock::Time(2s));
    const auto visible = Catalog::merge(&floor, *recovered, Clock::Time(1s));
    CHECK(visible && visible->visible && visible->record.version == 8);

    const Catalog::Record equal{1, nullptr, std::nullopt}; // Equal-version watermarks/source expiration preserve valid bodies elsewhere.
    const auto kept = Catalog::merge(&distant, equal, Clock::Time(2s));
    CHECK(kept && !kept->visible && kept->record.value == value && kept->record.deadline == distant.deadline);
    const auto expired = Catalog::merge(&*initial, equal, Clock::Time(2s));
    CHECK(expired && expired->visible && !expired->record.value && expired->record.version == 1);
    error(Catalog::renew(&*initial, &distant, 1, 1000, clock(2s)), Catalog::Error::Ended);
    const auto released = Catalog::expire(*initial, Clock::Time(2s));
    CHECK(released.version == 1 && !released.value && !released.deadline);
    CHECK(Catalog::expire(distant, Clock::Time(2s)).deadline == distant.deadline);

    error(Catalog::publish(&distant, &distant, bytes("other"), 1, 1000, clock()), Catalog::Error::Conflict);
    const Catalog::Record conflict{1, bytes("other"), Clock::Time(10s)};
    error(Catalog::merge(&distant, conflict, Clock::Time(2s)), Catalog::Error::Conflict);
    const auto jump = Catalog::publish(&distant, &distant, value, 99, 1000, clock());
    CHECK(jump && jump->deadline == Clock::Time(2s)); // Higher versions do not inherit the old 100-second deadline.
    const auto newer = Catalog::merge(&distant, *jump, Clock::Time(1s));
    CHECK(newer && newer->visible); // Content version itself is visible, even when bytes are unchanged.
    const auto timed = Catalog::merge(&distant, *jump, Clock::Time(2s));
    CHECK(timed && timed->visible && !timed->record.value && timed->record.version == 99);

    for (const auto ttl : {0U, 999U, 600001U, UINT32_MAX}) {
        error(Catalog::publish(nullptr, nullptr, value, 1, ttl, clock()), Catalog::Error::Input);
        error(Catalog::renew(&distant, &distant, 1, ttl, clock()), Catalog::Error::Input);
    }
    error(Catalog::publish(nullptr, nullptr, nullptr, 1, 1000, clock()), Catalog::Error::Input);
    error(Catalog::publish(nullptr, nullptr, value, 0, 1000, clock()), Catalog::Error::Input);
    error(Catalog::publish(nullptr, nullptr, value, 1, 1000, Clock::Reading{}), Catalog::Error::Clock);
    error(Catalog::renew(&distant, &distant, 1, 1000, Clock::Reading{}), Catalog::Error::Clock);
    error(Catalog::merge(nullptr, {}, Clock::Time(1s)), Catalog::Error::Input);
    error(Catalog::merge(nullptr, Catalog::Record{1, value, std::nullopt}, Clock::Time(1s)), Catalog::Error::Input);
    const auto top = Catalog::publish(nullptr, nullptr, bytes(""), UINT64_MAX, 600000, clock());
    CHECK(top && top->value && top->value->empty());
    CHECK(Catalog::renew(&*top, &*top, UINT64_MAX, 1000, clock()));
}

/// Source arrival order preserves highest version and longest equal-version deadline without rescanning all sources for lower versions.
void convergence() {

    const auto value = bytes("shared");
    std::array<Catalog::Record, 4> facts{{{2, value, Clock::Time(20s)}, {7, value, Clock::Time(5s)}, {7, value, Clock::Time(10s)}, {7, nullptr, std::nullopt}}};
    std::array<unsigned, 4> order{0, 1, 2, 3}; // All 24 permutations include watermark arrival before/after bodies.
    do {
        std::optional<Catalog::Record> current;
        for (const auto item : order) {
            const auto next = Catalog::merge(current ? &*current : nullptr, facts[item], Clock::Time(1s));
            CHECK(next);
            current = next->record;
        }
        CHECK(current && current->version == 7 && current->value == value && current->deadline == Clock::Time(10s));
    } while (std::ranges::next_permutation(order).found);
}

/// Native pages keep Attr/Data separate; renewal COW preserves old snapshot deadlines/content.
void pages() {

    astra::Pages<Ephemeris::Record> registrations; // Single-threaded fixture; does not exercise cross-thread read-completion synchronization.
    const auto key = std::make_shared<const std::string>("00112233-4455-4677-8899-aabbccddeeff");
    const auto initial = Ephemeris::create(bytes("attr"), bytes("data"), 1000, clock());
    CHECK(initial);
    registrations.prepare(0);
    registrations.set(0, key, *initial);
    const auto frozen = registrations.capture();
    const auto renewed = Ephemeris::renew(*registrations.at(0), 1, clock(1500ms));
    CHECK(renewed);
    registrations.prepare(0);
    registrations.set(0, nullptr, renewed->record);
    CHECK(registrations.at(0)->deadline == Clock::Time(2500ms));
    CHECK(registrations.at(1) == nullptr && registrations.at(UINT64_MAX) == nullptr);
    frozen.each([&](const std::string& name, const Ephemeris::Record& record) {
        CHECK(name == *key && record.deadline == Clock::Time(2s) && record.renewal == 0);
        CHECK(record.attr == initial->attr && record.data == initial->data);
    });

    astra::Pages<Catalog::Record> catalog; // Watermark has no Value but remains a valid native record.
    catalog.prepare(0);
    catalog.set(0, std::make_shared<const std::string>("key"), {5, nullptr, std::nullopt});
    const auto watermarks = catalog.capture();
    CHECK(watermarks.size() == 1 && catalog.at(0)->version == 5);
    catalog.prepare(0);
    catalog.erase(0);
    CHECK(catalog.at(0) == nullptr && catalog.capture().size() == 0 && watermarks.size() == 1);
    watermarks.each([](const std::string& name, const Catalog::Record& record) { CHECK(name == "key" && record.version == 5 && !record.value); });
}

/// Compare a retained native page view with an independent ordered slot map.
void verify(const astra::Pages<Catalog::Record>::View& view, const std::map<std::uint64_t, Catalog::Record>& model) {

    // The map owns the expected records supplied to set, without reading page internals.
    CHECK(view.size() == model.size());
    auto current = model.begin();
    view.each([&current, &model](const std::string& name, const Catalog::Record& record) {
        CHECK(current != model.end());
        CHECK(name == std::to_string(current->first));
        CHECK(record.version == current->second.version && record.value == current->second.value && record.deadline == current->second.deadline);
        ++current;
    });
    CHECK(current == model.end());

    // Each offset, page limit and acceptance budget has an independently calculated prefix.
    for (std::size_t offset = 0; offset <= model.size(); ++offset) {
        for (const auto maximum : {std::size_t{0}, std::size_t{1}, std::size_t{2}, std::size_t{64}, model.size() + 1}) {
            for (const auto budget : {std::size_t{0}, std::size_t{1}, maximum}) {
                auto expected = model.begin();
                std::advance(expected, static_cast<std::ptrdiff_t>(offset));
                std::size_t calls{};    // Callback attempts include the first rejected record.
                std::size_t accepted{}; // Only true callback results advance the next offset.
                const auto consumed = view.page(offset, maximum, [&expected, &model, &calls, &accepted, budget](const std::string& name, const Catalog::Record& record) {
                    CHECK(expected != model.end());
                    CHECK(name == std::to_string(expected->first));
                    CHECK(record.version == expected->second.version && record.value == expected->second.value && record.deadline == expected->second.deadline);
                    ++calls;
                    if (accepted == budget) {
                        return false;
                    }
                    ++accepted;
                    ++expected;
                    return true;
                });
                const auto available = std::min(maximum, model.size() - offset);
                const auto prefix = std::min(available, budget);
                CHECK(consumed == prefix && accepted == prefix);
                CHECK(calls == prefix + static_cast<std::size_t>(prefix < available));
            }
        }
    }

    // Invalid offsets fail before entering a reader, including a zero-size page request.
    for (const auto maximum : {std::size_t{0}, std::size_t{1}}) {
        bool rejected{};
        try {
            static_cast<void>(view.page(model.size() + 1, maximum, [](const auto&, const auto&) {
                CHECK(false);
                return true;
            }));
        } catch (const std::out_of_range&) {
            rejected = true;
        }
        CHECK(rejected && view.size() == model.size());
    }
}

/// Exercise every representable tree level, retained roots and reader failures.
void sparse() {

    astra::Pages<Catalog::Record> index;            // All mutation and reader completion run on this thread.
    std::map<std::uint64_t, Catalog::Record> model; // Slot ordering is independent of the radix tree.
    const auto empty = index.capture();
    verify(empty, model);
    std::vector<std::uint64_t> slots{0, 1, 63}; // Leaf boundaries plus both sides of every deeper boundary.
    for (unsigned shift = 6; shift <= 62; shift += 4) {
        const auto boundary = std::uint64_t{1} << shift;
        slots.push_back(boundary - 1);
        slots.push_back(boundary);
    }
    slots.push_back(std::uint64_t{1} << 63);
    slots.push_back(UINT64_MAX - 1); // The maximum value remains the next-slot exhaustion sentinel.
    std::ranges::sort(slots);
    slots.erase(std::unique(slots.begin(), slots.end()), slots.end());
    std::uint64_t version{}; // Each caller-provided value has a distinct positive version.
    for (const auto slot : slots) {
        ++version;
        const Catalog::Record record{version, version % 2 ? bytes(std::to_string(version)) : nullptr, version % 2 ? std::optional(Clock::Time(2s)) : std::nullopt};
        index.prepare(slot);
        CHECK(index.at(slot) == nullptr && index.capture().size() == model.size());
        index.set(slot, std::make_shared<const std::string>(std::to_string(slot)), record);
        model.emplace(slot, record);
        CHECK(index.at(slot)->version == version && index.capture().size() == model.size());
    }
    const auto frozen = index.capture();
    const auto original = model;
    verify(frozen, original);
    CHECK(index.next() == 2 && index.at(UINT64_MAX) == nullptr);

    // A paused or throwing reader cannot consume or alter the captured root.
    for (const auto offset : {std::size_t{0}, model.size() / 2, model.size() - 1}) {
        std::size_t calls{};
        bool failed{};
        try {
            static_cast<void>(frozen.page(offset, 2, [&calls](const auto&, const auto&) -> bool {
                ++calls;
                throw std::range_error("controlled reader failure");
            }));
        } catch (const std::range_error&) {
            failed = true;
        }
        CHECK(failed && calls == 1);
    }
    bool failed{};
    try {
        frozen.each([](const auto&, const auto&) { throw std::range_error("controlled traversal failure"); });
    } catch (const std::range_error&) {
        failed = true;
    }
    CHECK(failed);
    verify(frozen, original);

    // Overwriting preserves the key and old snapshot; deleting every slot restores an empty tree.
    for (const auto slot : slots) {
        const Catalog::Record record{++version, bytes("replacement"), Clock::Time(3s)};
        index.prepare(slot);
        index.set(slot, nullptr, record);
        model[slot] = record;
        CHECK(index.find(slot).first && **index.find(slot).first == std::to_string(slot));
    }
    verify(index.capture(), model);
    verify(frozen, original);
    for (auto current = slots.rbegin(); current != slots.rend(); ++current) {
        index.prepare(*current);
        index.erase(*current);
        model.erase(*current);
        CHECK(index.at(*current) == nullptr && index.capture().size() == model.size());
    }
    verify(index.capture(), model);
    verify(frozen, original);
    CHECK(index.next() == 0);

    // Dense occupancy must skip a full leaf, then reuse its smallest hole.
    for (std::uint64_t slot = 0; slot != 65; ++slot) {
        CHECK(index.next() == slot);
        const Catalog::Record record{slot + 1, nullptr, std::nullopt};
        index.prepare(slot);
        index.set(slot, std::make_shared<const std::string>(std::to_string(slot)), record);
        model.emplace(slot, record);
    }
    CHECK(index.next() == 65);
    for (const auto slot : {std::uint64_t{0}, std::uint64_t{63}, std::uint64_t{64}}) {
        index.prepare(slot);
        index.erase(slot);
        model.erase(slot);
    }
    CHECK(index.next() == 0);
    verify(index.capture(), model);
    const auto retained = index.capture();
    index = {};
    CHECK(index.next() == 0 && index.capture().size() == 0);
    verify(retained, model);
    std::cout << "ASTRA-PAGES-SPARSE {\"slots\":" << slots.size() << ",\"reader_failures\":4,\"dense_slots\":65}\n";
}

/// Enumerate every four-action history over writes and erases at two distant slots.
void histories() {

    // Six choices are full/tombstone writes at either slot and conditional erases of either slot.
    constexpr std::array<std::uint64_t, 2> slots{0, UINT64_MAX - 1};
    constexpr unsigned maximum = 6 * 6 * 6 * 6;
    unsigned histories{};
    unsigned writes{};
    unsigned erases{};
    unsigned absent{};
    for (unsigned history = 0; history != maximum; ++history) {
        astra::Pages<Catalog::Record> index;
        std::map<std::uint64_t, Catalog::Record> model;
        auto choices = history; // Base-six digits independently select the complete finite history.
        for (unsigned step = 0; step != 4; ++step) {
            const auto frozen = index.capture();
            const auto before = model;
            const auto choice = choices % 6;
            choices /= 6;
            const auto slot = slots[choice % 2];
            if (choice < 4) {
                const auto value = choice < 2 ? bytes(std::to_string(step)) : nullptr;
                const Catalog::Record record{step + 1, value, value ? std::optional(Clock::Time(4s)) : std::nullopt};
                const auto added = !model.contains(slot);
                index.prepare(slot);
                index.set(slot, added ? std::make_shared<const std::string>(std::to_string(slot)) : nullptr, record);
                model[slot] = record;
                ++writes;
            } else if (model.contains(slot)) {
                index.prepare(slot);
                index.erase(slot);
                model.erase(slot);
                ++erases;
            } else {
                CHECK(index.at(slot) == nullptr);
                ++absent;
            }
            std::uint64_t next{}; // Linear reference search, without page capacities or tree geometry.
            while (model.contains(next)) {
                ++next;
            }
            CHECK(index.next() == next);
            for (const auto address : slots) {
                const auto* actual = index.at(address);
                const auto expected = model.find(address);
                CHECK((actual != nullptr) == (expected != model.end()));
                if (actual) {
                    CHECK(actual->version == expected->second.version && actual->value == expected->second.value && actual->deadline == expected->second.deadline);
                }
            }
            verify(index.capture(), model);
            verify(frozen, before);
        }
        ++histories;
    }
    CHECK(histories == 1296 && writes == 3456 && erases > 0 && absent > 0 && writes + erases + absent == histories * 4);
    std::cout << "ASTRA-PAGES-HISTORIES {\"histories\":" << histories << ",\"writes\":" << writes << ",\"erases\":" << erases << ",\"absent\":" << absent << "}\n";
}

/// Scheduler stores only group boundaries, without second per-record deadlines; fixture advances time explicitly without sleeps.
void agenda() {

    Agenda wheel(Clock::Time(1s));
    CHECK(wheel.next() == Clock::Time(1010ms));
    Agenda phase(Clock::Time(1003ms)); // Independent source phases preserve the earliest boundary rather than truncating to aligned ten-millisecond ticks.
    CHECK(phase.next() == Clock::Time(1013ms));
    Agenda limit(Clock::Time::max() - 1ms); // Saturate sub-tick remaining range without signed overflow.
    CHECK(limit.next() == Clock::Time::max());
    Agenda::Node node; // Stable embedded hooks scheduled by the real Agenda.
    unsigned fired{};  // Counts actual expiration callbacks, not empty ticks.
    wheel.set(node, Clock::Time(1015ms));
    wheel.advance(Clock::Time(1019ms), [&](auto*, auto) { ++fired; });
    CHECK(fired == 0 && wheel.time() == Clock::Time(1010ms));
    wheel.advance(Clock::Time(1020ms), [&](auto*, auto boundary) { CHECK(boundary == Clock::Time(1020ms)); ++fired; });
    CHECK(fired == 1 && !node.scheduled());

    wheel.set(node, Clock::Time(1030ms));
    wheel.advance(Clock::Time(1040ms), [&](auto* current, auto boundary) {
        ++fired;
        CHECK(boundary == Clock::Time(1030ms) || boundary == Clock::Time(1040ms));
        if (boundary == Clock::Time(1030ms)) {
            wheel.set(*current, Clock::Time(1040ms)); // Callback rescheduling uses the current tick, avoiding an extra-tick delay.
        }
    });
    CHECK(fired == 3 && !node.scheduled());

    wheel.set(node, Clock::Time(1050ms));
    bool failed{};
    try {
        wheel.advance(Clock::Time(1060ms), [](auto*, auto) { throw std::bad_alloc{}; });
    } catch (const std::bad_alloc&) {
        failed = true;
    }
    CHECK(failed && node.scheduled() && wheel.time() == Clock::Time(1050ms) && wheel.next() == Clock::Time(1060ms));
    wheel.advance(Clock::Time(1060ms), [&](auto*, auto boundary) { CHECK(boundary == Clock::Time(1060ms)); ++fired; });
    CHECK(fired == 4 && !node.scheduled());
    wheel.advance(Clock::Time(3601s + 3ms), [](auto*, auto) { CHECK(false); });
    CHECK(wheel.time() == Clock::Time(3601s)); // Full one-hour catch-up without truncation at 1024 ticks.
    wheel.set(node, Clock::Time(3602s));
    wheel.advance(Clock::Time(3602s), [&](auto*, auto boundary) { CHECK(boundary == Clock::Time(3602s)); ++fired; });
    CHECK(fired == 5 && !node.scheduled());

    wheel.set(node, Clock::Time(3603s));
    Agenda::erase(node);
    wheel.advance(Clock::Time(3603s), [](auto*, auto) { CHECK(false); });
    bool reversed{};
    try {
        wheel.advance(Clock::Time(3602s), [](auto*, auto) {});
    } catch (const std::invalid_argument&) {
        reversed = true;
    }
    CHECK(reversed && wheel.time() == Clock::Time(3603s));
}
} // namespace

int main() {

    try {
        ephemeris();
        uuid();
        catalog();
        convergence();
        pages();
        sparse();
        histories();
        agenda();
        std::cout << "native rules: ok\n";
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
