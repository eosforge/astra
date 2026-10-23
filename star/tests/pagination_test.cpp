// Verify native delta compaction, frozen atomic snapshots, and page rollback against independent event expectations.
#include "catalog_edition.hpp"
#include "check.hpp"
#include "ephemeris_edition.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

namespace {
// Record effective finite histories and permutations separately from successful assertions.
struct Counts {
    /// Valid three-operation histories with an existing initial record.
    std::uint64_t histories{};
    /// All six-event arrangements, without random sampling.
    std::uint64_t permutations{};
    /// Complete whole-scope and exact-target observations.
    std::uint64_t editions{};
};

// Keep arbitrary immutable bytes distinct from a missing record.
astra::Catalog::Value buffer(std::size_t size, std::uint8_t value) {
    return std::make_shared<const astra::Catalog::Buffer>(size, value);
}

// Exercise both real domain encoders without exposing their private implementation types.
template <typename Domain>
class Fixture {
    using Projection = typename Domain::State::Projection; // Native frozen event and point types.
    using Event = typename Projection::Event;
    using Content = typename Domain::State::Content;
    using Edition = typename Domain::Edition;

public:
    // Use fixed valid keys rather than entropy or allocator-dependent identity.
    static std::string key(unsigned index) {
        if constexpr (std::is_same_v<Domain, astra::Catalog>) {
            return std::string(1, static_cast<char>('a' + index));
        } else {
            std::string result(16, '\0'); // RFC version/variant bytes are literal test inputs.
            result[0] = static_cast<char>(index);
            result[6] = '\x40';
            result[8] = '\x80';
            return result;
        }
    }

    // Build a native immutable public record from independent literal payloads.
    static Content content(std::uint64_t version, std::size_t size = 1) {
        if constexpr (std::is_same_v<Domain, astra::Catalog>) {
            return {.version = version, .value = buffer(size, static_cast<std::uint8_t>(version))};
        } else {
            return {.attr = buffer(1, 'A'), .data = buffer(size, static_cast<std::uint8_t>(version))};
        }
    }

    // Generate an ordinary committed event; full/data/erase are the only bounded actions.
    static Event event(unsigned index, std::uint64_t version, unsigned action) {
        auto name = std::make_shared<const typename Domain::State::Source::Name>(typename Domain::State::Source::Name{std::make_shared<const astra::Scope>(astra::Scope{"pages", "main"}), key(index)});
        return {.name = std::move(name), .record = action == 2 ? std::nullopt : std::optional(content(version)), .version = version, .data = action == 1, .bytes = 128};
    }

    // Exhaust coherent action histories and every input permutation against a chronological last-action oracle.
    static void permutations(Counts& counts) {
        for (unsigned encoded = 0; encoded < 27; ++encoded) {
            std::array<unsigned, 3> actions{}; // Base-three input description, independent of production merging.
            auto remaining = encoded;
            bool present = true; // Data-only initially has a complete client baseline.
            bool valid = true;
            bool full = false; // Any replacement/deletion requires the eventual live result to carry Attr.
            for (auto& action : actions) {
                action = remaining % 3;
                remaining /= 3;
                if ((action != 0 && !present) || (std::is_same_v<Domain, astra::Catalog> && action == 1)) {
                    valid = false;
                }
                present = action != 2;
                full = full || action != 1;
            }
            if (!valid) {
                continue;
            }
            ++counts.histories;
            const std::array<Event, 6> chronological{event(0, 1, actions[0]), event(0, 2, actions[1]), event(0, 3, actions[2]), event(1, 4, 0), event(1, 5, 2), event(2, 6, 0)};
            const std::map<std::string, std::optional<std::uint64_t>> expected{{key(0), present ? std::optional<std::uint64_t>(3) : std::nullopt}, {key(1), std::nullopt}, {key(2), 6}};
            std::array<unsigned, 6> order{0, 1, 2, 3, 4, 5}; // Enumerate all 720 arrangements, including nontrivial permutation cycles.
            do {
                ++counts.permutations;
                std::vector<Event> input;
                input.reserve(16); // Preserve unused physical slots when compaction accounts retained capacity.
                for (const auto index : order) {
                    input.push_back(chronological[index]);
                }
                for (const auto& target : {std::string{}, key(0), key(1), key(3)}) {
                    auto captured = input; // Each edition receives a separately measured retained vector allocation.
                    captured.reserve(16);
                    const auto capacity = captured.capacity();
                    Edition edition(6, std::move(captured), target);
                    auto filtered = expected; // Oracle is a chronological map, not a copy of Pagination's ordering/merge algorithm.
                    if (!target.empty()) {
                        std::erase_if(filtered, [&](const auto& item) { return item.first != target; });
                    }
                    CHECK(edition.bytes() == filtered.size() * 128 + (capacity - filtered.size()) * sizeof(Event));
                    const auto page = edition.next("star");
                    CHECK(page.mode() == proto::comet::v1::MODE_APPLY && page.complete() && page.has_version() && page.version() == 6 && page.instance() == "star");
                    CHECK(edition.complete() && page.changes_size() == static_cast<int>(filtered.size()));
                    auto wanted = filtered.begin();
                    for (const auto& change : page.changes()) {
                        CHECK(wanted != filtered.end());
                        if constexpr (std::is_same_v<Domain, astra::Catalog>) {
                            CHECK(change.key() == wanted->first);
                            CHECK(wanted->second ? change.has_value() && change.version() == *wanted->second && change.value() == std::string(1, static_cast<char>(*wanted->second)) : change.has_erase());
                        } else {
                            CHECK(change.uuid() == wanted->first);
                            const bool complete = wanted->first != key(0) || full;
                            if (!wanted->second) {
                                CHECK(change.has_erase());
                            } else if (complete) {
                                CHECK(change.has_record() && change.record().attr() == "A" && change.record().data() == std::string(1, static_cast<char>(*wanted->second)));
                            } else {
                                CHECK(change.has_data() && change.data() == std::string(1, static_cast<char>(*wanted->second)));
                            }
                        }
                        ++wanted;
                    }
                    CHECK(wanted == filtered.end());
                    ++counts.editions;
                }
            } while (std::next_permutation(order.begin(), order.end()));
        }
    }

    // Reject corrupt envelopes before target filtering and preserve position when later row encoding fails.
    static void rejection() {
        for (unsigned damaged = 0; damaged < 4; ++damaged) {
            auto invalid = event(0, 1, 0);
            if (damaged == 0) {
                invalid.name.reset();
            } else if (damaged == 1) {
                invalid.version = 0;
            } else if (damaged == 2) {
                invalid.version = 7;
            } else {
                invalid.record.reset();
                invalid.data = true;
            }
            bool rejected{};
            try {
                Edition edition(6, std::vector<Event>{std::move(invalid)}, key(3));
            } catch (const std::invalid_argument&) {
                rejected = true;
            }
            CHECK(rejected);
        }
        Edition good(1, std::vector<Event>{event(0, 1, 0)});
        auto reference = good;
        for (const auto& instance : {std::string{}, std::string(129, 'x')}) {
            bool rejected{};
            try {
                static_cast<void>(good.next(instance));
            } catch (const std::invalid_argument&) {
                rejected = true;
            }
            CHECK(rejected && !good.complete());
        }
        CHECK(good.next("star").SerializeAsString() == reference.next("star").SerializeAsString());
        bool completed{};
        try {
            static_cast<void>(good.next("star"));
        } catch (const std::logic_error&) {
            completed = true;
        }
        CHECK(completed);

        for (unsigned fault = 0; fault < 2; ++fault) {
            auto second = event(1, 2, 0); // The first row succeeds before the second row fails.
            if (fault == 0) {
                if constexpr (std::is_same_v<Domain, astra::Catalog>) {
                    second.record->value.reset();
                } else {
                    second.record->data.reset();
                }
            } else {
                second.record = content(2, 8 * 1024 * 1024);
            }
            Edition failed(2, std::vector<Event>{event(0, 1, 0), std::move(second)});
            for (unsigned attempt = 0; attempt < 2; ++attempt) {
                bool rejected{};
                try {
                    static_cast<void>(failed.next("star"));
                } catch (const std::invalid_argument&) {
                    CHECK(fault == 0);
                    rejected = true;
                } catch (const std::length_error&) {
                    CHECK(fault == 1);
                    rejected = true;
                }
                CHECK(rejected && !failed.complete() && failed.version() == 2);
            }
        }
    }
};

// Capture 257 records before a two-key atomic commit straddling the page boundary; neither snapshot nor replay may expose half.
void snapshots() {
    astra::Catalog::State state([] { return std::optional(astra::Clock::Reading{.time = astra::Clock::Time(std::chrono::seconds(1)), .ready = true}); }, {});
    const astra::Scope scope{"pages", "atomic"};
    for (unsigned index = 0; index < 257; ++index) {
        CHECK(state.publish(scope, std::to_string(1000 + index), buffer(1, 'o'), 1, 1000));
    }
    auto before = state.capture(scope);
    CHECK(before && before->version() == 257);
    astra::Catalog::Edition frozen(std::move(*before));
    const std::array<astra::Catalog::State::Entry, 2> entries{{{"1254", buffer(1, 'n')}, {"1256", buffer(1, 'n')}}};
    CHECK(state.publish(scope, entries, 2, 1000));
    auto after = state.capture(scope);
    CHECK(after && after->version() == 259);
    astra::Catalog::Edition current(std::move(*after));
    const auto middle = state.changes(scope, 258);
    CHECK(!middle && middle.error() == astra::Catalog::State::Error::History);
    auto suffix = state.changes(scope, 257);
    CHECK(suffix && suffix->size() == 2);
    astra::Catalog::Edition delta(259, std::move(*suffix));
    const auto changes = delta.next("star");
    CHECK(changes.complete() && changes.version() == 259 && changes.changes_size() == 2);
    CHECK(changes.changes(0).key() == "1254" && changes.changes(1).key() == "1256");
    for (const auto& change : changes.changes()) {
        CHECK(change.version() == 2 && change.value() == "n");
    }
    for (unsigned captured = 0; captured < 2; ++captured) {
        auto& edition = captured == 0 ? frozen : current;
        unsigned rows{};
        unsigned pages{};
        while (!edition.complete()) {
            const auto page = edition.next("star");
            CHECK(page.mode() == proto::comet::v1::MODE_RESET && page.changes_size() == (pages == 0 ? 256 : 1));
            CHECK(page.complete() == (pages == 1));
            CHECK(page.complete() ? page.has_version() && page.version() == (captured == 0 ? 257 : 259) && page.instance() == "star" : !page.has_version() && page.instance().empty());
            for (const auto& change : page.changes()) {
                CHECK(change.key() == std::to_string(1000 + rows));
                const bool updated = captured != 0 && (rows == 254 || rows == 256);
                CHECK(change.has_value() && change.value() == (updated ? "n" : "o") && change.version() == (updated ? 2 : 1));
                ++rows;
            }
            ++pages;
        }
        CHECK(rows == 257 && pages == 2);
    }
}
} // namespace

// Run a finite offline inventory; no transport, wall-clock waiting, or production hooks are involved.
int main() {
    try {
        Counts counts;
        Fixture<astra::Catalog>::permutations(counts);
        Fixture<astra::Ephemeris>::permutations(counts);
        CHECK(counts.histories == 22 && counts.permutations == 15840 && counts.editions == 63360);
        Fixture<astra::Catalog>::rejection();
        Fixture<astra::Ephemeris>::rejection();
        snapshots();
        std::cout << "ASTRA-PAGINATION {\"histories\":" << counts.histories << ",\"permutations\":" << counts.permutations << ",\"editions\":" << counts.editions << "}\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
