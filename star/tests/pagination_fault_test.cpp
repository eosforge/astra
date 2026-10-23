// Exhaust allocation failures in native page construction and encoding without leaking frozen ownership or advancing a failed cursor.
#include "catalog_edition.hpp"
#include "check.hpp"
#include "edition.hpp"
#include "ephemeris_edition.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <shared_mutex>
#include <string>
#include <type_traits>
#include <vector>

namespace {
/// Successful ordinary allocations remaining before one injected exception; -1 disables injection.
thread_local std::ptrdiff_t remaining = -1;
/// Whether this attempt actually reached its requested allocation boundary.
thread_local bool injected{};

/// Replace ordinary throwing allocation only within this isolated test executable.
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

/// Release ordinary storage, including null; over-aligned allocation is outside this sweep.
[[gnu::noinline]] void release(void* value) noexcept {
    std::free(value);
}

/// Limit injection to the production call, leaving cleanup and independent oracles uninjected.
class Failure {
public:
    /// Fail after point successful allocations, with a fresh counter for every new edition.
    explicit Failure(std::ptrdiff_t point) {
        remaining = point;
        injected = false;
    }

    /// Disable injection on both normal return and exception unwinding.
    ~Failure() {
        remaining = -1;
    }

    /// Injection ownership cannot be copied or reassigned.
    Failure(const Failure&) = delete;
    Failure& operator=(const Failure&) = delete;
};
} // namespace

/// Ordinary scalar allocation participates in the isolated failure sweep.
void* operator new(std::size_t size) {
    return allocate(size);
}

/// Ordinary array allocation shares the same single-failure counter.
void* operator new[](std::size_t size) {
    return allocate(size);
}

/// Release scalar storage in its original allocation domain.
void operator delete(void* value) noexcept {
    release(value);
}

/// Release array storage in its original allocation domain.
void operator delete[](void* value) noexcept {
    release(value);
}

/// Sized scalar deletion has the same release semantics.
void operator delete(void* value, std::size_t) noexcept {
    release(value);
}

/// Sized array deletion has the same release semantics.
void operator delete[](void* value, std::size_t) noexcept {
    release(value);
}

namespace {
/// Keep finite scenario and failure exposure separate from aggregate assertion counts.
struct Counts {
    /// Independently completed domain/scenario sweeps.
    unsigned scenarios{};
    /// Attempted allocation boundaries, including each terminal uninjected success.
    unsigned attempts{};
    /// Reached failure points whose rollback and healthy replay were checked.
    unsigned failures{};
};

/// Exercise real Scene roots, domain encoding, and generated Protobuf allocation paths.
template <typename Domain>
class Fixture {
    using Projection = typename Domain::State::Projection;
    using Content = typename Domain::State::Content;
    using Edition = typename Domain::Edition;
    using Name = typename Domain::State::Source::Name;

    /// Distinguish first/intermediate/final pages and empty-but-valid reset replies.
    enum class Case {
        /// Snapshot page before any cursor advancement.
        First,
        /// Snapshot page after one successful page.
        Middle,
        /// Final snapshot page including instance and version allocation.
        Last,
        /// Exact present record with a large payload.
        Point,
        /// Exact present record with empty payloads.
        Zero,
        /// Exact absent record, retaining the captured cursor.
        Missing,
        /// Empty whole-scope snapshot at cursor zero.
        Empty,
        /// Incremental first page with a complete record.
        Delta,
        /// Final incremental page with data/full and erase actions.
        Tail
    };

    /// Independent literal payload size forces snapshot pages to contain one row each.
    static constexpr std::size_t payload_ = 128 * 1024;

    /// Domain-valid keys force owned key storage without entropy or source-derived expectations.
    static std::string key(unsigned index) {
        if constexpr (std::is_same_v<Domain, astra::Catalog>) {
            return std::string(64, 'k') + static_cast<char>('0' + index);
        } else {
            std::string result(16, '\0');
            result[0] = static_cast<char>(index);
            result[6] = '\x40';
            result[8] = '\x80';
            return result;
        }
    }

    /// Immutable input bytes; an empty buffer remains distinct from an absent record.
    static astra::Catalog::Value buffer(std::size_t size, unsigned value) {
        return std::make_shared<const astra::Catalog::Buffer>(size, static_cast<std::uint8_t>(value));
    }

    /// Construct complete public records from literal input indices and payload sizes.
    static Content content(unsigned index, bool empty = false) {
        if constexpr (std::is_same_v<Domain, astra::Catalog>) {
            return {.version = index + 1, .value = buffer(empty ? 0 : payload_, 'a' + index)};
        } else {
            return {.attr = buffer(empty ? 0 : 64, 'A' + index), .data = buffer(empty ? 0 : payload_, 'a' + index)};
        }
    }

    /// Use real shared source names while keeping the fixture free of clocks and networking.
    static std::shared_ptr<const Name> name(unsigned index) {
        return std::make_shared<const Name>(std::make_shared<const astra::Scope>("pages", "fault"), key(index));
    }

    /// Count only the immutable payload retained by each native projection record.
    static std::size_t measure(const Content& value) noexcept {
        if constexpr (std::is_same_v<Domain, astra::Catalog>) {
            return value.value->size();
        } else {
            return value.attr->size() + value.data->size();
        }
    }

    /// Build a fresh real edition before enabling allocation injection.
    static Edition create(Case scenario) {

        if (scenario == Case::Point || scenario == Case::Zero || scenario == Case::Missing) {
            return Edition(key(0), typename Projection::Point{.name = name(0), .record = scenario == Case::Missing ? std::nullopt : std::optional(content(0, scenario == Case::Zero)), .version = 7});
        }
        if (scenario == Case::Delta || scenario == Case::Tail) {
            std::vector<typename Projection::Event> events;
            for (unsigned index = 0; index < 3; ++index) {
                events.push_back({.name = name(index), .record = index == 2 ? std::nullopt : std::optional(content(index)), .version = index + 1, .data = index == 1 && std::is_same_v<Domain, astra::Ephemeris>, .bytes = payload_ + 128});
            }
            return Edition(3, std::move(events));
        }

        const auto gate = std::make_shared<std::shared_mutex>();
        Projection scene(gate, measure);
        if (scenario != Case::Empty) {
            for (unsigned index = 0; index < 3; ++index) {
                typename Projection::Retired retired;
                const std::lock_guard lock(*gate);
                auto edit = scene.prepare(name(index), content(index), {});
                CHECK(edit);
                retired = edit->commit();
            }
        }
        const std::lock_guard lock(*gate);
        return Edition(scene.capture()); // The captured root must outlive this local Scene.
    }

    /// Verify exact row identity, action, metadata, and bytes without invoking a second encoder.
    static void inspect(const typename Edition::Reply& page, Case scenario, unsigned index, const std::string& instance) {

        const bool delta = scenario == Case::Delta || scenario == Case::Tail;
        const bool snapshot = scenario == Case::First || scenario == Case::Middle || scenario == Case::Last;
        const bool empty = scenario == Case::Empty || scenario == Case::Missing;
        const unsigned rows = empty ? 0 : delta && index == 1 ? 2
                                                              : 1;
        const bool finished = snapshot ? index == 2 : delta ? index == 1
                                                            : true;
        const unsigned version = scenario == Case::Empty ? 0 : snapshot || delta ? 3
                                                                                 : 7;
        CHECK(page.mode() == (delta ? proto::comet::v1::MODE_APPLY : proto::comet::v1::MODE_RESET));
        CHECK(page.changes_size() == static_cast<int>(rows));
        CHECK(page.complete() == finished && page.has_version() == finished);
        CHECK(page.version() == (finished ? version : 0));
        CHECK(page.instance() == (finished ? instance : std::string{}));
        for (unsigned offset = 0; offset < rows; ++offset) {
            const auto& change = page.changes(static_cast<int>(offset));
            const unsigned item = snapshot || delta ? index + offset : 0;
            const bool erased = delta && item == 2;
            const auto size = scenario == Case::Zero ? 0 : payload_;
            if constexpr (std::is_same_v<Domain, astra::Catalog>) {
                CHECK(change.key() == key(item));
                CHECK(change.has_erase() == erased && change.has_value() == !erased);
                if (!erased) {
                    CHECK(change.version() == item + 1 && change.value() == std::string(size, static_cast<char>('a' + item)));
                }
            } else {
                const bool data = delta && item == 1;
                CHECK(change.uuid() == key(item));
                CHECK(change.has_erase() == erased && change.has_data() == data && change.has_record() == (!erased && !data));
                if (data) {
                    CHECK(change.data() == std::string(size, static_cast<char>('a' + item)));
                } else if (!erased) {
                    CHECK(change.record().attr() == std::string(scenario == Case::Zero ? 0 : 64, static_cast<char>('A' + item)));
                    CHECK(change.record().data() == std::string(size, static_cast<char>('a' + item)));
                }
            }
        }
    }

public:
    /// Exhaust each allocation index until the first uninjected success within a fixed 128-point budget.
    static void run(Counts& counts) {

        constexpr std::array names{"first", "middle", "last", "point", "zero", "missing", "empty", "delta", "tail"};
        const std::string instance(128, 's'); // Force final-page instance allocation even for empty replies.
        for (unsigned selected = 0; selected < names.size(); ++selected) {
            const auto scenario = static_cast<Case>(selected);
            const unsigned skipped = scenario == Case::Middle || scenario == Case::Tail ? 1 : scenario == Case::Last ? 2
                                                                                                                     : 0;
            bool completed{};
            unsigned failures{};
            for (std::ptrdiff_t point = 0; point < 128; ++point) {
                auto edition = create(scenario);
                for (unsigned index = 0; index < skipped; ++index) {
                    inspect(edition.next(instance), scenario, index, instance);
                    CHECK(!edition.complete());
                }
                auto frozen = edition;
                const auto version = edition.version();
                const auto bytes = edition.bytes();
                std::optional<typename Edition::Reply> page;
                bool failed{};
                try {
                    const Failure failure(point);
                    page.emplace(edition.next(instance));
                } catch (const std::bad_alloc&) {
                    CHECK(injected);
                    failed = true;
                }

                CHECK(failed == injected);
                CHECK(edition.version() == version && edition.bytes() == bytes);
                CHECK(!frozen.complete() && frozen.version() == version && frozen.bytes() == bytes);
                if (failed) {
                    CHECK(!page && !edition.complete());
                    page.emplace(edition.next(instance)); // The same failed row and cursor must still be available.
                    ++failures;
                    ++counts.failures;
                }
                inspect(*page, scenario, skipped, instance);
                CHECK(edition.complete() == page->complete());
                for (unsigned index = skipped + 1; !edition.complete(); ++index) {
                    CHECK(index <= 2); // A missing final commit cannot turn this test into an unbounded loop.
                    inspect(edition.next(instance), scenario, index, instance);
                }
                for (unsigned index = skipped; !frozen.complete(); ++index) {
                    CHECK(index <= 2);
                    inspect(frozen.next(instance), scenario, index, instance);
                }
                CHECK(edition.bytes() == bytes && frozen.bytes() == bytes);
                ++counts.attempts;
                std::cout << "ASTRA-PAGE-FAULT {\"domain\":\"" << (std::is_same_v<Domain, astra::Catalog> ? "catalog" : "ephemeris") << "\",\"case\":\"" << names[selected] << "\",\"point\":" << point << ",\"injected\":" << (failed ? "true" : "false") << "}\n";
                if (!failed) {
                    completed = true;
                    break;
                }
            }
            CHECK(completed && failures > 0);
            ++counts.scenarios;
        }
    }

    /// Force repeated-field growth through four small rows rather than only byte-limited single-row pages.
    static void dense(Counts& counts) {

        const std::string instance(128, 's');
        bool completed{};
        unsigned failures{};
        for (std::ptrdiff_t point = 0; point < 128; ++point) {
            std::vector<typename Projection::Event> events;
            for (unsigned index = 0; index < 4; ++index) {
                events.push_back({.name = name(index), .record = index == 3 ? std::nullopt : std::optional(content(index, true)), .version = index + 1, .data = index == 1 && std::is_same_v<Domain, astra::Ephemeris>, .bytes = 128});
            }
            Edition edition(4, std::move(events));
            const auto bytes = edition.bytes();
            std::optional<typename Edition::Reply> page;
            bool failed{};
            try {
                const Failure failure(point);
                page.emplace(edition.next(instance));
            } catch (const std::bad_alloc&) {
                CHECK(injected);
                failed = true;
            }
            CHECK(failed == injected && edition.bytes() == bytes && edition.version() == 4);
            if (failed) {
                CHECK(!edition.complete() && !page);
                page.emplace(edition.next(instance));
                ++failures;
                ++counts.failures;
            }
            CHECK(edition.complete() && page->changes_size() == 4);
            CHECK(page->mode() == proto::comet::v1::MODE_APPLY && page->complete() && page->version() == 4 && page->instance() == instance);
            for (unsigned index = 0; index < 4; ++index) {
                const auto& change = page->changes(static_cast<int>(index));
                if constexpr (std::is_same_v<Domain, astra::Catalog>) {
                    CHECK(change.key() == key(index) && change.has_erase() == (index == 3) && change.has_value() == (index != 3));
                    CHECK(index == 3 || (change.version() == index + 1 && change.value().empty()));
                } else {
                    CHECK(change.uuid() == key(index) && change.has_erase() == (index == 3));
                    CHECK(change.has_data() == (index == 1) && change.has_record() == (index == 0 || index == 2));
                    CHECK(change.data().empty() && change.record().attr().empty() && change.record().data().empty());
                }
            }
            ++counts.attempts;
            std::cout << "ASTRA-PAGE-FAULT {\"domain\":\"" << (std::is_same_v<Domain, astra::Catalog> ? "catalog" : "ephemeris") << "\",\"case\":\"dense\",\"point\":" << point << ",\"injected\":" << (failed ? "true" : "false") << "}\n";
            if (!failed) {
                completed = true;
                break;
            }
        }
        CHECK(completed && failures > 0);
        ++counts.scenarios;
    }
};

/// Cover the equivalent Almanac oneof, repeated-field growth, and final-instance ownership paths.
void almanac(Counts& counts) {

    const std::string instance(128, 's');
    for (unsigned selected = 0; selected < 3; ++selected) {
        bool completed{};
        unsigned failures{};
        for (std::ptrdiff_t point = 0; point < 128; ++point) {
            const auto create = [selected] {
                if (selected == 0) {
                    return astra::Edition{};
                }
                if (selected == 1) {
                    return astra::Edition(std::string(64, 'k'), astra::Almanac::Point{.version = 7, .value = std::make_shared<const astra::Almanac::Buffer>(64, 'v')});
                }
                astra::Almanac::Replay replay{.version = 7, .changes = {}};
                for (unsigned index = 0; index < 4; ++index) {
                    replay.changes.push_back({.key = std::make_shared<const std::string>(std::string(64, 'k') + static_cast<char>('0' + index)), .value = index == 3 ? nullptr : std::make_shared<const astra::Almanac::Buffer>(index == 2 ? 0 : 64, static_cast<std::uint8_t>('a' + index)), .version = 7});
                }
                return astra::Edition(std::move(replay));
            };
            auto edition = create();
            const auto bytes = edition.bytes();
            const auto version = selected == 0 ? 0U : 7U;
            std::optional<proto::comet::v1::AlmanacWatchReply> page;
            bool failed{};
            try {
                const Failure failure(point);
                page.emplace(edition.next(instance));
            } catch (const std::bad_alloc&) {
                CHECK(injected);
                failed = true;
            }
            CHECK(failed == injected && edition.bytes() == bytes && edition.version() == version);
            if (failed) {
                CHECK(!page && !edition.complete());
                page.emplace(edition.next(instance));
                ++failures;
                ++counts.failures;
            }
            CHECK(page->complete() && edition.complete() && page->version() == version && page->instance() == instance);
            CHECK(page->mode() == (selected == 2 ? proto::comet::v1::MODE_APPLY : proto::comet::v1::MODE_RESET));
            CHECK(page->changes_size() == (selected == 0 ? 0 : selected == 1 ? 1
                                                                             : 4));
            for (int index = 0; index < page->changes_size(); ++index) {
                const auto& change = page->changes(index);
                CHECK(change.key() == (selected == 1 ? std::string(64, 'k') : std::string(64, 'k') + static_cast<char>('0' + index)));
                CHECK(change.has_erase() == (index == 3) && change.has_value() == (index != 3));
                CHECK(index == 3 || change.value() == std::string(index == 2 ? 0 : 64, selected == 1 ? 'v' : static_cast<char>('a' + index)));
            }
            ++counts.attempts;
            constexpr std::array names{"empty", "point", "dense"};
            std::cout << "ASTRA-PAGE-FAULT {\"domain\":\"almanac\",\"case\":\"" << names[selected] << "\",\"point\":" << point << ",\"injected\":" << (failed ? "true" : "false") << "}\n";
            if (!failed) {
                completed = true;
                break;
            }
        }
        CHECK(completed && failures > 0);
        ++counts.scenarios;
    }
}

/// Fail exact-key projection construction, then verify frozen ownership and a healthy complete retry.
void construction(Counts& counts) {

    const auto key = std::make_shared<const std::string>("target");
    const auto value = std::make_shared<const astra::Almanac::Buffer>(64, static_cast<std::uint8_t>('v'));
    const astra::Almanac::Replay frozen{.version = 7, .changes = {{.key = key, .value = value, .version = 7}}};
    const auto keys = key.use_count();
    const auto values = value.use_count();
    // Historical charging includes the owning Change record as well as key/value payload.
    const auto bytes = sizeof(astra::Almanac::Change) + key->size() + value->size();
    const std::string instance(128, 's');
    bool completed{};
    unsigned failures{};
    for (std::ptrdiff_t point = 0; point < 128; ++point) {
        auto replay = frozen;
        std::optional<astra::Edition> edition;
        bool failed{};
        try {
            const Failure failure(point);
            edition.emplace(std::move(replay), *key);
        } catch (const std::bad_alloc&) {
            CHECK(injected);
            failed = true;
        }
        CHECK(failed == injected);
        CHECK(frozen.version == 7 && frozen.changes.size() == 1 && frozen.changes.front().key == key && frozen.changes.front().value == value && frozen.changes.front().version == 7);
        if (failed) {
            CHECK(!edition && key.use_count() == keys && value.use_count() == values);
            edition.emplace(frozen, *key);
            ++failures;
            ++counts.failures;
        }
        CHECK(!edition->complete() && edition->version() == 7 && edition->bytes() == bytes);
        const auto page = edition->next(instance);
        CHECK(page.complete() && page.mode() == proto::comet::v1::MODE_APPLY && page.version() == 7 && page.instance() == instance && page.changes_size() == 1 && page.changes(0).key() == *key && page.changes(0).has_value() && page.changes(0).value() == std::string(64, 'v'));
        CHECK(edition->complete() && edition->version() == 7 && edition->bytes() == bytes && key.use_count() == keys + 1 && value.use_count() == values + 1);
        ++counts.attempts;
        std::cout << "ASTRA-PAGE-FAULT {\"domain\":\"almanac\",\"case\":\"construction\",\"point\":" << point << ",\"injected\":" << (failed ? "true" : "false") << "}\n";
        if (!failed) {
            completed = true;
            break;
        }
    }
    CHECK(completed && failures > 0);
    ++counts.scenarios;
}
} // namespace

/// Run both native encoders; each scenario must include real failures and a terminal clean success.
int main() {
    try {
        Counts counts;
        Fixture<astra::Catalog>::run(counts);
        Fixture<astra::Ephemeris>::run(counts);
        CHECK(counts.scenarios == 18 && counts.attempts == counts.failures + counts.scenarios);
        Fixture<astra::Catalog>::dense(counts);
        Fixture<astra::Ephemeris>::dense(counts);
        almanac(counts);
        construction(counts);
        CHECK(counts.scenarios == 24 && counts.attempts == counts.failures + counts.scenarios);
        std::cout << "ASTRA-PAGE-FAULT-SUMMARY {\"scenarios\":" << counts.scenarios << ",\"attempts\":" << counts.attempts << ",\"failures\":" << counts.failures << "}\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
