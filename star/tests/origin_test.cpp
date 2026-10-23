// Verify native-source history, positions, and staged replacement behavior.
#include "catalog.hpp"
#include "check.hpp"
#include "ephemeris.hpp"
#include "origin.hpp"

#include <atomic>
#include <chrono>
#include <iostream>
#include <mutex>
#include <thread>

namespace {
using namespace std::chrono_literals;
using astra::Catalog;
using astra::Clock;
using astra::Ephemeris;
using astra::Scope;
/// Real native rules/index/history with explicit outer locking and time; no network workers.
using Source = astra::Origin<Catalog::Record>;

/// Type-name detection fails at the constraint boundary rather than instantiating an internal static_assert failure.
template <typename Item>
concept Accepted = requires { typename astra::Origin<Item>; };

/// Native shared records are valid; potentially allocating string copies are rejected.
static_assert(Accepted<Catalog::Record> && Accepted<Ephemeris::Record> && !Accepted<std::string>);

/// Catalog payload measure counts shared bodies; Origin separately charges watermark metadata.
std::size_t measure(const Catalog::Record& record) noexcept {
    return record.value ? record.value->size() : 0;
}

/// Ephemeris measures Attr/Data separately without concatenation or temporary serialization.
std::size_t measure(const Ephemeris::Record& record) noexcept {
    return (record.attr ? record.attr->size() : 0) + (record.data ? record.data->size() : 0);
}

/// Payload-free watermark separates source position from per-key application version.
Catalog::Record record(std::uint64_t version) {
    return Catalog::Record{version, nullptr, std::nullopt};
}

/// Models outer atomic publication with retired resources declared before lock for off-lock destruction.
void commit(Source& source, const std::shared_ptr<std::shared_mutex>& gate, Scope scope, std::string key, std::optional<Catalog::Record> value, std::optional<std::uint64_t> position, std::chrono::steady_clock::time_point now) {

    Source::Retired retired;
    const std::lock_guard lock(*gate);
    auto edit = source.prepare(scope, std::move(key), std::move(value), position, now);
    CHECK(edit);
    retired = edit->commit();
}

/// One source position spans Sector/Spectrum; reclaiming empty Scopes cannot recycle sequence numbers.
void scopes() {

    const auto gate = std::make_shared<std::shared_mutex>();
    Source source(gate, measure, true);
    const auto now = std::chrono::steady_clock::now();
    commit(source, gate, {"one", "main"}, "key", record(20), 1, now);
    commit(source, gate, {"two", "other"}, "key", record(7), 2, now);
    const auto frozen = [&] { const std::lock_guard lock(*gate); return source.capture(); }();
    CHECK(frozen.size() == 2 && frozen.position() == 2);
    unsigned count{};
    frozen.each([&](const Scope& scope, const std::string& key, const Catalog::Record& value) {
        CHECK(key == "key" && ((scope.sector == "one" && value.version == 20) || (scope.sector == "two" && value.version == 7)));
        ++count;
    });
    CHECK(count == 2);
    {
        const std::lock_guard lock(*gate);
        auto history = source.replay(0);
        CHECK(history && history->size() == 2 && (*history)[0].position == 1 && (*history)[1].position == 2);
        CHECK((*history)[0].name->scope->sector == "one" && (*history)[1].name->scope->sector == "two");
        CHECK(source.next() == 3 && source.find({"one", "main"}, "key")->version == 20);
        CHECK(!source.find({"unknown", "main"}, "key"));
    }

    commit(source, gate, {"one", "main"}, "key", std::nullopt, 3, now);
    commit(source, gate, {"two", "other"}, "key", std::nullopt, 4, now);
    commit(source, gate, {"one", "main"}, "new", record(100), 5, now);
    CHECK(frozen.size() == 2); // Old roots own names independently of reclaimed directories.
    {
        const std::lock_guard lock(*gate);
        CHECK(source.position() == 5 && source.capture().size() == 1);
        const auto history = source.replay(2);
        CHECK(history && history->size() == 3 && !(*history)[0].record && !(*history)[1].record);
    }
}

/// If another preparation fails, discard Edit and preserve native root/directory/position/history.
void rollback() {

    const auto gate = std::make_shared<std::shared_mutex>();
    Source source(gate, measure, true, {.records = 1, .scopes = 1, .bytes = 4096});
    const auto now = std::chrono::steady_clock::now();
    {
        const std::lock_guard lock(*gate);
        {
            auto prepared = source.prepare({"first", "scope"}, "key", record(8), 1, now);
            CHECK(prepared);
            bool blocked{};
            try {
                static_cast<void>(source.capture());
            } catch (const std::logic_error&) {
                blocked = true;
            }
            CHECK(blocked); // Temporary preparation cannot be read as complete state.
        }
        CHECK(source.position() == 0 && source.capture().size() == 0 && source.replay(0)->empty());
    }
    commit(source, gate, {"second", "scope"}, "key", record(12), 1, now);
    {
        const std::lock_guard lock(*gate);
        {
            auto prepared = source.prepare({"second", "scope"}, "key", record(99), 2, now);
            CHECK(prepared);
        }
        CHECK(source.position() == 1 && source.find({"second", "scope"}, "key")->version == 12);
        CHECK(source.replay(0)->size() == 1);
        const auto full = source.prepare({"third", "scope"}, "key", record(1), 2, now);
        CHECK(!full && full.error() == Source::Error::Capacity);
        const auto skipped = source.prepare({"second", "scope"}, "key", record(99), 3, now);
        CHECK(!skipped && skipped.error() == Source::Error::Version);
        CHECK(source.position() == 1);
    }
}

/// Oversized/disabled/evicted history explicitly requires baselines, without empty-queue pop or gapped suffix success.
void history() {

    const auto gate = std::make_shared<std::shared_mutex>();
    const auto now = std::chrono::steady_clock::now();
    Source source(gate, measure, true, {.history = 2, .backlog = 4096});
    for (std::uint64_t position = 1; position <= 3; ++position) {
        commit(source, gate, {"one", "scope"}, "key", record(position), position, now);
    }
    {
        const std::lock_guard lock(*gate);
        CHECK(source.replay(0).error() == Source::Error::History);
        const auto result = source.replay(1);
        CHECK(result && result->size() == 2 && result->front().position == 2 && result->back().position == 3);
        CHECK(source.replay(4).error() == Source::Error::Version);
    }
    Catalog::Record large{4, std::make_shared<const Catalog::Buffer>(8192), Clock::Time(5s)};
    commit(source, gate, {"one", "scope"}, "key", large, 4, now);
    {
        const std::lock_guard lock(*gate);
        CHECK(source.position() == 4 && source.find({"one", "scope"}, "key")->value->size() == 8192);
        CHECK(source.replay(3).error() == Source::Error::History);
    }
    commit(source, gate, {"one", "scope"}, "key", record(4), std::nullopt, now); // Local TTL maintenance leaves a watermark without another source position.
    commit(source, gate, {"one", "scope"}, "key", record(5), 5, now);
    {
        const std::lock_guard lock(*gate);
        CHECK(source.replay(4)->size() == 1 && source.position() == 5);
    }

    for (const auto limits : {Source::Limits{.history = 0}, Source::Limits{.backlog = 0}, Source::Limits{.retention = 0s}}) {
        Source disabled(gate, measure, true, limits);
        commit(disabled, gate, {"one", "scope"}, "key", record(1), 1, now);
        const std::lock_guard lock(*gate);
        CHECK(disabled.position() == 1 && disabled.capture().size() == 1);
        CHECK(disabled.replay(0).error() == Source::Error::History);
        const auto delivery = disabled.deliver(0, 8, 4096); // Zero budget evicts even the new item; bounded send requires a full baseline.
        CHECK(delivery && delivery->baseline && delivery->events.empty() && delivery->baseline->position() == 1);
    }
    Source replica(gate, measure, false);
    commit(replica, gate, {"one", "scope"}, "key", record(1), 1, now);
    {
        const std::lock_guard lock(*gate);
        CHECK(replica.position() == 1 && replica.replay(0).error() == Source::Error::History);
    }
}

/// Age prunes only on writes; replay and bounded sends agree, preserving idle retained deletions.
void retention() {

    const auto gate = std::make_shared<std::shared_mutex>();
    Source source(gate, measure, true);
    const auto now = std::chrono::steady_clock::now();
    const auto stored = now - 1h; // Construct old history directly without sleeps/system-clock changes.
    const Scope scope{"idle", "history"};
    commit(source, gate, scope, "key", record(1), 1, stored);
    commit(source, gate, scope, "key", std::nullopt, 2, stored);
    {
        const std::lock_guard lock(*gate);
        const auto replay = source.replay(0);
        CHECK(replay && replay->size() == 2 && replay->front().record && !replay->back().record);
        CHECK(replay->front().stored == stored && replay->back().form == Source::Form::Erase);
        const auto first = source.deliver(0, 1, 4096); // Unpruned age alone cannot force baseline; count still limits the first prefix.
        CHECK(first && !first->baseline && first->events.size() == 1 && first->events.front().position == 1);
        const auto cost = first->events.front().bytes; // Byte budget fits only the first event, without assuming fixed struct size.
        const auto limited = source.deliver(0, 8, cost);
        CHECK(limited && !limited->baseline && limited->events.size() == 1);
        CHECK(source.deliver(0, 1, cost - 1).error() == Source::Error::Capacity);
        const auto tail = source.deliver(1, 8, 4096); // The next send cannot skip retained deletion.
        CHECK(tail && !tail->baseline && tail->events.size() == 1 && tail->events.front().position == 2 && !tail->events.front().record);
        const auto caught = source.deliver(2, 8, 4096); // Already-caught-up sends produce no baseline or synthetic event.
        CHECK(caught && !caught->baseline && caught->events.empty() && source.replay(2)->empty());
        CHECK(source.deliver(3, 8, 4096).error() == Source::Error::Version);
        CHECK(source.deliver(0, 0, 4096).error() == Source::Error::Input && source.deliver(0, 1, 0).error() == Source::Error::Input);
        CHECK(source.capture().size() == 0); // Reading old creation history cannot revive a deleted record.
    }

    commit(source, gate, scope, "key", record(3), 3, now); // Only a real new commit prunes old prefixes.
    {
        const std::lock_guard lock(*gate);
        CHECK(source.replay(0).error() == Source::Error::History && source.replay(1).error() == Source::Error::History);
        const auto missing = source.deliver(1, 8, 4096); // Losing the deletion position explicitly requires a baseline.
        CHECK(missing && missing->baseline && missing->events.empty() && missing->baseline->position() == 3);
        const auto replay = source.replay(2); // A cursor exactly at the pruning boundary still permits recovery.
        const auto tail = source.deliver(2, 8, 4096);
        CHECK(replay && replay->size() == 1 && replay->front().position == 3);
        CHECK(tail && !tail->baseline && tail->events.size() == 1 && tail->events.front().position == 3);
    }
    commit(source, gate, scope, "key", std::nullopt, 4, now + 10min); // Exact age boundary still prunes physically on write.
    {
        const std::lock_guard lock(*gate);
        CHECK(source.replay(2).error() == Source::Error::History);
        const auto replay = source.replay(3);
        CHECK(replay && replay->size() == 1 && replay->front().position == 4 && !replay->front().record);
    }
}

/// Whole-source replacement preserves old state after interrupted/duplicate preparation, without partially publishing a baseline by Scope.
void snapshot() {

    const auto gate = std::make_shared<std::shared_mutex>();
    Source replica(gate, measure, false);
    const auto now = std::chrono::steady_clock::now();
    commit(replica, gate, {"old", "scope"}, "key", record(1), 1, now);
    const auto old = [&] { const std::lock_guard lock(*gate); return replica.capture(); }();
    auto draft = replica.prepare(20); // Fill private Scope data outside target gate without exposing partial target state.
    CHECK(draft.set({"new", "first"}, "one", record(9)));
    CHECK(draft.set({"new", "second"}, "two", record(7)));
    const auto duplicate = draft.set({"new", "first"}, "one", record(99));
    CHECK(!duplicate && duplicate.error() == Source::Error::Duplicate);
    {
        std::optional<Source::Replaced> retired;
        const std::lock_guard lock(*gate);
        CHECK(replica.position() == 1 && replica.capture().size() == 1);
        auto result = replica.reset(std::move(draft));
        CHECK(result);
        retired.emplace(std::move(*result));
        CHECK(replica.position() == 20 && replica.capture().size() == 2);
        CHECK(!replica.find({"old", "scope"}, "key") && replica.find({"new", "first"}, "one")->version == 9);
    }
    old.each([](const Scope& scope, const auto& key, const auto& value) { CHECK(scope.sector == "old" && key == "key" && value.version == 1); });
    commit(replica, gate, {"new", "second"}, "two", record(8), 21, now);
    auto stale = replica.prepare(19);
    auto empty = replica.prepare(22);
    {
        std::optional<Source::Replaced> retired;
        const std::lock_guard lock(*gate);
        CHECK(replica.reset(std::move(stale)).error() == Source::Error::Version);
        CHECK(replica.position() == 21);
        auto result = replica.reset(std::move(empty));
        CHECK(result);
        retired.emplace(std::move(*result));
        CHECK(replica.position() == 22 && replica.capture().size() == 0 && replica.next() == 23);
    }
    auto exhausted = replica.prepare(UINT64_MAX); // Maximum source position cannot reset through a new Scope or empty baseline.
    {
        std::optional<Source::Replaced> retired;
        const std::lock_guard lock(*gate);
        auto result = replica.reset(std::move(exhausted));
        CHECK(result);
        retired.emplace(std::move(*result));
        CHECK(replica.next().error() == Source::Error::Version);
        const auto rejected = replica.prepare({"new", "scope"}, "key", record(1), 0, now);
        CHECK(!rejected && rejected.error() == Source::Error::Version);
    }
}

/// Ephemeris shares sequencing but retains separate native payloads, without a common serialized KV body.
void native() {

    constexpr std::string_view uuid("\0\0\0\0\0\0\x40\0\x80\0\0\0\0\0\0\x09", 16); // Binary keys still validate UUID version/variant and reject text aliases.
    using ESource = astra::Origin<Ephemeris::Record, true>;                        // Alias keeps template commas outside the single-argument CHECK macro.
    const auto gate = std::make_shared<std::shared_mutex>();
    ESource source(gate, measure, true);
    const auto now = std::chrono::steady_clock::now();
    const Ephemeris::Record initial{std::make_shared<const Ephemeris::Buffer>(3), std::make_shared<const Ephemeris::Buffer>(7), Clock::Time(10s), 0, 0, 1000};
    std::optional<ESource::View> frozen;
    {
        ESource::Retired retired;
        const std::lock_guard lock(*gate);
        auto edit = source.prepare({"services", "main"}, uuid, initial, 1, now);
        CHECK(edit);
        retired = edit->commit();
        frozen = source.capture();
    }
    {
        ESource::Retired retired;
        const std::lock_guard lock(*gate);
        auto next = initial; // Renewal shares bodies while old snapshots retain original deadlines.
        next.deadline = Clock::Time(20s);
        next.renewal = 1;
        auto edit = source.prepare({"services", "main"}, uuid, next, 2, now, ESource::Form::Renew);
        CHECK(edit);
        retired = edit->commit();
        CHECK(source.replay(1)->front().form == ESource::Form::Renew);
    }
    frozen->each([&](const auto&, const auto&, const auto& value) {
        CHECK(value.attr == initial.attr && value.data == initial.data && value.deadline == initial.deadline && value.renewal == 0);
    });
}

/// Unsequenced internal watermark COW batches preserve old directories/versions on failure or discard.
void batch() {

    const auto gate = std::make_shared<std::shared_mutex>();
    Source source(gate, measure, false, {.records = 3});
    const auto now = std::chrono::steady_clock::now();
    const astra::Scope scope{"one", "scope"};
    commit(source, gate, scope, "one", record(1), 1, now);
    const auto frozen = [&] { const std::lock_guard lock(*gate); return source.capture(); }();
    {
        const std::lock_guard lock(*gate);
        auto candidate = source.prepare();
        CHECK(candidate.set(scope, "one", record(9)));
        CHECK(candidate.set({"new", "scope"}, "two", record(2)));
        CHECK(candidate.find(scope, "one")->version == 9);
        CHECK(candidate.set(scope, "one", record(10)).error() == Source::Error::Duplicate);
    }
    {
        std::optional<Source::Tree> retired;
        const std::lock_guard lock(*gate);
        CHECK(source.position() == 1 && source.capture().size() == 1);
        CHECK(source.find(scope, "one")->version == 1 && !source.find({"new", "scope"}, "two"));
        auto candidate = source.prepare();
        CHECK(candidate.set(scope, "one", record(9)));
        CHECK(candidate.set({"new", "scope"}, "two", record(2)));
        retired.emplace(candidate.commit());
        CHECK(source.position() == 1 && source.capture().size() == 2);
        CHECK(source.find(scope, "one")->version == 9);
    }
    frozen.each([](const auto&, const auto& key, const auto& value) { CHECK(key == "one" && value.version == 1); });
}

/// Views retain independent completion locks after source destruction, including COW/callback exception synchronization.
void lifetime() {

    const auto gate = std::make_shared<std::shared_mutex>();
    std::optional<Source::View> frozen;
    {
        Source source(gate, measure, true);
        const auto now = std::chrono::steady_clock::now();
        commit(source, gate, {"one", "scope"}, "key", record(1), 1, now);
        frozen = [&] { const std::lock_guard lock(*gate); return source.capture(); }();
        frozen->each([&](const auto&, const auto&, const auto&) {
            commit(source, gate, {"one", "scope"}, "key", record(2), 2, now); // Callbacks run outside commit lock and permit reentry.
        });
    }
    frozen->each([](const auto&, const auto& key, const auto& value) { CHECK(key == "key" && value.version == 1); });
    bool thrown{};
    try {
        frozen->each([](const auto&, const auto&, const auto&) { throw std::runtime_error("reader"); });
    } catch (const std::runtime_error&) {
        thrown = true;
    }
    CHECK(thrown);
    const std::lock_guard lock(*gate); // Exception exit leaves no locked Fence.
}

/// Batch deletion reuses slots without aliasing old keys to new data; discard restores directories and commit does not confirm source-wide completion.
void removal() {

    const auto gate = std::make_shared<std::shared_mutex>();
    Source source(gate, measure, false, {.records = 1}); // Full-capacity replacement deletes before adding.
    const Scope scope{"a", "main"};
    commit(source, gate, scope, "old", record(1), 1, std::chrono::steady_clock::now());
    {
        const std::lock_guard lock(*gate);
        auto batch = source.prepare();
        CHECK(batch.erase(scope, "old") && batch.set(scope, "new", record(2)));
        CHECK(!batch.find(scope, "old") && batch.find(scope, "new")->version == 2);
        CHECK(batch.set(scope, "old", record(3)).error() == Source::Error::Duplicate);
    }
    {
        std::optional<Source::Tree> retired;
        const std::lock_guard lock(*gate);
        CHECK(source.find(scope, "old") && !source.find(scope, "new"));
        auto batch = source.prepare();
        CHECK(batch.erase(scope, "old") && batch.set(scope, "new", record(2)));
        retired.emplace(batch.commit());
        CHECK(!source.find(scope, "old") && source.find(scope, "new") && source.position() == 1);
        CHECK(source.confirm(2) && !source.confirm(1));
        std::size_t count{}; // Per-Scope traversal visits no other Scope.
        source.each(scope, [&](const auto&, const auto&) { ++count; });
        CHECK(count == 1 && source.scopes() == std::vector<Scope>{scope});
    }
}

} // namespace

int main() {

    try {
        scopes();
        rollback();
        history();
        retention();
        snapshot();
        native();
        lifetime();
        batch();
        removal();
        std::cout << "source commits: ok\n";
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
