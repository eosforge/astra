// Verify scoped view publication and replay across atomic batch boundaries.
#include "catalog_state.hpp"
#include "check.hpp"

#include <iostream>
#include <new>

namespace {
using State = astra::Catalog::State;
using Scene = State::Projection;
using Content = State::Content;
using Source = State::Source;

/// Real source Name type; probes the public Item noexcept commit contract.
template <typename Item>
concept Accepted = requires { typename astra::Scene<Item, Source::Name>; };

/// Potentially throwing string copies fail at the type boundary.
static_assert(Accepted<Content> && !Accepted<std::string>);

/// Measure the actual content type without network/time dependencies.
std::size_t measure(const Content& record) noexcept {
    return record.value->size();
}

/// Shared fixture address; old names must survive independently of source lifetime.
Source::Tree::Key name(std::string key) {
    return std::make_shared<const Source::Name>(std::make_shared<const astra::Scope>("route", "main"), std::move(key));
}

/// Public record contains only version/opaque bytes, without hidden TTL/source position.
Content record(std::uint64_t version) {
    return {version, std::make_shared<const astra::Catalog::Buffer>(16, static_cast<std::uint8_t>(version))};
}

/// Multi-target atomic replacement: failure/discard publishes no root/cursor/deletion or directory capacity.
void atomic() {

    const auto gate = std::make_shared<std::shared_mutex>();
    Scene scene(gate, measure, {.records = 2});
    const auto now = std::chrono::steady_clock::now();
    const auto one = name("one"), two = name("two"), three = name("three");
    std::optional<Scene::View> frozen;
    {
        Scene::Retired retired;
        const std::lock_guard lock(*gate);
        auto edit = scene.prepare(one, record(1), now);
        CHECK(edit);
        retired = edit->commit();
        frozen.emplace(scene.capture());
    }
    {
        const std::lock_guard lock(*gate);
        {
            auto batch = scene.prepare(4096);
            CHECK(batch.set(one, {}, now));
            CHECK(batch.set(two, record(2), now));
            CHECK(batch.set(three, record(3), now)); // Deleted-slot reuse cannot mutate old roots.
        }
        CHECK(scene.capture().version() == 1 && scene.capture().size() == 1);
        CHECK(scene.find("one").record && !scene.find("two").record && !scene.find("three").record);
        CHECK(scene.replay(0)->size() == 1);
    }
    std::optional<Scene::Batch::Retired> retired; // Reclaim old trees/history outside gate after commit.
    {
        const std::lock_guard lock(*gate);
        auto batch = scene.prepare(4096);
        CHECK(batch.find("one").record && !batch.find("two").record);
        CHECK(batch.set(one, {}, now));
        CHECK(batch.set(two, record(2), now));
        CHECK(!batch.find("two").record); // New directories cannot resolve old keys to reused-slot content.
        CHECK(batch.set(three, record(3), now));
        retired.emplace(batch.commit());
        CHECK(scene.capture().version() == 4 && scene.capture().size() == 2);
        CHECK(!scene.find("one").record && scene.find("two").record->version == 2 && scene.find("three").record->version == 3);
        CHECK(retired->events.size() == 3 && retired->events[0].version == 2 && retired->events[2].version == 4);
        CHECK(scene.replay(1)->size() == 3);
    }
    frozen->each([](const auto& key, const Content& content) { CHECK(key == "one" && content.version == 1); });
}

/// Duplicate targets, capacity, and zero history fail without relying on assertions to compensate partial publication.
void limits() {

    const auto gate = std::make_shared<std::shared_mutex>();
    Scene scene(gate, measure, {.records = 1, .history = 0});
    const auto now = std::chrono::steady_clock::now();
    const auto one = name("one"), two = name("two");
    {
        const std::lock_guard lock(*gate);
        {
            auto batch = scene.prepare(0);
            CHECK(batch.set(one, record(1), now));
            CHECK(!batch.set(one, record(2), now));
        }
        CHECK(scene.capture().version() == 0 && scene.capture().size() == 0);
        {
            auto batch = scene.prepare(0);
            CHECK(batch.set(one, record(1), now));
            CHECK(!batch.set(two, record(2), now));
        }
        CHECK(scene.capture().version() == 0 && scene.capture().size() == 0);
    }
    std::optional<Scene::Batch::Retired> retired;
    {
        const std::lock_guard lock(*gate);
        auto batch = scene.prepare(0);
        CHECK(batch.set(one, record(5), now));
        retired.emplace(batch.commit());
        CHECK(scene.capture().version() == 1 && scene.history() == 0);
        CHECK(scene.replay(0).error() == Scene::Error::History);
        CHECK(retired->events.size() == 1 && retired->events[0].record->version == 5); // Notifications cannot depend on replaying pruned history.
    }
}

/// Unpruned old history remains recoverable; single/batch writes prune at the same age boundary without losing deletions.
void history(bool batch) {

    const auto gate = std::make_shared<std::shared_mutex>();
    Scene scene(gate, measure, {});
    const auto now = std::chrono::steady_clock::now();
    const auto stored = now - std::chrono::hours(1); // Initial events are already old, with no later write yet triggering pruning.
    const auto change = [&](std::uint64_t version, std::chrono::steady_clock::time_point stamp) {
        // Version zero denotes deletion; other values are public content versions. Stamp controls retention only, never business TTL.
        Scene::Retired retired;                        // Release single-item notification/old content after unlock.
        std::optional<Scene::Batch::Retired> replaced; // Release swapped batch pages/history outside lock too.
        const std::lock_guard lock(*gate);
        const auto value = version ? std::optional(record(version)) : std::nullopt; // Deletion gets its own contiguous cursor.
        if (batch) {
            auto edit = scene.prepare(4096);
            CHECK(edit.set(name("key"), value, stamp));
            replaced.emplace(edit.commit());
        } else {
            auto edit = scene.prepare(name("key"), value, stamp);
            CHECK(edit);
            retired = edit->commit();
        }
    };
    change(1, stored);
    change(0, stored);
    {
        const std::lock_guard lock(*gate);
        const auto replay = scene.replay(0); // Even after one idle hour, retained creation/deletion form a complete suffix.
        CHECK(replay && replay->size() == 2 && replay->front().record && !replay->back().record);
        CHECK(replay->front().version == 1 && replay->back().version == 2 && replay->front().stored == stored);
        CHECK(scene.replay(2)->empty() && scene.replay(3).error() == Scene::Error::Version);
        CHECK(scene.capture().size() == 0); // Replay reads history without writing deleted content back into projection.
    }

    change(3, now); // A new write prunes creation/deletion; missing versions cannot be bridged into false complete replay.
    {
        const std::lock_guard lock(*gate);
        CHECK(scene.replay(0).error() == Scene::Error::History && scene.replay(1).error() == Scene::Error::History);
        const auto replay = scene.replay(2); // A reader at the old deletion boundary can continue with the new creation.
        CHECK(replay && replay->size() == 1 && replay->front().version == 3 && replay->front().record);
    }
    change(0, now + std::chrono::minutes(10)); // Writes at exact retention age still prune.
    {
        const std::lock_guard lock(*gate);
        CHECK(scene.replay(2).error() == Scene::Error::History);
        const auto replay = scene.replay(3);
        CHECK(replay && replay->size() == 1 && replay->front().version == 4 && !replay->front().record);
    }
}

/// After all external/history references vanish, current records remain findable/replaceable and deletion releases Name; cover short/max-length keys.
void ownership(const std::string& key, Scene::Limits limits) {

    // Shared gate; limits separately disable history count, bytes, or age. Fixed now avoids real waits.
    const auto gate = std::make_shared<std::shared_mutex>();
    Scene scene(gate, measure, limits);
    const auto now = std::chrono::steady_clock::now();
    std::weak_ptr<const Source::Name> observed; // Weakly observes the original Name without extending production ownership.
    {
        Scene::Retired retired; // Release notifications after unlock so they cannot hide missing tree ownership.
        const std::lock_guard lock(*gate);
        auto original = name(key); // Name owns characters independently of caller key storage.
        observed = original;
        auto edit = scene.prepare(std::move(original), record(1), now);
        CHECK(edit && !original);
        retired = edit->commit();
        CHECK(scene.history() == 0);
        CHECK(scene.replay(0).error() == Scene::Error::History && scene.replay(1)->empty()); // Zero budget truly retains no newly committed history.
    }
    CHECK(!observed.expired()); // Only the active tree retains Name after caller/Event ownership is released.

    {
        Scene::Retired retired;
        const std::lock_guard lock(*gate);
        const auto before = scene.find(key);
        CHECK(before.record && before.record->version == 1);
        auto edit = scene.prepare(name(key), record(2), now); // Equal text at a different address reuses the original Name.
        CHECK(edit);
        retired = edit->commit();
        const auto after = scene.find(key); // Point lookup sees new content while outer history remains empty.
        CHECK(scene.history() == 0 && after.record && after.record->version == 2);
    }
    CHECK(!observed.expired());

    {
        Scene::Retired retired; // Deletion-notification release removes the final Name owner.
        const std::lock_guard lock(*gate);
        auto edit = scene.prepare(name(key), {}, now);
        CHECK(edit);
        retired = edit->commit();
        CHECK(!scene.find(key).record && scene.capture().size() == 0 && scene.history() == 0);
    }
    CHECK(observed.expired()); // Detect Name leaks that could mask dangling borrows.
}

/// Caller throws after prepare/move; destruction of both original/moved transactions leaves no partial entry, leaked Name, or permanent editing flag.
void rollback() {

    // Fresh Scene per single Edit/Batch case isolates capacity/cursor state.
    for (const bool batch : {false, true}) {
        const auto gate = std::make_shared<std::shared_mutex>();  // Outer domain lock outlives the transaction.
        Scene scene(gate, measure, {.records = 1, .history = 0}); // One-key limit exposes temporary directory leaks.
        const auto now = std::chrono::steady_clock::now();
        std::weak_ptr<const Source::Name> observed; // Failed transactions cannot retain unpublished names.
        bool caught{};                              // Require the explicit caller exception, not silent return.
        bool raised{};                              // Set only after successful prepare/move, excluding accidental earlier allocation failure.
        try {
            const std::lock_guard lock(*gate);
            auto original = name("pending");
            observed = original;
            if (batch) {
                auto prepared = scene.prepare(0);
                CHECK(prepared.set(std::move(original), record(1), now));
                [[maybe_unused]] auto active = std::move(prepared); // Only the moved-to candidate owns rollback; original destruction must not repeat it.
                raised = true;
                throw std::bad_alloc{};
            }
            auto prepared = scene.prepare(std::move(original), record(1), now);
            CHECK(prepared);
            [[maybe_unused]] auto active = std::move(*prepared); // Also destroys the moved-from empty transaction inside expected.
            raised = true;
            throw std::bad_alloc{};
        } catch (const std::bad_alloc&) {
            caught = true;
        }
        CHECK(caught && raised && observed.expired());

        Scene::Retired retired; // Release successful recovery notifications outside domain lock.
        const std::lock_guard lock(*gate);
        CHECK(scene.capture().version() == 0 && scene.capture().size() == 0);
        const auto replay = scene.replay(0); // After rollback, explicitly validate the empty-history result before inspecting its container.
        CHECK(!scene.find("pending").record && scene.history() == 0 && replay && replay->empty());
        auto edit = scene.prepare(name("next"), record(2), now); // Successful later insertion proves editing/capacity restoration.
        CHECK(edit);
        retired = edit->commit();
        const auto next = scene.find("next"); // After publication, content and cursor can continue advancing.
        CHECK(scene.capture().version() == 1 && next.record && next.record->version == 2);
    }
}
} // namespace

/// Projection preparation/publication component checks, separate from multi-Star replication acceptance.
int main() {

    try {
        atomic();
        limits();
        history(false);
        history(true);
        // Short and heap-backed long keys under all three zero-history limits must remain owned by the active tree.
        for (const auto& key : {std::string("s"), std::string(1024, 'k')}) {
            ownership(key, {.history = 0});
            ownership(key, {.backlog = 0});
            ownership(key, {.retention = std::chrono::steady_clock::duration::zero()});
        }
        rollback();
        std::cout << "projection batch: ok\n";
        return 0;
    } catch (const std::exception& failure) {
        std::cerr << failure.what() << '\n';
        return 1;
    }
}
