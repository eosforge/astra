// Apply remote Ephemeris sources while preserving ownership and local expiry semantics.
#include "ephemeris_state.hpp"
#include <astra/profile.hpp>

namespace astra {
Ephemeris::State::Guard Ephemeris::State::acquire(std::string_view id, std::unique_lock<std::shared_mutex>& domain) const {

    const auto found = replicas_.find(id); // Use directory iterators only under domain lock; the guard retains source ownership.
    Guard result(found == replicas_.end() ? nullptr : found->second, domain);
    const auto current = replicas_.find(id); // The source may retire while waiting; an old object cannot become a newly admitted source.
    if (current == replicas_.end() || current->second.get() != result.get()) {
        return Guard(nullptr, domain);
    }
    return result;
}

Ephemeris::State::Projection* Ephemeris::State::locate(const Scope& scope) {
    return Context<State>::locate(*this, scope);
}

std::expected<void, Ephemeris::State::Error> Ephemeris::State::admit(std::string_view id) {

    if (!Scope::text(id, 1024)) {
        return std::unexpected(Error::Input);
    }
    const std::lock_guard lock(*gate_);
    if (const auto existing = replicas_.find(id); existing != replicas_.end()) {
        return existing->second->retired ? std::unexpected(Error::Obsolete) : std::expected<void, Error>{};
    }
    if (replicas_.size() == limits_.replicas) {
        return std::unexpected(Error::Capacity);
    }
    auto replica = std::make_shared<Replica>(gate_, limits_.source);
    replicas_.emplace(std::string(id), std::move(replica));
    return {};
}

void Ephemeris::State::retire(std::string_view id) {

    ASTRA_PROFILE_SCOPE("star.ephemeris_replica.Ephemeris.State.retire");
    ASTRA_PROFILE_BEGIN(profileLock53, "star.ephemeris_replica.Ephemeris.State.retire.wait.lock");
    const std::lock_guard lock(*gate_);
    ASTRA_PROFILE_END(profileLock53);
    const auto found = replicas_.find(id);
    if (found != replicas_.end()) {
        found->second->retired = true;
        due_ = Clock::Time{};
        found->second->coverage.clear(); // Stop installing old tasks; a confirmed retired identity need not wait for the old prefix to catch up.
    }
}

std::expected<std::uint64_t, Ephemeris::State::Error> Ephemeris::State::received(std::string_view id) const {
    std::unique_lock lock(*gate_);
    auto borrowed = acquire(id, lock); // Wait for the source outside the local commit lock.
    return !borrowed.get() ? std::expected<std::uint64_t, Error>(std::unexpected(Error::Input)) : borrowed.get()->source.position();
}

std::expected<Ephemeris::State::Source::Draft, Ephemeris::State::Error> Ephemeris::State::prepare(std::string_view id, std::uint64_t position) {

    ASTRA_PROFILE_SCOPE("star.ephemeris_replica.Ephemeris.State.prepare");

    ASTRA_PROFILE_BEGIN(profileLock70, "star.ephemeris_replica.Ephemeris.State.prepare.wait.lock");
    std::unique_lock lock(*gate_);
    ASTRA_PROFILE_END(profileLock70);
    auto borrowed = acquire(id, lock); // Wait for the source outside the local commit lock.
    if (!borrowed.get()) {
        return std::unexpected(Error::Input);
    }
    if (borrowed.get()->retired) {
        return std::unexpected(Error::Obsolete);
    }
    if (position < borrowed.get()->source.position() || std::ranges::any_of(borrowed.get()->coverage, [position](const Replica::Coverage& value) { return value.position > position; })) {
        return std::unexpected(Error::Obsolete);
    }
    return borrowed.get()->source.prepare(position);
}

std::expected<std::optional<Ephemeris::Record>, Ephemeris::State::Error> Ephemeris::State::replica(std::string_view id, const Scope& scope, std::string_view uuid) const {

    ASTRA_PROFILE_SCOPE("star.ephemeris_replica.Ephemeris.State.replica");

    if (!scope.valid() || !Ephemeris::valid(uuid)) {
        return std::unexpected(Error::Input);
    }
    ASTRA_PROFILE_BEGIN(profileLock89, "star.ephemeris_replica.Ephemeris.State.replica.wait.lock");
    std::unique_lock lock(*gate_);
    ASTRA_PROFILE_END(profileLock89);
    auto borrowed = acquire(id, lock); // Wait for the source outside the local commit lock.
    if (!borrowed.get()) {
        return std::unexpected(Error::Input);
    }
    return borrowed.get()->source.find(scope, uuid); // Final apply advances local TTL first; this earlier reading cannot guarantee liveness.
}

std::expected<Ephemeris::State::Point, Ephemeris::State::Error> Ephemeris::State::resolve(const Scope& scope, std::string_view key) {

    if (!scope.valid() || !Ephemeris::valid(key)) {
        return std::unexpected(Error::Input);
    }
    const std::shared_lock lock(*export_); // Read local-source facts and contiguous position; receivers evaluate original absolute deadlines.
    return Point{source_.position(), source_.find(scope, key)};
}

std::expected<bool, Ephemeris::State::Error> Ephemeris::State::covered(std::string_view id, std::uint64_t position, const Scope& scope, std::string_view key) {

    if (!scope.valid() || !Ephemeris::valid(key) || position == 0) {
        return std::unexpected(Error::Input);
    }
    Source::Retired retired;
    std::unique_lock lock(*gate_);
    auto borrowed = acquire(id, lock); // Wait for the source outside the local commit lock.
    if (!borrowed.get()) {
        return std::unexpected(Error::Input);
    }
    auto& replica = *borrowed.get();
    if (replica.retired) {
        return std::unexpected(Error::Obsolete);
    }
    if (position <= replica.source.position()) {
        return true;
    }
    if (replica.source.position() == UINT64_MAX || position != replica.source.position() + 1) {
        return std::unexpected(Error::History);
    }
    if (std::ranges::none_of(replica.coverage, [&](const Replica::Coverage& value) { return *value.name->scope == scope && (value.name->key.empty() || value.name->key == key) && value.position >= position; })) {
        return false;
    }
    // Check coverage before requesting repair, including when native bodies expired but Data/Renew events were already covered.
    auto skipped = replica.source.prepare(scope, key, replica.source.find(scope, key), position, std::chrono::steady_clock::now());
    if (!skipped) {
        return std::unexpected(error(skipped.error()));
    }
    retired = skipped->commit();
    std::erase_if(replica.coverage, [position](const Replica::Coverage& value) { return value.position <= position; });
    return true;
}

std::expected<void, Ephemeris::State::Error> Ephemeris::State::apply(std::string_view id, std::uint64_t position, const Scope& scope, std::string_view uuid, std::optional<Record> record, Source::Form form) {
    return receive(id, position, scope, uuid, std::move(record), form, false);
}

std::expected<void, Ephemeris::State::Error> Ephemeris::State::repair(std::string_view id, std::uint64_t position, const Scope& scope, std::string_view uuid, std::optional<Record> record) {

    ASTRA_PROFILE_SCOPE("star.ephemeris_replica.Ephemeris.State.repair");
    const auto form = record ? Source::Form::Record : Source::Form::Erase;
    return receive(id, position, scope, uuid, std::move(record), form, true);
}

std::expected<void, Ephemeris::State::Error> Ephemeris::State::receive(std::string_view id, std::uint64_t position, const Scope& scope, std::string_view uuid, std::optional<Record> record, Source::Form form, bool repair) {

    ASTRA_PROFILE_SCOPE("star.ephemeris_replica.Ephemeris.State.receive");

    if (!scope.valid() || !Ephemeris::valid(uuid) || position == 0 || (record && (!Ephemeris::valid(*record) || record->deadline.time_since_epoch().count() == 0)) || (form == Source::Form::Erase) != !record) {
        return std::unexpected(Error::Input);
    }
    std::vector<Retired> expired;
    Retired retired;
    ASTRA_PROFILE_BEGIN(profileLock156, "star.ephemeris_replica.Ephemeris.State.receive.wait.lock");
    std::unique_lock lock(*gate_);
    ASTRA_PROFILE_END(profileLock156);
    auto borrowed = acquire(id, lock); // Wait for the source outside the local commit lock.
    if (!borrowed.get()) {
        return std::unexpected(Error::Input);
    }
    auto& replica = *borrowed.get();
    if (replica.retired) {
        return std::unexpected(Error::Obsolete);
    }
    if (position <= replica.source.position()) {
        return {}; // Replay of an installed prefix changes neither deadline nor projection.
    }
    if (!repair && (replica.source.position() == UINT64_MAX || position != replica.source.position() + 1)) {
        return std::unexpected(Error::History);
    }
    auto index = replica.coverage.size(); // Store indices rather than iterators across reserve; size means no match.
    std::uint64_t covered{};              // Highest source position covered for this target by a Scope or targeted repair.
    std::size_t targets{};                // Count only exact targets against the 128-item quota, excluding Scope markers.
    // One pass finds the target, Scope coverage, and exact-target count; retain stable indices across growth.
    for (std::size_t item = 0; item < replica.coverage.size(); ++item) {
        const auto& value = replica.coverage[item];
        targets += !value.name->key.empty();
        if (*value.name->scope != scope) {
            continue;
        }
        if (value.name->key == uuid) {
            index = item;
        }
        if (value.name->key.empty() || value.name->key == uuid) {
            covered = std::max(covered, value.position);
        }
    }
    const bool precise = index != replica.coverage.size(); // Later reserve cannot leave this decision dependent on an invalidated iterator.
    if (covered >= position) {
        if (!repair) {
            // Repair R cannot skip other targets. Older events for this target advance the group prefix individually without changing records or leases.
            auto skipped = replica.source.prepare(scope, uuid, replica.source.find(scope, uuid), position, std::chrono::steady_clock::now());
            if (!skipped) {
                return std::unexpected(error(skipped.error()));
            }
            retired.source = skipped->commit();
            std::erase_if(replica.coverage, [&](const Replica::Coverage& value) { return value.position <= position; });
        }
        return {};
    }
    if (repair && !precise && targets >= 128) {
        return std::unexpected(Error::Capacity);
    }
    auto stamp = reading();
    if (!stamp) {
        return std::unexpected(stamp.error());
    }
    advance(replica, stamp->time, expired); // With the source locked, process old deadlines before preparing new facts.
    advance(stamp->time, expired, &replica);
    const auto old = replica.source.find(scope, uuid);
    if (!old && (form == Source::Form::Data || form == Source::Form::Renew)) {
        return std::unexpected(Error::Ended); // Partial fields cannot create an incomplete registration; require targeted full repair.
    }
    if (old && record) {
        if (!Ephemeris::follows(*old, *record)) {
            return std::unexpected(Error::Conflict);
        }
        if ((form == Source::Form::Data && (record->update <= old->update || record->renewal != old->renewal || record->generation != old->generation || record->deadline < old->deadline)) || (form == Source::Form::Renew && (record->renewal <= old->renewal || record->update != old->update || *record->data != *old->data || record->deadline < old->deadline))) {
            return std::unexpected(Error::Obsolete);
        }
    }
    if (record && record->deadline <= stamp->time) {
        record.reset(); // Late complete facts still confirm contiguous position without granting a new TTL or exposing expired registrations.
    }
    auto* scene = locate(scope);
    const auto visible = scene ? scene->find(uuid) : Projection::Point{};
    Pending pending{*this, scope}; // Rolls back new projection directories only; owns no local-wheel node.
    if (record && !scene) {
        const auto located = obtain(scope);
        if (!located) {
            return std::unexpected(located.error());
        }
        scene = *located;
        pending.created = true;
    }
    const auto before = scene ? scene->history() : 0;
    const auto retention = scene ? allowance(*scene) : 0;
    const auto bytes = replica.source.bytes();
    auto origin = replica.source.prepare(scope, uuid, record, repair ? std::nullopt : std::optional(position), std::chrono::steady_clock::now());
    if (!origin) {
        return std::unexpected(error(origin.error()));
    }
    if (origin->bytes() > limits_.replicaBytes || replicaBytes_ - bytes > limits_.replicaBytes - origin->bytes()) {
        return std::unexpected(Error::Capacity);
    }
    auto choice = choose(origin->name(), record, &replica, stamp->time);
    if (!choice) {
        return std::unexpected(choice.error());
    }
    std::optional<Projection::Edit> projection;
    if (choice->changed) {
        auto prepared = scene->prepare(choice->name, choice->content(), std::chrono::steady_clock::now(), choice->record.has_value() && visible.record.has_value(), retention);
        if (!prepared) {
            return std::unexpected(error(prepared.error()));
        }
        projection.emplace(std::move(*prepared));
    }
    const auto timer = replica.timers.find(origin->name().get());
    Timer* hook = timer == replica.timers.end() ? nullptr : timer->second.get(); // Acquire stable nodes before reserve, without retaining invalidatable iterators.
    std::unique_ptr<Timer> prepared;                                             // Allocate new nodes before final time sampling, outside the active table.
    if (record && !hook) {
        if (!replica.agenda) {
            replica.agenda = std::make_unique<Agenda>(stamp->time);
            due_ = std::min(due_, replica.agenda->next()); // Include a newly created wheel in the shared next-boundary calculation immediately.
        }
        prepared = std::make_unique<Timer>(origin->name());
        replica.timers.reserve(replica.timers.size() + 1);
    }
    std::optional<Replica::Coverage> preparedCoverage; // Prepare coverage evidence with bodies before installation, not afterward.
    if (repair && !precise) {
        replica.coverage.reserve(replica.coverage.size() + 1);
        preparedCoverage.emplace(origin->name(), position);
    }
    stamp = reading();
    if (!stamp) {
        return std::unexpected(stamp.error());
    }
    if ((record && record->deadline <= stamp->time) || (choice->record && choice->record->deadline <= stamp->time)) {
        return std::unexpected(Error::Ended); // If expiration occurs during preparation, abandon the candidate and recover from current state.
    }

    // Hook insertion is the final allocating operation; only noexcept commit/schedule/notification follows.
    if (prepared) {
        hook = prepared.get();
        replica.timers.emplace(origin->name().get(), std::move(prepared));
    }
    retired.source = origin->commit();
    if (projection) {
        retired.scene = projection->commit();
    }
    replicaBytes_ = replicaBytes_ - bytes + replica.source.bytes();
    if (record) {
        replica.agenda->set(*hook, record->deadline);
    } else if (hook) {
        Agenda::erase(*hook);
        const auto removed = replica.timers.find(retired.source.name.get());
        retired.timer = std::move(removed->second);
        replica.timers.erase(removed);
    }
    choice->commit();
    if (preparedCoverage) {
        replica.coverage.push_back(std::move(*preparedCoverage));
    } else if (repair) {
        replica.coverage[index].position = position;
    } else {
        std::erase_if(replica.coverage, [&](const Replica::Coverage& value) { return value.position <= position; });
    }
    pending.committed = true;
    if (projection) {
        publish(*scene, before, retired.scene.event);
    }
    return {};
}

std::expected<Ephemeris::State::Recovery, Ephemeris::State::Error> Ephemeris::State::restore(std::string_view id, Source::Draft&& draft) {

    ASTRA_PROFILE_SCOPE("star.ephemeris_replica.Ephemeris.State.restore");

    ASTRA_PROFILE_BEGIN(profileLock316, "star.ephemeris_replica.Ephemeris.State.restore.wait.lock");
    std::unique_lock lock(*gate_);
    ASTRA_PROFILE_END(profileLock316);
    auto borrowed = acquire(id, lock); // Wait for the source outside the local commit lock.
    if (!borrowed.get()) {
        return std::unexpected(Error::Input);
    }
    auto& replica = *borrowed.get();
    if (replica.retired || std::ranges::any_of(replica.coverage, [&](const Replica::Coverage& value) { return value.position > draft.position(); })) {
        return std::unexpected(Error::Obsolete);
    }
    const auto valid = replica.source.validate(draft);
    if (!valid) {
        return std::unexpected(error(valid.error()));
    }
    auto scopes = replica.source.scopes(); // Install an empty baseline for old Scopes absent from the new inventory, preventing leftover facts.
    auto incoming = draft.scopes();
    scopes.insert(scopes.end(), std::make_move_iterator(incoming.begin()), std::make_move_iterator(incoming.end()));
    std::ranges::sort(scopes);
    scopes.erase(std::unique(scopes.begin(), scopes.end()), scopes.end());
    return Recovery(*this, std::string(id), std::move(draft), std::move(scopes));
}

std::expected<void, Ephemeris::State::Error> Ephemeris::State::replace(std::string_view id, Source::Draft&& draft) {

    auto task = restore(id, std::move(draft));
    if (!task) {
        return std::unexpected(task.error());
    }
    for (;;) {
        const auto result = task->step(); // Unlock and reclaim old pages before starting the next Scope.
        if (!result) {
            return std::unexpected(result.error());
        }
        if (*result) {
            return {};
        }
    }
}

std::expected<void, Ephemeris::State::Error> Ephemeris::State::finish(std::string_view id, std::uint64_t position) {

    ASTRA_PROFILE_SCOPE("star.ephemeris_replica.Ephemeris.State.finish");

    ASTRA_PROFILE_BEGIN(profileLock350, "star.ephemeris_replica.Ephemeris.State.finish.wait.lock");
    std::unique_lock lock(*gate_);
    ASTRA_PROFILE_END(profileLock350);
    auto borrowed = acquire(id, lock); // Wait for the source outside the local commit lock.
    if (!borrowed.get()) {
        return std::unexpected(Error::Input);
    }
    auto& replica = *borrowed.get();
    if (replica.retired || std::ranges::any_of(replica.coverage, [position](const Replica::Coverage& value) { return value.position > position; }) || !replica.source.confirm(position)) {
        return std::unexpected(Error::Obsolete);
    }
    replica.coverage.clear(); // After every Scope completes, the contiguous prefix subsumes Scope coverage evidence.
    return {};
}

std::expected<void, Ephemeris::State::Error> Ephemeris::State::install(std::string_view id, const Source::Draft& draft, const Scope& scope) {

    ASTRA_PROFILE_SCOPE("star.ephemeris_replica.Ephemeris.State.install");

    // Reclaim large old source/projection roots and replaced group schedulers outside gate.
    std::optional<Source::Tree> oldSource;
    std::vector<std::unique_ptr<Timer>> oldTimers;      // Destroy replaced hooks outside the lock.
    std::optional<Projection::Batch::Retired> oldScene; // Release old projections and notification events after unlock.

    std::unordered_map<const Source::Name*, std::unique_ptr<Timer>> timers;
    std::vector<Retired> expired;
    ASTRA_PROFILE_BEGIN(profileLock370, "star.ephemeris_replica.Ephemeris.State.install.wait.lock");
    std::unique_lock lock(*gate_);
    ASTRA_PROFILE_END(profileLock370);
    auto borrowed = acquire(id, lock); // Wait for the source outside the local commit lock.
    if (!borrowed.get()) {
        return std::unexpected(Error::Input);
    }
    auto& replica = *borrowed.get();
    if (replica.retired) {
        return std::unexpected(Error::Obsolete);
    }
    if (draft.position() < replica.source.position() || std::ranges::any_of(replica.coverage, [&](const Replica::Coverage& value) { return value.position > draft.position(); })) {
        return std::unexpected(Error::Obsolete);
    }
    auto stamp = reading();
    if (!stamp) {
        return std::unexpected(stamp.error());
    }
    advance(replica, stamp->time, expired); // With the source locked, process old deadlines before preparing new facts.
    advance(stamp->time, expired, &replica);
    const auto bytes = replica.source.bytes();

    /// Separate exclusive source preparation from shared projection commit. Rows own names/immutable bodies without copying business bytes.
    struct Native {
        /// Stable names owned by native candidates, never request-borrowed string_views.
        Source::Tree::Key name;
        /// Complete native facts retain sender deadlines without renewing TTL.
        Record record;
    };

    std::vector<Source::Tree::Key> previous; // Enumerate old Scope entries under the source lock, outside the domain lock.
    std::vector<Native> rows;                // Own with the candidate; final merge need not query or validate input bodies again.
    std::optional<Source::Batch> origin;     // Establish lifetime before off-lock preparation; rollback or publish only after reacquiring domain.
    std::optional<Error> failure;            // Callback failure discards private preparation without publishing prepared rows.
    Guard::outside(lock, [&] {
        replica.source.each(scope, [&](const Source::Tree::Key& name, const Record&) { previous.push_back(name); });
        origin.emplace(replica.source.prepare());
        for (const auto& name : previous) {
            if (!draft.find(scope, name->key)) {
                const auto erased = origin->erase(scope, name->key);
                if (!erased) {
                    failure = error(erased.error());
                    return;
                }
            }
        }
        draft.each(scope, [&](const Source::Tree::Key& name, Record incoming) {
            if (failure) {
                return;
            }
            if (!Ephemeris::valid(name->key) || !Ephemeris::valid(incoming) || incoming.deadline.time_since_epoch().count() == 0) {
                failure = Error::Input;
                return;
            }
            const auto old = origin->find(scope, name->key);
            if (old && !Ephemeris::follows(*old, incoming)) {
                failure = Error::Conflict;
                return;
            }
            if (old) {
                incoming.attr = old->attr; // Fixed attributes were already fully compared; never rescan them under the final domain lock.
                if (old->data == incoming.data || *old->data == *incoming.data) {
                    incoming.data = old->data;
                }
            }
            auto native = origin->set(scope, name->key, incoming);
            if (!native) {
                failure = error(native.error());
                return;
            }
            timers.emplace(native->get(), std::make_unique<Timer>(*native));
            rows.push_back({*native, std::move(incoming)});
        });
    });
    if (failure) {
        return std::unexpected(*failure);
    }
    if (replica.retired) {
        return std::unexpected(Error::Obsolete); // Identity revocation during preparation takes precedence over publication.
    }
    stamp = reading(); // Local writes may advance watermarks, projections, or time; merge again against current state.
    if (!stamp) {
        return std::unexpected(stamp.error());
    }
    advance(stamp->time, expired, &replica); // Borrowed protects this source exclusively; other sources and merged projections may still expire.
    if (!timers.empty() && !replica.agenda) {
        replica.agenda = std::make_unique<Agenda>(stamp->time);
        due_ = std::min(due_, replica.agenda->next());
    }
    const auto scopeCoverage = std::ranges::find_if(replica.coverage, [&](const Replica::Coverage& value) { return *value.name->scope == scope && value.name->key.empty(); });
    if (scopeCoverage == replica.coverage.end() && std::ranges::count_if(replica.coverage, [](const Replica::Coverage& value) { return value.name->key.empty(); }) >= static_cast<std::ptrdiff_t>(limits_.source.scopes * 2)) {
        return std::unexpected(Error::Capacity);
    }
    auto marker = std::make_shared<const Source::Name>(std::make_shared<const Scope>(scope), std::string{}); // Empty key is an internal whole-Scope coverage marker.
    replica.coverage.reserve(replica.coverage.size() + 1);                                                   // Preallocate coverage before commit so recording it cannot fail afterward.

    /// Plan only real content changes; equal Attr/Data and lease-only updates preserve the public cursor.
    struct Change {
        /// Shares source or prior visible names, retaining temporary deletion targets too.
        Source::Tree::Key name;
        /// Absence means this source's public deletion.
        std::optional<Content> record;
        /// Data-only hint when Attr already exists.
        bool data{};
    };

    std::vector<Change> changes;
    std::vector<Choice> choices; // Prepare all logical IDs together with the Scope projection; failure rolls back everything.
    choices.reserve(previous.size() + rows.size());
    std::optional<Clock::Time> earliest;
    const auto select = [&](const Source::Tree::Key& name, std::optional<Record> record) -> std::expected<void, Error> {
        auto choice = choose(name, std::move(record), &replica, stamp->time);
        if (!choice) {
            return std::unexpected(choice.error());
        }
        if (choice->record) {
            earliest = earliest ? std::min(*earliest, choice->record->deadline) : choice->record->deadline;
        }
        if (choice->changed) {
            auto* scene = locate(*name->scope);
            const auto visible = scene ? scene->find(name->key) : Projection::Point{};
            changes.push_back({choice->name, choice->content(), visible.record.has_value() && choice->record.has_value()});
        }
        choices.push_back(std::move(*choice));
        return {};
    };
    for (const auto& name : previous) {
        const auto incoming = draft.find(*name->scope, name->key);
        if (incoming && incoming->deadline > stamp->time) {
            continue;
        }
        if (auto selected = select(name, {}); !selected) {
            return selected;
        }
    }
    for (const auto& row : rows) {
        if (row.record.deadline <= stamp->time) {
            continue;
        }
        if (auto selected = select(row.name, row.record); !selected) {
            return selected;
        }
    }

    // One COW batch candidate per Scope. On failure, destroy it before removing the new empty Scope; never copy the full public hash table.
    Pending pending{*this, scope}; // Directory rollback responsibility must outlive the batch candidate.
    std::optional<Projection::Batch> projection;
    auto history = history_; // Use the domain's remaining history allowance without changing other Scopes' history.
    if (!changes.empty()) {
        const auto count = scopes_;
        auto located = obtain(scope);
        if (!located) {
            return std::unexpected(located.error());
        }
        pending.created = scopes_ != count;
        auto& scene = **located;
        const auto before = scene.history();
        projection.emplace(scene.prepare(allowance(scene)));
        for (const auto& row : changes) {
            auto prepared = projection->set(row.name, row.record, std::chrono::steady_clock::now(), row.data);
            if (!prepared) {
                return std::unexpected(error(prepared.error()));
            }
        }
        history = history - before + projection->history();
    }
    if (origin->bytes() > limits_.replicaBytes || replicaBytes_ - bytes > limits_.replicaBytes - origin->bytes()) {
        return std::unexpected(Error::Capacity);
    }
    oldTimers.reserve(previous.size());
    replica.timers.reserve(replica.timers.size() + timers.size()); // Merge transfers preallocated nodes without constructing nodes or growing buckets during commit.
    stamp = reading();
    if (!stamp) {
        return std::unexpected(stamp.error());
    }
    if (earliest && *earliest <= stamp->time) {
        return std::unexpected(Error::Ended);
    }
    oldSource.emplace(origin->commit()); // Publish only this Scope, preserving the complete source prefix.

    if (projection) {
        oldScene.emplace(projection->commit());
    }
    for (const auto& name : previous) {
        const auto node = replica.timers.find(name.get());
        if (node != replica.timers.end()) {
            Agenda::erase(*node->second);
            oldTimers.push_back(std::move(node->second));
            replica.timers.erase(node);
        }
    }
    for (auto& [name, timer] : timers) {
        const auto record = replica.source.find(scope, name->key); // The committed native batch owns stable names referenced by the timer.
        replica.agenda->set(*timer, record->deadline);
    }
    replica.timers.merge(timers);
    std::erase_if(replica.coverage, [&](const Replica::Coverage& value) { return *value.name->scope == scope; });
    replica.coverage.push_back({std::move(marker), draft.position()});
    replicaBytes_ = replicaBytes_ - bytes + replica.source.bytes();
    history_ = history;
    for (auto& choice : choices) {
        choice.commit();
    }
    pending.committed = true;
    if (notify_ && oldScene) {
        for (const auto& event : oldScene->events) {
            notify_(context_, scope, event);
        }
    }
    return {};
}

void Ephemeris::State::advance(Replica& replica, Clock::Time now, std::vector<Retired>& retired) {

    ASTRA_PROFILE_SCOPE("star.ephemeris_replica.Ephemeris.State.advance");

    if (!replica.agenda) {
        return;
    }
    replica.agenda->advance(now, [&](Agenda::Node* hook, Clock::Time boundary) {
        auto& timer = *static_cast<Timer*>(hook);
        const auto old = replica.source.find(*timer.name->scope, timer.name->key);
        if (!old) {
            throw std::logic_error("Replica timer has no native record");
        }
        if (old->deadline > boundary) {
            replica.agenda->set(timer, old->deadline);
            return;
        }
        retired.emplace_back(); // Prepare off-lock reclamation slots before commit; Agenda reschedules the current node on failure.
        auto& released = retired.back();
        auto* scene = locate(*timer.name->scope);
        const auto visible = scene ? scene->find(timer.name->key) : Projection::Point{};
        const auto before = scene ? scene->history() : 0;
        const auto retention = scene ? allowance(*scene) : 0;
        const auto bytes = replica.source.bytes();
        auto origin = replica.source.prepare(*timer.name->scope, timer.name->key, {}, std::nullopt, std::chrono::steady_clock::now());
        if (!origin) {
            throw std::runtime_error("Replica expiry could not prepare native state");
        }
        auto choice = choose(origin->name(), {}, &replica, now);
        if (!choice) {
            throw std::runtime_error("Replica expiry could not merge logical registration");
        }
        std::optional<Projection::Edit> projection;
        if (choice->changed) {
            auto prepared = scene->prepare(choice->name, choice->content(), std::chrono::steady_clock::now(), visible.record.has_value() && choice->record.has_value(), retention);
            if (!prepared) {
                throw std::runtime_error("Replica expiry could not prepare projection");
            }
            projection.emplace(std::move(*prepared));
        }
        released.source = origin->commit();
        if (projection) {
            released.scene = projection->commit();
        }
        choice->commit();
        replicaBytes_ = replicaBytes_ - bytes + replica.source.bytes();
        const auto node = replica.timers.find(timer.name.get());
        Agenda::erase(timer);
        released.timer = std::move(node->second);
        replica.timers.erase(node);
        if (projection) {
            publish(*scene, before, released.scene.event);
        }
    });
}
} // namespace astra
