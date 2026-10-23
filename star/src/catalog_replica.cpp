// Apply remote Catalog sources while preserving version coverage and merged-view consistency.
#include "catalog_state.hpp"
#include <astra/profile.hpp>

namespace astra {
Catalog::State::Guard Catalog::State::acquire(std::string_view id, std::unique_lock<std::shared_mutex>& domain) const {

    const auto found = replicas_.find(id); // Use directory iterators only under domain lock; the guard retains source ownership.
    Guard result(found == replicas_.end() ? nullptr : found->second, domain);
    const auto current = replicas_.find(id); // The source may retire while waiting; an old object cannot become a newly admitted source.
    if (current == replicas_.end() || current->second.get() != result.get()) {
        return Guard(nullptr, domain);
    }
    return result;
}

Catalog::State::Hooks::~Hooks() {
    if (!committed) {
        for (const auto* name : added) {
            owner.deadlines_.erase(name);
        }
    }
}

void Catalog::State::Hooks::add(const Source::Tree::Key& name) {
    if (!owner.deadlines_.contains(name.get())) {
        added.push_back(name.get()); // Register rollback responsibility before later allocations.
        owner.deadlines_.emplace(name.get(), std::make_unique<Timer>(name));
    }
}

Catalog::State::Projection* Catalog::State::locate(const Scope& scope) {
    return Context<State>::locate(*this, scope);
}

std::expected<void, Catalog::State::Error> Catalog::State::admit(std::string_view id) {

    if (!Scope::text(id, 1024)) {
        return std::unexpected(Error::Input);
    }
    const std::lock_guard lock(*gate_);
    if (const auto found = replicas_.find(id); found != replicas_.end()) {
        return found->second->retired ? std::unexpected(Error::Version) : std::expected<void, Error>{};
    }
    if (replicas_.size() == limits_.replicas) {
        return std::unexpected(Error::Capacity);
    }
    replicas_.emplace(std::string(id), std::make_shared<Replica>(gate_, limits_.source));
    return {};
}

void Catalog::State::retire(std::string_view id) {

    ASTRA_PROFILE_SCOPE("star.catalog_replica.Catalog.State.retire");
    ASTRA_PROFILE_BEGIN(profileLock54, "star.catalog_replica.Catalog.State.retire.wait.lock");
    const std::lock_guard lock(*gate_);
    ASTRA_PROFILE_END(profileLock54);
    const auto found = replicas_.find(id);
    if (found != replicas_.end()) {
        found->second->retired = true;
        due_ = Clock::Time{};
        found->second->coverage.clear(); // Reject further suffixes from this old identity while preserving existing deadlines.
    }
}

std::expected<std::uint64_t, Catalog::State::Error> Catalog::State::received(std::string_view id) const {
    std::unique_lock lock(*gate_);
    auto borrowed = acquire(id, lock); // Wait for the source outside the local commit lock.
    return !borrowed.get() ? std::expected<std::uint64_t, Error>(std::unexpected(Error::Input)) : borrowed.get()->source.position();
}

std::expected<Catalog::State::Source::Draft, Catalog::State::Error> Catalog::State::prepare(std::string_view id, std::uint64_t position) {

    ASTRA_PROFILE_SCOPE("star.catalog_replica.Catalog.State.prepare");

    ASTRA_PROFILE_BEGIN(profileLock71, "star.catalog_replica.Catalog.State.prepare.wait.lock");
    std::unique_lock lock(*gate_);
    ASTRA_PROFILE_END(profileLock71);
    auto borrowed = acquire(id, lock);
    if (!borrowed.get()) {
        return std::unexpected(Error::Input);
    }
    const auto& replica = *borrowed.get();
    if (replica.retired || position < replica.source.position() || std::ranges::any_of(replica.coverage, [position](const Replica::Coverage& value) { return value.position > position; })) {
        return std::unexpected(Error::Version);
    }
    return replica.source.prepare(position);
}

std::expected<std::optional<Catalog::Record>, Catalog::State::Error> Catalog::State::replica(std::string_view id, const Scope& scope, std::string_view key) const {

    ASTRA_PROFILE_SCOPE("star.catalog_replica.Catalog.State.replica");

    if (!scope.valid() || !Scope::text(key, 1024)) {
        return std::unexpected(Error::Input);
    }
    ASTRA_PROFILE_BEGIN(profileLock88, "star.catalog_replica.Catalog.State.replica.wait.lock");
    std::unique_lock lock(*gate_);
    ASTRA_PROFILE_END(profileLock88);
    auto borrowed = acquire(id, lock);
    if (!borrowed.get()) {
        return std::unexpected(Error::Input);
    }
    return borrowed.get()->source.find(scope, key); // Return this source's facts only, without borrowing merged_ bodies or later deadlines.
}

std::expected<Catalog::State::Point, Catalog::State::Error> Catalog::State::resolve(const Scope& scope, std::string_view key) {

    if (!scope.valid() || !Scope::text(key, 1024)) {
        return std::unexpected(Error::Input);
    }
    const std::shared_lock lock(*export_); // Read local-source facts and contiguous position; receivers evaluate original absolute deadlines.
    return Point{source_.position(), source_.find(scope, key)};
}

std::expected<bool, Catalog::State::Error> Catalog::State::covered(std::string_view id, std::uint64_t position, const Scope& scope, std::string_view key) {

    if (!scope.valid() || !Scope::text(key, 1024) || position == 0) {
        return std::unexpected(Error::Input);
    }
    Source::Retired retired;
    std::unique_lock lock(*gate_);
    auto borrowed = acquire(id, lock);
    if (!borrowed.get()) {
        return std::unexpected(Error::Input);
    }
    auto& replica = *borrowed.get();
    if (replica.retired) {
        return std::unexpected(Error::Version);
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

std::expected<void, Catalog::State::Error> Catalog::State::apply(std::string_view id, std::uint64_t position, const Scope& scope, std::string_view key, Record record, Source::Form form) {
    return receive(id, position, scope, key, std::move(record), form, false);
}

std::expected<void, Catalog::State::Error> Catalog::State::repair(std::string_view id, std::uint64_t position, const Scope& scope, std::string_view key, std::optional<Record> record) {

    ASTRA_PROFILE_SCOPE("star.catalog_replica.Catalog.State.repair");
    return receive(id, position, scope, key, std::move(record), Source::Form::Record, true);
}

std::expected<void, Catalog::State::Error> Catalog::State::receive(std::string_view id, std::uint64_t position, const Scope& scope, std::string_view key, std::optional<Record> record, Source::Form form, bool repair) {

    ASTRA_PROFILE_SCOPE("star.catalog_replica.Catalog.State.receive");

    if (!scope.valid() || !Scope::text(key, 1024) || position == 0 || (record && !Catalog::valid(*record)) || (!repair && !record) || (form != Source::Form::Record && form != Source::Form::Renew)) {
        return std::unexpected(Error::Input);
    }
    std::vector<Retired> expired; // Destroy large old references after releasing gate.
    Retired retired;
    ASTRA_PROFILE_BEGIN(profileLock154, "star.catalog_replica.Catalog.State.receive.wait.lock");
    std::unique_lock lock(*gate_);
    ASTRA_PROFILE_END(profileLock154);
    auto borrowed = acquire(id, lock);
    if (!borrowed.get()) {
        return std::unexpected(Error::Input);
    }
    auto& replica = *borrowed.get();
    if (replica.retired) {
        return std::unexpected(Error::Version);
    }
    if (position <= replica.source.position()) {
        return {}; // Duplicate prefixes cannot refresh TTL or overwrite newer local facts.
    }
    if (!repair && (replica.source.position() == UINT64_MAX || position != replica.source.position() + 1)) {
        return std::unexpected(Error::History);
    }
    auto index = replica.coverage.size(); // Store indices rather than iterators across reserve; size means no match.
    std::uint64_t covered{};              // Highest source position covered for this target by a Scope or targeted repair.
    std::size_t targets{};                // Count only exact targets against the 128-item quota, excluding Scope markers.

    for (std::size_t item = 0; item < replica.coverage.size(); ++item) {
        const auto& value = replica.coverage[item];
        targets += !value.name->key.empty();
        if (*value.name->scope != scope) {
            continue;
        }
        if (value.name->key == key) {
            index = item;
        }
        if (value.name->key.empty() || value.name->key == key) {
            covered = std::max(covered, value.position);
        }
    }
    const bool precise = index != replica.coverage.size();
    if (covered >= position) {
        if (!repair) {
            auto skipped = replica.source.prepare(scope, key, replica.source.find(scope, key), position, std::chrono::steady_clock::now());
            if (!skipped) {
                return std::unexpected(error(skipped.error()));
            }
            retired.source = skipped->commit();
            std::erase_if(replica.coverage, [position](const Replica::Coverage& value) { return value.position <= position; });
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
    const auto old = replica.source.find(scope, key);
    if (form == Source::Form::Renew && (!old || !old->value || !record->value || old->version != record->version)) {
        return std::unexpected(Error::Ended); // A deadline-only update cannot create a missing or differently versioned source body.
    }
    if (old && record && (record->version < old->version || (record->version == old->version && old->value && record->value && (*old->value != *record->value || *record->deadline < *old->deadline)))) {
        return std::unexpected(Error::Conflict);
    }
    if (record) {
        record = Catalog::expire(*record, stamp->time);
    }
    const auto known = merged_.find(scope, key); // Prepare source facts separately from cross-source watermarks; unknown cannot clear a watermark.
    std::optional<Catalog::Change> combined;
    if (record) {
        auto candidate = Catalog::merge(known ? &*known : nullptr, *record, stamp->time);
        if (!candidate) {
            return std::unexpected(error(candidate.error()));
        }
        combined = std::move(*candidate);
    }
    const auto bytes = replica.source.bytes();
    auto origin = replica.source.prepare(scope, key, record, repair ? std::nullopt : std::optional(position), std::chrono::steady_clock::now());
    if (!origin) {
        return std::unexpected(error(origin.error()));
    }
    if (origin->bytes() > limits_.replicaBytes || replicaBytes_ - bytes > limits_.replicaBytes - origin->bytes()) {
        return std::unexpected(Error::Capacity);
    }
    std::optional<Source::Edit> merged;
    if (combined) {
        auto candidate = merged_.prepare(scope, key, combined->record, std::nullopt, std::chrono::steady_clock::now());
        if (!candidate) {
            return std::unexpected(error(candidate.error()));
        }
        merged.emplace(std::move(*candidate));
    }
    Pending pending{*this, scope}; // Roll back new projection directories and merged hooks if commit fails.
    auto* scene = locate(scope);
    if (combined && combined->visible && !scene) {
        auto located = obtain(scope);
        if (!located) {
            return std::unexpected(located.error());
        }
        scene = *located;
        pending.created = true;
    }
    std::optional<Projection::Edit> projection;
    const auto before = scene ? scene->history() : 0;
    if (combined && combined->visible) {
        auto candidate = scene->prepare(merged->name(), combined->record.value ? std::optional(Content{combined->record.version, combined->record.value}) : std::nullopt, std::chrono::steady_clock::now(), false, allowance(*scene));
        if (!candidate) {
            return std::unexpected(error(candidate.error()));
        }
        projection.emplace(std::move(*candidate));
    }
    const auto node = replica.timers.find(origin->name().get());
    Timer* hook = node == replica.timers.end() ? nullptr : node->second.get(); // Do not retain iterators across reserve.
    std::unique_ptr<Timer> prepared;
    if (record && record->value && !hook) {
        if (!replica.agenda) {
            replica.agenda = std::make_unique<Agenda>(stamp->time);
            due_ = std::min(due_, replica.agenda->next()); // Include a newly created wheel in the shared next-boundary calculation immediately.
        }
        prepared = std::make_unique<Timer>(origin->name());
        replica.timers.reserve(replica.timers.size() + 1);
    }
    if (combined && combined->record.value && !deadlines_.contains(merged->name().get())) {
        if (!outlook_) {
            outlook_ = std::make_unique<Agenda>(stamp->time);
            due_ = std::min(due_, outlook_->next());
        }
        pending.deadline = merged->name().get();
        deadlines_.emplace(pending.deadline, std::make_unique<Timer>(merged->name()));
    }
    std::optional<Replica::Coverage> preparedCoverage;
    if (repair && !precise) {
        replica.coverage.reserve(replica.coverage.size() + 1);
        preparedCoverage.emplace(origin->name(), position);
    }
    stamp = reading(); // Final acceptance must not expose bodies that expired during preparation.
    if (!stamp) {
        return std::unexpected(stamp.error());
    }
    if ((record && record->value && *record->deadline <= stamp->time) || (combined && combined->record.value && *combined->record.deadline <= stamp->time)) {
        return std::unexpected(Error::Ended);
    }

    if (prepared) {
        hook = prepared.get();
        replica.timers.emplace(origin->name().get(), std::move(prepared)); // Last potentially allocating operation.
    }
    retired.source = origin->commit();
    if (merged) {
        retired.merged = merged->commit();
    }
    if (projection) {
        retired.scene = projection->commit();
    }
    replicaBytes_ = replicaBytes_ - bytes + replica.source.bytes();
    if (record && record->value) {
        replica.agenda->set(*hook, *record->deadline);
    } else if (hook) {
        Agenda::erase(*hook);
        const auto removed = replica.timers.find(retired.source.name.get());
        retired.timer = std::move(removed->second);
        replica.timers.erase(removed);
    }
    if (combined) {
        const auto deadline = deadlines_.find(retired.merged.name.get());
        if (combined->record.value) {
            outlook_->set(*deadline->second, *combined->record.deadline);
        } else if (deadline != deadlines_.end()) {
            Agenda::erase(*deadline->second);
            retired.deadline = std::move(deadline->second);
            deadlines_.erase(deadline);
        }
    }
    if (preparedCoverage) {
        replica.coverage.push_back(std::move(*preparedCoverage));
    } else if (repair) {
        replica.coverage[index].position = position;
    } else {
        std::erase_if(replica.coverage, [position](const Replica::Coverage& value) { return value.position <= position; });
    }
    pending.committed = true;
    if (projection) {
        publish(*scene, before, retired.scene.event);
    }
    return {};
}

std::expected<Catalog::State::Recovery, Catalog::State::Error> Catalog::State::restore(std::string_view id, Source::Draft&& draft) {

    ASTRA_PROFILE_SCOPE("star.catalog_replica.Catalog.State.restore");

    ASTRA_PROFILE_BEGIN(profileLock329, "star.catalog_replica.Catalog.State.restore.wait.lock");
    std::unique_lock lock(*gate_);
    ASTRA_PROFILE_END(profileLock329);
    auto borrowed = acquire(id, lock);
    if (!borrowed.get()) {
        return std::unexpected(Error::Input);
    }
    auto& replica = *borrowed.get();
    if (replica.retired || std::ranges::any_of(replica.coverage, [&](const Replica::Coverage& value) { return value.position > draft.position(); })) {
        return std::unexpected(Error::Version);
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

std::expected<void, Catalog::State::Error> Catalog::State::replace(std::string_view id, Source::Draft&& draft) {

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

std::expected<void, Catalog::State::Error> Catalog::State::finish(std::string_view id, std::uint64_t position) {

    ASTRA_PROFILE_SCOPE("star.catalog_replica.Catalog.State.finish");

    ASTRA_PROFILE_BEGIN(profileLock363, "star.catalog_replica.Catalog.State.finish.wait.lock");
    std::unique_lock lock(*gate_);
    ASTRA_PROFILE_END(profileLock363);
    auto borrowed = acquire(id, lock);
    if (!borrowed.get()) {
        return std::unexpected(Error::Input);
    }
    auto& replica = *borrowed.get();
    if (replica.retired || std::ranges::any_of(replica.coverage, [position](const Replica::Coverage& value) { return value.position > position; }) || !replica.source.confirm(position)) {
        return std::unexpected(Error::Version);
    }
    replica.coverage.clear(); // After every Scope completes, the contiguous prefix subsumes Scope coverage evidence.
    return {};
}

std::expected<void, Catalog::State::Error> Catalog::State::install(std::string_view id, const Source::Draft& draft, const Scope& scope) {

    ASTRA_PROFILE_SCOPE("star.catalog_replica.Catalog.State.install");

    // Retain old roots/wheels/nodes until after commit unlock. Candidate failure preserves all three installed roots.
    std::optional<Source::Tree> oldSource;
    std::vector<std::unique_ptr<Timer>> oldTimers; // Destroy replaced hooks outside the lock.
    std::optional<Source::Tree> oldMerged;
    std::optional<Projection::Batch::Retired> oldScene; // Release old projections and notification events after unlock.
    std::vector<std::unique_ptr<Timer>> oldDeadlines;

    std::unordered_map<const Source::Name*, std::unique_ptr<Timer>> timers;
    std::vector<Retired> expired;
    ASTRA_PROFILE_BEGIN(profileLock385, "star.catalog_replica.Catalog.State.install.wait.lock");
    std::unique_lock lock(*gate_);
    ASTRA_PROFILE_END(profileLock385);
    auto borrowed = acquire(id, lock);
    if (!borrowed.get()) {
        return std::unexpected(Error::Input);
    }
    auto& replica = *borrowed.get();
    if (replica.retired || draft.position() < replica.source.position() || std::ranges::any_of(replica.coverage, [&](const Replica::Coverage& value) { return value.position > draft.position(); })) {
        return std::unexpected(Error::Version);
    }
    auto stamp = reading();
    if (!stamp) {
        return std::unexpected(stamp.error());
    }
    advance(replica, stamp->time, expired);
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
            if (!Catalog::valid(incoming)) {
                failure = Error::Input;
                return;
            }
            const auto old = origin->find(scope, name->key);
            if (old && (incoming.version < old->version || (incoming.version == old->version && old->value && incoming.value && ((old->value != incoming.value && *old->value != *incoming.value) || *incoming.deadline < *old->deadline)))) {
                failure = Error::Conflict;
                return;
            }
            if (old && old->version == incoming.version && old->value && incoming.value) {
                incoming.value = old->value; // Off-lock byte equality permits reusing existing bodies during final merge.
            }
            auto native = origin->set(scope, name->key, incoming);
            if (!native) {
                failure = error(native.error());
                return;
            }
            if (incoming.value) {
                timers.emplace(native->get(), std::make_unique<Timer>(*native));
            }
            rows.push_back({*native, std::move(incoming)});
        });
    });
    if (failure) {
        return std::unexpected(*failure);
    }
    if (replica.retired) {
        return std::unexpected(Error::Version); // Identity revocation during preparation takes precedence over publication.
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

    /// Only upsert known merged watermarks; missing source rows and equal-version watermarks preserve valid local bodies.
    struct Change {
        /// Use stable merged-index names, independently of replaceable source page slots.
        Source::Tree::Key name;
        /// Merged highest version and longest accepted deadline.
        Record record;
        /// Create a Scene commit only for content changes.
        bool visible{};
    };

    auto merged = merged_.prepare();
    std::vector<Change> changes;
    Hooks hooks{*this, {}, false};
    std::optional<Clock::Time> earliest; // Minimum deadline among live candidates, required to remain valid at final time sampling.
    for (const auto& row : rows) {
        const auto& name = row.name;
        const auto& incoming = row.record;
        const auto known = merged.find(*name->scope, name->key);
        auto combined = Catalog::merge(known ? &*known : nullptr, incoming, stamp->time);
        if (!combined) {
            return std::unexpected(error(combined.error()));
        }
        auto prepared = merged.set(*name->scope, name->key, combined->record);
        if (!prepared) {
            return std::unexpected(error(prepared.error()));
        }
        if (combined->record.value) {
            if (!outlook_) {
                outlook_ = std::make_unique<Agenda>(stamp->time);
                due_ = std::min(due_, outlook_->next());
            }
            hooks.add(*prepared);
            earliest = earliest ? std::min(*earliest, *combined->record.deadline) : combined->record.deadline;
        }
        changes.push_back({*prepared, combined->record, combined->visible});
    }

    Pending pending{*this, scope}; // Directory rollback responsibility must outlive the batch candidate.
    std::optional<Projection::Batch> projection;
    auto history = history_; // Use the domain's remaining history allowance without changing other Scopes' history.
    if (std::ranges::any_of(changes, [](const Change& row) { return row.visible; })) {
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
            if (!row.visible) {
                continue;
            }
            auto prepared = projection->set(row.name, row.record.value ? std::optional(Content{row.record.version, row.record.value}) : std::nullopt, std::chrono::steady_clock::now());
            if (!prepared) {
                return std::unexpected(error(prepared.error()));
            }
        }
        history = history - before + projection->history();
    }
    oldDeadlines.reserve(changes.size()); // Prepare removal capacity before commit; notification/commit must not allocate.
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

    oldMerged.emplace(merged.commit());
    if (projection) {
        oldScene.emplace(projection->commit());
    }
    for (const auto& row : changes) {
        const auto timer = deadlines_.find(row.name.get());
        if (row.record.value) {
            outlook_->set(*timer->second, *row.record.deadline);
        } else if (timer != deadlines_.end()) {
            Agenda::erase(*timer->second);
            oldDeadlines.push_back(std::move(timer->second));
            deadlines_.erase(timer);
        }
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
        replica.agenda->set(*timer, *record->deadline);
    }
    replica.timers.merge(timers);
    std::erase_if(replica.coverage, [&](const Replica::Coverage& value) { return *value.name->scope == scope; });
    replica.coverage.push_back({std::move(marker), draft.position()});
    replicaBytes_ = replicaBytes_ - bytes + replica.source.bytes();
    history_ = history;
    hooks.committed = true;
    pending.committed = true;
    if (notify_ && oldScene) {
        for (const auto& event : oldScene->events) {
            notify_(context_, scope, event);
        }
    }
    return {};
}

void Catalog::State::advance(Replica& replica, Clock::Time now, std::vector<Retired>& retired) {

    ASTRA_PROFILE_SCOPE("star.catalog_replica.Catalog.State.advance");

    if (!replica.agenda) {
        return;
    }
    replica.agenda->advance(now, [&](Agenda::Node* hook, Clock::Time boundary) {
        auto& timer = *static_cast<Timer*>(hook); // Source timers retain detached nodes until safe reclamation.
        const auto old = replica.source.find(*timer.name->scope, timer.name->key);
        if (!old || !old->value) {
            throw std::logic_error("Catalog replica timer has no active record");
        }
        if (*old->deadline > boundary) {
            replica.agenda->set(timer, *old->deadline);
            return;
        }
        retired.emplace_back();
        auto& released = retired.back();
        const auto bytes = replica.source.bytes();
        auto origin = replica.source.prepare(*timer.name->scope, timer.name->key, Catalog::expire(*old, boundary), std::nullopt, std::chrono::steady_clock::now());
        if (!origin) {
            throw std::runtime_error("Catalog replica expiry could not prepare watermark");
        }
        released.source = origin->commit(); // Expire merged visibility by its own longest deadline without broadcasting remote expiration.
        replicaBytes_ = replicaBytes_ - bytes + replica.source.bytes();
        const auto node = replica.timers.find(timer.name.get());
        Agenda::erase(timer);
        released.timer = std::move(node->second);
        replica.timers.erase(node);
    });
}
} // namespace astra
