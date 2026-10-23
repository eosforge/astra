// Coordinate Catalog native sources, merged views, quotas, and scheduled expiry.
#include "catalog_state.hpp"

#include <astra/profile.hpp>

#include <algorithm>
#include <array>
#include <cassert>
#include <utility>

namespace astra {
Catalog::State::State(Clock& clock) : State([&clock] { return clock.now(); }, Limits{}) {}

Catalog::State::State(Time time, Limits limits) : time_(std::move(time)), limits_(limits), source_(export_, static_cast<Source::Measure>(&State::measure), true, limits.source), merged_(gate_, static_cast<Source::Measure>(&State::measure), false, limits.source) {
    if (!time_) {
        throw std::invalid_argument("Catalog requires a clock");
    }
}

Catalog::State::~State() = default;

Catalog::State::Pending::~Pending() {

    if (committed) {
        return;
    }
    if (timer) {
        owner.timers_.erase(timer);
    }
    if (deadline) {
        owner.deadlines_.erase(deadline);
    }
    if (created) {
        const auto sector = owner.scenes_.find(scope.sector); // Reclaim only new Scopes whose cursor remains zero.
        sector->second.erase(scope.spectrum);
        if (sector->second.empty()) {
            owner.scenes_.erase(sector);
        }
        --owner.scopes_;
    }
}

std::size_t Catalog::State::measure(const Record& record) noexcept {
    return record.value ? record.value->size() : 0;
}

std::size_t Catalog::State::measure(const Content& record) noexcept {
    return record.value ? record.value->size() : 0;
}

Catalog::State::Error Catalog::State::error(Catalog::Error value) noexcept {
    switch (value) {
    case Catalog::Error::Input:
        return Error::Input;
    case Catalog::Error::Clock:
        return Error::Clock;
    case Catalog::Error::Ended:
        return Error::Ended;
    case Catalog::Error::Version:
        return Error::Version;
    case Catalog::Error::Conflict:
        return Error::Conflict;
    case Catalog::Error::Exhausted:
        return Error::Exhausted;
    }
    return Error::Input;
}

Catalog::State::Error Catalog::State::error(Source::Error value) noexcept {
    switch (value) {
    case Source::Error::Input:
        return Error::Input;
    case Source::Error::Duplicate:
        return Error::Conflict;
    case Source::Error::Capacity:
        return Error::Capacity;
    case Source::Error::Version:
        return Error::Exhausted;
    case Source::Error::History:
        return Error::History;
    }
    return Error::Input;
}

Catalog::State::Error Catalog::State::error(Projection::Error value) noexcept {
    switch (value) {
    case Projection::Error::Input:
        return Error::Input;
    case Projection::Error::Capacity:
        return Error::Capacity;
    case Projection::Error::Version:
        return Error::Exhausted;
    case Projection::Error::History:
        return Error::History;
    }
    return Error::Input;
}

void Catalog::State::notify(Notify notify, void* context) {
    const std::lock_guard lock(*gate_);
    notify_ = notify;
    context_ = context;
}

std::expected<std::vector<std::uint64_t>, Catalog::State::Error> Catalog::State::versions(const Scope& scope, std::span<const std::string_view> keys) const {

    // Validate the bounded request and prepare output outside the lock; failure creates no application state.
    if (!scope.valid() || keys.empty() || keys.size() > 128) {
        return std::unexpected(Error::Input);
    }
    std::array<std::string_view, 128> names;
    auto unique = std::span(names).first(keys.size()); // Preserve request order in the response.
    for (std::size_t index = 0; index < keys.size(); ++index) {
        if (!Scope::text(keys[index], 1024)) {
            return std::unexpected(Error::Input);
        }
        unique[index] = keys[index];
    }
    std::ranges::sort(unique);
    if (std::ranges::adjacent_find(unique) != unique.end()) {
        return std::unexpected(Error::Input);
    }
    std::vector<std::uint64_t> result(keys.size()); // Unknown keys remain zero without synthetic tombstones or application versions.

    // merged_ retains highest watermarks after expiration; visible projections cannot recover versions of lost bodies.
    const std::shared_lock lock(*gate_);
    for (std::size_t index = 0; index < keys.size(); ++index) {
        if (const auto record = merged_.find(scope, keys[index])) {
            result[index] = record->version;
        }
    }
    return result;
}

std::expected<Clock::Reading, Catalog::State::Error> Catalog::State::reading() {
    ASTRA_PROFILE_SCOPE("star.catalog_state.Catalog.State.reading");
    return Context<State>::reading(*this);
}

std::expected<Catalog::State::Projection*, Catalog::State::Error> Catalog::State::obtain(const Scope& scope) {
    return Context<State>::obtain(*this, scope);
}

std::size_t Catalog::State::allowance(const Projection& scene) const {
    return Context<State>::allowance(*this, scene);
}

void Catalog::State::publish(Projection& scene, std::size_t before, const Projection::Event& event) noexcept {
    ASTRA_PROFILE_SCOPE("star.catalog_state.Catalog.State.publish");
    Context<State>::publish(*this, scene, before, event);
}

std::expected<void, Catalog::State::Error> Catalog::State::publish(const Scope& scope, std::string_view key, Value value, std::uint64_t version, std::uint32_t ttl) {

    ASTRA_PROFILE_SCOPE("star.catalog_state.Catalog.State.publish");
    return change(scope, key, std::move(value), version, ttl, false);
}

std::expected<void, Catalog::State::Error> Catalog::State::publish(const Scope& scope, std::span<const Entry> entries, std::uint64_t version, std::uint32_t ttl, bool renewal) {

    // Validate the complete nonempty unique-key batch sharing one version/TTL before locking.
    std::array<std::string_view, 128> names;
    std::size_t bytes{}; // Bound each body before summing bytes to prevent size_t overflow from bypassing the batch budget.
    if (!scope.valid() || entries.empty() || entries.size() > 128 || !version || ttl < 1000 || ttl > 600000) {
        return std::unexpected(Error::Input);
    }
    auto keys = std::span(names).first(entries.size());
    for (std::size_t index = 0; index < entries.size(); ++index) {
        const auto& entry = entries[index];
        if (!Scope::text(entry.key, 1024) || (renewal ? static_cast<bool>(entry.value) : !entry.value)) {
            return std::unexpected(Error::Input);
        }
        if (entry.value && entry.value->size() > 1024 * 1024) {
            return std::unexpected(Error::Capacity);
        }
        bytes += entry.key.size() + (entry.value ? entry.value->size() : 0);
        if (bytes > 1024 * 1024) {
            return std::unexpected(Error::Capacity);
        }
        keys[index] = entry.key;
    }
    std::ranges::sort(keys);
    if (std::ranges::adjacent_find(keys) != keys.end()) {
        return std::unexpected(Error::Input);
    }

    // Reuse the transactional single-key edit without copying both bounded histories.
    if (entries.size() == 1) {
        return change(scope, entries.front().key, entries.front().value, version, ttl, renewal);
    }

    // Construct old roots and expiration-reclamation lists before the lock; capture snapshots only at complete commit boundaries.
    std::vector<Retired> expired;
    std::optional<Source::Tree> oldSource, oldMerged;
    std::unique_ptr<std::deque<Source::Event>> oldHistory;
    std::optional<Projection::Batch::Retired> oldScene;
    const std::lock_guard lock(*gate_);
    auto stamp = reading();
    if (!stamp) {
        return std::unexpected(stamp.error());
    }
    advance(stamp->time, expired);
    const std::unique_lock originLock(*export_);

    /// Stage old, source, and merged records before publishing a complete Catalog batch.
    struct Row {
        /// Capture the previous local record and merged known record before preparing this batch row.
        std::optional<Record> old, known;
        /// Retain the proposed local record and its merged visible result until atomic publication.
        Record candidate, combined;
        /// Keep prepared local-source and merged-index keys stable across the batch commit.
        Source::Tree::Key source, merged;
    };

    std::vector<Row> rows;
    rows.reserve(entries.size());
    for (const auto& entry : entries) {
        auto old = source_.find(scope, entry.key), known = merged_.find(scope, entry.key);
        auto candidate = renewal ? Catalog::renew(old ? &*old : nullptr, known ? &*known : nullptr, version, ttl, *stamp) : Catalog::publish(old ? &*old : nullptr, known ? &*known : nullptr, entry.value, version, ttl, *stamp);
        if (!candidate) {
            return std::unexpected(error(candidate.error()));
        }
        auto combined = Catalog::merge(known ? &*known : nullptr, *candidate, stamp->time);
        if (!combined) {
            return std::unexpected(error(combined.error()));
        }
        rows.push_back({std::move(old), std::move(known), *candidate, combined->record, {}, {}});
    }

    // Each new hook has rollback responsibility; the first Pending also owns new-Scope rollback and outlives batch candidates.
    std::vector<std::unique_ptr<Pending>> pending;
    pending.reserve(entries.size());
    for (std::size_t index = 0; index < entries.size(); ++index) {
        pending.push_back(std::make_unique<Pending>(*this, scope));
    }
    const auto count = scopes_;
    const auto located = obtain(scope);
    if (!located) {
        return std::unexpected(located.error());
    }
    pending.front()->created = scopes_ != count;
    auto& scene = **located;
    const auto before = scene.history();
    auto projection = scene.prepare(allowance(scene));
    auto origin = source_.batch(); // Assign contiguous positions and swap the complete source and send history once.
    auto merged = merged_.prepare();
    if (!agenda_) {
        agenda_ = std::make_unique<Agenda>(stamp->time);
        due_ = std::min(due_, agenda_->next());
    }
    if (!outlook_) {
        outlook_ = std::make_unique<Agenda>(stamp->time);
        due_ = std::min(due_, outlook_->next());
    }
    for (std::size_t index = 0; index < entries.size(); ++index) {
        auto& row = rows[index];
        const auto& entry = entries[index];
        auto source = origin.set(scope, entry.key, row.candidate, renewal ? Source::Form::Renew : Source::Form::Record);
        if (!source) {
            return std::unexpected(error(source.error()));
        }
        row.source = *source;
        auto target = merged.set(scope, entry.key, row.combined);
        if (!target) {
            return std::unexpected(error(target.error()));
        }
        row.merged = *target;
        if (Catalog::visible(row.known ? &*row.known : nullptr, row.combined)) {
            if (auto prepared = projection.set(row.merged, Content{row.combined.version, row.combined.value}, std::chrono::steady_clock::now()); !prepared) {
                return std::unexpected(error(prepared.error()));
            }
        }
        if (!timers_.contains(row.source.get())) {
            timers_.emplace(row.source.get(), std::make_unique<Timer>(row.source));
            pending[index]->timer = row.source.get();
        }
        if (!deadlines_.contains(row.merged.get())) {
            deadlines_.emplace(row.merged.get(), std::make_unique<Timer>(row.merged));
            pending[index]->deadline = row.merged.get();
        }
    }
    const auto events = projection.seal(); // Prepare complete notification before commit; no later allocation or partial-key publication.
    stamp = reading();
    if (!stamp) {
        return std::unexpected(stamp.error());
    }
    for (std::size_t index = 0; index < entries.size(); ++index) {
        auto& row = rows[index]; // One final clock sample covers all keys; any expired renewal rejects the entire batch.
        auto candidate = renewal ? Catalog::renew(row.old ? &*row.old : nullptr, row.known ? &*row.known : nullptr, version, ttl, *stamp) : Catalog::publish(row.old ? &*row.old : nullptr, row.known ? &*row.known : nullptr, row.candidate.value, version, ttl, *stamp);
        if (!candidate) {
            return std::unexpected(error(candidate.error()));
        }
        auto combined = Catalog::merge(row.known ? &*row.known : nullptr, *candidate, stamp->time);
        if (!combined || !origin.revise(scope, entries[index].key, *candidate) || !merged.revise(scope, entries[index].key, combined->record)) {
            throw std::logic_error("Catalog batch changed prepared payload");
        }
        row.candidate = *candidate;
        row.combined = combined->record;
    }

    oldSource.emplace(origin.commit(&oldHistory));
    oldMerged.emplace(merged.commit());
    oldScene.emplace(projection.commit());
    for (std::size_t index = 0; index < rows.size(); ++index) {
        const auto& row = rows[index]; // All scheduling nodes are allocated; only scalar/list updates remain.
        agenda_->set(*timers_.find(row.source.get())->second, *row.candidate.deadline);
        outlook_->set(*deadlines_.find(row.merged.get())->second, *row.combined.deadline);
        pending[index]->committed = true;
    }
    history_ = history_ - before + scene.history();
    if (notify_ && !events->empty()) {
        Projection::Event event;
        event.version = events->back().version;
        event.batch = events;
        notify_(context_, scope, event);
    }
    return {};
}

std::expected<void, Catalog::State::Error> Catalog::State::renew(const Scope& scope, std::string_view key, std::uint64_t version, std::uint32_t ttl) {
    return change(scope, key, {}, version, ttl, true);
}

std::expected<void, Catalog::State::Error> Catalog::State::change(const Scope& scope, std::string_view key, Value value, std::uint64_t version, std::uint32_t ttl, bool renewal) {

    ASTRA_PROFILE_SCOPE("star.catalog_state.Catalog.State.change");

    if (!scope.valid() || !Scope::text(key, 1024)) {
        return std::unexpected(Error::Input);
    }
    std::vector<Retired> expired; // Release all old references outside the commit lock, including final large-body ownership.
    Retired retired;
    ASTRA_PROFILE_BEGIN(profileLock163, "star.catalog_state.Catalog.State.change.wait.lock");
    const std::lock_guard lock(*gate_);
    ASTRA_PROFILE_END(profileLock163);
    auto stamp = reading();
    if (!stamp) {
        return std::unexpected(stamp.error());
    }
    advance(stamp->time, expired);
    ASTRA_PROFILE_BEGIN(profileLock169, "star.catalog_state.Catalog.State.change.wait.origin_lock");
    const std::unique_lock originLock(*export_); // Local-root/history publication shares the export lock; remote Scope installation does not need it.
    ASTRA_PROFILE_END(profileLock169);
    const auto old = source_.find(scope, key), known = merged_.find(scope, key);
    const auto* current = old ? &*old : nullptr;
    const auto* highest = known ? &*known : nullptr;
    auto candidate = renewal ? Catalog::renew(current, highest, version, ttl, *stamp) : Catalog::publish(current, highest, value, version, ttl, *stamp);
    if (!candidate) {
        return std::unexpected(error(candidate.error()));
    }
    auto combined = Catalog::merge(highest, *candidate, stamp->time);
    if (!combined) {
        return std::unexpected(error(combined.error()));
    }
    Pending pending{*this, scope}; // Until all three candidates commit, new Scope and both hook types roll back automatically.
    const auto scopes = scopes_;
    const auto located = obtain(scope);
    if (!located) {
        return std::unexpected(located.error());
    }
    pending.created = scopes_ != scopes;
    auto& scene = **located;
    const auto before = scene.history();
    const auto retention = allowance(scene);
    const auto position = source_.next();
    if (!position) {
        return std::unexpected(error(position.error()));
    }
    auto origin = source_.prepare(scope, key, *candidate, *position, std::chrono::steady_clock::now(), renewal ? Source::Form::Renew : Source::Form::Record);
    if (!origin) {
        return std::unexpected(error(origin.error()));
    }
    auto merged = merged_.prepare(scope, key, combined->record, std::nullopt, std::chrono::steady_clock::now());
    if (!merged) {
        return std::unexpected(error(merged.error()));
    }
    std::optional<Projection::Edit> projection;
    if (combined->visible) {
        auto prepared = scene.prepare(merged->name(), Content{combined->record.version, combined->record.value}, std::chrono::steady_clock::now(), false, retention);
        if (!prepared) {
            return std::unexpected(error(prepared.error()));
        }
        projection.emplace(std::move(*prepared));
    }
    if (!agenda_) {
        agenda_ = std::make_unique<Agenda>(stamp->time);
        due_ = std::min(due_, agenda_->next()); // Include newly created wheels in the shared next-boundary calculation immediately.
    }
    if (!outlook_) {
        outlook_ = std::make_unique<Agenda>(stamp->time);
        due_ = std::min(due_, outlook_->next());
    }
    auto found = timers_.find(origin->name().get());
    if (found == timers_.end()) {
        found = timers_.emplace(origin->name().get(), std::make_unique<Timer>(origin->name())).first;
        pending.timer = origin->name().get();
    }
    auto visible = deadlines_.find(merged->name().get());
    if (visible == deadlines_.end()) {
        visible = deadlines_.emplace(merged->name().get(), std::make_unique<Timer>(merged->name())).first;
        pending.deadline = merged->name().get();
    }

    stamp = reading(); // Final time determines both local-source and merged deadlines; a later remote deadline cannot extend local facts.
    if (!stamp) {
        return std::unexpected(stamp.error());
    }
    candidate = renewal ? Catalog::renew(current, highest, version, ttl, *stamp) : Catalog::publish(current, highest, candidate->value, version, ttl, *stamp); // Reuse the body already validated as equal so final recheck takes the pointer fast path.
    if (!candidate) {
        return std::unexpected(error(candidate.error()));
    }
    combined = Catalog::merge(highest, *candidate, stamp->time);
    if (!combined || !origin->revise(*candidate) || !merged->revise(combined->record)) {
        throw std::logic_error("Catalog final check changed prepared payload");
    }
    retired.source = origin->commit();
    retired.merged = merged->commit();
    if (projection) {
        retired.scene = projection->commit();
    }
    agenda_->set(*found->second, *candidate->deadline);
    outlook_->set(*visible->second, *combined->record.deadline);
    pending.committed = true;
    if (projection) {
        publish(scene, before, retired.scene.event);
    }
    return {};
}

std::expected<Catalog::State::Retired, Catalog::State::Error> Catalog::State::expire(const Scope& scope, std::string_view key, Clock::Time time, bool projected) {

    ASTRA_PROFILE_SCOPE("star.catalog_state.Catalog.State.expire");

    auto& source = projected ? merged_ : source_; // Keep source and merged deadlines distinct: local expiration cannot revoke an equal-version body retained remotely.
    auto& timers = projected ? deadlines_ : timers_;
    const auto old = source.find(scope, key);
    if (!old || !old->value || *old->deadline > time) {
        return std::unexpected(Error::Ended);
    }
    Projection* scene{};
    std::size_t before{}, retention{};
    if (projected) {
        const auto located = obtain(scope);
        if (!located) {
            return std::unexpected(located.error());
        }
        scene = *located;
        before = scene->history();
        retention = allowance(*scene);
    }
    auto origin = source.prepare(scope, key, Catalog::expire(*old, time), std::nullopt, std::chrono::steady_clock::now());
    if (!origin) {
        return std::unexpected(error(origin.error()));
    }
    std::optional<Projection::Edit> projection;
    if (projected) {
        auto prepared = scene->prepare(origin->name(), {}, std::chrono::steady_clock::now(), false, retention);
        if (!prepared) {
            return std::unexpected(error(prepared.error()));
        }
        projection.emplace(std::move(*prepared));
    }
    const auto timer = timers.find(origin->name().get());
    if (timer == timers.end()) {
        throw std::logic_error("Active Catalog lacks its timer");
    }

    Retired retired;
    retired.source = origin->commit(); // Source/watermark maintenance creates no source position or broadcast history.
    if (projection) {
        retired.scene = projection->commit();
    }
    Agenda::erase(*timer->second);
    retired.timer = std::move(timer->second);
    timers.erase(timer);
    if (projection) {
        publish(*scene, before, retired.scene.event);
    }
    return retired;
}

std::shared_ptr<Catalog::State::Replica> Catalog::State::advance(Clock::Time now, std::vector<Retired>& retired, Replica* held) {

    ASTRA_PROFILE_SCOPE("star.catalog_state.Catalog.State.advance");

    std::shared_ptr<Replica> blocked; // Return a busy source with expiration/retirement work so public reads can wait outside the domain lock.
    if (now < due_) {
        return {}; // If no wheel can advance, skip per-source traversal without truncating elapsed ticks or time.
    }
    const auto advance = [&](Source& source, Agenda* agenda, bool projected) {
        if (!agenda) {
            return;
        }
        agenda->advance(now, [&](Agenda::Node* hook, Clock::Time boundary) {
            auto& timer = *static_cast<Timer*>(hook);
            const auto record = source.find(*timer.name->scope, timer.name->key);
            if (!record || !record->value) {
                throw std::logic_error("Scheduled Catalog lacks an active native record");
            }
            if (*record->deadline > boundary) {
                agenda->set(timer, *record->deadline);
                return;
            }
            retired.emplace_back();
            auto removed = expire(*timer.name->scope, timer.name->key, boundary, projected);
            if (!removed) {
                throw std::runtime_error("Catalog expiry could not commit");
            }
            retired.back() = std::move(*removed);
        });
    };
    {
        ASTRA_PROFILE_BEGIN(profileLock334, "star.catalog_state.Catalog.State.advance.wait.origin_lock");
        const std::unique_lock originLock(*export_);
        ASTRA_PROFILE_END(profileLock334);
        advance(source_, agenda_.get(), false);
    } // Release the export lock after local maintenance, before remote maintenance.

    advance(merged_, outlook_.get(), true);
    for (auto current = replicas_.begin(); current != replicas_.end();) {
        const auto owner = current->second; // Keep the source alive until preparing unlocks; directory removal cannot destroy a locked mutex.
        auto& replica = *owner;             // Identity may retire during preparation, but the final guard retains the object.
        if (&replica == held) {
            ++current;
            continue; // Already holds the nonrecursive source lock; never try_lock it again or inspect its changing native directory.
        }
        ASTRA_PROFILE_BEGIN(profileLock346, "star.catalog_state.Catalog.State.advance.wait.preparing");
        const std::unique_lock preparing(replica.mutex, std::try_to_lock); // Only try under domain lock; waiting would invert lock order.
        ASTRA_PROFILE_END(profileLock346);
        if (!preparing.owns_lock()) {
            if (!blocked && (replica.retired || (replica.agenda && replica.agenda->next() <= now))) {
                blocked = current->second;
            }
            ++current;
            continue;
        }
        this->advance(replica, now, retired);
        if (replica.retired && replica.timers.empty()) {
            replicaBytes_ -= replica.source.bytes();
            current = replicas_.erase(current); // merged_ retains learned watermarks; the controller retains old-identity rejection evidence.
        } else {
            ++current;
        }
    }
    // Busy sources retain their old boundary in the minimum. Incomplete maintenance cannot imply catch-up; exceptions preserve old due_.
    due_ = Clock::Time::max();
    const auto include = [&](const Agenda* agenda) {
        if (agenda) {
            due_ = std::min(due_, agenda->next());
        }
    };
    include(agenda_.get());
    include(outlook_.get());
    for (const auto& [id, replica] : replicas_) {
        include(replica->agenda.get());
    }
    if (blocked) {
        due_ = std::min(due_, now); // Even empty retired sources require reclamation and a future check without a wheel.
    }
    return blocked;
}

void Catalog::State::tick() {

    ASTRA_PROFILE_SCOPE("star.catalog_state.Catalog.State.tick");

    std::vector<Retired> retired; // Wait/reclaim outside domain lock; failure preserves earlier completed expirations.
    ASTRA_PROFILE_BEGIN(profileLock379, "star.catalog_state.Catalog.State.tick.wait.lock");
    std::unique_lock lock(*gate_);
    ASTRA_PROFILE_END(profileLock379);
    if (!agenda_ && !outlook_ && replicas_.empty()) {
        return; // An uninitialized Clock is allowed only when there is no cleanup responsibility.
    }
    for (;;) {
        const auto stamp = reading(); // Resample after each wait; an earlier reading cannot prove completion.
        if (!stamp) {
            throw std::runtime_error("Catalog clock is unavailable");
        }
        auto blocked = advance(stamp->time, retired);
        if (!blocked) {
            return;
        }
        Guard waiting(std::move(blocked), lock); // Other-source and local writes may acquire domain while this wait runs.
    }
}

auto Catalog::State::execute(auto&& action) {
    return Reading<State>::execute(*this, std::forward<decltype(action)>(action));
}

std::expected<Catalog::State::Projection::View, Catalog::State::Error> Catalog::State::capture(const Scope& scope) {

    ASTRA_PROFILE_SCOPE("star.catalog_state.Catalog.State.capture");

    if (!scope.valid()) {
        return std::unexpected(Error::Input);
    }

    // Borrow Scene only under domain lock; returned Views own their pages and synchronization domain.
    return execute([&]() -> std::expected<Projection::View, Error> {
        const auto* scene = locate(scope); // Absent Scopes consume no permanent directory quota; Feed retains observer registrations.
        return scene ? scene->capture() : Projection::empty(gate_);
    });
}

std::expected<Catalog::State::Projection::Point, Catalog::State::Error> Catalog::State::find(const Scope& scope, std::string_view key) {

    ASTRA_PROFILE_SCOPE("star.catalog_state.Catalog.State.find");

    if (!scope.valid() || !Scope::text(key, 1024)) {
        return std::unexpected(Error::Input);
    }

    // Borrow input key synchronously; Point owns name/body references. An absent Scope returns an empty result at cursor zero.
    return execute([&]() -> std::expected<Projection::Point, Error> {
        const auto* scene = locate(scope); // Missing Scope/target returns explicit absence without implicit Scope creation.
        return scene ? scene->find(key) : Projection::Point{};
    });
}

std::expected<std::vector<Catalog::State::Projection::Event>, Catalog::State::Error> Catalog::State::changes(const Scope& scope, std::uint64_t since) {

    ASTRA_PROFILE_SCOPE("star.catalog_state.Catalog.State.changes");

    if (!scope.valid()) {
        return std::unexpected(Error::Input);
    }

    return execute([&]() -> std::expected<std::vector<Projection::Event>, Error> {
        if (const auto* scene = locate(scope)) {
            return scene->replay(since).transform_error([](Projection::Error failure) { return failure == Projection::Error::Version ? Error::Input : error(failure); });
        }
        if (since != 0) {
            return std::unexpected(Error::Input); // An absent Scope permits only cursor zero, never acknowledgement of a future cursor.
        }
        return std::vector<Projection::Event>{};
    });
}

Catalog::State::Source::View Catalog::State::source() {

    ASTRA_PROFILE_SCOPE("star.catalog_state.Catalog.State.source");
    ASTRA_PROFILE_BEGIN(profileLock442, "star.catalog_state.Catalog.State.source.wait.lock");
    const std::shared_lock lock(*export_); // Export retains original deadlines for receiver-side expiration; it triggers no domain GC.
    ASTRA_PROFILE_END(profileLock442);
    return source_.capture();
}

std::expected<std::vector<Catalog::State::Source::Event>, Catalog::State::Error> Catalog::State::events(std::uint64_t since) {

    ASTRA_PROFILE_SCOPE("star.catalog_state.Catalog.State.events");
    ASTRA_PROFILE_BEGIN(profileLock447, "star.catalog_state.Catalog.State.events.wait.lock");
    const std::shared_lock lock(*export_);
    ASTRA_PROFILE_END(profileLock447);
    return source_.replay(since).transform_error([](Source::Error failure) { return failure == Source::Error::Version ? Error::Input : error(failure); });
}

std::expected<Catalog::State::Source::Delivery, Catalog::State::Error> Catalog::State::deliver(std::uint64_t since, std::size_t count, std::size_t bytes) {

    ASTRA_PROFILE_SCOPE("star.catalog_state.Catalog.State.deliver");
    ASTRA_PROFILE_BEGIN(profileLock452, "star.catalog_state.Catalog.State.deliver.wait.lock");
    const std::shared_lock lock(*export_); // Snapshot/suffix capture does not wait for remote installation, public-projection preparation, or other-source GC.
    ASTRA_PROFILE_END(profileLock452);
    return source_.deliver(since, count, bytes).transform_error([](Source::Error failure) { return failure == Source::Error::Version ? Error::Input : error(failure); });
}

} // namespace astra
