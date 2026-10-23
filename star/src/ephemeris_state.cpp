// Coordinate Ephemeris ownership, replicated sources, quotas, and lifetime scheduling.
#include "ephemeris_state.hpp"

#include <astra/profile.hpp>

#include <cassert>
#include <tuple>
#include <utility>

namespace astra {
Ephemeris::State::State(Clock& clock) : State([&clock] { return clock.now(); }, Limits{}) {}

Ephemeris::State::State(Time time, Limits limits) : time_(std::move(time)), limits_(limits), source_(export_, static_cast<Source::Measure>(&State::measure), true, limits.source) {
    if (!time_) {
        throw std::invalid_argument("Ephemeris requires a clock");
    }
}

Ephemeris::State::~State() = default;

Ephemeris::State::Pending::~Pending() {

    if (committed) {
        return;
    }
    if (timer) {
        owner.timers_.erase(timer);
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

std::size_t Ephemeris::State::measure(const Record& record) noexcept {
    return record.attr->size() + record.data->size() + 2 * sizeof(Contribution) + 128;
}

std::size_t Ephemeris::State::measure(const Content& record) noexcept {
    return record.attr->size() + record.data->size();
}

Ephemeris::State::Error Ephemeris::State::error(Ephemeris::Error value) noexcept {
    switch (value) {
    case Ephemeris::Error::Input:
        return Error::Input;
    case Ephemeris::Error::Clock:
        return Error::Clock;
    case Ephemeris::Error::Ended:
        return Error::Ended;
    case Ephemeris::Error::Obsolete:
        return Error::Obsolete;
    case Ephemeris::Error::Conflict:
        return Error::Conflict;
    case Ephemeris::Error::Exhausted:
        return Error::Exhausted;
    }
    return Error::Input;
}

Ephemeris::State::Error Ephemeris::State::error(Source::Error value) noexcept {
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

Ephemeris::State::Error Ephemeris::State::error(Projection::Error value) noexcept {
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

void Ephemeris::State::notify(Notify notify, void* context) {
    const std::lock_guard lock(*gate_); // Updates only the internal collector, without replay.
    notify_ = notify;
    context_ = context;
}

std::expected<Clock::Reading, Ephemeris::State::Error> Ephemeris::State::reading() {
    ASTRA_PROFILE_SCOPE("star.ephemeris_state.Ephemeris.State.reading");
    return Context<State>::reading(*this);
}

std::expected<Ephemeris::State::Projection*, Ephemeris::State::Error> Ephemeris::State::obtain(const Scope& scope) {
    return Context<State>::obtain(*this, scope);
}

std::size_t Ephemeris::State::allowance(const Projection& scene) const {
    return Context<State>::allowance(*this, scene);
}

void Ephemeris::State::publish(Projection& scene, std::size_t before, const Projection::Event& event) noexcept {
    ASTRA_PROFILE_SCOPE("star.ephemeris_state.Ephemeris.State.publish");
    Context<State>::publish(*this, scene, before, event);
}

std::expected<Ephemeris::State::Receipt, Ephemeris::State::Error> Ephemeris::State::create(const Scope& scope, Value attr, Value data, std::uint32_t ttl, std::string uuid, std::uint64_t generation, std::uint64_t order, std::string_view capability) {

    if (!scope.valid() || !Ephemeris::valid(attr) || !Ephemeris::valid(data) || ttl < 1000 || ttl > 600000 || (generation == 0 && (!uuid.empty() || !capability.empty() || order != 0))) {
        return std::unexpected(Error::Input);
    }
    if (generation) {
        if (!Ephemeris::valid(uuid) || capability.size() != 32 || uuid != Ephemeris::identity(scope, attr, ttl, capability)) {
            return std::unexpected(Error::Input);
        }
    } else {
        uuid = Ephemeris::uuid();
    }
    Receipt receipt{uuid, {}, 0, generation, ttl}; // Allocate receipt text before commit.
    std::vector<Retired> expired;
    Retired retired;
    const std::lock_guard lock(*gate_);
    auto stamp = reading();
    if (!stamp) {
        return std::unexpected(stamp.error());
    }
    advance(stamp->time, expired);
    const std::unique_lock originLock(*export_);
    const auto old = source_.find(scope, uuid);
    if (old && (!generation || old->generation > generation)) {
        return std::unexpected(Error::Obsolete);
    }
    if (old && old->generation == generation) {
        if (*old->attr != *attr || old->ttl != ttl) {
            return std::unexpected(Error::Conflict);
        }
        receipt.data = old->data;
        receipt.order = old->update;
        return receipt; // Equal registration generation confirms the prior result without granting another TTL.
    }
    auto lookup = std::make_shared<const Source::Name>(std::make_shared<const Scope>(scope), uuid);
    if (const auto known = choices_.find(lookup); known != choices_.end()) {
        for (const auto& row : known->second) {
            if (row.record.deadline <= stamp->time) {
                continue;
            }
            if (!generation || !row.record.generation || row.record.generation > generation || row.record.ttl != ttl || *row.record.attr != *attr) {
                return std::unexpected(Error::Conflict);
            }
            if (row.record.update > order) {
                data = row.record.data;
                order = row.record.update;
            } else if (row.record.update == order && *row.record.data != *data) {
                return std::unexpected(Error::Conflict);
            }
        }
    }
    auto candidate = Ephemeris::create(attr, data, ttl, *stamp);
    if (!candidate) {
        return std::unexpected(error(candidate.error()));
    }
    candidate->update = order;
    candidate->generation = generation;
    const auto count = scopes_;
    const auto located = obtain(scope);
    if (!located) {
        return std::unexpected(located.error());
    }
    auto& scene = **located;
    Pending pending{*this, scope, nullptr, scopes_ != count, false};
    const auto before = scene.history();
    const auto position = source_.next();
    if (!position) {
        return std::unexpected(error(position.error()));
    }
    auto origin = source_.prepare(scope, uuid, *candidate, *position, std::chrono::steady_clock::now());
    if (!origin) {
        return std::unexpected(error(origin.error()));
    }
    auto choice = choose(origin->name(), *candidate, nullptr, stamp->time);
    if (!choice) {
        return std::unexpected(choice.error());
    }
    std::optional<Projection::Edit> projection;
    if (choice->changed) {
        auto prepared = scene.prepare(choice->name, choice->content(), std::chrono::steady_clock::now(), scene.find(uuid).record.has_value(), allowance(scene));
        if (!prepared) {
            return std::unexpected(error(prepared.error()));
        }
        projection.emplace(std::move(*prepared));
    }
    if (!agenda_) {
        agenda_ = std::make_unique<Agenda>(stamp->time);
        due_ = std::min(due_, agenda_->next());
    }
    auto found = timers_.find(origin->name().get());
    if (found == timers_.end()) {
        auto timer = std::make_unique<Timer>(origin->name());
        found = timers_.emplace(origin->name().get(), std::move(timer)).first;
        pending.timer = origin->name().get();
    }
    stamp = reading();
    if (!stamp) {
        return std::unexpected(stamp.error());
    }
    auto final = Ephemeris::create(attr, data, ttl, *stamp);
    if (!final) {
        return std::unexpected(error(final.error()));
    }
    candidate->deadline = final->deadline;
    if (choice->record && choice->name != origin->name() && choice->record->deadline <= stamp->time) {
        return std::unexpected(Error::Ended);
    }
    choice->revise(*candidate);
    if (!origin->revise(*candidate)) {
        throw std::logic_error("Ephemeris creation cost changed");
    }
    receipt.data = candidate->data;
    receipt.order = candidate->update;
    retired.source = origin->commit();
    if (projection) {
        retired.scene = projection->commit();
    }
    choice->commit();
    agenda_->set(*found->second, candidate->deadline);
    pending.committed = true;
    if (projection) {
        publish(scene, before, retired.scene.event);
    }
    return receipt;
}

std::expected<void, Ephemeris::State::Error> Ephemeris::State::update(const Scope& scope, std::string_view uuid, Value data, std::uint64_t order, std::uint64_t generation, std::string_view capability) {
    return change(scope, uuid, std::move(data), order, false, generation, capability);
}

std::expected<void, Ephemeris::State::Error> Ephemeris::State::renew(const Scope& scope, std::string_view uuid, std::uint64_t order, std::uint64_t generation, std::string_view capability) {
    return change(scope, uuid, {}, order, true, generation, capability);
}

std::expected<void, Ephemeris::State::Error> Ephemeris::State::change(const Scope& scope, std::string_view uuid, Value data, std::uint64_t order, bool renewal, std::uint64_t generation, std::string_view capability) {

    ASTRA_PROFILE_SCOPE("star.ephemeris_state.Ephemeris.State.change");

    if (!scope.valid() || !Ephemeris::valid(uuid)) {
        return std::unexpected(Error::Input);
    }
    std::vector<Retired> expired; // Reclaim payloads retired by catch-up outside the lock.
    Retired retired;
    ASTRA_PROFILE_BEGIN(profileLock236, "star.ephemeris_state.Ephemeris.State.change.wait.lock");
    const std::lock_guard lock(*gate_);
    ASTRA_PROFILE_END(profileLock236);
    auto stamp = reading();
    if (!stamp) {
        return std::unexpected(stamp.error());
    }
    advance(stamp->time, expired);
    ASTRA_PROFILE_BEGIN(profileLock242, "star.ephemeris_state.Ephemeris.State.change.wait.origin_lock");
    const std::unique_lock originLock(*export_); // Local-root/history publication shares the export lock; remote Scope installation does not need it.
    ASTRA_PROFILE_END(profileLock242);
    const auto old = source_.find(scope, uuid); // Query only the local source; replicas cannot become renewable local registrations.
    if (!old) {
        return std::unexpected(Error::Ended);
    }
    if (old->generation != generation || (generation && uuid != Ephemeris::identity(scope, old->attr, old->ttl, capability))) {
        return std::unexpected(Error::Obsolete);
    }
    auto candidate = renewal ? Ephemeris::renew(*old, order, *stamp) : Ephemeris::update(*old, data, order, *stamp);
    if (!candidate) {
        return std::unexpected(error(candidate.error()));
    }
    if (!candidate->changed) {
        const auto final = reading(); // Even idempotent confirmation rechecks expiration with current time after catch-up.
        if (!final) {
            return std::unexpected(final.error());
        }
        const auto checked = Ephemeris::active(*old, *final);
        if (!checked) {
            return std::unexpected(error(checked.error()));
        }
        return {};
    } // Valid same-order confirmation advances no position.
    const auto located = obtain(scope);
    if (!located) {
        return std::unexpected(located.error());
    }
    auto& scene = **located;
    const auto before = scene.history();
    const auto retention = allowance(scene);
    const auto position = source_.next();
    if (!position) {
        return std::unexpected(error(position.error()));
    }
    auto origin = source_.prepare(scope, uuid, candidate->record, *position, std::chrono::steady_clock::now(), renewal ? Source::Form::Renew : Source::Form::Data);
    if (!origin) {
        return std::unexpected(error(origin.error()));
    }
    auto choice = choose(origin->name(), candidate->record, nullptr, stamp->time);
    if (!choice) {
        return std::unexpected(choice.error());
    }
    std::optional<Projection::Edit> projection;
    if (choice->changed) {
        auto prepared = scene.prepare(choice->name, choice->content(), std::chrono::steady_clock::now(), scene.find(uuid).record.has_value(), retention);
        if (!prepared) {
            return std::unexpected(error(prepared.error()));
        }
        projection.emplace(std::move(*prepared));
    }
    const auto timer = timers_.find(origin->name().get()); // Lookup hooks by name pointer without UUID formatting or key allocation.
    if (timer == timers_.end()) {
        throw std::logic_error("Active Ephemeris lacks its timer");
    }

    stamp = reading(); // An original lease expiring during preparation cannot be renewed from a stale reading.
    if (!stamp) {
        return std::unexpected(stamp.error());
    }
    candidate = renewal ? Ephemeris::renew(*old, order, *stamp) : Ephemeris::update(*old, data, order, *stamp);
    if (!candidate) {
        return std::unexpected(error(candidate.error()));
    }
    if (choice->record && choice->name != origin->name() && choice->record->deadline <= stamp->time) {
        return std::unexpected(Error::Ended);
    }
    choice->revise(candidate->record);
    if (!origin->revise(candidate->record)) {
        throw std::logic_error("Ephemeris final check changed prepared payload cost");
    }
    retired.source = origin->commit();
    if (projection) {
        retired.scene = projection->commit();
    }
    choice->commit();
    agenda_->set(*timer->second, candidate->record.deadline);
    if (projection) {
        publish(scene, before, retired.scene.event);
    }
    return {};
}

std::expected<Ephemeris::State::Retired, Ephemeris::State::Error> Ephemeris::State::erase(const Scope& scope, std::string_view uuid, std::chrono::steady_clock::time_point now, bool active) {

    const auto old = source_.find(scope, uuid);
    if (!old) {
        return std::unexpected(Error::Ended);
    }
    const auto located = obtain(scope);
    if (!located) {
        return std::unexpected(located.error());
    }
    auto& scene = **located;
    const auto before = scene.history();
    const auto retention = allowance(scene);
    const auto position = source_.next();
    if (!position) {
        return std::unexpected(error(position.error()));
    }
    auto origin = source_.prepare(scope, uuid, {}, *position, now, Source::Form::Erase);
    if (!origin) {
        return std::unexpected(error(origin.error()));
    }
    const auto stamp = reading();
    if (!stamp) {
        return std::unexpected(stamp.error());
    }
    auto choice = choose(origin->name(), {}, nullptr, stamp->time);
    if (!choice) {
        return std::unexpected(choice.error());
    }
    std::optional<Projection::Edit> projection;
    if (choice->changed) {
        auto prepared = scene.prepare(choice->name, choice->content(), now, scene.find(uuid).record.has_value() && choice->record.has_value(), retention);
        if (!prepared) {
            return std::unexpected(error(prepared.error()));
        }
        projection.emplace(std::move(*prepared));
    }
    const auto timer = timers_.find(origin->name().get());
    if (timer == timers_.end()) {
        throw std::logic_error("Active Ephemeris lacks its timer");
    }
    if (active) {
        const auto stamp = reading(); // Explicit removal also rechecks that UUID remains live after preparation.
        if (!stamp) {
            return std::unexpected(stamp.error());
        }
        const auto checked = Ephemeris::active(*old, *stamp);
        if (!checked) {
            return std::unexpected(error(checked.error()));
        }
    }

    Retired retired; // Transfer nonempty payloads for destruction outside the outer domain lock.
    retired.source = origin->commit();
    if (projection) {
        retired.scene = projection->commit();
    }
    choice->commit();
    Agenda::erase(*timer->second); // Detach before moving outside the lock so destruction cannot touch an active wheel.
    retired.timer = std::move(timer->second);
    timers_.erase(timer);
    if (projection) {
        publish(scene, before, retired.scene.event);
    }
    return retired;
}

std::expected<void, Ephemeris::State::Error> Ephemeris::State::remove(const Scope& scope, std::string_view uuid, std::uint64_t generation, std::string_view capability) {

    ASTRA_PROFILE_SCOPE("star.ephemeris_state.Ephemeris.State.remove");

    if (!scope.valid() || !Ephemeris::valid(uuid)) {
        return std::unexpected(Error::Input);
    }
    std::vector<Retired> expired;
    std::optional<Retired> retired; // Declare before the lock so removed resources are reclaimed after unlock.
    ASTRA_PROFILE_BEGIN(profileLock373, "star.ephemeris_state.Ephemeris.State.remove.wait.lock");
    const std::lock_guard lock(*gate_);
    ASTRA_PROFILE_END(profileLock373);
    const auto stamp = reading();
    if (!stamp) {
        return std::unexpected(stamp.error());
    }
    advance(stamp->time, expired);
    ASTRA_PROFILE_BEGIN(profileLock379, "star.ephemeris_state.Ephemeris.State.remove.wait.origin_lock");
    const std::unique_lock originLock(*export_); // Local-root/history publication shares the export lock; remote Scope installation does not need it.
    ASTRA_PROFILE_END(profileLock379);
    const auto old = source_.find(scope, uuid);
    if (!old) {
        return std::unexpected(Error::Ended);
    }
    if (old->generation != generation || (generation && uuid != Ephemeris::identity(scope, old->attr, old->ttl, capability))) {
        return std::unexpected(Error::Obsolete);
    }
    auto removed = erase(scope, uuid, std::chrono::steady_clock::now(), true);
    if (!removed) {
        return std::unexpected(removed.error());
    }
    retired.emplace(std::move(*removed));
    return {};
}

std::shared_ptr<Ephemeris::State::Replica> Ephemeris::State::advance(Clock::Time now, std::vector<Retired>& retired, Replica* held) {

    ASTRA_PROFILE_SCOPE("star.ephemeris_state.Ephemeris.State.advance");

    std::shared_ptr<Replica> blocked; // Return a busy source with expiration/retirement work so public reads can wait outside the domain lock.
    if (now < due_) {
        return {}; // If no wheel can advance, skip per-source traversal without truncating elapsed ticks or time.
    }
    for (auto item = replicas_.begin(); item != replicas_.end();) {
        const auto owner = item->second; // Keep the source alive until preparing unlocks; directory removal cannot destroy a locked mutex.
        auto& replica = *owner;          // Retain the current group address through this expiration pass.
        if (&replica == held) {
            ++item;
            continue; // Already holds the nonrecursive source lock; never try_lock it again or inspect its changing native directory.
        }
        ASTRA_PROFILE_BEGIN(profileLock400, "star.ephemeris_state.Ephemeris.State.advance.wait.preparing");
        const std::unique_lock preparing(replica.mutex, std::try_to_lock); // Only try under domain lock; waiting would invert lock order.
        ASTRA_PROFILE_END(profileLock400);
        if (!preparing.owns_lock()) {
            if (!blocked && (replica.retired || (replica.agenda && replica.agenda->next() <= now))) {
                blocked = item->second;
            }
            ++item;
            continue;
        }
        advance(replica, now, retired);
        if (replica.retired && replica.timers.empty()) {
            item = replicas_.erase(item); // Reclaim empty retired-process wheels once native rows, active scheduling, and ownership indices are gone.
        } else {
            ++item;
        }
    }
    ASTRA_PROFILE_BEGIN(profileLock414, "star.ephemeris_state.Ephemeris.State.advance.wait.origin_lock");
    const std::unique_lock originLock(*export_); // Remote cleanup is complete; acquire export only for local-source maintenance.
    ASTRA_PROFILE_END(profileLock414);
    if (agenda_) {
        agenda_->advance(now, [&](Agenda::Node* hook, Clock::Time boundary) {
            auto& timer = *static_cast<Timer*>(hook); // Hooks originate only from this State, never arbitrary external nodes.
            const auto record = source_.find(*timer.name->scope, timer.name->key);
            if (!record) {
                throw std::logic_error("Scheduled Ephemeris lacks its native record");
            }
            if (record->deadline > boundary) {
                agenda_->set(timer, record->deadline); // Segmented wakeups for distant deadlines must not delete records early.
                return;
            }
            retired.emplace_back(); // Prepare off-lock reclamation capacity first; Agenda reschedules on allocation failure.
            auto removed = erase(*timer.name->scope, timer.name->key, std::chrono::steady_clock::now());
            if (!removed) {
                throw std::runtime_error("Ephemeris expiry could not commit");
            }
            retired.back() = std::move(*removed); // Local expiration is authoritative termination, published with downstream deletion.
        });
    }
    // Busy sources retain their old boundary in the minimum. Incomplete maintenance cannot imply catch-up; exceptions preserve old due_.
    due_ = Clock::Time::max();
    const auto include = [&](const Agenda* agenda) {
        if (agenda) {
            due_ = std::min(due_, agenda->next());
        }
    };
    include(agenda_.get());
    for (const auto& [id, replica] : replicas_) {
        include(replica->agenda.get());
    }
    if (blocked) {
        due_ = std::min(due_, now); // Even empty retired sources require reclamation and a future check without a wheel.
    }
    return blocked;
}

void Ephemeris::State::tick() {

    ASTRA_PROFILE_SCOPE("star.ephemeris_state.Ephemeris.State.tick");

    std::vector<Retired> retired; // Wait/reclaim outside domain lock; failure preserves earlier completed expirations.
    ASTRA_PROFILE_BEGIN(profileLock450, "star.ephemeris_state.Ephemeris.State.tick.wait.lock");
    std::unique_lock lock(*gate_);
    ASTRA_PROFILE_END(profileLock450);
    if (!agenda_ && replicas_.empty()) {
        return; // An uninitialized Clock is allowed only when there is no cleanup responsibility.
    }
    for (;;) {
        const auto stamp = reading(); // Resample after each wait; an earlier reading cannot prove completion.
        if (!stamp) {
            throw std::runtime_error("Ephemeris clock is unavailable");
        }
        auto blocked = advance(stamp->time, retired);
        if (!blocked) {
            return;
        }
        Guard waiting(std::move(blocked), lock); // Other-source and local writes may acquire domain while this wait runs.
    }
}

auto Ephemeris::State::execute(auto&& action) {
    return Reading<State>::execute(*this, std::forward<decltype(action)>(action));
}

std::expected<Ephemeris::State::Projection::View, Ephemeris::State::Error> Ephemeris::State::capture(const Scope& scope) {

    ASTRA_PROFILE_SCOPE("star.ephemeris_state.Ephemeris.State.capture");

    if (!scope.valid()) {
        return std::unexpected(Error::Input);
    }

    // Borrow Scene only under domain lock; returned Views own their pages and synchronization domain.
    return execute([&]() -> std::expected<Projection::View, Error> {
        const auto* scene = locate(scope); // Absent Scopes consume no permanent directory quota; Feed retains observer registrations.
        return scene ? scene->capture() : Projection::empty(gate_);
    });
}

std::expected<Ephemeris::State::Projection::Point, Ephemeris::State::Error> Ephemeris::State::find(const Scope& scope, std::string_view uuid) {

    ASTRA_PROFILE_SCOPE("star.ephemeris_state.Ephemeris.State.find");

    if (!scope.valid() || !Ephemeris::valid(uuid)) {
        return std::unexpected(Error::Input);
    }

    // Borrow input UUID synchronously; Point owns name/body references. Missing Scope yields an empty result at cursor zero.
    return execute([&]() -> std::expected<Projection::Point, Error> {
        const auto* scene = locate(scope); // Missing Scope/target returns explicit absence without implicit Scope creation.
        return scene ? scene->find(uuid) : Projection::Point{};
    });
}

std::expected<std::vector<Ephemeris::State::Projection::Event>, Ephemeris::State::Error> Ephemeris::State::changes(const Scope& scope, std::uint64_t since) {

    ASTRA_PROFILE_SCOPE("star.ephemeris_state.Ephemeris.State.changes");

    if (!scope.valid()) {
        return std::unexpected(Error::Input);
    }

    // Scene borrow is confined to this read; future since is invalid and successful temporary expected vectors move to the caller.
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

Ephemeris::State::Source::View Ephemeris::State::source() {

    ASTRA_PROFILE_SCOPE("star.ephemeris_state.Ephemeris.State.source");
    ASTRA_PROFILE_BEGIN(profileLock513, "star.ephemeris_state.Ephemeris.State.source.wait.lock");
    const std::shared_lock lock(*export_); // Export retains original deadlines for receiver-side expiration; it triggers no domain GC.
    ASTRA_PROFILE_END(profileLock513);
    return source_.capture();
}

std::expected<std::vector<Ephemeris::State::Source::Event>, Ephemeris::State::Error> Ephemeris::State::events(std::uint64_t since) {

    ASTRA_PROFILE_SCOPE("star.ephemeris_state.Ephemeris.State.events");
    ASTRA_PROFILE_BEGIN(profileLock518, "star.ephemeris_state.Ephemeris.State.events.wait.lock");
    const std::shared_lock lock(*export_);
    ASTRA_PROFILE_END(profileLock518);
    return source_.replay(since).transform_error([](Source::Error failure) { return failure == Source::Error::Version ? Error::Input : error(failure); });
}

std::expected<Ephemeris::State::Source::Delivery, Ephemeris::State::Error> Ephemeris::State::deliver(std::uint64_t since, std::size_t count, std::size_t bytes) {

    ASTRA_PROFILE_SCOPE("star.ephemeris_state.Ephemeris.State.deliver");
    ASTRA_PROFILE_BEGIN(profileLock523, "star.ephemeris_state.Ephemeris.State.deliver.wait.lock");
    const std::shared_lock lock(*export_); // Snapshot/suffix capture does not wait for remote installation, public-projection preparation, or other-source GC.
    ASTRA_PROFILE_END(profileLock523);
    return source_.deliver(since, count, bytes).transform_error([](Source::Error failure) { return failure == Source::Error::Version ? Error::Input : error(failure); });
}

} // namespace astra

namespace astra {
Ephemeris::State::Choice::Choice(State& owner, Choices::iterator position, std::vector<Contribution> rows, Source::Tree::Key name, std::optional<Record> record, bool changed, bool created, bool single) : owner(&owner), position(position), rows(std::move(rows)), name(std::move(name)), record(std::move(record)), changed(changed), created(created), single(single) {}

Ephemeris::State::Choice::Choice(Choice&& other) noexcept : owner(std::exchange(other.owner, nullptr)), position(other.position), rows(std::move(other.rows)), name(std::move(other.name)), record(std::move(other.record)), changed(other.changed), created(other.created), single(other.single) {}

Ephemeris::State::Choice::~Choice() {
    if (owner && created) {
        owner->choices_.erase(position);
    }
}

void Ephemeris::State::Choice::revise(const Record& replacement) noexcept {
    if (single) {
        record = replacement;
    } else {
        for (auto& row : rows) {
            if (!row.owner) {
                row.record = replacement;
            }
        }
    }
}

void Ephemeris::State::Choice::commit() noexcept {

    // The single candidate remains untouched until the same atomic commit boundary.
    if (single) {
        position->second.front().name.swap(name);
        std::swap(position->second.front().record, *record);
    } else {
        position->second.swap(rows);
        if (position->second.empty()) {
            owner->choices_.erase(position);
        }
    }

    owner = nullptr;
}

std::expected<Ephemeris::State::Choice, Ephemeris::State::Error> Ephemeris::State::choose(const Source::Tree::Key& name, std::optional<Record> record, const Replica* owner, Clock::Time now) {

    // An active same-source replacement is already the sole winner. Stage it inline;
    // removals, expired input and competing sources retain the general merge path.
    const auto found = choices_.find(name);
    const bool single = record && record->deadline > now && found != choices_.end() && found->second.size() == 1 && found->second.front().owner == owner;
    std::vector<Contribution> rows;
    auto key = name;
    std::optional<Record> winner;
    if (single) {
        winner = std::move(record);
    } else {
        rows = found == choices_.end() ? std::vector<Contribution>{} : found->second;
        std::erase_if(rows, [&](const Contribution& row) { return row.owner == owner; });
        if (record) {
            for (const auto& row : rows) {
                if (row.record.deadline <= now) {
                    continue;
                }
                if (!record->generation || !row.record.generation || record->ttl != row.record.ttl || (record->attr != row.record.attr && *record->attr != *row.record.attr) || (record->update == row.record.update && record->data != row.record.data && *record->data != *row.record.data)) {
                    return std::unexpected(Error::Conflict);
                }
            }
            rows.push_back({name, *record, owner});
        }
        const Contribution* selected{}; // Preserve Data-order/generation/deadline arbitration.
        for (const auto& row : rows) {
            if (row.record.deadline <= now) {
                continue;
            }
            if (!selected || std::tie(row.record.update, row.record.generation, row.record.deadline) > std::tie(selected->record.update, selected->record.generation, selected->record.deadline)) {
                selected = &row;
            }
        }
        key = selected ? selected->name : name;
        winner = selected ? std::optional(selected->record) : std::nullopt;
    }

    // Shared immutable identity proves equality; distinct buffers still use exact byte equality.
    auto* scene = locate(*name->scope);
    const auto visible = scene ? scene->find(name->key) : Projection::Point{};
    const bool changed = winner ? !visible.record || (visible.record->attr != winner->attr && *visible.record->attr != *winner->attr) || (visible.record->data != winner->data && *visible.record->data != *winner->data) : visible.record.has_value();
    const auto position = found == choices_.end() ? choices_.emplace(name, std::vector<Contribution>{}).first : found;
    return Choice(*this, position, std::move(rows), std::move(key), std::move(winner), changed, found == choices_.end(), single);
}
} // namespace astra
