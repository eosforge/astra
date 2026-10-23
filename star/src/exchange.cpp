// Exchange per-source replication and recovery data between admitted Star peers.
#include "exchange.hpp"

#include <astra/profile.hpp>

#include <cassert>

namespace astra {
bool Exchange::Budget::acquire(std::size_t bytes) noexcept {
    if (used > maximum || bytes > maximum - used) {
        return false;
    }
    used += bytes;
    return true;
}

void Exchange::Budget::release(std::size_t bytes) noexcept {
    assert(bytes <= used); // Assertions check internal budget ownership only, never untrusted peer input.
    used -= bytes;
}

template <typename Domain>
Exchange::Pipe<Domain>::Pipe(State& state, const std::string& peer, Budget& budget, std::size_t capacity, Steady::time_point now) : state_(state), peer_(peer), budget_(budget), dispatch_(state, capacity, std::min<std::size_t>(capacity, 256 * 1024), &budget, [](void* owner, std::size_t bytes) noexcept { return static_cast<Budget*>(owner)->acquire(bytes); }, [](void* owner, std::size_t bytes) noexcept { static_cast<Budget*>(owner)->release(bytes); }), deadline_(now + std::chrono::seconds(30)) {
    const auto position = state_.received(peer_);
    if (!position) {
        throw std::invalid_argument("Peer source was not admitted");
    }
    received_ = seen_ = *position;
}

template <typename Domain>
Exchange::Pipe<Domain>::~Pipe() {
    clear();
}

template <typename Domain>
void Exchange::Pipe<Domain>::clear() noexcept {
    recovery_.reset(); // State retains installed-Scope coverage; incomplete sources are not acknowledged.
    landing_.reset();
    pending_.clear();
    repair_.reset();
    budget_.release(bytes_ + workspace_);
    bytes_ = workspace_ = 0;
    requested_ = false;
}

template <typename Domain>
Status Exchange::Pipe<Domain>::failure(typename State::Error error) {
    if (error == State::Error::Capacity) {
        return {Status::Code::Capacity, "Peer source capacity exceeded"};
    }
    if (error == State::Error::Clock || error == State::Error::Ended) {
        return {Status::Code::Transport, "Peer source is temporarily unavailable"};
    }
    return {Status::Code::Protocol, "Peer source fact conflicts with installed state"};
}

template <typename Domain>
const std::string& Exchange::Pipe<Domain>::key(const Delta& delta) {
    if constexpr (std::same_as<Domain, Catalog>) {
        return delta.key();
    } else {
        return delta.uuid();
    }
}

template <typename Domain>
Result<void> Exchange::Pipe<Domain>::resume(std::uint64_t position) {

    ASTRA_PROFILE_SCOPE("star.exchange.Exchange.Pipe_Domain.resume");
    const auto result = dispatch_.resume(position);
    if (!result) {
        return std::unexpected(failure(result.error()));
    }
    opened_ = true;
    return {};
}

template <typename Domain>
bool Exchange::Pipe<Domain>::acknowledge(std::uint64_t position) {

    ASTRA_PROFILE_SCOPE("star.exchange.Exchange.Pipe_Domain.acknowledge");
    return dispatch_.acknowledge(position);
}

template <typename Domain>
void Exchange::Pipe<Domain>::acknowledge() {

    ASTRA_PROFILE_SCOPE("star.exchange.Exchange.Pipe_Domain.acknowledge");
    const auto position = state_.received(peer_); // Neither remote head nor repair R directly becomes ACK.
    if (!position) {
        throw std::logic_error("Admitted source disappeared during replication");
    }
    received_ = *position;
    acknowledgement_ = received_;
}

template <typename Domain>
bool Exchange::Pipe<Domain>::ready() const noexcept {
    return target_ && received_ >= *target_ && !landing_ && !recovery_;
}

template <typename Domain>
Result<void> Exchange::Pipe<Domain>::changes(const Changes& message, Steady::time_point now) {

    ASTRA_PROFILE_SCOPE("star.exchange.Exchange.Pipe_Domain.changes");

    if (landing_ || recovery_ || !Parcel::valid(message) || (message.entries().empty() ? message.head() != seen_ : (seen_ == UINT64_MAX || message.entries(0).position() != seen_ + 1))) {
        return Status::protocol("Non-contiguous peer changes");
    }
    if (!target_) {
        target_ = message.head();
    }
    if (message.entries().empty()) {
        acknowledge(); // Empty sources still complete initial synchronization without synthetic commits.
        return {};
    }
    const auto bytes = message.ByteSizeLong() + sizeof(Pending); // Charge queue nodes as well as bodies, including empty packets.
    constexpr std::size_t backlog = 8 * 1024 * 1024;             // Per-domain backlog hard limit matching send packet capacity.
    if (pending_.size() == 64 || bytes > backlog || bytes_ > backlog - bytes || !budget_.acquire(bytes)) {
        return Status::capacity("Peer recovery backlog exceeded");
    }
    try {
        pending_.push_back({message, 0, bytes}); // Retain bounded original packets without duplicating bodies into per-key tasks.
    } catch (...) {
        budget_.release(bytes);
        throw;
    }
    bytes_ += bytes;
    seen_ = message.entries().rbegin()->position();
    return drain(now);
}

template <typename Domain>
Result<void> Exchange::Pipe<Domain>::snapshot(const Snapshot& page, Steady::time_point now) {

    ASTRA_PROFILE_SCOPE("star.exchange.Exchange.Pipe_Domain.snapshot");

    /// Release receive workspace on each page failure, independently of final OnDone; Session still terminates the logical stream.
    struct Guard {
        /// Borrows this receiver only for the snapshot call.
        Pipe& pipe;
        /// Set only after successful page acceptance; errors/exceptions clear private candidates and budget.
        bool keep{};

        ~Guard() { // Noexcept clear cannot regress an acknowledged source.
            if (!keep) {
                pipe.clear();
            }
        }
    } guard{*this}; // Covers append allocation exceptions and restore failure without another heap object.

    if (recovery_) {
        return Status::protocol("Peer snapshot installation is still in progress");
    }
    if (!landing_) {
        if (page.position() < seen_) {
            return Status::protocol("Peer snapshot regresses received prefix");
        }
        auto candidate = state_.prepare(peer_, page.position()); // State rechecks contiguous position, target coverage, and trusted retirement.
        if (!candidate) {
            return std::unexpected(failure(candidate.error()));
        }
        constexpr std::size_t workspace = 64 * 1024 * 1024; // One full-source candidate reserves at most the domain native limit.
        if (!budget_.acquire(workspace)) {
            return Status::capacity("Concurrent peer snapshots exceed budget");
        }
        clear(); // A baseline supersedes backlog/repair, but discarding them cannot advance installed position.
        workspace_ = workspace;
        landing_.emplace(std::move(*candidate));
        deadline_ = now + std::chrono::seconds(30);
        if (!target_) {
            target_ = page.position();
        }
    }
    const auto accepted = landing_->append(page, received_);
    if (!accepted) {
        return accepted.error() == Landing<Domain>::Error::Capacity ? Status::capacity("Peer snapshot exceeds limits") : Status::protocol("Invalid peer snapshot");
    }
    deadline_ = now + std::chrono::seconds(30); // Each page must progress; append rejects empty incomplete pages.
    if (!landing_->complete()) {
        guard.keep = true;
        return {};
    }
    auto complete = landing_->take(received_);
    if (!complete) {
        return Status::protocol("Peer snapshot lacks a complete boundary");
    }
    auto installed = state_.restore(peer_, std::move(*complete));
    if (!installed) {
        return std::unexpected(failure(installed.error()));
    }
    recovery_.emplace(std::move(*installed));
    landing_.reset();
    seen_ = page.position(); // Complete target received, but ACK still waits for all Scope installations.
    guard.keep = true;
    return {};
}

template <typename Domain>
Result<void> Exchange::Pipe<Domain>::missing(const Delta& delta, Steady::time_point now) {

    ASTRA_PROFILE_SCOPE("star.exchange.Exchange.Pipe_Domain.missing");

    proto::astra::v1::Repair request; // Correlate only source, domain, address, target, and triggering position.
    request.set_domain(domain);
    request.mutable_scope()->CopyFrom(delta.scope());
    request.set_key(key(delta));
    request.set_trigger(delta.position());
    if constexpr (std::same_as<Domain, Catalog>) {
        request.set_version(delta.lease().version());
    }
    repair_.emplace(std::move(request));
    requested_ = false;
    deadline_ = now + std::chrono::seconds(30);
    return {};
}

template <typename Domain>
Result<bool> Exchange::Pipe<Domain>::apply(const Delta& delta, Steady::time_point now) {

    ASTRA_PROFILE_SCOPE("star.exchange.Exchange.Pipe_Domain.apply");

    const auto scope = Parcel::scope(delta.scope()); // The packet is validated; retain owned Scope rather than borrowing temporary text.
    if (!scope) {
        return Status::protocol("Invalid peer scope");
    }
    const auto covered = state_.covered(peer_, delta.position(), *scope, key(delta));
    if (!covered) {
        return std::unexpected(failure(covered.error()));
    }
    if (*covered) {
        return true; // Covered old target events no longer require released payloads.
    }
    std::optional<typename Domain::Record> record;
    auto form = State::Source::Form::Record;
    bool partial{};
    if (delta.has_record()) {
        record = Parcel::record(delta.record());
        if (!record) {
            return Status::protocol("Invalid complete peer record");
        }
    } else if (delta.has_lease()) {
        const auto previous = state_.replica(peer_, *scope, key(delta));
        if (!previous) {
            return std::unexpected(failure(previous.error()));
        }
        record = *previous;
        if constexpr (std::same_as<Domain, Catalog>) {
            if (record && (!record->value || record->version != delta.lease().version())) {
                record.reset();
            }
        }
        if (!record) {
            const auto requested = missing(delta, now);
            return requested ? Result<bool>(false) : std::unexpected(requested.error());
        }
        record->deadline = *Parcel::time(delta.lease().deadline());
        if constexpr (std::same_as<Domain, Ephemeris>) {
            record->renewal = delta.lease().order();
        }
        form = State::Source::Form::Renew;
        partial = true;
    } else if constexpr (std::same_as<Domain, Ephemeris>) {
        if (delta.has_data()) {
            const auto previous = state_.replica(peer_, *scope, key(delta));
            if (!previous) {
                return std::unexpected(failure(previous.error()));
            }
            record = *previous;
            if (!record) {
                const auto requested = missing(delta, now);
                return requested ? Result<bool>(false) : std::unexpected(requested.error());
            }
            record->data = std::make_shared<const Ephemeris::Buffer>(delta.data().data().begin(), delta.data().data().end());
            record->update = delta.data().order();
            if (delta.data().deadline()) {
                record->deadline = *Parcel::time(delta.data().deadline());
            }
            form = State::Source::Form::Data;
            partial = true;
        } else if (delta.has_erase()) {
            form = State::Source::Form::Erase;
        } else {
            return Status::protocol("Invalid Ephemeris peer operation");
        }
    } else {
        return Status::protocol("Invalid Catalog peer operation");
    }
    const auto installed = [&] {
        if constexpr (std::same_as<Domain, Catalog>) {
            return state_.apply(peer_, delta.position(), *scope, key(delta), *record, form);
        } else {
            return state_.apply(peer_, delta.position(), *scope, key(delta), record, form);
        }
    }();
    if (!installed) {
        if (partial && installed.error() == State::Error::Ended) {
            const auto requested = missing(delta, now); // If final State advancement finds an expired body, require complete repair rather than acknowledging a partial record.
            return requested ? Result<bool>(false) : std::unexpected(requested.error());
        }
        return std::unexpected(failure(installed.error()));
    }
    return true;
}

template <typename Domain>
Result<void> Exchange::Pipe<Domain>::drain(Steady::time_point now) {

    ASTRA_PROFILE_SCOPE("star.exchange.Exchange.Pipe_Domain.drain");

    unsigned remaining = 256; // At most one packet's commit count per round, preventing post-repair Runtime monopolization.
    while (!repair_ && !pending_.empty() && remaining != 0) {
        auto& pending = pending_.front();
        while (pending.offset < pending.message.entries_size() && remaining != 0) {
            const auto installed = apply(pending.message.entries(pending.offset), now);
            if (!installed) {
                return std::unexpected(installed.error());
            }
            if (!*installed) {
                return {}; // Keep the triggering target in its packet; after repair, covered confirms it without skipping other targets.
            }
            ++pending.offset;
            --remaining;
            acknowledge();
            deadline_ = now + std::chrono::seconds(30);
        }
        if (pending.offset == pending.message.entries_size()) {
            budget_.release(pending.bytes);
            bytes_ -= pending.bytes;
            pending_.pop_front();
        }
    }
    return {};
}

template <typename Domain>
Result<void> Exchange::Pipe<Domain>::repaired(const proto::astra::v1::Repaired& reply, Steady::time_point now) {

    if (!repair_) {
        return {}; // A full baseline may supersede old repair; late responses cannot regress data.
    }
    const auto& request = reply.request();
    if (request.domain() != domain || request.scope().sector() != repair_->scope().sector() || request.scope().spectrum() != repair_->scope().spectrum() || request.key() != repair_->key() || request.trigger() != repair_->trigger() || request.version() != repair_->version() || reply.position() < request.trigger()) {
        return Status::protocol("Peer repair correlation mismatch");
    }
    const auto scope = Parcel::scope(request.scope());
    if (!scope) {
        return Status::protocol("Invalid peer repair scope");
    }
    std::optional<typename Domain::Record> record;
    if (!reply.has_unknown()) {
        if constexpr (std::same_as<Domain, Catalog>) {
            if (!reply.has_catalog()) {
                return Status::protocol("Peer repair has the wrong domain");
            }
            record = Parcel::record(reply.catalog());
        } else {
            if (!reply.has_ephemeris()) {
                return Status::protocol("Peer repair has the wrong domain");
            }
            record = Parcel::record(reply.ephemeris());
        }
        if (!record) {
            return Status::protocol("Invalid complete peer repair");
        }
    }
    const auto installed = state_.repair(peer_, reply.position(), *scope, request.key(), std::move(record));
    if (!installed) {
        return std::unexpected(failure(installed.error()));
    }
    repair_.reset();
    requested_ = false;
    deadline_ = now + std::chrono::seconds(30);
    return drain(now); // Resume from the triggering commit; R cannot skip other keys/Scopes.
}

template <typename Domain>
Result<void> Exchange::Pipe<Domain>::repair(const proto::astra::v1::Repair& request, Packet& response) {

    ASTRA_PROFILE_SCOPE("star.exchange.Exchange.Pipe_Domain.repair");

    const auto scope = Parcel::scope(request.scope());
    if (!scope || request.domain() != domain || request.trigger() == 0 || (std::same_as<Domain, Catalog> ? request.version() == 0 : request.version() != 0)) {
        return Status::protocol("Invalid peer repair request");
    }
    const auto current = state_.resolve(*scope, request.key()); // Native fact and source position come from one commit boundary.
    if (!current) {
        return std::unexpected(failure(current.error()));
    }
    if (current->position < request.trigger()) {
        return Status::protocol("Peer repair requests a future position");
    }
    auto* reply = response.mutable_repaired();
    reply->mutable_request()->CopyFrom(request);
    reply->set_position(current->position);
    if (!current->record) {
        reply->mutable_unknown();
    } else if constexpr (std::same_as<Domain, Catalog>) {
        Parcel::record(*reply->mutable_catalog(), *current->record);
    } else {
        Parcel::record(*reply->mutable_ephemeris(), *current->record);
    }
    return {};
}

template <typename Domain>
bool Exchange::Pipe<Domain>::expired(Steady::time_point now) const noexcept {
    return (!ready() || landing_ || recovery_ || repair_ || !pending_.empty()) && now >= deadline_;
}

template <typename Domain>
Result<const Exchange::Packet*> Exchange::Pipe<Domain>::prepare(Steady::time_point now) {

    ASTRA_PROFILE_SCOPE("star.exchange.Exchange.Pipe_Domain.prepare");

    if (expired(now)) {
        return Status::timeout("Peer synchronization made no progress");
    }
    if (packet_) {
        return &*packet_;
    }
    if (recovery_) {
        const auto installed = recovery_->step(); // Never retain locks across control rounds, leaving execution opportunities for other sources and SDK calls.
        if (!installed) {
            return std::unexpected(failure(installed.error()));
        }
        deadline_ = now + std::chrono::seconds(30);
        if (*installed) {
            recovery_.reset();
            budget_.release(workspace_);
            workspace_ = 0;
            acknowledge(); // Return the new source-wide position only after finish succeeds.
        }
    }
    const auto drained = drain(now);
    if (!drained) {
        return std::unexpected(drained.error());
    }
    if (resume_ || (repair_ && !requested_) || acknowledgement_) {
        Packet packet; // Publish control packets after complete encoding; allocation failure preserves recovery responsibility.
        if (resume_) {
            packet.mutable_resume()->set_domain(domain);
            packet.mutable_resume()->set_version(received_);
            resume_ = false;
        } else if (repair_ && !requested_) {
            packet.mutable_repair()->CopyFrom(*repair_);
            requested_ = true;
        } else {
            packet.mutable_ack()->set_domain(domain);
            packet.mutable_ack()->set_version(*acknowledgement_);
            acknowledgement_.reset();
        }
        packet_.emplace(std::move(packet));
        dispatched_ = false;
        return &*packet_;
    }
    if (!opened_) {
        return nullptr;
    }
    const auto packet = dispatch_.prepare();
    if (!packet) {
        return std::unexpected(failure(packet.error()));
    }
    dispatched_ = *packet != nullptr;
    return *packet;
}

template <typename Domain>
Exchange::Packet Exchange::Pipe<Domain>::take() {

    ASTRA_PROFILE_SCOPE("star.exchange.Exchange.Pipe_Domain.take");
    if (dispatched_) {
        dispatched_ = false;
        return dispatch_.dispatched();
    }
    assert(packet_);
    auto packet = std::move(*packet_);
    packet_.reset();
    return packet;
}

Exchange::Exchange(Catalog::State& catalog, Ephemeris::State& ephemeris, std::string peer, Budget& budget, std::size_t capacity, Steady::time_point now) : peer_(std::move(peer)), budget_(budget), capacity_(capacity), catalog_(catalog, peer_, budget, capacity, now), ephemeris_(ephemeris, peer_, budget, capacity, now) {}

Exchange::~Exchange() {
    budget_.release(responseBytes_); // Each Pipe releases its own candidate/backlog; only repair responses remain here.
}

Result<void> Exchange::receive(const Packet& packet, Steady::time_point now) {

    ASTRA_PROFILE_SCOPE("star.exchange.Exchange.receive");
    ASTRA_PROFILE_COUNT("star.exchange.received", 1);
    ASTRA_PROFILE_COUNT("star.exchange.received_ack", packet.has_ack());

    using enum proto::astra::v1::Domain;
    // Dispatch directly by oneof; explicitly reject Session control messages without runtime reflection.
    switch (packet.body_case()) {
    case Packet::kResume:
        if (packet.resume().domain() == DOMAIN_CATALOG) {
            return catalog_.resume(packet.resume().version());
        }
        if (packet.resume().domain() == DOMAIN_EPHEMERIS) {
            return ephemeris_.resume(packet.resume().version());
        }
        break;
    case Packet::kAck: {
        const auto& ack = packet.ack();
        const bool accepted = ack.domain() == DOMAIN_CATALOG ? catalog_.acknowledge(ack.version()) : ack.domain() == DOMAIN_EPHEMERIS && ephemeris_.acknowledge(ack.version());
        return accepted ? Result<void>{} : Status::protocol("Invalid cumulative peer acknowledgement");
    }
    case Packet::kCatalogSnapshot:
        return catalog_.snapshot(packet.catalog_snapshot(), now);
    case Packet::kEphemerisSnapshot:
        return ephemeris_.snapshot(packet.ephemeris_snapshot(), now);
    case Packet::kCatalogChanges:
        return catalog_.changes(packet.catalog_changes(), now);
    case Packet::kEphemerisChanges:
        return ephemeris_.changes(packet.ephemeris_changes(), now);
    case Packet::kRepaired:
        if (packet.repaired().request().domain() == DOMAIN_CATALOG) {
            return catalog_.repaired(packet.repaired(), now);
        }
        if (packet.repaired().request().domain() == DOMAIN_EPHEMERIS) {
            return ephemeris_.repaired(packet.repaired(), now);
        }
        break;
    case Packet::kRepair: {
        if (responses_.size() == 8) {
            return Status::capacity("Too many pending peer repairs");
        }
        Packet response;
        const auto& request = packet.repair();
        const auto prepared = request.domain() == DOMAIN_CATALOG ? catalog_.repair(request, response) : request.domain() == DOMAIN_EPHEMERIS ? ephemeris_.repair(request, response)
                                                                                                                                             : Result<void>(Status::protocol("Invalid repair domain"));
        if (!prepared) {
            return prepared;
        }
        const auto encoded = response.ByteSizeLong();     // The immutable response shares one size traversal for wire and retention accounting.
        const auto bytes = encoded + sizeof(Response);    // Charge repair queue nodes separately from frame capacity.
        constexpr std::size_t replies = 16 * 1024 * 1024; // Bound total pending repair responses; check the base before subtracting allowance.
        if (encoded > capacity_ || bytes > replies || responseBytes_ > replies - bytes || !budget_.acquire(bytes)) {
            return Status::capacity("Peer repair response budget exceeded");
        }
        try {
            responses_.push_back({std::move(response), bytes});
        } catch (...) {
            budget_.release(bytes);
            throw;
        }
        responseBytes_ += bytes;
        return {};
    }
    case Packet::kHello:       // Session consumes handshake messages outside business recovery.
    case Packet::kPing:        // Session consumes heartbeat requests.
    case Packet::kPong:        // Session consumes heartbeat replies.
    case Packet::kRejection:   // Protocol rejection terminates through Session.
    case Packet::BODY_NOT_SET: // Empty and unknown-fields-only packets are invalid business messages.
        break;
    }
    return Status::protocol("Unexpected peer data message");
}

Result<const Exchange::Packet*> Exchange::prepare(Steady::time_point now) {

    ASTRA_PROFILE_SCOPE("star.exchange.Exchange.prepare");

    if (catalog_.expired(now) || ephemeris_.expired(now)) {
        return Status::timeout("Peer synchronization made no progress");
    }

    // Prioritize repair replies so two peers waiting for completion do not send only ordinary large packets.
    if (!responses_.empty()) {
        selected_ = 3;
        return &responses_.front().packet;
    }
    for (unsigned attempt = 0; attempt != 2; ++attempt) {
        const auto which = (turn_ + attempt) % 2;
        auto packet = which == 0 ? catalog_.prepare(now) : ephemeris_.prepare(now);
        if (!packet) {
            return std::unexpected(packet.error());
        }
        if (*packet) {
            selected_ = which + 1;
            return *packet;
        }
    }
    selected_ = 0;
    return nullptr;
}

Exchange::Packet Exchange::take() {

    ASTRA_PROFILE_SCOPE("star.exchange.Exchange.take");

    if (selected_ == 3) {
        auto packet = std::move(responses_.front().packet);
        const auto bytes = responses_.front().bytes;
        responses_.pop_front();
        responseBytes_ -= bytes;
        budget_.release(bytes); // Session owns the sole in-flight packet's lifetime and hard capacity.
        selected_ = 0;
        return packet;
    }
    assert(selected_ == 1 || selected_ == 2);
    const auto selected = std::exchange(selected_, 0U);
    turn_ = selected % 2;
    return selected == 1 ? catalog_.take() : ephemeris_.take();
}

bool Exchange::ready() const noexcept {
    return catalog_.ready() && ephemeris_.ready();
}

bool Exchange::pending() const noexcept {
    return catalog_.pending() || ephemeris_.pending();
}
} // namespace astra
