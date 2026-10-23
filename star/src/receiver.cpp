// Receive authoritative Almanac state without exposing incomplete replacement snapshots.
#include "receiver.hpp"

#include "orbit.pb.h"
#include <astra/profile.hpp>

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace astra {
Receiver::Receiver(Library& output, Access& access) : output_(output), access_(access), inventory_(output.positions()) {}

bool Receiver::ready() const noexcept {
    return ready_ && !failed_;
}

bool Receiver::valid(const Scope& scope, const proto::comet::v1::AlmanacChange& change, bool snapshot) {

    if (!Scope::text(change.key(), 1024) || change.action_case() == proto::comet::v1::AlmanacChange::ACTION_NOT_SET || (snapshot && change.action_case() != proto::comet::v1::AlmanacChange::kValue) || change.value().size() > 1024 * 1024) {
        return false;
    }
    if (scope.sector != "__auth" || scope.spectrum != "comet") {
        return true;
    }

    // Internal credentials obey the management endpoint's limits; malformed state cannot produce partially valid authentication.
    if (change.key().size() > 128 || change.value().size() > 8192) {
        return false;
    }
    if (change.action_case() == proto::comet::v1::AlmanacChange::kErase) {
        return true;
    }
    proto::orbit::v1::Credential credential; // Decode only the fixed internal Scope, never ordinary application Buffers.
    return credential.ParseFromString(change.value()) && !credential.secret().empty() && credential.secret().size() <= 4096;
}

Result<void> Receiver::failure(Almanac::Error error) {
    if (error == Almanac::Error::Capacity) {
        return Status::capacity("Almanac installation capacity exceeded");
    }
    if (error == Almanac::Error::Version || error == Almanac::Error::History || error == Almanac::Error::Unready) {
        return Status::conflict("Almanac installation is not continuous");
    }
    return Status::protocol("Invalid Almanac installation data");
}

Result<void> Receiver::plan(const proto::polaris::v1::Inventory& page) {

    ASTRA_PROFILE_SCOPE("star.receiver.Receiver.plan");

    if (planned_) {
        return Status::protocol("Repeated initial Almanac plan");
    }
    // Staged minimum positions become startup requirements only after all plan pages complete.
    for (const auto& position : page.positions()) {
        Scope scope{position.scope().sector(), position.scope().spectrum()};
        if (!scope.valid() || plan_.contains(scope) || plan_.size() >= 4096) {
            return Status::protocol("Invalid or duplicate Almanac plan scope");
        }
        if (const auto book = output_.find(scope)) {
            if (const auto current = book->usage().version; current && *current > position.version()) {
                return Status::conflict("Authority is behind installed Almanac");
            }
        }
        plan_.emplace(std::move(scope), position.version());
    }
    planned_ = page.complete();
    return {};
}

void Receiver::acknowledge(const Scope& scope, std::uint64_t version) {
    // Map presence denotes an installed baseline, including a valid empty version zero.
    auto& present = acknowledgements_[scope];
    present = std::max(present, version);
}

Result<void> Receiver::snapshot(const proto::polaris::v1::Snapshot& page) {

    ASTRA_PROFILE_SCOPE("star.receiver.Receiver.snapshot");

    // Every page carries stable Scope/version; check business page limits in addition to upstream gRPC decode budgets.
    Scope scope{page.scope().sector(), page.scope().spectrum()};
    if (!scope.valid() || !page.has_version() || page.entries_size() > 65536 || (!page.complete() && page.entries().empty())) {
        return Status::protocol("Invalid Almanac snapshot page");
    }
    for (const auto& entry : page.entries()) {
        if (!valid(scope, entry, true)) {
            return Status::protocol("Invalid Almanac snapshot record");
        }
    }
    if (!draft_) {
        auto draft = output_.prepare(scope, page.version()); // Private preparation creates no routing and changes no old read view.
        if (!draft) {
            return failure(draft.error());
        }
        draft_.emplace(std::move(*draft));
        if (scope.sector == "__auth" && scope.spectrum == "comet") {
            credentials_.emplace();
        }
    }
    if (draft_->scope() != scope || draft_->version() != page.version()) {
        return Status::protocol("Almanac snapshot scope or version changed");
    }

    // Copy each value once into immutable storage shared by later views, without retaining writable Proto buffers.
    for (const auto& entry : page.entries()) {
        if (credentials_) {
            proto::orbit::v1::Credential credential; // Bodies were prevalidated; candidate index still accepts only complete valid SECRET values.
            if (!credential.ParseFromString(entry.value()) || !credentials_->set(entry.key(), Almanac::Buffer(credential.secret().begin(), credential.secret().end()))) {
                return Status::protocol("Invalid credential snapshot index");
            }
        }
        Almanac::Buffer value(entry.value().begin(), entry.value().end());
        if (auto added = draft_->set(entry.key(), std::move(value)); !added) {
            return failure(added.error());
        }
    }
    if (page.complete()) {
        // Commit credentials and index together. Access invalidates old authorization first; stream cancellation propagates after unlock.
        auto commit = [&] { return output_.reset(std::move(*draft_)); };
        if (auto installed = credentials_ ? access_.reset(std::move(*credentials_), commit) : commit(); !installed) {
            return failure(installed.error());
        }
        draft_.reset();
        credentials_.reset();
        acknowledge(scope, page.version());
    }
    return {};
}

Result<void> Receiver::updates(const proto::polaris::v1::Updates& page) {

    ASTRA_PROFILE_SCOPE("star.receiver.Receiver.updates");

    Scope scope{page.scope().sector(), page.scope().spectrum()}; // One packet belongs to one actual group.
    if (!scope.valid() || page.patches().empty() || page.patches_size() > 65536 || draft_) {
        return Status::protocol("Invalid Almanac update batch");
    }
    // Previous checks packet-internal continuity; native Almanac skips the already installed prefix idempotently.
    std::uint64_t previous{};
    for (const auto& patch : page.patches()) {
        if ((patch.has_change() == !patch.changes().empty()) || patch.version() == 0 || (previous != 0 && (previous == std::numeric_limits<std::uint64_t>::max() || patch.version() != previous + 1)) || (patch.has_change() && !valid(scope, patch.change(), false))) {
            return Status::protocol("Invalid or noncontiguous Almanac patches");
        }
        if (!patch.changes().empty()) {
            if (scope.sector.starts_with("__")) {
                return Status::protocol("Internal Almanac batch is forbidden");
            }
            for (const auto& entry : patch.changes()) {
                if (!valid(scope, entry, false)) {
                    return Status::protocol("Invalid Almanac batch entry");
                }
            }
        }
        previous = patch.version();
    }

    // Every successful prefix is complete and visible. Later failure preserves its version for the reconnect inventory.
    for (const auto& patch : page.patches()) {
        if (!patch.changes().empty()) {
            std::vector<Almanac::Change> changes; // Fix the complete batch body before commit; receiver never publishes per item.
            changes.reserve(static_cast<std::size_t>(patch.changes_size()));
            for (const auto& entry : patch.changes()) {
                Almanac::Value value; // Null means Delete; empty Buffer is a valid value.
                if (entry.action_case() == proto::comet::v1::AlmanacChange::kValue) {
                    value = std::make_shared<const Almanac::Buffer>(entry.value().begin(), entry.value().end());
                }
                changes.push_back({std::make_shared<const std::string>(entry.key()), std::move(value), patch.version()});
            }
            if (auto applied = output_.apply(scope, patch.version(), std::move(changes)); !applied) {
                return failure(applied.error());
            }
            acknowledge(scope, *output_.find(scope)->usage().version);
            continue;
        }
        std::optional<Almanac::Buffer> value; // Absent means Delete; present empty bytes mean Set.
        if (patch.change().action_case() == proto::comet::v1::AlmanacChange::kValue) {
            value.emplace(patch.change().value().begin(), patch.change().value().end());
        }
        auto commit = [&] { return output_.apply(scope, patch.version(), patch.change().key(), std::move(value)); };
        std::expected<bool, Almanac::Error> applied; // One actual commit per patch; replay cannot trigger another revocation.
        if (scope.sector == "__auth" && scope.spectrum == "comet") {
            std::optional<Almanac::Buffer> secret; // Delete creates no credential; empty SECRET was rejected in whole-packet validation.
            if (value) {
                proto::orbit::v1::Credential credential;
                if (!credential.ParseFromString(patch.change().value())) {
                    return Status::protocol("Invalid credential patch index");
                }
                secret.emplace(credential.secret().begin(), credential.secret().end());
            }
            applied = access_.apply(patch.change().key(), std::move(secret), commit);
        } else {
            applied = commit();
        }
        if (!applied) {
            return failure(applied.error());
        }
        acknowledge(scope, *output_.find(scope)->usage().version);
    }
    return {};
}

Result<void> Receiver::receive(const proto::polaris::v1::Packet& packet) {

    ASTRA_PROFILE_SCOPE("star.receiver.Receiver.receive");

    if (failed_) {
        return Status::protocol("Almanac receiver is closed");
    }
    try {
        auto result = process(packet); // Only this entry advances protocol state; failure discards preparation and permanently closes this receiver.
        if (!result) {
            failed_ = true;
            draft_.reset();
        }
        return result;
    } catch (...) {
        failed_ = true;
        draft_.reset();
        throw;
    }
}

Result<void> Receiver::process(const proto::polaris::v1::Packet& packet) {

    ASTRA_PROFILE_SCOPE("star.receiver.Receiver.process");

    if (packet.ByteSizeLong() > 8 * 1024 * 1024) {
        return Status::capacity("Almanac packet exceeds receive budget");
    }
    if (packet.has_plan()) {
        return plan(packet.plan());
    }
    if (!planned_) {
        return Status::protocol("Almanac initial plan is incomplete");
    }

    if (packet.has_snapshot()) {
        return snapshot(packet.snapshot());
    }
    if (packet.has_updates()) {
        return updates(packet.updates());
    }
    if (packet.has_probe()) {
        if (inventory_) {
            return Status::protocol("Overlapping Almanac inventory probes");
        }
        inventory_ = output_.positions();
        position_ = 0;
        return {};
    }
    if (packet.has_ready() && !ready_ && !draft_) {
        // Ready is a server observation; client independently verifies complete installation of this round's plan.
        for (const auto& [scope, minimum] : plan_) {
            const auto book = output_.find(scope);
            if (!book || !book->usage().version || *book->usage().version < minimum) {
                return Status::protocol("Premature Almanac readiness");
            }
        }
        ready_ = true;
        return {};
    }
    return Status::protocol("Unexpected Almanac control frame");
}

std::optional<proto::polaris::v1::Packet> Receiver::next(std::size_t maximum) {

    ASTRA_PROFILE_SCOPE("star.receiver.Receiver.next");

    if (maximum < 1024 || maximum > 8 * 1024 * 1024) {
        throw std::invalid_argument("Invalid Almanac negotiated send capacity");
    }

    if (failed_) {
        return std::nullopt;
    }

    proto::polaris::v1::Packet packet; // Reuse owned frames only after gRPC write completion.
    if (inventory_) {
        auto* page = packet.mutable_inventory(); // Even empty inventories send complete; zero messages do not establish completeness.
        std::size_t bytes = 32;                  // Conservative encoded position cost includes two addresses of at most 128 bytes and a version.
        while (position_ < inventory_->size()) {
            const auto& position = (*inventory_)[position_];
            // Budget before encoding rather than exceeding limits then stopping next round. At least one position fits within 1024 bytes.
            const auto cost = position.scope.sector.size() + position.scope.spectrum.size() + 32;
            if (bytes + cost > std::min(maximum, std::size_t{256 * 1024})) {
                break;
            }
            auto* entry = page->add_positions();
            entry->mutable_scope()->set_sector(position.scope.sector);
            entry->mutable_scope()->set_spectrum(position.scope.spectrum);
            entry->set_version(position.version);
            bytes += cost;
            ++position_;
        }
        if (position_ == inventory_->size()) {
            page->set_complete(true);
            inventory_.reset();
        }
        return packet;
    }
    if (acknowledgements_.empty()) {
        return std::nullopt;
    }

    const auto& [scope, version] = *acknowledgements_.begin(); // Preserve pending ACK until encoding succeeds so allocation failure loses no confirmation evidence.
    auto* position = packet.mutable_acknowledged();
    position->mutable_scope()->set_sector(scope.sector);
    position->mutable_scope()->set_spectrum(scope.spectrum);
    position->set_version(version);
    acknowledgements_.erase(acknowledgements_.begin());
    return packet;
}
} // namespace astra
