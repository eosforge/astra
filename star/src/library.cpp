// Retain authoritative Almanac views and history for consistent downstream delivery.
#include "library.hpp"

#include <astra/profile.hpp>

#include <set>
#include <stdexcept>

namespace astra {
Library::Library() : Library(Limits{}) {}

Library::Library(Limits limits, Notify changed) : limits_(limits), changed_(std::move(changed)) {
    if (limits.scopes == 0 || limits.scopes > 16384 || limits.scope.bytes > limits.bytes || limits.bytes > 4ULL * 1024 * 1024 * 1024) {
        throw std::invalid_argument("Invalid Almanac library capacity");
    }
}

Library::Draft::Draft(const Library* owner, Scope scope, std::uint64_t version, std::shared_ptr<Almanac> book) : owner_(owner), scope_(std::move(scope)), version_(version), book_(std::move(book)), draft_(book_->prepare(version)) {}

std::expected<void, Almanac::Error> Library::Draft::set(std::string key, Almanac::Buffer value) {

    if (!Scope::text(key, 1024)) {
        return std::unexpected(Almanac::Error::Input);
    }
    // Update accounting only after native preparation succeeds; duplicate keys cannot add cost twice.
    const auto cost = key.size() + value.size();
    if (auto result = draft_.set(std::move(key), std::move(value)); !result) {
        return result;
    }
    bytes_ += cost;
    return {};
}

const Scope& Library::Draft::scope() const noexcept {
    return scope_;
}

std::uint64_t Library::Draft::version() const noexcept {
    return version_;
}

std::shared_ptr<Almanac> Library::locate(const Scope& scope) const {

    // Lock only for index lookup; returned shared ownership needs no outer lock.
    const std::shared_lock lock(mutex_);
    const auto sector = books_.find(scope.sector);
    if (sector == books_.end()) {
        return {};
    }
    const auto spectrum = sector->second.find(scope.spectrum);
    return spectrum == sector->second.end() ? nullptr : spectrum->second;
}

std::shared_ptr<const Almanac> Library::find(const Scope& scope) const {
    return scope.valid() ? locate(scope) : nullptr;
}

std::expected<Library::Draft, Almanac::Error> Library::prepare(Scope scope, std::uint64_t version) {

    ASTRA_PROFILE_SCOPE("star.library.Library.prepare");

    if (!scope.valid()) {
        return std::unexpected(Almanac::Error::Input);
    }
    // Shared book ownership avoids borrowing Map nodes across receiving; full content remains private in Draft.
    auto book = locate(scope);
    if (book) {
        const auto current = book->usage();
        if (current.version && version < *current.version) {
            return std::unexpected(Almanac::Error::Version);
        }
    } else {
        ASTRA_PROFILE_BEGIN(profileLock65, "star.library.Library.prepare.wait.lock");
        const std::lock_guard lock(writer_); // Check complete-group capacity before candidate reservation and again at commit.
        ASTRA_PROFILE_END(profileLock65);
        if (scopes_ >= limits_.scopes) {
            return std::unexpected(Almanac::Error::Capacity);
        }
        book = std::make_shared<Almanac>(limits_.scope);
    }
    return Draft(this, std::move(scope), version, std::move(book));
}

std::expected<bool, Almanac::Error> Library::reset(Draft&& draft) {

    ASTRA_PROFILE_SCOPE("star.library.Library.reset");

    if (draft.owner_ != this || !draft.book_) {
        return std::unexpected(Almanac::Error::Input);
    }
    // Writer serializes global accounting without blocking existing-Scope point reads or immutable traversal.
    ASTRA_PROFILE_BEGIN(profileLock80, "star.library.Library.reset.wait.writer");
    const std::lock_guard writer(writer_);
    ASTRA_PROFILE_END(profileLock80);
    const auto existing = locate(draft.scope_);
    if (existing && existing != draft.book_) {
        return std::unexpected(Almanac::Error::Version);
    }
    const auto before = draft.book_->usage();
    if (draft.bytes_ > limits_.bytes - (bytes_ - before.bytes) || (!existing && scopes_ == limits_.scopes)) {
        return std::unexpected(Almanac::Error::Capacity);
    }

    if (!existing) {
        // Prepare both routing levels for new groups; readers cannot see partial entries. Native installation failure rolls routing back.
        ASTRA_PROFILE_BEGIN(profileLock92, "star.library.Library.reset.wait.lock");
        const std::unique_lock lock(mutex_); // New groups have no old content; commit swaps only prepared roots.
        ASTRA_PROFILE_END(profileLock92);
        const auto [sector, created] = books_.try_emplace(draft.scope_.sector);
        try {
            sector->second.emplace(draft.scope_.spectrum, draft.book_);
            if (auto installed = draft.book_->reset(std::move(draft.draft_)); !installed) {
                sector->second.erase(draft.scope_.spectrum);
                if (created) {
                    books_.erase(sector);
                }
                return installed;
            }
        } catch (...) {
            sector->second.erase(draft.scope_.spectrum);
            if (created) {
                books_.erase(sector);
            }
            throw;
        }
        ++scopes_;
    } else {
        if (auto installed = existing->reset(std::move(draft.draft_)); !installed || !*installed) {
            return installed;
        }
    }

    // Data is published; remaining scalar updates cannot fail. Consume candidates to prevent repeat installation of writable containers.
    bytes_ = bytes_ - before.bytes + draft.bytes_;
    history_ -= before.history;
    draft.book_.reset();
    if (changed_) {
        changed_(draft.scope_, {{}, {}, draft.version_});
    }
    return true;
}

std::expected<bool, Almanac::Error> Library::apply(const Scope& scope, std::uint64_t version, std::string key, std::optional<Almanac::Buffer> value) {

    ASTRA_PROFILE_SCOPE("star.library.Library.apply");

    if (!scope.valid() || !Scope::text(key, 1024)) {
        return std::unexpected(Almanac::Error::Input);
    }
    ASTRA_PROFILE_BEGIN(profileLock132, "star.library.Library.apply.wait.writer");
    const std::lock_guard writer(writer_); // One publication stream accounts for all groups without holding routing lock.
    ASTRA_PROFILE_END(profileLock132);
    const auto book = locate(scope);
    if (!book) {
        return std::unexpected(Almanac::Error::Unready);
    }
    const auto before = book->usage();
    if (before.version && version != 0 && version <= *before.version) {
        return false;
    }
    const auto old = book->find(key);
    if (!old) {
        return std::unexpected(old.error());
    }
    // Charge complete old/new values; missing-key Delete creates no entry.
    const auto removed = old->value ? key.size() + old->value->size() : 0;
    const auto added = value ? key.size() + value->size() : 0;
    if (added > limits_.bytes - (bytes_ - removed)) {
        return std::unexpected(Almanac::Error::Capacity);
    }
    // History retention cannot reject authoritative data. When full, old cursors recover through snapshots.
    const auto retention = limits_.history - (history_ - before.history);
    Almanac::Change committed; // Use shared bodies from the actual commit boundary, not a later mutable point lookup.
    const auto result = book->apply(version, std::move(key), std::move(value), retention, &committed);
    if (result && *result) {
        const auto after = book->usage();
        bytes_ = bytes_ - before.bytes + after.bytes;
        history_ = history_ - before.history + after.history;
        if (changed_) {
            changed_(scope, committed);
        }
    }
    return result;
}

std::expected<bool, Almanac::Error> Library::apply(const Scope& scope, std::uint64_t version, std::vector<Almanac::Change> changes) {

    if (!scope.valid() || scope.sector.starts_with("__") || changes.empty()) {
        return std::unexpected(Almanac::Error::Input);
    }
    const std::lock_guard writer(writer_); // Serialize global accounting/notifications without holding routing lock during preparation.
    const auto book = locate(scope);
    if (!book) {
        return std::unexpected(Almanac::Error::Unready);
    }
    const auto before = book->usage();
    if (before.version && version != 0 && version <= *before.version) {
        return false; // Already installed old versions neither recharge nor notify.
    }
    auto bytes = bytes_; // Subtract each unique target's old value once to prevent duplicate-key accounting underflow.
    std::set<std::string_view> seen;
    for (const auto& change : changes) {
        if (!change.key || !Scope::text(*change.key, 1024) || (change.value && change.value->size() > 1024 * 1024) || !seen.insert(*change.key).second) {
            return std::unexpected(Almanac::Error::Input);
        }
        const auto old = book->find(*change.key);
        if (!old) {
            return std::unexpected(old.error());
        }
        if (old->value) {
            bytes -= change.key->size() + old->value->size();
        }
    }
    // Subtract all old values before testing new costs, using overflow-safe budget comparisons.
    for (const auto& change : changes) {
        if (change.value) {
            const auto cost = change.key->size() + change.value->size();
            if (cost > limits_.bytes - bytes) {
                return std::unexpected(Almanac::Error::Capacity);
            }
            bytes += cost;
        }
    }
    Almanac::Change committed; // Allocate notification envelopes before commit.
    const auto result = book->apply(version, std::move(changes), limits_.history - (history_ - before.history), &committed);
    if (result && *result) {
        const auto after = book->usage();
        bytes_ = bytes_ - before.bytes + after.bytes;
        history_ = history_ - before.history + after.history;
        if (changed_) {
            changed_(scope, committed);
        }
    }
    return result;
}

std::vector<Library::Position> Library::positions() const {

    ASTRA_PROFILE_SCOPE("star.library.Library.positions");

    // Writer fixes version boundaries; lock fixes both index levels. Neither payload copying nor external calls occur here.
    ASTRA_PROFILE_BEGIN(profileLock169, "star.library.Library.positions.wait.writer");
    const std::lock_guard writer(writer_);
    ASTRA_PROFILE_END(profileLock169);
    ASTRA_PROFILE_BEGIN(profileLock170, "star.library.Library.positions.wait.lock");
    const std::shared_lock lock(mutex_);
    ASTRA_PROFILE_END(profileLock170);
    std::vector<Position> positions;
    positions.reserve(scopes_);
    for (const auto& [sector, spectra] : books_) {
        for (const auto& [spectrum, book] : spectra) {
            if (const auto version = book->usage().version) {
                positions.push_back({Scope{sector, spectrum}, *version});
            }
        }
    }
    return positions;
}
} // namespace astra
