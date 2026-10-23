// Choose eligible Star endpoints and preserve selection state across connectivity changes.
#include "selection.hpp"

#include <astra/profile.hpp>
#include <astra/scope.hpp>

#include <algorithm>

namespace comet {
Observer::State Observer::View::state() const noexcept {
    return state_;
}

const Scope& Observer::View::scope() const noexcept {
    return scope_;
}

const std::string& Observer::View::target() const noexcept {
    return target_;
}

const std::string& Observer::View::instance() const noexcept {
    static const std::string empty; // Stable empty reference for unready views; does not borrow a closed object.
    return contents_ ? contents_->instance : empty;
}

std::optional<std::uint64_t> Observer::View::version() const noexcept {
    return contents_ ? std::optional(contents_->version) : std::nullopt;
}

std::size_t Observer::View::size() const noexcept {
    return contents_ ? contents_->data.size() : 0;
}

const std::optional<Error>& Observer::View::error() const noexcept {
    return error_;
}

std::optional<Observer::Record> Observer::View::find(std::string_view uuid) const {
    const auto* record = contents_ ? contents_->data.find(uuid) : nullptr; // This View retains both immutable payloads.
    return record ? std::optional(Record{record->attr, record->data}) : std::nullopt;
}

void Observer::View::visit(void* context, void (*visitor)(void*, std::string_view, const Record&)) const {
    const auto contents = contents_; // Callbacks may reenter and reassign the original View; this traversal still owns the old root.
    if (contents) {
        contents->data.each([&](std::string_view uuid, const detail::Registration& record) {
            const Record complete{record.attr, record.data}; // Shares ownership without copying Attr or Data bytes.
            visitor(context, uuid, complete);
        });
    }
}

} // namespace comet

namespace comet::detail {
Selection::Selection(Scope scope, std::string target, std::size_t bytes, std::size_t records, Reserve reserve) : scope_(std::move(scope)), target_(std::move(target)), bytes_(bytes), records_(records), reserve_(std::move(reserve)) {
    if (bytes == 0 || bytes > 1024ULL * 1024 * 1024 || records == 0 || records > 65536) {
        throw std::invalid_argument("Invalid Observer view capacity");
    }
}

Selection::~Selection() {
    if (reserve_) {
        static_cast<void>(reserve_(0));
    }
}

/// Selection::discard drops candidate and deduplication state, retaining the confirmed view and cursor.
/// Used on failure and after successful commit to free preparation resources.
void Selection::discard() noexcept {
    draft_.reset();
    std::unordered_set<std::string>{}.swap(seen_); // Do not retain the bucket-array high-water mark of an old large snapshot.
    seenBytes_ = 0;
    mode_ = proto::comet::v1::MODE_UNSPECIFIED;
    if (reserve_) {
        static_cast<void>(reserve_((current_ ? current_->data.footprint() : 0) + estimates_->data.footprint()));
    }
}

/// Selection::begin starts a candidate for the expected instance and clears the old candidate.
/// expected is the required instance; changing instances requires full replacement.
void Selection::begin(std::string expected) {
    discard();
    expected_ = std::move(expected);
    first_ = true;
    valid_ = true;
}

Result<std::optional<Observer::View>> Selection::fail(Error::Code code) {
    discard();
    valid_ = false;
    return std::unexpected(Error{code, Error::Effect::Unapplied, {}, {}, {}});
}

Observer::View Selection::view(Observer::State state, std::optional<Error> error) const {
    Observer::View result; // Copy scalar state with the current complete root; old Views retain their state and version.
    result.contents_ = current_;
    result.state_ = state;
    result.scope_ = scope_;
    result.target_ = target_;
    result.error_ = std::move(error);
    return result;
}

Result<std::optional<Observer::View>> Selection::accept(const proto::comet::v1::EphemerisWatchReply& page) {

    ASTRA_PROFILE_SCOPE("comet.cpp.selection.Selection.accept");

    // Positions appear only on complete final pages; empty nonfinal pages are invalid and cannot create endless nonprogressing streams.
    if (!valid_ || (page.mode() != proto::comet::v1::MODE_RESET && page.mode() != proto::comet::v1::MODE_APPLY) || page.complete() != page.has_version() || page.complete() != !page.instance().empty() || (!page.complete() && page.changes().empty()) || page.ByteSizeLong() > 8 * 1024 * 1024) {
        return fail(Error::Code::Protocol);
    }
    if (page.complete() && (!astra::Scope::text(page.instance(), 128) || (!expected_.empty() && expected_ != page.instance()) || (current_ && current_->instance == page.instance() && page.version() < current_->version))) {
        return fail(Error::Code::Protocol);
    }
    if (!draft_) {
        if ((page.mode() == proto::comet::v1::MODE_RESET && !first_) || (page.mode() == proto::comet::v1::MODE_APPLY && (!current_ || fresh_))) {
            return fail(Error::Code::Protocol);
        }
        mode_ = page.mode();
        if (mode_ == proto::comet::v1::MODE_RESET) {
            draft_.emplace(Table<Registration>{});
        } else {
            draft_.emplace(current_->data);
        } // Construct the candidate directly from the original root, avoiding a conditional-expression Table copy.
    } else if (mode_ != page.mode()) {
        return fail(Error::Code::Protocol);
    }
    if (page.complete() && mode_ == proto::comet::v1::MODE_APPLY && (current_->instance != page.instance() || (page.version() == current_->version && (!first_ || !seen_.empty() || !page.changes().empty())))) {
        return fail(Error::Code::Protocol);
    }

    // Retain the whole batch's changed Keys; final-page eviction uses latest local estimates without overwriting unrelated in-flight local writes.
    const bool track = !page.complete() || page.changes_size() != 1 || !seen_.empty(); // A single-page, single-item batch borrows that item for eviction, preserving the allocation-free deduplication path.
    for (const auto& change : page.changes()) {
        // seen tracks this batch only; limits cover both current and final record sets without accumulating Keys across reconnects.
        if (!valid(change.uuid()) || (!target_.empty() && target_ != change.uuid())) {
            return fail(Error::Code::Protocol);
        }
        if (track) {
            if (seen_.size() == records_ * 2) {
                return fail(seen_.contains(change.uuid()) ? Error::Code::Protocol : Error::Code::Limit); // Report duplicate keys before capacity overflow even when full.
            }
            if (!seen_.insert(change.uuid()).second) {
                return fail(Error::Code::Protocol);
            }
            seenBytes_ += change.uuid().size();
        }
        switch (change.action_case()) {
        case proto::comet::v1::EphemerisChange::kRecord: {
            const auto& record = change.record(); // Complete registration; empty Attr or Data is still a valid complete value.
            if (record.attr().size() > 1024 * 1024 || record.data().size() > 1024 * 1024) {
                return fail(Error::Code::Limit);
            }
            const auto* old = current_ ? current_->data.find(change.uuid()) : nullptr;
            const bool same = old && std::ranges::equal(*old->attr, record.attr(), [](std::uint8_t left, char right) { return left == static_cast<std::uint8_t>(right); }); // Compare full Attr at most once; Data-only updates skip this path.
            if (mode_ == proto::comet::v1::MODE_APPLY && old && !same) {
                return fail(Error::Code::Protocol); // A full-record fallback must never overwrite Attr for a known UUID.
            }
            auto attr = same ? old->attr : std::make_shared<const std::vector<std::uint8_t>>(record.attr().begin(), record.attr().end());
            auto data = std::make_shared<const std::vector<std::uint8_t>>(record.data().begin(), record.data().end());
            draft_->set(change.uuid(), Registration{std::move(attr), std::move(data)});
            break;
        }
        case proto::comet::v1::EphemerisChange::kData: {
            if (mode_ != proto::comet::v1::MODE_APPLY) {
                return fail(Error::Code::Protocol);
            }
            if (change.data().size() > 1024 * 1024) {
                return fail(Error::Code::Limit);
            }
            const auto* old = current_->data.find(change.uuid()); // UUIDs are unique within a batch; the current complete baseline is the sole Attr source.
            if (!old) {
                return fail(Error::Code::History); // Private fallback signal; installs no partial registration and advances no cursor.
            }
            draft_->set(change.uuid(), Registration{old->attr, std::make_shared<const std::vector<std::uint8_t>>(change.data().begin(), change.data().end())});
            break;
        }
        case proto::comet::v1::EphemerisChange::kErase:
            if (mode_ != proto::comet::v1::MODE_APPLY) {
                return fail(Error::Code::Protocol);
            }
            draft_->erase(change.uuid());
            break;
        default:
            return fail(Error::Code::Protocol);
        }
        // Set may precede Delete for another Key; check temporary peak separately from final visible capacity.
        if (draft_->size() > records_ * 2 || draft_->bytes() > bytes_ * 2) {
            return fail(Error::Code::Limit);
        }
    }
    // Preparation charges old contents, candidate, deduplication buckets and Keys; shared pages are charged conservatively by reference lifetime.
    const auto metadata = seenBytes_ + seen_.size() * (sizeof(std::string) + 32) + seen_.bucket_count() * sizeof(void*);
    const auto prepared = draft_->footprint() + metadata;
    if (prepared > bytes_ * 2 || (reserve_ && !reserve_(prepared + (current_ ? current_->data.footprint() : 0) + estimates_->data.footprint()))) {
        return fail(Error::Code::Limit);
    }
    if (!page.complete()) {
        return std::optional<Observer::View>{};
    }
    if (draft_->size() > records_ || draft_->bytes() > bytes_) {
        return fail(Error::Code::Limit);
    }
    if (page.version() == 0 && draft_->size() != 0) {
        return fail(Error::Code::Protocol);
    }

    // Prepare even the View wrapper's bounded fields before advancing the root or recovery cursor, so allocation failure preserves both.
    auto next = std::make_shared<Registrations>();
    next->instance = page.instance();
    next->version = page.version();
    std::string expected = page.instance(); // Swap only after preparation; no fallible string assignment remains after commit.
    auto result = view(Observer::State::Ready);
    next->data = std::move(*draft_).finish();
    if (next->data.footprint() > bytes_) {
        return fail(Error::Code::Limit);
    }
    auto estimates = std::make_shared<Estimates>();
    auto local = mode_ == proto::comet::v1::MODE_RESET ? Table<Estimate>::Draft(Table<Estimate>{}) : Table<Estimate>::Draft(estimates_->data); // Construct Draft directly without first copying the fixed 256-page Table root.
    if (!track) {
        local.erase(page.changes(0).uuid());
    }
    for (const auto& id : seen_) {
        local.erase(id); // Invalidate estimates only for Keys changed by this authority batch; retain latest estimates for other Keys.
    }
    if (next->data.footprint() + local.footprint() > bytes_ || (reserve_ && !reserve_(prepared + (current_ ? current_->data.footprint() : 0) + estimates_->data.footprint() + local.footprint()))) {
        return fail(Error::Code::Limit);
    }
    estimates->data = std::move(local).finish();
    result.contents_ = next;
    estimates_ = std::move(estimates);
    current_ = std::move(next);
    expected_.swap(expected);
    first_ = false;
    fresh_ = false;
    discard();
    return std::optional<Observer::View>(std::move(result));
}
} // namespace comet::detail

namespace comet::detail {
/// Selection::valid checks binary UUID shape without allocating a temporary string.
/// uuid is a raw 16-byte UUIDv4 with fixed version and variant bits.
bool Selection::valid(std::string_view uuid) noexcept {
    if (uuid.size() != 16) {
        return false;
    }
    const auto bytes = reinterpret_cast<const std::uint8_t*>(uuid.data());
    return (bytes[6] & 0xf0U) == 0x40U && (bytes[8] & 0xc0U) == 0x80U;
}

/// Selection::repair allows one object-local recovery for insufficient history, without shared failover.
/// code classifies the failure; returns whether recovery is allowed.
bool Selection::repair(Error::Code code) noexcept {
    if (code != Error::Code::History || repaired_) {
        return false;
    }
    repaired_ = true;
    fresh_ = true;
    return true;
}

/// Selection::resume reports cursor resumability; false for a new instance or after repair.
/// Cursor recovery is allowed without a full replacement.
bool Selection::resume() const noexcept {
    return !fresh_;
}
} // namespace comet::detail

namespace comet::detail {
Observer::Pool Selection::pool(std::weak_ptr<Observing> owner) const {
    Observer::Pool result;
    result.contents_ = current_;
    result.estimates_ = estimates_;
    result.owner_ = std::move(owner);
    return result;
}

Result<void> Selection::estimate(std::string_view id, const Value& authority, const Value& previous, Value data) {

    const auto* row = current_ ? current_->data.find(id) : nullptr;
    if (!row || row->data != authority) {
        return std::unexpected(Error{Error::Code::Obsolete, Error::Effect::Unapplied, {}, {}, {}});
    }
    const auto* old = estimates_->data.find(id);
    if ((old ? old->data : row->data) != previous) {
        return std::unexpected(Error{Error::Code::Conflict, Error::Effect::Unapplied, {}, {}, {}});
    }
    auto next = std::make_shared<Estimates>();
    Table<Estimate>::Draft draft(estimates_->data);
    draft.set(id, Estimate{authority, std::move(data)});
    const auto pending = draft_ ? draft_->footprint() + seenBytes_ + seen_.size() * (sizeof(std::string) + 32) + seen_.bucket_count() * sizeof(void*) : 0; // Received network candidates also consume shared budget.
    const auto original = current_->data.footprint() + estimates_->data.footprint() + pending;
    const auto retained = current_->data.footprint() + draft.footprint();
    if (retained > bytes_ || (reserve_ && !reserve_(original + draft.footprint()))) {
        return std::unexpected(Error{Error::Code::Limit, Error::Effect::Unapplied, {}, {}, {}});
    }
    try {
        next->data = std::move(draft).finish();
    } catch (...) {
        if (reserve_) {
            static_cast<void>(reserve_(original));
        }
        throw;
    }
    estimates_ = std::move(next);
    if (reserve_) {
        static_cast<void>(reserve_(current_->data.footprint() + estimates_->data.footprint() + pending));
    }
    return {};
}
} // namespace comet::detail

namespace comet {
std::size_t Observer::Pool::size() const noexcept {
    return contents_ ? contents_->data.size() : 0;
}

std::optional<Observer::Item> Observer::Pool::find(std::string_view id) const {
    const auto* row = contents_ ? contents_->data.find(id) : nullptr;
    if (!row) {
        return {};
    }
    const auto* local = estimates_ ? estimates_->data.find(id) : nullptr;
    Item item;
    item.id_ = id;
    item.record_ = Record{row->attr, local && local->authority == row->data ? local->data : row->data};
    item.authority_ = row->data;
    item.owner_ = owner_;
    return item;
}

void Observer::Pool::visit(void* context, void (*visitor)(void*, Item)) const {
    const auto pool = *this; // Callbacks may reenter and release the original pool; this round still owns both roots.
    if (pool.contents_) {
        pool.contents_->data.each([&](std::string_view id, const detail::Registration&) { visitor(context, *pool.find(id)); });
    }
}
} // namespace comet
