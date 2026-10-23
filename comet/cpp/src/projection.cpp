// Assemble incoming pages into consistent SDK state without exposing partial resets or batches.
#include "projection.hpp"

#include <astra/profile.hpp>
#include <astra/scope.hpp>

namespace comet {
Reader::State Reader::View::state() const noexcept {
    return state_;
}

const Scope& Reader::View::scope() const noexcept {
    return scope_;
}

const std::string& Reader::View::target() const noexcept {
    return target_;
}

const std::string& Reader::View::instance() const noexcept {
    static const std::string empty; // Stable empty reference for unready views; does not borrow a closed object.
    return contents_ ? contents_->instance : empty;
}

std::optional<std::uint64_t> Reader::View::version() const noexcept {
    return contents_ ? std::optional(contents_->version) : std::nullopt;
}

/// Reader::View::size returns record count, or zero before readiness.
std::size_t Reader::View::size() const noexcept {
    return contents_ ? contents_->data.size() : 0;
}

const std::optional<Error>& Reader::View::error() const noexcept {
    return error_;
}

Value Reader::View::find(std::string_view key) const {
    const auto* record = contents_ ? contents_->data.find(key) : nullptr; // Borrows immutable pages owned by this view only.
    return record ? record->value : nullptr;
}

/// Reader::View::visit traverses all records by shared ownership without copying bytes.
/// context and visitor provide callback state and invocation.
void Reader::View::visit(void* context, void (*visitor)(void*, std::string_view, const Value&)) const {
    const auto contents = contents_; // Callbacks may reenter and reassign the original View; this traversal still owns the old root.
    if (contents) {
        contents->data.each([&](std::string_view key, const detail::Datum& record) { visitor(context, key, record.value); });
    }
}
} // namespace comet

namespace comet::detail {
Projection::Projection(Scope scope, std::string target, std::size_t bytes, std::size_t records, Reserve reserve) : scope_(std::move(scope)), target_(std::move(target)), bytes_(bytes), records_(records), reserve_(std::move(reserve)) {
    if (bytes == 0 || bytes > 1024ULL * 1024 * 1024 || records == 0 || records > 65536) {
        throw std::invalid_argument("Invalid Reader view capacity");
    }
}

Projection::~Projection() {
    if (reserve_) {
        static_cast<void>(reserve_(0));
    }
}

/// Projection::discard drops candidate and deduplication state, retaining the confirmed view and cursor.
void Projection::discard() noexcept {
    draft_.reset();
    std::unordered_set<std::string>{}.swap(seen_); // Do not retain the bucket-array high-water mark of an old large snapshot.
    seenBytes_ = 0;
    mode_ = proto::comet::v1::MODE_UNSPECIFIED;
    if (reserve_) {
        static_cast<void>(reserve_(current_ ? current_->data.footprint() : 0));
    }
}

/// Projection::begin starts a candidate for expected instance and clears the previous candidate.
/// expected is the required instance.
void Projection::begin(std::string expected) {
    discard();
    expected_ = std::move(expected);
    first_ = true;
    valid_ = true;
}

Result<std::optional<Reader::View>> Projection::fail(Error::Code code) {
    discard();
    valid_ = false;
    return std::unexpected(Error{code, Error::Effect::Unapplied, {}, {}, {}});
}

Reader::View Projection::view(Reader::State state, std::optional<Error> error) const {
    Reader::View result; // Copy scalar state with the current complete root; old Views retain their state and version.
    result.contents_ = current_;
    result.state_ = state;
    result.scope_ = scope_;
    result.target_ = target_;
    result.error_ = std::move(error);
    return result;
}

Result<std::optional<Reader::View>> Projection::accept(const proto::comet::v1::AlmanacWatchReply& page) {

    ASTRA_PROFILE_SCOPE("comet.cpp.projection.Projection.accept");

    // Positions appear only on complete final pages; empty nonfinal pages are invalid and cannot create endless nonprogressing streams.
    if (!valid_ || (page.mode() != proto::comet::v1::MODE_RESET && page.mode() != proto::comet::v1::MODE_APPLY) || page.complete() != page.has_version() || page.complete() != !page.instance().empty() || (!page.complete() && page.changes().empty()) || page.ByteSizeLong() > 8 * 1024 * 1024) {
        return fail(Error::Code::Protocol);
    }
    if (page.complete() && (!astra::Scope::text(page.instance(), 128) || (!expected_.empty() && expected_ != page.instance()))) {
        return fail(Error::Code::Protocol);
    }
    if (page.complete() && current_ && page.version() < current_->version) {
        return fail(Error::Code::Version); // Do not install a regressed view after switching to a lagging Star; retain the authority floor in recovery requests.
    }
    if (!draft_) {
        if ((page.mode() == proto::comet::v1::MODE_RESET && !first_) || (page.mode() == proto::comet::v1::MODE_APPLY && !current_)) {
            return fail(Error::Code::Protocol);
        }
        mode_ = page.mode();
        if (mode_ == proto::comet::v1::MODE_RESET) {
            draft_.emplace(Table<Datum>{});
        } else {
            draft_.emplace(current_->data);
        } // Construct the candidate directly from the original root, avoiding a conditional-expression Table copy.
    } else if (mode_ != page.mode()) {
        return fail(Error::Code::Protocol);
    }
    if (page.complete() && mode_ == proto::comet::v1::MODE_APPLY && (current_->instance != page.instance() || (page.version() == current_->version && (!first_ || !seen_.empty() || !page.changes().empty())))) {
        return fail(Error::Code::Protocol);
    }

    // A complete single-item batch cannot contain duplicates, so small updates need no deduplication nodes or buckets.
    const bool track = !page.complete() || page.changes_size() != 1 || !seen_.empty(); // If earlier pages exist, continue deduplicating across pages.
    for (const auto& change : page.changes()) {
        // seen tracks this batch only; limits cover both current and final record sets without accumulating Keys across reconnects.
        if (!astra::Scope::text(change.key(), 1024) || (!target_.empty() && target_ != change.key())) {
            return fail(Error::Code::Protocol);
        }
        if (track) {
            if (seen_.size() == records_ * 2) {
                return fail(seen_.contains(change.key()) ? Error::Code::Protocol : Error::Code::Limit); // Report duplicate keys before capacity overflow even when full.
            }
            if (!seen_.insert(change.key()).second) {
                return fail(Error::Code::Protocol);
            }
            seenBytes_ += change.key().size();
        }
        switch (change.action_case()) {
        case proto::comet::v1::AlmanacChange::kValue: {
            if (change.value().size() > 1024 * 1024) {
                return fail(Error::Code::Limit);
            }
            const auto& value = change.value(); // Protobuf reuses bytes on the next Read; acquire independent immutable ownership here.
            draft_->set(change.key(), Datum{std::make_shared<const std::vector<std::uint8_t>>(value.begin(), value.end())});
            break;
        }
        case proto::comet::v1::AlmanacChange::kErase:
            if (mode_ != proto::comet::v1::MODE_APPLY) {
                return fail(Error::Code::Protocol);
            }
            draft_->erase(change.key());
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
    if (prepared > bytes_ * 2 || (reserve_ && !reserve_(prepared + (current_ ? current_->data.footprint() : 0)))) {
        return fail(Error::Code::Limit);
    }
    if (!page.complete()) {
        return std::optional<Reader::View>{};
    }
    if (draft_->size() > records_ || draft_->bytes() > bytes_) {
        return fail(Error::Code::Limit);
    }
    if (page.version() == 0 && draft_->size() != 0) {
        return fail(Error::Code::Protocol);
    }

    // Prepare even the View wrapper's bounded fields before advancing the root or recovery cursor, so allocation failure preserves both.
    auto next = std::make_shared<Contents>();
    next->instance = page.instance();
    next->version = page.version();
    std::string expected = page.instance(); // Swap only after preparation; no fallible string assignment remains after commit.
    auto result = view(Reader::State::Ready);
    next->data = std::move(*draft_).finish();
    if (next->data.footprint() > bytes_) {
        return fail(Error::Code::Limit);
    }
    result.contents_ = next;
    current_ = std::move(next);
    expected_.swap(expected);
    first_ = false;
    discard();
    return std::optional<Reader::View>(std::move(result));
}
} // namespace comet::detail
