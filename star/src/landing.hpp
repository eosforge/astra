// Stage one source's private full recovery candidate before atomic installation.
#pragma once
#include "parcel.hpp"
#include <astra/profile.hpp>

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace astra {
/// Private full-baseline candidate for one source/domain; publishes no source root, projection, or ACK.
/// After take, caller prepares merge/deadlines and rechecks identity/position before committing with Origin::reset.
template <typename Domain>
requires(std::same_as<Domain, Catalog> || std::same_as<Domain, Ephemeris>)
class Landing {
public:
    /// Receiver-owned remote source; never borrow the local sending source.
    using Source = Origin<typename Domain::Record, std::same_as<Domain, Ephemeris>>;
    using Page = std::conditional_t<std::same_as<Domain, Catalog>, proto::astra::v1::CatalogSnapshot, proto::astra::v1::EphemerisSnapshot>;
    /// Distinct structure/duplicate/capacity/position errors, without parsing diagnostic text for recovery decisions.
    using Error = typename Source::Error;

    /// Source and fixed capacity outlive the task. Bytes includes all received encoded fragments; Draft separately bounds native indexing.
    explicit Landing(Source& source, std::size_t bytes = 64 * 1024 * 1024) : source_(&source), maximum_(bytes) {
        if (bytes == 0) {
            throw std::invalid_argument("Snapshot receive budget must be positive");
        }
    }

    /// State passes a private Draft after verifying identity/position, without exposing the live source to networking.
    explicit Landing(typename Source::Draft&& draft, std::size_t bytes = 64 * 1024 * 1024) : maximum_(bytes), draft_(std::move(draft)), position_(draft_->position()) {
        if (bytes == 0) {
            throw std::invalid_argument("Snapshot receive budget must be positive");
        }
    }

    /// Minimum is the maximum contiguous/valid targeted-repair coverage position; recheck per page and at final installation.
    /// Every error/exception discards the partial baseline, preserving installed source and public Views.
    std::expected<void, Error> append(const Page& page, std::uint64_t minimum) {

        ASTRA_PROFILE_SCOPE("star.landing.append");

        try {
            const auto bytes = page.ByteSizeLong(); // Independent per-page and whole-candidate budgets, without relying on HTTP/2 windows.
            if (complete_ || page.position() < minimum || (draft_ && page.position() != position_)) {
                return reject(Error::Version);
            }
            if (page.entries_size() > 256 || bytes > 8 * 1024 * 1024 || bytes > maximum_ - received_) {
                return reject(Error::Capacity);
            }
            if ((!page.complete() && page.entries().empty()) || (page.position() == 0 && !page.entries().empty())) {
                return reject(Error::Input);
            }
            if (!draft_) {
                if (!source_) {
                    return reject(Error::Input); // After discarding a transferred Draft, State must revalidate before creating another candidate.
                }
                draft_.emplace(source_->prepare(page.position())); // Reads fixed limits without modifying the live remote source.
                position_ = page.position();
            }
            for (const auto& entry : page.entries()) {
                const auto scope = Parcel::scope(entry.scope());
                const auto& key = [&]() -> const std::string& { if constexpr (std::same_as<Domain, Catalog>){ return entry.key();
} else{ return entry.uuid();
} }();
                const bool valid = [&] { if constexpr (std::same_as<Domain, Catalog>){ return Scope::text(key, 1024);
} else{ return Ephemeris::valid(key);
} }();
                if (!scope || !valid || !entry.has_record()) {
                    return reject(Error::Input);
                }
                auto record = Parcel::record(entry.record()); // Copy each large body once into a truly immutable native owner.
                if (!record) {
                    return reject(Error::Input);
                }
                const auto added = draft_->set(*scope, key, std::move(*record));
                if (!added) {
                    return reject(added.error());
                }
            }
            received_ += bytes;
            complete_ = page.complete();
            return {};
        } catch (...) {
            clear(); // Even bad_alloc discards a partially inserted page, preventing later continuation of an incomplete candidate.
            throw;
        }
    }

    /// Complete means baseline body received, not installed or ACKable.
    bool complete() const noexcept {
        return complete_;
    }

    /// Candidate's claimed position, initially zero; never report as receiver contiguous position.
    std::uint64_t position() const noexcept {
        return position_;
    }

    /// Transfers only after complete; failed outer commit lets Draft reclaim privately without partially public state.
    std::expected<typename Source::Draft, Error> take(std::uint64_t minimum) {

        ASTRA_PROFILE_SCOPE("star.landing.take");

        if (!complete_ || !draft_ || position_ < minimum) {
            const auto error = position_ < minimum ? Error::Version : Error::Input;
            clear();
            return std::unexpected(error);
        }
        auto candidate = std::move(*draft_);
        clear();
        return candidate;
    }

    /// Disconnection/replacement/cancellation releases only this candidate, without renumbering or deleting installed remote facts.
    void clear() noexcept {
        draft_.reset();
        position_ = 0;
        received_ = 0;
        complete_ = false;
    }

private:
    /// Clear before returning failure so repeated error branches cannot retain candidates.
    std::expected<void, Error> reject(Error error) {
        clear();
        return std::unexpected(error);
    }

    /// Controlled recovery task retains lifetime, without borrowing SessionPacket.
    Source* source_{};
    /// Positive encoded-byte limit for the entire group under construction.
    const std::size_t maximum_;
    /// Unpublished native candidate, possibly containing multiple Scopes/watermarks.
    std::optional<typename Source::Draft> draft_;
    /// Position shared by every fragment, initially zero.
    std::uint64_t position_{};
    /// Encoded cost of complete received pages; reset on failure.
    std::size_t received_{};
    /// True only after successful processing of the complete page.
    bool complete_{};
};
} // namespace astra
