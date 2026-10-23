// Share prepared downstream pages across watchers while retaining bounded delivery state.
#pragma once
#include <astra/profile.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace astra {
/// Frozen pages for one Scope/target/cursor range. Constructed and advanced only by the existing control thread, without extra locks or workers.
template <typename Edition>
class Broadcast {
public:
    /// gRPC borrows the immutable message object; streams need not share serialized bytes.
    /// Private cursor after constructing this page; copies share only immutable batches.
    struct Page {
        /// Immutable through every corresponding OnWriteDone.
        typename Edition::Reply message;
        /// Each stream adopts this position independently of other streams' network completion.
        Edition after;
        /// Complete Protobuf wire size, computed once but conservatively charged to every stream.
        std::size_t bytes{};
    };

    /// Absent since selects reset; present since fixes the contiguous apply start. Empty target selects the entire Scope.
    Broadcast(Edition edition, std::optional<std::uint64_t> since, std::string target) : seed_(std::move(edition)), since_(since), target_(std::move(target)) {}

    /// Matches only the same batch; never combines data-only/deletion events from different cursors.
    bool matches(std::optional<std::uint64_t> since, std::uint64_t version, std::string_view target) const noexcept {
        return since_ == since && seed_.version() == version && target_ == target;
    }

    /// A cached batch may prefix a newer suffix, but must advance the cursor to avoid empty-apply busy loops.
    bool prefix(std::uint64_t since, std::uint64_t latest, std::string_view target) const noexcept {
        return since_ == since && target_ == target && since < seed_.version() && seed_.version() <= latest;
    }

    /// Frozen end cursor, independent of each stream's last network acknowledgement.
    std::uint64_t version() const noexcept {
        return seed_.version();
    }

    /// Independent page cursor sharing the root/suffix containers without copying content or the complete event vector.
    Edition begin() const {
        return seed_;
    }

    /// Read only on the control thread advancing next; non-atomic cache statistics add no hot-path synchronization.
    std::uint64_t hits() const noexcept {
        return hits_;
    }

    /// Includes first construction and reconstruction after weak expiry.
    std::uint64_t misses() const noexcept {
        return misses_;
    }

    /// Successful reconstruction after release, excluding first construction and failures; same thread restriction as hits.
    std::uint64_t rebuilds() const noexcept {
        return rebuilds_;
    }

    /// Separate weak cache per page; interleaved slow/fast subscribers do not replace each other's pages. Bodies release when unused.
    std::shared_ptr<const Page> next(Edition& cursor, std::size_t offset, std::string_view instance) {

        ASTRA_PROFILE_SCOPE("star.broadcast.next");

        if (cursor.complete()) {
            throw std::logic_error("Publication cursor already completed");
        }
        if (offset > pages_.size()) {
            throw std::logic_error("Publication page skipped"); // Cursors advance sequentially, preventing invalid page numbers from causing sparse allocations.
        }
        if (offset == pages_.size()) {
            pages_.emplace_back(); // Allocate the weak slot before consuming the cursor; at most one slot per actually requested page.
        }
        if (auto cached = pages_[offset].lock()) {
            ASTRA_PROFILE_COUNT("star.broadcast.hit", 1);
            ++hits_; // A hit adopts the encoded position without repeating domain pagination.
            cursor = cached->after;
            return cached;
        }

        // Ownership distinguishes a never-populated weak slot from a released page, without extra per-page flags or allocations.
        const std::weak_ptr<const Page> empty;
        const bool rebuilding = pages_[offset].owner_before(empty) || empty.owner_before(pages_[offset]); // Expired weak references retain their former control-block identity.
        auto message = cursor.next(instance);                                                             // Failure ends only this stream, preserving other cursors and published messages.
        const auto bytes = message.ByteSizeLong();
        auto page = std::make_shared<const Page>(std::move(message), cursor, bytes);
        pages_[offset] = page;
        ++misses_;
        ASTRA_PROFILE_COUNT("star.broadcast.miss", 1);
        ASTRA_PROFILE_COUNT("star.broadcast.encoded_bytes", bytes);
        if (rebuilding) {
            ++rebuilds_;
            ASTRA_PROFILE_COUNT("star.broadcast.rebuild", 1);
            ASTRA_PROFILE_COUNT("star.broadcast.rebuilt_bytes", bytes); // Reconstructed wire bytes, not added heap memory or duplicate network traffic.
        }
        return page;
    }

private:
    /// Initial page position; all derived cursors share this immutable record source.
    const Edition seed_;
    /// Distinguishes reset from recovery at zero; zero is not a sentinel.
    const std::optional<std::uint64_t> since_;
    /// Fixed target for the batch.
    const std::string target_;
    /// Page-index metadata grows with the frozen batch and releases with it, without strongly retaining completed bodies.
    std::vector<std::weak_ptr<const Page>> pages_;
    /// Count encoded pages reused without repeating domain pagination.
    std::uint64_t hits_{};
    /// Count requests for which no matching encoded page can be reused.
    std::uint64_t misses_{};
    /// Count successful page reconstruction after weak-cache expiry, excluding first construction and failures.
    std::uint64_t rebuilds_{};
};
} // namespace astra
