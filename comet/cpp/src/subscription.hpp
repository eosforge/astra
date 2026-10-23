// Own shared streaming subscription state and delivery transitions.
#pragma once
#include "comet.grpc.pb.h"
#include "table.hpp"
#include <comet/subscriber.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace comet::detail {
/// Public Catalog record includes content version and complete payload, without TTL or source position.
struct Publication {
    /// Conservative extra cost of the record's vector and shared control block, excluding payload bytes.
    static constexpr std::size_t overhead = sizeof(std::vector<std::uint8_t>) + 32;
    /// Positive business version and immutable payload; retains no remote deadline.
    Subscriber::Record record;

    /// Logical accounting contract for the private Table.
    std::size_t bytes() const noexcept {
        return record.value->size();
    }
};

/// One complete publication point, without network handles, callbacks, or Client ownership.
struct Publications {
    /// Immutable paged dictionary shares unchanged pages across snapshots.
    Table<Publication> data;
    /// Actual Star ID for these complete contents.
    std::string instance;
    /// Local view cursor for this Star; zero is a valid empty baseline.
    std::uint64_t version{};
};

/// Sequential Catalog installation policy; replaces the root only after all complete-batch validation succeeds.
class Subscription {
public:
    /// Public reader interface for this projection.
    using API = Subscriber;
    /// Private concrete downstream message.
    using Reply = proto::comet::v1::CatalogWatchReply;
    /// Private generated Watch service.
    using Service = proto::comet::v1::Catalog;

    /// Recovery carries the last complete view cursor and actual instance; a new Star may send a full reset.
    bool resume() const noexcept {
        return true;
    }

    /// Ordinary protocol errors are not hidden by endless downloads.
    bool repair(Error::Code) noexcept {
        return false;
    }

    /// Factory validates scope and target; bytes and records bound local installation.
    /// reserve adjusts conservative shared Client charges. Shrinking or zeroing must succeed; empty callback supports standalone use.
    using Reserve = std::move_only_function<bool(std::size_t) noexcept>;
    /// Own the fixed binding and optional charge callback; bytes must be 1..1 GiB and records 1..65536, otherwise throw invalid_argument.
    Subscription(Scope scope, std::string target, std::size_t bytes, std::size_t records, Reserve reserve = {});
    /// Returns network-controlled charges without affecting application-retained old View lifetimes.
    ~Subscription();
    /// New streams drop incomplete candidates but retain the last complete position; expected comes from login and may initially be empty anonymously.
    void begin(std::string expected = {});
    /// Consumes generated messages: empty until complete, then an immutable View. Errors retain the old root and invalidate this stream.
    Result<std::optional<Subscriber::View>> accept(const proto::comet::v1::CatalogWatchReply& page);
    /// Wraps the last complete contents without network access or changes to Views already delivered.
    Subscriber::View view(Subscriber::State state, std::optional<Error> error = {}) const;
    /// Drops incomplete pages without canceling network or changing old views; also used on allocation failure and disconnection.
    void discard() noexcept;

private:
    /// Unified failure path invalidates the stream; corrupt pages are not ignorable heartbeats.
    Result<std::optional<Subscriber::View>> fail(Error::Code code);
    /// Fixed for life; a new range requires a new object.
    const Scope scope_;
    /// Empty selects the whole group; otherwise accepts only the exact Key.
    const std::string target_;
    /// Logical Key and value capacity, separate from gRPC message size.
    const std::size_t bytes_;
    /// Maximum installed records, initialized from Subscriber::Options.
    const std::size_t records_;
    /// Adjusts shared budget only; invokes no user code and acquires no Reading lock.
    Reserve reserve_;
    /// Last complete publication, independent of network lifetime.
    std::shared_ptr<const Publications> current_;
    /// Private writable pages for the current batch; unreadable externally until complete.
    std::optional<Table<Publication>::Draft> draft_;
    /// Cross-page deduplication for this batch; completion or failure immediately frees actual buckets and Keys.
    std::unordered_set<std::string> seen_;
    /// Deduplication Key bytes, charged with batch metadata.
    std::size_t seenBytes_{};
    /// Actual Star confirmed by this stream, fixed after the first complete batch.
    std::string expected_;
    /// Current batch mode; unspecified before a batch starts.
    proto::comet::v1::Mode mode_{};
    /// reset is valid only as the first batch of a new stream.
    bool first_ = true;
    /// True after begin; protocol or capacity failure requires another begin.
    bool valid_{};
};
} // namespace comet::detail
