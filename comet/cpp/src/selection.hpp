// Choose eligible Star endpoints and preserve selection state across connectivity changes.
#pragma once
#include "comet.grpc.pb.h"
#include "table.hpp"
#include <comet/observer.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace comet::detail {
/// Ephemeris records contain complete Attr and Data, without server TTL, source, or operation order.
struct Registration {
    /// Two independent immutable payload objects.
    static constexpr std::size_t overhead = 2 * (sizeof(std::vector<std::uint8_t>) + 32);
    /// Fixed Attr; later data branches share this reference.
    Value attr;
    /// Current Data; valid empty payloads still own an actual vector.
    Value data;

    /// Complete-registration accounting for the private Table.
    std::size_t bytes() const noexcept {
        return attr->size() + data->size();
    }
};

/// One complete publication point, without network handles, callbacks, or Client ownership.
struct Registrations {
    /// Immutable paged dictionary shares unchanged pages across snapshots.
    Table<Registration> data;
    /// Actual Star ID for these complete contents.
    std::string instance;
    /// This Star's merged Ephemeris cursor; zero permits a valid empty baseline.
    std::uint64_t version{};
};

/// Local estimates and authority data are separate; network commit evicts only changed Keys.
struct Estimate {
    /// Charge the estimate buffer header and shared ownership overhead separately from payload bytes.
    static constexpr std::size_t overhead = sizeof(std::vector<std::uint8_t>) + 32;
    /// Immutable authority object also identifies the generation; payload is opaque.
    Value authority;
    /// Complete estimate used for local selection.
    Value data;

    /// Conservatively charges both owners.
    std::size_t bytes() const noexcept {
        return authority->size() + data->size();
    }
};

/// Immutable estimate root retained across independent selector snapshots.
struct Estimates {
    /// COW prevents concurrent adjustments from changing old pools retained by selectors.
    Table<Estimate> data;
};

/// Sequential Ephemeris installation policy; replaces the root only after all complete-batch validation succeeds.
class Selection {
public:
    /// Public reader interface for this projection.
    using API = Observer;
    /// Private concrete downstream message.
    using Reply = proto::comet::v1::EphemerisWatchReply;
    /// Private generated Watch service.
    using Service = proto::comet::v1::Ephemeris;
    /// Accepts only raw 16-byte UUIDv4, without hot-path formatting.
    static bool valid(std::string_view uuid) noexcept;
    /// Missing Attr permits at most one fresh-snapshot fallback; other errors fail immediately.
    bool repair(Error::Code code) noexcept;
    /// Fallback omits the recovery version but retains the old complete view for application reads.
    bool resume() const noexcept;
    /// Factory validates scope and target; bytes and records bound local installation.
    /// reserve adjusts conservative shared Client charges. Shrinking or zeroing must succeed; empty callback supports standalone use.
    using Reserve = std::move_only_function<bool(std::size_t) noexcept>;
    /// Own the fixed binding and optional charge callback; bytes must be 1..1 GiB and records 1..65536, otherwise throw invalid_argument.
    Selection(Scope scope, std::string target, std::size_t bytes, std::size_t records, Reserve reserve = {});
    /// Returns network-controlled charges without affecting application-retained old View lifetimes.
    ~Selection();
    /// New streams drop incomplete candidates but retain the last complete position; expected comes from login and may initially be empty anonymously.
    void begin(std::string expected = {});
    /// Consumes generated messages: empty until complete, then an immutable View. Errors retain the old root and invalidate this stream.
    Result<std::optional<Observer::View>> accept(const proto::comet::v1::EphemerisWatchReply& page);
    /// Wraps the last complete contents without network access or changes to Views already delivered.
    Observer::View view(Observer::State state, std::optional<Error> error = {}) const;
    /// Drops incomplete pages without canceling network or changing old views; also used on allocation failure and disconnection.
    void discard() noexcept;
    /// Pins both roots under Watching's short lock without invoking user code.
    Observer::Pool pool(std::weak_ptr<Observing> owner) const;
    /// Bounded local commit using authority generation and estimate CAS.
    Result<void> estimate(std::string_view id, const Value& authority, const Value& previous, Value data);

private:
    /// Unified failure path invalidates the stream; corrupt pages are not ignorable heartbeats.
    Result<std::optional<Observer::View>> fail(Error::Code code);
    /// Fixed for life; a new range requires a new object.
    const Scope scope_;
    /// Empty selects the whole group; otherwise accepts only the exact Key.
    const std::string target_;
    /// Logical Key and value capacity, separate from gRPC message size.
    const std::size_t bytes_;
    /// Maximum installed records, initialized from Observer::Options.
    const std::size_t records_;
    /// Adjusts shared budget only; invokes no user code and acquires no Reading lock.
    Reserve reserve_;
    /// Current estimate root; replaced only under Watching's lock.
    std::shared_ptr<const Estimates> estimates_ = std::make_shared<Estimates>();
    /// Last complete publication, independent of network lifetime.
    std::shared_ptr<const Registrations> current_;
    /// Private writable pages for the current batch; unreadable externally until complete.
    std::optional<Table<Registration>::Draft> draft_;
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
    /// The sole missing-Attr fallback has been consumed; a successful baseline does not reset it.
    bool repaired_{};
    /// Next stream must obtain a complete reset instead of resuming from the corrupt delta cursor.
    bool fresh_{};
    /// True after begin; protocol or capacity failure requires another begin.
    bool valid_{};
};
} // namespace comet::detail
