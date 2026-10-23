// Deliver public Almanac reads from consistent authoritative views.
#pragma once
#include "edition.hpp"
#include "gateway.hpp"
#include "library.hpp"
#include "progress.hpp"
#include "watch_kernel.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <string>

namespace astra {
/// Public Almanac feed. gRPC callbacks publish I/O results; the shared loop pumps bounded work without per-subscription threads.
/// Connect Library commits to changed so snapshot transmission retains its own suffix independently of global history retention.
class Readout final : public proto::comet::v1::Almanac::CallbackService {
public:
    /// Deployment resource budgets, not protocol constants or whole-process RSS limits.
    struct Limits {
        /// All admitted, sending, and cancelled streams awaiting OnDone: default 4096, range 1..65536.
        std::size_t streams = 4096;
        /// Conservative logical bytes across frozen batches and compacted suffixes; default 256 MiB.
        std::size_t bytes = 256 * 1024 * 1024;
        /// Per-stream compacted suffix limit, default 8 MiB; never includes a copied whole snapshot.
        std::size_t pending = 8 * 1024 * 1024;
        /// Maximum monotonic wait per page write, positive, default 30 seconds.
        std::chrono::milliseconds timeout{30000};
    };

    /// Library/Gateway outlive all RPCs; wake only signals the shared loop. Construction starts no thread/listener.
    Readout(Library& library, Gateway& gateway, std::function<void()> wake);
    /// Explicit reduced budgets are allowed; invalid configuration throws invalid_argument.
    Readout(Library& library, Gateway& gateway, std::function<void()> wake, Limits limits);
    /// Stop, drain Server, and pump until empty before destruction; never destroy reactors still used by gRPC.
    ~Readout() override;
    /// Validates address/recovery position and orders login permission with event-index registration. Internal __ Scopes are forbidden.
    grpc::ServerWriteReactor<proto::comet::v1::AlmanacWatchReply>* Watch(grpc::CallbackServerContext* context, const proto::comet::v1::WatchRequest* request) override;
    /// Library calls in commit order under writer_. Merge immutable references only; failure closes affected streams without undoing committed writes.
    void changed(const Scope& scope, const Almanac::Change& change) noexcept;
    /// One control thread, at most maximum iterations, default 32. Each transfers at most one Scope-progress item and handles one ready task; scan write timeouts once per second without network waits.
    void pump(std::chrono::steady_clock::time_point now, std::size_t maximum = 32);
    /// Rejects new subscriptions and wakes existing streams for cancellation; continue pumping until every OnDone is reclaimed.
    void stop() noexcept;
    /// No RPCs remain owned by this feed after OnDone reclamation; does not imply the entire Server stopped.
    bool empty() const;

    /// Read-only attribution counters, initially zero and accumulated under mutex_, without changing scheduling/budgets.
    struct Delivery {
        /// Same-Scope streams visited by changed, excluding unrelated exact targets.
        std::uint64_t scans{};
        /// Streams accepting changes into suffixes, excluding reset/filter events.
        std::uint64_t matched{};
    };

    /// Snapshots collection visits/admissions under mutex_, excluding Scope progress and network sends.
    Delivery delivery() const;

private:
    /// Shared active Reactor ownership; callback-state and compacted-suffix locks remain separate.
    class Stream;
    /// Immediate rejection bypasses the active index and self-deletes from OnDone.
    class Rejected;
    /// Allocation-free intrusive ready enqueue under mutex_; at most one position per stream.
    void enqueue(Stream& stream) noexcept;
    /// I/O callback wakes only this stream under mutex_, without Library/Access calls.
    void signal(Stream& stream) noexcept;
    /// Captures the first complete projection under stream I/O lock, outside initial permission/global queue locks. Reacquire final permission before sending.
    std::expected<Edition, grpc::Status> initial(Stream& stream);
    /// Advances one task; context remains valid until OnDone acquires the same I/O lock.
    void advance(Stream& stream, std::chrono::steady_clock::time_point now);
    /// Removes completed indices and returns logical budgets under mutex_, without waiting for streams.
    void retire(Stream& stream);
    /// Fixed native routing; reads only completely installed state.
    Library& library_;
    /// Login guard and shared error mapping, without another SECRET comparison.
    Gateway& gateway_;
    /// Wake must neither block nor reenter pump, and must not capture short-lived RPCs.
    const std::function<void()> wake_;
    /// Accounting rules remain fixed during operation.
    const Limits limits_;
    /// Protects routing, ready queue, accounting, and suffixes. Unlock before StartWrite after accepting a page; final authentication still covers acceptance.
    mutable std::mutex mutex_;

    /// Owns active streams only, with nonowning whole-Scope/exact-target views and Scope watermarks. Pump handles idle progress.
    struct Group : Progress<Stream>::Group {
        /// Nonowning whole-Scope streams visited on every commit.
        std::set<Stream*> broadcast;
        /// Nonowning exact-target stream view.
        std::map<std::string, std::set<Stream*>, std::less<>> precise;
    };

    /// Only Scopes with active streams; remove after the final stream exits.
    std::map<Scope, Group> streams_;
    /// Committed-Scope bounded round-robin queue, without reading RPC I/O state.
    Progress<Stream> progress_;
    /// Separate intrusive ready/in-flight lists; page sending allocates no index node.
    astra::Watch<Stream> queue_;
    /// Active count and globally retained bytes, protected by mutex_.
    std::size_t count_{};
    /// Charge pending, frozen, and encoded Almanac stream bytes against the shared budget.
    std::size_t bytes_{};
    /// Monotonic changed scan/admission counters for exact-target body collection cost.
    std::uint64_t scans_{};
    /// Count admitted Almanac notification targets after filtering and budget checks.
    std::uint64_t matched_{};
    /// Cross-thread stop, set true only under mutex_.
    bool stopped_{};
    /// Control-thread write-timeout scan deadline; idle subscriptions are not polled for versions.
    std::chrono::steady_clock::time_point sweep_{};
};
} // namespace astra
