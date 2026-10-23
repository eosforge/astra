// Pump shared watch lifecycles from I/O completions without one worker thread per stream.
#pragma once
#include "broadcast.hpp"
#include "gateway.hpp"
#include "progress.hpp"
#include "watch_kernel.hpp"
#include <astra/profile.hpp>
#include <astra/scope.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <utility>
#include <vector>

namespace astra {
/// Shared public feed for dynamic domains. gRPC callbacks report I/O results; the existing control loop pumps bounded work without per-subscription threads.
/// Connect State commit notifications to changed so snapshot transmission retains its own suffix independently of global history retention.
template <class Domain>
class Downstream {
    /// Domain-specific commit boundary and business rules.
    using State = typename Domain::State;
    /// Domain-specific paging, without a cross-domain oneof.
    using Edition = typename Domain::Edition;
    /// Generated response type for this RPC.
    using Reply = typename Edition::Reply;
    /// Matching subscription intervals share preparation and in-flight messages, with independent per-stream completion.
    using Batch = Broadcast<Edition>;
    /// Immutable public change.
    using Event = typename State::Projection::Event;

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

    /// State/Gateway outlive every RPC. Wake only signals the shared loop; construction starts no thread or listener.
    Downstream(State& state, Gateway& gateway, std::function<void()> wake);
    /// Explicit reduced budgets are allowed; invalid configuration throws invalid_argument.
    Downstream(State& state, Gateway& gateway, std::function<void()> wake, Limits limits);
    /// Stop, drain Server, and pump until empty before destruction; never destroy reactors still used by gRPC.
    ~Downstream();
    /// Validates address/recovery position and orders login permission with event-index registration. Internal __ Scopes are forbidden.
    grpc::ServerWriteReactor<Reply>* Watch(grpc::CallbackServerContext* context, const proto::comet::v1::WatchRequest* request);
    /// State calls in commit order under the domain lock. Merge immutable references only; failure ends affected streams without rolling back committed writes.
    void changed(const Scope& scope, const Event& change) noexcept;
    /// One control thread, at most maximum iterations, default 32. Each transfers at most one Scope-progress item and handles one ready task; scan write timeouts once per second without network waits.
    void pump(std::chrono::steady_clock::time_point now, std::size_t maximum = 32);
    /// Rejects new subscriptions and wakes existing streams for cancellation; continue pumping until every OnDone is reclaimed.
    void stop() noexcept;
    /// Expiration failure ends current catch-up guarantees. New streams retry capture; partial advancement never becomes a complete snapshot.
    void invalidate() noexcept;
    /// No RPCs remain owned by this feed after OnDone reclamation; does not imply the entire Server stopped.
    bool empty() const;

    /// Read-only dispatch counters for attribution: scans count visited streams, hits count suffix acceptance. Scheduling is unchanged.
    struct Delivery {
        /// Total body-target visits by changed, excluding empty-progress scheduling.
        std::uint64_t scans{};
        /// Successful suffix admissions, excluding budget rejection.
        std::uint64_t matched{};
    };

    /// Snapshots counters under mutex_ without advancing sends or changing budgets.
    Delivery delivery() const;

private:
    /// Shared active Reactor ownership; callback-state and compacted-suffix locks remain separate.
    class Stream;
    /// Immediate rejection bypasses the active index and self-deletes from OnDone.
    class Rejected;

    /// One recent weak cache per Scope, without growth by target/version combinations.
    struct Group : Progress<Stream>::Group {
        /// Nonowning whole-Scope streams visited on every commit.
        std::set<Stream*> broadcast;
        /// Nonowning exact-target stream index, located directly by changed key.
        std::map<std::string, std::set<Stream*>, std::less<>> precise;
        /// Retains no body/snapshot without active consumers.
        std::weak_ptr<Batch> batch;
    };

    /// Reuses batches with matching target/baseline/start. Caller holds no mutex_ and has completed domain preparation.
    std::shared_ptr<Batch> freeze(Stream& stream, Edition edition, std::optional<std::uint64_t> since);
    /// Allocation-free intrusive ready enqueue under mutex_; at most one position per stream.
    void enqueue(Stream& stream) noexcept;
    /// I/O callback wakes only its stream under mutex_, without State/Access calls.
    void signal(Stream& stream) noexcept;
    /// Captures the first complete projection under stream I/O lock, outside initial permission/global queue locks. Reacquire final permission before sending.
    std::expected<Edition, grpc::Status> initial(Stream& stream);
    /// Advances one task; context remains valid until OnDone acquires the same I/O lock.
    void advance(Stream& stream, std::chrono::steady_clock::time_point now);
    /// Removes completed indices and returns logical budgets under mutex_, without waiting for streams.
    void retire(Stream& stream);
    /// Fixed native routing; reads only completely installed state.
    State& state_;
    /// Login guard and shared error mapping, without another SECRET comparison.
    Gateway& gateway_;
    /// Wake must neither block nor reenter pump, and must not capture short-lived RPCs.
    const std::function<void()> wake_;
    /// Accounting rules remain fixed during operation.
    const Limits limits_;
    /// Protects routing, ready queue, accounting, and suffixes. Unlock before StartWrite after accepting a page; final authentication still covers acceptance.
    mutable std::mutex mutex_;
    /// Only Scopes with active streams; remove after the final stream exits.
    std::map<Scope, Group> streams_;
    /// Committed-Scope bounded round-robin queue, without reading RPC I/O state.
    Progress<Stream> progress_;
    /// Separate intrusive ready/in-flight lists; page sending allocates no index node.
    astra::Watch<Stream> queue_;
    /// Active count and globally retained bytes, protected by mutex_.
    std::size_t count_{};
    /// Charge pending, frozen, and encoded stream bytes against the shared watch budget.
    std::size_t bytes_{};
    /// Monotonic changed scan/admission counters measuring exact-target index pruning.
    std::uint64_t scans_{};
    /// Count admitted notification targets after filtering and overflow checks.
    std::uint64_t matched_{};
    /// Cross-thread stop, set true only under mutex_.
    bool stopped_{};
    /// Control-thread write-timeout scan deadline; idle subscriptions are not polled for versions.
    std::chrono::steady_clock::time_point sweep_{};
};

template <class Domain>
class Downstream<Domain>::Rejected final : public grpc::ServerWriteReactor<typename Downstream<Domain>::Reply> {
public:
    /// Entry point already prepared the error; retains no authorization or business state.
    explicit Rejected(grpc::Status status) {
        this->Finish(std::move(status));
    }

    /// The final gRPC callback is this object's only deletion point.
    void OnDone() override {
        delete this;
    }
};

template <class Domain>
class Downstream<Domain>::Stream final : public grpc::ServerWriteReactor<typename Downstream<Domain>::Reply>, public std::enable_shared_from_this<Stream> {
public:
    /// Stop callback borrows the RPC context only during its valid lifetime; calls neither Access nor business code.
    struct Cancel {
        /// gRPC retains context until stop_callback destruction unregisters this borrower.
        grpc::CallbackServerContext* context;

        /// Requests gRPC cancellation only; never releases Stream on the stop-source caller's thread.
        void operator()() const noexcept {
            context->TryCancel();
        }
    };

    /// Copies small request fields in the handler, retaining no request memory beyond OnDone.
    Stream(Downstream<Domain>& owner, grpc::CallbackServerContext& context, const proto::comet::v1::WatchRequest& request, std::stop_token token) : owner(owner), context(context), scope{request.scope().sector(), request.scope().spectrum()}, target(request.target()), instance(request.instance()), requested(request.has_version() ? std::optional(request.version()) : std::nullopt), cancel(std::make_unique<std::stop_callback<Cancel>>(token, Cancel{&context})) {}

    /// Destruction unregisters the stop callback; the final owner releases only after OnDone.
    ~Stream() override = default;

    /// Write completion publishes results only; the gRPC callback does not encode the next page.
    void OnWriteDone(bool ok) override {

        ASTRA_PROFILE_SCOPE("star.downstream.OnWriteDone");
        ASTRA_PROFILE_BEGIN(profileLock153, "star.downstream.OnWriteDone.wait.lock");
        const std::lock_guard lock(io);
        ASTRA_PROFILE_END(profileLock153);
        ASTRA_PROFILE_CONSUME(profileWrite, "star.downstream.write_to_callback");
        writing = false;
        written = ok;
        failed = failed || !ok;
        busy.store(false, std::memory_order_release);
        owner.signal(*this);
    }

    /// Cancellation may race write completion; the control thread orders Finish.
    void OnCancel() override {
        const std::lock_guard lock(io);
        failed = true;
        owner.signal(*this);
    }

    /// No self-delete. After acquiring io, the control thread only reclaims and cannot access context.
    void OnDone() override {
        const std::lock_guard lock(io);
        cancel.reset(); // Context may disappear immediately on return; unregister borrowing here, not during later control-thread reclamation.
        done = true;
        owner.signal(*this);
    }

    /// Outlives OnDone and control-thread reclamation.
    Downstream<Domain>& owner;
    /// Access only under io while done=false.
    grpc::CallbackServerContext& context;
    /// Fixed external address, with __ already rejected.
    const Scope scope;
    /// Empty selects the whole Scope; otherwise an exact key.
    const std::string target;
    /// Requested recovery Star ID, not an authentication credential.
    const std::string instance;
    /// Absent differs from explicit zero.
    const std::optional<std::uint64_t> requested;
    /// Context-lifetime boundary between I/O callbacks and pump.
    std::mutex io;
    /// Under io, guards submission through completion; absent when instrumentation is disabled.
    ASTRA_PROFILE_STAMP(profileWrite);
    /// At most one StartWrite; cleared only by completion callback.
    bool writing{};
    /// Successful write result not yet consumed by pump.
    bool written{};
    /// One-way gRPC cancellation/failure flag.
    bool failed{};
    /// Finish called; awaiting OnDone.
    bool finished{};
    /// OnDone received; context access is forbidden afterward.
    bool done{};
    /// Selects writing streams for low-frequency timeout scanning.
    std::atomic_bool busy{};
    /// Page's monotonic write deadline. Writers hold io and index locks; readers hold at least one.
    std::chrono::steady_clock::time_point deadline{};
    /// Borrowed by gRPC while writing; never clear or overwrite early.
    std::shared_ptr<const typename Batch::Page> page;
    /// Shared frozen batch, without sharing RPC completion state.
    std::shared_ptr<Batch> batch;
    /// Next page number for this stream, starting at zero per batch.
    std::size_t offset{};
    /// Frozen batch owned by the sole control thread; callbacks never change it.
    std::optional<Edition> edition;
    /// Initial baseline captured; later batches are apply only.
    bool started{};
    /// Position whose final complete page actually wrote successfully.
    std::uint64_t cursor{};
    /// Conservative current-edition charge, adjusted under mutex_.
    std::size_t held{};
    /// Final unfrozen operations compacted by key.
    std::map<std::string, Event, std::less<>> pending;
    /// Pending key/node/payload charge, protected by mutex_.
    std::size_t bytes{};
    /// One-way suffix allocation/budget/continuity failure under mutex_.
    bool overflow{};
    /// At most one ready-list position, protected by mutex_.
    bool queued{};
    /// Intrusive ready successor, without separate allocation.
    Stream* next{};
    /// Separate intrusive in-flight list under the owner's index lock; initially unlinked.
    typename astra::Watch<Stream>::Link flight;
    /// Must unregister context borrowing before OnDone returns.
    std::unique_ptr<std::stop_callback<Cancel>> cancel;
    /// Logical in-flight page bytes, charged under mutex_.
    std::size_t encoded{};
};

template <class Domain>
Downstream<Domain>::Downstream(State& state, Gateway& gateway, std::function<void()> wake) : Downstream(state, gateway, std::move(wake), Limits{}) {}

template <class Domain>
Downstream<Domain>::Downstream(State& state, Gateway& gateway, std::function<void()> wake, Limits limits) : state_(state), gateway_(gateway), wake_(std::move(wake)), limits_(limits) {
    astra::Watch<Stream>::validate(limits_, "Invalid Dynamic watch budget");
    if (!wake_) {
        throw std::invalid_argument("Invalid Dynamic watch budget");
    }
    state_.notify([](void* context, const Scope& scope, const Event& event) noexcept { static_cast<Downstream*>(context)->changed(scope, event); }, this);
}

template <class Domain>
Downstream<Domain>::~Downstream() {
    state_.notify(nullptr, nullptr); // After stop/drain, detach the sole collector so no callback targets a destroyed Feed.
}

template <class Domain>
void Downstream<Domain>::enqueue(Stream& stream) noexcept {
    queue_.enqueue(stream);
}

template <class Domain>
void Downstream<Domain>::signal(Stream& stream) noexcept {

    bool scheduled{}; // Wake newly queued positions; existing notification or pump's remaining-work signal covers already queued streams.
    {
        const std::lock_guard lock(mutex_);
        scheduled = queue_.enqueue(stream);
    }
    if (scheduled) {
        wake_(); // Do not extend Wakeup lock contention into the shared subscription-index lock.
    }
}

template <class Domain>
grpc::ServerWriteReactor<typename Downstream<Domain>::Reply>* Downstream<Domain>::Watch(grpc::CallbackServerContext* context, const proto::comet::v1::WatchRequest* request) {

    ASTRA_PROFILE_SCOPE("star.downstream.Downstream_Domain.Watch");

    try {
        // Acquire permission before event-index lock. Credential installation follows Access -> State -> event index; never reverse it.
        auto permit = gateway_.enter(*context);
        if (!permit) {
            return new Rejected(permit.error());
        }
        if (!Scope::text(request->scope().sector(), 128) || !Scope::text(request->scope().spectrum(), 128) || (!request->target().empty() && !Edition::target(request->target())) || (request->has_version() && request->instance().empty()) || (!request->instance().empty() && !Scope::text(request->instance(), 128))) {
            return new Rejected(gateway_.error(*context, grpc::StatusCode::INVALID_ARGUMENT, proto::comet::v1::REASON_INPUT, "Invalid Dynamic watch request"));
        }
        if (request->scope().sector().starts_with("__")) {
            return new Rejected(gateway_.error(*context, grpc::StatusCode::PERMISSION_DENIED, proto::comet::v1::REASON_DENIED, "Internal scopes are not public"));
        }
        const Scope scope{request->scope().sector(), request->scope().spectrum()}; // Check length/UTF-8 before copying request fields.
        const auto token = permit->has_value() ? permit->value().stopped() : std::stop_token{};
        auto stream = std::make_shared<Stream>(*this, *context, *request, token);
        {
            ASTRA_PROFILE_BEGIN(profileLock255, "star.downstream.Downstream_Domain.Watch.wait.lock");
            const std::lock_guard lock(mutex_);
            ASTRA_PROFILE_END(profileLock255);
            if (stopped_ || count_ == limits_.streams) {
                return new Rejected(gateway_.error(*context, grpc::StatusCode::RESOURCE_EXHAUSTED, proto::comet::v1::REASON_BUSY, "Dynamic watch capacity unavailable"));
            }
            // Observe commits before capturing the root. Later version pruning removes overlap without losing post-snapshot changes.
            const auto [group, created] = streams_.try_emplace(scope);
            try {
                group->second.streams.emplace(stream.get(), stream);
                if (stream->target.empty()) {
                    group->second.broadcast.insert(stream.get()); // Visit whole-Scope streams on every commit through nonowning pointers.
                } else {
                    group->second.precise[stream->target].insert(stream.get()); // Share one target set instead of copying keys per stream.
                }
            } catch (...) {
                progress_.erase(group->second, stream.get()); // Owner rollback also clears nonowning views, leaving no ghost stream.
                group->second.broadcast.erase(stream.get());
                if (const auto bucket = group->second.precise.find(stream->target); bucket != group->second.precise.end()) {
                    bucket->second.erase(stream.get());
                    if (bucket->second.empty()) {
                        group->second.precise.erase(bucket);
                    }
                }
                if (created || group->second.streams.empty()) {
                    streams_.erase(group);
                }
                throw;
            }
            ++count_;
            enqueue(*stream);
        }
        wake_();
        return stream.get();
    } catch (...) {
        return new Rejected(gateway_.error(*context, grpc::StatusCode::RESOURCE_EXHAUSTED, proto::comet::v1::REASON_BUSY, "Dynamic watch preparation failed"));
    }
}

template <class Domain>
void Downstream<Domain>::changed(const Scope& scope, const Event& change) noexcept {

    ASTRA_PROFILE_SCOPE("star.downstream.Downstream_Domain.changed");

    ASTRA_PROFILE_BEGIN(profileLock295, "star.downstream.Downstream_Domain.changed.wait.lock");
    const std::lock_guard lock(mutex_);
    ASTRA_PROFILE_END(profileLock295);
    const auto group = streams_.find(scope);
    if (group == streams_.end()) {
        return;
    }
    const auto collect = [&](const Event& event) { // Collect one complete batch under one collector lock.
        // Continuity/reset belong to the Scope. Exact-target filtering still preserves complete coverage evidence.
        progress_.publish(group->second, event.version, !event.name);
        const auto visit = [&](Stream& stream) {
            if (stream.overflow) {
                return;
            }
            ++scans_; // Count only visited streams; pump progress covers skipped idle exact streams outside the commit lock.
            // Charge nodes and duplicate index keys; repeated changes retain only one shared final value per key.
            const auto cost = event.bytes + event.name->key.size() + 64;
            const auto old = stream.pending.lower_bound(event.name->key);
            const bool exists = old != stream.pending.end() && old->first == event.name->key;
            const auto previous = exists ? old->second.bytes + old->first.size() + 64 : 0;
            if (previous > stream.bytes || previous > bytes_) {
                stream.overflow = true; // Reject inconsistent accounting instead of zeroing it and continuing with underflowing subtraction.
                enqueue(stream);
                return;
            }
            const auto held = stream.bytes - previous;
            const auto total = bytes_ - previous;
            if (held > limits_.pending || stream.encoded > limits_.pending - held || cost > limits_.pending - held - stream.encoded || total > limits_.bytes || cost > limits_.bytes - total) {
                stream.overflow = true;
            } else {
                try {
                    if (exists) {
                        old->second = Edition::merge(old->second, event); // Preserve full Ephemeris Attr merge evidence without another lookup or key copy.
                    } else {
                        stream.pending.emplace_hint(old, event.name->key, event);
                    }
                    stream.bytes = held + cost;
                    bytes_ = total + cost;
                    ++matched_; // Only admitted suffix targets count as hits, excluding overflow and filtering.
                } catch (...) {
                    stream.overflow = true;
                }
            }
            enqueue(stream);
        };
        if (event.name) {
            // Collect compacted bodies only; Scope rotation handles reset/unrelated progress without full commit-time scanning.
            for (auto* pointer : group->second.broadcast) {
                visit(*pointer);
            }
            if (const auto bucket = group->second.precise.find(event.name->key); bucket != group->second.precise.end()) {
                for (auto* pointer : bucket->second) {
                    visit(*pointer);
                }
            }
        }
    };
    if (change.batch) {
        for (const auto& entry : *change.batch) {
            collect(entry);
        }
    } else {
        collect(change);
    }
    wake_();
}

template <class Domain>
typename Downstream<Domain>::Delivery Downstream<Domain>::delivery() const {

    const std::lock_guard lock(mutex_);
    return {.scans = scans_, .matched = matched_};
}

template <class Domain>
std::expected<typename Downstream<Domain>::Edition, grpc::Status> Downstream<Domain>::initial(Stream& stream) {

    ASTRA_PROFILE_SCOPE("star.downstream.Downstream_Domain.initial");

    // Dynamic cursors recover only within one instance; cross-Star authoritative version floors do not apply to local projections.
    if (stream.requested && stream.instance == gateway_.instance()) {
        auto replay = state_.changes(stream.scope, *stream.requested);
        if (replay) {
            const auto version = replay->empty() ? *stream.requested : replay->back().version; // Unfiltered complete suffix fixes its completion position.
            return Edition(version, std::move(*replay), stream.target);
        }
        if (replay.error() != State::Error::History && replay.error() != State::Error::Input) {
            return std::unexpected(gateway_.error(stream.context, replay.error() == State::Error::Input ? grpc::StatusCode::FAILED_PRECONDITION : grpc::StatusCode::UNAVAILABLE, replay.error() == State::Error::Clock ? proto::comet::v1::REASON_CLOCK : proto::comet::v1::REASON_HISTORY, "Dynamic cursor is unavailable"));
        }
    }
    if (!stream.target.empty()) {
        auto point = state_.find(stream.scope, stream.target);
        if (point) {
            return Edition(stream.target, std::move(*point));
        }
    } else if (auto view = state_.capture(stream.scope)) {
        return Edition(std::move(*view));
    }
    return std::unexpected(gateway_.error(stream.context, grpc::StatusCode::UNAVAILABLE, proto::comet::v1::REASON_BUSY, "Dynamic baseline is unavailable"));
}

template <class Domain>
std::shared_ptr<typename Downstream<Domain>::Batch> Downstream<Domain>::freeze(Stream& stream, Edition edition, std::optional<std::uint64_t> since) {

    ASTRA_PROFILE_SCOPE("star.downstream.Downstream_Domain.freeze");

    ASTRA_PROFILE_BEGIN(profileLock381, "star.downstream.Downstream_Domain.freeze.wait.lock");
    const std::lock_guard lock(mutex_);
    ASTRA_PROFILE_END(profileLock381);
    auto& group = streams_.find(stream.scope)->second; // The stream owns its Scope entry until OnDone reclamation.
    if (auto batch = group.batch.lock(); batch && batch->matches(since, edition.version(), stream.target)) {
        return batch;
    }

    auto batch = std::make_shared<Batch>(std::move(edition), since, stream.target);
    group.batch = batch;
    return batch;
}

template <class Domain>
void Downstream<Domain>::retire(Stream& stream) {
    bytes_ -= stream.bytes + stream.held + stream.encoded;
    queue_.settle(stream);
    const auto group = streams_.find(stream.scope);
    progress_.erase(group->second, &stream);
    group->second.broadcast.erase(&stream); // Clear nonowning views under the same lock as ownership to prevent dangling pointers.
    if (const auto bucket = group->second.precise.find(stream.target); bucket != group->second.precise.end()) {
        bucket->second.erase(&stream);
        if (bucket->second.empty()) {
            group->second.precise.erase(bucket); // Remove empty target sets rather than retaining historical target count.
        }
    }
    if (group->second.streams.empty()) {
        streams_.erase(group);
    }
    --count_;
}

template <class Domain>
void Downstream<Domain>::advance(Stream& stream, std::chrono::steady_clock::time_point now) {

    ASTRA_PROFILE_SCOPE("star.downstream.Downstream_Domain.advance");

    // io excludes OnDone so context stays valid through login permission and gRPC submission.
    ASTRA_PROFILE_BEGIN(profileLock414, "star.downstream.Downstream_Domain.advance.wait.io");
    const std::lock_guard io(stream.io);
    ASTRA_PROFILE_END(profileLock414);
    if (stream.done) {
        ASTRA_PROFILE_BEGIN(profileLock416, "star.downstream.Downstream_Domain.advance.wait.lock");
        const std::lock_guard lock(mutex_);
        ASTRA_PROFILE_END(profileLock416);
        // OnDone may requeue after this task is popped; leave reclamation to the final queue position to preserve links.
        if (!stream.queued) {
            retire(stream);
        }
        return;
    }
    if (stream.finished) {
        return;
    }
    if (stream.writing) {
        bool stopping; // Shutdown requests immediate cancellation without waiting for the normal page timeout.
        {
            ASTRA_PROFILE_BEGIN(profileLock429, "star.downstream.Downstream_Domain.advance.wait.lock");
            const std::lock_guard lock(mutex_);
            ASTRA_PROFILE_END(profileLock429);
            stopping = stopped_ || stream.overflow;
        }
        if (stopping || now >= stream.deadline) {
            stream.context.TryCancel();
        }
        return;
    }
    auto permit = gateway_.enter(stream.context); // Never acquire Access under event-index lock; credential installation uses the opposite order.
    if (!permit) {
        stream.finished = true;
        stream.Finish(permit.error());
        return;
    }
    permit->reset(); // Prepare large pages outside authentication lock; reacquire final permission before sending so revocation still invalidates preparation.
    {
        ASTRA_PROFILE_BEGIN(profileLock445, "star.downstream.Downstream_Domain.advance.wait.lock");
        std::unique_lock lock(mutex_); // Protect only stop/budget state, never error encoding or gRPC calls.
        ASTRA_PROFILE_END(profileLock445);
        if (stream.failed || stopped_ || stream.overflow) {
            const bool overflow = stream.overflow; // Freeze the rejection reason before unlock; later notifications may still change overflow.
            lock.unlock();
            stream.finished = true;
            stream.Finish(gateway_.error(stream.context, overflow ? grpc::StatusCode::RESOURCE_EXHAUSTED : grpc::StatusCode::CANCELLED, overflow ? proto::comet::v1::REASON_BUSY : proto::comet::v1::REASON_SESSION, "Dynamic watch cannot continue"));
            return;
        }
    }

    try {
        if (stream.written) {
            stream.written = false;
            if (stream.edition->complete()) {
                stream.cursor = stream.edition->version(); // Advance this stream only after the complete page actually writes successfully.
                {
                    ASTRA_PROFILE_BEGIN(profileLock461, "star.downstream.Downstream_Domain.advance.wait.lock");
                    const std::lock_guard lock(mutex_);
                    ASTRA_PROFILE_END(profileLock461);
                    bytes_ -= stream.held;
                    stream.held = 0;
                }
                stream.edition.reset();
                stream.batch.reset();
                stream.offset = 0;
            }
            stream.page.reset(); // Release actual page allocations; Clear must not retain large capacity while accounting reports zero.
            {
                ASTRA_PROFILE_BEGIN(profileLock471, "star.downstream.Downstream_Domain.advance.wait.lock");
                const std::lock_guard lock(mutex_);
                ASTRA_PROFILE_END(profileLock471);
                bytes_ -= stream.encoded;
                stream.encoded = 0;
                queue_.settle(stream);
            }
        }
        if (!stream.started) {
            auto edition = initial(stream);
            if (!edition) {
                stream.finished = true;
                stream.Finish(edition.error());
                return;
            }
            const auto since = edition->reset() ? std::nullopt : stream.requested; // Reset cache keys do not use the requested old cursor.
            stream.batch = freeze(stream, std::move(*edition), since);
            stream.edition.emplace(stream.batch->begin());
            stream.started = true;
            ASTRA_PROFILE_BEGIN(profileLock488, "star.downstream.Downstream_Domain.advance.wait.lock");
            const std::lock_guard lock(mutex_);
            ASTRA_PROFILE_END(profileLock488);
            // Do not resend notifications covered by the captured baseline. A higher full replacement cannot impersonate contiguous apply.
            const auto baseline = stream.edition->version();
            for (auto entry = stream.pending.begin(); entry != stream.pending.end();) {
                if (entry->second.version <= baseline) {
                    const auto cost = entry->second.bytes + entry->first.size() + 64;
                    stream.bytes -= cost;
                    bytes_ -= cost;
                    entry = stream.pending.erase(entry);
                } else {
                    ++entry;
                }
            }
            const auto held = stream.edition->bytes(); // Check sums for overflow before charging frozen batches.
            if (held > limits_.bytes || bytes_ > limits_.bytes - held) {
                stream.overflow = true;
            } else {
                stream.held = held;
                bytes_ += stream.held;
            }
        }

        // Transfer suffix ownership once under index lock, then sort/compact outside it to avoid blocking State commit collection.
        std::map<std::string, Event, std::less<>> pending; // Private old suffix, destroyed outside mutex_.
        std::optional<std::uint64_t> preparing;            // Frozen end cursor; new notifications may append to a fresh suffix.
        {
            ASTRA_PROFILE_BEGIN(profileLock514, "star.downstream.Downstream_Domain.advance.wait.lock");
            std::unique_lock lock(mutex_); // Failure releases the Scope index before finishing the RPC.
            ASTRA_PROFILE_END(profileLock514);
            const auto& group = streams_.find(stream.scope)->second; // Capture progress and suffix at one commit boundary under index lock.
            const auto baseline = stream.edition ? stream.edition->version() : stream.cursor;
            if (stream.overflow || !group.covers(baseline)) {
                lock.unlock();
                stream.finished = true;
                stream.Finish(gateway_.error(stream.context, grpc::StatusCode::OUT_OF_RANGE, proto::comet::v1::REASON_HISTORY, "Dynamic watch requires a new baseline"));
                return;
            }
            if (!stream.edition) {
                const auto frontier = group.version; // Scope watermark is every stream's progress target, including synthesized idle-stream progress.
                if (frontier <= stream.cursor) {
                    return;
                }
                preparing = frontier;
                auto cached = group.batch.lock(); // Matching intervals reuse even the event vector through the already located Scope.
                if (cached && cached->prefix(stream.cursor, *preparing, stream.target)) {
                    preparing = cached->version(); // New events preserve the shared prefix and retain newer versions in this stream's suffix.
                    stream.batch = std::move(cached);
                    stream.edition.emplace(stream.batch->begin());
                }
                pending.swap(stream.pending);
                stream.held = std::exchange(stream.bytes, 0); // Private preparation remains charged outside the lock; never temporarily zero it to bypass global budget.
                if (stream.edition) {
                    for (auto entry = pending.begin(); entry != pending.end();) {
                        if (entry->second.version <= *preparing) {
                            ++entry;
                            continue;
                        }
                        const auto cost = entry->second.bytes + entry->first.size() + 64; // Cached confirmation covers only the old prefix, preserving newer compacted facts.
                        stream.pending.insert(pending.extract(entry++));                  // Transfer nodes without another key or container-node allocation.
                        stream.bytes += cost;
                        stream.held -= cost;
                    }
                }
            }
        }
        if (preparing) {
            if (!stream.edition) {
                std::vector<Event> replay; // Construct the contiguous suffix once per uncached fixed interval.
                replay.reserve(pending.size());
                for (auto& [key, change] : pending) {
                    if (change.version > stream.cursor) {
                        replay.push_back(std::move(change));
                    }
                }
                stream.batch = freeze(stream, Edition(*preparing, std::move(replay), stream.target), stream.cursor);
                stream.edition.emplace(stream.batch->begin());
            }
            pending.clear(); // Release keys/nodes outside event-index lock.
            ASTRA_PROFILE_BEGIN(profileLock562, "star.downstream.Downstream_Domain.advance.wait.lock");
            const std::lock_guard lock(mutex_);
            ASTRA_PROFILE_END(profileLock562);
            bytes_ -= stream.held;
            stream.held = 0;
            const auto held = stream.edition->bytes(); // Conservatively charge private suffixes per stream with underflow-safe comparisons.
            if (held > limits_.bytes || bytes_ > limits_.bytes - held) {
                stream.overflow = true;
            } else {
                stream.held = held;
                bytes_ += stream.held; // Charge each stream even when physical storage is shared, bounding slow-subscriber backlog.
            }
        }
        // Encode one bounded page outside global lock. Permit never spans network waiting.
        stream.page = stream.batch->next(*stream.edition, stream.offset++, gateway_.instance());
        const auto encoded = stream.page->bytes;       // Compute full size once and charge both in-flight and global retention budgets.
        auto sending = gateway_.enter(stream.context); // Permission covers final checks and nonblocking StartWrite only, excluding encoding and network waits.
        if (!sending) {
            stream.page.reset();
            stream.finished = true;
            stream.Finish(sending.error());
            return;
        }
        ASTRA_PROFILE_BEGIN(profileLock583, "star.downstream.Downstream_Domain.advance.wait.lock");
        std::unique_lock lock(mutex_); // Accept and charge under one lock, then submit to gRPC outside it.
        ASTRA_PROFILE_END(profileLock583);
        const auto overTotal = astra::Watch<Stream>::exceeds(bytes_, encoded, limits_.bytes); // Reject already exceeded global budgets before subtracting, preventing unsigned wraparound.
        const auto overStream = astra::Watch<Stream>::exceeds(stream.bytes, encoded, limits_.pending);
        if (stream.overflow || stopped_ || !streams_.find(stream.scope)->second.covers(stream.edition->version()) || overTotal || overStream) {
            lock.unlock();
            stream.page.reset(); // An unaccepted page retains no uncharged large encoding buffer.
            stream.finished = true;
            stream.Finish(gateway_.error(stream.context, grpc::StatusCode::RESOURCE_EXHAUSTED, proto::comet::v1::REASON_BUSY, "Dynamic send budget unavailable"));
            return;
        }
        stream.encoded = encoded;
        bytes_ += encoded;
        stream.deadline = now + limits_.timeout;
        stream.writing = true;
        stream.busy.store(true, std::memory_order_release);
        queue_.write(stream);
        // Page is now accepted and charged in flight; io and sending still protect buffer lifetime and authentication.
        // Later stop/gaps treat it as in flight. After unlock, neither reread index fields nor retract the accepted page.
        lock.unlock();
        ASTRA_PROFILE_MARK(stream.profileWrite);
        ASTRA_PROFILE_COUNT("star.downstream.submitted_bytes", stream.page->bytes);
        ASTRA_PROFILE_BEGIN(submission, "star.downstream.submit");
        stream.StartWrite(&stream.page->message);
        ASTRA_PROFILE_END(submission);
    } catch (...) {
        stream.finished = true;
        stream.Finish(gateway_.error(stream.context, grpc::StatusCode::RESOURCE_EXHAUSTED, proto::comet::v1::REASON_BUSY, "Dynamic page preparation failed"));
    }
}

template <class Domain>
void Downstream<Domain>::pump(std::chrono::steady_clock::time_point now, std::size_t maximum) {

    ASTRA_PROFILE_SCOPE("star.downstream.Downstream_Domain.pump");

    // Only the serial control loop accesses the scan deadline; skip index locking before it expires.
    if (now >= sweep_) {
        ASTRA_PROFILE_BEGIN(profileLock614, "star.downstream.Downstream_Domain.pump.wait.lock");
        const std::lock_guard lock(mutex_);
        ASTRA_PROFILE_END(profileLock614);
        queue_.sweep(now, sweep_, wake_);
    }

    // Count bounds both Scope notifications and real task advances. Release index lock each iteration instead of scanning Scopes in one batch.
    for (std::size_t count = 0; count < maximum; ++count) {
        std::shared_ptr<Stream> stream; // Retain popped tasks so OnDone index reclamation cannot destroy stack-borrowed objects.
        {
            ASTRA_PROFILE_BEGIN(profileLock622, "star.downstream.Downstream_Domain.pump.wait.lock");
            const std::lock_guard lock(mutex_);
            ASTRA_PROFILE_END(profileLock622);
            stream = queue_.pop(progress_);
            if (!stream) {
                break;
            }
        }
        advance(*stream, now);
    }
    ASTRA_PROFILE_BEGIN(profileLock630, "star.downstream.Downstream_Domain.pump.wait.lock");
    const std::lock_guard lock(mutex_);
    ASTRA_PROFILE_END(profileLock630);
    if (!queue_.idle() || progress_.pending()) {
        wake_(); // Drain even one unrelated commit without waiting for another update or periodic fallback.
    }
}

template <class Domain>
void Downstream<Domain>::stop() noexcept {
    const std::lock_guard lock(mutex_);
    stopped_ = true;
    for (const auto& [scope, group] : streams_) {
        static_cast<void>(scope);
        for (const auto& [address, stream] : group.streams) {
            static_cast<void>(address);
            enqueue(*stream);
        }
    }
    wake_();
}

template <class Domain>
bool Downstream<Domain>::empty() const {
    const std::lock_guard lock(mutex_);
    return count_ == 0;
}

template <class Domain>
void Downstream<Domain>::invalidate() noexcept {
    const std::lock_guard lock(mutex_); // Never call native state here, avoiding inverse locking with commit callbacks.
    for (const auto& [scope, group] : streams_) {
        static_cast<void>(scope);
        for (const auto& [address, stream] : group.streams) {
            static_cast<void>(address);
            stream->overflow = true;
            enqueue(*stream);
        }
    }
    wake_();
}

} // namespace astra
