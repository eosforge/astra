// Deliver public Almanac reads from consistent authoritative views.
#include "readout.hpp"

#include "watch_kernel.hpp"
#include <astra/profile.hpp>

#include <algorithm>
#include <atomic>
#include <stdexcept>
#include <utility>

namespace astra {
/// Complete an immediately rejected watch RPC without retaining business state.
class Readout::Rejected final : public grpc::ServerWriteReactor<proto::comet::v1::AlmanacWatchReply> {
public:
    /// Entry point already prepared the error; retains no authorization or business state.
    explicit Rejected(grpc::Status status) {
        Finish(std::move(status));
    }

    /// The final gRPC callback is this object's only deletion point.
    void OnDone() override {
        delete this;
    }
};

/// Keep one Almanac watch and its cancellation borrows alive through final gRPC completion.
class Readout::Stream final : public grpc::ServerWriteReactor<proto::comet::v1::AlmanacWatchReply>, public std::enable_shared_from_this<Stream> {
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
    Stream(Readout& owner, grpc::CallbackServerContext& context, const proto::comet::v1::WatchRequest& request, std::stop_token token) : owner(owner), context(context), scope{request.scope().sector(), request.scope().spectrum()}, target(request.target()), instance(request.instance()), requested(request.has_version() ? std::optional(request.version()) : std::nullopt), cancel(std::make_unique<std::stop_callback<Cancel>>(token, Cancel{&context})) {}

    /// Destruction unregisters the stop callback; the final owner releases only after OnDone.
    ~Stream() override = default;

    /// Write completion publishes results only; the gRPC callback does not encode the next page.
    void OnWriteDone(bool ok) override {

        ASTRA_PROFILE_SCOPE("star.readout.OnWriteDone");
        ASTRA_PROFILE_BEGIN(profileLock42, "star.readout.OnWriteDone.wait.lock");
        const std::lock_guard lock(io);
        ASTRA_PROFILE_END(profileLock42);
        ASTRA_PROFILE_CONSUME(profileWrite, "star.readout.write_to_callback");
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
    Readout& owner;
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
    proto::comet::v1::AlmanacWatchReply page;
    /// Frozen batch owned by the sole control thread; callbacks never change it.
    std::optional<Edition> edition;
    /// Initial baseline captured; later batches are apply only.
    bool started{};
    /// Position whose final complete page actually wrote successfully.
    std::uint64_t cursor{};
    /// Conservative current-edition charge, adjusted under mutex_.
    std::size_t held{};
    /// Final unfrozen operations compacted by key.
    std::map<std::string, Almanac::Change, std::less<>> pending;
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

Readout::Readout(Library& library, Gateway& gateway, std::function<void()> wake) : Readout(library, gateway, std::move(wake), Limits{}) {}

Readout::Readout(Library& library, Gateway& gateway, std::function<void()> wake, Limits limits) : library_(library), gateway_(gateway), wake_(std::move(wake)), limits_(limits) {
    astra::Watch<Stream>::validate(limits_, "Invalid Almanac watch budget");
    if (!wake_) {
        throw std::invalid_argument("Invalid Almanac watch budget");
    }
}

Readout::~Readout() = default;

void Readout::enqueue(Stream& stream) noexcept {
    queue_.enqueue(stream);
}

void Readout::signal(Stream& stream) noexcept {

    bool scheduled{}; // Queued streams consume the latest I/O state; repeated callbacks need no duplicate wakeup.
    {
        const std::lock_guard lock(mutex_);
        scheduled = queue_.enqueue(stream);
    }
    if (scheduled) {
        wake_(); // Notify outside index lock, following dynamic-domain scheduling.
    }
}

grpc::ServerWriteReactor<proto::comet::v1::AlmanacWatchReply>* Readout::Watch(grpc::CallbackServerContext* context, const proto::comet::v1::WatchRequest* request) {

    ASTRA_PROFILE_SCOPE("star.readout.Readout.Watch");

    try {
        // Acquire permission before event-index lock. Revocation follows Access -> Library -> event index; never reverse it.
        auto permit = gateway_.enter(*context);
        if (!permit) {
            return new Rejected(permit.error());
        }
        if (!Scope::text(request->scope().sector(), 128) || !Scope::text(request->scope().spectrum(), 128) || request->scope().sector().starts_with("__") || (!request->target().empty() && !Scope::text(request->target(), 1024)) || (request->has_version() && request->instance().empty()) || (!request->instance().empty() && !Scope::text(request->instance(), 128))) {
            return new Rejected(gateway_.error(*context, grpc::StatusCode::INVALID_ARGUMENT, proto::comet::v1::REASON_INPUT, "Invalid Almanac watch request"));
        }
        const Scope scope{request->scope().sector(), request->scope().spectrum()}; // Check static boundaries before copying bounded request fields.
        const auto token = permit->has_value() ? permit->value().stopped() : std::stop_token{};
        auto stream = std::make_shared<Stream>(*this, *context, *request, token);
        {
            ASTRA_PROFILE_BEGIN(profileLock130, "star.readout.Readout.Watch.wait.lock");
            const std::lock_guard lock(mutex_);
            ASTRA_PROFILE_END(profileLock130);
            if (stopped_ || count_ == limits_.streams) {
                return new Rejected(gateway_.error(*context, grpc::StatusCode::RESOURCE_EXHAUSTED, proto::comet::v1::REASON_BUSY, "Almanac watch capacity unavailable"));
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
        return new Rejected(gateway_.error(*context, grpc::StatusCode::RESOURCE_EXHAUSTED, proto::comet::v1::REASON_BUSY, "Almanac watch preparation failed"));
    }
}

void Readout::changed(const Scope& scope, const Almanac::Change& change) noexcept {

    ASTRA_PROFILE_SCOPE("star.readout.Readout.changed");

    ASTRA_PROFILE_BEGIN(profileLock169, "star.readout.Readout.changed.wait.lock");
    const std::lock_guard lock(mutex_);
    ASTRA_PROFILE_END(profileLock169);
    const auto group = streams_.find(scope);
    if (group == streams_.end()) {
        return;
    }
    // Continuity/reset belong to the Scope. Exact-target filtering still preserves complete coverage evidence.
    progress_.publish(group->second, change.version, !change.key && !change.batch);
    const auto collect = [&](const Almanac::Change& event) {
        const auto visit = [&](Stream& stream) {
            if (stream.overflow) {
                return;
            }
            ++scans_; // Count only visited streams; pump progress covers skipped idle exact streams outside the commit lock.
            // Charge nodes and duplicate index keys; repeated changes retain only one shared final value per key.
            const auto cost = event.bytes() + event.key->size() + 64;
            const auto old = stream.pending.lower_bound(*event.key); // Reuse the same lookup for the existing item or exact insertion position.
            const bool exists = old != stream.pending.end() && old->first == *event.key;
            const auto previous = exists ? old->second.bytes() + old->first.size() + 64 : 0;
            if (previous > stream.bytes || previous > bytes_) {
                stream.overflow = true; // Reject inconsistent accounting instead of zeroing it and continuing with underflowing subtraction.
                enqueue(stream);
                return;
            }
            const auto held = stream.bytes - previous; // Other-key bytes retained after replacement, with subtraction already validated.
            const auto total = bytes_ - previous;      // Global retention subtracts the same old record used by final accounting.
            if (held > limits_.pending || stream.encoded > limits_.pending - held || cost > limits_.pending - held - stream.encoded || total > limits_.bytes || cost > limits_.bytes - total) {
                stream.overflow = true;
            } else {
                try {
                    if (exists) {
                        old->second = event; // Replace only immutable event references, without another lookup or key copy.
                    } else {
                        stream.pending.emplace_hint(old, *event.key, event);
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
        if (event.key) {
            // Collect compacted bodies only; Scope rotation handles reset/unrelated progress without full commit-time scanning.
            for (auto* pointer : group->second.broadcast) {
                visit(*pointer);
            }
            if (const auto bucket = group->second.precise.find(*event.key); bucket != group->second.precise.end()) {
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

Readout::Delivery Readout::delivery() const {

    const std::lock_guard lock(mutex_);
    return {.scans = scans_, .matched = matched_};
}

std::expected<Edition, grpc::Status> Readout::initial(Stream& stream) {

    ASTRA_PROFILE_SCOPE("star.readout.Readout.initial");

    const auto book = library_.find(stream.scope); // Share group ownership without retaining routing lock across network work.
    const auto version = book ? book->usage().version : std::optional<std::uint64_t>{0};
    if (!version || (stream.requested && *version < *stream.requested)) {
        return std::unexpected(gateway_.error(stream.context, grpc::StatusCode::UNAVAILABLE, proto::comet::v1::REASON_VERSION, "Almanac authority version is behind", version));
    }
    if (book && stream.requested && stream.instance == gateway_.instance()) {
        if (auto replay = book->replay(*stream.requested)) {
            return Edition(std::move(*replay), stream.target);
        }
    }
    if (!book) {
        return Edition();
    }
    if (!stream.target.empty()) {
        auto point = book->find(stream.target);
        if (point) {
            return Edition(stream.target, std::move(*point));
        }
    } else if (auto view = book->view()) {
        return Edition(std::move(*view));
    }
    return std::unexpected(gateway_.error(stream.context, grpc::StatusCode::UNAVAILABLE, proto::comet::v1::REASON_BUSY, "Almanac baseline is unavailable"));
}

void Readout::retire(Stream& stream) {
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

void Readout::advance(Stream& stream, std::chrono::steady_clock::time_point now) {

    ASTRA_PROFILE_SCOPE("star.readout.Readout.advance");

    // io excludes OnDone so context stays valid through login permission and gRPC submission.
    ASTRA_PROFILE_BEGIN(profileLock273, "star.readout.Readout.advance.wait.io");
    const std::lock_guard io(stream.io);
    ASTRA_PROFILE_END(profileLock273);
    if (stream.done) {
        ASTRA_PROFILE_BEGIN(profileLock275, "star.readout.Readout.advance.wait.lock");
        const std::lock_guard lock(mutex_);
        ASTRA_PROFILE_END(profileLock275);
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
            ASTRA_PROFILE_BEGIN(profileLock288, "star.readout.Readout.advance.wait.lock");
            const std::lock_guard lock(mutex_);
            ASTRA_PROFILE_END(profileLock288);
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
        ASTRA_PROFILE_BEGIN(profileLock304, "star.readout.Readout.advance.wait.lock");
        std::unique_lock lock(mutex_); // Protect only stop/budget state, never error encoding or gRPC calls.
        ASTRA_PROFILE_END(profileLock304);
        if (stream.failed || stopped_ || stream.overflow) {
            const bool overflow = stream.overflow; // Freeze the rejection reason before unlock; later notifications may still change overflow.
            lock.unlock();
            stream.finished = true;
            stream.Finish(gateway_.error(stream.context, overflow ? grpc::StatusCode::RESOURCE_EXHAUSTED : grpc::StatusCode::CANCELLED, overflow ? proto::comet::v1::REASON_BUSY : proto::comet::v1::REASON_SESSION, "Almanac watch cannot continue"));
            return;
        }
    }

    try {
        if (stream.written) {
            stream.written = false;
            if (stream.edition->complete()) {
                stream.cursor = stream.edition->version(); // Advance this stream only after the complete page actually writes successfully.
                {
                    ASTRA_PROFILE_BEGIN(profileLock320, "star.readout.Readout.advance.wait.lock");
                    const std::lock_guard lock(mutex_);
                    ASTRA_PROFILE_END(profileLock320);
                    bytes_ -= stream.held;
                    stream.held = 0;
                }
                stream.edition.reset();
            }
            proto::comet::v1::AlmanacWatchReply{}.Swap(&stream.page); // Release actual page allocations; Clear must not retain large capacity while accounting reports zero.
            {
                ASTRA_PROFILE_BEGIN(profileLock328, "star.readout.Readout.advance.wait.lock");
                const std::lock_guard lock(mutex_);
                ASTRA_PROFILE_END(profileLock328);
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
            stream.edition.emplace(std::move(*edition));
            stream.started = true;
            ASTRA_PROFILE_BEGIN(profileLock343, "star.readout.Readout.advance.wait.lock");
            const std::lock_guard lock(mutex_);
            ASTRA_PROFILE_END(profileLock343);
            // Do not resend notifications covered by the captured baseline. A higher full replacement cannot impersonate contiguous apply.
            const auto baseline = stream.edition->version();
            for (auto entry = stream.pending.begin(); entry != stream.pending.end();) {
                if (entry->second.version <= baseline) {
                    const auto cost = entry->second.bytes() + entry->first.size() + 64;
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

        // Transfer suffix/end cursor under index lock; large-vector preparation and old-node destruction stay outside to avoid blocking commit collection.
        std::map<std::string, Almanac::Change, std::less<>> pending; // Transferred suffix remains charged through held and is destroyed outside mutex_.
        std::optional<std::uint64_t> preparing;                      // Present when a fixed apply must be built this round; zero is a valid version.
        {
            ASTRA_PROFILE_BEGIN(profileLock369, "star.readout.Readout.advance.wait.lock");
            std::unique_lock lock(mutex_); // Failure releases the Scope index before finishing the RPC.
            ASTRA_PROFILE_END(profileLock369);
            const auto& group = streams_.find(stream.scope)->second; // Capture progress and suffix at one commit boundary under index lock.
            const auto baseline = stream.edition ? stream.edition->version() : stream.cursor;
            if (stream.overflow || !group.covers(baseline)) {
                const bool overflow = stream.overflow; // Capture overload under the index lock before encoding the final RPC status.
                lock.unlock();
                stream.finished = true;
                stream.Finish(gateway_.error(stream.context, overflow ? grpc::StatusCode::RESOURCE_EXHAUSTED : grpc::StatusCode::OUT_OF_RANGE, overflow ? proto::comet::v1::REASON_BUSY : proto::comet::v1::REASON_HISTORY, overflow ? "Almanac watch exceeded its budget" : "Almanac watch requires a new baseline"));
                return;
            }
            if (!stream.edition) {
                if (group.version <= stream.cursor) {
                    return;
                }
                preparing = group.version;
                pending.swap(stream.pending);
                stream.held = std::exchange(stream.bytes, 0); // New notifications enter a fresh suffix while old preparation remains charged.
            }
        }
        if (preparing) {
            Almanac::Replay replay{*preparing, {}}; // No finite-history lookup; exact-target misses still emit complete empty apply.
            replay.changes.reserve(pending.size());
            for (auto& [key, change] : pending) {
                if (change.version > stream.cursor) {
                    replay.changes.push_back(std::move(change));
                }
            }
            stream.edition.emplace(std::move(replay), stream.target);
            pending.clear(); // Release old index nodes outside event lock.
            ASTRA_PROFILE_BEGIN(profileLock397, "star.readout.Readout.advance.wait.lock");
            const std::lock_guard lock(mutex_);
            ASTRA_PROFILE_END(profileLock397);
            bytes_ -= stream.held;
            stream.held = 0;
            const auto held = stream.edition->bytes(); // Use validated subtraction for remaining allowance, never overflowed sums.
            if (held > limits_.bytes || bytes_ > limits_.bytes - held) {
                stream.overflow = true;
            } else {
                stream.held = held;
                bytes_ += held;
            }
        }
        // Encode one bounded page outside global lock. Permit never spans network waiting.
        stream.page = stream.edition->next(gateway_.instance());
        const auto encoded = stream.page.ByteSizeLong(); // Compute full size once and charge both in-flight and global retention budgets.
        auto sending = gateway_.enter(stream.context);   // Permission covers final checks and nonblocking StartWrite only, excluding encoding and network waits.
        if (!sending) {
            proto::comet::v1::AlmanacWatchReply{}.Swap(&stream.page);
            stream.finished = true;
            stream.Finish(sending.error());
            return;
        }
        ASTRA_PROFILE_BEGIN(profileLock418, "star.readout.Readout.advance.wait.lock");
        std::unique_lock lock(mutex_); // Accept and charge under one lock, then submit to gRPC outside it.
        ASTRA_PROFILE_END(profileLock418);
        const auto overTotal = astra::Watch<Stream>::exceeds(bytes_, encoded, limits_.bytes); // Reject already exceeded global budgets before subtracting, preventing unsigned wraparound.
        const auto overStream = astra::Watch<Stream>::exceeds(stream.bytes, encoded, limits_.pending);
        if (stream.overflow || stopped_ || !streams_.find(stream.scope)->second.covers(stream.edition->version()) || overTotal || overStream) {
            lock.unlock();
            proto::comet::v1::AlmanacWatchReply{}.Swap(&stream.page); // An unaccepted page retains no uncharged large encoding buffer.
            stream.finished = true;
            stream.Finish(gateway_.error(stream.context, grpc::StatusCode::RESOURCE_EXHAUSTED, proto::comet::v1::REASON_BUSY, "Almanac send budget unavailable"));
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
        ASTRA_PROFILE_COUNT("star.readout.submitted_bytes", stream.encoded);
        ASTRA_PROFILE_BEGIN(submission, "star.readout.submit");
        stream.StartWrite(&stream.page);
        ASTRA_PROFILE_END(submission);
    } catch (...) {
        stream.finished = true;
        stream.Finish(gateway_.error(stream.context, grpc::StatusCode::RESOURCE_EXHAUSTED, proto::comet::v1::REASON_BUSY, "Almanac page preparation failed"));
    }
}

void Readout::pump(std::chrono::steady_clock::time_point now, std::size_t maximum) {

    ASTRA_PROFILE_SCOPE("star.readout.Readout.pump");

    // Only the serial control loop accesses the scan deadline; skip index locking before it expires.
    if (now >= sweep_) {
        ASTRA_PROFILE_BEGIN(profileLock448, "star.readout.Readout.pump.wait.lock");
        const std::lock_guard lock(mutex_);
        ASTRA_PROFILE_END(profileLock448);
        queue_.sweep(now, sweep_, wake_);
    }

    // Count bounds both Scope notifications and real task advances. Release index lock each iteration instead of scanning Scopes in one batch.
    for (std::size_t count = 0; count < maximum; ++count) {
        std::shared_ptr<Stream> stream; // Retain popped tasks so OnDone index reclamation cannot destroy stack-borrowed objects.
        {
            ASTRA_PROFILE_BEGIN(profileLock456, "star.readout.Readout.pump.wait.lock");
            const std::lock_guard lock(mutex_);
            ASTRA_PROFILE_END(profileLock456);
            stream = queue_.pop(progress_);
            if (!stream) {
                break;
            }
        }
        advance(*stream, now);
    }
    ASTRA_PROFILE_BEGIN(profileLock464, "star.readout.Readout.pump.wait.lock");
    const std::lock_guard lock(mutex_);
    ASTRA_PROFILE_END(profileLock464);
    if (!queue_.idle() || progress_.pending()) {
        wake_(); // Drain even one unrelated commit without waiting for another update or periodic fallback.
    }
}

void Readout::stop() noexcept {
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

bool Readout::empty() const {
    const std::lock_guard lock(mutex_);
    return count_ == 0;
}
} // namespace astra
