// Coordinate shared watch activity state and streaming lifecycle transitions.
#pragma once
#include "core.hpp"
#include <astra/profile.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <concepts>
#include <condition_variable>
#include <cstddef>
#include <expected>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace comet::detail {
/// Private state for one application Reader; RPCs may extend cleanup lifetime but not subscription intent.
template <class Policy>
class Watching : public Activity, public std::enable_shared_from_this<Watching<Policy>> {
    /// Corresponding public read handle; its type never enters the wire protocol.
    using API = typename Policy::API;
    /// Read-only view delivered after complete installation.
    using View = typename API::View;
    /// Read domains share lifecycle states.
    using State = typename API::State;
    /// Local capacity and observer for the fixed range.
    using Options = typename API::Options;
    /// Generated replies remain private to the implementation.
    using Reply = typename Policy::Reply;
    /// Generated dedicated Watch service.
    using Service = typename Policy::Service;

public:
    /// Created after Core validates factory parameters and quota; construction sends no RPC and invokes no observer.
    Watching(std::shared_ptr<Core> core, Scope scope, std::string target, Options options);
    /// Native projection returns controlled charges; all RPCs and observers must finish before the last reference is released.
    ~Watching();
    /// Snapshots current state under a short lock, without network waits.
    View load() const;
    /// Replaces the state callback and first delivers current state; empty removes it.
    Result<void> changed(std::move_only_function<void(View)> callback);
    /// Delivers complete contents only; attaching after installation still receives the baseline.
    Result<void> watch(std::move_only_function<void(View)> callback, bool exact);
    /// Returns application ownership on the first close only; in-flight work still awaits OnDone.
    void close() noexcept;
    /// Blocking in SDK observers is forbidden.
    bool wait(std::chrono::milliseconds timeout) const;
    /// Core factory accounting uses atomic flags without acquiring Watching's lock in reverse order.
    bool closed() const noexcept override;
    /// Closed, fully cleaned objects may leave Core's weak directory; users may retain the last View.
    bool finished() const noexcept override;

    /// Pins pool roots only; selector runs on the caller thread outside the lock.
    Result<Observer::Pool> pool() requires std::same_as<Policy, Selection> {
        const std::lock_guard lock(mutex_);
        if (closed() || core_->stopped()) {
            return std::unexpected(Error{Error::Code::Closed, Error::Effect::Unapplied, {}, {}, {}});
        }
        if (view_.state() != State::Ready) {
            return std::unexpected(view_.error().value_or(Error{Error::Code::Busy, Error::Effect::Unapplied, {}, {}, {}}));
        }
        return projection_->pool(this->shared_from_this());
    }

    /// CAS and complete network commit share a short lock, never held across user code.
    Result<void> estimate(std::string_view id, const Value& authority, const Value& previous, Value data) requires std::same_as<Policy, Selection> {
        const std::lock_guard lock(mutex_);
        if (closed() || core_->stopped()) {
            return std::unexpected(Error{Error::Code::Closed, Error::Effect::Unapplied, {}, {}, {}});
        }
        return projection_->estimate(id, authority, previous, std::move(data));
    }

    /// Watch does not consume Beacon keepalive quota.
    bool streaming() const noexcept override {
        return true;
    }

    /// Sole Core control round calls sequentially; binding and error are fixed snapshots outside Core's lock. Returns the next actual schedule time.
    Core::Time poll(Core::Time now, const std::shared_ptr<const Binding>& binding, const std::optional<Error>& error, bool closing) override;

private:
    /// Local close was processed and preparation storage returned; wait also requires actual OnDone.
    bool cleaned_{};
    /// Actual callback RPC with one in-flight read, including cleanup after cancellation.
    class Stream;
    /// Publishes state once without user code; caller unlocks at the notification boundary before invocation.
    bool publish(State state, std::optional<Error> error = {});
    /// New streams freeze range and recovery position; the previous Stream must reach OnDone before another is created.
    void start(const std::shared_ptr<const Binding>& binding);
    /// Adjusts shared charges under Watching's lock; failure preserves previous quota.
    bool reserve(std::size_t requested) noexcept;
    /// Active application business work owns the shared core; View never retains this reference.
    const std::shared_ptr<Core> core_;
    /// Fixed external address; network requests own their strings separately.
    const Scope scope_;
    /// Empty selects the whole group; otherwise one exact Key.
    const std::string target_;
    /// Protects projection, handle state, and notification start; never held across user callbacks or network waits.
    mutable std::mutex mutex_;
    /// Sole wait point for local cleanup.
    mutable std::condition_variable condition_;
    /// reserve runs under this Watching lock; Core accounts through an atomic total.
    std::size_t bytes_{};
    /// close may release controlled network storage; current View becomes application-retained old content.
    std::optional<Policy> projection_;
    /// Last complete installation and latest local state, never an incomplete candidate.
    View view_;
    /// Shared wrapper prevents replacement within a callback from destroying the executing function.
    using Callback = std::move_only_function<void(View)>;
    /// State notification, independent of data-baseline delivery.
    std::shared_ptr<Callback> changed_;
    /// Latest data observer; callbacks are serial per object.
    std::shared_ptr<Callback> watched_;
    /// Complete contents await delivery; state changes do not generate empty data notifications.
    bool updated_{};
    /// Sole actual RPC; cancellation neither clears this reference nor returns physical quota early.
    std::shared_ptr<Stream> stream_;
    /// Actual request target; compared with current Core binding by pointer identity.
    std::shared_ptr<const Binding> binding_;
    /// One-way application stop flag; returns Core ownership once.
    std::atomic_bool closed_{};
    /// Published last by the control round; factory may remove unscheduled objects without this object's lock.
    std::atomic_bool finished_{};
    /// Permanent local or protocol failure retains old views without redownloading the same corrupt contents forever.
    bool failed_{};
    /// User callback has started; close lets it finish and wait includes its completion.
    bool notifying_{};
    /// Complete state awaiting notification; intermediate states may coalesce without a FIFO.
    bool dirty_{};
    /// Bounded recovery backoff; TCP success alone cannot reset repeated stream failures.
    unsigned failures_{};
    /// Next reconnect time, without millisecond polling or per-object Alarm.
    Core::Time retry_{};
};

template <class Policy>
class Watching<Policy>::Stream final : public grpc::ClientReadReactor<typename Policy::Reply> {
public:
    /// owner retains in-flight lifetime; start follows Stream installation in Reading, avoiding this escaping from construction.
    Stream(std::shared_ptr<Watching> owner, std::shared_ptr<const Binding> binding, proto::comet::v1::WatchRequest request) : owner_(std::move(owner)), binding_(std::move(binding)), request_(std::move(request)), stub_(Service::NewStub(binding_->streams)) {
        if (!binding_->session.empty()) {
            context_.AddMetadata("comet-session-bin", binding_->session);
        }
    }

    /// Release the final reply only after network completion, then return its controlled memory charge.
    ~Stream() override {
        Reply{}.Swap(&page_); // Release the final page after actual network completion, then return its controlled charge.
        static_cast<void>(owner_->core_->resize(bytes_, 0));
    }

    /// Members and request have stable ownership; a sole hold protects external control-path reads.
    void start() {

        ASTRA_PROFILE_SCOPE("comet.cpp.watching.start");
        stub_->async()->Watch(&context_, &request_, this);
        this->AddHold();
        held_ = true;
        this->StartRead(&page_);
        deadline_ = std::chrono::steady_clock::now() + owner_->core_->options_.timeout;
        this->StartCall();
    }

    /// Cancellation stops this call only; Reading returns in-flight quota after OnDone.
    void cancel() {
        const std::lock_guard lock(mutex_);
        context_.TryCancel();
        release();
    }

    /// Publish complete Read results to Core only; gRPC threads neither decode/install nor invoke observers.
    void OnReadDone(bool ok) override {

        ASTRA_PROFILE_SCOPE("comet.cpp.watching.OnReadDone");
        ASTRA_PROFILE_BEGIN(profileLock93, "comet.cpp.watching.OnReadDone.wait.lock");
        const std::lock_guard lock(mutex_);
        ASTRA_PROFILE_END(profileLock93);
        ASTRA_PROFILE_MARK(profileReady_);
        stage_ = ok ? Stage::Ready : Stage::Ended;
        if (ok) {
            const auto bytes = page_.SpaceUsedLong(); // Actual owned storage is known after decoding; include it in the global Reader budget.
            if (!owner_->core_->resize(0, bytes)) {
                stage_ = Stage::Overflow;
                Reply{}.Swap(&page_);
            } else {
                bytes_ = bytes;
            }
        }
        owner_->core_->wake(owner_.get());
    }

    /// This Stream owns context; read trailing metadata after OnDone.
    void OnDone(const grpc::Status& status) override {

        ASTRA_PROFILE_SCOPE("comet.cpp.watching.OnDone");
        ASTRA_PROFILE_BEGIN(profileLock109, "comet.cpp.watching.OnDone.wait.lock");
        const std::lock_guard lock(mutex_);
        ASTRA_PROFILE_END(profileLock109);
        code_ = status.error_code(); // Do not copy message or details containing arbitrary remote payload.
        done_ = true;
        owner_->core_->wake(owner_.get());
    }

private:
    friend class Watching;
    /// Single-page receive order uses mutually exclusive phases rather than combinable available, consumed, ended, and overflow flags.
    enum class Stage {
        /// Initial phase: the sole StartRead is active or starts in start; gRPC owns page_ for writing.
        Reading,
        /// Read succeeded and decoding budget was acquired; control round exclusively consumes page_.
        Ready,
        /// Control round moved the page out; another StartRead waits for notification return.
        Consumed,
        /// Read reached EOF; return the control hold and await actual OnDone.
        Ended,
        /// Decoding budget rejected and page freed; control round reports capacity failure and cancels.
        Overflow
    };

    /// Protected by Stream::mutex_; tracks successful-page queuing from callback to control round only.
    ASTRA_PROFILE_STAMP(profileReady_);
    /// Transitions only under mutex_; each OnReadDone ends one reading phase.
    Stage stage_ = Stage::Reading;
    /// No-progress deadline for initial or partial batches; completely ready idle streams have no overall deadline.
    Core::Time deadline_ = Core::Time::max();
    /// Local no-progress cancellation must not be reported as credential revocation.
    bool timed_{};
    /// Stream canceled for the sole missing-Attr fallback; OnDone must not invalidate the shared Session.
    bool repair_{};
    /// Whether this stream installed a complete batch; shared Core backoff updates only on initial recovery.
    bool recovered_{};
    /// Owned storage of the sole received page; returned after page release or actual OnDone.
    std::size_t bytes_{};

    /// With mutex_ held, return the hold exactly once after EOF or cancellation so OnDone can occur.
    void release() {
        if (held_) {
            held_ = false;
            this->RemoveHold();
        }
    }

    /// Retains private state until OnDone cleanup; public Reader close is accounted separately.
    const std::shared_ptr<Watching> owner_;
    /// Fixed actual Star and Session; target changes never redirect an old request.
    const std::shared_ptr<const Binding> binding_;
    /// Sent once, with fixed recovery position and range.
    const proto::comet::v1::WatchRequest request_;
    /// Corresponds to this fixed transport.
    std::unique_ptr<typename Service::Stub> stub_;
    /// Long-lived Watch must not use the three-second unary overall deadline.
    grpc::ClientContext context_;
    /// Buffer ownership boundary between control path and both gRPC callbacks.
    std::mutex mutex_;
    /// At most one unconsumed page; return it before the next StartRead.
    Reply page_;
    /// Sole control-path hold has not been returned.
    bool held_{};
    /// Final gRPC completion permits clearing the parent Stream reference and actual RPC quota.
    bool done_{};
    /// No actual final status exists before OnDone.
    grpc::StatusCode code_ = grpc::StatusCode::UNKNOWN;
};

template <class Policy>
Watching<Policy>::Watching(std::shared_ptr<Core> core, Scope scope, std::string target, Options options) : core_(std::move(core)), scope_(std::move(scope)), target_(std::move(target)), projection_(std::in_place, scope_, target_, options.bytes, options.records, [this](std::size_t requested) noexcept { return reserve(requested); }), changed_(options.changed ? std::make_shared<Callback>(std::move(options.changed)) : nullptr) {
    view_ = projection_->view(State::Waiting);
}

template <class Policy>
Watching<Policy>::~Watching() = default;

template <class Policy>
bool Watching<Policy>::reserve(std::size_t requested) noexcept {
    if (!core_->resize(bytes_, requested)) {
        return false;
    }
    bytes_ = requested;
    return true;
}

template <class Policy>
typename Watching<Policy>::View Watching<Policy>::load() const {

    ASTRA_PROFILE_SCOPE("comet.cpp.watching.Watching_Policy.load");
    ASTRA_PROFILE_BEGIN(profileLock177, "comet.cpp.watching.Watching_Policy.load.wait.lock");
    const std::lock_guard lock(mutex_);
    ASTRA_PROFILE_END(profileLock177);
    auto view = view_; // Owns bounded state fields; large contents share only an immutable root.
    if (closed() || core_->stopped()) {
        view.state_ = State::Closed;
    }
    return view;
}

template <class Policy>
Result<void> Watching<Policy>::changed(std::move_only_function<void(View)> callback) {

    auto next = callback ? std::make_shared<Callback>(std::move(callback)) : nullptr;
    {
        const std::lock_guard lock(mutex_);
        if (closed() || core_->stopped()) {
            return std::unexpected(Error{Error::Code::Closed, Error::Effect::Unapplied, {}, {}, {}});
        }
        changed_.swap(next);
        dirty_ = true;
    }
    core_->wake(this);
    return {};
}

template <class Policy>
Result<void> Watching<Policy>::watch(std::move_only_function<void(View)> callback, bool exact) {

    if (exact != !target_.empty()) {
        return std::unexpected(Error{Error::Code::Input, Error::Effect::Unapplied, {}, {}, {}});
    }
    auto next = callback ? std::make_shared<Callback>(std::move(callback)) : nullptr;
    {
        const std::lock_guard lock(mutex_);
        if (closed() || core_->stopped()) {
            return std::unexpected(Error{Error::Code::Closed, Error::Effect::Unapplied, {}, {}, {}});
        }
        watched_.swap(next);
        updated_ = view_.version().has_value();
    }
    core_->wake(this);
    return {};
}

template <class Policy>
bool Watching<Policy>::closed() const noexcept {
    return closed_.load(std::memory_order_acquire);
}

template <class Policy>
bool Watching<Policy>::finished() const noexcept {
    return finished_.load(std::memory_order_acquire);
}

template <class Policy>
void Watching<Policy>::close() noexcept {
    bool first; // Uses the same short lock as notification start; never enters Core or waits for network while locked.
    {
        const std::lock_guard lock(mutex_);
        first = !closed_.exchange(true, std::memory_order_acq_rel);
    }
    if (first) {
        core_->release(); // Internal RPC shared_ptr references do not extend application subscription intent.
        core_->wake(this);
    }
}

template <class Policy>
bool Watching<Policy>::wait(std::chrono::milliseconds timeout) const {
    if (Core::notifying()) {
        throw std::logic_error("Cannot wait inside a Comet callback");
    }
    std::unique_lock lock(mutex_);
    return condition_.wait_until(lock, Core::deadline(timeout), [this] { return cleaned_ && !stream_ && !notifying_; });
}

template <class Policy>
bool Watching<Policy>::publish(State state, std::optional<Error> error) {

    ASTRA_PROFILE_SCOPE("comet.cpp.watching.Watching_Policy.publish");
    // Identical state and reason need no repeat notification; each complete data batch marks dirty separately.
    const bool changed = view_.state() != state || view_.error().has_value() != error.has_value() || (error && view_.error() && error->code != view_.error()->code);
    view_ = projection_->view(state, std::move(error));
    dirty_ = dirty_ || changed;
    return changed;
}

template <class Policy>
void Watching<Policy>::start(const std::shared_ptr<const Binding>& binding) {

    ASTRA_PROFILE_SCOPE("comet.cpp.watching.Watching_Policy.start");

    proto::comet::v1::WatchRequest request; // Only this object's complete position may resume the same range.
    request.mutable_scope()->set_sector(scope_.sector);
    request.mutable_scope()->set_spectrum(scope_.spectrum);
    request.set_target(target_);
    if (view_.version() && projection_->resume()) {
        request.set_instance(view_.instance());
        request.set_version(*view_.version());
    }
    projection_->begin(binding->instance);
    auto stream = std::make_shared<Stream>(this->shared_from_this(), binding, std::move(request));
    // No RPC is sent between these actions; failure cannot leave an uncharged request.
    if (!core_->claim()) {
        retry_ = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
        return;
    }
    binding_ = binding;
    stream_ = std::move(stream);
    stream_->start();
}

template <class Policy>
Core::Time Watching<Policy>::poll(Core::Time now, const std::shared_ptr<const Binding>& binding, const std::optional<Error>& error, bool closing) {

    ASTRA_PROFILE_SCOPE("comet.cpp.watching.Watching_Policy.poll");

    ASTRA_PROFILE_BEGIN(profileLock252, "comet.cpp.watching.Watching_Policy.poll.wait.lock");
    std::unique_lock lock(mutex_);
    ASTRA_PROFILE_END(profileLock252);
    if (closing || core_->stopped()) {
        // Control round applies explicit Client closure; actual cancellation and preparation release stay outside application destruction.
        if (!closed_.exchange(true, std::memory_order_acq_rel)) {
            lock.unlock();
            core_->release();
            lock.lock();
        }
    }
    const bool stopped = closed();
    if (stopped && !cleaned_) {
        view_.state_ = State::Closed;
        view_.error_.reset();
        dirty_ = false;
        projection_.reset(); // Application now owns the old contents retained by view_; controlled recovery budget no longer charges them.
        if (stream_) {
            stream_->cancel();
        }
        auto notice = std::move(changed_); // Release business captures outside the object lock and break ownership cycles after closure.
        auto watched = std::move(watched_);
        lock.unlock();
        notice.reset();
        watched.reset();
        lock.lock();
        cleaned_ = true;
    }
    if (stream_ && !stopped && binding_ != binding) {
        projection_->discard();
        stream_->cancel(); // Old requests remain bound to their original target; late pages never enter the new binding.
        publish(view_.version() ? State::Stale : State::Waiting, error);
    }
    if (!stream_ && !stopped && !binding && !failed_) {
        // Initial login rejection also notifies Readers without streams, avoiding indefinite unexplained waiting.
        publish(error ? State::Failed : view_.version() ? State::Stale
                                                        : State::Waiting,
                error);
    }

    if (stream_) {
        auto stream = stream_; // Retain current access when releasing the parent reference, so this stack cannot destroy a locked mutex.
        ASTRA_PROFILE_BEGIN(profileLock286, "comet.cpp.watching.Watching_Policy.poll.wait.io");
        std::unique_lock io(stream->mutex_);
        ASTRA_PROFILE_END(profileLock286);
        if (stream->done_) {
            io.unlock();
            stream_.reset();
            core_->relinquish();
            if (!stopped && binding_ == binding && !failed_ && !stream->repair_) {
                auto failure = Core::failure(grpc::Status(stream->code_, ""), stream->context_);
                if (failure.code == Error::Code::Transport && stream->code_ == grpc::StatusCode::CANCELLED && !binding_->session.empty() && !stream->timed_) {
                    failure.code = Error::Code::Session; // Credential revocation cancels dependent streams; reauthenticate at the same endpoint before considering Star failover.
                }
                projection_->discard();
                // Authority lag or insufficient history may recover locally without a shared Client failover storm.
                failed_ = failure.code == Error::Code::Input || failure.code == Error::Code::Limit || failure.code == Error::Code::Protocol;
                publish(failed_ ? State::Failed : view_.version() ? State::Stale
                                                                  : State::Waiting,
                        failure);
                failures_ = std::min(failures_ + 1, 32U);
                retry_ = now + core_->delay(failures_);
                if (failure.code == Error::Code::Session || failure.code == Error::Code::Transport) {
                    core_->lost(binding_, failure);
                }
            }
        } else if (!stopped && !stream->timed_ && stream->stage_ == Stream::Stage::Reading && now >= stream->deadline_) {
            stream->timed_ = true;
            io.unlock();
            projection_->discard();
            publish(view_.version() ? State::Stale : State::Waiting, Error{Error::Code::Timeout, Error::Effect::Unapplied, {}, {}, {}});
            stream->cancel(); // A target missing the first or next page within the confirmation deadline cannot retain Watch quota forever.
        } else if (stream->stage_ == Stream::Stage::Overflow && !stopped && !failed_) {
            io.unlock();
            projection_->discard();
            failed_ = true;
            publish(State::Failed, Error{Error::Code::Limit, Error::Effect::Unapplied, {}, {}, {}});
            stream->cancel();
        } else if (stream->stage_ == Stream::Stage::Ended) {
            stream->release();
        } else if (stream->stage_ == Stream::Stage::Ready && !stopped && binding_ == binding && !failed_) {
            ASTRA_PROFILE_CONSUME(stream->profileReady_, "comet.watch.ready_to_consume");
            auto page = std::move(stream->page_); // Exclusively consumes the current complete page; no next-page read during parsing.
            stream->stage_ = Stream::Stage::Consumed;
            io.unlock();
            try {
                auto accepted = projection_->accept(page);
                if (!accepted) {
                    if (projection_->repair(accepted.error().code)) {
                        stream->repair_ = true;
                        failures_ = std::min(failures_ + 1, 32U);
                        retry_ = now + core_->delay(failures_);
                        publish(view_.version() ? State::Stale : State::Waiting, accepted.error());
                    } else {
                        failed_ = true;
                        auto failure = accepted.error(); // Once the sole missing-Attr fallback is spent, expose further failures as protocol errors.
                        if (failure.code == Error::Code::History) {
                            failure.code = Error::Code::Protocol;
                        }
                        publish(State::Failed, std::move(failure));
                    }
                    stream->cancel();
                } else if (*accepted) {
                    stream->deadline_ = Core::Time::max(); // No updates after readiness is valid; data silence alone is not disconnection.
                    view_ = std::move(**accepted);
                    dirty_ = true;
                    updated_ = true;
                    failures_ = 0; // Only a complete applied batch ends consecutive failure, not TCP connection success.
                    if (!stream->recovered_) {
                        stream->recovered_ = true;
                        core_->recovered(binding_);
                    }
                } else {
                    stream->deadline_ = now + core_->options_.timeout;
                }
            } catch (...) {
                projection_->discard();
                failed_ = true;
                publish(State::Failed, Error{Error::Code::Internal, Error::Effect::Unapplied, {}, {}, {}});
                stream->cancel();
            }
            Reply{}.Swap(&page);
            ASTRA_PROFILE_BEGIN(profileLock361, "comet.cpp.watching.Watching_Policy.poll.wait.consumed");
            const std::lock_guard consumed(stream->mutex_);
            ASTRA_PROFILE_END(profileLock361);
            static_cast<void>(core_->resize(stream->bytes_, 0));
            stream->bytes_ = 0; // Private decoded page was released; the next Read may reacquire decoding budget.
            // Next Read waits for user notifications below, keeping subscription callbacks serial without a notification queue.
        }
    }

    if (dirty_ && !stopped && changed_ && core_->notification()) {
        auto callback = changed_;
        auto notification = view_; // Fix the current state before callback entry; user may close nonblockingly or start other asynchronous work.
        notifying_ = true;
        dirty_ = false;
        lock.unlock();
        const bool previous = Core::notifying();
        Core::notify(true);
        try {
            (*callback)(std::move(notification));
        } catch (...) {
            core_->exception(); // Do not roll back installed data or replay notifications; record a bounded diagnostic count only.
        }
        callback.reset(); // Callbacks may replace themselves; capture destructors may reenter the same object too.
        Core::notify(previous);
        lock.lock();
        notifying_ = false;
    }
    if (!changed_) {
        dirty_ = false;
    }
    if (updated_ && !closed() && watched_ && core_->notification()) {
        auto callback = watched_;
        auto notification = view_;
        updated_ = false;
        notifying_ = true;
        lock.unlock();
        const bool previous = Core::notifying();
        Core::notify(true);
        try {
            (*callback)(std::move(notification));
        } catch (...) {
            core_->exception();
        }
        callback.reset(); // Retain notification context outside the object lock, preventing self-wait or deadlock during capture destruction.
        Core::notify(previous);
        lock.lock();
        notifying_ = false;
    }

    if (stream_ && !closed() && !failed_ && binding_ == binding && !core_->stopped()) {
        ASTRA_PROFILE_BEGIN(profileLock388, "comet.cpp.watching.Watching_Policy.poll.wait.io");
        const std::lock_guard io(stream_->mutex_);
        ASTRA_PROFILE_END(profileLock388);
        if (stream_->stage_ == Stream::Stage::Consumed && !stream_->done_ && stream_->held_) {
            // Only consumed pages return to reading; other wakes cannot issue duplicate StartRead on the same buffer.
            stream_->stage_ = Stream::Stage::Reading;
            stream_->page_.Clear();
            stream_->StartRead(&stream_->page_);
        }
    }
    if (!stream_ && !closed() && !failed_ && binding && now >= retry_ && !core_->stopped()) {
        start(binding);
    }
    if (cleaned_ && !stream_ && !notifying_) {
        finished_.store(true, std::memory_order_release);
    }
    condition_.notify_all();
    if (closed() || failed_ || stream_ || !binding) {
        return stream_ && !closed() && !failed_ && !stream_->timed_ ? stream_->deadline_ : Core::Time::max();
    }
    return retry_;
}

} // namespace comet::detail
