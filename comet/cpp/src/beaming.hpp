// Manage private Beacon publication, renewal, and asynchronous completion state.
#pragma once
#include "core.hpp"
#include "lifetime.hpp"
#include <comet/beacon.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>

namespace comet::detail {
/// Shares synchronous Data and asynchronous lease state; recovery uses confirmed cache without replaying business requests.
class Beaming final : public Activity, public std::enable_shared_from_this<Beaming> {
public:
    /// Construction reserves cache only; registration starts after accept.
    Beaming(std::shared_ptr<Core> core, Scope scope, Value attr, Value data, std::chrono::milliseconds ttl, std::chrono::milliseconds beat, Beacon::Options options);
    /// Returns fixed cache after all actual RPCs and samples finish.
    ~Beaming() override;
    /// Factory performs the sole synchronous initial registration and closes immediately on failure.
    Result<void> initialize(Core::Time deadline);
    /// One synchronous call, without queuing or background retries.
    Result<Beacon::Receipt> update(Value data, std::chrono::milliseconds timeout, Core::Time started);
    /// Replaces the sampler and generation; an empty callback removes it.
    Result<void> tick(std::chrono::milliseconds interval, std::move_only_function<Value()> callback);
    /// Replaces the state callback and schedules the current state.
    Result<void> changed(std::move_only_function<void(Beacon::State)> callback);
    /// Rechecks the suspend-inclusive lease budget each time.
    Beacon::State state() const;
    /// Cancels explicit RPCs and automatic work without waiting for user callbacks.
    void close() noexcept;
    /// Only external threads may wait for actual local completion.
    bool wait(std::chrono::milliseconds timeout) const;

    /// Read the published close flag without waiting for outstanding callbacks to finish.
    bool closed() const noexcept override {
        return closed_.load(std::memory_order_acquire);
    }

    /// Read the completion flag published after registration work and callbacks have drained.
    bool finished() const noexcept override {
        return finished_.load(std::memory_order_acquire);
    }

    /// Physical quota is separate from Watch quota.
    bool streaming() const noexcept override {
        return false;
    }

    /// Sole control round; does not block on network I/O.
    Core::Time poll(Core::Time now, const std::shared_ptr<const Binding>& binding, const std::optional<Error>& error, bool closing) override;

private:
    /// Active notifications own their callback wrappers.
    using Notice = std::move_only_function<void(Beacon::State)>;
    /// Samplers return only complete owned Data.
    using Sample = std::move_only_function<Value()>;

    /// Requests cancellation of the context whose lifetime encloses the stop callback.
    struct Cancel {
        /// stop_callback must be destroyed before context.
        grpc::ClientContext* context;

        /// Request cancellation without waiting for network completion.
        void operator()() const noexcept {
            context->TryCancel();
        }
    };

    /// Owns one synchronous context and its client/object shutdown registrations until the RPC returns.
    struct Call {
        /// Synchronous application-thread RPC; cancellation does not end this storage's lifetime early.
        grpc::ClientContext context;
        /// Shared Client closure cancels directly without waiting for a control round.
        std::stop_callback<Cancel> shutdown;
        /// Object closure or target replacement cancels directly.
        std::stop_callback<Cancel> cancellation;
        /// Captures the fixed stop token for this attempt.
        explicit Call(Beaming& owner);
    };

    /// Returns the synchronous operation's memory and concurrency quotas on every exit.
    struct Operation {
        /// Sole owner of active_ cleanup.
        Beaming& owner;
        /// Whether synchronous-call quota was acquired.
        bool admitted{};
        /// Whether an actual unary slot was acquired.
        bool claimed{};
        /// In-flight request, reply, and input ownership budget.
        std::size_t bytes{};

        /// Track one synchronous operation without sending a request or acquiring quotas.
        explicit Operation(Beaming& owner) : owner(owner) {}

        /// Returns quota after the actual synchronous RPC returns, waking maintenance and wait.
        ~Operation();
    };

    /// Owns an asynchronous request and reply until its final callback publishes completion.
    template <class Request, class Reply>
    struct Attempt {
        /// Keeps the object alive until the final callback without counting as an application owner.
        std::shared_ptr<Beaming> owner;
        /// Actual request target cannot be redirected.
        std::shared_ptr<const Binding> binding;
        /// Immutable after sending.
        Request request;
        /// Release/acquire on done publishes the complete reply.
        Reply reply;
        /// Fixed finite deadline.
        grpc::ClientContext context;
        /// Suspend-inclusive time of the first actual send.
        Lifetime::Time sent{};
        /// Final network completion, not a cancellation request.
        std::atomic_bool done{};
        /// Retains only a bounded error code.
        grpc::StatusCode code = grpc::StatusCode::UNKNOWN;
        /// Actual owned memory budget.
        std::size_t bytes{};
        /// Actual automatic RPC slot.
        bool claimed{};
        /// Reserved slot for renewal or removal.
        bool priority{};

        /// Return any acquired RPC slot and memory charge after the final owner releases the attempt.
        ~Attempt() {
            if (claimed) {
                owner->core_->returning(priority, true);
            }
            static_cast<void>(owner->core_->resize(bytes, 0));
        }
    };

    /// Initial registration or recovery attempt carrying the confirmed content.
    using Creating = Attempt<proto::comet::v1::CreateRequest, proto::comet::v1::CreateReply>;
    /// Lease-renewal attempt without business content changes.
    using Renewing = Attempt<proto::comet::v1::RenewRequest, proto::comet::v1::RenewReply>;
    /// Best-effort removal attempt during closure.
    using Removing = Attempt<proto::comet::v1::RemoveRequest, proto::comet::v1::Empty>;
    template <class T>
    /// Prepares an owned context without sending.
    std::shared_ptr<T> prepare(const std::shared_ptr<const Binding>& binding, Core::Time deadline, bool priority);
    template <class T>
    /// Charges memory and acquires an actual slot only after encoding.
    bool admit(const std::shared_ptr<T>& call);
    template <class T>
    /// Network callbacks publish the final result only.
    static void complete(const std::shared_ptr<T>& call, const grpc::Status& status) noexcept;
    /// Waits for shared authentication and freezes the target within the original deadline.
    Result<void> begin(Operation& operation, Core::Time deadline, std::size_t bytes, std::shared_ptr<const Binding>& binding);
    /// Rechecks lifecycle and target immediately before sending.
    Result<void> context(grpc::ClientContext& context, const std::shared_ptr<const Binding>& binding, Core::Time deadline);
    /// Rejects stale generations when sample is present.
    Result<Beacon::Receipt> submit(Value data, Core::Time deadline, std::optional<std::uint64_t> sample);
    /// Runs on bounded workers, catches business exceptions, and always returns sampling_.
    void sample() noexcept;
    /// Validates the successful reply before installing the confirmed cache.
    Result<void> install(const proto::comet::v1::CreateReply& reply, const std::shared_ptr<const Binding>& binding, std::uint64_t generation, Lifetime::Time sent, std::size_t& reserved);
    /// Control round consumes automatic calls, not synchronous application results.
    void consume(const std::shared_ptr<const Binding>& binding);
    /// Reuses the logical ID and confirmed Data; each recovery consumes a new registration generation.
    void restore(const std::shared_ptr<const Binding>& binding, Core::Time now, Lifetime::Time time);
    /// Uses a new independent order without recalculating an old reply's lease.
    void renew(const std::shared_ptr<const Binding>& binding, Core::Time now, Lifetime::Time time);
    /// Attempts removal at most once within the shutdown budget.
    void remove(const std::shared_ptr<const Binding>& binding);
    /// Updates local state and shared connection failures under lock.
    void failure(const std::shared_ptr<const Binding>& binding, Error error);
    /// Marks notification work without invoking user code.
    void publish(Beacon::Phase phase, std::optional<Error> error = {});
    /// Compares the registered Star and actual endpoint; reauthentication may reuse them.
    bool target(const Binding& binding) const;
    /// Bounded local error.
    static Error error(Error::Code code, Error::Effect effect = Error::Effect::Unapplied);
    /// Shared connection and scheduling for all objects.
    const std::shared_ptr<Core> core_;
    /// Fixed registration scope.
    const Scope scope_;
    /// Fixed attributes, immutable after the factory returns.
    const Value attr_;
    /// Last successfully confirmed Data; holds the initial value before first registration.
    Value data_;
    /// Fixed TTL in 1 s..10 min.
    const std::chrono::milliseconds ttl_;
    /// 0 < beat < ttl; restarts after actual sending.
    const std::chrono::milliseconds beat_;
    /// Never held across user code or synchronous RPC.
    mutable std::mutex mutex_;
    /// Local cleanup notification.
    mutable std::condition_variable condition_;
    /// Fixed Attr, confirmed Data, and metadata budget.
    std::size_t bytes_{};
    /// Logical UUID survives recovery; instance tracks the latest confirmed target.
    Beacon::State state_;
    /// Issued by the first successful registration; never logged or exposed in public state.
    std::string capability_;
    /// Actual registered target; cleared when invalidated.
    std::shared_ptr<const Binding> binding_;
    /// Fixed target for an explicit synchronous call.
    std::shared_ptr<const Binding> activeBinding_;
    /// Sole stop source while active_.
    std::stop_source cancellation_{std::nostopstate};
    /// Admits only one synchronous call per object.
    bool active_{};
    /// Background recovery is allowed only after successful initial registration.
    bool initialized_{};
    /// Permanent errors stop recovery; a new ID cannot bypass them.
    bool permanent_{};
    /// Conservative lease measured from the first send.
    Lifetime lifetime_;
    /// Last actual send of a new Update, Renew, or Create, not an input attempt.
    std::optional<Lifetime::Time> sent_;
    /// Consumed Data order; unknown outcomes cannot reuse it.
    std::uint64_t issued_{};
    /// Data order of the recovery cache, distinct from issued_.
    std::uint64_t confirmed_{};
    /// Starts at 1 and increments on recovery; exhaustion never wraps.
    std::uint64_t generation_ = 1;
    /// Independent renewal sequence for the current registration.
    std::uint64_t renewal_{};
    /// Automatic maintenance backoff; initially eligible immediately.
    Core::Time retry_{};
    /// Bounded backoff exponent.
    unsigned failures_{};
    /// An executing notification retains the old callback during replacement.
    std::shared_ptr<Notice> changed_;
    /// Coalesces state notifications without an accumulating queue.
    bool dirty_{};
    /// Started callbacks may finish; wait includes their completion.
    bool notifying_{};
    /// Current optional sampler.
    std::shared_ptr<Sample> sampler_;
    /// Sampling period; zero when disabled.
    std::chrono::milliseconds interval_{};
    /// Next sample time; missed periods are not replayed.
    Core::Time tick_{};
    /// Sampler replacement and explicit updates invalidate old samples.
    std::uint64_t samplingGeneration_{};
    /// True from worker-slot queuing until sampling and commit finish.
    bool sampling_{};
    /// Immediate admission gate for closure.
    std::atomic_bool closed_{};
    /// All actual RPCs, samples, and notifications have finished.
    std::atomic_bool finished_{};
    /// Bounded shutdown retention; released on completion.
    std::shared_ptr<Beaming> retained_;
    /// Deadline fixed by the first close.
    Core::Time closeAt_{};
    /// At most one Remove attempt.
    bool removed_{};
    /// Cancellation still waits for done and never starts a second recovery.
    std::shared_ptr<Creating> creating_;
    /// Automatically reserved slot, independent of explicit Update.
    std::shared_ptr<Renewing> renewing_;
    /// Finite cleanup budget.
    std::shared_ptr<Removing> removing_;
};
} // namespace comet::detail
