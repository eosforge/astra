// Manage private Catalog writes and their completion and cancellation state.
#pragma once
#include "core.hpp"
#include <comet/publisher.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <vector>

namespace comet::detail {
/// Calling thread performs Query and Publish; control round only cancels. Retains no desired values or automatic renewals.
class Publishing final : public Activity, public std::enable_shared_from_this<Publishing> {
public:
    /// Local construction sends no RPC before admission.
    Publishing(std::shared_ptr<Core> core, Scope scope);
    /// Returns the last Key version-baseline budget; retains no Data.
    ~Publishing() override;
    /// At most one call per object.
    Result<Publisher::Receipt> update(std::vector<Publisher::Entry> entries, std::chrono::milliseconds ttl, std::chrono::milliseconds timeout);
    /// Closes the stop gate and cancels this call immediately, without waiting for Core.
    void close() noexcept;
    /// Waits for the actual synchronous call to finish; forbidden in notifications.
    bool wait(std::chrono::milliseconds timeout) const;
    /// Object stop gate.
    bool closed() const noexcept override;
    /// Closed and actual call completed.
    bool finished() const noexcept override;

    /// Consumes a writer-object slot.
    bool streaming() const noexcept override {
        return false;
    }

    /// Cancels only the executing call on the invalidated binding.
    Core::Time poll(Core::Time now, const std::shared_ptr<const Binding>& binding, const std::optional<Error>& error, bool closing) override;

private:
    /// stop_callback destruction excludes execution, preventing close from borrowing an expired stack context.
    struct Cancel {
        /// Valid only while its Call lives and the callback remains registered.
        grpc::ClientContext* context;

        /// Acquires neither Core nor Publishing locks and invokes no user code.
        void operator()() const noexcept {
            context->TryCancel();
        }
    };

    /// Keep one RPC context alive until both client and per-call cancellation callbacks unregister.
    struct Call {
        /// Construct context before registering shared closure and per-call cancellation.
        explicit Call(Publishing& owner);

        /// Destroyed last, after both cancellation callbacks unregister.
        grpc::ClientContext context;
        /// Client closure triggers directly, independently of control-round availability.
        std::stop_callback<Cancel> shutdown;
        /// Belongs only to this update; cannot cancel the next call.
        std::stop_callback<Cancel> cancellation;
    };

    /// Resources span one update and return exactly on exceptions, return, or cancellation; no background replay.
    struct Operation {
        /// The call's strong reference keeps owner alive.
        explicit Operation(Publishing& owner) : owner(owner) {}

        /// Return budget and slots after actual RPC completion; failure invalidates the reusable baseline.
        ~Operation();
        /// Owning object for this attempt; owns no thread.
        Publishing& owner;
        /// Current controlled encoding and payload budget; zero before acquisition.
        std::size_t bytes{};
        /// Explicit-call slot acquired.
        bool admitted{};
        /// Actual RPC slot acquired.
        bool claimed{};
        /// Only confirmation with matching instance and version permits a later Query to be skipped.
        bool confirmed{};
    };

    /// Does not expose business payload.
    static Error error(Error::Code code, Error::Effect effect = Error::Effect::Unapplied);
    /// Fixed target and remaining deadline.
    Result<void> prepare(grpc::ClientContext& context, const std::shared_ptr<const Binding>& binding, Core::Time deadline);
    /// Frees Key baseline and charges once no update is concurrent, without acquiring the Core lock.
    void discard() noexcept;
    /// Read-only version baseline for one call.
    Result<std::uint64_t> query(const std::shared_ptr<const Binding>& binding, const std::vector<Publisher::Entry>& entries, Core::Time deadline, std::string& instance);

    /// Authentication and budget shared by all roles.
    const std::shared_ptr<Core> core_;
    /// Fixed public scope.
    const Scope scope_;
    /// Protects cancellation source and active flag; never held across network or user code.
    mutable std::mutex mutex_;
    /// Local drain notification for wait.
    mutable std::condition_variable condition_;
    /// Created per update; old control rounds can cancel only old state.
    std::stop_source cancellation_{std::nostopstate};
    /// Fixed target for this call, released on completion.
    std::shared_ptr<const Binding> binding_;
    /// Target of the last successful batch; cache does not retain old connections.
    std::weak_ptr<const Binding> confirmed_;
    /// Sorted exact Keys from the last batch, at most 128; no unbounded version table.
    std::vector<std::string> keys_;
    /// Last confirmed instance; anonymous access also requires watermark ownership.
    std::string instance_;
    /// Shared Key-baseline budget, returned on closure or destruction.
    std::size_t bytes_{};
    /// Highest allocated version; unknown outcomes consume versions too. No Data cache.
    std::uint64_t issued_{};
    /// An entire update is running; concurrent replacement is forbidden.
    bool active_{};
    /// One-way stop gate.
    std::atomic_bool closed_{};
};
} // namespace comet::detail
