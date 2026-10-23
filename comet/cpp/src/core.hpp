// Coordinate SDK connections and owned activities through the client control loop.
#pragma once
#include "comet.grpc.pb.h"
#include <comet/client.hpp>

#include <grpcpp/alarm.h>

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
#include <vector>

namespace comet::detail {
/// Bounded worker channel used only for Beacon ticks.
class Sampling;

/// Confirmed public binding. In-flight requests retain it and are never redirected by Client endpoint changes.
struct Binding {
    /// Explicit Star address for this attempt; no cross-Star round-robin.
    std::string endpoint;
    /// Star ID confirmed by login; anonymous access may remain unknown until the first valid business response.
    std::string instance;
    /// 32-byte binary token; empty for anonymous access and never logged.
    std::string session;
    /// Bounded long-lived stream Channel for Session and Watch.
    std::shared_ptr<grpc::Channel> streams;
    /// Independent subchannel pool avoids competing with long-lived HTTP/2 streams.
    std::shared_ptr<grpc::Channel> unary;
    /// Shared by all Publishers targeting this endpoint.
    std::shared_ptr<proto::comet::v1::Catalog::Stub> catalog;
    /// Fixed transport Stub shared by all Beacons, without per-heartbeat reconstruction.
    std::shared_ptr<proto::comet::v1::Ephemeris::Stub> ephemeris;
};

/// Live business object in a shared Client; supports cleanup and one advancement step, without a task queue or executor.
class Activity {
public:
    /// Release concrete objects only after actual gRPC completion.
    virtual ~Activity() = default;
    /// Application no longer owns the intent to recover automatically.
    virtual bool closed() const noexcept = 0;
    /// Local cleanup and actual RPCs are complete.
    virtual bool finished() const noexcept = 0;
    /// Watch and automatic writers account for application and actual-RPC capacity separately.
    virtual bool streaming() const noexcept = 0;
    /// Called by the sole control round outside the Core lock.
    virtual std::chrono::steady_clock::time_point poll(std::chrono::steady_clock::time_point now, const std::shared_ptr<const Binding>& binding, const std::optional<Error>& error, bool closing) = 0;

private:
    friend class Core;
    /// Control-round-only deadline; initially zero for first advancement. Network events do not change it.
    std::chrono::steady_clock::time_point next_{};
    /// Set only after admission. Ready queue borrows the control block; removal clears it to reject late wakes.
    std::weak_ptr<Activity> self_;
    /// Core lock enforces one ready entry per object; clear before consumption so poll events queue for the next round.
    bool ready_{};
};

/// Private shared Client core using one gRPC Alarm and existing callback threads, without per-object timers or a Task framework.
class Core : public std::enable_shared_from_this<Core> {
public:
    /// Local scheduling only; Comet does not read Pulsar.
    using Time = std::chrono::steady_clock::time_point;
    /// Validates local configuration and trust without business RPCs; expected failures return Error.
    static Result<std::shared_ptr<Core>> prepare(Client::Options options);
    /// Called after the first application Owner is ready; schedules asynchronously without waiting for connection.
    void start();
    /// Admits business handles; ownership and object quota increase only after successful creation.
    Result<std::shared_ptr<Reading>> reader(Scope scope, std::string target, Reader::Options options);
    /// Fixed Catalog scope and Key; shares Watch capacity.
    Result<std::shared_ptr<Subscribing>> subscriber(Scope scope, std::string target, Subscriber::Options options);
    /// Ephemeris shares connection and budget; projection accepts complete registrations or Data for known UUIDs only.
    Result<std::shared_ptr<Observing>> observer(Scope scope, std::string target, Observer::Options options);
    /// Binds only a Catalog scope, without caching business values or fixing TTL.
    Result<std::shared_ptr<Publishing>> publisher(Scope scope);
    /// Waits for authentication or an explicit error within the shared operation deadline.
    Result<std::shared_ptr<const Binding>> acquire(Time deadline, const std::atomic_bool& cancelled) const;
    /// Checks the original target before the next RPC starts.
    bool current(const std::shared_ptr<const Binding>& binding) const;
    /// Schedules only after local validation and admission.
    Result<std::shared_ptr<Beaming>> beacon(Scope scope, Value attr, Value data, std::chrono::milliseconds ttl, std::chrono::milliseconds beat, Beacon::Options options, Time deadline);
    /// Replaces future authentication SECRET; confirmed Sessions remain valid, while unconfirmed attempts cancel and restart.
    Result<void> secret(std::vector<std::uint8_t> value);
    /// Final Owner or business-handle closure decreases ownership; zero closes the internal lifecycle automatically.
    void release() noexcept;
    /// Closes all business work and Sessions without synchronously waiting for user callbacks or network.
    void close() noexcept;
    /// External threads may await all local work; SDK callbacks receive logic_error.
    bool wait(std::chrono::milliseconds timeout) const;
    /// Network or local changes wake the current Alarm without starting a concurrent control round.
    /// An object pointer wakes only that object; null signals shared identity, capacity, or closure changes.
    void wake(Activity* activity = nullptr) noexcept;

    /// Explicit Client close immediately prevents new notifications, without waiting for per-object control work.
    bool stopped() const noexcept {
        return stopped_.load(std::memory_order_acquire);
    }

    /// Only current shared Session or transport failures trigger Client recovery; local version or capacity errors do not.
    void lost(const std::shared_ptr<const Binding>& binding, Error error);
    /// Actual in-flight Watch quota is separate from application handle count and retained until OnDone.
    bool claim() noexcept;
    /// Paired exactly once with each successful claim.
    void relinquish() noexcept;
    /// Adjusts controlled Reading memory from previous to requested; failure preserves charges and acquires no business-state lock.
    bool resize(std::size_t previous, std::size_t requested) noexcept;
    /// User-callback boundary marker rejects SDK waits on the same thread; callbacks need not use a fixed thread.
    static bool notifying() noexcept;
    /// Actual callback entry saves and restores the prior value.
    static void notify(bool active) noexcept;
    /// Notification start ordered against explicit closure; caller holds Reading's short lock.
    bool notification() const noexcept;
    /// Counts observer exceptions only, without recording application data or exception text.
    void exception() noexcept;
    /// Observer exception diagnostic count for this shared Client.
    std::uint64_t exceptions() const noexcept;

    /// Read-only scheduling counters start at zero and accumulate under mutex_; measurements do not alter advancement or wake semantics.
    struct Schedule {
        /// Directory maintenance rounds, including expiry and shared-state broadcasts.
        std::uint64_t directory{};
        /// Ready-only rounds that do not scan idle objects.
        std::uint64_t ready{};
        /// Total actual object polls; divide by rounds for average work per round.
        std::uint64_t polled{};
    };

    /// Snapshots directory rounds, ready rounds, and object polls under mutex_, without network or callback waits.
    Schedule schedule() const;

private:
    /// Cancels synchronous RPCs outside the Core lock on explicit close or final-owner release.
    std::stop_source shutdown_;
    /// Shared one-way stop gate; late successes cannot clear close.
    std::atomic_bool stopped_{};
    friend class ::comet::Client;
    friend class Beaming;
    friend class Publishing;
    /// Test-only access to deterministic ownership schedules; no runtime hook.
    friend class Probe;
    template <class Policy>
    friend class Watching;
    /// Object is prepared outside the lock and unpublished; admit one application owner only on success.
    Result<void> accept(const std::shared_ptr<Activity>& activity);
    /// At most 256 explicit requests, 48 automatic Beacon recovery calls, and 16 dedicated renewal or cleanup slots.
    bool outgoing(bool priority, bool automatic) noexcept;
    /// Returns quota exactly when the final callback object is released.
    void returning(bool priority, bool automatic) noexcept;
    /// At most 256 unfinished synchronous Publisher and Beacon calls, including unsent calls.
    bool admitting() noexcept;
    /// Runs on shared Client sampling workers; returns false at capacity.
    bool sample(std::move_only_function<void()> callback);
    /// Lazily creates two threads; rejects new candidates after closure.
    std::shared_ptr<Sampling> sampling_;
    /// Returns quota once on synchronous return or candidate rollback.
    void settled() noexcept;
    /// One actual Session RPC continues reading after confirmation to detect closure or an invalid second confirmation.
    class Login;
    /// Construction schedules no timer; prepare creates the object without shared_from_this during construction or partial publication.
    Core(Client::Options options, std::shared_ptr<grpc::ChannelCredentials> credentials, Value secret);
    /// Sole Alarm entry extracts shared state before advancing Reading; never calls business objects or user callbacks under the Core lock.
    void tick();
    /// Consumes the sole Session's results; confirmation and closure need no network-wait thread.
    Time session(Time now);
    /// Starts a Session only after the previous one actually finishes; returns the actual retry deadline.
    Time dial(Time now);
    /// Clears shared failure backoff only after complete business recovery.
    void recovered(const std::shared_ptr<const Binding>& binding);
    /// Set and Cancel must be ordered under mutex_; Alarm itself does not make them thread-safe.
    void schedule(Time time);
    /// Current endpoint readiness deadline, separate from confirmed long-lived Session lifetime.
    Time connectingUntil_{};
    /// One failure count controls bounded backoff; brief TCP success does not reset persistent failures.
    std::chrono::milliseconds delay(unsigned failures) const noexcept;
    /// wait uses saturating addition: nonpositive values check immediately; oversized positive values clamp to the latest representable time.
    static Time deadline(std::chrono::milliseconds timeout) noexcept;
    /// Freezes both Channels for the selected endpoint; ordinary reauthentication may reuse its underlying connections.
    std::shared_ptr<Binding> connect() const;
    /// Parses only allowlisted generated failure fields; never echoes arbitrary remote text or treats unknown outcomes as success.
    static Error failure(const grpc::Status& status, const grpc::ClientContext& context);
    /// Fixed endpoints, APIKEY, TLS, and capacity; SECRET comes from a separate immutable value.
    const Client::Options options_;
    /// Independent client trust without server private keys.
    const std::shared_ptr<grpc::ChannelCredentials> credentials_;
    /// Protects lifecycle and timer state; never held across gRPC network waits or user code.
    mutable std::mutex mutex_;
    /// Local cleanup wait; does not extend operation deadlines.
    mutable std::condition_variable condition_;
    /// One shared timer resource; Core remains alive until its closure is released.
    grpc::Alarm alarm_;
    /// Alarm is Set; cleared when its firing or cancellation callback takes ownership.
    bool scheduled_{};
    /// A control round is running; wake only coalesces notifications.
    bool running_{};
    /// New events during a control round require an immediate recheck next round.
    bool awakened_{};
    /// Shared binding or quota changes require every object to recheck; ordinary object completions leave this clear.
    bool refresh_ = true;
    /// One-way admission stop; credential changes and late successes cannot reopen it.
    bool closing_{};
    /// All actual RPCs and local notifications ended; completion condition for wait.
    bool complete_{};
    /// Initial application Client Owner count; internal shared_ptr references do not increment it.
    std::size_t owners_ = 1;
    /// Avoids business-object -> Core ownership cycles; type erasure occurs only within a control round.
    std::vector<std::weak_ptr<Activity>> readers_;
    /// Targeted event queue reserves directory capacity on admission; noexcept wake allocates nothing and does not retain objects.
    std::vector<std::weak_ptr<Activity>> ready_;
    /// Control-round-only conservative minimum deadline; may wake early. Scan the directory only on expiry or shared changes.
    Time due_ = Time::max();
    /// Sole control round reuses capacity and clears strong references on every exit, including exceptions, avoiding cross-round cycles.
    std::vector<std::shared_ptr<Activity>> polling_;
    /// Includes canceled Sessions awaiting OnDone; never begins a second authentication early.
    std::shared_ptr<Login> login_;
    /// Unconfirmed transport for the current endpoint; not exposed to authenticated business work.
    std::shared_ptr<Binding> connecting_;
    /// Last complete immutable authentication binding; invalidation immediately prevents new requests from using it.
    std::shared_ptr<const Binding> binding_;
    /// Current complete SECRET; replacement leaves requests already copied by old Logins unchanged.
    Value secret_;
    /// Explicit authentication or protocol errors pause progress; a new SECRET may clear an authentication pause.
    std::optional<Error> blocked_;
    /// Current sequential endpoint index; no per-RPC load balancing across Stars.
    std::size_t endpoint_{};
    /// Bounded consecutive connection and authentication transport failure count.
    unsigned failures_{};
    /// Monotonic deadline for the next admission attempt.
    Time retry_{};
    /// Actual Watches awaiting OnDone, independent of application-object quota.
    std::atomic_size_t calls_{};
    /// Actual ordinary write requests not yet released; initially zero.
    std::atomic_size_t unary_{};
    /// Queued and in-flight explicit calls, excluding independent background recovery.
    std::atomic_size_t admitted_{};
    /// Actual in-flight automatic Beacon Create or Data calls; at most 48.
    std::atomic_size_t recovery_{};
    /// Actual Renew or Remove calls not yet released; initially zero.
    std::atomic_size_t maintenance_{};
    /// Total controlled Reading storage; application-retained old Views cannot be forcibly reclaimed.
    std::atomic_size_t bytes_{};
    /// Saturating observer exception count; initially zero.
    std::atomic_uint64_t exceptions_{};
    /// Directory maintenance rounds; initially zero, incremented only by the control round under mutex_.
    std::uint64_t directoryRounds_{};
    /// Ready-only rounds; initially zero, measures whether ordinary events scan the directory.
    std::uint64_t readyRounds_{};
    /// Actual object polls; initially zero, divided by rounds for average work.
    std::uint64_t polled_{};
    /// Release inspected activities outside the control lock, including those not polled.
    std::vector<std::shared_ptr<Activity>> retained_;
};
} // namespace comet::detail
