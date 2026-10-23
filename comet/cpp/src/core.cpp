// Coordinate SDK connections and owned activities through the client control loop.
#include "core.hpp"

#include "beaming.hpp"
#include "observing.hpp"
#include "publishing.hpp"
#include "reading.hpp"
#include "roots.hpp"
#include "sampling.hpp"
#include "subscribing.hpp"
#include <astra/config.hpp>
#include <astra/profile.hpp>
#include <astra/scope.hpp>

#include <grpc/support/time.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/resource_quota.h>
#include <grpcpp/security/tls_certificate_provider.h>
#include <grpcpp/security/tls_credentials_options.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <fstream>
#include <functional>
#include <ios>
#include <iterator>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <set>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace comet::detail {
namespace {
/// Thread-local observer-call marker; stores neither object pointers nor global Client state.
thread_local bool callback{};

// Allocate the holder before locking the weak reference; even allocation failure cannot destroy an inspected object under Core's lock.
Activity* retain(const std::weak_ptr<Activity>& source, std::vector<std::shared_ptr<Activity>>& held) {
    held.emplace_back();
    held.back() = source.lock();
    return held.back().get();
}

/// Accept bounded regular CA files only; the SDK neither installs certificates nor downloads roots.
Result<std::string> certificate(const std::filesystem::path& path) {
    std::error_code error;
    if (!std::filesystem::is_regular_file(path, error) || error || std::filesystem::file_size(path, error) > 1024 * 1024 || error) {
        return std::unexpected(Error{Error::Code::Input, Error::Effect::Unapplied, {}, {}, {}});
    }
    std::ifstream file(path, std::ios::binary);
    std::string bytes(1024 * 1024 + 1, '\0');
    file.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    if (file.bad() || (!file.eof() && file.fail()) || file.gcount() == 0 || file.gcount() > 1024 * 1024) {
        return std::unexpected(Error{Error::Code::Input, Error::Effect::Unapplied, {}, {}, {}});
    }
    bytes.resize(static_cast<std::size_t>(file.gcount()));
    if (bytes.contains("PRIVATE KEY")) {
        return std::unexpected(Error{Error::Code::Input, Error::Effect::Unapplied, {}, {}, {}});
    }
    return bytes;
}
} // namespace

/// Own one streaming login attempt and its immutable credentials until final gRPC completion.
class Core::Login final : public grpc::ClientReadReactor<proto::comet::v1::SessionReply> {
public:
    /// owner retains the in-flight call; secret is immutable for this attempt despite Client::secret changes.
    Login(std::shared_ptr<Core> owner, std::shared_ptr<Binding> binding, Value secret, Time deadline) : owner_(std::move(owner)), binding_(std::move(binding)), secret_(std::move(secret)), deadline_(deadline), stub_(proto::comet::v1::Gateway::NewStub(binding_->streams)) {
        request_.set_key(owner_->options_.key);
        request_.set_secret(secret_->data(), secret_->size());
    }

    /// Start after Core owns this object; a long-lived Session must not inherit a three-second overall deadline.
    void start() {
        const std::lock_guard lock(mutex_); // secret() or close may cancel immediately after the call is scheduled.
        stub_->async()->Session(&context_, &request_, this);
        AddHold();
        held_ = true;
        StartRead(&reply_);
        StartCall();
    }

    void cancel() { // Order Set, Cancel, and callbacks under this object's I/O lock, outside the Core lock.
        const std::lock_guard lock(mutex_);
        context_.TryCancel();
        release();
    }

    void OnReadDone(bool ok) override { // Report complete messages or EOF only; the sole Core control round validates and updates connection state.
        const std::lock_guard lock(mutex_);
        available_ = ok;
        ended_ = !ok;
        owner_->wake();
    }

    void OnDone(const grpc::Status& status) override { // This object owns context; the control round may read metadata.
        const std::lock_guard lock(mutex_);
        code_ = status.error_code();
        done_ = true;
        owner_->wake();
    }

private:
    friend class Core;

    void release() {
        if (held_) {
            held_ = false;
            RemoveHold();
        }
    } // I/O lock is held; return the control hold exactly once.

    /// Background references are not application owners; the last application close still cancels this RPC.
    const std::shared_ptr<Core> owner_;
    /// Candidate binding for this attempt, not yet published.
    const std::shared_ptr<Binding> binding_;
    /// Pointer identity detects attempts superseded by credential changes without adding protocol generations.
    const Value secret_;
    /// Initial-confirmation timeout only; disabled once confirmed.
    const Time deadline_;
    /// Uses only the long-lived stream Channel.
    std::unique_ptr<proto::comet::v1::Gateway::Stub> stub_;
    /// Exclusively owns metadata and cancellation state.
    grpc::ClientContext context_;
    /// Independent request for this attempt, including frozen SECRET.
    proto::comet::v1::SessionRequest request_;
    /// Exactly one valid confirmation; a second successful message is a protocol error.
    proto::comet::v1::SessionReply reply_;
    /// Synchronizes messages, holds, and final status between network callbacks and the control round.
    std::mutex mutex_;
    /// External control hold retained until final completion.
    bool held_{};
    /// One complete, unconsumed confirmation.
    bool available_{};
    /// Read reached EOF; the control round must return its hold.
    bool ended_{};
    /// OnDone arrived; this object and its quota may be released.
    bool done_{};
    /// A complete valid confirmation was received, distinguishing revocation from initial login rejection.
    bool confirmed_{};
    /// Only OnDone publishes the actual final status.
    grpc::StatusCode code_ = grpc::StatusCode::UNKNOWN;
};

Core::Core(Client::Options options, std::shared_ptr<grpc::ChannelCredentials> credentials, Value secret) : options_(std::move(options)), credentials_(std::move(credentials)), secret_(std::move(secret)) {}

Result<std::shared_ptr<Core>> Core::prepare(Client::Options options) {

    const auto invalid = [] { return std::unexpected(Error{Error::Code::Input, Error::Effect::Unapplied, {}, {}, {}}); };
    if (options.endpoints.empty() || options.endpoints.size() > 64 || options.readers == 0 || options.readers > 4096 || options.beacons == 0 || options.beacons > 65536 || options.bytes < 16384 || options.bytes > 4ULL * 1024 * 1024 * 1024 || options.timeout.count() <= 0 || options.timeout > std::chrono::minutes(1)) {
        return invalid();
    }
    if (options.auth ? (!astra::Scope::text(options.key, 128) || options.secret.empty() || options.secret.size() > 4096) : (!options.key.empty() || !options.secret.empty())) {
        return invalid();
    }
    if (!options.tls && !options.ca.empty()) {
        return invalid();
    }
    std::set<std::string> endpoints; // Startup deduplication and normalization, not per-RPC address selection.
    for (auto& endpoint : options.endpoints) {
        auto normalized = astra::Config::formatPulsar(endpoint);
        if (!normalized || !endpoints.insert(*normalized).second) {
            return invalid();
        }
        endpoint = std::move(*normalized);
    }

    std::shared_ptr<grpc::ChannelCredentials> credentials;
    if (options.tls) {
        auto ca = options.ca.empty() ? Result<std::string>(std::string(roots())) : certificate(options.ca);
        if (!ca) {
            return std::unexpected(ca.error());
        }
        grpc::experimental::TlsChannelCredentialsOptions tls;
        if (!ca->empty()) {
            auto provider = std::make_shared<grpc::experimental::InMemoryCertificateProvider>();
            if (!provider->UpdateRoot(std::move(*ca)).ok() || !provider->ValidateCredentials().ok()) {
                return invalid();
            }
            tls.set_root_certificate_provider(std::move(provider));
        }
        tls.set_verify_server_certs(true);
        tls.set_check_call_host(true);
        tls.set_min_tls_version(TLS1_3);
        tls.set_max_tls_version(TLS1_3);
        credentials = grpc::experimental::TlsCredentials(tls);
    } else {
        credentials = grpc::InsecureChannelCredentials();
    }
    if (!credentials) {
        return invalid();
    }
    auto secret = std::make_shared<const std::vector<std::uint8_t>>(std::move(options.secret)); // Options retains no second copy of credential contents.
    return std::shared_ptr<Core>(new Core(std::move(options), std::move(credentials), std::move(secret)));
}

/// Core::connect freezes the endpoint before constructing both transports outside the Core lock.
std::shared_ptr<Binding> Core::connect() const {

    ASTRA_PROFILE_SCOPE("comet.cpp.core.Core.connect");

    auto binding = std::make_shared<Binding>(); // Only two transports for the current endpoint; Watch count does not expand the connection pool.
    {
        const std::lock_guard lock(mutex_);
        binding->endpoint = options_.endpoints[endpoint_];
    }
    grpc::ChannelArguments arguments;
    arguments.SetInt("grpc.use_local_subchannel_pool", 1);
    arguments.SetInt("grpc.enable_retries", 0);
    arguments.SetInt("grpc.keepalive_time_ms", 60000);
    arguments.SetInt("grpc.keepalive_timeout_ms", 20000);
    arguments.SetInt("grpc.keepalive_permit_without_calls", 0);
    arguments.SetMaxReceiveMessageSize(8 * 1024 * 1024);
    arguments.SetMaxSendMessageSize(8 * 1024 * 1024);
    grpc::ResourceQuota quota; // Charge decoding and transport separately from business-state Buffer storage.
    quota.Resize(32 * 1024 * 1024);
    arguments.SetResourceQuota(quota);
    binding->streams = grpc::CreateCustomChannel(binding->endpoint, credentials_, arguments);
    binding->unary = grpc::CreateCustomChannel(binding->endpoint, credentials_, arguments);
    binding->ephemeris = proto::comet::v1::Ephemeris::NewStub(binding->unary);
    binding->catalog = proto::comet::v1::Catalog::NewStub(binding->unary);
    return binding;
}

/// Core::schedule requests advancement at this time; preserves an earlier scheduled deadline.
void Core::schedule(Time time) {

    ASTRA_PROFILE_SCOPE("comet.cpp.core.Core.schedule");
    const auto remaining = std::chrono::duration_cast<std::chrono::nanoseconds>(std::max(time - std::chrono::steady_clock::now(), Time::duration::zero())).count();
    scheduled_ = true;
    alarm_.Set(gpr_time_add(gpr_now(GPR_CLOCK_MONOTONIC), gpr_time_from_nanos(remaining, GPR_TIMESPAN)), [owner = shared_from_this()](bool) mutable {
        // Alarm retains its fired closure; transfer this round's ownership out to break Core -> Alarm -> Core cycles.
        // active covers the entire tick even if a later Set replaces the old closure.
        const auto active = std::move(owner);
        active->tick();
    });
}

/// Core::start starts the control loop idempotently.
void Core::start() {
    const std::lock_guard lock(mutex_);
    if (!scheduled_ && !running_ && !closing_) {
        schedule(std::chrono::steady_clock::now()); // Repeated start must not Set the same Alarm again.
    }
}

/// Core::wake marks an object ready and wakes the control round; null wakes without marking an object.
void Core::wake(Activity* activity) noexcept {

    ASTRA_PROFILE_SCOPE("comet.cpp.core.Core.wake");

    ASTRA_PROFILE_BEGIN(profileLock205, "comet.cpp.core.Core.wake.wait.lock");
    const std::lock_guard lock(mutex_);
    ASTRA_PROFILE_END(profileLock205);
    if (activity) {
        // Caller lifetime covers this call only. Queue weak references, coalescing events without raw pointers or ownership cycles.
        if (!activity->ready_ && !activity->self_.expired()) {
            ready_.push_back(activity->self_); // accept reserved one slot per directory object; no allocation occurs here.
            activity->ready_ = true;
        }
    } else {
        refresh_ = true;
    }

    condition_.notify_all(); // Closure and cancellation also wake authentication waits in synchronous calls.
    awakened_ = true;
    if (scheduled_) {
        alarm_.Cancel();
    }
}

/// Core::release returns one owner reference; zero permits shutdown completion.
void Core::release() noexcept {

    bool closing; // Run stop callbacks outside the Core lock to avoid reentering internal locks during shutdown.
    {
        const std::lock_guard lock(mutex_);
        if (owners_ != 0 && --owners_ == 0) {
            closing_ = true;
            if (sampling_) {
                sampling_->close();
            }
            refresh_ = true;
            stopped_.store(true, std::memory_order_release);
        }
        closing = closing_;
        condition_.notify_all();
        awakened_ = true;
        if (scheduled_) {
            alarm_.Cancel();
        }
    }
    if (closing) {
        shutdown_.request_stop();
    }
}

/// Core::close stops admission and begins orderly shutdown idempotently.
void Core::close() noexcept {

    {
        const std::lock_guard lock(mutex_);
        stopped_.store(true, std::memory_order_release);
        closing_ = true;
        if (sampling_) {
            sampling_->close();
        }
        condition_.notify_all(); // Synchronous writes awaiting authentication must observe closure immediately, without waiting for user callbacks.
        refresh_ = true;
        awakened_ = true;
        if (scheduled_) {
            alarm_.Cancel();
        }
    }
    shutdown_.request_stop(); // Cancel in-flight synchronous RPCs immediately, independently of control-round event consumption.
}

/// Core::wait awaits shutdown completion and returns false on timeout.
bool Core::wait(std::chrono::milliseconds timeout) const {

    if (notifying()) {
        throw std::logic_error("Cannot wait inside a Comet callback");
    }

    std::unique_lock lock(mutex_);
    if (!condition_.wait_until(lock, deadline(timeout), [this] { return complete_; })) {
        return false;
    }

    const auto sampling = sampling_; // Once complete, reject samples and join actual threads outside the Core lock.
    lock.unlock();

    if (sampling) {
        sampling->wait();
    }
    return true;
}

Core::Time Core::deadline(std::chrono::milliseconds timeout) noexcept {

    const auto now = std::chrono::steady_clock::now(); // Capture time once; do not derive shutdown waits from wall time.
    if (timeout <= std::chrono::milliseconds::zero()) {
        return now;
    }
    constexpr auto maximum = std::chrono::duration_cast<std::chrono::milliseconds>(Time::duration::max()); // Clamp before converting milliseconds to nanoseconds to avoid signed overflow.
    if (timeout >= maximum) {
        return Time::max();
    }

    const auto duration = std::chrono::duration_cast<Time::duration>(timeout); // Positive and representable; subsequent subtraction cannot underflow.
    return now > Time::max() - duration ? Time::max() : now + duration;
}

/// Core::notifying reports user-callback execution, where waiting is forbidden.
bool Core::notifying() noexcept {
    return callback;
}

/// Core::notify sets callback activity; pair entry and exit.
void Core::notify(bool active) noexcept {
    callback = active;
}

/// Core::notification reports whether a notification may be delivered.
bool Core::notification() const noexcept {
    const std::lock_guard lock(mutex_);
    return !closing_; // Acquiring this lock starts the notification; later close waits for it to finish instead of withdrawing it.
}

/// Core::exception marks an internal failure for closure by a later control round.
void Core::exception() noexcept {
    auto count = exceptions_.load(std::memory_order_relaxed); // Diagnostic ordering is independent of data publication; saturate at uint64 maximum.
    while (count != std::numeric_limits<std::uint64_t>::max() && !exceptions_.compare_exchange_weak(count, count + 1, std::memory_order_relaxed)) {
    }
}

std::uint64_t Core::exceptions() const noexcept {
    return exceptions_.load(std::memory_order_relaxed);
}

Core::Schedule Core::schedule() const {

    ASTRA_PROFILE_SCOPE("comet.cpp.core.Core.schedule");

    ASTRA_PROFILE_BEGIN(profileLock286, "comet.cpp.core.Core.schedule.wait.lock");
    const std::lock_guard lock(mutex_);
    ASTRA_PROFILE_END(profileLock286);
    return {.directory = directoryRounds_, .ready = readyRounds_, .polled = polled_};
}

Core::Time Core::session(Time now) {

    std::shared_ptr<Login> login; // Retain the in-flight object independently; never acquire Login's I/O lock under the Core lock.
    Value secret;
    bool closing;
    std::shared_ptr<const Binding> binding;
    std::vector<std::shared_ptr<Activity>> held; // The final reference may invoke an application capture destructor; release it after all locks.
    {
        const std::lock_guard lock(mutex_);
        login = login_;
        secret = secret_;
        closing = closing_ && std::ranges::all_of(readers_, [&held](const auto& weak) { const auto* object = retain(weak, held); return !object || object->finished(); });
        binding = binding_;
    }
    if (!login) {
        return Time::max();
    }

    const std::lock_guard io(login->mutex_);
    const bool obsolete = !login->confirmed_ && login->secret_ != secret;  // Late initial confirmation with old credentials cannot replace a new attempt; confirmed Sessions remain valid.
    const bool detached = login->confirmed_ && binding != login->binding_; // Business failure already triggered shared recovery; do not rotate endpoints twice.
    if (closing || obsolete || detached || (!login->confirmed_ && now >= login->deadline_)) {
        login->context_.TryCancel();
        login->release();
    }

    if (login->available_ && !closing && !obsolete && !detached && (login->confirmed_ || now < login->deadline_)) {
        login->available_ = false;
        const auto& reply = login->reply_; // Initial confirmation requires a complete token and identity; a second confirmation cannot change stream identity.
        const bool valid = !login->confirmed_ && reply.session().size() == 32 && astra::Scope::text(reply.instance(), 128);
        {
            const std::lock_guard lock(mutex_);
            if (!closing_ && secret_ == login->secret_) {
                if (valid) {
                    login->binding_->instance = reply.instance();
                    login->binding_->session = reply.session();
                    login->confirmed_ = true;
                    refresh_ = true;
                    binding_ = login->binding_; // Publish the immutable binding only after both strings are complete.
                    blocked_.reset();
                } else {
                    binding_.reset();
                    blocked_ = Error{Error::Code::Protocol, Error::Effect::Unapplied, {}, {}, {}};
                    refresh_ = true; // Publish after validation; the transport wake may already have been consumed.
                }
            }
        }
        if (valid) {
            login->reply_.Clear();
            login->StartRead(&login->reply_); // Continue reading the long stream to EOF; cleanup uses neither periodic idle probes nor Release RPCs.
        } else {
            login->context_.TryCancel();
            login->release();
        }
    }
    if (login->ended_) {
        login->release();
    }
    if (!login->done_) {
        return login->confirmed_ || closing || obsolete || detached || now >= login->deadline_ ? Time::max() : login->deadline_;
    }

    // Consume trailing metadata and return Session quota only after OnDone. A revoked confirmed stream may log in again.
    // Pause for new SECRET only if the new login is explicitly rejected, so revocation cannot lock out valid accounts.
    const auto error = failure(grpc::Status(login->code_, ""), login->context_);
    const std::lock_guard lock(mutex_);
    if (login_ != login) {
        return Time::max();
    }
    login_.reset();
    if (binding_ == login->binding_) {
        refresh_ = true;
        binding_.reset();
    }
    if (closing_ || secret_ != login->secret_ || detached || blocked_) {
        return retry_;
    }
    if (!login->confirmed_ && (error.code == Error::Code::Session || error.code == Error::Code::Input)) {
        blocked_ = error;
        refresh_ = true; // Idle activities need the installed error, not only the earlier OnDone wake.
        return Time::max();
    }
    if ((error.code == Error::Code::Transport || error.code == Error::Code::Timeout || login->code_ == grpc::StatusCode::CANCELLED) && !(login->confirmed_ && login->code_ == grpc::StatusCode::CANCELLED)) {
        connecting_.reset();
        endpoint_ = (endpoint_ + 1) % options_.endpoints.size();
    }
    failures_ = std::min(failures_ + 1, 32U);
    retry_ = now + delay(failures_);
    return retry_;
}

/// Core::recovered confirms binding recovery, resets failures, and resumes subscriptions.
void Core::recovered(const std::shared_ptr<const Binding>& binding) {

    ASTRA_PROFILE_SCOPE("comet.cpp.core.Core.recovered");
    ASTRA_PROFILE_BEGIN(profileLock380, "comet.cpp.core.Core.recovered.wait.lock");
    const std::lock_guard lock(mutex_);
    ASTRA_PROFILE_END(profileLock380);
    if (binding_ == binding && !closing_) {
        failures_ = 0;
    }
}

Core::Time Core::dial(Time now) {

    std::shared_ptr<Binding> connecting; // Construct Channels outside the lock; only this control round selects the next endpoint.
    {
        const std::lock_guard lock(mutex_);
        if (closing_ || blocked_ || login_ || binding_) {
            return Time::max();
        }
        if (now < retry_) {
            return retry_;
        }
        connecting = connecting_;
    }
    if (!connecting) {
        connecting = connect();
        const std::lock_guard lock(mutex_);
        if (closing_) {
            return Time::max();
        }
        connecting_ = connecting;
        connectingUntil_ = now + options_.timeout;
    }

    const auto state = connecting->streams->GetState(true); // Advance connection nonblockingly without occupying a gRPC callback thread for TCP/TLS waits.
    if (state != GRPC_CHANNEL_READY) {
        const std::lock_guard lock(mutex_);
        if (now >= connectingUntil_) {
            connecting_.reset();
            endpoint_ = (endpoint_ + 1) % options_.endpoints.size();
            failures_ = std::min(failures_ + 1, 32U);
            retry_ = now + delay(failures_);
            return retry_;
        }
        return std::min(connectingUntil_, now + std::chrono::milliseconds(20));
    }

    std::shared_ptr<Login> login;
    {
        const std::lock_guard lock(mutex_);
        if (closing_ || blocked_ || login_ || binding_) {
            return Time::max();
        }
        if (!options_.auth) {
            refresh_ = true; // Reconnect deadline wakes must expose new bindings even to objects previously waiting indefinitely.
            binding_ = connecting;
            return Time::max();
        }
        auto binding = std::make_shared<Binding>(*connecting); // Share the Channel without changing confirmed Session strings retained by old Watches.
        login = std::make_shared<Login>(shared_from_this(), std::move(binding), secret_, now + options_.timeout);
        login_ = login; // Core must retain this object before exposing this to gRPC outside the lock.
    }
    login->start();
    return now + options_.timeout;
}

/// Core::tick advances at most eight rounds and sleeps when no events remain.
void Core::tick() {

    ASTRA_PROFILE_SCOPE("comet.cpp.core.Core.tick");

    // Alarm callbacks use one control path; wake merges into awakened_ while a round runs, without concurrent entry.
    {
        ASTRA_PROFILE_BEGIN(profileLock446, "comet.cpp.core.Core.tick.wait.lock");
        const std::lock_guard lock(mutex_);
        ASTRA_PROFILE_END(profileLock446);
        scheduled_ = false;
        running_ = true;
        awakened_ = false;
    }
    auto next = std::chrono::steady_clock::now() + std::chrono::seconds(1); // Idle fallback; actual network events cancel Alarm immediately to wake the loop.
    bool finished = false;
    try {
        // Continue directly for completions arriving during processing, avoiding another gRPC Alarm queue hop.
        // Yield the callback thread after at most eight rounds; sleep immediately when no new events remain.
        for (unsigned round = 0; round < 8; ++round) {
            {
                ASTRA_PROFILE_BEGIN(profileLock458, "comet.cpp.core.Core.tick.wait.lock");
                const std::lock_guard lock(mutex_);
                ASTRA_PROFILE_END(profileLock458);
                awakened_ = false; // This round consumes marked objects; later events mark them again.
            }

            /// Temporary strong references cover this round only; clear outside the Core lock on every exit, retaining bounded array capacity.
            struct Release {
                /// Borrows Core workspace only, without accessing the application directory.
                std::vector<std::shared_ptr<Activity>>& objects;
                /// Inspected idle or finished objects have the same destructor boundary.
                std::vector<std::shared_ptr<Activity>>& held;

                ~Release() {
                    objects.clear();
                    held.clear();
                } // Release may invoke business destructors and Core::release; it must occur outside the Core lock.
            } release{polling_, retained_};

            const auto now = std::chrono::steady_clock::now(); // One monotonic timestamp per round; no Pulsar or system wall-clock reads.
            next = now + std::chrono::seconds(1);              // Recompute each round instead of reusing a consumed expired deadline.
            next = std::min(next, session(now));
            next = std::min(next, dial(now));
            condition_.notify_all(); // Binding was published under the shared lock; wake calling threads before user notifications.
            {
                ASTRA_PROFILE_BEGIN(profileLock476, "comet.cpp.core.Core.tick.wait.lock");
                const std::lock_guard lock(mutex_);
                ASTRA_PROFILE_END(profileLock476);
                polling_.reserve(readers_.size());                   // Directory size is bounded; reuse capacity instead of allocating on every network wake.
                retained_.reserve(readers_.size());                  // Reuse the bounded inspection workspace; no per-event directory scan.
                const bool refresh = std::exchange(refresh_, false); // Broadcast to all active objects only on shared-state changes.
                if (refresh || now >= due_) {
                    ASTRA_PROFILE_COUNT("comet.core.directory_items", readers_.size());
                    ++directoryRounds_; // Count directory maintenance rounds, including expiry and shared-state broadcasts, separately from ready rounds.
                    // Scan only for expiry or shared-state changes; capture ready objects in the same scan without advancing twice.
                    ready_.clear();
                    due_ = Time::max();
                    std::erase_if(readers_, [this, now, refresh](const auto& weak) {
                        auto* reader = retain(weak, retained_); // Keep every inspected object alive until the control lock has been released.
                        if (!reader) {
                            return true;
                        }
                        const bool ready = std::exchange(reader->ready_, false); // Consume before unlocking so new poll events may enqueue again.
                        if (reader->finished()) {
                            reader->self_.reset(); // Late callbacks from retired objects must not reclaim queue slots.
                            return true;
                        }
                        if (refresh || ready || now >= reader->next_) {
                            polling_.push_back(retained_.back());
                        } else {
                            due_ = std::min(due_, reader->next_);
                        }
                        return false;
                    });
                } else {
                    ASTRA_PROFILE_COUNT("comet.core.ready_items", ready_.size());
                    ++readyRounds_; // Ordinary network completions use only the ready queue; idle objects are not scanned.
                    // Resolve only the K queued objects, avoiding an N-object idle scan for a single event.
                    for (const auto& weak : ready_) {
                        if (auto* reader = retain(weak, retained_)) {
                            reader->ready_ = false;
                            if (!reader->finished()) {
                                polling_.push_back(retained_.back());
                            }
                        }
                    }
                    ready_.clear();
                }
            }
            // Advance cleanup and keepalive before Watches that may invoke user callbacks; reuse existing workers and queues.
            std::ranges::partition(polling_, [](const auto& object) { return !object->streaming(); });
            for (const auto& reader : polling_) {
                std::shared_ptr<const Binding> binding;
                std::optional<Error> error;
                bool closing;
                {
                    ASTRA_PROFILE_BEGIN(profileLock519, "comet.cpp.core.Core.tick.wait.lock");
                    const std::lock_guard lock(mutex_);
                    ASTRA_PROFILE_END(profileLock519);
                    // An earlier Reader may invalidate the shared Session; later objects must not use the round's stale initial binding.
                    binding = binding_;
                    error = blocked_;
                    closing = closing_;
                }
                reader->next_ = reader->poll(now, binding, error, closing);
                due_ = std::min(due_, reader->next_); // Targeted advancement may move deadlines earlier; a stale minimum adds only an early wake, never a late renewal.
            }
            next = std::min(next, due_); // Preserve the original deadline even when no object expired this round; do not fall back to one-second polling.
            {
                ASTRA_PROFILE_BEGIN(profileLock530, "comet.cpp.core.Core.tick.wait.lock");
                const std::lock_guard lock(mutex_);
                ASTRA_PROFILE_END(profileLock530);
                ASTRA_PROFILE_COUNT("comet.core.polled_items", polling_.size());
                polled_ += polling_.size(); // Update statistics in the existing critical section without an extra control-lock acquisition.
                // Factories may admit objects during callbacks after this round's snapshot; inspect the actual directory before completing close.
                // Otherwise unfinished objects could be missed and their wait could remain blocked forever.
                const bool cleaned = closing_ && std::ranges::all_of(readers_, [this](const auto& weak) { const auto* reader = retain(weak, retained_); return !reader || reader->finished(); });
                finished = closing_ && !login_ && calls_.load(std::memory_order_relaxed) == 0 && unary_.load(std::memory_order_relaxed) == 0 && maintenance_.load(std::memory_order_relaxed) == 0 && recovery_.load(std::memory_order_relaxed) == 0 && admitted_.load(std::memory_order_relaxed) == 0 && cleaned && (!sampling_ || sampling_->finished());
                if (finished) {
                    connecting_.reset();
                    binding_.reset();
                    readers_.clear();
                    ready_.clear();
                    complete_ = true;
                    condition_.notify_all();
                }
            }
            ASTRA_PROFILE_BEGIN(profileLock545, "comet.cpp.core.Core.tick.wait.lock");
            const std::lock_guard lock(mutex_);
            ASTRA_PROFILE_END(profileLock545);
            if (finished || !awakened_) {
                break; // Deadline remains in next; avoid rescanning the directory for a new round without work.
            }
        }
    } catch (...) {
        // Internal preparation failures must not escape gRPC callbacks. Stop admission and continue cancellation and quota return later.
        // Do not report completion while RPCs remain; persistent allocation failure carries no business-recovery guarantee.
        close();
        next = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
    }

    ASTRA_PROFILE_BEGIN(profileLock556, "comet.cpp.core.Core.tick.wait.lock");
    const std::lock_guard lock(mutex_);
    ASTRA_PROFILE_END(profileLock556);
    running_ = false;
    if (!finished) {
        schedule(awakened_ ? std::chrono::steady_clock::now() : next);
    }
}

/// Core::delay computes capped failure backoff without throwing.
std::chrono::milliseconds Core::delay(unsigned failures) const noexcept {
    const auto base = std::min<std::uint64_t>(5000, std::uint64_t{100} << std::min(failures, 6U));
    const auto jitter = std::hash<std::string>{}(options_.endpoints.front()) % (base / 4 + 1); // Read fixed configuration only, avoiding endpoint_ contention with synchronous-RPC failover.
    return std::chrono::milliseconds(std::min<std::uint64_t>(5000, base + jitter));
}

Result<std::shared_ptr<Reading>> Core::reader(Scope scope, std::string target, Reader::Options options) {

    const astra::Scope address{scope.sector, scope.spectrum}; // Reuse text validation without exposing server Scope types in the public ABI.
    if (!address.valid() || address.internal() || (!target.empty() && !astra::Scope::text(target, 1024)) || options.bytes < 16384 || options.bytes > 1024ULL * 1024 * 1024 || options.records == 0 || options.records > 65536) {
        return std::unexpected(Error{Error::Code::Input, Error::Effect::Unapplied, {}, {}, {}});
    }

    auto reading = std::make_shared<Reading>(shared_from_this(), std::move(scope), std::move(target), std::move(options)); // Unaccepted objects prepare resources without sending RPCs.
    return accept(reading).transform([&reading] { return std::move(reading); });                                           // Transfer ownership on synchronous success; failure destroys the unaccepted object automatically.
}

Result<std::shared_ptr<Subscribing>> Core::subscriber(Scope scope, std::string target, Subscriber::Options options) {

    const astra::Scope address{scope.sector, scope.spectrum}; // Reuse text validation without exposing server Scope types in the public ABI.
    if (!address.valid() || address.internal() || (!target.empty() && !astra::Scope::text(target, 1024)) || options.bytes < 16384 || options.bytes > 1024ULL * 1024 * 1024 || options.records == 0 || options.records > 65536) {
        return std::unexpected(Error{Error::Code::Input, Error::Effect::Unapplied, {}, {}, {}});
    }

    auto reading = std::make_shared<Subscribing>(shared_from_this(), std::move(scope), std::move(target), std::move(options)); // Unaccepted objects prepare resources without sending RPCs.
    return accept(reading).transform([&reading] { return std::move(reading); });                                               // Uses the same ownership and failure boundary as Reader.
}

Result<std::shared_ptr<Observing>> Core::observer(Scope scope, std::string target, Observer::Options options) {

    const astra::Scope address{scope.sector, scope.spectrum}; // Reuse text validation without exposing server Scope types in the public ABI.
    if (!address.valid() || address.internal() || (!target.empty() && !Selection::valid(target)) || options.bytes < 16384 || options.bytes > 1024ULL * 1024 * 1024 || options.records == 0 || options.records > 65536) {
        return std::unexpected(Error{Error::Code::Input, Error::Effect::Unapplied, {}, {}, {}});
    }

    auto reading = std::make_shared<Observing>(shared_from_this(), std::move(scope), std::move(target), std::move(options)); // Unaccepted objects prepare resources without sending RPCs.
    return accept(reading).transform([&reading] { return std::move(reading); });                                             // Consume expected synchronously without a callback queue or extra reference copies.
}

Result<std::shared_ptr<Beaming>> Core::beacon(Scope scope, Value attr, Value data, std::chrono::milliseconds ttl, std::chrono::milliseconds beat, Beacon::Options options, Time deadline) {

    const astra::Scope address{scope.sector, scope.spectrum};
    if (!address.valid() || address.internal() || !attr || !data || attr->size() > 1024 * 1024 || data->size() > 1024 * 1024 || ttl < std::chrono::seconds(1) || ttl > std::chrono::minutes(10) || beat.count() <= 0 || beat >= ttl || options.timeout.count() <= 0 || options.timeout > std::chrono::minutes(1)) {
        return std::unexpected(Error{Error::Code::Input, Error::Effect::Unapplied, {}, {}, {}});
    }
    if (notifying()) {
        return std::unexpected(Error{Error::Code::Busy, Error::Effect::Unapplied, {}, {}, {}});
    }
    std::shared_ptr<Beaming> object; // Insufficient shared budget during construction rejects admission without changing other objects.
    try {
        object = std::make_shared<Beaming>(shared_from_this(), std::move(scope), std::move(attr), std::move(data), ttl, beat, std::move(options));
    } catch (const std::length_error&) {
        return std::unexpected(Error{Error::Code::Busy, Error::Effect::Unapplied, {}, {}, {}});
    }

    if (auto accepted = accept(object); !accepted) {
        return std::unexpected(accepted.error());
    }
    try {
        auto initialized = object->initialize(deadline);
        if (!initialized) {
            object->close();
            return std::unexpected(initialized.error());
        }
    } catch (...) {
        object->close();
        throw;
    }
    return object;
}

Result<std::shared_ptr<Publishing>> Core::publisher(Scope scope) {

    const astra::Scope address{scope.sector, scope.spectrum}; // Factory validates the fixed scope only; each update validates TTL.
    if (!address.valid() || address.internal()) {
        return std::unexpected(Error{Error::Code::Input, Error::Effect::Unapplied, {}, {}, {}});
    }
    auto object = std::make_shared<Publishing>(shared_from_this(), std::move(scope)); // Increment business ownership only after successful admission.
    return accept(object).transform([&object] { return std::move(object); });
}

Result<std::shared_ptr<const Binding>> Core::acquire(Time deadline, const std::atomic_bool& cancelled) const {

    std::unique_lock lock(mutex_);                                                                                    // Reuse the authentication and shutdown condition variable, without polling or extra threads.
    const auto ready = [&] { return closing_ || cancelled.load(std::memory_order_acquire) || binding_ || blocked_; }; // Borrows the call's stop gate only while waiting.
    if (!condition_.wait_until(lock, deadline, ready)) {
        return std::unexpected(Error{Error::Code::Timeout, Error::Effect::Unapplied, {}, {}, {}});
    }
    if (closing_ || cancelled.load(std::memory_order_acquire)) {
        return std::unexpected(Error{Error::Code::Closed, Error::Effect::Unapplied, {}, {}, {}});
    }
    if (blocked_) {
        auto failure = *blocked_; // Authentication waiting has not submitted business work and inherits no uncertainty from other RPCs.
        failure.effect = Error::Effect::Unapplied;
        return std::unexpected(std::move(failure));
    }
    return binding_;
}

bool Core::current(const std::shared_ptr<const Binding>& binding) const {
    const std::lock_guard lock(mutex_);
    return !closing_ && binding && binding_ == binding;
}

/// Core::outgoing acquires an outgoing slot and returns false when full.
/// priority and automatic select independent priority and automatic-traffic quotas.
bool Core::outgoing(bool priority, bool automatic) noexcept {

    ASTRA_PROFILE_SCOPE("comet.cpp.core.Core.outgoing");
    auto& counter = priority ? maintenance_ : automatic ? recovery_
                                                        : unary_; // Background recovery cannot exhaust the 16 keepalive slots.
    const std::size_t maximum = priority ? 16 : automatic ? 48
                                                          : 256;
    auto count = counter.load(std::memory_order_relaxed);
    while (count < maximum) {
        if (counter.compare_exchange_weak(count, count + 1, std::memory_order_relaxed)) {
            return true;
        }
    }
    return false;
}

/// Core::returning returns an outgoing slot, paired with outgoing.
void Core::returning(bool priority, bool automatic) noexcept {

    ASTRA_PROFILE_SCOPE("comet.cpp.core.Core.returning");
    const auto previous = (priority ? maintenance_ : automatic ? recovery_
                                                               : unary_)
                              .fetch_sub(1, std::memory_order_relaxed); // Return quota only when the actual callback is released; cancellation does not free capacity early.
    if (previous == (priority ? 16 : automatic ? 48
                                               : 256)) {
        wake(); // Broadcast only on full-to-available transitions; ordinary completions wake their own Activity independently.
    }
}

/// Core::admitting admits unfinished explicit operations; callers check their lifecycle stop gate separately.
bool Core::admitting() noexcept {
    auto count = admitted_.load(std::memory_order_relaxed);
    while (count < 256) {
        if (admitted_.compare_exchange_weak(count, count + 1, std::memory_order_relaxed)) {
            return true;
        }
    }
    return false;
}

/// Core::settled returns one explicit-operation quota; the owning object wakes the control round separately on completion.
void Core::settled() noexcept {
    admitted_.fetch_sub(1, std::memory_order_relaxed);
}

/// Core::accept admits a new active object or returns an error at capacity.
/// activity is the candidate object; insufficient capacity rejects it.
Result<void> Core::accept(const std::shared_ptr<Activity>& activity) {

    ASTRA_PROFILE_SCOPE("comet.cpp.core.Core.accept");

    std::vector<std::shared_ptr<Activity>> held; // Declare before the guard so all inspected references are released after unlocking.
    ASTRA_PROFILE_BEGIN(profileLock676, "comet.cpp.core.Core.accept.wait.lock");
    const std::lock_guard lock(mutex_);
    ASTRA_PROFILE_END(profileLock676);
    if (closing_) {
        return std::unexpected(Error{Error::Code::Closed, Error::Effect::Unapplied, {}, {}, {}});
    }
    held.reserve(2 * readers_.size() + ready_.size()); // Prepare every inspection slot before erase_if mutates either weak directory.
    // Admission is infrequent directory maintenance; prune expired weak entries so creation/destruction without advancement cannot fill the queue.
    const auto retired = [&held](const auto& weak) {
        auto* reader = retain(weak, held);
        if (!reader) {
            return true;
        }
        if (!reader->finished()) {
            return false;
        }
        reader->self_.reset();
        reader->ready_ = false;
        return true;
    };
    std::erase_if(readers_, retired);
    std::erase_if(ready_, retired); // Remove from the directory before pruning the queue, preventing stale ready slots when finished changes concurrently.
    std::size_t count{};            // Closed objects awaiting cleanup consume no application quota; calls_ still charges their actual RPCs.
    std::size_t retained{};         // Closed objects awaiting actual cleanup also have a separate limit.
    for (const auto& reader : readers_) {
        if (const auto* owned = retain(reader, held); owned && owned->streaming() == activity->streaming()) {
            ++retained;
            count += static_cast<std::size_t>(!owned->closed());
        }
    }
    if (count >= (activity->streaming() ? options_.readers : options_.beacons) || retained >= 2 * (activity->streaming() ? options_.readers : options_.beacons)) {
        return std::unexpected(Error{Error::Code::Busy, Error::Effect::Unapplied, {}, {}, {}});
    }

    // Reserve simultaneous readiness for all directory objects before publication; geometric growth avoids quadratic per-object copying.
    if (ready_.capacity() < readers_.size() + 1) {
        ready_.reserve(std::max(readers_.size() + 1, ready_.capacity() * 2));
    }
    readers_.push_back(activity);
    activity->self_ = activity;
    activity->ready_ = true;
    ready_.push_back(activity);
    ++owners_;
    awakened_ = true;
    if (scheduled_) {
        alarm_.Cancel();
    }
    return {};
}

/// Core::secret replaces future login credentials and cancels the old login; local replacement does not directly revoke other server Sessions.
/// value contains new credential bytes; callers should clear their copy after use.
Result<void> Core::secret(std::vector<std::uint8_t> value) {

    if (!options_.auth || value.empty() || value.size() > 4096) {
        return std::unexpected(Error{Error::Code::Input, Error::Effect::Unapplied, {}, {}, {}});
    }
    auto secret = std::make_shared<const std::vector<std::uint8_t>>(std::move(value));
    std::shared_ptr<Login> login;
    {
        const std::lock_guard lock(mutex_);
        if (closing_) {
            return std::unexpected(Error{Error::Code::Closed, Error::Effect::Unapplied, {}, {}, {}});
        }
        secret_ = std::move(secret);
        blocked_.reset();
        if (!binding_) {
            login = login_; // Cancel only unconfirmed logins; valid identities end on server revocation or disconnection.
        }
        retry_ = Time{};
    }
    if (login) {
        login->cancel();
    }
    wake();
    return {};
}

/// Core::claim acquires a Watch slot and returns false when full.
bool Core::claim() noexcept {
    auto count = calls_.load(std::memory_order_relaxed);
    while (count < options_.readers) {
        if (calls_.compare_exchange_weak(count, count + 1, std::memory_order_relaxed)) {
            return true;
        }
    }
    return false;
}

/// Core::relinquish returns a Watch slot, paired with claim.
void Core::relinquish() noexcept {
    if (calls_.fetch_sub(1, std::memory_order_relaxed) == options_.readers) {
        wake(); // When actual OnDone returns a previously exhausted Watch slot, wake objects still waiting to open a stream.
    }
}

/// Core::resize adjusts the shared budget and returns false above the limit.
/// previous and requested are the old and new budgets; growth must remain bounded.
bool Core::resize(std::size_t previous, std::size_t requested) noexcept {
    auto total = bytes_.load(std::memory_order_relaxed);
    do {
        if (total < previous || requested > options_.bytes - (total - previous)) {
            return false;
        }
    } while (!bytes_.compare_exchange_weak(total, total - previous + requested, std::memory_order_relaxed));
    return true;
}

/// Core::lost invalidates a binding and starts recovery for dependent objects.
/// binding is the invalidated binding; error describes the failure.
void Core::lost(const std::shared_ptr<const Binding>& binding, Error error) {

    ASTRA_PROFILE_SCOPE("comet.cpp.core.Core.lost");

    std::shared_ptr<Login> login;
    {
        ASTRA_PROFILE_BEGIN(profileLock783, "comet.cpp.core.Core.lost.wait.lock");
        const std::lock_guard lock(mutex_);
        ASTRA_PROFILE_END(profileLock783);
        if (binding_ != binding || closing_) {
            return;
        }
        binding_.reset();
        login = login_;
        if (!options_.auth && error.code == Error::Code::Session) {
            blocked_ = error; // If the server rejects anonymous configuration, do not recreate it forever or silently switch to authenticated login.
        }
        if (error.code == Error::Code::Transport) {
            connecting_.reset();
            endpoint_ = (endpoint_ + 1) % options_.endpoints.size();
        }
        failures_ = std::min(failures_ + 1, 32U);
        retry_ = std::chrono::steady_clock::now() + delay(failures_);
    }
    if (login) {
        login->cancel();
    }
    wake();
}

Error Core::failure(const grpc::Status& status, const grpc::ClientContext& context) {

    Error error; // Without trustworthy details, network closure cannot prove that a write did not commit.
    switch (status.error_code()) {
    case grpc::StatusCode::UNAUTHENTICATED:
        error.code = Error::Code::Session;
        break;
    case grpc::StatusCode::INVALID_ARGUMENT:
        error.code = Error::Code::Input;
        break;
    case grpc::StatusCode::RESOURCE_EXHAUSTED:
        error.code = Error::Code::Busy;
        break;
    case grpc::StatusCode::DEADLINE_EXCEEDED:
        error.code = Error::Code::Timeout;
        break;
    case grpc::StatusCode::UNIMPLEMENTED:
        error.code = Error::Code::Protocol; // An unimplemented RPC cannot be fixed by reconnecting with the same protocol; do not fail over the whole Client.
        break;
    default:
        error.code = Error::Code::Transport;
        break;
    }
    const auto& metadata = context.GetServerTrailingMetadata();
    const auto range = metadata.equal_range("comet-error-bin");
    if (range.first == range.second || std::next(range.first) != range.second || range.first->second.size() > 4096) {
        return error;
    }
    proto::comet::v1::Failure failure;
    if (!failure.ParseFromArray(range.first->second.data(), static_cast<int>(range.first->second.size()))) {
        return error;
    }
    switch (failure.reason()) {
    case proto::comet::v1::REASON_DENIED: // Public fixed-boundary rejections must not become unbounded retries as unrecognized transport failures.
    case proto::comet::v1::REASON_INPUT:
        error.code = Error::Code::Input;
        break;
    case proto::comet::v1::REASON_SESSION:
        error.code = Error::Code::Session;
        break;
    case proto::comet::v1::REASON_VERSION:
        error.code = Error::Code::Version;
        break;
    case proto::comet::v1::REASON_ENDED:
        error.code = Error::Code::Ended;
        break;
    case proto::comet::v1::REASON_OBSOLETE:
        error.code = Error::Code::Obsolete;
        break;
    case proto::comet::v1::REASON_CONFLICT:
        error.code = Error::Code::Conflict;
        break;
    case proto::comet::v1::REASON_HISTORY:
        error.code = Error::Code::History;
        break;
    case proto::comet::v1::REASON_LIMIT:
        error.code = Error::Code::Limit;
        break;
    case proto::comet::v1::REASON_BUSY:
        error.code = Error::Code::Busy;
        break;
    case proto::comet::v1::REASON_INSTANCE:
        error.code = Error::Code::Instance;
        break;
    case proto::comet::v1::REASON_CLOCK:
        error.code = Error::Code::Clock;
        break;
    default:
        return error;
    }
    if (failure.effect() == proto::comet::v1::EFFECT_UNAPPLIED) {
        error.effect = Error::Effect::Unapplied;
    }
    if (astra::Scope::text(failure.instance(), 128)) {
        error.instance = failure.instance();
    }
    if (failure.has_version()) {
        error.version = failure.version();
    }
    if (failure.has_retry_ms()) {
        error.retry = std::chrono::milliseconds(std::min(failure.retry_ms(), 5000U));
    }
    return error;
}
} // namespace comet::detail

namespace comet {
/// Release one application ownership count when the last shared Client handle disappears.
struct Client::Owner {
    /// Count application Client owners only, separately from internal RPC references.
    std::shared_ptr<detail::Core> core;

    ~Owner() {
        core->release();
    } // When the last Client disappears, active Readers retain their own application ownership counts.
};

Client::Client(std::shared_ptr<Owner> owner) : owner_(std::move(owner)) {}

Result<Client> Client::open(Options options) {
    auto core = detail::Core::prepare(std::move(options));
    if (!core) {
        return std::unexpected(core.error());
    }
    auto owner = std::make_shared<Owner>(*core); // Start background work only after Owner allocation succeeds, avoiding self-retaining Sessions on failure.
    (*core)->start();
    return Client(std::move(owner));
}

Result<void> Client::secret(std::vector<std::uint8_t> value) {
    if (!owner_) {
        return std::unexpected(Error{Error::Code::Closed, Error::Effect::Unapplied, {}, {}, {}});
    }
    return owner_->core->secret(std::move(value));
}

Result<Reader> Client::reader(Scope scope, std::string target, Reader::Options options) {
    if (!owner_) {
        return std::unexpected(Error{Error::Code::Closed, Error::Effect::Unapplied, {}, {}, {}});
    }
    auto reading = owner_->core->reader(std::move(scope), std::move(target), std::move(options));
    if (!reading) {
        return std::unexpected(reading.error());
    }
    return Reader(std::move(*reading));
}

Result<Subscriber> Client::subscriber(Scope scope, std::string target, Subscriber::Options options) {
    if (!owner_) {
        return std::unexpected(Error{Error::Code::Closed, Error::Effect::Unapplied, {}, {}, {}});
    }
    auto reading = owner_->core->subscriber(std::move(scope), std::move(target), std::move(options));
    if (!reading) {
        return std::unexpected(reading.error());
    }
    return Subscriber(std::move(*reading));
}

Result<Observer> Client::observer(Scope scope, std::string target, Observer::Options options) {
    if (!owner_) {
        return std::unexpected(Error{Error::Code::Closed, Error::Effect::Unapplied, {}, {}, {}});
    }
    auto reading = owner_->core->observer(std::move(scope), std::move(target), std::move(options));
    if (!reading) {
        return std::unexpected(reading.error());
    }
    return Observer(std::move(*reading));
}

Result<Beacon> Client::beacon(Scope scope, std::vector<std::uint8_t> attr, std::vector<std::uint8_t> data, std::chrono::milliseconds ttl, std::chrono::milliseconds beat, Beacon::Options options) {
    if (!owner_) {
        return std::unexpected(Error{Error::Code::Closed, Error::Effect::Unapplied, {}, {}, {}});
    }
    const auto deadline = detail::Core::deadline(options.timeout); // Fix the total initial-registration deadline before acquiring an owned copy.
    auto created = owner_->core->beacon(std::move(scope), std::make_shared<const std::vector<std::uint8_t>>(std::move(attr)), std::make_shared<const std::vector<std::uint8_t>>(std::move(data)), ttl, beat, std::move(options), deadline);
    if (!created) {
        return std::unexpected(created.error());
    }
    return Beacon(std::move(*created));
}

Result<Publisher> Client::publisher(Scope scope) {
    if (!owner_) {
        return std::unexpected(Error{Error::Code::Closed, Error::Effect::Unapplied, {}, {}, {}});
    }
    auto object = owner_->core->publisher(std::move(scope)); // The local factory sends no business RPC.
    return object.transform([](auto&& value) { return Publisher(std::move(value)); });
}

void Client::close() noexcept {
    if (owner_) {
        owner_->core->close();
    }
}

bool Client::wait(std::chrono::milliseconds timeout) const {
    return !owner_ || owner_->core->wait(timeout);
}

std::uint64_t Client::exceptions() const noexcept {
    return owner_ ? owner_->core->exceptions() : 0;
}
} // namespace comet

namespace comet::detail {
bool Core::sample(std::move_only_function<void()> work) {
    const std::lock_guard lock(mutex_);
    if (closing_) {
        return false;
    }
    if (!sampling_) {
        sampling_ = Sampling::open();
    }
    return sampling_->submit(std::move(work));
}
} // namespace comet::detail
