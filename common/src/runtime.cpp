// Node Runtime owns inbound/outbound Session lifecycles, service listeners, and the control loop.
#include "admission.hpp"
#include "catalog_service.hpp"
#include "ephemeris_service.hpp"
#include "exchange.hpp"
#include "grpc_session.hpp"
#include "intake.hpp"
#include "metrics.hpp"
#include "process.hpp"
#include "pulse_client.hpp"
#include "readout.hpp"
#include <astra/profile.hpp>
#include <astra/runtime.hpp>

#include <grpc/impl/channel_arg_names.h>
#include <grpc/support/time.h>
#include <grpcpp/health_check_service_interface.h>
#include <grpcpp/server_builder.h>

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <iostream>
#include <iterator>
#include <limits>
#include <stdexcept>

namespace astra {
namespace {
/// Rejects inadmissible or over-capacity RPCs with immediate Finish; OnDone alone releases them, outside business collections.
class Rejection final : public grpc::ServerBidiReactor<proto::astra::v1::SessionPacket, proto::astra::v1::SessionPacket> {
public:
    /// Finishes with fixed code during construction; absent from Runtime's Session collection and released only by OnDone.
    explicit Rejection(grpc::StatusCode code) {

        Finish(grpc::Status(code, "Star is not accepting this session"));
    }

    /// Deletes this unshared rejection reactor after final gRPC completion.
    void OnDone() override {
        delete this;
    }
};

/// Service handler and sole node control-loop owner.
class Runtime final : public proto::astra::v1::StarTransport::CallbackService {
public:
    /// Takes validated configuration, identity, and role policy; process ID comes from first admission. Construction starts no listener or admission.
    Runtime(Config config, std::shared_ptr<Identity> identity, std::unique_ptr<Policy> policy) : config_(std::move(config)), identity_(std::move(identity)), policy_(std::move(policy)), logger_(config_.role) {}

    /// Handler admits and registers ownership only; parsing, signatures, policy, and logs stay on the control loop.
    grpc::ServerBidiReactor<proto::astra::v1::SessionPacket, proto::astra::v1::SessionPacket>* OpenSession(grpc::CallbackServerContext* context) override {

        ASTRA_PROFILE_SCOPE("common.runtime.OpenSession");

        try {
            // Synchronizes incoming ownership because handlers run on gRPC workers.
            ASTRA_PROFILE_BEGIN(profileLock60, "common.runtime.OpenSession.wait.lock");
            std::lock_guard lock(incomingMutex_);
            ASTRA_PROFILE_END(profileLock60);

            if (!accepting_ || config_.role != Member::Role::Star) {
                return new Rejection(grpc::StatusCode::UNAVAILABLE);
            }

            if (inbound_ >= config_.maxInbound) {
                return new Rejection(grpc::StatusCode::RESOURCE_EXHAUSTED);
            }

            auto generation = nextGeneration();

            auto session = std::make_shared<Inbound>(context, config_, generation, hello_, notifier());
            // Borrowed reactor pointer is returned only after Session enters Runtime ownership.
            auto* reactor = session.get();

            incoming_.push_back(std::move(session));
            ++inbound_;

            wake_->notify();
            return reactor;
        } catch (...) {

            return new Rejection(grpc::StatusCode::INTERNAL);
        }
    }

    /// Borrows entry-owned Signals, creates TLS listener, runs the control loop, and drains shutdown; returns 0 normally or 1 on fatal admission failure.
    /// Listener/internal exceptions propagate to entry; failures after running begins first perform shutdown without logging exception text.
    int run(const Signals& signals) {

        grpc::EnableDefaultHealthCheckService(true); // Uses standard gRPC health service without an extra Comet Inspect handshake.
        // Bind and obtain the actual port before admission; never advertise an unbound or zero-port endpoint to Pulsar.
        grpc::ServerBuilder builder;
        builder.SetMaxReceiveMessageSize(static_cast<int>(config_.maxFrameBytes));
        builder.SetMaxSendMessageSize(static_cast<int>(config_.maxFrameBytes));
        builder.AddChannelArgument("grpc.server_handshake_timeout_ms", static_cast<int>(config_.handshakeTimeout.count()));
        // Deployment endpoints must be unique; separate identities cannot share SO_REUSEPORT.
        builder.AddChannelArgument("grpc.so_reuseport", 0);
        builder.AddChannelArgument("grpc.max_connection_idle_ms", 60000);
        // Listener gRPC resource quota is separate from application Session and message-queue limits.
        grpc::ResourceQuota quota;
        quota.Resize(32 * 1024 * 1024);
        builder.SetResourceQuota(quota);
        builder.RegisterService(this);
        // Actual bound port, initially zero until successful listener creation.
        int port = 0;

        builder.AddListeningPort(config_.listen.text(), identity_->serverCredentials(), &port);
        server_ = builder.BuildAndStart();
        if (!server_ || port <= 0) {
            throw std::runtime_error("Cannot bind TLS gRPC listener");
        }
        if (auto* health = server_->GetHealthCheckService()) {
            health->SetServingStatus(false); // A bound listener does not establish identity, baseline, or business readiness.
        }

        if (config_.advertise.port == 0) {
            config_.advertise.port = static_cast<std::uint16_t>(port);
        }
        try {
            if (config_.metrics) {
                metrics_ = std::make_unique<Metrics>(*config_.metrics);
                logger_.write("metrics_started", "{\"listen\":\"" + metrics_->endpoint().text() + "\"}");
            }

            admission_ = std::make_unique<Admission>(config_, identity_, notifier());
            logger_.write("started", "{\"advertise\":\"" + config_.advertise.text() + "\"}");

            while (!signals.requested() && !fatal_) {

                // Captured wake sequence; sleep only while unchanged to avoid a check-to-wait lost event.
                const auto observed = wake_->observe();

                step();

                wake_->wait(observed);
            }
        } catch (...) {

            shutdown();
            throw;
        }

        shutdown();
        return fatal_ ? 1 : 0;
    }

private:
    /// Allocates process-unique nonzero Session generations across handler/control threads; atomic uniqueness does not publish object state.
    Generation nextGeneration() {

        // CAS expected generation, updated on failure; maximum is reserved for exhaustion.
        auto current = nextGeneration_.load(std::memory_order_relaxed);

        while (current != std::numeric_limits<std::uint64_t>::max()) {
            if (nextGeneration_.compare_exchange_weak(current, current + 1, std::memory_order_relaxed)) {
                return {current};
            }
        }
        throw std::runtime_error("Session generation exhausted");
    }

    /// Returns a closure owning independent Wakeup, never this, so completion publication may permit immediate Session reclamation.
    std::function<void()> notifier() const {
        return [wake = wake_] { wake->notify(); };
    }

    /// Transfers handler-created incoming Sessions under the admission lock without changing in-flight counts or advancing protocol.
    void collect() {

        ASTRA_PROFILE_SCOPE("common.runtime.collect");

        // Coordinates handler queue/admission state with the control loop, without network waits.
        ASTRA_PROFILE_BEGIN(profileLock180, "common.runtime.collect.wait.lock");
        std::lock_guard lock(incomingMutex_);
        ASTRA_PROFILE_END(profileLock180);

        sessions_.insert(sessions_.end(), std::make_move_iterator(incoming_.begin()), std::make_move_iterator(incoming_.end()));
        incoming_.clear();
    }

    /// Reclaims done Sessions only, reporting closed or failed according to installed identity at monotonic now for backoff.
    /// Returns inbound capacity here, never when cancellation merely requests final completion.
    void reap(Steady::time_point now) {

        ASTRA_PROFILE_SCOPE("common.runtime.reap");

        std::erase_if(sessions_, [&](const std::shared_ptr<Session>& session) {
            if (!session->done()) {
                return false;
            }

            // Completed Session's final classification, empty without a specific error.
            const auto error = session->error();
            // Fallback transport diagnostic for unexplained closure; never remote text.
            const auto reason = error.value_or(Status::Code::Transport);

            if (session->installed()) {
                policy_->closed(session->generation(), error, now);
                logger_.failure("disconnected", reason);
            } else if (session->expected()) {

                policy_->failed(*session->expected(), reason, now);
                logger_.failure("connect_failed", reason);
            }

            if (session->direction() == Policy::Direction::Inbound) {

                ASTRA_PROFILE_BEGIN(profileLock214, "common.runtime.reap.wait.lock");
                std::lock_guard lock(incomingMutex_);
                ASTRA_PROFILE_END(profileLock214);
                --inbound_;
            }

            return true;
        });
    }

    /// Advances current Sessions at one monotonic timestamp, cancels displaced generations, then reclaims completed objects.
    void pumpSessions(Steady::time_point now) {

        ASTRA_PROFILE_SCOPE("common.runtime.pump_sessions");

        for (const auto& session : sessions_) {
            // Pre-pump installation state identifies first-admission log events this round.
            const bool installed = session->installed();

            const auto cancelled = session->pump(*policy_, *identity_, now);

            if (!installed && session->installed()) {
                logger_.write("connected");
            }

            for (const auto generation : cancelled) {
                // Finds old generation for cancellation; already-reclaimed entries do not affect the new Session.
                const auto old = std::ranges::find(sessions_, generation, [](const auto& item) { return item->generation(); });
                if (old != sessions_.end()) {
                    (*old)->cancel();
                }
            }
            bind(session, now); // Wire newly admitted Hello immediately, before business data can arrive next round.
        }

        reap(now);
    }

    /// Accept source identity only from trusted directory or verified Hello; retain highest deployment epoch through disconnection and TTL cleanup.
    Result<void> observe(const Member& member) {

        ASTRA_PROFILE_SCOPE("common.runtime.observe");

        if (member.role != Member::Role::Star || member.id == id_) {
            return {};
        }
        const auto found = sources_.find(member.principal);
        if (found == sources_.end()) {
            if (sources_.size() >= config_.maxMembers - 1) {
                return Status::capacity("Peer identity capacity exceeded");
            }
            sources_.emplace(member.principal, member);
            return {};
        }
        const auto replacement = supersedes(member, found->second);
        if (!replacement) {
            return std::unexpected(replacement.error());
        }
        if (*replacement) {
            Member prepared = member; // Allocate strings before retirement so publishing the replacement identity cannot fail allocation afterward.
            catalog_->retire(found->second.id);
            ephemeris_->retire(found->second.id);
            found->second = std::move(prepared);
        }
        return {};
    }

    /// Wire business replication for the current installed Star Session; old Sessions only cancel, while Planet remains on its frozen control path.
    void bind(const std::shared_ptr<Session>& session, Steady::time_point now) {

        ASTRA_PROFILE_SCOPE("common.runtime.bind");

        if (!catalog_ || !ephemeris_ || !session->installed() || session->bound() || session->error() || !session->peer() || session->peer()->role != Member::Role::Star) {
            return;
        }
        try {
            const auto accepted = observe(*session->peer());
            if (!accepted) {
                session->cancel(accepted.error().code);
                return;
            }
            const auto catalog = catalog_->admit(session->peer()->id);
            const auto ephemeris = ephemeris_->admit(session->peer()->id);
            if (!catalog || !ephemeris) {
                session->cancel(Status::Code::Capacity);
                return;
            }
            session->bind(std::make_unique<Exchange>(*catalog_, *ephemeris_, session->peer()->id, recovery_, session->capacity(), now));
        } catch (const std::bad_alloc&) {
            session->cancel(Status::Code::Capacity);
        } catch (...) {
            session->cancel(Status::Code::Internal);
        }
    }

    /// Initial source recovery waits at most 30 s; expiry permits explicit degraded opening, never claims missing/partial baselines succeeded.
    void ready(Steady::time_point now, bool clock) {

        ASTRA_PROFILE_SCOPE("common.runtime.ready");

        if (businessReady_ || !clock || !almanacReady_ || config_.role != Member::Role::Star) {
            return;
        }
        if (!recoveryDeadline_) {
            recoveryDeadline_ = now + std::chrono::seconds(30);
        }
        std::size_t complete{}; // Count only highest current identities whose valid streams completed both domains' initialization.
        for (const auto& [principal, member] : sources_) {
            (void)principal;
            complete += std::ranges::any_of(sessions_, [&](const auto& session) { return session->peer() && session->peer()->id == member.id && session->synchronized(); });
        }
        if (complete == sources_.size() || now >= *recoveryDeadline_) {
            businessReady_ = true;
            if (gateway_) {
                gateway_->ready();
            }
            if (auto* health = server_->GetHealthCheckService()) {
                health->SetServingStatus(true);
            }
            if (public_) {
                if (auto* health = public_->GetHealthCheckService()) {
                    health->SetServingStatus(true);
                }
            }
            logger_.write(complete == sources_.size() ? "business_ready" : "business_degraded", "{\"synchronized\":" + std::to_string(complete) + ",\"sources\":" + std::to_string(sources_.size()) + "}");
        }
    }

    /// Advances initial admission and candidate refresh independently, preserving local identity and retry deadlines on failure.
    void advanceAdmission(Steady::time_point now) {

        ASTRA_PROFILE_SCOPE("common.runtime.advance_admission");

        if (auto result = admission_->poll()) {
            if (*result) {

                auto& joined = **result;
                if (hello_ && config_.role == Member::Role::Star) {
                    auto refreshed = policy_->refresh(joined.local, joined.members); // Late directory results cannot regress newer signature-verified identities.
                    if (!refreshed) {
                        fatal_ = true;
                        logger_.failure("directory_rejected", refreshed.error().code);
                        return;
                    }
                    for (const auto generation : *refreshed) {
                        for (const auto& session : sessions_) {
                            if (session->generation() == generation) {
                                session->cancel();
                            }
                        }
                    }
                } else {
                    if (auto initialized = policy_->initialize(joined.local, joined.members); !initialized) {
                        fatal_ = true;
                        logger_.failure("registration_rejected", initialized.error().code);
                        return;
                    }
                }

                if (!hello_) {
                    // Coordinates handler queue/admission state with the control loop, without network waits.
                    ASTRA_PROFILE_BEGIN(profileLock368, "common.runtime.advance_admission.wait.lock");
                    std::lock_guard lock(incomingMutex_);
                    ASTRA_PROFILE_END(profileLock368);
                    id_ = joined.local.id;
                    hello_ = joined.hello;
                    accepting_ = config_.role != Member::Role::Star;
                    logger_.write("initialized", "{\"id\":" + jsonString(id_) + "}");
                }

                registrationFailures_ = 0;
                if (config_.role == Member::Role::Star) {
                    nextRegistration_ = now + Milliseconds(30000 + std::hash<std::string>{}(id_) % 5001);
                    if (!almanac_) {
                        almanac_ = std::make_unique<Library>(Library::Limits{}, [this](const Scope& scope, const Almanac::Change& change) noexcept {
                            if (readout_) {
                                readout_->changed(scope, change);
                            }
                        });
                        access_ = std::make_unique<Access>();
                        ephemeris_ = std::make_unique<Ephemeris::State>([this] { return synchronizedClock_.now(); }, Ephemeris::State::Limits{.source = {}, .projection = {}, .replicas = config_.maxMembers - 1});
                        catalog_ = std::make_unique<Catalog::State>([this] { return synchronizedClock_.now(); }, Catalog::State::Limits{.source = {}, .projection = {}, .replicas = config_.maxMembers - 1});
                        if (config_.comet) {
                            gateway_ = std::make_unique<Gateway>(*access_, id_, config_.auth);
                            readout_ = std::make_unique<Readout>(*almanac_, *gateway_, notifier());
                            ephemerisService_ = std::make_unique<Ephemeris::Service>(*ephemeris_, *gateway_, notifier());
                            catalogService_ = std::make_unique<Catalog::Service>(*catalog_, *gateway_, notifier());
                            openComet();
                        }
                    }
                    for (const auto& member : joined.members) {
                        const auto found = sources_.find(member.principal);
                        if (found != sources_.end() && member.epoch < found->second.epoch) {
                            continue; // Directory queries may lag verified Hello; never regress deployment identity.
                        }
                        if (const auto accepted = observe(member); !accepted) {
                            fatal_ = true;
                            logger_.failure("source_identity_rejected", accepted.error().code);
                            return;
                        }
                    }
                    if (!joined.services.empty()) {
                        auto candidate = joined.services.front(); // Trusted complete-directory role and alias validation already succeeded.
                        if (polaris_ && candidate.principal != polaris_->principal) {
                            polarisConflict_ = true;
                            if (intake_) {
                                intake_->cancel(Status::Code::Conflict);
                            }
                            logger_.failure("polaris_conflict", Status::Code::Conflict);
                        } else if (!polaris_ || candidate.epoch >= polaris_->epoch) {
                            if (polaris_ && !supersedes(candidate, *polaris_)) {
                                polarisConflict_ = true;
                                if (intake_) {
                                    intake_->cancel(Status::Code::Identity);
                                }
                            } else {
                                if (intake_ && candidate != intake_->target()) {
                                    intake_->cancel();
                                }
                                polaris_ = std::move(candidate);
                                polarisConflict_ = false;
                            }
                        }
                    }
                }
                // Start Star sampling only after admission, reusing process credentials; old control planes without Pulse remain explicitly unready.
                if (config_.role == Member::Role::Star && joined.pulseEndpoint != pulseEndpoint_) {
                    pulse_.reset();
                    pulseEndpoint_ = joined.pulseEndpoint;
                    if (!pulseEndpoint_.empty()) {
                        pulse_ = std::make_unique<Sampler>(pulseEndpoint_, identity_, hello_, synchronizedClock_);
                    }
                }
            } else {

                const auto code = result->error().code;
                if (admission_->revoked()) {
                    fatal_ = true;
                    logger_.failure("admission_revoked", code);
                    return;
                }
                // Only transport, timeout, and capacity failures may retry initial admission.
                const bool temporary = code == Status::Code::Transport || code == Status::Code::Timeout || code == Status::Code::Capacity;
                if (config_.role == Member::Role::Star && hello_ && !temporary) {
                    // Untrusted or conflicting directories pause new authority installation but preserve the complete old baseline; later List may recover.
                    polarisConflict_ = true;
                    if (intake_) {
                        intake_->cancel(code);
                    }
                }
                // A nontemporary error before initialization is fatal.
                if (!temporary && !hello_) {
                    fatal_ = true;
                    logger_.failure("registration_rejected", code);
                    return;
                }

                registrationFailures_ = std::min(registrationFailures_ + 1, 100U);
                nextRegistration_ = now + retryDelay(registrationFailures_, config_, std::hash<std::string>{}(id_.empty() ? config_.advertise.text() : id_));
                logger_.failure("registration_retry", code);
            }
        }

        if (!admission_->pending() && now >= nextRegistration_) {
            if (!hello_) {

                admission_->begin(0);
            } else if (config_.role == Member::Role::Star) {
                admission_->begin(0); // Registered Star calls List with admission metadata, without resending passwords.
            } else if (policy_->needsRefresh(now)) {

                if (candidateRound_ == std::numeric_limits<std::uint32_t>::max()) {
                    fatal_ = true;
                    return;
                }

                admission_->begin(++candidateRound_);
            }
        }
    }

    /// Receives bounded Almanac pages on the existing control loop, without per-group threads or connections.
    /// clock indicates established absolute local time; later holdover preserves completed startup eligibility.
    void advanceAlmanac(Steady::time_point now, bool clock) {

        ASTRA_PROFILE_SCOPE("common.runtime.advance_almanac");

        if (config_.role != Member::Role::Star || !hello_ || !almanac_) {
            return;
        }
        if (intake_) {
            intake_->pump(now);
            if (polaris_ && intake_->target().principal == polaris_->principal && intake_->target().epoch > polaris_->epoch) {
                polaris_ = intake_->target(); // New verified instances take priority over potentially late next-round queries.
            }
            if (intake_->ready() && !almanacReady_) {
                almanacReady_ = true;
                logger_.write("almanac_initialized");
            }
            if (intake_->done()) {
                logger_.failure("almanac_disconnected", intake_->error().value_or(Status::Code::Transport));
                intake_.reset();
                almanacFailures_ = std::min(almanacFailures_ + 1, 100U);
                nextAlmanac_ = now + retryDelay(almanacFailures_, config_, std::hash<std::string>{}(id_));
            } else if (intake_->ready()) {
                almanacFailures_ = 0;
            }
        }

        if (!intake_ && polaris_ && !polarisConflict_ && clock && now >= nextAlmanac_) {
            intake_ = std::make_unique<Intake>(identity_, *hello_, *polaris_, *almanac_, *access_, notifier());
        }
        if (almanacReady_ && clock) {
            ASTRA_PROFILE_BEGIN(profileLock520, "common.runtime.advance_almanac.wait.lock");
            const std::lock_guard lock(incomingMutex_); // Admit peer Star streams only after the initial baseline is complete.
            ASTRA_PROFILE_END(profileLock520);
            accepting_ = true;
        }
    }

    /// Public listener exposes business services only, with separate TLS/message budgets and no Orbit, Pulse, or Polaris writes.
    void openComet() {

        ASTRA_PROFILE_SCOPE("common.runtime.open_comet");

        auto credentials = config_.tls ? Identity::external(config_.cometIdentity) : Result<std::shared_ptr<grpc::ServerCredentials>>(grpc::InsecureServerCredentials());
        if (!credentials) {
            throw std::runtime_error("Cannot prepare independent Comet transport");
        }
        grpc::ServerBuilder builder;
        builder.SetMaxReceiveMessageSize(8 * 1024 * 1024);
        builder.SetMaxSendMessageSize(8 * 1024 * 1024);
        builder.AddChannelArgument("grpc.so_reuseport", 0);
        builder.AddChannelArgument("grpc.server_handshake_timeout_ms", 5000);
        builder.AddChannelArgument(GRPC_ARG_HTTP2_MIN_RECV_PING_INTERVAL_WITHOUT_DATA_MS, 60000);
        builder.AddChannelArgument("grpc.keepalive_time_ms", 60000);
        builder.AddChannelArgument("grpc.keepalive_timeout_ms", 20000);
        builder.AddChannelArgument("grpc.keepalive_permit_without_calls", 0);
        grpc::ResourceQuota quota; // Receive/decoding and transport limits are separate from Readout's logical retention budget.
        quota.Resize(64 * 1024 * 1024);
        builder.SetResourceQuota(quota);
        builder.RegisterService(gateway_.get());
        builder.RegisterService(readout_.get());
        builder.RegisterService(ephemerisService_.get());
        builder.RegisterService(catalogService_.get());
        int port{}; // Log the actual public port without changing internal advertise.
        builder.AddListeningPort(config_.comet->text(), *credentials, &port);
        public_ = builder.BuildAndStart();
        if (!public_ || port <= 0) {
            throw std::runtime_error("Cannot bind independent Comet listener");
        }
        if (auto* health = public_->GetHealthCheckService()) {
            health->SetServingStatus(false);
            for (const auto name : {"proto.comet.v1.Gateway", "proto.comet.v1.Almanac", "proto.comet.v1.Catalog", "proto.comet.v1.Ephemeris"}) {
                health->SetServingStatus(name, false);
            }
        }
        config_.comet->port = static_cast<std::uint16_t>(port);
        logger_.write("comet_listening", "{\"endpoint\":" + jsonString(config_.comet->text()) + "}");
    }

    /// Dial budget spans rounds; start at most one stream per round to avoid startup bursts.
    void dial(Steady::time_point now) {

        ASTRA_PROFILE_SCOPE("common.runtime.dial");

        if (hello_ && (config_.role != Member::Role::Star || almanacReady_) && now >= nextDial_) {

            const auto pending = std::count_if(sessions_.begin(), sessions_.end(), [](const auto& session) { return session->direction() == Policy::Direction::Outbound && !session->installed(); });

            if (static_cast<std::size_t>(pending) < config_.maxDials) {

                if (auto target = policy_->due(now)) {

                    sessions_.push_back(connectSession(config_, *identity_, nextGeneration(), hello_, std::move(*target), notifier()));
                    // Throttle dial starts to at most one per 250 ms.
                    nextDial_ = now + Milliseconds(250);
                }
            }
        }
    }

    /// Sole protocol/role advancement loop coordinates Session reclamation, admission, dialing, and diagnostics.
    void step() {

        ASTRA_PROFILE_SCOPE("common.runtime.step");

        // Shared monotonic timestamp for this round's Session deadlines, backoff, and history retention.
        const auto now = Steady::now();
        collect();
        pumpSessions(now);
        advanceAdmission(now);
        if (fatal_) {
            return;
        }
        // One business-time reading per round; uninitialized time cannot guess finite deadlines, while holdover retains local advancement and leases.
        const auto time = synchronizedClock_.now();
        advanceAlmanac(now, time.has_value());
        if (readout_) {
            readout_->pump(now);
        }
        if (catalogService_) {
            catalogService_->pump(now);
        }
        if (ephemerisService_) {
            ephemerisService_->pump(now); // The same control loop advances source deadlines and active Watches.
        }
        ready(now, time.has_value()); // Open Comet only after complete initial sources or explicit bounded degradation.
        dial(now);                    // Start peers after admission, Clock, and initial Almanac complete.

        // synchronized reports reference quality separately from local time availability; holdover does not revoke registration or renewal eligibility.
        const bool synchronized = time && time->synchronized;
        if (metrics_ && now >= nextMetrics_) {
            const auto state = policy_->status(); // Bounded read-only topology counts without business Key/Scope traversal.
            static_cast<void>(metrics_->publish({id_, businessReady_, almanacReady_, time && time->ready, synchronized, time ? time->uncertaintyNanoseconds : 0, state.members, state.inbound + state.outbound, recovery_.used}));
            nextMetrics_ = now + std::chrono::seconds(1); // HTTP requests neither resample nor contend on business locks.
        }
        if (config_.role == Member::Role::Star && synchronized != reportedSynchronized_) {
            reportedSynchronized_ = synchronized;
            logger_.write(synchronized ? "clock_synchronized" : time ? "clock_holdover"
                                                                     : "clock_unavailable");
        }

        if (config_.statusInterval.count() != 0 && now >= nextStatus_) {
            logger_.status(policy_->status(), id_);
            if (config_.role == Member::Role::Star) {
                logger_.write("clock_status", time ? std::string("{\"ready\":") + (time->ready ? "true" : "false") + ",\"synchronized\":" + (synchronized ? "true" : "false") + ",\"nanoseconds\":" + std::to_string(time->time.time_since_epoch().count()) + ",\"uncertainty_ns\":" + std::to_string(time->uncertaintyNanoseconds) + ",\"rtt_ns\":" + std::to_string(time->rttNanoseconds) + "}" : "{\"ready\":false,\"synchronized\":false}");
            }
            nextStatus_ = now + config_.statusInterval;
        }
    }

    /// Stops admission, cancels owned RPCs, and advances final completion under one deadline before server shutdown.
    /// If draining exceeds the deadline, emit a fixed event and _Exit(1), never destroy objects still borrowed by gRPC.
    void shutdown() {

        // Shared shutdown deadline; later phases consume remaining budget only.
        const auto deadline = Steady::now() + config_.shutdownTimeout;
        if (server_) {
            if (auto* health = server_->GetHealthCheckService()) {
                health->SetServingStatus(false);
            }
        }
        if (public_) {
            if (auto* health = public_->GetHealthCheckService()) {
                health->SetServingStatus(false);
            }
        }
        metrics_.reset(); // Stop metrics worker so a closing node cannot keep reporting prior readiness.
        if (gateway_) {
            gateway_->stop();
        }
        if (readout_) {
            readout_->stop();
        }
        if (catalogService_) {
            catalogService_->stop();
        }
        if (ephemerisService_) {
            ephemerisService_->stop();
        }
        if (pulse_) {
            pulse_->stop();
        }
        {
            // Coordinates handler queue/admission state with the control loop, without network waits.
            std::lock_guard lock(incomingMutex_);
            accepting_ = false;
        }
        if (admission_) {
            admission_->cancel();
        }
        if (intake_) {
            intake_->cancel();
        }
        collect();

        for (const auto& session : sessions_) {
            session->cancel();
        }

        // Continue Finish/RemoveHold and OnDone before joining or destroying callback-borrowed objects.

        while (!sessions_.empty() || (admission_ && admission_->pending()) || intake_ || (readout_ && !readout_->empty()) || (ephemerisService_ && !ephemerisService_->empty()) || (catalogService_ && !catalogService_->empty())) {
            // Captured wake sequence; sleep only while unchanged to avoid a check-to-wait lost event.
            const auto observed = wake_->observe();
            pumpSessions(Steady::now());
            if (readout_) {
                readout_->pump(Steady::now());
            }
            if (catalogService_) {
                catalogService_->pump(Steady::now());
            }
            if (ephemerisService_) {
                ephemerisService_->pump(Steady::now());
            }
            if (admission_) {
                static_cast<void>(admission_->poll());
            }
            if (intake_ && intake_->done()) {
                intake_.reset();
            }
            if (Steady::now() >= deadline) {

                logger_.write("shutdown_timeout");
                std::_Exit(1);
            }
            wake_->wait(observed);
        }

        if (public_) {
            const auto remaining = std::chrono::duration_cast<std::chrono::nanoseconds>(std::max(deadline - Steady::now(), Steady::duration::zero())).count();
            public_->Shutdown(gpr_time_add(gpr_now(GPR_CLOCK_MONOTONIC), gpr_time_from_nanos(remaining, GPR_TIMESPAN)));
            public_->Wait();
            public_.reset();
        }
        if (server_) {
            const auto remaining = std::chrono::duration_cast<std::chrono::nanoseconds>(std::max(deadline - Steady::now(), Steady::duration::zero())).count();
            server_->Shutdown(gpr_time_add(gpr_now(GPR_CLOCK_MONOTONIC), gpr_time_from_nanos(remaining, GPR_TIMESPAN)));
            server_->Wait();
            server_.reset();
        }
        admission_.reset();
        pulse_.reset();
        logger_.write("stopped");
    }

    /// Owned node configuration.
    Config config_;
    /// Shared node certificate and admission material.
    std::shared_ptr<Identity> identity_;
    /// Local ID fixed by first Pulsar registration.
    Id id_;
    /// Role topology policy.
    std::unique_ptr<Policy> policy_;
    /// Structured process logger.
    Logger logger_;
    /// Independent asynchronous-event wake source.
    std::shared_ptr<Wakeup> wake_ = std::make_shared<Wakeup>();

    /// Recovery workspace budget outlives all Session collaborators and bounds cross-stream extra storage.
    Exchange::Budget recovery_;
    /// Current trusted identity per deployment; omissions/disconnection never erase it, and maxMembers bounds capacity.
    std::map<Principal, Member> sources_;
    /// Initial source-wait deadline after Almanac and Clock readiness.
    std::optional<Steady::time_point> recoveryDeadline_;
    /// Once opened, local business capability survives later source outages.
    bool businessReady_{};
    /// Optional independent metrics worker shares fixed-size immutable snapshots only.
    std::unique_ptr<Metrics> metrics_;
    /// Next monotonic metrics-publication time; initially eligible immediately.
    Steady::time_point nextMetrics_{};

    /// Handlers write incoming_/inbound_; after collect, only control loop owns sessions_. Installed hello_ is immutable.
    /// Protects incoming_ and accepting_ across threads.
    std::mutex incomingMutex_;
    /// Inbound admission gate; initially false.
    bool accepting_{};
    /// Accepted and unfinished inbound Session count.
    std::size_t inbound_{};
    /// New-Session staging queue populated by gRPC workers.
    std::vector<std::shared_ptr<Session>> incoming_;
    /// Main Session collection, advanced only by the control loop.
    std::vector<std::shared_ptr<Session>> sessions_;
    /// Shared immutable handshake Hello after admission.
    std::shared_ptr<const proto::astra::v1::Hello> hello_;
    /// Atomic process-wide monotonically allocated Session generation.
    std::atomic_uint64_t nextGeneration_{1};
    /// Owned Pulsar admission coordinator.
    std::unique_ptr<Admission> admission_;
    /// Clock precedes state/sampler borrowers in declaration order and outlives their destruction.
    Clock synchronizedClock_;
    /// Native registration state for own source and public projection, without a generic Store placeholder.
    /// Own Catalog content versions, watermarks, and finite TTLs.
    std::unique_ptr<Catalog::State> catalog_;
    /// Own Ephemeris domain state until all dependent services and feeds have stopped.
    std::unique_ptr<Ephemeris::State> ephemeris_;
    /// Native Almanac precedes receive streams; retain complete baseline until streams fully stop.
    std::unique_ptr<Library> almanac_;
    /// Business Session index committed with internal credentials; outlives Intake and later public RPCs.
    std::unique_ptr<Access> access_;
    /// Public services release before Library/Access; actual Server drains before destroying borrowed state.
    std::unique_ptr<Gateway> gateway_;
    /// Own the Almanac watch pump assembled for this runtime.
    std::unique_ptr<Readout> readout_;
    /// Native writes and active Watches share this public service; release after Server drains.
    /// Public single-Key writes and dynamic-content Watch.
    std::unique_ptr<Catalog::Service> catalogService_;
    /// Own the Ephemeris RPC adapter borrowing the domain state and gateway.
    std::unique_ptr<Ephemeris::Service> ephemerisService_;
    /// Independent business listener; internal RPCs are never registered here.
    std::unique_ptr<grpc::Server> public_;
    /// Current synchronization stream includes closing objects; return its sole slot only after OnDone.
    std::unique_ptr<Intake> intake_;
    /// Latest verified Polaris deployment; omissions and transient outages do not erase replacement history.
    std::optional<Member> polaris_;
    /// Ambiguous directory pauses installation, initially false; network reachability never elects authority.
    bool polarisConflict_{};
    /// Initial complete Almanac remains installed through disconnection without reverting all business state to uninitialized.
    bool almanacReady_{};
    /// Synchronization failures and next reconnect time, initially zero; complete readiness resets failures.
    std::uint32_t almanacFailures_{};
    /// Next permitted stream-open deadline; installed business version is unchanged.
    Steady::time_point nextAlmanac_{};
    /// Owns independent sampling thread, initially empty; created after admission supplies Pulse and drained on closure.
    std::unique_ptr<Sampler> pulse_;
    /// Current sampling endpoint and reported quality state, control-thread-only.
    std::string pulseEndpoint_;
    /// Last logged synchronization quality, initially false; log transitions only, independently of renewal eligibility.
    bool reportedSynchronized_{};

    /// Release Server and Admission after shutdown drains every OnDone; member destruction order is not RPC cancellation.
    /// Owned gRPC listener.
    std::unique_ptr<grpc::Server> server_;
    /// Fatal runtime failure flag.
    bool fatal_{};
    /// Current candidate refresh round.
    std::uint32_t candidateRound_{};
    /// Consecutive Pulsar failures for backoff.
    std::uint32_t registrationFailures_{};
    /// Next permitted Pulsar attempt time.
    Steady::time_point nextRegistration_{};
    /// Next permitted outgoing dial start.
    Steady::time_point nextDial_{};
    /// Next periodic connection-status output time.
    Steady::time_point nextStatus_{};
};
} // namespace

/// Shared Star/Planet process entry parses role-specific configuration and owns Runtime; returns 0 normally, 2 for input errors, 1 for runtime failure.
int runNode(int argc, char** argv, Member::Role role, PolicyFactory factory) {

    try {
        // Help/version requests load no identity or network; string_view arguments borrow argv for this call only.
        if (argc == 2 && (std::string_view(argv[1]) == "--help" || std::string_view(argv[1]) == "-h")) {
            std::cout << Config::help(role);
            return 0;
        }
        if (argc == 2 && std::string_view(argv[1]) == "--version") {

            std::cout << (role == Member::Role::Star ? "star" : "planet") << " 0.1.0 (C++26, gRPC v1)\n";
            return 0;
        }

        std::vector<std::string_view> arguments;
        for (int i = 1; i < argc; ++i) {
            arguments.emplace_back(argv[i]);
        }

        auto config = Config::parse(arguments, role);
        if (!config) {
            std::cerr << config.error().message << '\n';
            return 2;
        }

        // Validate identity after configuration; Pulsar issues process ID and reconnects reuse admission.

        auto identity = Identity::load(config->identity, config->advertise);
        if (!identity) {
            std::cerr << identity.error().message << '\n';
            return 1;
        }

        Signals signals;

        Runtime runtime(*config, *identity, factory(*config));

        return runtime.run(signals);
    } catch (const std::exception&) {
        // Catch fatal C++ exceptions at the process boundary without exposing their arbitrary text.
        std::cerr << "Internal service failure\n";
        return 1;
    }
}
} // namespace astra
