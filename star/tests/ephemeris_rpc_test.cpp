// Verify Ephemeris public RPC behavior and session-bound publication lifetimes.
#include "catalog_edition.hpp"
#include "check.hpp"
#include "ephemeris_edition.hpp"
#include "ephemeris_service.hpp"
#include "identity.hpp"

#include <grpcpp/create_channel.h>
#include <grpcpp/server_builder.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <concepts>
#include <condition_variable>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <map>
#include <new>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <tuple>
#include <vector>

namespace {
using namespace std::chrono_literals;
using astra::Clock;
using astra::Ephemeris;

/// Real TLS/gRPC/native source/projection/wheel, with a verified Access fixture identity. Gateway cases cover long-lived login streams.
class Fixture {
public:
    /// Select a failure only in this fixture's explicitly controlled clock callback.
    enum class Fault {
        /// Return the configured reading.
        None,
        /// Fail before state preparation with allocation exhaustion.
        Allocation,
        /// Fail before state preparation with an unexpected callback exception.
        Exception
    };

    /// Pause the pump before arming a fault so only the requested unary consumes it.
    std::atomic<Fault> fault{Fault::None};
    /// May pause the sole pump while real commit notifications still reach the collector.
    std::mutex control;
    /// Control-thread wait synchronization, outside business locks.
    std::mutex sleep;
    /// Wake fixture waiters when the observed RPC or state transition completes.
    std::condition_variable_any changed;
    /// Deterministic Unix nanoseconds, read-only to RPC workers.
    std::atomic<std::int64_t> now{1'000'000'000};
    /// Initial local-time readiness; synchronized remains false.
    std::atomic_bool ready{true};
    /// Real admission/revocation index, not a boolean authentication stub.
    astra::Access access;
    /// Fixed current instance.
    astra::Gateway gateway{access, "star-test"};
    /// Real State, outliving Service.
    Ephemeris::State state;
    /// Exercise the production unary admission slots and exception boundary.
    Ephemeris::Service service;
    /// Fixture identity, revoked on destruction.
    std::shared_ptr<astra::Access::Session> session;
    /// Private loopback listener, explicitly drained.
    std::unique_ptr<grpc::Server> server;
    /// Actual TLS channel.
    std::shared_ptr<grpc::Channel> channel;
    /// Actual generated Stub.
    std::unique_ptr<proto::comet::v1::Ephemeris::Stub> stub;
    /// One fixture driver per service, shared by Watches rather than per connection.
    std::jthread worker;
    /// Explicit teardown and destruction share one owner.
    bool stopped{};

    /// Only time is injected; authorization/state/order use production implementations without expiration sleeps.
    explicit Fixture(bool history = true, std::ptrdiff_t maximum = 128, Ephemeris::State::Limits limits = {}) : state([this] {
        switch (fault.load()) {
        case Fault::Allocation:
            throw std::bad_alloc();
        case Fault::Exception:
            throw std::runtime_error("Fixture clock failure");
        case Fault::None:
            break;
        }
        return std::optional(Clock::Reading{.time = Clock::Time(std::chrono::nanoseconds(now.load())), .ready = ready.load(), .synchronized = false}); }, [history, limits]() mutable { if (!history) { limits.history = 0; limits.source.history = 0; } return limits; }()), service(state, gateway, maximum) {

        astra::Access::Draft accounts;
        CHECK(accounts.set("application", {1, 2, 3}));
        CHECK(access.reset(std::move(accounts), [] { return std::expected<bool, astra::Almanac::Error>(true); }));
        const std::array<std::uint8_t, 3> secret{1, 2, 3};
        auto opened = access.open("application", secret);
        CHECK(opened);
        session = std::move(*opened);
        const auto identity = astra::Identity::load(std::filesystem::path(ASTRA_FIXTURES) / "star-a", *astra::Endpoint::parse("127.0.0.1:7443"));
        CHECK(identity);
        grpc::ServerBuilder builder;
        builder.SetMaxReceiveMessageSize(4 * 1024 * 1024);
        builder.RegisterService(&gateway);
        builder.RegisterService(&service);
        int port{};
        builder.AddListeningPort("127.0.0.1:0", (*identity)->serverCredentials(), &port);
        server = builder.BuildAndStart();
        CHECK(server && port > 0);
        try {
            channel = grpc::CreateChannel("127.0.0.1:" + std::to_string(port), (*identity)->channelCredentials());
            stub = proto::comet::v1::Ephemeris::NewStub(channel);
            gateway.ready();
            worker = std::jthread([this](std::stop_token stop) {
                while (!stop.stop_requested()) {
                    {
                        const std::lock_guard lock(control);
                        service.pump(std::chrono::steady_clock::now());
                    }
                    std::unique_lock lock(sleep);
                    changed.wait_for(lock, stop, 2ms, [] { return false; });
                }
            });
        } catch (...) {
            server->Shutdown();
            server->Wait();
            throw;
        }
    }

    /// Revoke fixture identity and drain only its owned listener.
    ~Fixture() {
        stop();
    }

    /// Drain native callbacks before releasing the state; repeated stop is harmless.
    void stop() {

        if (stopped) {
            return;
        }
        gateway.stop();
        service.stop();
        access.close(session);
        server->Shutdown(std::chrono::system_clock::now() + 3s);
        server->Wait();
        worker.request_stop();
        changed.notify_all();
        worker.join();
        service.pump(std::chrono::steady_clock::now(), 65536);
        stopped = true;
    }

    /// Fresh deadline/metadata per RPC; token=false exercises anonymous rejection.
    void prepare(grpc::ClientContext& context, bool token = true) const {
        context.set_deadline(std::chrono::system_clock::now() + 3s);
        if (token) {
            context.AddMetadata("comet-session-bin", std::string(session->token()));
        }
    }

    static proto::comet::v1::CreateRequest create(std::uint32_t ttl = 1000) {
        proto::comet::v1::CreateRequest request;
        request.mutable_scope()->set_sector("service");
        request.mutable_scope()->set_spectrum("main");
        request.set_attr("fixed");
        request.set_data("initial");
        request.set_ttl_ms(ttl);
        return request;
    }

    /// Verify actual metadata reason/effect/instance rather than interpreting error text.
    static proto::comet::v1::Failure failure(const grpc::ClientContext& context, proto::comet::v1::Reason reason) {
        const auto found = context.GetServerTrailingMetadata().find("comet-error-bin");
        CHECK(found != context.GetServerTrailingMetadata().end());
        proto::comet::v1::Failure failure;
        CHECK(failure.ParseFromArray(found->second.data(), static_cast<int>(found->second.size())));
        CHECK(failure.reason() == reason && failure.effect() == proto::comet::v1::EFFECT_UNAPPLIED && failure.instance() == "star-test");
        return failure;
    }

    /// Copy every committed field, including payload bytes, for independent before/after comparisons.
    static auto facts(const Ephemeris::State::Source::View& view) {
        std::map<std::tuple<std::string, std::string, std::string>, std::tuple<Ephemeris::Buffer, Ephemeris::Buffer, Clock::Time, std::uint64_t, std::uint64_t, std::uint32_t, std::uint64_t>> result;
        view.each([&result](const astra::Scope& scope, std::string_view uuid, const Ephemeris::Record& record) {
            CHECK(record.attr && record.data);
            CHECK(result.emplace(std::tuple(scope.sector, scope.spectrum, std::string(uuid)), std::tuple(*record.attr, *record.data, record.deadline, record.update, record.renewal, record.ttl, record.generation)).second);
        });
        return result;
    }

    /// Send a real typed unary and discard only its unused success payload.
    template <typename Request>
    grpc::Status invoke(grpc::ClientContext& context, const Request& request) {
        if constexpr (std::same_as<Request, proto::comet::v1::CreateRequest>) {
            proto::comet::v1::CreateReply reply;
            return stub->Create(&context, request, &reply);
        } else if constexpr (std::same_as<Request, proto::comet::v1::UpdateRequest>) {
            proto::comet::v1::UpdateReply reply;
            return stub->Update(&context, request, &reply);
        } else if constexpr (std::same_as<Request, proto::comet::v1::RenewRequest>) {
            proto::comet::v1::RenewReply reply;
            return stub->Renew(&context, request, &reply);
        } else {
            static_assert(std::same_as<Request, proto::comet::v1::RemoveRequest>);
            proto::comet::v1::Empty reply;
            return stub->Remove(&context, request, &reply);
        }
    }

    /// A definitive refusal must preserve every source field, cursor, byte count and retained root.
    template <typename Request>
    void reject(const Request& request, grpc::StatusCode code, proto::comet::v1::Reason reason, bool token = true) {

        const auto before = state.source();
        const auto saved = facts(before);
        grpc::ClientContext context;
        prepare(context, token);
        CHECK(invoke(context, request).error_code() == code);
        const auto detail = failure(context, reason);
        if constexpr (std::same_as<Request, proto::comet::v1::CreateRequest>) {
            if (request.ttl_ms() < 1000 || request.ttl_ms() > 600000) {
                CHECK(detail.ttl_min_ms() == 1000 && detail.ttl_max_ms() == 600000);
            }
        }

        const auto after = state.source();
        CHECK(after.position() == before.position() && after.size() == before.size() && after.bytes() == before.bytes());
        CHECK(facts(after) == saved && facts(before) == saved);
    }

    /// Return the server's actual registration identity and committed body.
    proto::comet::v1::CreateReply accept(const proto::comet::v1::CreateRequest& request) {
        grpc::ClientContext context;
        prepare(context);
        proto::comet::v1::CreateReply reply;
        CHECK(stub->Create(&context, request, &reply).ok());
        CHECK(reply.instance() == "star-test" && Ephemeris::valid(reply.uuid()) && reply.ttl_ms() == request.ttl_ms());
        return reply;
    }
};

/// Cover every malformed creation family before its public/native commit boundary.
void creation() {

    Fixture fixture(true, 1);
    for (int index = 0; index < 21; ++index) {
        auto request = Fixture::create();
        auto code = grpc::StatusCode::INVALID_ARGUMENT;
        auto reason = proto::comet::v1::REASON_INPUT;
        // The UUID is a literal valid binary UUIDv4, independent of the implementation's generator.
        std::string uuid(16, '\0');
        uuid[6] = '\x40';
        uuid[8] = '\x80';
        switch (index) {
        case 0:
            request.mutable_scope()->clear_sector();
            break;
        case 1:
            request.mutable_scope()->clear_spectrum();
            break;
        case 2:
            request.mutable_scope()->set_sector(std::string(129, 's'));
            break;
        case 3:
            request.mutable_scope()->set_spectrum(std::string(129, 's'));
            break;
        case 4:
            request.mutable_scope()->set_sector(std::string("s\0x", 3));
            break;
        case 5:
            request.mutable_scope()->set_spectrum(std::string("s\0x", 3));
            break;
        case 6:
            request.mutable_scope()->set_sector("__internal");
            code = grpc::StatusCode::PERMISSION_DENIED;
            reason = proto::comet::v1::REASON_DENIED;
            break;
        case 7:
        case 8:
            if (index == 7) {
                request.set_attr(std::string(1024 * 1024 + 1, 'a'));
            } else {
                request.set_data(std::string(1024 * 1024 + 1, 'd'));
            }
            code = grpc::StatusCode::RESOURCE_EXHAUSTED;
            reason = proto::comet::v1::REASON_LIMIT;
            break;
        case 9:
            request.set_ttl_ms(0);
            break;
        case 10:
            request.set_ttl_ms(999);
            break;
        case 11:
            request.set_ttl_ms(600001);
            break;
        case 12:
            request.set_uuid(uuid);
            break;
        case 13:
            request.set_capability(std::string(32, 'c'));
            break;
        case 14:
            request.set_order(1);
            break;
        case 15:
            request.set_generation(2);
            break;
        case 16:
            request.set_generation(1);
            request.set_capability(std::string(32, 'c'));
            break;
        case 17:
            request.set_generation(1);
            request.set_order(1);
            break;
        case 18:
            request.set_generation(1);
            request.set_uuid("invalid");
            request.set_capability(std::string(32, 'c'));
            break;
        case 19:
            request.set_generation(1);
            request.set_uuid(uuid);
            request.set_capability(std::string(31, 'c'));
            break;
        case 20:
            request.set_generation(1);
            request.set_uuid(uuid);
            request.set_capability(std::string(32, 'c'));
            break;
        }
        fixture.reject(request, code, reason);
        CHECK(fixture.state.source().position() == 0 && fixture.state.source().size() == 0);
        std::cout << "ASTRA-EPHEMERIS-BOUNDARY create " << index << '\n';
    }
}

/// Use the same denied scope/identity families on each separately generated mutation interface.
template <typename Request>
void mutations(Fixture& fixture, const Request& original, std::string_view group, int count) {

    for (int index = 0; index < count; ++index) {
        auto request = original;
        auto code = grpc::StatusCode::INVALID_ARGUMENT;
        auto reason = proto::comet::v1::REASON_INPUT;
        bool token = true;
        switch (index) {
        case 0:
            request.mutable_scope()->clear_sector();
            break;
        case 1:
            request.mutable_scope()->clear_spectrum();
            break;
        case 2:
            request.mutable_scope()->set_sector("__internal");
            code = grpc::StatusCode::PERMISSION_DENIED;
            reason = proto::comet::v1::REASON_DENIED;
            break;
        case 3:
            request.clear_uuid();
            break;
        case 4:
            request.set_uuid(std::string(16, '\0'));
            break;
        case 5:
        case 6:
            request.set_instance(index == 5 ? "" : "other-star");
            code = grpc::StatusCode::FAILED_PRECONDITION;
            reason = proto::comet::v1::REASON_INSTANCE;
            break;
        case 7:
            token = false;
            code = grpc::StatusCode::UNAUTHENTICATED;
            reason = proto::comet::v1::REASON_SESSION;
            break;
        case 8:
            request.set_generation(1);
            code = grpc::StatusCode::FAILED_PRECONDITION;
            reason = proto::comet::v1::REASON_OBSOLETE;
            break;
        case 9: {
            auto uuid = original.uuid();
            uuid[0] = static_cast<char>(static_cast<unsigned char>(uuid[0]) ^ 1U);
            request.set_uuid(uuid);
            code = grpc::StatusCode::NOT_FOUND;
            reason = proto::comet::v1::REASON_ENDED;
            break;
        }
        case 10:
            if constexpr (!std::same_as<Request, proto::comet::v1::RemoveRequest>) {
                request.set_order(0);
            }
            break;
        case 11:
            if constexpr (std::same_as<Request, proto::comet::v1::UpdateRequest>) {
                request.set_data(std::string(1024 * 1024 + 1, 'x'));
            }
            code = grpc::StatusCode::RESOURCE_EXHAUSTED;
            reason = proto::comet::v1::REASON_LIMIT;
            break;
        }
        fixture.reject(request, code, reason, token);
        std::cout << "ASTRA-EPHEMERIS-BOUNDARY " << group << ' ' << index << '\n';
    }
}

/// Validate refused mutations against one unchanged native registration and retained source root.
void boundaries() {

    Fixture fixture(true, 1);
    const auto request = Fixture::create();
    const auto created = fixture.accept(request);
    proto::comet::v1::UpdateRequest update;
    *update.mutable_scope() = request.scope();
    update.set_instance(created.instance());
    update.set_uuid(created.uuid());
    update.set_order(1);
    update.set_data("changed");
    mutations(fixture, update, "update", 12);

    proto::comet::v1::RenewRequest renew;
    *renew.mutable_scope() = request.scope();
    renew.set_instance(created.instance());
    renew.set_uuid(created.uuid());
    renew.set_order(1);
    mutations(fixture, renew, "renew", 11);

    proto::comet::v1::RemoveRequest remove;
    *remove.mutable_scope() = request.scope();
    remove.set_instance(created.instance());
    remove.set_uuid(created.uuid());
    mutations(fixture, remove, "remove", 10);
}

/// Distinguish conflicting content, stale generations, independent renewal order and capability refusal.
void versions() {

    Fixture fixture(true, 1);
    auto request = Fixture::create();
    request.set_generation(1);
    const auto created = fixture.accept(request);
    CHECK(created.generation() == 1 && created.capability().size() == 32);
    proto::comet::v1::UpdateRequest update;
    *update.mutable_scope() = request.scope();
    update.set_instance(created.instance());
    update.set_uuid(created.uuid());
    update.set_generation(1);
    update.set_capability(created.capability());
    update.set_order(1);
    update.set_data("committed");
    grpc::ClientContext updating;
    fixture.prepare(updating);
    CHECK(fixture.invoke(updating, update).ok());
    update.set_data("conflicting");
    fixture.reject(update, grpc::StatusCode::FAILED_PRECONDITION, proto::comet::v1::REASON_CONFLICT);
    std::cout << "ASTRA-EPHEMERIS-BOUNDARY versions 0\n";
    update.set_generation(2);
    fixture.reject(update, grpc::StatusCode::FAILED_PRECONDITION, proto::comet::v1::REASON_OBSOLETE);
    std::cout << "ASTRA-EPHEMERIS-BOUNDARY versions 1\n";

    proto::comet::v1::RenewRequest renew;
    *renew.mutable_scope() = request.scope();
    renew.set_instance(created.instance());
    renew.set_uuid(created.uuid());
    renew.set_generation(1);
    renew.set_capability(created.capability());
    renew.set_order(2);
    grpc::ClientContext renewing;
    fixture.prepare(renewing);
    CHECK(fixture.invoke(renewing, renew).ok());
    renew.set_order(1);
    fixture.reject(renew, grpc::StatusCode::FAILED_PRECONDITION, proto::comet::v1::REASON_OBSOLETE);
    std::cout << "ASTRA-EPHEMERIS-BOUNDARY versions 2\n";

    proto::comet::v1::RemoveRequest remove;
    *remove.mutable_scope() = request.scope();
    remove.set_instance(created.instance());
    remove.set_uuid(created.uuid());
    remove.set_generation(1);
    auto capability = created.capability();
    capability[0] = static_cast<char>(static_cast<unsigned char>(capability[0]) ^ 1U);
    remove.set_capability(capability);
    fixture.reject(remove, grpc::StatusCode::FAILED_PRECONDITION, proto::comet::v1::REASON_OBSOLETE);
    std::cout << "ASTRA-EPHEMERIS-BOUNDARY versions 3\n";

    request.set_uuid(created.uuid());
    request.set_capability(created.capability());
    request.set_generation(2);
    CHECK(fixture.accept(request).generation() == 2);
    request.set_generation(1);
    fixture.reject(request, grpc::StatusCode::FAILED_PRECONDITION, proto::comet::v1::REASON_OBSOLETE);
    std::cout << "ASTRA-EPHEMERIS-BOUNDARY versions 4\n";
}

/// Exact payload/TTL edges, native quotas and deadline overflow retain distinct public semantics.
void limits() {

    {
        Fixture fixture;
        auto request = Fixture::create(600000);
        request.set_attr(std::string(1024 * 1024, 'a'));
        request.set_data(std::string(1024 * 1024, 'd'));
        const auto created = fixture.accept(request);
        CHECK(created.data() == request.data());
        fixture.state.source().each([&request](const astra::Scope&, std::string_view, const Ephemeris::Record& record) {
            CHECK(record.attr->size() == request.attr().size() && record.data->size() == request.data().size());
            CHECK(std::all_of(record.attr->begin(), record.attr->end(), [](auto byte) { return byte == 'a'; }));
            CHECK(std::all_of(record.data->begin(), record.data->end(), [](auto byte) { return byte == 'd'; }));
        });
        std::cout << "ASTRA-EPHEMERIS-BOUNDARY limits 0\n";
    }
    {
        Fixture fixture;
        auto request = Fixture::create(1000);
        request.clear_attr();
        request.clear_data();
        CHECK(fixture.accept(request).data().empty());
        CHECK(fixture.state.source().size() == 1);
        std::cout << "ASTRA-EPHEMERIS-BOUNDARY limits 1\n";
    }
    {
        Ephemeris::State::Limits limits;
        limits.scopes = 0;
        Fixture fixture(true, 1, limits);
        fixture.reject(Fixture::create(), grpc::StatusCode::RESOURCE_EXHAUSTED, proto::comet::v1::REASON_LIMIT);
        std::cout << "ASTRA-EPHEMERIS-BOUNDARY limits 2\n";
    }
    {
        Ephemeris::State::Limits limits;
        limits.source.records = 1;
        Fixture fixture(true, 1, limits);
        const auto request = Fixture::create();
        const auto created = fixture.accept(request);
        fixture.reject(request, grpc::StatusCode::RESOURCE_EXHAUSTED, proto::comet::v1::REASON_LIMIT);
        proto::comet::v1::RemoveRequest remove;
        *remove.mutable_scope() = request.scope();
        remove.set_instance(created.instance());
        remove.set_uuid(created.uuid());
        grpc::ClientContext context;
        fixture.prepare(context);
        CHECK(fixture.invoke(context, remove).ok());
        CHECK(fixture.accept(request).uuid() != created.uuid() && fixture.state.source().size() == 1);
        std::cout << "ASTRA-EPHEMERIS-BOUNDARY limits 3\n";
    }
    {
        Fixture fixture;
        const std::lock_guard pause(fixture.control);
        fixture.now = std::numeric_limits<std::int64_t>::max() - 500'000'000;
        fixture.reject(Fixture::create(), grpc::StatusCode::OUT_OF_RANGE, proto::comet::v1::REASON_LIMIT);
        std::cout << "ASTRA-EPHEMERIS-BOUNDARY limits 4\n";
    }
}

/// Exceptions at each public mutation boundary leave frozen facts intact and return the sole admission slot.
void exceptions() {

    const auto facts = &Fixture::facts; // Share only the complete immutable-state representation.
    for (const auto fault : {Fixture::Fault::Allocation, Fixture::Fault::Exception}) {
        for (int operation = 0; operation < 4; ++operation) {
            Fixture fixture(true, 1);
            const auto request = Fixture::create();
            grpc::ClientContext initial;
            fixture.prepare(initial);
            proto::comet::v1::CreateReply created;
            CHECK(fixture.stub->Create(&initial, request, &created).ok());
            CHECK(created.instance() == "star-test" && Ephemeris::valid(created.uuid()));
            const std::lock_guard lock(fixture.control);
            fixture.now = 1'500'000'000;
            const auto before = fixture.state.source();
            const auto saved = facts(before);

            const auto invoke = [&](grpc::ClientContext& context) {
                if (operation == 0) {
                    proto::comet::v1::CreateReply reply;
                    return fixture.stub->Create(&context, request, &reply);
                }
                if (operation == 1) {
                    proto::comet::v1::UpdateRequest update;
                    *update.mutable_scope() = request.scope();
                    update.set_instance(created.instance());
                    update.set_uuid(created.uuid());
                    update.set_order(1);
                    update.set_data("changed");
                    proto::comet::v1::UpdateReply reply;
                    return fixture.stub->Update(&context, update, &reply);
                }
                if (operation == 2) {
                    proto::comet::v1::RenewRequest renew;
                    *renew.mutable_scope() = request.scope();
                    renew.set_instance(created.instance());
                    renew.set_uuid(created.uuid());
                    renew.set_order(1);
                    proto::comet::v1::RenewReply reply;
                    return fixture.stub->Renew(&context, renew, &reply);
                }
                proto::comet::v1::RemoveRequest remove;
                *remove.mutable_scope() = request.scope();
                remove.set_instance(created.instance());
                remove.set_uuid(created.uuid());
                proto::comet::v1::Empty reply;
                return fixture.stub->Remove(&context, remove, &reply);
            };
            grpc::ClientContext failing;
            fixture.prepare(failing);
            fixture.fault = fault;
            const auto status = invoke(failing);
            fixture.fault = Fixture::Fault::None;
            CHECK(status.error_code() == (fault == Fixture::Fault::Allocation ? grpc::StatusCode::RESOURCE_EXHAUSTED : grpc::StatusCode::INTERNAL));
            CHECK(failing.GetServerTrailingMetadata().find("comet-error-bin") == failing.GetServerTrailingMetadata().end());
            const auto after = fixture.state.source();
            CHECK(after.position() == before.position() && after.size() == before.size() && after.bytes() == before.bytes());
            CHECK(facts(after) == saved && facts(before) == saved);

            grpc::ClientContext healthy;
            fixture.prepare(healthy);
            CHECK(invoke(healthy).ok());
            const auto recovered = fixture.state.source();
            CHECK(recovered.position() == before.position() + 1);
            const std::array<std::size_t, 4> sizes{2, 1, 1, 0}; // Create, Update, Renew, Remove.
            CHECK(recovered.size() == sizes[static_cast<std::size_t>(operation)]);
            CHECK(facts(before) == saved && facts(recovered) != saved);
            std::cout << "ASTRA-EPHEMERIS-EXCEPTION " << static_cast<int>(fault) << ' ' << operation << '\n';
        }
    }
}

/// Owns one real Watch; exception cleanup TryCancel/Finish leaves no active fixture stream.
class Watching {
public:
    /// Stable context address spans the stream.
    grpc::ClientContext context;
    /// Final Finish occurs once.
    std::unique_ptr<grpc::ClientReader<proto::comet::v1::EphemerisWatchReply>> stream;
    /// Cache terminal transport completion so cleanup cannot finish the stream twice.
    std::optional<grpc::Status> status;

    /// Recover cursor only within the same instance; empty target selects all, otherwise a canonical UUID.
    Watching(Fixture& fixture, std::string target = {}, std::optional<std::uint64_t> version = {}, std::string instance = "star-test") {
        context.set_deadline(std::chrono::system_clock::now() + 10s);
        context.AddMetadata("comet-session-bin", std::string(fixture.session->token()));
        proto::comet::v1::WatchRequest request;
        request.mutable_scope()->set_sector("service");
        request.mutable_scope()->set_spectrum("main");
        request.set_target(std::move(target));
        request.set_instance(std::move(instance));
        if (version) {
            request.set_version(*version);
        }
        stream = fixture.stub->Watch(&context, request);
    }

    /// End the stream first; shared fixture worker keeps draining server OnDone.
    ~Watching() {
        if (!status) {
            context.TryCancel();
            static_cast<void>(finish());
        }
    }

    /// Observe server termination without first requesting client cancellation.
    const grpc::Status& finish() {
        if (!status) {
            status = stream->Finish();
        }
        return *status;
    }

    /// Fixture content fits one page; incomplete batches cannot count as successful views.
    proto::comet::v1::EphemerisWatchReply next() {
        proto::comet::v1::EphemerisWatchReply reply;
        CHECK(stream->Read(&reply) && reply.complete() && reply.has_version() && reply.instance() == "star-test");
        return reply;
    }
};

/// Reject invalid service limits, then verify the upper admitted limit without starting any stream.
void configuration() {

    Fixture fixture;
    int index = 0;
    for (const auto maximum : {-1, 0, 65537}) {
        bool rejected = false;
        try {
            Ephemeris::Service invalid(fixture.state, fixture.gateway, maximum);
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        CHECK(rejected);
        std::cout << "ASTRA-EPHEMERIS-BOUNDARY configuration " << index++ << '\n';
    }
    Ephemeris::Service valid(fixture.state, fixture.gateway, 65536);
    valid.stop();
    CHECK(valid.empty());
    std::cout << "ASTRA-EPHEMERIS-BOUNDARY configuration 3\n";
}

/// Explicit stop and failed maintenance retire old streams without corrupting retained source facts.
void cleanup() {

    for (int index = 0; index < 2; ++index) {
        Fixture fixture;
        CHECK(fixture.service.empty());
        const auto created = fixture.accept(Fixture::create());
        Watching watch(fixture);
        const auto initial = watch.next();
        CHECK(initial.mode() == proto::comet::v1::MODE_RESET && initial.changes_size() == 1 && initial.version() == 1);
        CHECK(initial.changes(0).uuid() == created.uuid() && !fixture.service.empty());
        const auto before = fixture.state.source();
        const auto saved = Fixture::facts(before);
        {
            const std::lock_guard pause(fixture.control);
            if (index == 0) {
                fixture.service.stop();
            } else {
                fixture.fault = Fixture::Fault::Exception;
            }
            fixture.service.pump(std::chrono::steady_clock::now());
            fixture.fault = Fixture::Fault::None;
        }
        proto::comet::v1::EphemerisWatchReply reply;
        CHECK(!watch.stream->Read(&reply));
        CHECK(watch.finish().error_code() == (index == 0 ? grpc::StatusCode::CANCELLED : grpc::StatusCode::RESOURCE_EXHAUSTED));
        static_cast<void>(Fixture::failure(watch.context, index == 0 ? proto::comet::v1::REASON_SESSION : proto::comet::v1::REASON_BUSY));
        CHECK(Fixture::facts(fixture.state.source()) == saved && Fixture::facts(before) == saved);
        if (index == 1) {
            Watching recovered(fixture);
            const auto reset = recovered.next();
            CHECK(reset.mode() == proto::comet::v1::MODE_RESET && reset.version() == 1 && reset.changes_size() == 1);
            CHECK(reset.changes(0).uuid() == created.uuid() && reset.changes(0).has_record());
            CHECK(reset.changes(0).record().attr() == "fixed" && reset.changes(0).record().data() == "initial");
        }
        fixture.stop();
        CHECK(fixture.service.empty());
        fixture.stop();
        CHECK(fixture.service.empty());
        std::cout << "ASTRA-EPHEMERIS-BOUNDARY cleanup " << index << '\n';
    }
}

/// Active streams retain suffixes with zero history. Create+Data compaction retains Attr; data-only requires an existing baseline.
void streaming() {

    Fixture fixture(false);
    Watching watch(fixture);
    const auto empty = watch.next();
    CHECK(empty.mode() == proto::comet::v1::MODE_RESET && empty.changes_size() == 0 && empty.version() == 0);
    const astra::Scope scope{"service", "main"};
    const auto attr = std::make_shared<const Ephemeris::Buffer>(8, 1);
    const auto first = std::make_shared<const Ephemeris::Buffer>(8, 2);
    const auto last = std::make_shared<const Ephemeris::Buffer>(8, 3);
    std::string uuid;
    {
        const std::lock_guard pause(fixture.control); // Force Create+Update into one unsent batch.
        auto created = fixture.state.create(scope, attr, first, 1000);
        CHECK(created);
        uuid = created->uuid;
        CHECK(fixture.state.update(scope, uuid, last, 1));
        CHECK(!fixture.state.changes(scope, 0)); // History is truly disabled; feed cannot repair gaps by later replay.
    }
    const auto introduced = watch.next();
    CHECK(introduced.mode() == proto::comet::v1::MODE_APPLY && introduced.version() == 2 && introduced.changes_size() == 1);
    CHECK(introduced.changes(0).uuid() == uuid && introduced.changes(0).has_record());
    CHECK(introduced.changes(0).record().attr() == std::string(8, 1) && introduced.changes(0).record().data() == std::string(8, 3));

    CHECK(fixture.state.renew(scope, uuid, 1));
    CHECK(fixture.state.update(scope, uuid, first, 2));
    const auto updated = watch.next();
    CHECK(updated.version() == 3 && updated.changes_size() == 1 && updated.changes(0).has_data());
    CHECK(updated.changes(0).data() == std::string(8, 2));
    Watching switched(fixture, uuid, 1000, "old-star");
    const auto reset = switched.next();
    CHECK(reset.mode() == proto::comet::v1::MODE_RESET && reset.version() == 3 && reset.changes(0).has_record());
    CHECK(fixture.state.remove(scope, uuid));
    const auto erased = watch.next();
    CHECK(erased.version() == 4 && erased.changes_size() == 1 && erased.changes(0).has_erase());
    const auto precise = switched.next();
    CHECK(precise.version() == 4 && precise.changes(0).has_erase());
}

/// Same-instance retained history recovers with apply; cross-instance reset always returns complete Records.
void resume() {

    Fixture fixture;
    const astra::Scope scope{"service", "main"};
    const auto attr = std::make_shared<const Ephemeris::Buffer>(4, 1);
    const auto data = std::make_shared<const Ephemeris::Buffer>(4, 2);
    const auto created = fixture.state.create(scope, attr, data, 1000);
    CHECK(created && fixture.state.update(scope, created->uuid, std::make_shared<const Ephemeris::Buffer>(4, 3), 1));
    Watching all(fixture, {}, 0);
    const auto combined = all.next();
    CHECK(combined.mode() == proto::comet::v1::MODE_APPLY && combined.version() == 2 && combined.changes(0).has_record());
    Watching known(fixture, created->uuid, 1);
    const auto incremental = known.next();
    CHECK(incremental.mode() == proto::comet::v1::MODE_APPLY && incremental.version() == 2 && incremental.changes(0).has_data());
    fixture.now = 2'000'000'000; // Shared worker advances deadlines without a client request to trigger cleanup.
    CHECK(known.next().changes(0).has_erase());
}

/// Streams may reuse an old prefix but must receive newer appended Data. Cancelling one preserves others' in-flight pages.
void fanout() {

    Fixture fixture(false); // Zero history requires each active stream's suffix and shared frozen batches.
    const astra::Scope scope{"service", "main"};
    const auto attr = std::make_shared<const Ephemeris::Buffer>(8, 1);
    const auto created = fixture.state.create(scope, attr, std::make_shared<const Ephemeris::Buffer>(8, 2), 1000);
    CHECK(created);
    std::array<std::unique_ptr<Watching>, 4> watches; // Three whole-Scope streams and one exact target must not incorrectly share filtered results.
    for (std::size_t index = 0; index < watches.size(); ++index) {
        watches[index] = std::make_unique<Watching>(fixture, index == 3 ? created->uuid : "");
        CHECK(watches[index]->next().version() == 1);
    }
    {
        const std::lock_guard pause(fixture.control);
        for (std::uint64_t order = 1; order <= 20; ++order) {
            CHECK(fixture.state.update(scope, created->uuid, std::make_shared<const Ephemeris::Buffer>(8, static_cast<std::uint8_t>(order)), order));
        }
    }
    const auto first = watches[0]->next();
    CHECK(first.version() == 21 && first.changes(0).data() == std::string(8, 20));
    watches[1].reset(); // Cancelling a stream cannot affect shared pages retained by slow readers.
    {
        const std::lock_guard pause(fixture.control);
        for (std::uint64_t order = 21; order <= 40; ++order) {
            CHECK(fixture.state.update(scope, created->uuid, std::make_shared<const Ephemeris::Buffer>(8, static_cast<std::uint8_t>(order)), order));
        }
    }
    for (const auto index : {0U, 2U, 3U}) {
        std::uint64_t version = index == 0 ? 21 : 1; // Each network stream has its own confirmed position.
        while (version < 41) {
            const auto page = watches[index]->next();
            CHECK(page.version() > version && page.version() <= 41 && page.changes_size() == 1);
            version = page.version();
            const auto& change = page.changes(0);
            CHECK(change.uuid() == created->uuid && change.has_data());
            if (version == 41) {
                CHECK(change.data() == std::string(8, 40));
            }
        }
    }
}

/// Real create/update/renew/replay/remove keep source positions separate from downstream content cursors.
void lifecycle() {

    Fixture fixture;
    auto request = Fixture::create();
    proto::comet::v1::CreateReply created;
    grpc::ClientContext creating;
    fixture.prepare(creating);
    CHECK(fixture.stub->Create(&creating, request, &created).ok());
    CHECK(created.instance() == "star-test" && Ephemeris::valid(created.uuid()) && created.ttl_ms() == 1000);
    CHECK(fixture.state.source().position() == 1);

    proto::comet::v1::UpdateRequest update;
    update.set_instance(created.instance());
    *update.mutable_scope() = request.scope();
    update.set_uuid(created.uuid());
    update.set_order(2);
    update.set_data("latest");
    proto::comet::v1::UpdateReply updated;
    grpc::ClientContext updating;
    fixture.prepare(updating);
    CHECK(fixture.stub->Update(&updating, update, &updated).ok() && updated.order() == 2);
    CHECK(fixture.state.capture({"service", "main"})->version() == 2);
    update.set_order(1);
    grpc::ClientContext obsolete;
    fixture.prepare(obsolete);
    CHECK(fixture.stub->Update(&obsolete, update, &updated).error_code() == grpc::StatusCode::FAILED_PRECONDITION);
    Fixture::failure(obsolete, proto::comet::v1::REASON_OBSOLETE);
    CHECK(fixture.state.source().position() == 2);

    fixture.now = 1'500'000'000;
    proto::comet::v1::RenewRequest renew;
    renew.set_instance(created.instance());
    *renew.mutable_scope() = request.scope();
    renew.set_uuid(created.uuid());
    renew.set_order(1);
    proto::comet::v1::RenewReply renewed;
    grpc::ClientContext renewing;
    fixture.prepare(renewing);
    CHECK(fixture.stub->Renew(&renewing, renew, &renewed).ok() && renewed.order() == 1);
    CHECK(fixture.state.source().position() == 3 && fixture.state.capture({"service", "main"})->version() == 2);
    fixture.now = 1'800'000'000;
    grpc::ClientContext repeating;
    fixture.prepare(repeating);
    CHECK(fixture.stub->Renew(&repeating, renew, &renewed).ok() && fixture.state.source().position() == 3);
    fixture.state.source().each([](const astra::Scope&, const std::string&, const Ephemeris::Record& record) { CHECK(record.deadline == Clock::Time(2500ms)); });

    proto::comet::v1::RemoveRequest remove;
    remove.set_instance(created.instance());
    *remove.mutable_scope() = request.scope();
    remove.set_uuid(created.uuid());
    proto::comet::v1::Empty empty;
    grpc::ClientContext removing;
    fixture.prepare(removing);
    CHECK(fixture.stub->Remove(&removing, remove, &empty).ok());
    CHECK(fixture.state.source().position() == 4 && fixture.state.capture({"service", "main"})->size() == 0);
    grpc::ClientContext ended;
    fixture.prepare(ended);
    CHECK(fixture.stub->Renew(&ended, renew, &renewed).error_code() == grpc::StatusCode::NOT_FOUND);
    Fixture::failure(ended, proto::comet::v1::REASON_ENDED);
}

/// Anonymous/wrong-instance/internal-Scope/TTL/time rejection creates no hidden registration; revoked sessions cannot write again.
void rejection() {

    Fixture fixture;
    auto request = Fixture::create();
    proto::comet::v1::CreateReply reply;
    grpc::ClientContext anonymous;
    fixture.prepare(anonymous, false);
    CHECK(fixture.stub->Create(&anonymous, request, &reply).error_code() == grpc::StatusCode::UNAUTHENTICATED);
    Fixture::failure(anonymous, proto::comet::v1::REASON_SESSION);
    request.set_instance("another-star");
    grpc::ClientContext other;
    fixture.prepare(other);
    CHECK(fixture.stub->Create(&other, request, &reply).error_code() == grpc::StatusCode::FAILED_PRECONDITION);
    Fixture::failure(other, proto::comet::v1::REASON_INSTANCE);
    request.clear_instance();
    request.mutable_scope()->set_sector("__internal");
    grpc::ClientContext internal;
    fixture.prepare(internal);
    CHECK(fixture.stub->Create(&internal, request, &reply).error_code() == grpc::StatusCode::PERMISSION_DENIED);
    Fixture::failure(internal, proto::comet::v1::REASON_DENIED);
    request = Fixture::create(999);
    grpc::ClientContext shortTtl;
    fixture.prepare(shortTtl);
    CHECK(fixture.stub->Create(&shortTtl, request, &reply).error_code() == grpc::StatusCode::INVALID_ARGUMENT);
    const auto limits = Fixture::failure(shortTtl, proto::comet::v1::REASON_INPUT);
    CHECK(limits.ttl_min_ms() == 1000 && limits.ttl_max_ms() == 600000);
    request = Fixture::create();
    fixture.ready = false;
    grpc::ClientContext unready;
    fixture.prepare(unready);
    CHECK(fixture.stub->Create(&unready, request, &reply).error_code() == grpc::StatusCode::UNAVAILABLE);
    Fixture::failure(unready, proto::comet::v1::REASON_CLOCK);
    fixture.ready = true;
    CHECK(fixture.state.source().position() == 0 && fixture.state.source().size() == 0);
    fixture.access.close(fixture.session);
    grpc::ClientContext revoked;
    fixture.prepare(revoked);
    CHECK(fixture.stub->Create(&revoked, request, &reply).error_code() == grpc::StatusCode::UNAUTHENTICATED);
    CHECK(fixture.state.source().position() == 0);
}

/// Real native-history compaction preserves unique items, final values, and Attr baselines without self-move loss.
void editions() {

    const astra::Scope scope{"edition", "main"};
    const auto time = [] { return std::optional(astra::Clock::Reading{.time = astra::Clock::Time(1s), .ready = true}); };
    const auto buffer = [](std::uint8_t value) { return std::make_shared<const Ephemeris::Buffer>(1, value); };

    {
        astra::Catalog::State state(time, {});
        CHECK(state.publish(scope, "a", buffer(1), 1, 1000));
        CHECK(state.publish(scope, "b", buffer(2), 1, 1000));
        CHECK(state.publish(scope, "c", buffer(3), 1, 1000));
        auto initial = state.changes(scope, 0);
        CHECK(initial);
        astra::Catalog::Edition singles(3, std::move(*initial));
        const auto first = singles.next("star-test");
        CHECK(first.complete() && first.changes_size() == 3 && first.changes(0).key() == "a" && first.changes(1).key() == "b" && first.changes(2).key() == "c");

        auto captured = state.capture(scope); // Edition owns version/accounting/old bodies after root transfer.
        auto point = state.find(scope, "a");  // Point construction transfers Record without borrowing Point.
        CHECK(captured && point);
        const auto retained = captured->bytes();
        astra::Catalog::Edition frozen(std::move(*captured));
        astra::Catalog::Edition exact("a", std::move(*point));
        CHECK(state.publish(scope, "a", buffer(7), 2, 1000));
        CHECK(state.publish(scope, "b", buffer(8), 2, 1000));
        const auto snapshot = frozen.next("star-test"); // Later version-five state cannot alter the frozen version-three records.
        const auto single = exact.next("star-test");
        CHECK(snapshot.complete() && snapshot.version() == 3 && snapshot.changes_size() == 3 && frozen.bytes() == retained);
        for (const auto& change : snapshot.changes()) {
            CHECK(change.version() == 1 && change.value() == std::string(1, static_cast<char>(change.key()[0] - 'a' + 1)));
        }
        CHECK(single.complete() && single.version() == 3 && single.changes_size() == 1 && single.changes(0).key() == "a" && single.changes(0).value() == std::string(1, '\1'));

        auto history = state.changes(scope, 0); // Repeated-key groups followed by a unique tail exercise forward in-place compaction.
        CHECK(history);
        astra::Catalog::Edition merged(5, std::move(*history));
        const auto page = merged.next("star-test");
        CHECK(page.complete() && page.version() == 5 && page.changes_size() == 3);
        CHECK(page.changes(0).key() == "a" && page.changes(0).version() == 2 && page.changes(0).value() == std::string(1, '\7'));
        CHECK(page.changes(1).key() == "b" && page.changes(1).version() == 2 && page.changes(1).value() == std::string(1, '\10'));
        CHECK(page.changes(2).key() == "c" && page.changes(2).version() == 1 && page.changes(2).value() == std::string(1, '\3'));
    }

    {
        Ephemeris::State state(time, {});
        const auto one = state.create(scope, buffer(9), buffer(1), 1000);
        const auto two = state.create(scope, buffer(9), buffer(2), 1000);
        const auto three = state.create(scope, buffer(9), buffer(3), 1000);
        CHECK(one && two && three);
        auto captured = state.capture(scope); // Later updates/deletions cannot alter transferred Attr/Data roots.
        auto point = state.find(scope, one->uuid);
        CHECK(captured && point);
        const auto retained = captured->bytes();
        Ephemeris::Edition frozen(std::move(*captured));
        Ephemeris::Edition exact(one->uuid, std::move(*point));
        CHECK(state.update(scope, one->uuid, buffer(4), 1));
        CHECK(state.update(scope, one->uuid, buffer(5), 2));
        CHECK(state.remove(scope, two->uuid));
        CHECK(state.update(scope, three->uuid, buffer(6), 1));

        const auto snapshot = frozen.next("star-test");
        const auto single = exact.next("star-test");
        const std::map<std::string, char> expected{{one->uuid, '\1'}, {two->uuid, '\2'}, {three->uuid, '\3'}}; // No ordering assumption for random UUIDs.
        CHECK(snapshot.complete() && snapshot.version() == 3 && snapshot.changes_size() == 3 && frozen.bytes() == retained);
        for (const auto& change : snapshot.changes()) {
            CHECK(change.has_record() && change.record().attr() == std::string(1, '\11') && change.record().data() == std::string(1, expected.at(change.uuid())));
        }
        CHECK(single.complete() && single.version() == 3 && single.changes_size() == 1 && single.changes(0).uuid() == one->uuid && single.changes(0).record().data() == std::string(1, '\1'));

        for (const auto since : {0U, 3U}) {
            auto history = state.changes(scope, since); // Zero cursor retains Attr; an existing baseline permits data-only.
            CHECK(history);
            Ephemeris::Edition merged(7, std::move(*history));
            const auto page = merged.next("star-test");
            CHECK(page.complete() && page.version() == 7 && page.changes_size() == 3);
            std::map<std::string, std::string> records;
            for (const auto& change : page.changes()) {
                if (change.uuid() == two->uuid) {
                    CHECK(change.has_erase());
                } else {
                    CHECK(since == 0 ? change.has_record() : change.has_data());
                    if (since == 0) {
                        CHECK(change.record().attr() == std::string(1, '\11'));
                    }
                    CHECK(records.emplace(change.uuid(), since == 0 ? change.record().data() : change.data()).second);
                }
            }
            CHECK(records.size() == 2 && records.at(one->uuid) == std::string(1, '\5') && records.at(three->uuid) == std::string(1, '\6'));
        }
    }
}

/// Exact-target index limits body fanout; real streams verify hit data-only and miss empty-progress pages.
void delivery() {

    Fixture fixture(false);
    const astra::Scope scope{"service", "main"};
    const auto attr = std::make_shared<const Ephemeris::Buffer>(8, 1);
    const auto first = fixture.state.create(scope, attr, std::make_shared<const Ephemeris::Buffer>(8, 2), 1000);
    const auto second = fixture.state.create(scope, attr, std::make_shared<const Ephemeris::Buffer>(8, 3), 1000);
    CHECK(first && second);
    std::array<std::unique_ptr<Watching>, 4> watches;
    for (std::size_t index = 0; index < watches.size(); ++index) {
        watches[index] = std::make_unique<Watching>(fixture, index < 2 ? first->uuid : second->uuid);
        CHECK(watches[index]->next().version() == 2);
    }
    const auto before = fixture.service.delivery();
    CHECK(fixture.state.update(scope, first->uuid, std::make_shared<const Ephemeris::Buffer>(8, 4), 1));
    const auto after = fixture.service.delivery();
    CHECK(after.scans == before.scans + 2 && after.matched == before.matched + 2); // Visit only two matching streams; pump lazily advances unrelated target watermarks/progress.
    for (std::size_t index = 0; index < watches.size(); ++index) {
        const auto page = watches[index]->next(); // Even zero history must retain complete progress through active-stream notification.
        CHECK(page.mode() == proto::comet::v1::MODE_APPLY && page.version() == 3);
        if (index < 2) {
            CHECK(page.changes_size() == 1 && page.changes(0).uuid() == first->uuid && page.changes(0).has_data() && page.changes(0).data() == std::string(8, '\4'));
        } else {
            CHECK(page.changes().empty());
        }
    }
}

/// Directed fanout: many idle exact subscriptions, one hit. Assert scan/hit counts and report commit-notification duration.
/// Optional attribution runs only with explicit VERDANDI_FANOUT_LOAD=1..4096; ordinary regression retains bounded functional cases.
void load() {

    const char* sized = std::getenv("VERDANDI_FANOUT_LOAD");
    if (!sized) {
        return;
    }
    const std::string_view input(sized);
    unsigned total{}; // Require full numeric consumption and the service's stream-limit bound; reject partial/overflowed configuration.
    const auto [end, error] = std::from_chars(input.data(), input.data() + input.size(), total);
    if (error != std::errc{} || end != input.data() + input.size() || total == 0 || total > 4096) {
        throw std::invalid_argument("VERDANDI_FANOUT_LOAD must be an integer in 1..4096");
    }
    Fixture fixture(false);
    const astra::Scope scope{"service", "main"};
    const auto attr = std::make_shared<const Ephemeris::Buffer>(8, 1);
    std::vector<std::string> uuids;
    uuids.reserve(total);
    for (unsigned index = 0; index < total; ++index) {
        auto created = fixture.state.create(scope, attr, std::make_shared<const Ephemeris::Buffer>(8, 2), 1000);
        CHECK(created);
        uuids.push_back(created->uuid);
    }
    std::vector<std::unique_ptr<Watching>> watches;
    watches.reserve(total);
    for (const auto& uuid : uuids) {
        watches.push_back(std::make_unique<Watching>(fixture, uuid));
        CHECK(watches.back()->next().version() == total);
    }
    const auto before = fixture.service.delivery();
    const auto started = std::chrono::steady_clock::now();
    CHECK(fixture.state.update(scope, uuids.front(), std::make_shared<const Ephemeris::Buffer>(8, 4), 1));
    const auto elapsed = std::chrono::steady_clock::now() - started;
    const auto after = fixture.service.delivery();
    CHECK(after.scans == before.scans + 1 && after.matched == before.matched + 1); // One UUID per bucket: one update visits only the matching stream; pump advances the others.
    std::cout << "fanout load: streams=" << total << " update_us=" << std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count() << " scans=" << after.scans - before.scans << " matched=" << after.matched - before.matched << '\n';
}

/// Attribution compares no subscriptions, exact hit (merge/enqueue), and exact miss (lookup/skip).
/// Average 200 iterations per path; print durations without timing assertions and assert exact scan/match deltas.
void split() {

    if (!std::getenv("VERDANDI_FANOUT_LOAD")) {
        return;
    }
    Fixture fixture(false);
    const astra::Scope scope{"service", "main"};
    const auto attr = std::make_shared<const Ephemeris::Buffer>(8, 1);
    const auto data = std::make_shared<const Ephemeris::Buffer>(8, 2);
    const auto first = fixture.state.create(scope, attr, data, 1000);
    const auto second = fixture.state.create(scope, attr, data, 1000);
    CHECK(first && second);
    constexpr unsigned rounds = 200;
    const auto content = [](unsigned order) { return std::make_shared<const Ephemeris::Buffer>(8, static_cast<std::uint8_t>(order % 251)); };
    const auto time = [&](auto&& work) {
        const auto started = std::chrono::steady_clock::now();
        for (unsigned order = 1; order <= rounds; ++order) {
            work(order);
        }
        const auto elapsed = std::chrono::steady_clock::now() - started;
        return static_cast<double>(std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count()) / static_cast<double>(rounds) / 1000.0;
    };
    // Change bodies each iteration; same-body new orders bypass Scene commits/notifications and would measure a different path.
    const auto idle = time([&](unsigned order) { CHECK(fixture.state.update(scope, first->uuid, content(order), order)); });
    Watching watch(fixture, first->uuid);
    const auto initial = watch.next();
    CHECK(initial.complete() && initial.has_version());
    const auto before = fixture.service.delivery();
    const auto hit = time([&](unsigned order) { CHECK(fixture.state.update(scope, first->uuid, content(order), rounds + order)); });
    const auto middle = fixture.service.delivery();
    const auto miss = time([&](unsigned order) { CHECK(fixture.state.update(scope, second->uuid, content(order), order)); });
    const auto after = fixture.service.delivery();
    std::cout << "split: idle_us=" << idle << " hit_us=" << hit << " miss_us=" << miss << " dscans_b=" << (middle.scans - before.scans) << " dmatch_b=" << (middle.matched - before.matched) << " dscans_c=" << (after.scans - middle.scans) << '\n';
    CHECK(middle.scans == before.scans + rounds && middle.matched == before.matched + rounds);
    CHECK(after.scans == middle.scans && after.matched == middle.matched);
}
} // namespace

/// Bounded real loopback fixture, without deployment processes or long stress runs.
int main() {
    try {
        editions();
        lifecycle();
        rejection();
        exceptions();
        creation();
        boundaries();
        versions();
        limits();
        configuration();
        cleanup();
        streaming();
        resume();
        fanout();
        delivery();
        load();
        split();
        std::cout << "Ephemeris RPC tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
