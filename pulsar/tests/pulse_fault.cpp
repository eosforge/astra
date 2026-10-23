// Verify Pulse qualification boundaries through owned TLS streams and controlled clock observations.
#include "pulsar_test.hpp"
#include "pulse.hpp"

#include <grpc/support/time.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/server_builder.h>

#include <array>
#include <iostream>
#include <limits>
#include <mutex>
#include <stdexcept>

using namespace astra;

namespace {
/// Select the isolated failure or successful pair of clock observations.
enum class Mode {
    /// The first read has no epoch anchor.
    Empty,
    /// The first reading has lost reference qualification.
    Unsynchronized,
    /// Qualification disappears before the second observation.
    Lost,
    /// The second observation becomes unavailable.
    Missing,
    /// The second observation precedes the first.
    Reversed,
    /// The exposed reference precision is invalid.
    Imprecise,
    /// The first clock read throws a stable diagnostic exception.
    Failed,
    /// The second clock read throws an allocation exception.
    Allocation,
    /// Both observations share the same valid coordinate.
    Equal,
    /// The second observation advances by one nanosecond.
    Advanced,
};

/// Bind fault state to one owned Source; every unrelated source retains its native implementation.
struct Probe {
    /// Serialize callback observations and final fixture assertions.
    std::mutex mutex;
    /// Borrow the selected Source only while its complete service is alive.
    const Source* source{};
    /// Current isolated scenario; changed only after the preceding service has drained.
    Mode mode{};
    /// Actual calls made by the production Pulse callback.
    unsigned reads{};
    /// Actual precision queries made by the production Pulse callback.
    unsigned precisions{};
} probe;

/// Keep injected observations available until the server and all callback reactors are destroyed.
class Binding {
public:
    /// Install one scenario before its server starts accepting traffic.
    Binding(const Source& source, Mode mode) {
        const std::lock_guard lock(probe.mutex);
        CHECK(!probe.source);
        probe.source = &source;
        probe.mode = mode;
        probe.reads = probe.precisions = 0;
    }

    /// Remove the borrowed source only after the server's owning guard has drained it.
    ~Binding() {
        const std::lock_guard lock(probe.mutex);
        probe.source = nullptr;
    }

    /// Keep one owner responsible for withdrawing the test binding.
    Binding(const Binding&) = delete;
    /// Prevent replacing an active binding without draining its service.
    Binding& operator=(const Binding&) = delete;
};

/// Drain callback reactors before their borrowed service, clock, authority or ledger can disappear.
struct Server {
    /// Own the actual gRPC server, including construction-failure cleanup.
    std::unique_ptr<grpc::Server> value;

    /// Cancel remaining calls within the existing fixture budget and await actual completion.
    ~Server() {
        if (value) {
            value->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));
            value->Wait();
        }
    }
};

/// Cancel and finish the actual client call even when a boundary assertion fails.
struct Call {
    /// Keep request metadata and cancellation alive until the stream finishes.
    grpc::ClientContext context;
    /// Own the channel stub throughout the synchronous stream.
    std::unique_ptr<proto::pulsar::v1::Pulse::Stub> stub;
    /// Own the native call and its message operations.
    std::unique_ptr<grpc::ClientReaderWriter<proto::pulsar::v1::Ping, proto::pulsar::v1::Pong>> stream;
    /// Record receipt of the final status, preventing a second Finish.
    bool finished{};

    /// Open one authenticated, bounded TLS call to the uniquely owned listener.
    Call(int port, const Identity& client, const proto::orbit::v1::RegistrationResponse& token) {
        context.set_deadline(gpr_time_add(gpr_now(GPR_CLOCK_MONOTONIC), gpr_time_from_seconds(5, GPR_TIMESPAN)));
        context.AddMetadata("astra-admission-bin", token.admission());
        context.AddMetadata("astra-signature-bin", token.signature());
        stub = proto::pulsar::v1::Pulse::NewStub(grpc::CreateChannel("127.0.0.1:" + std::to_string(port), client.channelCredentials()));
        stream = stub->Bounce(&context);
    }

    /// Preserve failure diagnostics while draining the in-flight call before its context is released.
    ~Call() {
        if (!finished) {
            context.TryCancel();
            static_cast<void>(stream->Finish());
        }
    }

    /// Return the unmodified native status and retire this call's cleanup obligation.
    grpc::Status finish() {
        auto result = stream->Finish();
        finished = true;
        return result;
    }
};

/// Describe independent public results and the exact clock calls each path must perform.
struct Case {
    /// Stable nonsecret observation identity.
    std::string_view name;
    /// Selected deterministic clock boundary.
    Mode mode;
    /// Literal request coordinate, including the inclusive signed maximum and its successor.
    std::uint64_t time;
    /// Required final wire status.
    grpc::StatusCode code;
    /// Required stable wire reason; empty for success.
    std::string_view reason;
    /// Required number of production clock reads.
    unsigned reads;
    /// Required number of production precision queries.
    unsigned precisions;
};

/// Exercise one actual stream; failed qualification must not publish a partial Pong.
void run(const Case& item, const Authority& authority, const Ledger& ledger, const Identity& client, const proto::orbit::v1::RegistrationResponse& token) {
    Source clock([] { return std::optional<Clock::Estimate>{}; });
    Binding binding(clock, item.mode);
    Pulse service(authority, ledger, clock);
    Server server;
    grpc::ServerBuilder builder;
    builder.RegisterService(&service);
    builder.AddChannelArgument("grpc.so_reuseport", 0);
    grpc::ResourceQuota quota;
    quota.Resize(16 * 1024 * 1024);
    quota.SetMaxThreads(16);
    builder.SetResourceQuota(quota);
    int port = 0;
    builder.AddListeningPort("127.0.0.1:0", authority.identity().serverCredentials(), &port);
    server.value = builder.BuildAndStart();
    CHECK(server.value && port > 0);
    Call call(port, client, token);
    proto::pulsar::v1::Ping ping;
    proto::pulsar::v1::Pong pong;
    ping.set_t0(item.time);
    CHECK(call.stream->Write(ping));
    if (item.code == grpc::StatusCode::OK) {
        CHECK(call.stream->Read(&pong));
        CHECK(pong.t0() == item.time);
        CHECK(pong.t1() == 1'800'000'000'000'000'000ULL);
        CHECK(pong.t2() == pong.t1() + (item.mode == Mode::Equal ? 0 : 1));
        CHECK(pong.synchronized());
        CHECK(pong.precision_ns() == 7 && pong.uncertainty_ns() == 29);
        CHECK(call.stream->WritesDone());
    }
    CHECK(!call.stream->Read(&pong));
    if (item.code != grpc::StatusCode::OK) {
        CHECK(pong.ByteSizeLong() == 0);
    }
    const auto status = call.finish();
    CHECK(status.error_code() == item.code);
    CHECK(status.error_message() == item.reason);
    {
        const std::lock_guard lock(probe.mutex);
        CHECK(probe.reads == item.reads);
        CHECK(probe.precisions == item.precisions);
    }
    server.value->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));
    server.value->Wait();
    server.value.reset();
    std::cout << "PULSAR-PULSE {\"case\":\"" << item.name << "\"}\n";
}
} // namespace

extern "C" std::optional<Clock::Reading> __real__ZNK5astra6Source3nowEv(const Source* source);
extern "C" std::uint64_t __real__ZNK5astra6Source9precisionEv(const Source* source) noexcept;

/// Intercept only the selected Source's external read calls; the native sampling worker is unchanged.
extern "C" std::optional<Clock::Reading> __wrap__ZNK5astra6Source3nowEv(const Source* source) {
    {
        const std::lock_guard lock(probe.mutex);
        if (source == probe.source) {
            const auto second = ++probe.reads == 2;
            if (probe.mode == Mode::Failed) {
                throw std::runtime_error("Controlled Pulse clock refusal");
            }
            if (second && probe.mode == Mode::Allocation) {
                throw std::bad_alloc();
            }
            if (probe.mode == Mode::Empty || (second && probe.mode == Mode::Missing)) {
                return std::nullopt;
            }
            Clock::Reading result;
            result.time = Clock::Time(std::chrono::nanoseconds(1'800'000'000'000'000'000LL));
            result.time += std::chrono::nanoseconds(second ? (probe.mode == Mode::Reversed ? -1 : probe.mode == Mode::Equal ? 0
                                                                                                                            : 1)
                                                           : 0);
            result.uncertaintyNanoseconds = second ? 29 : 23;
            result.ready = true;
            result.synchronized = probe.mode != Mode::Unsynchronized && !(second && probe.mode == Mode::Lost);
            return result;
        }
    }
    return __real__ZNK5astra6Source3nowEv(source);
}

/// Observe the actual production precision query without changing another Source's behavior.
extern "C" std::uint64_t __wrap__ZNK5astra6Source9precisionEv(const Source* source) noexcept {
    {
        const std::lock_guard lock(probe.mutex);
        if (source == probe.source) {
            ++probe.precisions;
            return probe.mode == Mode::Imprecise ? 0 : 7;
        }
    }
    return __real__ZNK5astra6Source9precisionEv(source);
}

namespace astra::test {
/// Test qualification failures and immediate healthy reuse with the same signed member and durable ledger.
void pulse() {
    const auto endpoint = *Endpoint::parse("127.0.0.1:7443");
    auto authority = Authority::load(std::filesystem::path(ASTRA_FIXTURES) / "pulsar", endpoint, endpoint);
    auto client = Identity::load(std::filesystem::path(ASTRA_FIXTURES) / "star-a", endpoint);
    CHECK(authority && client);
    Directory directory;
    Ledger ledger(directory.path / "pulse.db", "alpha", (*authority)->keyId(), 2, 8, true);
    proto::orbit::v1::RegistrationResponse token;
    Member member;
    CHECK(ledger.registerMember(test::member(1), std::string(32, 'p'), [&](const Member& local, const auto&) {
        member = local;
        (*authority)->sign(Identity::encode(local), token);
    }));
    CHECK(ledger.current(member));
    const auto snapshot = ledger.snapshot(member);
    CHECK(snapshot && snapshot->size() == 1);
    constexpr auto maximum = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    const std::array cases{
        Case{"first-empty", Mode::Empty, 1, grpc::StatusCode::UNAVAILABLE, "Physical time not synchronized", 1, 0},
        Case{"first-unsynchronized", Mode::Unsynchronized, 1, grpc::StatusCode::UNAVAILABLE, "Physical time not synchronized", 1, 0},
        Case{"timestamp-overflow", Mode::Advanced, maximum + 1, grpc::StatusCode::INVALID_ARGUMENT, "Invalid Pulse timestamp", 1, 0},
        Case{"second-missing", Mode::Missing, 1, grpc::StatusCode::UNAVAILABLE, "Physical time not synchronized", 2, 1},
        Case{"second-unsynchronized", Mode::Lost, 1, grpc::StatusCode::UNAVAILABLE, "Physical time not synchronized", 2, 1},
        Case{"second-reversed", Mode::Reversed, 1, grpc::StatusCode::UNAVAILABLE, "Physical time not synchronized", 2, 1},
        Case{"precision-zero", Mode::Imprecise, 1, grpc::StatusCode::UNAVAILABLE, "Physical time not synchronized", 2, 1},
        Case{"first-exception", Mode::Failed, 1, grpc::StatusCode::UNAVAILABLE, "Physical time unavailable", 1, 0},
        Case{"second-allocation", Mode::Allocation, 1, grpc::StatusCode::UNAVAILABLE, "Physical time unavailable", 2, 1},
        Case{"equal", Mode::Equal, 1, grpc::StatusCode::OK, {}, 2, 1},
        Case{"advanced", Mode::Advanced, 1, grpc::StatusCode::OK, {}, 2, 1},
        Case{"timestamp-maximum", Mode::Advanced, maximum, grpc::StatusCode::OK, {}, 2, 1}};
    const Case healthy{"recovered", Mode::Advanced, 2, grpc::StatusCode::OK, {}, 2, 1};
    for (const auto& item : cases) {
        run(item, **authority, ledger, **client, token);
        CHECK(ledger.current(member));
        CHECK(ledger.snapshot(member) == snapshot);
        if (item.code != grpc::StatusCode::OK) {
            run(healthy, **authority, ledger, **client, token);
            CHECK(ledger.snapshot(member) == snapshot);
        }
    }
    std::cout << "PULSAR-PULSE {\"complete\":true,\"cases\":12,\"recoveries\":9}\n";
}
} // namespace astra::test
