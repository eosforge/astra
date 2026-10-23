// Exercise real scalar-allocation failures in signing, credential parsing and precommit registration.
#include "issuer.hpp"
#include "pulsar_test.hpp"

#include <grpc/support/time.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/server_builder.h>

#include <cstdio>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <span>
#include <string_view>

namespace astra::test {
namespace {
/// Count only the initiating thread's selected operation, failing at most one scalar allocation.
struct Probe {
    /// Authentication must finish before registration's allocation domain begins.
    bool pending{}, active{}, armed{};
    /// UINT_MAX observes the healthy domain without injecting a failure.
    unsigned position = std::numeric_limits<unsigned>::max();
    /// Actual selected primitive entries and refusals, never inferred from a loop budget.
    unsigned calls{}, failures{};
};

/// gRPC/TLS workers and unrelated test operations never inherit this allocation scope.
thread_local Probe probe;

/// Reset the one-shot native substitution before assertions or object destruction outside the target.
class Allocation {
public:
    /// after=true excludes the actual KDF and its permit from the registration domain.
    explicit Allocation(unsigned position = std::numeric_limits<unsigned>::max(), bool after = false) {
        probe = {.pending = after, .active = !after, .armed = !after, .position = position};
    }

    /// Always disarm, including when an unexpected exception escapes the production operation.
    ~Allocation() {
        probe = {};
    }

    /// Preserve real counts while disabling injection before independent checks.
    Probe finish() {
        const auto result = probe;
        probe = {};
        return result;
    }
};

/// Emit the domain and ordinal before entry so a process-level failure retains its exact counterexample.
void entered(std::string_view domain, unsigned ordinal) {
    std::fprintf(stdout, "PULSAR-ALLOCATION {\"domain\":\"%.*s\",\"ordinal\":%u,\"begin\":true}\n", static_cast<int>(domain.size()), domain.data(), ordinal);
    std::fflush(stdout);
}

/// Verify one real sign/parse operation with a nonvacuous healthy baseline and every measured allocation.
template <typename F>
void failures(std::string_view domain, F operation) {

    const auto control = [&] {
        Allocation allocation;
        operation();
        const auto result = allocation.finish();
        CHECK(result.armed && result.calls > 0 && result.calls <= 256 && result.failures == 0);
        return result.calls;
    };
    const auto count = control();
    CHECK(control() == count);
    for (unsigned ordinal = 0; ordinal < count; ++ordinal) {
        entered(domain, ordinal);
        bool refused{};
        Allocation allocation(ordinal);
        try {
            operation();
        } catch (const std::bad_alloc&) {
            refused = true;
        }
        const auto result = allocation.finish();
        CHECK(refused && result.armed && result.failures == 1 && result.calls == ordinal + 1);
    }
    operation();
    std::fprintf(stdout, "PULSAR-ALLOCATION {\"domain\":\"%.*s\",\"allocations\":%u,\"refusals\":%u,\"recovered\":true}\n", static_cast<int>(domain.size()), domain.data(), count, count);
}

/// Keep the initial committed state identical while measuring a successful new registration elsewhere.
void registration(const std::filesystem::path& root, const Authority& authority, const Identity& identity) {

    auto seed = member(1);
    seed.epoch.value = 0;
    const std::string original(32, 's');
    proto::orbit::v1::RegistrationRequest request;
    request.set_username(identity.username());
    request.set_password(identity.password());
    request.set_galaxy("alpha");
    request.set_group("default");
    request.set_advertise("127.0.0.1:7443");
    request.set_role(proto::orbit::v1::ROLE_STAR);
    request.set_request_id(std::string(32, 'r'));
    const auto baseline = [&](std::string_view name) {
        Ledger ledger(root / name, "alpha", authority.keyId(), 2, 8, true);
        CHECK(ledger.registerMember(seed, original, [](const auto&, const auto&) {}));
        Issuer issuer("alpha", "127.0.0.1:7442", authority, ledger);
        grpc::ServerContext context;
        proto::orbit::v1::RegistrationResponse response;
        Allocation allocation(std::numeric_limits<unsigned>::max(), true);
        const auto status = issuer.Register(&context, &request, &response);
        const auto result = allocation.finish();
        CHECK(status.ok() && response.members_size() == 2 && !response.admission().empty() && response.signature().size() == 64);
        CHECK(result.armed && !result.pending && result.calls > 0 && result.calls <= 256 && result.failures == 0);
        return result.calls;
    };
    static_cast<void>(baseline("warmup.db"));
    const auto count = baseline("baseline.db");
    CHECK(baseline("control.db") == count);

    Ledger ledger(root / "refusals.db", "alpha", authority.keyId(), 2, 8, true);
    Member current;
    CHECK(ledger.registerMember(seed, original, [&](const Member& member, const auto&) { current = member; }));
    const auto snapshot = ledger.snapshot(current);
    CHECK(snapshot && snapshot->size() == 1);
    Issuer issuer("alpha", "127.0.0.1:7442", authority, ledger);
    for (unsigned ordinal = 0; ordinal < count; ++ordinal) {
        entered("registration", ordinal);
        grpc::ServerContext context;
        proto::orbit::v1::RegistrationResponse response;
        Allocation allocation(ordinal, true);
        const auto status = issuer.Register(&context, &request, &response);
        const auto result = allocation.finish();
        CHECK(result.armed && !result.pending && result.failures == 1 && result.calls == ordinal + 1);
        CHECK(status.error_code() == grpc::StatusCode::RESOURCE_EXHAUSTED && response.ByteSizeLong() == 0);
        CHECK(ledger.snapshot(current) == snapshot);
    }
    grpc::ServerContext context;
    proto::orbit::v1::RegistrationResponse response;
    CHECK(issuer.Register(&context, &request, &response).ok() && response.members_size() == 2);
    CHECK(ledger.snapshot(current)->size() == 2 && snapshot->size() == 1);
    std::fprintf(stdout, "PULSAR-ALLOCATION {\"domain\":\"registration\",\"allocations\":%u,\"refusals\":%u,\"recovered\":true}\n", count, count);
}

/// Observe scalar allocation only inside the real directory handler, after TLS and metadata reception.
class Listing final : public proto::orbit::v1::Admission::Service {
public:
    /// Preserve the native handler's outcome before gRPC serializes its response.
    struct Result {
        /// Actual initiating-thread allocation counts and one-shot refusal.
        Probe probe;
        /// Native status and response size, independent of the client transport status.
        grpc::StatusCode code;
        /// Record the native response size in bytes, independently of transport status.
        std::size_t bytes;
    };

    /// The caller retains the issuer until the listener has shut down and drained.
    explicit Listing(Issuer& issuer) : issuer_(issuer) {}

    /// Configure one sequential request before it enters an owned worker.
    void select(unsigned position = std::numeric_limits<unsigned>::max()) {
        const std::lock_guard lock(mutex_);
        CHECK(done_);
        position_ = position;
        done_ = false;
    }

    /// Invoke actual admission verification, snapshot selection and response preparation.
    grpc::Status List(grpc::ServerContext* context, const proto::orbit::v1::DirectoryRequest* request, proto::orbit::v1::DirectoryResponse* response) override {

        unsigned position;
        {
            const std::lock_guard lock(mutex_);
            CHECK(!done_);
            position = position_;
        }
        Allocation allocation(position);
        const auto status = issuer_.List(context, request, response);
        const auto observed = allocation.finish();

        const std::lock_guard lock(mutex_);
        result_ = {observed, status.error_code(), response->ByteSizeLong()};
        done_ = true;
        return status;
    }

    /// Read one completed native result under the same publication lock.
    Result result() const {
        const std::lock_guard lock(mutex_);
        CHECK(done_);
        return result_;
    }

private:
    /// Never destroy the issuer while this service owns a live callback.
    Issuer& issuer_;
    /// Separate client configuration/result observation from the gRPC handler's local allocator probe.
    mutable std::mutex mutex_;
    /// UINT_MAX observes rather than refuses; only one request may be active.
    unsigned position_ = std::numeric_limits<unsigned>::max();
    /// True initially and after the native response has been measured.
    bool done_ = true;
    /// A failed request must retain an empty response and an explicit resource error.
    Result result_{};
};

/// Enumerate directory allocations through real signed admission and an isolated TLS listener.
void listing(const std::filesystem::path& root, const Authority& authority, const Identity& identity) {

    Ledger ledger(root / "listing.db", "alpha", authority.keyId(), 2, 8, true);
    auto first = member(1), second = member(2);
    CHECK(ledger.registerMember(first, std::string(32, 'a'), [&](const Member& current, const auto&) { first = current; }));
    CHECK(ledger.registerMember(second, std::string(32, 'b'), [&](const Member& current, const auto&) { second = current; }));
    const auto snapshot = ledger.snapshot(first);
    CHECK(snapshot && snapshot->size() == 2);
    proto::orbit::v1::RegistrationResponse receipt;
    authority.sign(Identity::encode(first), receipt);
    Issuer issuer("alpha", "127.0.0.1:7442", authority, ledger);
    Listing service(issuer);

    grpc::ServerBuilder builder;
    builder.RegisterService(&service);
    builder.AddChannelArgument("grpc.so_reuseport", 0);
    grpc::ResourceQuota quota;
    quota.Resize(16 * 1024 * 1024);
    quota.SetMaxThreads(8);
    builder.SetResourceQuota(quota);
    int port{};
    builder.AddListeningPort("127.0.0.1:0", authority.identity().serverCredentials(), &port);
    auto server = builder.BuildAndStart();
    CHECK(server && port > 0);
    auto stub = proto::orbit::v1::Admission::NewStub(grpc::CreateChannel("127.0.0.1:" + std::to_string(port), identity.channelCredentials()));

    /// Drain all server handlers before releasing their borrowed issuer and identity objects.
    struct Drain {
        /// The unique server and all borrowed dependencies outlive this guard.
        std::unique_ptr<grpc::Server>& server;

        /// Await every handler before its issuer, ledger or signing material can be released.
        ~Drain() {
            server->Shutdown(std::chrono::system_clock::now() + std::chrono::seconds(5));
            server->Wait();
        }
    } drain{server};

    const auto invoke = [&](unsigned position = std::numeric_limits<unsigned>::max()) {
        service.select(position);
        grpc::ClientContext context;
        context.AddMetadata("astra-admission-bin", receipt.admission());
        context.AddMetadata("astra-signature-bin", receipt.signature());
        context.set_deadline(gpr_time_add(gpr_now(GPR_CLOCK_MONOTONIC), gpr_time_from_seconds(45, GPR_TIMESPAN)));
        proto::orbit::v1::DirectoryRequest request;
        proto::orbit::v1::DirectoryResponse response;
        const auto status = stub->List(&context, request, &response);
        const auto result = service.result();
        CHECK(result.probe.armed && !result.probe.pending && status.error_code() == result.code);
        if (position == std::numeric_limits<unsigned>::max()) {
            CHECK(status.ok() && result.probe.failures == 0 && result.probe.calls > 0 && result.probe.calls <= 256);
            CHECK(response.members_size() == 2 && result.bytes == response.ByteSizeLong());
            CHECK(response.members(0).id() == first.id && response.members(0).epoch() == first.epoch.value);
            CHECK(response.members(1).id() == second.id && response.members(1).epoch() == second.epoch.value);
        } else {
            CHECK(result.probe.failures == 1 && result.probe.calls == position + 1);
            CHECK(result.code == grpc::StatusCode::RESOURCE_EXHAUSTED && result.bytes == 0 && response.ByteSizeLong() == 0);
        }
        CHECK(ledger.snapshot(first) == snapshot);
        return result.probe.calls;
    };
    static_cast<void>(invoke());
    const auto count = invoke();
    CHECK(invoke() == count);
    for (unsigned ordinal = 0; ordinal < count; ++ordinal) {
        entered("directory", ordinal);
        static_cast<void>(invoke(ordinal));
    }
    CHECK(invoke() == count);
    std::fprintf(stdout, "PULSAR-ALLOCATION {\"domain\":\"directory\",\"allocations\":%u,\"refusals\":%u,\"recovered\":true}\n", count, count);
}
} // namespace
} // namespace astra::test

/// Original installed scalar allocator and authentication method supplied by the test-only linker bindings.
extern "C" void* __real__Znwm(std::size_t);
extern "C" grpc::Status __real__ZNK5astra9Authority12authenticateERN4grpc13ServerContextERKN5proto5orbit2v119RegistrationRequestE(const astra::Authority*, grpc::ServerContext&, const proto::orbit::v1::RegistrationRequest&);

/// Fail exactly one measured allocation and retain the actual allocator for every other call.
extern "C" void* __wrap__Znwm(std::size_t size) {
    auto& probe = astra::test::probe;
    if (probe.active && probe.calls++ == probe.position) {
        probe.active = false;
        ++probe.failures;
        throw std::bad_alloc{};
    }
    return __real__Znwm(size);
}

/// Real account/password/role checks complete before entering a selected registration allocation domain.
extern "C" grpc::Status __wrap__ZNK5astra9Authority12authenticateERN4grpc13ServerContextERKN5proto5orbit2v119RegistrationRequestE(const astra::Authority* authority, grpc::ServerContext& context, const proto::orbit::v1::RegistrationRequest& request) {
    auto result = __real__ZNK5astra9Authority12authenticateERN4grpc13ServerContextERKN5proto5orbit2v119RegistrationRequestE(authority, context, request);
    auto& probe = astra::test::probe;
    if (result.ok() && probe.pending) {
        probe.pending = false;
        probe.active = probe.armed = true;
    }
    return result;
}

namespace astra::test {
/// Preserve every current response destructor and real parsing/signing path under scalar allocation refusal.
void allocation() {

    const Directory directory;
    const auto endpoint = *Endpoint::parse("127.0.0.1:7443");
    const auto authority = Authority::load(std::filesystem::path(ASTRA_FIXTURES) / "pulsar", endpoint, endpoint);
    const auto identity = Identity::load(std::filesystem::path(ASTRA_FIXTURES) / "star-a", endpoint);
    CHECK(authority && identity);
    {
        // Only the owned public fixture copy loses read permission; deployed material is never touched.
        const auto copy = directory.path / "authority";
        std::filesystem::copy(std::filesystem::path(ASTRA_FIXTURES) / "pulsar", copy, std::filesystem::copy_options::recursive);
        const auto key = copy / "admission.key";
        const auto permissions = std::filesystem::status(key).permissions();
        CHECK(geteuid() != 0);
        std::filesystem::permissions(key, std::filesystem::perms::none);
        const auto refused = Authority::load(copy, endpoint, endpoint);
        std::filesystem::permissions(key, permissions);
        CHECK(!refused && refused.error().code == Status::Code::Identity);
        CHECK(Authority::load(copy, endpoint, endpoint));
        std::fprintf(stdout, "PULSAR-ALLOCATION {\"domain\":\"authority-read\",\"refusals\":1,\"recovered\":true}\n");
        std::fflush(stdout);
    }
    auto current = member(1);
    current.galaxy = std::string(64, 'a');
    current.group = std::string(64, 'g');
    current.id = std::string(128, 'i');
    const auto address = Endpoint::parse("[2001:db8:1234:5678:9abc:def0:1234:5678]:7443");
    CHECK(address);
    current.address = *address;
    current.epoch.value = 1;
    CHECK(current.validate());
    const auto encoded = Identity::encode(current);
    proto::orbit::v1::RegistrationResponse receipt;
    (*authority)->sign(encoded, receipt);
    const auto admission = std::span(reinterpret_cast<const std::uint8_t*>(receipt.admission().data()), receipt.admission().size());
    const auto signature = std::span(reinterpret_cast<const std::uint8_t*>(receipt.signature().data()), receipt.signature().size());
    const auto decoded = (*identity)->verify(admission, signature);
    CHECK(decoded && *decoded == current);
    failures("sign", [&] {
        proto::orbit::v1::RegistrationResponse response;
        (*authority)->sign(encoded, response);
    });
    failures("verify", [&] {
        const auto decoded = (*identity)->verify(admission, signature);
        CHECK(decoded && *decoded == current);
    });
    registration(directory.path, **authority, **identity);
    listing(directory.path, **authority, **identity);
}
} // namespace astra::test
