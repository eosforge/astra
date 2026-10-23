// Verify admission failure isolation and partial-response cancellation through real TLS and SQLite.
#include "database_fault.hpp"
#include "pulsar_test.hpp"
#include "server.hpp"

#include <grpc/support/time.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/server_builder.h>
#include <openssl/rand.h>

#include <algorithm>
#include <condition_variable>
#include <future>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <vector>

namespace astra::test {
namespace {
using namespace std::chrono_literals;

/// Own one sequential scenario and observe its handler before transport cancellation replaces its result.
class Probe {
public:
    /// Each substitution is local to an owned admission handler, never TLS or unrelated workers.
    enum class Kind {
        /// Forward all real operations unchanged.
        None,
        /// Throw after the selected real member encoding has completed.
        Allocation,
        /// Throw a nonallocation exception after the selected real encoding.
        Failure,
        /// Report one deliberate entropy refusal after actually invoking the native generator.
        Entropy,
        /// Hold after successful real authentication and before registration preparation.
        Authentication,
        /// Hold after encoding one directory item and before the next cancellation check.
        Encoding
    };

    /// Select the next scenario only after the previous handler has retired.
    void arm(Kind kind = Kind::None, unsigned ordinal = 1) {
        const std::lock_guard lock(mutex_);
        CHECK(!context_ && !done_);
        kind_ = kind;
        ordinal_ = ordinal;
        encodings_ = hits_ = 0;
        released_ = expired_ = false;
    }

    /// Borrow a live context until the same handler publishes its actual result.
    void begin(grpc::ServerContext& context) {
        const std::lock_guard lock(mutex_);
        context_ = &context;
    }

    /// Record the real service result and whether an error exposed any partial response.
    void end(const grpc::Status& status, std::size_t bytes) {
        const std::lock_guard lock(mutex_);
        code_ = status.error_code();
        reason_ = status.error_message();
        empty_ = bytes == 0;
        context_ = nullptr;
        done_ = true;
        changed_.notify_all();
    }

    /// Inject only once at the chosen boundary after its real computation.
    bool point(Kind boundary) {

        std::unique_lock lock(mutex_);
        if (boundary == Kind::Encoding) {
            ++encodings_;
        }
        const bool selected = boundary == Kind::Encoding ? (kind_ == Kind::Encoding || kind_ == Kind::Allocation || kind_ == Kind::Failure) && encodings_ == ordinal_ : boundary == kind_;
        if (!selected || hits_ != 0) {
            return false;
        }
        ++hits_;
        changed_.notify_all();
        if (kind_ == Kind::Authentication || kind_ == Kind::Encoding) {
            if (!changed_.wait_for(lock, 30s, [this] { return released_; })) {
                expired_ = true;
            }
        } else if (kind_ == Kind::Allocation) {
            throw std::bad_alloc{};
        } else if (kind_ == Kind::Failure) {
            throw std::runtime_error("Owned admission preparation failure");
        }
        return kind_ == Kind::Entropy;
    }

    /// Wait for an actual probe hit, then verify cancellation on the same server context.
    void cancel(grpc::ClientContext& client) {

        {
            std::unique_lock lock(mutex_);
            CHECK(changed_.wait_for(lock, 30s, [this] { return hits_ != 0; }));
            CHECK(context_ && !expired_);
        }
        client.TryCancel();
        const auto deadline = std::chrono::steady_clock::now() + 10s;
        while (std::chrono::steady_clock::now() < deadline) {
            {
                const std::lock_guard lock(mutex_);
                CHECK(context_);
                if (context_->IsCancelled()) {
                    return;
                }
            }
            std::this_thread::yield();
        }
        CHECK(false && "Owned admission handler did not observe cancellation");
    }

    /// Always release a held handler before joining or shutting down its server.
    void release() {
        const std::lock_guard lock(mutex_);
        released_ = true;
        changed_.notify_all();
    }

    /// Require the service's exact status, fixed reason, probe count and partial-response isolation.
    void finish(grpc::StatusCode expected, std::string_view reason = {}) {

        std::unique_lock lock(mutex_);
        CHECK(changed_.wait_for(lock, 30s, [this] { return done_; }));
        CHECK(!context_ && !expired_ && code_ == expected);
        CHECK(expected == grpc::StatusCode::OK || empty_);
        CHECK(reason.empty() || reason_ == reason);
        CHECK(hits_ == (kind_ == Kind::None ? 0U : 1U));
        done_ = false;
    }

private:
    /// Protect the single live handler, controlled barrier and independent result oracle.
    std::mutex mutex_;
    /// Notify real entry, cancellation release and handler retirement.
    std::condition_variable changed_;
    /// Borrowed only while the handler is executing, cleared before return.
    grpc::ServerContext* context_{};
    /// One boundary substitution or scheduling barrier per scenario.
    Kind kind_ = Kind::None;
    /// One-based real encoding position; count includes ledger preparation for registration.
    unsigned ordinal_ = 1, encodings_{}, hits_{};
    /// Barrier/result state; expiration is always a fixture failure.
    bool released_{}, expired_{}, done_{}, empty_{};
    /// Capture the service result before gRPC can replace it with client cancellation.
    grpc::StatusCode code_ = grpc::StatusCode::UNKNOWN;
    /// Stable public reason only, containing no credentials or generated identity bytes.
    std::string reason_;
};

/// TLS workers and unrelated callers never inherit an admission handler's fault context.
thread_local Probe* active{};

/// Forward real admission methods while observing their pre-transport outcome.
class Service final : public proto::orbit::v1::Admission::Service {
public:
    /// Borrow the real issuer and scenario owner until all handlers have drained.
    Service(Issuer& issuer, Probe& probe) : issuer_(issuer), probe_(probe) {}

    /// Invoke the production registration implementation without fabricating authentication success.
    grpc::Status Register(grpc::ServerContext* context, const proto::orbit::v1::RegistrationRequest* request, proto::orbit::v1::RegistrationResponse* response) override {
        Scope scope(probe_, *context);
        const auto status = issuer_.Register(context, request, response);
        probe_.end(status, response->ByteSizeLong());
        return status;
    }

    /// Preserve the actual directory status even when the client has already cancelled.
    grpc::Status List(grpc::ServerContext* context, const proto::orbit::v1::DirectoryRequest* request, proto::orbit::v1::DirectoryResponse* response) override {
        Scope scope(probe_, *context);
        const auto status = issuer_.List(context, request, response);
        probe_.end(status, response->ByteSizeLong());
        return status;
    }

private:
    /// Bind fault state to this handler thread, restoring its prior state on every return.
    class Scope {
    public:
        /// The real context remains valid until the service method returns.
        Scope(Probe& probe, grpc::ServerContext& context) : previous_(active) {
            probe.begin(context);
            active = &probe;
        }

        /// Do not leak a previous scenario into the next task on a reused gRPC worker.
        ~Scope() {
            active = previous_;
        }

    private:
        /// Restore any outer test scope without transferring ownership.
        Probe* previous_;
    };

    /// The fixture owns both dependencies beyond the listener's shutdown and Wait.
    Issuer& issuer_;
    /// Borrow the controlled injection state used by this isolated admission service.
    Probe& probe_;
};

/// Own an ephemeral TLS listener, real issuer and client material for one finite suite.
class Fixture {
public:
    /// The caller owns the real durable ledger and immutable signing authority.
    Fixture(const Authority& authority, Ledger& ledger, std::string galaxy = "alpha") : issuer_(std::move(galaxy), "127.0.0.1:7442", authority, ledger), service_(issuer_, probe) {

        const auto identity = Identity::load(std::filesystem::path(ASTRA_FIXTURES) / "star-a", *Endpoint::parse("127.0.0.1:7443"));
        CHECK(identity);
        identity_ = *identity;
        grpc::ServerBuilder builder;
        builder.RegisterService(&service_);
        builder.AddChannelArgument("grpc.so_reuseport", 0);
        builder.SetMaxReceiveMessageSize(4096);
        grpc::ResourceQuota quota;
        quota.Resize(16 * 1024 * 1024);
        quota.SetMaxThreads(8);
        builder.SetResourceQuota(quota);
        int port{};
        builder.AddListeningPort("127.0.0.1:0", authority.identity().serverCredentials(), &port);
        server_ = builder.BuildAndStart();
        CHECK(server_ && port > 0);
        stub_ = proto::orbit::v1::Admission::NewStub(grpc::CreateChannel("127.0.0.1:" + std::to_string(port), identity_->channelCredentials()));
    }

    /// Unblock scheduling probes, stop admission and wait before releasing any borrowed dependency.
    ~Fixture() {
        probe.release();
        if (server_) {
            server_->Shutdown(std::chrono::system_clock::now() + 5s);
            server_->Wait();
        }
    }

    /// Construct valid public credentials and a unique fixed-width startup token.
    proto::orbit::v1::RegistrationRequest request(char token, std::uint16_t port = 7443) const {
        proto::orbit::v1::RegistrationRequest request;
        request.set_username(identity_->username());
        request.set_password(identity_->password());
        request.set_galaxy("alpha");
        request.set_group("default");
        request.set_role(proto::orbit::v1::ROLE_STAR);
        request.set_advertise("127.0.0.1:" + std::to_string(port));
        request.set_request_id(std::string(32, token));
        return request;
    }

    /// Require a complete successful response, or no client-visible fields on failure.
    proto::orbit::v1::RegistrationResponse registration(const proto::orbit::v1::RegistrationRequest& request, grpc::StatusCode expected, std::string_view reason = {}, bool cancel = false) {

        grpc::ClientContext context;
        proto::orbit::v1::RegistrationResponse response;
        invoke(context, [&] { return stub_->Register(&context, request, &response); }, expected, reason, cancel);
        CHECK(expected == grpc::StatusCode::OK ? !response.admission().empty() && response.signature().size() == 64 && response.members_size() > 0 : response.ByteSizeLong() == 0);
        return response;
    }

    /// Query using an actual signed current admission and preserve cancellation's server-side result.
    proto::orbit::v1::DirectoryResponse directory(const proto::orbit::v1::RegistrationResponse& receipt, grpc::StatusCode expected, std::string_view reason = {}, bool cancel = false, bool malformed = false) {

        grpc::ClientContext context;
        context.AddMetadata("astra-admission-bin", receipt.admission());
        context.AddMetadata("astra-signature-bin", receipt.signature());
        proto::orbit::v1::DirectoryRequest request;
        if (malformed) {
            CHECK(request.ParseFromString(std::string("\x08\x01", 2)));
        }
        proto::orbit::v1::DirectoryResponse response;
        invoke(context, [&] { return stub_->List(&context, request, &response); }, expected, reason, cancel);
        CHECK(expected == grpc::StatusCode::OK || response.ByteSizeLong() == 0);
        return response;
    }

    /// One sequential probe shared only with this fixture's real service handlers.
    Probe probe;

private:
    /// Cancel and release barriers during unwinding before the future joins its worker.
    template <typename F>
    void invoke(grpc::ClientContext& context, F operation, grpc::StatusCode expected, std::string_view reason, bool cancel) {

        context.set_deadline(gpr_time_add(gpr_now(GPR_CLOCK_MONOTONIC), gpr_time_from_seconds(45, GPR_TIMESPAN)));
        std::future<grpc::Status> result;

        /// Cancel the request and release the held server operation before joining its future.
        struct Drain {
            /// Both references outlive this guard and the following future join.
            grpc::ClientContext& context;
            /// Borrow the probe whose pending callbacks must be released during fixture drainage.
            Probe& probe;

            /// Release the server before future destruction can wait for a held operation.
            ~Drain() {
                context.TryCancel();
                probe.release();
            }
        } drain{context, probe};

        result = std::async(std::launch::async, std::move(operation));
        if (cancel) {
            probe.cancel(context);
            probe.release();
        }
        CHECK(result.wait_for(45s) == std::future_status::ready);
        CHECK(result.get().error_code() == expected);
        probe.finish(expected, reason);
    }

    /// Keep the actual issuer, observed service, credentials and listener in dependency order.
    Issuer issuer_;
    /// Own the admission service before starting its listener and until the listener drains.
    Service service_;
    /// Retain public test TLS and signing material for the isolated listener.
    std::shared_ptr<Identity> identity_;
    /// Own the test listener; shutdown and wait precede destruction of its service.
    std::unique_ptr<grpc::Server> server_;
    /// Own the client stub targeting this fixture listener.
    std::unique_ptr<proto::orbit::v1::Admission::Stub> stub_;
};

/// Count durable startup rows independently of the in-memory ledger snapshot.
unsigned starts(const std::filesystem::path& path) {

    sqlite3* database{};
    const auto opened = sqlite3_open_v2(path.c_str(), &database, SQLITE_OPEN_READONLY, nullptr);
    const std::unique_ptr<sqlite3, decltype(&sqlite3_close_v2)> connection(database, sqlite3_close_v2);
    CHECK(opened == SQLITE_OK);
    sqlite3_stmt* statement{};
    const auto prepared = sqlite3_prepare_v3(database, "SELECT count(*) FROM starts", -1, 0, &statement, nullptr);
    const std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)> query(statement, sqlite3_finalize);
    CHECK(prepared == SQLITE_OK);
    CHECK(sqlite3_step(statement) == SQLITE_ROW);
    const auto result = static_cast<unsigned>(sqlite3_column_int(statement, 0));
    return result;
}

/// Emit a named case only after its independent response, snapshot and durability assertions pass.
void observed(std::string_view name) {
    std::cout << "PULSAR-ISSUER {\"case\":\"" << name << "\"}\n";
}
} // namespace
} // namespace astra::test

/// GNU ld supplies the original methods; explicit this parameters preserve their native ABI.
extern "C" grpc::Status __real__ZNK5astra9Authority12authenticateERN4grpc13ServerContextERKN5proto5orbit2v119RegistrationRequestE(const astra::Authority*, grpc::ServerContext&, const proto::orbit::v1::RegistrationRequest&);
extern "C" proto::orbit::v1::Member __real__ZN5astra8Identity6encodeERKNS_6MemberE(const astra::Member&);
extern "C" decltype(RAND_bytes) __real_RAND_bytes;

/// Hold only after real authentication succeeds; never manufacture an accepted credential.
extern "C" grpc::Status __wrap__ZNK5astra9Authority12authenticateERN4grpc13ServerContextERKN5proto5orbit2v119RegistrationRequestE(const astra::Authority* authority, grpc::ServerContext& context, const proto::orbit::v1::RegistrationRequest& request) {
    auto result = __real__ZNK5astra9Authority12authenticateERN4grpc13ServerContextERKN5proto5orbit2v119RegistrationRequestE(authority, context, request);
    if (result.ok() && astra::test::active) {
        static_cast<void>(astra::test::active->point(astra::test::Probe::Kind::Authentication));
    }
    return result;
}

/// Complete actual encoding before the selected exception or directory cancellation barrier.
extern "C" proto::orbit::v1::Member __wrap__ZN5astra8Identity6encodeERKNS_6MemberE(const astra::Member& member) {
    auto result = __real__ZN5astra8Identity6encodeERKNS_6MemberE(member);
    if (astra::test::active) {
        static_cast<void>(astra::test::active->point(astra::test::Probe::Kind::Encoding));
    }
    return result;
}

/// Deliberately substitute one error return only inside an owned handler, preserving real entropy work.
extern "C" int __wrap_RAND_bytes(std::uint8_t* output, std::size_t size) {
    const auto result = __real_RAND_bytes(output, size);
    return astra::test::active && astra::test::active->point(astra::test::Probe::Kind::Entropy) ? 0 : result;
}

namespace astra::test {
/// Exercise precommit faults, partial directory cancellation, error mapping and healthy recovery.
void issuer() {

    const Directory directory;
    const auto path = directory.path / "issuer.db";
    const auto endpoint = *Endpoint::parse("127.0.0.1:7443");
    const auto authority = Authority::load(std::filesystem::path(ASTRA_FIXTURES) / "pulsar", endpoint, endpoint);
    CHECK(authority);
    Fault disk;
    Member current;
    {
        Ledger ledger(path, "alpha", (*authority)->keyId(), 2, 32, true);
        Fixture fixture(**authority, ledger);
        fixture.probe.arm();
        auto receipt = fixture.registration(fixture.request('a'), grpc::StatusCode::OK);
        const auto local = (*authority)->identity().verify({reinterpret_cast<const std::uint8_t*>(receipt.admission().data()), receipt.admission().size()}, {reinterpret_cast<const std::uint8_t*>(receipt.signature().data()), receipt.signature().size()});
        CHECK(local);
        current = *local;
        fixture.probe.arm();
        static_cast<void>(fixture.registration(fixture.request('b', 7444), grpc::StatusCode::OK));
        const auto snapshot = ledger.snapshot(current);
        CHECK(snapshot && snapshot->size() == 2 && starts(path) == 2);

        fixture.probe.arm();
        static_cast<void>(fixture.registration(fixture.request('c', 7445), grpc::StatusCode::RESOURCE_EXHAUSTED, "Registration rejected"));
        CHECK(ledger.snapshot(current) == snapshot && starts(path) == 2);
        observed("member-capacity");
        {
            Fixture mismatch(**authority, ledger, "beta");
            auto request = mismatch.request('z');
            request.set_galaxy("beta");
            mismatch.probe.arm();
            static_cast<void>(mismatch.registration(request, grpc::StatusCode::INVALID_ARGUMENT, "Registration rejected"));
            CHECK(ledger.snapshot(current) == snapshot && starts(path) == 2);
            observed("configuration-error-mapping");
        }
        for (const auto kind : {Probe::Kind::Entropy, Probe::Kind::Allocation, Probe::Kind::Failure, Probe::Kind::Authentication}) {
            fixture.probe.arm(kind, kind == Probe::Kind::Failure ? 3 : 1);
            const auto code = kind == Probe::Kind::Allocation ? grpc::StatusCode::RESOURCE_EXHAUSTED : kind == Probe::Kind::Authentication ? grpc::StatusCode::CANCELLED
                                                                                                                                           : grpc::StatusCode::INTERNAL;
            const auto reason = kind == Probe::Kind::Allocation ? "Registration resources unavailable" : "Registration unavailable";
            static_cast<void>(fixture.registration(fixture.request('c'), code, reason, kind == Probe::Kind::Authentication));
            CHECK(ledger.snapshot(current) == snapshot && starts(path) == 2);
            observed(kind == Probe::Kind::Entropy ? "entropy-refusal" : kind == Probe::Kind::Allocation ? "registration-allocation"
                                                                    : kind == Probe::Kind::Failure      ? "registration-preparation"
                                                                                                        : "registration-cancel-before-prepare");
        }

        fixture.probe.arm();
        receipt = fixture.registration(fixture.request('c'), grpc::StatusCode::OK);
        const auto replacement = (*authority)->identity().verify({reinterpret_cast<const std::uint8_t*>(receipt.admission().data()), receipt.admission().size()}, {reinterpret_cast<const std::uint8_t*>(receipt.signature().data()), receipt.signature().size()});
        CHECK(replacement && replacement->epoch.value == current.epoch.value + 1 && !ledger.current(current));
        current = *replacement;
        const auto replaced = ledger.snapshot(current);
        CHECK(replaced && replaced->size() == 2 && starts(path) == 3 && snapshot->at(local->principal.text()) == *local);
        observed("registration-recovered-on-same-token");
        fixture.probe.arm();
        const auto topology = fixture.directory(receipt, grpc::StatusCode::OK);
        CHECK(topology.members_size() == 2);
        // Derive the complete ordered expectation from the independently captured committed members.
        std::vector<Member> expectedMembers, actualMembers;
        for (const auto& [principal, member] : *replaced) {
            static_cast<void>(principal);
            expectedMembers.push_back(member);
        }
        std::ranges::sort(expectedMembers, {}, &Member::id);
        for (const auto& encoded : topology.members()) {
            const auto member = decodeMember(encoded);
            CHECK(member);
            actualMembers.push_back(*member);
        }
        CHECK(actualMembers == expectedMembers);
        const auto expected = topology.SerializeAsString();
        fixture.probe.arm();
        static_cast<void>(fixture.directory(receipt, grpc::StatusCode::INVALID_ARGUMENT, "Directory request must be empty", false, true));
        observed("nonempty-directory");
        for (const auto kind : {Probe::Kind::Allocation, Probe::Kind::Failure, Probe::Kind::Encoding}) {
            fixture.probe.arm(kind, kind == Probe::Kind::Encoding ? 1 : 2);
            const auto code = kind == Probe::Kind::Allocation ? grpc::StatusCode::RESOURCE_EXHAUSTED : kind == Probe::Kind::Encoding ? grpc::StatusCode::CANCELLED
                                                                                                                                     : grpc::StatusCode::INTERNAL;
            const auto reason = kind == Probe::Kind::Allocation ? "Directory resources unavailable" : kind == Probe::Kind::Encoding ? "Directory cancelled"
                                                                                                                                    : "Directory unavailable";
            static_cast<void>(fixture.directory(receipt, code, reason, kind == Probe::Kind::Encoding));
            CHECK(ledger.snapshot(current) == replaced && starts(path) == 3);
            observed(kind == Probe::Kind::Allocation ? "directory-partial-allocation" : kind == Probe::Kind::Failure ? "directory-partial-preparation"
                                                                                                                     : "directory-partial-cancel");
            fixture.probe.arm();
            CHECK(fixture.directory(receipt, grpc::StatusCode::OK).SerializeAsString() == expected);
        }

        // A real journal write refusal must poison writes without replacing the last committed view.
        fixture.probe.arm();
        disk.arm(SQLITE_IOERR_WRITE);
        static_cast<void>(fixture.registration(fixture.request('d'), grpc::StatusCode::UNAVAILABLE, "Registration rejected"));
        CHECK(disk.hits() == 1);
        disk.clear();
        CHECK(ledger.snapshot(current) == replaced && starts(path) == 3);
        fixture.probe.arm();
        static_cast<void>(fixture.registration(fixture.request('d'), grpc::StatusCode::UNAVAILABLE, "Registration rejected"));
        CHECK(ledger.snapshot(current) == replaced && starts(path) == 3);
        observed("durability-refusal-and-write-isolation");
    }
    {
        Ledger recovered(path, "alpha", (*authority)->keyId(), 2, 32);
        CHECK(recovered.current(current) && recovered.snapshot(current)->size() == 2 && starts(path) == 3);
        observed("durability-reopen");
    }

    Server::Config config;
    config.listen = config.pulseListen = *Endpoint::parse("127.0.0.1:0", true);
    config.galaxy = "alpha";
    config.identity = std::filesystem::path(ASTRA_FIXTURES) / "pulsar";
    config.state = directory.path / "lifecycle.db";
    config.initialize = true;
    Server server(config, [] { return std::optional<Clock::Estimate>{}; });
    server.start();
    const auto admission = server.admissionEndpoint(), pulse = server.pulseEndpoint();
    bool refused{};
    try {
        server.start();
    } catch (const std::runtime_error& error) {
        refused = std::string_view(error.what()) == "Pulsar already started";
    }
    CHECK(refused && server.admissionEndpoint() == admission && server.pulseEndpoint() == pulse);
    server.stop();
    server.stop();
    server.start();
    CHECK(server.admissionEndpoint() == admission && server.pulseEndpoint() == pulse);
    server.stop();
    observed("duplicate-start-preserves-listeners");
}
} // namespace astra::test
